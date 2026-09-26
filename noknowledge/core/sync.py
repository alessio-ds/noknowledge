"""Device sync: approvals, live mirroring and history back-fill.

Three things travel between the devices of one account, all over the sealed
device channel in :mod:`noknowledge.core.device_channel`:

* **mirrors** — as you send a message from one device, a copy of it (and of your
  read/delivered state) goes to your other devices, so they show the same
  conversation. This is the XMPP "carbons" behaviour.
* **back-fill** — a device that asked, and was approved by a human on another
  device, receives the past inside a range it chose.
* **approvals** — the record of that human decision, which is what stops a stolen
  seed from pulling the past out of your devices.

The rule that keeps this safe is simple: **a device sends data only to devices
its human approved**. Receiving is not a security boundary — every device of the
account is entitled to the account's traffic, and a forged record fails its
signature or its AEAD.
"""

from __future__ import annotations

import json
import time
from typing import Callable, Iterable

from noknowledge.core import device_channel as channel
from noknowledge.core import history
from noknowledge.core.device_channel import SyncError
from noknowledge.core.devices import (
    DeviceEntry,
    DeviceKeys,
    device_keys_id,
    open_signed_payload,
    seal_payload,
)
from noknowledge.crypto import devicekeys
from noknowledge.crypto.encoding import b64d, b64e, canonical_json

# Storage keys inside the local store.
DEVICE_KEYS_STATE = "device_keys"
APPROVALS_STATE = "sync_approvals"
REQUESTED_STATE = "sync_requested"
INCOMING_STATE = "sync_incoming"
REQUESTS_STATE = "sync_requests"
SEEN_STATE = "sync_seen"
SIBLING_KEYS_STATE = "sync_sibling_keys"

#: A device that never answers its own history request is not retried forever.
MAX_SEEN_TRANSFERS = 200


# -- device keys -----------------------------------------------------------


def ensure_device_keys(client) -> dict:
    """This device's own keypair, generated on first use."""
    stored = client.store.get_state(client.identity_id, DEVICE_KEYS_STATE)
    if stored and stored.get("sdev") and stored.get("sagree"):
        return {
            "sdev": b64d(stored["sdev"]),
            "sagree": b64d(stored["sagree"]),
        }
    sdev_private, sagree_private = devicekeys.generate_device_keys()
    client.store.set_state(
        client.identity_id,
        DEVICE_KEYS_STATE,
        {"sdev": b64e(sdev_private), "sagree": b64e(sagree_private)},
    )
    return {"sdev": sdev_private, "sagree": sagree_private}


def device_keys_record(client) -> DeviceKeys:
    keys = ensure_device_keys(client)
    device_id = client.device_id()
    if not device_id:
        raise SyncError("this client is not provisioned")
    return DeviceKeys.create(
        client.identity,
        device_id,
        devicekeys.signing_public(keys["sdev"]),
        devicekeys.agreement_public(keys["sagree"]),
    )


def publish_device_keys(client) -> None:
    """Publish this device's keys so siblings can seal records to it."""
    record = device_keys_record(client)
    sealed = seal_payload(record.isign, record.idh, record.address(), record.to_bytes())
    try:
        client.backend.publish_bundle(record.address(), sealed)
    except Exception:
        # A relay refusing the record must not break provisioning; sync simply
        # stays unavailable until it is published.
        pass


def fetch_device_keys(client, device: DeviceEntry) -> DeviceKeys | None:
    """Another device's key record, cached in memory for a day."""
    cache = client._sibling_keys  # noqa: SLF001 (package-internal cache)
    entry = cache.get(device.device_id)
    now = time.time()
    if entry and now - entry["ts"] < 24 * 3600:
        return entry["record"]
    address = device_keys_id(
        client.identity.ed_public_bytes, client.identity.x_public_bytes, device.device_id
    )
    try:
        payload = client._backend_for(device.relays).fetch_bundle(address)
        opened = open_signed_payload(
            payload, client.identity.ed_public_bytes, client.identity.x_public_bytes
        )
        record = DeviceKeys.from_bytes(opened)
    except Exception:
        return entry["record"] if entry else None
    if record.device_id != device.device_id:
        return None
    if not record.belongs_to(
        client.identity_id, client.identity.ed_public_bytes, client.identity.x_public_bytes
    ):
        return None
    cache[device.device_id] = {"record": record, "ts": now}
    return record


def sibling_devices(
    client, include_self: bool = False, fresh: bool = False
) -> list[DeviceEntry]:
    """Every other device of this account, from our own signed list.

    ``fresh`` bypasses the cache: a device that just registered is exactly the
    case the cache would hide.
    """
    listing = client.own_device_list(max_age=0.0 if fresh else 300.0)
    devices = listing.devices if listing else []
    mine = client.device_id()
    return [
        device
        for device in devices
        if include_self or device.device_id != mine
    ]


def _device_by_id(client, device_id: str, fresh: bool = False) -> DeviceEntry | None:
    for device in sibling_devices(client, include_self=True, fresh=fresh):
        if device.device_id == device_id:
            return device
    return None


def _locate_device(client, device_id: str) -> DeviceEntry | None:
    """Find a sibling, refetching the list once if the cache does not have it."""
    return _device_by_id(client, device_id) or _device_by_id(
        client, device_id, fresh=True
    )


# -- approvals -------------------------------------------------------------


def approvals(client) -> dict:
    return client.store.get_state(client.identity_id, APPROVALS_STATE) or {}


def _set_approvals(client, value: dict) -> None:
    client.store.set_state(client.identity_id, APPROVALS_STATE, value)


def approved_devices(client) -> list[str]:
    return sorted(approvals(client).keys())


def mark_approved(client, device_id: str, transfer: str, since_ms, until_ms) -> None:
    """Remember that our human approved ``device_id`` for a range."""
    value = approvals(client)
    value[device_id] = {
        "transfer": transfer,
        "since": int(since_ms or 0),
        "until": int(until_ms or time.time() * 1000),
        "ts": int(time.time() * 1000),
    }
    _set_approvals(client, value)


def revoke_approval(client, device_id: str) -> None:
    value = approvals(client)
    value.pop(device_id, None)
    _set_approvals(client, value)


def _mark_seen(client, transfer: str) -> bool:
    """Record a transfer id; False when we have already handled it."""
    seen = client.store.get_state(client.identity_id, SEEN_STATE) or []
    if transfer in seen:
        return False
    seen.append(transfer)
    client.store.set_state(
        client.identity_id, SEEN_STATE, seen[-MAX_SEEN_TRANSFERS:]
    )
    return True


def incoming_request(client, device_id: str, transfer: str, since_ms) -> None:
    """Remember that a sibling asked for history and is waiting for a human."""
    pending = client.store.get_state(client.identity_id, REQUESTS_STATE) or {}
    pending[device_id] = {
        "transfer": transfer,
        "since": int(since_ms or 0),
        "ts": int(time.time() * 1000),
    }
    client.store.set_state(client.identity_id, REQUESTS_STATE, pending)


def pending_requests(client) -> list[dict]:
    """Devices asking for history, newest first, with the name we know them by."""
    pending = client.store.get_state(client.identity_id, REQUESTS_STATE) or {}
    known = {device.device_id: device for device in sibling_devices(client, True)}
    out = []
    for device_id, request in pending.items():
        if device_id in approvals(client):
            continue  # already handled
        device = known.get(device_id)
        out.append(
            {
                "device_id": device_id,
                "name": (device.name if device else "") or "",
                "since": request.get("since") or 0,
                "ts": request.get("ts") or 0,
                "transfer": request.get("transfer"),
            }
        )
    return sorted(out, key=lambda item: item["ts"], reverse=True)


def requested_from(client) -> dict:
    return client.store.get_state(client.identity_id, REQUESTED_STATE) or {}


# -- writing records -------------------------------------------------------


def _write_record(
    client,
    device: DeviceEntry,
    kind: int,
    plaintext: bytes,
    transfer: str,
    seq: int = 0,
    extra: dict | None = None,
) -> bytes:
    keys = ensure_device_keys(client)
    record = fetch_device_keys(client, device)
    if record is None:
        raise SyncError(f"device {device.device_id} has not published sync keys")
    blob = channel.seal_record(
        kind,
        plaintext,
        recipient_sagree=record.sagree,
        sender_device_id=client.device_id() or "",
        sender_sdev_private=keys["sdev"],
        transfer_id=transfer,
        seq=seq,
        extra=extra,
    )
    client._backend_for(device.relays).put(  # noqa: SLF001 (same package)
        client._device_capability(device), blob
    )
    return blob


def request_history(client, since_ms=None, budget: int | None = None) -> list[str]:
    """Ask every sibling device for the past. Returns who was asked."""
    transfer = channel.new_transfer_id()
    payload = canonical_json(
        {
            "since": int(since_ms or 0),
            "budget": int(budget if budget is not None else history.DEFAULT_BUDGET_BYTES),
            "device": client.device_id() or "",
        }
    )
    asked = []
    for device in sibling_devices(client):
        try:
            _write_record(client, device, channel.REQUEST, payload, transfer)
        except Exception:
            continue
        asked.append(device.device_id)
    if asked:
        client.store.set_state(
            client.identity_id,
            REQUESTED_STATE,
            {
                "transfer": transfer,
                "since": int(since_ms or 0),
                "asked": asked,
                "ts": int(time.time() * 1000),
            },
        )
    return asked


def approve_device(
    client,
    device_id: str,
    since_ms=None,
    budget: int | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> dict:
    """Approve a device and send it the history it asked for.

    This is the human decision that a stolen seed cannot make for you.
    """
    device = _locate_device(client, device_id)
    if device is None:
        raise SyncError(f"unknown device: {device_id}")
    pending = client.store.get_state(client.identity_id, REQUESTS_STATE) or {}
    request = pending.get(device_id) or {}
    since_ms = int(since_ms if since_ms is not None else request.get("since") or 0)
    budget = int(budget if budget is not None else history.DEFAULT_BUDGET_BYTES)
    transfer = channel.new_transfer_id()
    until_ms = int(time.time() * 1000)

    _write_record(
        client,
        device,
        channel.APPROVAL,
        canonical_json(
            {
                "device": device_id,
                "since": since_ms,
                "until": until_ms,
                "budget": budget,
            }
        ),
        transfer,
        extra={"since": since_ms, "until": until_ms},
    )
    mark_approved(client, device_id, transfer, since_ms, until_ms)

    counts = send_history(
        client, device, since_ms=since_ms, until_ms=until_ms, budget=budget,
        transfer=transfer, on_progress=on_progress,
    )
    # Done asking: forget the request so the prompt disappears.
    pending.pop(device_id, None)
    client.store.set_state(client.identity_id, REQUESTS_STATE, pending)
    return {"device_id": device_id, "since": since_ms, "transfer": transfer, **counts}


def deny_device(client, device_id: str) -> None:
    pending = client.store.get_state(client.identity_id, REQUESTS_STATE) or {}
    pending.pop(device_id, None)
    client.store.set_state(client.identity_id, REQUESTS_STATE, pending)


def build_items(
    client, since_ms, until_ms, budget: int
) -> tuple[list[tuple[str, object]], list[dict]]:
    """Everything that goes in a back-fill, as ``(kind, payload)`` pairs."""
    bundle = history.build_bundle(
        client, since_ms=since_ms, until_ms=until_ms, budget_bytes=budget
    )
    items: list[tuple[str, object]] = []
    for contact in bundle["contacts"]:
        items.append(("contact", contact))
    for message in bundle["messages"]:
        items.append(("message", message))
    for chunk in bundle["chunks"]:
        items.append(("chunk", chunk))
    return items, bundle["skipped"]


def send_history(
    client,
    device: DeviceEntry,
    *,
    since_ms,
    until_ms,
    budget: int,
    transfer: str | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> dict:
    """Stream a range of history to one approved device."""
    transfer = transfer or channel.new_transfer_id()
    items, skipped = build_items(client, since_ms, until_ms, budget)

    _write_record(
        client,
        device,
        channel.OFFER,
        canonical_json(
            {
                "count": len(items),
                "skipped": len(skipped),
                "since": int(since_ms or 0),
                "until": int(until_ms or 0),
                "budget": budget,
            }
        ),
        transfer,
        extra={"count": len(items)},
    )

    chain = channel.HashChain(transfer)
    for index, (kind, payload) in enumerate(items, start=1):
        raw = canonical_json({"kind": kind, **payload})
        _write_record(client, device, channel.ITEM, raw, transfer, seq=index)
        chain.add(raw, index)
        if on_progress:
            on_progress(index, len(items))

    _write_record(
        client,
        device,
        channel.COMPLETE,
        canonical_json({"count": len(items), "chain": chain.hexdigest()}),
        transfer,
        extra={"count": len(items), "chain": chain.hexdigest()},
    )
    return {"items": len(items), "skipped": len(skipped)}


# -- mirroring -------------------------------------------------------------


def mirror_message(client, contact_id: str, message: dict) -> int:
    """Copy one of our sent messages to the devices we approved."""
    targets = [
        device
        for device in sibling_devices(client)
        if device.device_id in approvals(client)
    ]
    if not targets:
        return 0
    contact = client.store.get_contact(client.identity_id, contact_id)
    if contact is None:
        return 0
    item = history.message_item(contact_id, message)
    item["id"] = message["id"]
    raw = canonical_json(
        {"kind": "mirror", "contact": history.contact_item(contact), "message": item}
    )
    sent = 0
    for device in targets:
        try:
            _write_record(
                client, device, channel.MIRROR, raw, channel.new_transfer_id()
            )
        except Exception:
            continue
        sent += 1
    return sent


def mirror_state(client, contact_id: str | None, message: dict) -> int:
    """Copy a read/delivered state change to the approved devices."""
    targets = [
        device
        for device in sibling_devices(client)
        if device.device_id in approvals(client)
    ]
    if not targets:
        return 0
    raw = canonical_json(
        {
            "kind": "state",
            "state": {
                "id": message.get("id"),
                "remote_id": message.get("remote_id"),
                "contact_id": contact_id or message.get("contact_id"),
                "state": message.get("state"),
            },
        }
    )
    sent = 0
    for device in targets:
        try:
            _write_record(
                client, device, channel.MIRROR, raw, channel.new_transfer_id()
            )
        except Exception:
            continue
        sent += 1
    return sent


# -- receiving -------------------------------------------------------------


def handle_record(client, blob: bytes) -> str | None:
    """Dispatch one inbound device record. Returns a short description."""
    kind, header, payload = channel.parse_record(blob)
    device_id = str(header.get("from") or "")
    device = _locate_device(client, device_id)
    if device is None:
        raise SyncError(f"record from unknown device: {device_id}")
    record = fetch_device_keys(client, device)
    if record is None:
        raise SyncError(f"no sync keys for device: {device_id}")
    keys = ensure_device_keys(client)
    kind, header, plaintext = channel.open_record(
        blob,
        my_sagree_private=keys["sagree"],
        sender_sdev=record.sdev,
        sender_device_id=device_id,
    )
    transfer = str(header.get("transfer") or "")

    if kind == channel.REQUEST:
        request = _loads(plaintext)
        incoming_request(client, device_id, transfer, request.get("since"))
        return f"sync request from {device_id}"

    if kind == channel.APPROVAL:
        # They vouched for us; we may send them our mirrors from now on.
        if _mark_seen(client, transfer):
            mark_approved(
                client,
                device_id,
                transfer,
                header.get("since"),
                header.get("until"),
            )
        return f"history approved by {device_id}"

    if kind == channel.OFFER:
        offer = _loads(plaintext)
        state = client.store.get_state(client.identity_id, INCOMING_STATE) or {}
        previous = state.get(device_id) or {}
        if previous.get("transfer") != transfer:
            client._sync_message_index = None  # noqa: SLF001 (new transfer)
        state[device_id] = {
            "transfer": transfer,
            "received": 0,
            "expected": int(offer.get("count") or 0),
            "skipped": int(offer.get("skipped") or 0),
            "chain": "",
            "done": False,
        }
        client.store.set_state(client.identity_id, INCOMING_STATE, state)
        return f"{offer.get('count')} item(s) offered by {device_id}"

    if kind == channel.ITEM:
        return _apply_item(client, device_id, transfer, plaintext, int(header.get("seq") or 0))

    if kind == channel.COMPLETE:
        complete = _loads(plaintext)
        state = client.store.get_state(client.identity_id, INCOMING_STATE) or {}
        entry = state.get(device_id) or {}
        expected = int(complete.get("count") or 0)
        received = int(entry.get("received") or 0)
        entry["done"] = True
        entry["expected"] = expected
        entry["complete"] = received >= expected and str(entry.get("chain") or "") == str(
            complete.get("chain") or ""
        )
        state[device_id] = entry
        client.store.set_state(client.identity_id, INCOMING_STATE, state)
        if not entry["complete"]:
            return f"history from {device_id} is incomplete ({received}/{expected})"
        return f"history from {device_id} complete ({received} item(s))"

    if kind == channel.MIRROR:
        return _apply_mirror(client, _loads(plaintext))

    return None


def _loads(plaintext: bytes) -> dict:
    try:
        value = json.loads(plaintext.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise SyncError("device record payload is malformed") from exc
    if not isinstance(value, dict):
        raise SyncError("device record payload is not an object")
    return value


def _apply_item(client, device_id: str, transfer: str, plaintext: bytes, seq: int) -> str:
    """Merge one back-fill item. Idempotent, so a resumed transfer is harmless."""
    item = _loads(plaintext)
    kind = item.get("kind")
    counts = history.new_counts()
    state = client.store.get_state(client.identity_id, INCOMING_STATE) or {}
    entry = state.get(device_id) or {
        "transfer": transfer,
        "seq": 0,
        "count": 0,
        "chain": "",
        "done": False,
    }

    if kind == "contact":
        payload = {key: value for key, value in item.items() if key != "kind"}
        history.merge_contacts(client, [payload], counts)
    elif kind == "message":
        payload = {key: value for key, value in item.items() if key != "kind"}
        index = client._sync_message_index  # noqa: SLF001 (per-transfer cache)
        if index is None:
            index = history.message_index(client)
            client._sync_message_index = index  # noqa: SLF001
        history.merge_messages(client, [payload], index, counts)
    elif kind == "chunk":
        payload = {key: value for key, value in item.items() if key != "kind"}
        history.merge_chunks(client, [payload], counts)
    else:
        raise SyncError(f"unknown history item: {kind}")

    # Extend the running digest so COMPLETE can tell a full transfer from a
    # truncated one.
    chain = channel.HashChain(transfer, resumed=str(entry.get("chain") or ""))
    chain.add(plaintext, seq)
    entry.update(
        {
            "transfer": transfer,
            "received": int(entry.get("received") or 0) + 1,
            "expected": int(entry.get("expected") or 0),
            "chain": chain.hexdigest(),
            "done": False,
        }
    )
    state[device_id] = entry
    client.store.set_state(client.identity_id, INCOMING_STATE, state)
    return f"{kind} from {device_id}"


def _apply_mirror(client, item: dict) -> str:
    kind = item.get("kind")
    if kind == "mirror":
        counts = history.new_counts()
        if item.get("contact"):
            history.merge_contacts(client, [item["contact"]], counts)
        index = history.message_index(client)
        history.merge_messages(client, [item.get("message")], index, counts)
        return "message mirrored" if counts["messages"] else "mirror ignored"

    if kind == "state":
        change = item.get("state") or {}
        target = None
        if change.get("remote_id"):
            target = client.store.find_by_remote_id(
                client.identity_id, str(change["remote_id"])
            )
        if target is None and change.get("id"):
            target = client.store.get_message(str(change["id"]))
        if target is None:
            return "state update for an unknown message"
        state = str(change.get("state") or "")
        if history.state_rank(state) > history.state_rank(target.get("state")):
            client.store.update_message(target["id"], state=state)
            return f"state {state}"
        return "state already newer"

    return "unknown mirror"


def iter_status(client) -> Iterable[dict]:
    """What the Devices dialog shows for each sibling."""
    incoming = client.store.get_state(client.identity_id, INCOMING_STATE) or {}
    outgoing = requested_from(client)
    approved = approvals(client)
    # Fresh: this drives a dialog a human is looking at, and the sibling they
    # just added is exactly what the cache would not show yet.
    for device in sibling_devices(client, fresh=True):
        entry = incoming.get(device.device_id) or {}
        yield {
            "device_id": device.device_id,
            "name": device.name,
            "approved": device.device_id in approved,
            "received": int(entry.get("received") or 0),
            "expected": int(entry.get("expected") or 0),
            "done": bool(entry.get("done")),
            "approved_from_us": device.device_id in approved,
            "asked": device.device_id in (outgoing.get("asked") or []),
            "has_keys": fetch_device_keys(client, device) is not None,
        }