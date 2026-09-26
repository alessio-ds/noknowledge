"""The noknowledge client.

Orchestrates identity provisioning, contact cards, X3DH handshakes, Double
Ratchet sessions, capability mailboxes, receipts and attachments. All relay
access goes through :class:`MultiRelayBackend`, so the relay set is the unit of
availability and a single relay failure is invisible to callers.
"""

from __future__ import annotations

import mimetypes
import os
import time
import uuid

from noknowledge.core.attachments import (
    AttachmentError,
    decode_manifest,
    decrypt_attachment,
    encrypt_attachment,
    manifest_dict,
)
from noknowledge.core.card import CardError, ContactCard
from noknowledge.core.devices import (
    LEGACY_DEVICE,
    DeviceEntry,
    DeviceList,
    DeviceListError,
    device_list_id,
    new_device_id,
    open_device_list,
    seal_device_list,
)
from noknowledge.core.session import Session
from noknowledge.crypto import x3dh
from noknowledge.crypto.encoding import b64d, b64e
from noknowledge.crypto.identity import Identity
from noknowledge.crypto.prekeys import PrekeyBundle, make_bundle
from noknowledge.crypto.ratchet import Ratchet
from noknowledge.wire.backends.base import MailboxCapability
from noknowledge.wire.backends.multi_relay import (
    MultiRelayBackend,
    normalize_relay_urls,
)
from noknowledge.wire.errors import WireError
from noknowledge.wire.protocol import (
    envelope_max_size,
    make_envelope,
    parse_wire,
    seal,
    unseal,
)
from noknowledge.wire.transport import Transport

DEFAULT_OPK_COUNT = 20


class ClientError(Exception):
    """Base class for client-side failures."""


class NotProvisioned(ClientError):
    """The client has no mailbox/prekeys yet."""


class UnknownContact(ClientError):
    """No such contact."""


def _now_ms() -> int:
    return int(time.time() * 1000)


def _new_id() -> str:
    return uuid.uuid4().hex


class Client:
    def __init__(
        self,
        identity: Identity,
        store,
        relays: list[str],
        name: str | None = None,
        transport: Transport | None = None,
        backend: MultiRelayBackend | None = None,
        opk_count: int = DEFAULT_OPK_COUNT,
    ) -> None:
        self.identity = identity
        self.store = store
        self.relays = normalize_relay_urls(list(relays))
        if not self.relays:
            raise ValueError("at least one relay URL is required")
        self.backend = backend or MultiRelayBackend(self.relays, transport=transport)
        # Backends for peers' relay sets, keyed by the normalised URL tuple. A
        # recipient's signed card says where their mailbox lives, so delivery
        # goes there rather than to our own relays.
        self._peer_backends: dict[tuple[str, ...], MultiRelayBackend] = {}
        self.identity_id = identity.identity_id
        self.name = name or identity.label or self.identity_id[:8]
        self.opk_count = opk_count
        self._own_inbox: MailboxCapability | None = None
        self._bundle_id: str | None = None
        self._card: ContactCard | None = None
        self._device_id: str | None = None

    # -- provisioning -----------------------------------------------------

    @property
    def card(self) -> ContactCard:
        self._ensure_provisioned()
        assert self._card is not None
        return self._card

    def card_string(self) -> str:
        return self.card.to_string()

    def _ensure_provisioned(self) -> None:
        if self._card is None:
            self.provision()

    def provision(self) -> ContactCard:
        """Create the mailbox, prekeys and bundle if they do not exist yet."""
        inbox_json = self.store.get_state(self.identity_id, "inbox")
        if inbox_json:
            self._own_inbox = MailboxCapability.from_json(inbox_json)
            self._bundle_id = self.store.get_state(self.identity_id, "bundle_id")
            stored_name = self.store.get_state(self.identity_id, "name")
            if stored_name:
                self.name = stored_name
            # Register the existing mailbox on the current relay set, so that
            # changing relays does not silently make the mailbox unreachable.
            try:
                self.backend.register_mailbox(self._own_inbox)
            except Exception:
                pass
            try:
                prekeys = self.store.load_prekeys(self.identity_id)
                if prekeys:
                    self._publish_bundle(prekeys)
            except Exception:
                pass
        else:
            self._own_inbox = self.backend.create_mailbox()
            self._bundle_id = b64e(os.urandom(16))
            prekeys = self._generate_prekeys(self.opk_count)
            self.store.save_prekeys(self.identity_id, prekeys)
            self._publish_bundle(prekeys)
            self.store.set_state(self.identity_id, "inbox", self._own_inbox.to_json())
            self.store.set_state(self.identity_id, "bundle_id", self._bundle_id)
            self.store.set_state(self.identity_id, "name", self.name)
        assert self._bundle_id is not None and self._own_inbox is not None
        self._card = ContactCard.create(
            self.identity, self._bundle_id, self._own_inbox, self.relays, self.name
        )
        self._ensure_device_registered()
        return self._card

    # -- devices ----------------------------------------------------------

    def device_id(self) -> str | None:
        """This device's identifier within the account, once provisioned."""
        return self._device_id

    def _device_entry(self) -> DeviceEntry:
        """This device as advertised to senders in the account's device list."""
        assert self._own_inbox is not None and self._bundle_id is not None
        return DeviceEntry(
            device_id=self._device_id or LEGACY_DEVICE,
            inbox=self._own_inbox.card_view(),
            relays=list(self.relays),
            bundle_id=self._bundle_id,
            name=self.name or "",
        )

    def _ensure_device_registered(self) -> None:
        """Add (or refresh) this device in the account's signed device list.

        This is what makes a recovered account work: the device gets its own
        mailbox and prekeys, then publishes itself so senders start delivering a
        copy here too.
        """
        if self._device_id is None:
            self._device_id = self.store.get_state(
                self.identity_id, "device_id"
            ) or new_device_id()
            self.store.set_state(self.identity_id, "device_id", self._device_id)
        assert self._own_inbox is not None and self._bundle_id is not None
        entry = self._device_entry()
        existing = self._fetch_own_device_list()
        if existing is not None and any(
            device.device_id == entry.device_id
            and device.inbox == entry.inbox
            and device.bundle_id == entry.bundle_id
            and list(device.relays) == list(entry.relays)
            for device in existing.devices
        ):
            # Already advertised exactly like this: republishing would only burn
            # a relay's prekey quota and churn the record.
            return
        entries = [
            device
            for device in (existing.devices if existing else [])
            if device.device_id != entry.device_id
        ]
        entries.append(entry)
        listing = DeviceList.create(self.identity, entries)
        try:
            self.backend.publish_bundle(listing.address(), seal_device_list(listing))
        except Exception:
            # A relay refusing the record must not break provisioning; senders
            # simply fall back to the inbox in our contact card.
            pass

    @property
    def device_list_address(self) -> str:
        return device_list_id(
            self.identity.ed_public_bytes, self.identity.x_public_bytes
        )

    def _fetch_own_device_list(self) -> DeviceList | None:
        try:
            payload = self.backend.fetch_bundle(self.device_list_address)
        except Exception:
            return None
        try:
            listing = open_device_list(
                payload, self.identity.ed_public_bytes, self.identity.x_public_bytes
            )
        except DeviceListError:
            return None
        if not listing.belongs_to(
            self.identity_id, self.identity.ed_public_bytes, self.identity.x_public_bytes
        ):
            return None
        return listing

    def devices(self) -> list[DeviceEntry]:
        """Every device currently registered to this account."""
        listing = self._fetch_own_device_list()
        return listing.devices if listing else [self._device_entry()]

    def _generate_prekeys(self, count: int) -> dict:
        spk_private, spk_public = x3dh.generate_keypair()
        opks = {}
        for index in range(1, count + 1):
            private, public = x3dh.generate_keypair()
            opks[str(index)] = {"priv": b64e(private), "pub": b64e(public)}
        return {
            "spk_id": 1,
            "spk_private": b64e(spk_private),
            "spk_public": b64e(spk_public),
            "opks": opks,
            "next_opk_id": count + 1,
        }

    def _publish_bundle(self, prekeys: dict) -> None:
        assert self._bundle_id is not None
        bundle = make_bundle(
            self.identity,
            b64d(self._bundle_id),
            int(prekeys["spk_id"]),
            b64d(prekeys["spk_public"]),
            [(int(key), b64d(value["pub"])) for key, value in prekeys["opks"].items()],
        )
        self.backend.publish_bundle(self._bundle_id, bundle.to_bytes())

    # -- relay set --------------------------------------------------------

    def relay_urls(self) -> list[str]:
        """The relays this identity uses, and advertises in its contact card."""
        return list(self.relays)

    def discover_relays(self, **kwargs) -> list[str]:
        """Relays we would use if we adopted everything advertised and alive.

        Read-only: nothing is changed until :meth:`refresh_relays` is called.
        """
        from noknowledge.wire.discovery import discover_relays

        return discover_relays(self.relays, self.backend.transport, **kwargs)

    def refresh_relays(self, **kwargs) -> list[str]:
        """Discover relays and adopt any newly reachable ones.

        Our mailbox is registered on the added relays and the prekey bundle
        republished there, and the contact card is rebuilt so new contacts are
        told about the wider set. Nothing is ever removed.
        """
        discovered = self.discover_relays(**kwargs)
        if discovered != self.relays:
            self._apply_relays(discovered)
        return list(self.relays)

    def _apply_relays(self, relays: list[str]) -> None:
        urls = normalize_relay_urls(list(relays))
        if not urls or urls == self.relays:
            return
        previous = self.backend
        self.relays = urls
        # Reuse the transport: peer backends share it, so it must stay open.
        self.backend = MultiRelayBackend(urls, transport=previous.transport)
        previous.shutdown()

        if self._own_inbox is not None:
            try:
                self.backend.register_mailbox(self._own_inbox)
            except Exception:
                pass
            try:
                prekeys = self.store.load_prekeys(self.identity_id)
                if prekeys:
                    self._publish_bundle(prekeys)
            except Exception:
                pass
        if self._card is not None and self._own_inbox is not None and self._bundle_id:
            self._card = ContactCard.create(
                self.identity, self._bundle_id, self._own_inbox, self.relays, self.name
            )

    # -- contacts ---------------------------------------------------------

    def add_contact(self, card_string: str, nickname: str | None = None) -> dict:
        try:
            card = ContactCard.from_string(card_string)
        except CardError as exc:
            raise ClientError(f"invalid contact card: {exc}") from exc
        if card.identity_id == self.identity_id:
            raise ClientError("cannot add your own card as a contact")
        return self._store_card(card, nickname)

    def _store_card(
        self, card: ContactCard, nickname: str | None = None, session: dict | None = None
    ) -> dict:
        existing = self.store.get_contact(self.identity_id, card.identity_id)
        contact = {
            "id": card.identity_id,
            "identity_id": self.identity_id,
            "nickname": nickname
            or (existing["nickname"] if existing else None)
            or card.name
            or card.identity_id[:8],
            "isign": card.isign,
            "idh": card.idh,
            "bundle_id": card.bundle_id,
            "inbox": card.inbox.card_view(),
            "relays": card.relays,
            "session": session
            if session is not None
            else (existing["session"] if existing else None),
            "verified": bool(existing["verified"]) if existing else False,
            "created_at": existing["created_at"] if existing else time.time(),
        }
        self.store.upsert_contact(self.identity_id, contact)
        return self.store.get_contact(self.identity_id, card.identity_id) or contact

    def list_contacts(self) -> list[dict]:
        return self.store.list_contacts(self.identity_id)

    def remove_contact(self, contact_id: str) -> None:
        self.store.delete_contact(self.identity_id, contact_id)

    def _require_contact(self, contact_id: str) -> dict:
        contact = self.store.get_contact(self.identity_id, contact_id)
        if contact is None:
            raise UnknownContact(contact_id)
        return contact

    # -- sessions ---------------------------------------------------------
    #
    # A contact may have several devices, each with its own mailbox and its own
    # Double Ratchet session. Sessions are therefore keyed by device id. The
    # stored blob is either the v2 container below or a bare v1 session, which
    # is read as the legacy device so existing contacts keep working.

    def _load_state(self, contact: dict) -> dict:
        """Session state for a contact.

        ``outbound`` sessions are keyed by the *peer's* device id, ``inbound``
        ones by *our* device id. They are kept apart on purpose: sharing one map
        let a receipt write clobber the very session needed to read the reply.
        """
        raw = contact.get("session")
        if raw and raw.get("v") == 2:
            devices = []
            for data in raw.get("devices") or []:
                try:
                    devices.append(DeviceEntry.from_dict(data))
                except DeviceListError:
                    continue
            return {
                "devices": devices,
                "outbound": {
                    key: Session.from_dict(value)
                    for key, value in (raw.get("outbound") or {}).items()
                },
                "inbound": {
                    key: Session.from_dict(value)
                    for key, value in (raw.get("inbound") or {}).items()
                },
            }
        if raw:
            # v1 blob: a single session, always an outbound one.
            return {
                "devices": [],
                "outbound": {LEGACY_DEVICE: Session.from_dict(raw)},
                "inbound": {},
            }
        return {"devices": [], "outbound": {}, "inbound": {}}

    def _save_state(self, contact_id: str, state: dict) -> None:
        self.store.set_contact_session(
            self.identity_id,
            contact_id,
            {
                "v": 2,
                "devices": [device.to_dict() for device in state.get("devices", [])],
                "outbound": {
                    key: session.to_dict()
                    for key, session in state.get("outbound", {}).items()
                },
                "inbound": {
                    key: session.to_dict()
                    for key, session in state.get("inbound", {}).items()
                },
            },
        )

    def _cached_devices(self, contact: dict) -> list[DeviceEntry]:
        devices = self._load_state(contact)["devices"]
        return devices or [self._legacy_device(contact)]

    def _legacy_device(self, contact: dict) -> DeviceEntry:
        """The single inbox advertised in a contact card, pre-device-lists."""
        return DeviceEntry(
            device_id=LEGACY_DEVICE,
            inbox=contact["inbox"],
            relays=list(contact.get("relays") or []),
            bundle_id=contact["bundle_id"],
            name=contact.get("nickname") or "",
        )

    def _find_session(
        self, sid: bytes
    ) -> tuple[dict | None, dict | None, str | None, str | None, Session | None]:
        """Locate a session by its wire id across every contact and bucket."""
        for contact in self.store.list_contacts(self.identity_id):
            state = self._load_state(contact)
            for bucket in ("outbound", "inbound"):
                for key, session in state[bucket].items():
                    if session.sid == sid:
                        return contact, state, bucket, key, session
        return None, None, None, None, None

    def _fetch_peer_device_list(self, contact: dict) -> DeviceList | None:
        address = device_list_id(contact["isign"], contact["idh"])
        try:
            payload = self._backend_for(contact.get("relays")).fetch_bundle(address)
        except Exception:
            return None
        try:
            listing = open_device_list(payload, contact["isign"], contact["idh"])
        except DeviceListError:
            return None
        if not listing.belongs_to(contact["id"], contact["isign"], contact["idh"]):
            return None
        return listing

    def _peer_devices(self, contact: dict) -> list[DeviceEntry]:
        """The peer's devices, freshly fetched, else the last known set."""
        listing = self._fetch_peer_device_list(contact)
        if listing is not None:
            return listing.devices
        return self._cached_devices(contact)

    def _fetch_device_bundle(self, contact: dict, device: DeviceEntry) -> PrekeyBundle:
        try:
            payload = self._backend_for(device.relays).fetch_bundle(device.bundle_id)
        except Exception as exc:
            raise ClientError(f"could not fetch prekey bundle: {exc}") from exc
        try:
            return PrekeyBundle.from_public(payload, contact["isign"], contact["idh"])
        except Exception as exc:
            raise ClientError(f"invalid prekey bundle: {exc}") from exc

    def _start_session(self, contact: dict, device: DeviceEntry) -> Session:
        bundle = self._fetch_device_bundle(contact, device)
        initiation = x3dh.initiate(bundle, contact["isign"], contact["idh"])
        return Session(
            sid=os.urandom(16),
            ratchet=Ratchet.initiator(initiation.sk, bundle.spk),
            sk=initiation.sk,
            init=initiation.init_dict(),
            established=False,
        )

    def _ensure_outbound_sessions(
        self, contact: dict, state: dict
    ) -> list[DeviceEntry]:
        """One outbound session per device of the peer, creating any missing."""
        devices = self._peer_devices(contact)
        if not devices:
            devices = [self._legacy_device(contact)]
        outbound = state["outbound"]
        for device in devices:
            if device.device_id not in outbound:
                outbound[device.device_id] = self._start_session(contact, device)
        # Sessions for devices the peer no longer advertises are kept, not
        # deleted: a stale list must never destroy history.
        return devices

    # -- sending ----------------------------------------------------------

    def _device_capability(self, device: DeviceEntry) -> MailboxCapability:
        """The write capability for one device's mailbox."""
        return MailboxCapability.from_card_view(device.inbox)

    def _backend_for(self, relays: list[str] | None) -> MultiRelayBackend:
        """A backend that can reach a peer, using the relays from *their* card.

        This is what makes relaying federated: two people configured with
        different relays can still talk, because each side delivers to the
        relays the other advertised. Anything touching our own mailbox still
        uses ``self.backend``.
        """
        urls = normalize_relay_urls(list(relays or []))
        if not urls:
            # Cards predating the relay list: fall back to our own relays.
            return self.backend
        key = tuple(urls)
        if key == tuple(self.relays):
            return self.backend
        backend = self._peer_backends.get(key)
        if backend is None:
            backend = MultiRelayBackend(urls, transport=self.backend.transport)
            self._peer_backends[key] = backend
        return backend

    def _send_envelope(
        self,
        contact: dict,
        device: DeviceEntry,
        session: Session,
        envelope: dict,
        kind: str,
    ) -> bytes:
        envelope = dict(envelope)
        init = None
        if session.is_pending:
            if session.sk is None or session.init is None:
                raise ClientError("pending session is missing handshake material")
            init = session.init
            envelope["auth"] = x3dh.build_auth(
                self.identity, session.sid, session.init, session.sk
            )
            envelope["card"] = self.card.signed_dict()
        blob = seal(
            session.ratchet,
            envelope,
            session.sid,
            init=init,
            max_size=envelope_max_size(kind),
        )
        self._backend_for(device.relays).put(self._device_capability(device), blob)
        return blob

    def _fan_out(
        self,
        contact: dict,
        devices: list[DeviceEntry],
        sessions: dict[str, Session],
        envelope_for,
        kind: str,
    ) -> list[tuple[DeviceEntry, bytes]]:
        """Deliver one copy per device, sealed with that device's own session.

        ``envelope_for(device)`` builds the plaintext for one device, so a file
        transfer can carry that device's own chunk ids.
        """
        results = []
        for device in devices:
            session = sessions[device.device_id]
            blob = self._send_envelope(
                contact, device, session, envelope_for(device), kind
            )
            results.append((device, blob))
        return results

    def send_text(self, contact_id: str, text: str) -> str:
        self._ensure_provisioned()
        contact = self._require_contact(contact_id)
        state = self._load_state(contact)
        devices = self._ensure_outbound_sessions(contact, state)
        state["devices"] = devices
        message_id = _new_id()
        envelope = make_envelope("text", {"text": text}, message_id, _now_ms())
        blobs = self._fan_out(
            contact, devices, state["outbound"], lambda device: envelope, "text"
        )
        self._save_state(contact_id, state)
        self.store.add_message(
            {
                "id": message_id,
                "identity_id": self.identity_id,
                "contact_id": contact_id,
                "direction": "sent",
                "type": "text",
                "body": {"text": text},
                "remote_id": None,
                "ts": _now_ms(),
                "state": "sent",
                "meta": None,
            }
        )
        for device, blob in blobs:
            self._queue_outbox(contact, device, message_id, blob)
        return message_id

    def send_file(self, contact_id: str, path: str, caption: str = "") -> str:
        self._ensure_provisioned()
        contact = self._require_contact(contact_id)
        state = self._load_state(contact)
        devices = self._ensure_outbound_sessions(contact, state)
        state["devices"] = devices
        with open(path, "rb") as handle:
            data = handle.read()
        attachment = encrypt_attachment(data)
        name = os.path.basename(path)
        mime = mimetypes.guess_type(path)[0] or "application/octet-stream"

        # Each device's mailbox needs its own chunk ids, so the manifest is built
        # per device and travels inside that device's copy of the message.
        bodies: dict[str, dict] = {}
        for device in devices:
            backend = self._backend_for(device.relays)
            capability = self._device_capability(device)
            chunk_ids = [
                backend.put_blob(capability, chunk.ciphertext)
                for chunk in attachment.chunks
            ]
            manifest = manifest_dict(attachment, chunk_ids)
            manifest["name"] = name
            manifest["mime"] = mime
            bodies[device.device_id] = {"caption": caption, "attachment": manifest}
        # Keep our own copy under the manifest we recorded locally, so the file
        # stays downloadable after the relay drops it and can travel with a
        # history transfer to another device.
        for entry, chunk in zip(
            bodies[devices[0].device_id]["attachment"]["chunks"], attachment.chunks
        ):
            self.store.put_local_blob(str(entry["id"]), chunk.ciphertext)

        message_id = _new_id()
        blobs = self._fan_out(
            contact,
            devices,
            state["outbound"],
            lambda device: make_envelope(
                "file", bodies[device.device_id], message_id, _now_ms()
            ),
            "file",
        )
        self._save_state(contact_id, state)
        body = bodies[devices[0].device_id]
        self.store.add_message(
            {
                "id": message_id,
                "identity_id": self.identity_id,
                "contact_id": contact_id,
                "direction": "sent",
                "type": "file",
                "body": body,
                "remote_id": None,
                "ts": _now_ms(),
                "state": "sent",
                "meta": None,
            }
        )
        for device, blob in blobs:
            self._queue_outbox(contact, device, message_id, blob)
        return message_id

    def _queue_outbox(
        self, contact: dict, device: DeviceEntry, message_id: str, blob: bytes
    ) -> None:
        self.store.outbox_add(
            {
                # One row per device copy. The message id is the prefix, so the
                # receipt for a message clears every device's row.
                "id": f"{message_id}:{device.device_id}",
                "identity_id": self.identity_id,
                "contact_id": contact["id"],
                "mailbox_id": device.inbox["id"],
                "relay": ",".join(device.relays),
                "payload": b64e(blob),
                "seq": 1,  # already accepted by at least one relay
                "created_at": time.time(),
            }
        )

    def flush_outbox(self) -> int:
        """Re-send messages that no relay accepted. Returns the count re-sent."""
        sent = 0
        for entry in self.store.outbox_list(self.identity_id):
            if entry.get("seq"):
                continue
            contact = self.store.get_contact(self.identity_id, entry["contact_id"])
            if contact is None:
                continue
            device = next(
                (
                    candidate
                    for candidate in self._cached_devices(contact)
                    if candidate.inbox.get("id") == entry["mailbox_id"]
                ),
                None,
            )
            if device is None:
                continue
            try:
                self._backend_for(device.relays).put(
                    self._device_capability(device), b64d(entry["payload"])
                )
                self.store.outbox_mark_sent(entry["id"])
                sent += 1
            except Exception:
                continue
        return sent

    # -- receiving --------------------------------------------------------

    def sync(self, wait: int = 0) -> list[dict]:
        self._ensure_provisioned()
        assert self._own_inbox is not None
        capability = self._own_inbox
        fetched = self.backend.fetch(capability, cursors={}, wait=wait)
        new_messages: list[dict] = []
        max_seq: dict[str, int] = {}
        for item in fetched:
            max_seq[item.relay] = max(max_seq.get(item.relay, 0), item.seq)
            try:
                message = self._handle_blob(item.blob)
            except Exception:
                message = None
            if message:
                new_messages.append(message)
        if max_seq:
            self.backend.ack(capability, max_seq)
        return new_messages

    def _handle_blob(self, blob: bytes) -> dict | None:
        wire = parse_wire(blob)
        sid = b64d(wire["sid"])
        contact, state, bucket, key, session = self._find_session(sid)

        fresh = False
        pending_opk: int | None = None
        if session is None:
            if "init" not in wire:
                return None
            started = self._begin_inbound(wire)
            if started is None:
                return None
            session, pending_opk = started
            fresh = True

        try:
            envelope, _sid, _init = unseal(session.ratchet, blob)
        except WireError:
            return None

        if fresh:
            contact = self._finish_inbound(session, envelope, pending_opk)
            if contact is None:
                return None
            # The peer addressed our own inbox directly, so this session belongs
            # to this device.
            state = self._load_state(contact)
            bucket, key = "inbound", self._device_id or LEGACY_DEVICE
        else:
            assert contact is not None and state is not None
            if not session.established:
                session.established = True
                session.sk = None

        assert contact is not None and state is not None
        assert bucket is not None and key is not None
        state[bucket][key] = session
        self._save_state(contact["id"], state)
        return self._process_envelope(contact, envelope)

    def _begin_inbound(self, wire: dict) -> tuple[Session, int | None] | None:
        init = wire["init"]
        prekeys = self.store.load_prekeys(self.identity_id)
        if not prekeys:
            return None
        if int(init["spk_id"]) != int(prekeys["spk_id"]):
            return None
        opk_id = init.get("opk_id")
        opk_private = None
        if opk_id is not None:
            entry = prekeys["opks"].get(str(opk_id))
            if entry is None:
                return None  # already consumed: one-time prekey is spent
            opk_private = b64d(entry["priv"])
        try:
            session_key = x3dh.respond(
                self.identity.x_private_bytes,
                b64d(prekeys["spk_private"]),
                opk_private,
                b64d(init["ek"]),
            )
        except Exception:
            return None
        session = Session(
            sid=b64d(wire["sid"]),
            ratchet=Ratchet.responder(
                session_key,
                b64d(prekeys["spk_private"]),
                b64d(prekeys["spk_public"]),
            ),
            sk=session_key,
            init=init,
            established=False,
        )
        return session, opk_id

    def _finish_inbound(
        self, session: Session, envelope: dict, opk_id: int | None
    ) -> dict | None:
        auth = envelope.get("auth")
        card_dict = envelope.get("card")
        if not isinstance(auth, dict) or not isinstance(card_dict, dict):
            return None
        if session.sk is None or session.init is None:
            return None
        if not x3dh.verify_auth(auth, session.sid, session.init, session.sk):
            return None
        try:
            card = ContactCard.from_dict(card_dict)
        except CardError:
            return None
        if card.identity_id != auth.get("id"):
            return None
        if card.isign != b64d(auth["isign"]):
            return None

        contact = self._store_card(card)
        self._consume_opk(opk_id)
        session.established = True
        session.sk = None
        return contact

    def _consume_opk(self, opk_id: int | None) -> None:
        if opk_id is None:
            return
        prekeys = self.store.load_prekeys(self.identity_id)
        if not prekeys:
            return
        if prekeys["opks"].pop(str(opk_id), None) is not None:
            self.store.save_prekeys(self.identity_id, prekeys)

    def _process_envelope(
        self,
        contact: dict,
        envelope: dict,
    ) -> dict | None:
        kind = envelope.get("type")
        envelope_id = envelope.get("id")
        body = envelope.get("body") or {}

        if kind in ("text", "file"):
            if not envelope_id:
                return None
            if self.store.find_by_remote_id(
                self.identity_id, envelope_id, direction="received"
            ):
                return None
            message = {
                "id": _new_id(),
                "identity_id": self.identity_id,
                "contact_id": contact["id"],
                "direction": "received",
                "type": kind,
                "body": body,
                "remote_id": envelope_id,
                "ts": int(envelope.get("ts") or _now_ms()),
                "state": "received",
                "meta": None,
            }
            self.store.add_message(message)
            self._send_receipt(contact, envelope_id, kind="delivered")
            return self.store.get_message(message["id"])

        if kind == "receipt":
            target = body.get("of")
            if target:
                state = body.get("kind") or "read"
                self.store.update_message(target, state=state)
                # One row per device copy, all prefixed by the message id.
                self.store.outbox_remove_for_message(target)
            return None

        return None

    def _send_receipt(
        self, contact: dict, of_id: str, kind: str = "delivered"
    ) -> None:
        """Tell every device of the peer that we opened its copy of a message."""
        envelope = make_envelope(
            "receipt", {"of": of_id, "kind": kind}, _new_id(), _now_ms()
        )
        try:
            # Re-read: the caller's dict may predate a session saved moments ago
            # (a stale row would rewrite the store and drop that session).
            contact = self.store.get_contact(self.identity_id, contact["id"]) or contact
            state = self._load_state(contact)
            devices = self._ensure_outbound_sessions(contact, state)
            state["devices"] = devices
            self._fan_out(
                contact, devices, state["outbound"], lambda device: envelope, "receipt"
            )
            self._save_state(contact["id"], state)
        except Exception:
            # A receipt is best effort: never let it fail the message it acks.
            pass

    def mark_read(self, contact_id: str, message_id: str) -> None:
        contact = self._require_contact(contact_id)
        message = self.store.get_message(message_id)
        if message is None:
            raise ClientError(f"unknown message: {message_id}")
        # The peer knows this message by *its* envelope id, which we recorded as
        # remote_id; referencing our local id would be meaningless to them.
        target = message.get("remote_id") or message_id
        self._send_receipt(contact, target, kind="read")

    # -- reading ----------------------------------------------------------

    def messages(self, contact_id: str) -> list[dict]:
        return self.store.list_messages(self.identity_id, contact_id)

    def download_attachment(self, message: dict) -> bytes:
        self._ensure_provisioned()
        manifest = (message.get("body") or {}).get("attachment")
        if not manifest:
            raise AttachmentError("message has no attachment")
        key, chunk_ids, nonces, expected_hash = decode_manifest(manifest)
        assert self._own_inbox is not None
        ciphertexts = []
        for chunk_id in chunk_ids:
            cached = self.store.get_local_blob(chunk_id)
            if cached is None:
                cached = self.backend.get_blob(self._own_inbox, chunk_id)
                self.store.put_local_blob(chunk_id, cached)
            ciphertexts.append(cached)
        return decrypt_attachment(key, nonces, ciphertexts, expected_hash)

    def close(self) -> None:
        for backend in self._peer_backends.values():
            backend.close()
        self._peer_backends.clear()
        self.backend.close()