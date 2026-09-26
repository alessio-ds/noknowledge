"""History bundles: one format for export files and device back-fill.

A bundle is the portable form of "what this account knows": contacts, messages
and the attachment ciphertext we hold locally. It is used twice, with the same
merge rules and therefore the same guarantees:

* as an **encrypted export file** the user can move between machines;
* as the **item stream** a device sends to a sibling when back-filling history.

Nothing here talks to a relay: a bundle is plaintext-in-memory until the caller
seals it (a passphrase-derived key for a file, a device channel key for a
transfer). Attachments are already AEAD-sealed for their recipient, so their
ciphertext travels as-is and is stored in the local cache under the same chunk
ids the message manifest already references — no manifest rewriting.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import zlib
from typing import Any

from noknowledge.crypto.aead import AEADError, decrypt, encrypt
from noknowledge.crypto.encoding import b64d, b64e, canonical_json

HISTORY_VERSION = 1

#: Bytes at the start of an export file, so we can tell one apart from anything
#: else the user might pick in a file dialog.
HISTORY_MAGIC = b"NKX1"

#: Default ceiling on attachment bytes carried by one bundle.
DEFAULT_BUDGET_BYTES = 100 * 1024 * 1024

#: Matching the identity vault: the export is only as strong as its passphrase.
PBKDF2_ITERATIONS = 600_000

#: Message states, ranked so a merge can never resurrect "unread".
_STATE_RANK = {"received": 0, "sent": 0, None: 0, "delivered": 1, "read": 2}


class HistoryError(Exception):
    """Raised when a bundle or export file is malformed or unreadable."""


# -- collection ------------------------------------------------------------


def _contact_item(contact: dict) -> dict:
    return {
        "id": contact["id"],
        "isign": b64e(contact["isign"]),
        "idh": b64e(contact["idh"]),
        "bundle": contact.get("bundle_id"),
        "inbox": contact.get("inbox") or {},
        "relays": list(contact.get("relays") or []),
        "nickname": contact.get("nickname"),
        "verified": bool(contact.get("verified")),
        "created_at": int(contact.get("created_at") or 0),
    }


def _message_item(contact_id: str, message: dict) -> dict:
    return {
        "contact_id": contact_id,
        "direction": message["direction"],
        "type": message["type"],
        "body": message.get("body"),
        "remote_id": message.get("remote_id"),
        "ts": int(message.get("ts") or 0),
        "state": message.get("state"),
    }


def _body_digest(body: Any) -> str:
    try:
        raw = canonical_json(body if body is not None else {})
    except TypeError:
        raw = json.dumps(body, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def message_key(item: dict) -> tuple:
    """Identity of a message for dedup, shared by both clients.

    A message that crossed the wire is identified by the sender's envelope id.
    One that never did (our own copy, or an import of an older one) falls back to
    who it was with, when, and what it said.
    """
    remote_id = item.get("remote_id")
    if remote_id:
        return ("r", item.get("contact_id"), item.get("direction"), str(remote_id))
    return (
        "l",
        item.get("contact_id"),
        item.get("direction"),
        int(item.get("ts") or 0),
        str(item.get("type")),
        _body_digest(item.get("body")),
    )


def build_bundle(
    client,
    *,
    since_ms: int | None = None,
    until_ms: int | None = None,
    budget_bytes: int = DEFAULT_BUDGET_BYTES,
    include_attachments: bool = True,
) -> dict:
    """Collect this device's history for the given window.

    Attachments are added oldest-first until ``budget_bytes`` is reached; the
    rest are listed under ``skipped`` so a caller can say what is missing instead
    of silently dropping it.
    """
    identity_id = client.identity_id
    until_ms = int(until_ms if until_ms is not None else time.time() * 1000)
    since_ms = int(since_ms or 0)

    contacts = [
        _contact_item(contact) for contact in client.store.list_contacts(identity_id)
    ]
    messages: list[dict] = []
    for message in client.store.list_all_messages(identity_id):
        if since_ms <= int(message.get("ts") or 0) <= until_ms:
            messages.append(_message_item(message["contact_id"], message))

    chunks: list[dict] = []
    skipped: list[dict] = []
    if include_attachments:
        seen: set[str] = set()
        used = 0
        for item in messages:
            attachment = (item.get("body") or {}).get("attachment") or {}
            for entry in attachment.get("chunks") or []:
                chunk_id = str(entry.get("id"))
                if not chunk_id or chunk_id in seen:
                    continue
                seen.add(chunk_id)
                ciphertext = client.store.get_local_blob(chunk_id)
                if ciphertext is None:
                    skipped.append({"id": chunk_id, "reason": "not held here"})
                    continue
                if used + len(ciphertext) > budget_bytes:
                    skipped.append({"id": chunk_id, "reason": "over budget"})
                    continue
                used += len(ciphertext)
                chunks.append({"id": chunk_id, "ct": b64e(ciphertext)})

    return {
        "v": HISTORY_VERSION,
        "created": int(time.time() * 1000),
        "from_device": client.device_id() or "legacy",
        "range": {"since": since_ms, "until": until_ms},
        "contacts": contacts,
        "messages": messages,
        "chunks": chunks,
        "skipped": skipped,
    }


def encode_bundle(bundle: dict) -> bytes:
    return canonical_json(bundle)


def decode_bundle(data: bytes | str) -> dict:
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    try:
        bundle = json.loads(data)
    except json.JSONDecodeError as exc:
        raise HistoryError("history bundle is not valid JSON") from exc
    if not isinstance(bundle, dict) or bundle.get("v") != HISTORY_VERSION:
        raise HistoryError("unsupported history bundle version")
    for field in ("contacts", "messages", "chunks"):
        if not isinstance(bundle.get(field), list):
            raise HistoryError(f"history bundle is missing {field}")
    return bundle


# -- merge -----------------------------------------------------------------


def _merge_contact(client, item: dict) -> bool:
    identity_id = client.identity_id
    contact_id = str(item.get("id") or "")
    if not contact_id:
        return False
    existing = client.store.get_contact(identity_id, contact_id)
    if existing is not None:
        # Routing is kept as it is: live traffic already keeps our view of the
        # peer's card fresh, and a stale bundle must not point delivery backwards.
        return False
    try:
        client.store.upsert_contact(
            identity_id,
            {
                "id": contact_id,
                "identity_id": identity_id,
                "nickname": item.get("nickname"),
                "isign": b64d(str(item["isign"])),
                "idh": b64d(str(item["idh"])),
                "bundle_id": item.get("bundle"),
                "inbox": item.get("inbox") or {},
                "relays": list(item.get("relays") or []),
                "session": None,
                "verified": bool(item.get("verified")),
                "created_at": int(item.get("created_at") or time.time()),
            },
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise HistoryError("malformed contact in history bundle") from exc
    return True


def merge_bundle(client, bundle: dict) -> dict:
    """Merge a bundle into the local store. Idempotent."""
    identity_id = client.identity_id
    counts = {"contacts": 0, "messages": 0, "updates": 0, "chunks": 0}

    for item in bundle.get("contacts") or []:
        if _merge_contact(client, item):
            counts["contacts"] += 1

    # Index what we already have, once, so a large bundle stays linear.
    known: dict[tuple, dict] = {}
    for contact in client.store.list_contacts(identity_id):
        for message in client.store.list_messages(identity_id, contact["id"]):
            known[message_key(message)] = message

    for item in bundle.get("messages") or []:
        if not item.get("contact_id"):
            continue
        key = message_key(item)
        existing = known.get(key)
        if existing is not None:
            incoming = item.get("state")
            if _STATE_RANK.get(incoming, 0) > _STATE_RANK.get(existing.get("state"), 0):
                client.store.update_message(existing["id"], state=incoming)
                counts["updates"] += 1
            continue
        message_id = os.urandom(16).hex()
        client.store.add_message(
            {
                "id": message_id,
                "identity_id": identity_id,
                "contact_id": item["contact_id"],
                "direction": item.get("direction") or "received",
                "type": item.get("type") or "text",
                "body": item.get("body"),
                "remote_id": item.get("remote_id"),
                "ts": int(item.get("ts") or 0),
                "state": item.get("state"),
                "meta": None,
            }
        )
        known[key] = client.store.get_message(message_id)
        counts["messages"] += 1

    for chunk in bundle.get("chunks") or []:
        chunk_id = str(chunk.get("id") or "")
        if not chunk_id:
            continue
        try:
            ciphertext = b64d(str(chunk["ct"]))
        except Exception as exc:
            raise HistoryError("malformed attachment chunk in history bundle") from exc
        if not client.store.has_local_blob(chunk_id):
            client.store.put_local_blob(chunk_id, ciphertext)
            counts["chunks"] += 1

    return counts


# -- encrypted export file -------------------------------------------------
#
# Layout: magic | version | u32 header length | header | nonce | ciphertext
# The header is cleartext so a reader knows the KDF parameters before unlocking;
# it carries no identity, no contact and no content.


def _export_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    from noknowledge.core.store import derive_key_from_passphrase

    return derive_key_from_passphrase(passphrase, salt, iterations)


def export_history(
    client,
    passphrase: str,
    *,
    since_ms: int | None = None,
    until_ms: int | None = None,
    budget_bytes: int = DEFAULT_BUDGET_BYTES,
    include_attachments: bool = True,
) -> bytes:
    if not passphrase:
        raise HistoryError("a passphrase is required to export history")
    bundle = build_bundle(
        client,
        since_ms=since_ms,
        until_ms=until_ms,
        budget_bytes=budget_bytes,
        include_attachments=include_attachments,
    )
    salt = os.urandom(16)
    iterations = PBKDF2_ITERATIONS
    key = _export_key(passphrase, salt, iterations)
    header = {
        "v": HISTORY_VERSION,
        "created": bundle["created"],
        "kdf": {"salt": b64e(salt), "iterations": iterations},
        "counts": {
            "contacts": len(bundle["contacts"]),
            "messages": len(bundle["messages"]),
            "chunks": len(bundle["chunks"]),
            "skipped": len(bundle["skipped"]),
        },
    }
    header_bytes = canonical_json(header)
    plaintext = zlib.compress(encode_bundle(bundle), 9)
    nonce, ciphertext = encrypt(key, plaintext, ad=HISTORY_MAGIC)
    return b"".join(
        [
            HISTORY_MAGIC,
            bytes([HISTORY_VERSION]),
            len(header_bytes).to_bytes(4, "big"),
            header_bytes,
            nonce,
            ciphertext,
        ]
    )


def is_history_file(data: bytes) -> bool:
    return data[: len(HISTORY_MAGIC)] == HISTORY_MAGIC


def read_export_header(data: bytes) -> dict:
    """The cleartext header of an export file, for showing counts before import."""
    if not is_history_file(data):
        raise HistoryError("not a noknowledge history file")
    try:
        version = data[4]
        length = int.from_bytes(data[5:9], "big")
        header = json.loads(data[9 : 9 + length].decode("utf-8"))
    except (IndexError, ValueError) as exc:
        raise HistoryError("history file is truncated") from exc
    if version != HISTORY_VERSION or header.get("v") != HISTORY_VERSION:
        raise HistoryError("unsupported history file version")
    return header


def import_history(client, data: bytes, passphrase: str) -> dict:
    header = read_export_header(data)
    if not passphrase:
        raise HistoryError("this history file needs its passphrase")
    try:
        kdf = header["kdf"]
        salt = b64d(str(kdf["salt"]))
        iterations = int(kdf["iterations"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HistoryError("malformed history file header") from exc

    length = int.from_bytes(data[5:9], "big")
    body = data[9 + length :]
    if len(body) <= 12:
        raise HistoryError("history file is truncated")
    key = _export_key(passphrase, salt, iterations)
    try:
        plaintext = decrypt(key, body[:12], body[12:], ad=HISTORY_MAGIC)
    except AEADError as exc:
        raise HistoryError("wrong passphrase, or the file is damaged") from exc
    try:
        bundle = decode_bundle(zlib.decompress(plaintext))
    except zlib.error as exc:
        raise HistoryError("history file is damaged") from exc
    return merge_bundle(client, bundle)