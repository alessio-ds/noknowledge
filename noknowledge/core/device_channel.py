"""The device-to-device channel.

Two devices of one account talk directly, through each other's mailboxes, with a
key nobody else holds — not the relay, and not the account's contacts.

Every record is sealed with ECIES: the sender generates an ephemeral X25519 key,
agrees it with the recipient device's published agreement key, and derives a
one-purpose key from that secret. The record header is signed by the sender's
device key, so the recipient can tell which device spoke and check that it really
is a device of this account (the account signature in the device-key record is
what authorises it).

Records are store-and-forward, so a sibling that is offline simply finds them in
its mailbox later. Nothing here is readable by a relay: it sees mailbox writes of
a given size, like any other message.
"""

from __future__ import annotations

import hashlib
import os
import time

from noknowledge.crypto import devicekeys
from noknowledge.crypto.encoding import b64d, b64e, canonical_json
from noknowledge.crypto.kdf import DEVICE_SYNC_INFO, DEVICE_SYNC_ITEM_INFO, hkdf

MAGIC = b"NKS1"
VERSION = 1
#: magic(4) + version(1) + kind(1) + reserved(2) + header length(4)
PREFIX_BYTES = 12

#: Record kinds. Numbers are wire-visible: never renumber one.
REQUEST = 1
OFFER = 2
ITEM = 3
COMPLETE = 4
APPROVAL = 5
MIRROR = 6

KIND_NAMES = {
    REQUEST: "request",
    OFFER: "offer",
    ITEM: "item",
    COMPLETE: "complete",
    APPROVAL: "approval",
    MIRROR: "mirror",
}

#: Largest record we will emit or accept, before base64 expansion.
MAX_RECORD_BYTES = 4 * 1024 * 1024


class SyncError(Exception):
    """Raised for malformed, unsigned or undecryptable device records."""


def is_device_record(blob: bytes) -> bool:
    return len(blob) >= PREFIX_BYTES and blob[:4] == MAGIC


def _frame(kind: int, header: dict, payload: bytes) -> bytes:
    header_bytes = canonical_json(header)
    return b"".join(
        [
            MAGIC,
            bytes([VERSION, kind]),
            b"\x00\x00",
            len(header_bytes).to_bytes(4, "big"),
            header_bytes,
            payload,
        ]
    )


def parse_record(blob: bytes) -> tuple[int, dict, bytes]:
    """Split a record into ``(kind, header, payload)`` without authenticating it."""
    if not is_device_record(blob):
        raise SyncError("not a device record")
    version = blob[4]
    if version != VERSION:
        raise SyncError(f"unsupported device record version: {version}")
    kind = blob[5]
    header_len = int.from_bytes(blob[8:12], "big")
    if header_len <= 0 or len(blob) < PREFIX_BYTES + header_len:
        raise SyncError("device record is truncated")
    import json

    try:
        header = json.loads(blob[PREFIX_BYTES : PREFIX_BYTES + header_len].decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise SyncError("device record header is malformed") from exc
    if not isinstance(header, dict):
        raise SyncError("device record header is not an object")
    return kind, header, blob[PREFIX_BYTES + header_len :]


def transfer_key(shared: bytes, transfer_id: str) -> bytes:
    return hkdf(shared, salt=transfer_id.encode("utf-8"), info=DEVICE_SYNC_INFO, length=32)


def item_key(key: bytes, seq: int) -> bytes:
    return hkdf(key, salt=b"", info=DEVICE_SYNC_ITEM_INFO + int(seq).to_bytes(4, "big"), length=32)


def new_transfer_id() -> str:
    return b64e(os.urandom(16))


def seal_record(
    kind: int,
    plaintext: bytes,
    *,
    recipient_sagree: bytes,
    sender_device_id: str,
    sender_sdev_private: bytes,
    transfer_id: str,
    seq: int = 0,
    extra: dict | None = None,
) -> bytes:
    """Seal one record for one recipient device."""
    from noknowledge.crypto.aead import encrypt

    ephemeral_private = devicekeys.new_agreement_private()
    shared = devicekeys.agreement(ephemeral_private, recipient_sagree)
    key = transfer_key(shared, transfer_id)

    header: dict = {
        "v": VERSION,
        "transfer": transfer_id,
        "from": sender_device_id,
        "eph": b64e(devicekeys.agreement_public(ephemeral_private)),
        "ts": int(time.time() * 1000),
        "seq": int(seq),
    }
    if extra:
        header.update(extra)
    header["sig"] = b64e(
        devicekeys.sign(sender_sdev_private, canonical_json(_unsigned(header)))
    )

    # The AEAD associated data is the signed header, so no field can be altered.
    ad = canonical_json(header)
    nonce, ciphertext = encrypt(item_key(key, seq), plaintext, ad=ad)
    return _frame(kind, header, nonce + ciphertext)


def _unsigned(header: dict) -> dict:
    return {key: value for key, value in header.items() if key != "sig"}


def open_record(
    blob: bytes,
    *,
    my_sagree_private: bytes,
    sender_sdev: bytes,
    sender_device_id: str,
) -> tuple[int, dict, bytes]:
    """Verify and decrypt a record from a sibling device."""
    from noknowledge.crypto.aead import AEADError, decrypt

    kind, header, payload = parse_record(blob)
    if str(header.get("from")) != sender_device_id:
        raise SyncError("device record is from an unexpected device")
    try:
        signature = b64d(str(header["sig"]))
        ephemeral = b64d(str(header["eph"]))
        transfer_id = str(header["transfer"])
        seq = int(header.get("seq") or 0)
    except (KeyError, TypeError, ValueError) as exc:
        raise SyncError("device record header is incomplete") from exc
    if not devicekeys.verify(sender_sdev, signature, canonical_json(_unsigned(header))):
        raise SyncError("device record signature is invalid")

    shared = devicekeys.agreement(my_sagree_private, ephemeral)
    key = transfer_key(shared, transfer_id)
    if len(payload) <= 12:
        raise SyncError("device record payload is truncated")
    ad = canonical_json(header)
    try:
        plaintext = decrypt(item_key(key, seq), payload[:12], payload[12:], ad=ad)
    except AEADError as exc:
        raise SyncError("device record could not be opened") from exc
    return kind, header, plaintext


class HashChain:
    """Ordered digest of the items in a transfer.

    Each item is authenticated on its own, so this exists to notice a transfer
    that stopped early: the sender's final digest only matches if every item
    arrived, in order. The running digest is a hex string between calls, which
    lets a receiver keep it in its store and resume across restarts.
    """

    def __init__(self, seed: str = "", resumed: str = "") -> None:
        self._digest = (
            bytes.fromhex(resumed)
            if resumed
            else hashlib.sha256(seed.encode("utf-8")).digest()
        )

    def add(self, item_bytes: bytes, seq: int) -> None:
        self._digest = hashlib.sha256(
            self._digest + int(seq).to_bytes(4, "big") + item_bytes
        ).digest()

    def hexdigest(self) -> str:
        return self._digest.hex()
