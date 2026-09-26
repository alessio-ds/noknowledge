"""Per-account device lists: the piece that makes seed recovery useful.

An **account** is an identity — the 24 words. A **device** is one mailbox plus
its own prekeys and its own ratchet sessions.

Devices cannot share a mailbox: whichever device polled first would consume the
message and ack it, and devices cannot share ratchet state because each would
advance the chain independently and diverge.

So each device registers itself in a signed **device list** stored at an address
anyone can derive from the account's *public* keys. A sender looks the list up,
gives each device its own Double Ratchet session, and delivers a copy to each.

Because the list lives at a publicly derivable address and is signed by the
account key, a freshly recovered device can fetch it, add itself, and start
receiving — with no coordination and no server support. The list is stored on a
relay using the existing prekey record endpoint, which is already a
public-read, operator-agnostic store for signed payloads.

The stored record is *sealed* under a key derived from the account's public
signing and agreement keys. Anyone holding the contact card can open it (they
have those keys), but the relay sees only an opaque box and so cannot group an
account's mailboxes together or link the record to an identity id.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

from noknowledge.crypto.aead import AEADError, decrypt, encrypt
from noknowledge.crypto.encoding import b64d, b64e, canonical_json
from noknowledge.crypto.identity import Identity, compute_identity_id
from noknowledge.crypto.kdf import (
    DEVICE_KEYS_ID_INFO,
    DEVICE_KEYS_SIGN_INFO,
    DEVICE_LIST_ENC_INFO,
    DEVICE_LIST_ID_INFO,
    DEVICE_SIGN_INFO,
    ZERO_SALT,
    hkdf,
)

DEVICE_LIST_VERSION = 1
DEVICE_ID_SIZE = 16

#: Key used for the single-device fallback when a peer has no device list yet
#: (an older client, or a contact added before this feature existed).
LEGACY_DEVICE = "legacy"


class DeviceListError(Exception):
    """Raised when a device list is malformed or fails verification."""


def device_list_id(ed_public: bytes, x_public: bytes) -> str:
    """Address of an account's device list, derivable by anyone from its keys."""
    digest = hashlib.sha256(DEVICE_LIST_ID_INFO + ed_public + x_public).digest()
    return b64e(digest[:16])


def new_device_id() -> str:
    import os

    return b64e(os.urandom(DEVICE_ID_SIZE))


def device_keys_id(ed_public: bytes, x_public: bytes, device_id: str) -> str:
    """Address of one device's sync key record.

    Kept out of the device list on purpose: the list's signed payload is rebuilt
    from its own fields, so adding a field would break verification for older
    clients and drop them back to single-device delivery.
    """
    digest = hashlib.sha256(
        DEVICE_KEYS_ID_INFO + ed_public + x_public + device_id.encode("utf-8")
    ).digest()
    return b64e(digest[:16])


@dataclass
class DeviceEntry:
    """One device's delivery address, as advertised to senders."""

    device_id: str
    inbox: dict
    relays: list[str]
    bundle_id: str
    name: str = ""

    def to_dict(self) -> dict:
        payload = {
            "device": self.device_id,
            "inbox": self.inbox,
            "relays": list(self.relays),
            "bundle": self.bundle_id,
        }
        if self.name:
            payload["name"] = self.name
        return payload

    @classmethod
    def from_dict(cls, data: dict) -> "DeviceEntry":
        try:
            return cls(
                device_id=str(data["device"]),
                inbox=dict(data["inbox"]),
                relays=[str(url) for url in data["relays"]],
                bundle_id=str(data["bundle"]),
                name=str(data.get("name") or ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise DeviceListError("malformed device entry") from exc


@dataclass
class DeviceList:
    account: str
    devices: list[DeviceEntry]
    updated: int
    isign: bytes
    idh: bytes
    signature: bytes = b""
    version: int = field(default=DEVICE_LIST_VERSION)

    # -- serialisation ----------------------------------------------------

    def address(self) -> str:
        return device_list_id(self.isign, self.idh)

    def payload(self) -> dict:
        return {
            "v": self.version,
            "account": self.account,
            "isign": b64e(self.isign),
            "idh": b64e(self.idh),
            # The relay's prekey endpoint requires a bundle_id field; the device
            # list address serves as one, which keeps the relay unchanged.
            "bundle_id": self.address(),
            "updated": int(self.updated),
            "devices": [device.to_dict() for device in self.devices],
        }

    def _signed_bytes(self) -> bytes:
        return DEVICE_SIGN_INFO + canonical_json(self.payload())

    def to_bytes(self) -> bytes:
        data = self.payload()
        data["sig"] = b64e(self.signature)
        return canonical_json(data)

    @classmethod
    def from_bytes(cls, data: bytes | str | dict) -> "DeviceList":
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError as exc:
                raise DeviceListError("device list is not valid JSON") from exc
        if not isinstance(data, dict):
            raise DeviceListError("device list is not an object")
        if data.get("v") != DEVICE_LIST_VERSION:
            raise DeviceListError(f"unsupported device list version: {data.get('v')}")
        try:
            isign = b64d(data["isign"])
            idh = b64d(data["idh"])
            account = str(data["account"])
            devices = [DeviceEntry.from_dict(entry) for entry in data["devices"]]
            updated = int(data["updated"])
            signature = b64d(data["sig"])
        except DeviceListError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise DeviceListError("malformed device list") from exc

        if compute_identity_id(isign, idh) != account:
            raise DeviceListError("device list account does not match its keys")
        if not devices:
            raise DeviceListError("device list has no devices")

        listing = cls(
            account=account,
            devices=devices,
            updated=updated,
            isign=isign,
            idh=idh,
            signature=signature,
        )
        if not Identity.verify(isign, signature, listing._signed_bytes()):
            raise DeviceListError("device list signature is invalid")
        return listing

    # -- construction -----------------------------------------------------

    @classmethod
    def create(
        cls, identity: Identity, devices: list[DeviceEntry], updated: int | None = None
    ) -> "DeviceList":
        listing = cls(
            account=identity.identity_id,
            devices=list(devices),
            updated=int(updated if updated is not None else time.time() * 1000),
            isign=identity.ed_public_bytes,
            idh=identity.x_public_bytes,
        )
        listing.signature = identity.sign(listing._signed_bytes())
        return listing

    def with_device(self, entry: DeviceEntry) -> "DeviceList":
        """A copy of this list with ``entry`` added or replaced."""
        others = [d for d in self.devices if d.device_id != entry.device_id]
        return DeviceList(
            account=self.account,
            devices=others + [entry],
            updated=int(time.time() * 1000),
            isign=self.isign,
            idh=self.idh,
        )

    def belongs_to(self, account: str, isign: bytes, idh: bytes) -> bool:
        """Whether this list is really the one for the peer we asked about."""
        return self.account == account and self.isign == isign and self.idh == idh


# -- sealed storage -------------------------------------------------------
#
# The record the relay holds must not tie an identity id to a set of mailboxes.
# The key is derived from public values the peer already has, so this is
# obfuscation against the relay, not secrecy against the peer.


def device_list_key(isign: bytes, idh: bytes) -> bytes:
    """Sealing key for one account's device list, from its public keys."""
    return hkdf(isign + idh, salt=ZERO_SALT, info=DEVICE_LIST_ENC_INFO, length=32)


def seal_device_list(listing: "DeviceList") -> bytes:
    """The opaque record to publish on a relay."""
    return seal_payload(listing.isign, listing.idh, listing.address(), listing.to_bytes())


def open_device_list(
    data: bytes | str | dict, isign: bytes, idh: bytes
) -> "DeviceList":
    """Open a device-list record fetched from a relay."""
    raw = data
    if isinstance(raw, (bytes, str)):
        # An unsealed record (older or handcrafted) is still read.
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DeviceListError("device list is not valid JSON") from exc
        if isinstance(parsed, dict) and parsed.get("box") is None:
            return DeviceList.from_bytes(parsed)
    return DeviceList.from_bytes(open_payload(raw, isign, idh))


def seal_payload(isign: bytes, idh: bytes, address: str, plaintext: bytes) -> bytes:
    """The opaque record to publish on a relay for any account-signed payload."""
    nonce, ciphertext = encrypt(device_list_key(isign, idh), plaintext)
    return canonical_json(
        {
            "v": DEVICE_LIST_VERSION,
            # The prekey endpoint keys its rows by this field, so it has to stay
            # visible; it is a public hash, nothing more.
            "bundle_id": address,
            "box": b64e(nonce + ciphertext),
        }
    )


def open_payload(data: bytes | str | dict, isign: bytes, idh: bytes) -> bytes:
    """Open a record fetched from a relay, using the peer's public keys."""
    if isinstance(data, bytes):
        raw: object = data.decode("utf-8")
    else:
        raw = data
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise DeviceListError("record is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise DeviceListError("record is not an object")
    box = raw.get("box")
    if box is None:
        raise DeviceListError("record is not sealed")
    try:
        blob = b64d(str(box))
    except Exception as exc:
        raise DeviceListError("record box is not valid base64") from exc
    if len(blob) <= 12:
        raise DeviceListError("record box is truncated")
    try:
        return decrypt(device_list_key(isign, idh), blob[:12], blob[12:])
    except AEADError as exc:
        raise DeviceListError("record could not be opened") from exc


def open_signed_payload(data: bytes | str | dict, isign: bytes, idh: bytes) -> dict:
    """Open any account-signed record, sealed or (legacy) plain."""
    raw = data
    if isinstance(raw, (bytes, str)):
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DeviceListError("record is not valid JSON") from exc
        if isinstance(parsed, dict) and parsed.get("box") is None:
            return parsed
    try:
        plaintext = open_payload(raw, isign, idh)
    except DeviceListError:
        raise
    try:
        opened = json.loads(plaintext.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise DeviceListError("record could not be parsed") from exc
    if not isinstance(opened, dict):
        raise DeviceListError("record is not an object")
    return opened


@dataclass
class DeviceKeys:
    """One device's own signing and agreement keys, vouched for by the account."""

    device_id: str
    sdev: bytes
    sagree: bytes
    isign: bytes
    idh: bytes
    account: str = ""
    signature: bytes = b""
    version: int = DEVICE_LIST_VERSION

    def address(self) -> str:
        return device_keys_id(self.isign, self.idh, self.device_id)

    def payload(self) -> dict:
        return {
            "v": self.version,
            "account": self.account,
            "isign": b64e(self.isign),
            "idh": b64e(self.idh),
            "device": self.device_id,
            "sdev": b64e(self.sdev),
            "sagree": b64e(self.sagree),
            "bundle_id": self.address(),
        }

    def _signed_bytes(self) -> bytes:
        return DEVICE_KEYS_SIGN_INFO + canonical_json(self.payload())

    def to_bytes(self) -> bytes:
        data = self.payload()
        data["sig"] = b64e(self.signature)
        return canonical_json(data)

    @classmethod
    def from_bytes(cls, data: bytes | str | dict) -> "DeviceKeys":
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError as exc:
                raise DeviceListError("device keys are not valid JSON") from exc
        if not isinstance(data, dict) or data.get("v") != DEVICE_LIST_VERSION:
            raise DeviceListError("unsupported device keys version")
        try:
            isign = b64d(str(data["isign"]))
            idh = b64d(str(data["idh"]))
            account = str(data["account"])
            device_id = str(data["device"])
            sdev = b64d(str(data["sdev"]))
            sagree = b64d(str(data["sagree"]))
            signature = b64d(str(data["sig"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise DeviceListError("malformed device keys") from exc
        if len(sdev) != 32 or len(sagree) != 32:
            raise DeviceListError("device keys have the wrong length")
        if compute_identity_id(isign, idh) != account:
            raise DeviceListError("device keys account does not match its keys")
        record = cls(
            device_id=device_id,
            sdev=sdev,
            sagree=sagree,
            isign=isign,
            idh=idh,
            account=account,
            signature=signature,
        )
        if not Identity.verify(isign, signature, record._signed_bytes()):
            raise DeviceListError("device keys signature is invalid")
        return record

    def belongs_to(self, account: str, isign: bytes, idh: bytes) -> bool:
        return (
            self.account == account and self.isign == isign and self.idh == idh
        )

    @classmethod
    def create(
        cls, identity: Identity, device_id: str, sdev: bytes, sagree: bytes
    ) -> "DeviceKeys":
        record = cls(
            device_id=device_id,
            sdev=sdev,
            sagree=sagree,
            isign=identity.ed_public_bytes,
            idh=identity.x_public_bytes,
            account=identity.identity_id,
        )
        record.signature = identity.sign(record._signed_bytes())
        return record
