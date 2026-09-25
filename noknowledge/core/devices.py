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
    nonce, ciphertext = encrypt(
        device_list_key(listing.isign, listing.idh), listing.to_bytes()
    )
    return canonical_json(
        {
            "v": DEVICE_LIST_VERSION,
            # The prekey endpoint keys its rows by this field, so it has to stay
            # visible; it is a public hash of the account keys, nothing more.
            "bundle_id": listing.address(),
            "box": b64e(nonce + ciphertext),
        }
    )


def open_device_list(
    data: bytes | str | dict, isign: bytes, idh: bytes
) -> "DeviceList":
    """Open a record fetched from a relay, using the peer's public keys."""
    if isinstance(data, bytes):
        raw: object = data.decode("utf-8")
    else:
        raw = data
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise DeviceListError("device list is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise DeviceListError("device list is not an object")
    box = raw.get("box")
    if box is None:
        # Unsealed record: nothing published by this version looks like that,
        # but an older or handcrafted one may, and reading it is harmless.
        return DeviceList.from_bytes(raw)
    try:
        blob = b64d(str(box))
    except Exception as exc:
        raise DeviceListError("device list box is not valid base64") from exc
    if len(blob) <= 12:
        raise DeviceListError("device list box is truncated")
    try:
        plaintext = decrypt(
            device_list_key(isign, idh), blob[:12], blob[12:]
        )
    except AEADError as exc:
        raise DeviceListError("device list could not be opened") from exc
    return DeviceList.from_bytes(plaintext)