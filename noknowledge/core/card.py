"""Signed contact cards.

A card is the entire invitation: identity public keys, a prekey bundle handle,
the recipient's mailbox write capability, and the relay set. It is signed by the
owner, so it can be relayed through untrusted channels (chat, QR, screenshots)
without tampering.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from noknowledge.crypto.encoding import (
    b64d,
    b64e,
    canonical_json,
    card_decode,
    card_encode,
)
from noknowledge.crypto.identity import Identity, compute_identity_id
from noknowledge.crypto.kdf import CARD_SIGN_INFO
from noknowledge.wire.backends.base import MailboxCapability

CARD_VERSION = 1


class CardError(Exception):
    """Raised when a contact card is malformed or fails verification."""


@dataclass
class ContactCard:
    identity_id: str
    isign: bytes
    idh: bytes
    bundle_id: str
    inbox: MailboxCapability
    relays: list[str] = field(default_factory=list)
    name: str | None = None
    signature: bytes | None = None

    # -- serialisation ----------------------------------------------------

    def payload(self) -> dict:
        payload = {
            "v": CARD_VERSION,
            "id": self.identity_id,
            "isign": b64e(self.isign),
            "idh": b64e(self.idh),
            "bundle": self.bundle_id,
            "inbox": self.inbox.card_view(),
            "relays": list(self.relays),
        }
        if self.name:
            payload["name"] = self.name
        return payload

    def signed_dict(self) -> dict:
        payload = self.payload()
        payload["sig"] = b64e(self.signature or b"")
        return payload

    def _signed_bytes(self) -> bytes:
        return CARD_SIGN_INFO + canonical_json(self.payload())

    def to_string(self) -> str:
        return card_encode(self.signed_dict())

    @classmethod
    def from_string(cls, text: str) -> "ContactCard":
        try:
            data = card_decode(text)
        except ValueError as exc:
            raise CardError(str(exc)) from exc
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "ContactCard":
        if data.get("v") != CARD_VERSION:
            raise CardError(f"unsupported card version: {data.get('v')}")
        try:
            isign = b64d(data["isign"])
            idh = b64d(data["idh"])
            identity_id = str(data["id"])
            bundle_id = str(data["bundle"])
            inbox = MailboxCapability.from_card_view(data["inbox"])
            relays = list(data.get("relays") or [])
            name = data.get("name")
            signature = b64d(data["sig"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CardError("malformed contact card") from exc

        if not relays:
            raise CardError("contact card has no relays")
        if compute_identity_id(isign, idh) != identity_id:
            raise CardError("contact card id does not match its public keys")
        inbox.validate()

        card = cls(
            identity_id=identity_id,
            isign=isign,
            idh=idh,
            bundle_id=bundle_id,
            inbox=inbox,
            relays=relays,
            name=name,
            signature=signature,
        )
        if not Identity.verify(isign, signature, card._signed_bytes()):
            raise CardError("contact card signature is invalid")
        return card

    @classmethod
    def create(
        cls,
        identity: Identity,
        bundle_id: str,
        inbox: MailboxCapability,
        relays: list[str],
        name: str | None = None,
    ) -> "ContactCard":
        card = cls(
            identity_id=identity.identity_id,
            isign=identity.ed_public_bytes,
            idh=identity.x_public_bytes,
            bundle_id=bundle_id,
            inbox=MailboxCapability(
                mailbox_id=inbox.mailbox_id, write_token=inbox.write_token
            ),
            relays=list(relays),
            name=name,
        )
        card.signature = identity.sign(card._signed_bytes())
        return card