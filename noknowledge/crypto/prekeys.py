"""Prekey bundles: signed prekeys and one-time prekeys for asynchronous X3DH.

A recipient publishes a signed bundle under a random ``bundle_id``. The relay
returns at most one unused one-time prekey per fetch, consumed atomically.
Because the bundle carries an Ed25519 signature over the signed prekey, a
malicious relay cannot substitute keys without detection.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from noknowledge.crypto.encoding import b64d, b64e, canonical_json
from noknowledge.crypto.identity import Identity
from noknowledge.crypto.kdf import SPK_SIGN_INFO

BUNDLE_VERSION = 1
BUNDLE_ID_SIZE = 16
MAX_OPKS = 100


class PrekeyError(Exception):
    """Raised for malformed or unverifiable prekey material."""


def _spk_signature(identity: Identity, bundle_id: bytes, spk_id: int, spk: bytes) -> bytes:
    message = (
        SPK_SIGN_INFO
        + bundle_id
        + spk_id.to_bytes(4, "big")
        + spk
    )
    return identity.sign(message)


@dataclass
class PrekeyBundle:
    bundle_id: bytes
    isign: bytes
    idh: bytes
    spk_id: int
    spk: bytes
    spk_sig: bytes
    opks: list[tuple[int, bytes]] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Full client-side representation, including identity keys."""
        return {
            "v": BUNDLE_VERSION,
            "bundle_id": b64e(self.bundle_id),
            "isign": b64e(self.isign),
            "idh": b64e(self.idh),
            "spk_id": self.spk_id,
            "spk": b64e(self.spk),
            "spk_sig": b64e(self.spk_sig),
            "opks": [{"opk_id": i, "opk": b64e(p)} for i, p in self.opks],
        }

    def to_public_dict(self) -> dict:
        """What is published to a relay: **no identity keys**.

        The relay learns only a random ``bundle_id`` and a signed prekey. The
        identity keys are supplied by the contact card, so publishing them would
        leak identities to the relay for no benefit.
        """
        return {
            "v": BUNDLE_VERSION,
            "bundle_id": b64e(self.bundle_id),
            "spk_id": self.spk_id,
            "spk": b64e(self.spk),
            "spk_sig": b64e(self.spk_sig),
            "opks": [{"opk_id": i, "opk": b64e(p)} for i, p in self.opks],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PrekeyBundle":
        if data.get("v") != BUNDLE_VERSION:
            raise PrekeyError(f"unsupported bundle version: {data.get('v')}")
        try:
            return cls(
                bundle_id=b64d(data["bundle_id"]),
                isign=b64d(data.get("isign", "")),
                idh=b64d(data.get("idh", "")),
                spk_id=int(data["spk_id"]),
                spk=b64d(data["spk"]),
                spk_sig=b64d(data["spk_sig"]),
                opks=[(int(o["opk_id"]), b64d(o["opk"])) for o in data.get("opks", [])],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PrekeyError("malformed prekey bundle") from exc

    @classmethod
    def from_public(
        cls, data: bytes | str | dict, isign: bytes, idh: bytes
    ) -> "PrekeyBundle":
        """Rehydrate a published bundle using identity keys from the card."""
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        if isinstance(data, str):
            data = json.loads(data)
        bundle = cls.from_dict(data)
        bundle.isign = isign
        bundle.idh = idh
        return bundle

    def to_bytes(self) -> bytes:
        """Canonical wire form published to the relay (no identity keys)."""
        return canonical_json(self.to_public_dict())

    @classmethod
    def from_bytes(cls, data: bytes | str, isign: bytes, idh: bytes) -> "PrekeyBundle":
        return cls.from_public(data, isign, idh)


def make_bundle(
    identity: Identity,
    bundle_id: bytes,
    spk_id: int,
    spk_public: bytes,
    opks: list[tuple[int, bytes]] | None = None,
) -> PrekeyBundle:
    """Build and sign a bundle for publication."""
    if len(bundle_id) != BUNDLE_ID_SIZE:
        raise PrekeyError("bundle_id must be 16 bytes")
    opks = opks or []
    if len(opks) > MAX_OPKS:
        raise PrekeyError(f"at most {MAX_OPKS} one-time prekeys per bundle")
    return PrekeyBundle(
        bundle_id=bundle_id,
        isign=identity.ed_public_bytes,
        idh=identity.x_public_bytes,
        spk_id=spk_id,
        spk=spk_public,
        spk_sig=_spk_signature(identity, bundle_id, spk_id, spk_public),
        opks=list(opks),
    )


def verify_bundle(bundle: PrekeyBundle, expected_isign: bytes) -> None:
    """Verify a bundle against the identity key taken from a signed card.

    Raises :class:`PrekeyError` on any mismatch. The relay response alone is
    never trusted: ``expected_isign`` must come from the contact card.
    """
    if bundle.isign != expected_isign:
        raise PrekeyError("bundle identity key does not match the contact card")
    if len(bundle.spk) != 32 or len(bundle.idh) != 32:
        raise PrekeyError("bundle contains malformed public keys")
    message = (
        SPK_SIGN_INFO
        + bundle.bundle_id
        + bundle.spk_id.to_bytes(4, "big")
        + bundle.spk
    )
    if not Identity.verify(bundle.isign, bundle.spk_sig, message):
        raise PrekeyError("signed prekey signature is invalid")


def new_bundle_id() -> bytes:
    return os.urandom(BUNDLE_ID_SIZE)