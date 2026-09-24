"""Anonymous X3DH handshake.

Classic X3DH places the initiator's identity key in the clear, which would hand
the relay the sender's identity. noknowledge instead contributes only an
ephemeral key: the initiator's identity is proven *inside* the encrypted
payload by the ``auth`` block (see :func:`build_auth`). This is what makes the
relay unable to learn who sent a message.

Shared secret:

    SK = HKDF( F || DH(EK, IK_b) || DH(EK, SPK_b) [|| DH(EK, OPK_b)] )
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from noknowledge.crypto.encoding import b64d, b64e, canonical_json
from noknowledge.crypto.identity import Identity, compute_identity_id
from noknowledge.crypto.kdf import (
    AUTH_SIGN_INFO,
    F,
    X3DH_INFO,
    ZERO_SALT,
    hkdf,
    sk_commitment,
)
from noknowledge.crypto.prekeys import PrekeyBundle, PrekeyError, verify_bundle

INIT_VERSION = 1
KEY_SIZE = 32


class HandshakeError(Exception):
    """Raised when a handshake cannot be completed or verified."""


def _public(seed: bytes) -> X25519PublicKey:
    try:
        return X25519PublicKey.from_public_bytes(seed)
    except ValueError as exc:
        raise HandshakeError("malformed X25519 public key") from exc


def _private(seed: bytes) -> X25519PrivateKey:
    try:
        return X25519PrivateKey.from_private_bytes(seed)
    except ValueError as exc:
        raise HandshakeError("malformed X25519 private key") from exc


def private_bytes(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def public_bytes(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh raw ``(private, public)`` X25519 pair."""
    key = X25519PrivateKey.generate()
    return private_bytes(key), public_bytes(key)


@dataclass
class Initiation:
    """Everything the initiator needs to start a ratchet and emit message one."""

    ek_public: bytes
    ek_private: bytes
    spk_id: int
    opk_id: int | None
    sk: bytes = field(repr=False)

    def init_dict(self) -> dict:
        """Canonical handshake header, bound into the AEAD associated data."""
        return {
            "ek": b64e(self.ek_public),
            "spk_id": self.spk_id,
            "opk_id": self.opk_id,
        }


def initiate(
    bundle: PrekeyBundle,
    expected_isign: bytes,
    expected_idh: bytes,
) -> Initiation:
    """Perform the initiator half of the handshake.

    ``expected_isign`` and ``expected_idh`` must come from the signed contact
    card, never from the relay response.
    """
    try:
        verify_bundle(bundle, expected_isign)
    except PrekeyError as exc:
        raise HandshakeError(f"prekey bundle rejected: {exc}") from exc
    if bundle.idh != expected_idh:
        raise HandshakeError("bundle identity key disagrees with the contact card")

    ephemeral = X25519PrivateKey.generate()
    dh1 = ephemeral.exchange(_public(bundle.idh))
    dh2 = ephemeral.exchange(_public(bundle.spk))
    dh3 = b""
    opk_id = None
    if bundle.opks:
        opk_id, opk_public = bundle.opks[0]
        dh3 = ephemeral.exchange(_public(opk_public))

    sk = hkdf(F + dh1 + dh2 + dh3, salt=ZERO_SALT, info=X3DH_INFO, length=KEY_SIZE)
    return Initiation(
        ek_public=public_bytes(ephemeral),
        ek_private=private_bytes(ephemeral),
        spk_id=bundle.spk_id,
        opk_id=opk_id,
        sk=sk,
    )


def respond(
    identity_x_private: bytes,
    signed_prekey_private: bytes,
    opk_private: bytes | None,
    ek_public: bytes,
) -> bytes:
    """Perform the responder half of the handshake, returning the shared secret."""
    ephemeral = _public(ek_public)
    dh1 = _private(identity_x_private).exchange(ephemeral)
    dh2 = _private(signed_prekey_private).exchange(ephemeral)
    dh3 = _private(opk_private).exchange(ephemeral) if opk_private else b""
    return hkdf(F + dh1 + dh2 + dh3, salt=ZERO_SALT, info=X3DH_INFO, length=KEY_SIZE)


# -- sender authentication (sealed-sender style) --------------------------


def build_auth(identity: Identity, sid: bytes, init_dict: dict, sk: bytes) -> dict:
    """Build the in-ciphertext proof binding a sender identity to a session."""
    commit = sk_commitment(sk)
    message = AUTH_SIGN_INFO + sid + canonical_json(init_dict) + commit
    return {
        "v": INIT_VERSION,
        "id": identity.identity_id,
        "isign": b64e(identity.ed_public_bytes),
        "idh": b64e(identity.x_public_bytes),
        "sk_commit": b64e(commit),
        "sig": b64e(identity.sign(message)),
    }


def verify_auth(auth: dict, sid: bytes, init_dict: dict, sk: bytes) -> bool:
    """Verify the sender proof. Returns ``False`` on any failure."""
    try:
        if auth.get("v") != INIT_VERSION:
            return False
        expected_commit = sk_commitment(sk)
        if not hmac.compare_digest(b64d(auth["sk_commit"]), expected_commit):
            return False
        isign = b64d(auth["isign"])
        idh = b64d(auth["idh"])
        if compute_identity_id(isign, idh) != auth.get("id"):
            return False
        message = AUTH_SIGN_INFO + sid + canonical_json(init_dict) + expected_commit
        return Identity.verify(isign, b64d(auth["sig"]), message)
    except (KeyError, ValueError, TypeError):
        return False