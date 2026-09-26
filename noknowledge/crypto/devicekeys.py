"""Per-device keys.

The account identity is shared by every device, so it cannot authenticate one
device to another or carry a key agreement that distinguishes them. Each device
therefore generates its own Ed25519 signing key and X25519 agreement key, and
publishes the public halves in an account-signed record. The account signature is
what makes a device's word trustworthy: a relay cannot invent a device, and no
device can impersonate a sibling.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

KEY_SIZE = 32
SIGNATURE_SIZE = 64


class DeviceKeyError(Exception):
    """Raised for malformed device keys or a failed verification."""


def _raw_private(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _raw_public(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def generate_device_keys() -> tuple[bytes, bytes]:
    """A fresh ``(ed25519_private, x25519_private)`` pair for one device."""
    ed = _raw_private(Ed25519PrivateKey.generate())
    x = _raw_private(X25519PrivateKey.generate())
    return ed, x


def signing_public(private: bytes) -> bytes:
    return _raw_public(Ed25519PrivateKey.from_private_bytes(private))


def agreement_public(private: bytes) -> bytes:
    return _raw_public(X25519PrivateKey.from_private_bytes(private))


def sign(private: bytes, data: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(private).sign(data)


def verify(public: bytes, signature: bytes, data: bytes) -> bool:
    if len(public) != KEY_SIZE or len(signature) != SIGNATURE_SIZE:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, data)
    except (InvalidSignature, ValueError):
        return False
    return True


def agreement(private: bytes, peer_public: bytes) -> bytes:
    """X25519 shared secret, rejecting the degenerate all-zero output."""
    if len(peer_public) != KEY_SIZE:
        raise DeviceKeyError("agreement key must be 32 bytes")
    shared = X25519PrivateKey.from_private_bytes(private).exchange(
        X25519PublicKey.from_public_bytes(peer_public)
    )
    if shared == b"\x00" * KEY_SIZE:
        raise DeviceKeyError("degenerate agreement key")
    return shared


def new_agreement_private() -> bytes:
    return os.urandom(KEY_SIZE)
