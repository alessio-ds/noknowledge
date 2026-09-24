"""Authenticated encryption (ChaCha20-Poly1305)."""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

KEY_SIZE = 32
NONCE_SIZE = 12


class AEADError(Exception):
    """Raised when authentication fails or parameters are malformed."""


def encrypt(key: bytes, plaintext: bytes, ad: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypt and authenticate. Returns ``(nonce, ciphertext)``."""
    if len(key) != KEY_SIZE:
        raise AEADError(f"invalid key size: {len(key)}")
    nonce = os.urandom(NONCE_SIZE)
    return nonce, ChaCha20Poly1305(key).encrypt(nonce, plaintext, ad)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, ad: bytes = b"") -> bytes:
    """Verify and decrypt. Raises :class:`AEADError` on any failure."""
    if len(key) != KEY_SIZE:
        raise AEADError(f"invalid key size: {len(key)}")
    if len(nonce) != NONCE_SIZE:
        raise AEADError(f"invalid nonce size: {len(nonce)}")
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, ad)
    except InvalidTag as exc:
        raise AEADError("authentication failed") from exc