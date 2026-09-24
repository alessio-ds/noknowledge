"""Capability tokens and optional proof-of-work."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time

TOKEN_SIZE = 32
MAILBOX_ID_SIZE = 16
CHUNK_ID_SIZE = 16


def new_token() -> bytes:
    return secrets.token_bytes(TOKEN_SIZE)


def new_mailbox_id() -> bytes:
    return secrets.token_bytes(MAILBOX_ID_SIZE)


def new_chunk_id() -> str:
    return secrets.token_hex(CHUNK_ID_SIZE)


def token_hash(token: bytes) -> bytes:
    """Hash a bearer token for storage. Tokens are 256-bit random, so a plain
    SHA-256 is sufficient and does not need a password KDF."""
    return hashlib.sha256(token).digest()


def verify_token(token: bytes, stored_hash: bytes) -> bool:
    """Constant-time token check."""
    if not token or not stored_hash:
        return False
    return hmac.compare_digest(token_hash(token), stored_hash)


def leading_zero_bits(digest: bytes) -> int:
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
            continue
        count += 8 - byte.bit_length()
        break
    return count


def verify_hashcash(value: str | None, bits: int, now: int | None = None, max_age: int = 3600) -> bool:
    """Verify a stateless hashcash stamp ``"<timestamp>:<nonce>"``.

    The timestamp bounds replay; the rate limiter bounds volume. Returns
    ``True`` when hashcash is not required (``bits <= 0``).
    """
    if bits <= 0:
        return True
    if not value or ":" not in value:
        return False
    timestamp_text, _, nonce = value.partition(":")
    try:
        timestamp = int(timestamp_text)
    except ValueError:
        return False
    current = int(time.time()) if now is None else now
    if timestamp > current + 60 or current - timestamp > max_age:
        return False
    digest = hashlib.sha256(f"{timestamp}:{nonce}".encode("utf-8")).digest()
    return leading_zero_bits(digest) >= bits