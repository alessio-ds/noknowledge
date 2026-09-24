"""Canonical encoding helpers used across the protocol.

Everything that is hashed, signed or authenticated goes through
:func:`canonical_json` so that both peers and the relay agree byte-for-byte.
"""

from __future__ import annotations

import base64
import json
import zlib

_B32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_B32_LOOKUP = {c: i for i, c in enumerate(_B32_ALPHABET)}
_B32_CONFUSABLES = {"I": "1", "L": "1", "O": "0", "U": "V"}

CARD_PREFIX = "nk://1/"


def b64e(data: bytes) -> str:
    """base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64d(text: str | bytes) -> bytes:
    """Decode base64url that may lack padding."""
    if isinstance(text, str):
        text = text.encode("ascii")
    return base64.urlsafe_b64decode(text + b"=" * (-len(text) % 4))


def b32e(data: bytes) -> str:
    """Crockford base32 without padding."""
    value = 0
    bits = 0
    out: list[str] = []
    for byte in data:
        value = (value << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(_B32_ALPHABET[(value >> bits) & 31])
    if bits:
        out.append(_B32_ALPHABET[(value << (5 - bits)) & 31])
    return "".join(out)


def b32d(text: str) -> bytes:
    """Decode Crockford base32, tolerating confusable characters."""
    value = 0
    bits = 0
    out = bytearray()
    for ch in text.strip().replace("-", "").upper():
        ch = _B32_CONFUSABLES.get(ch, ch)
        try:
            digit = _B32_LOOKUP[ch]
        except KeyError as exc:
            raise ValueError(f"invalid base32 character: {ch!r}") from exc
        value = (value << 5) | digit
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((value >> bits) & 0xFF)
    return bytes(out)


def canonical_json(obj) -> bytes:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def card_encode(payload: dict) -> str:
    """Serialise a contact card payload to its compact `nk://1/...` form."""
    return CARD_PREFIX + b64e(zlib.compress(canonical_json(payload), 9))


def card_decode(text: str) -> dict:
    """Parse a `nk://1/...` contact card string."""
    text = text.strip()
    if not text.lower().startswith(CARD_PREFIX):
        raise ValueError("not a noknowledge contact card")
    raw = b64d(text[len(CARD_PREFIX):])
    try:
        return json.loads(zlib.decompress(raw))
    except zlib.error as exc:
        raise ValueError("corrupt contact card") from exc