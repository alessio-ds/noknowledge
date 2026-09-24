"""Envelope padding.

Plaintext envelopes are padded to a multiple of :data:`BUCKET` bytes so that
ciphertext length does not reveal plaintext length. The padding is a random
alphanumeric string in the ``pad`` field; unpadding simply drops it.
"""

from __future__ import annotations

import json
import secrets

from noknowledge.crypto.encoding import canonical_json

BUCKET = 256
DEFAULT_MAX = 2048
MAX_ATTACHMENT_ENVELOPE = 65536

_PAD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


class PaddingError(Exception):
    """Raised when an envelope cannot be padded within its size limit."""


def padded_size(base_length: int, bucket: int = BUCKET, max_size: int | None = None) -> int:
    """Return the padded target length for a payload of ``base_length`` bytes."""
    target = max(bucket, (base_length // bucket + 1) * bucket)
    if max_size is not None and target > max_size:
        target = max_size
    return target


def pad_envelope(
    envelope: dict, bucket: int = BUCKET, max_size: int | None = None
) -> bytes:
    """Serialise ``envelope`` to canonical JSON padded to a size bucket."""
    envelope = dict(envelope)
    envelope["pad"] = ""
    base = canonical_json(envelope)
    if max_size is not None and len(base) > max_size:
        raise PaddingError(
            f"envelope body is {len(base)} bytes, exceeds limit {max_size}"
        )
    target = padded_size(len(base), bucket, max_size)
    pad_length = target - len(base)
    if pad_length < 0:
        raise PaddingError("envelope too large to pad")
    envelope["pad"] = "".join(secrets.choice(_PAD_ALPHABET) for _ in range(pad_length))
    data = canonical_json(envelope)
    if len(data) != target:  # pragma: no cover - defensive
        raise PaddingError(f"padding produced {len(data)} bytes, wanted {target}")
    return data


def unpad_envelope(data: bytes | str) -> dict:
    """Parse a padded envelope and strip the padding field."""
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    obj = json.loads(data)
    if not isinstance(obj, dict):
        raise PaddingError("envelope is not an object")
    obj.pop("pad", None)
    return obj