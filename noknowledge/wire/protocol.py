"""Wire message framing.

A relay blob is a small JSON object whose only cleartext fields are a random
pseudonymous session id, the ratchet header and the ciphertext. The handshake
header (``init``) appears only on the first message of a session, and contains
only ephemeral public material — never an identity key.
"""

from __future__ import annotations

import json

from noknowledge.crypto.encoding import b64d, b64e, canonical_json
from noknowledge.crypto.padding import (
    MAX_ATTACHMENT_ENVELOPE,
    DEFAULT_MAX,
    pad_envelope,
    unpad_envelope,
)
from noknowledge.crypto.ratchet import Ratchet
from noknowledge.version import PROTOCOL_VERSION
from noknowledge.wire.errors import WireError

WIRE_VERSION = PROTOCOL_VERSION
ENVELOPE_VERSION = PROTOCOL_VERSION


def build_wire(
    sid: bytes,
    header: dict,
    nonce: bytes,
    ciphertext: bytes,
    init: dict | None = None,
) -> bytes:
    wire: dict = {
        "v": WIRE_VERSION,
        "sid": b64e(sid),
        "hdr": header,
        "nonce": b64e(nonce),
        "ct": b64e(ciphertext),
    }
    if init is not None:
        wire["init"] = init
    return canonical_json(wire)


def parse_wire(blob: bytes | str) -> dict:
    if isinstance(blob, bytes):
        try:
            blob = blob.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WireError("wire message is not UTF-8") from exc
    try:
        wire = json.loads(blob)
    except json.JSONDecodeError as exc:
        raise WireError("wire message is not valid JSON") from exc
    if not isinstance(wire, dict) or wire.get("v") != WIRE_VERSION:
        raise WireError(f"unsupported wire version: {wire.get('v') if isinstance(wire, dict) else None}")
    for field in ("sid", "hdr", "nonce", "ct"):
        if field not in wire:
            raise WireError(f"wire message is missing {field!r}")
    return wire


def seal(
    ratchet: Ratchet,
    envelope: dict,
    sid: bytes,
    init: dict | None = None,
    max_size: int | None = None,
) -> bytes:
    """Pad, encrypt and frame an envelope for the relay."""
    limit = DEFAULT_MAX if max_size is None else max_size
    plaintext = pad_envelope(envelope, max_size=limit)
    header, nonce, ciphertext = ratchet.encrypt(plaintext, ad_context=init)
    return build_wire(sid, header, nonce, ciphertext, init)


def unseal(ratchet: Ratchet, blob: bytes | str) -> tuple[dict, bytes, dict | None]:
    """Parse, decrypt and unpad a relay blob.

    Returns ``(envelope, sid, init)`` where ``init`` is present only for the
    first message of a session.
    """
    wire = parse_wire(blob)
    init = wire.get("init")
    try:
        plaintext = ratchet.decrypt(
            wire["hdr"], b64d(wire["nonce"]), b64d(wire["ct"]), ad_context=init
        )
    except Exception as exc:
        raise WireError(f"could not open message: {exc}") from exc
    return unpad_envelope(plaintext), b64d(wire["sid"]), init


def make_envelope(
    kind: str,
    body: dict,
    message_id: str,
    timestamp_ms: int,
    auth: dict | None = None,
    card: dict | None = None,
) -> dict:
    envelope: dict = {
        "v": ENVELOPE_VERSION,
        "type": kind,
        "id": message_id,
        "ts": int(timestamp_ms),
        "body": body,
    }
    if auth is not None:
        envelope["auth"] = auth
    if card is not None:
        envelope["card"] = card
    return envelope


def envelope_max_size(kind: str) -> int:
    return MAX_ATTACHMENT_ENVELOPE if kind == "file" else DEFAULT_MAX