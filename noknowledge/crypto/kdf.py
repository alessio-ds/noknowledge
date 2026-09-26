"""Key derivation functions.

All key material is derived through HKDF-SHA256 with an explicit, unique
``info`` label per purpose. Chain keys use HMAC-SHA256 as in the Double Ratchet
specification.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Domain-separation labels. Never reuse a label for two purposes.
IDENTITY_INFO = b"noknowledge/identity/v1"
X3DH_INFO = b"noknowledge/x3dh/v1"
ROOT_INFO = b"nk/ratchet-root/v1"
SK_COMMIT_INFO = b"nk/sk-commit/v1"
CARD_SIGN_INFO = b"nk/card/v1"
SPK_SIGN_INFO = b"nk/spk/v1"
AUTH_SIGN_INFO = b"nk/auth/v1"
DEVICE_SIGN_INFO = b"nk/devices/v1"
DEVICE_LIST_ID_INFO = b"nk/devices/v1/id"
#: Per-device sync keys live in their own record so the device list format stays
#: unchanged and older clients keep parsing it.
DEVICE_KEYS_ID_INFO = b"nk/devices/v1/keys"
DEVICE_KEYS_SIGN_INFO = b"nk/devices/v1/keys/sig"
#: Device-to-device transfer: everything is derived from one ECIES secret.
DEVICE_SYNC_INFO = b"nk/devices/v1/sync"
DEVICE_SYNC_ITEM_INFO = b"nk/devices/v1/sync/item"
#: Device lists are sealed with a key derived from the account's *public* keys,
#: so any holder of the contact card can read them but the relay cannot.
DEVICE_LIST_ENC_INFO = b"nk/devices/v1/enc"
ID_HASH_INFO = b"nk-id"

# X25519 domain separation prefix (RFC 7748 / X3DH): 32 bytes of 0xFF.
F = b"\xff" * 32

ZERO_SALT = b"\x00" * 32


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 extract-and-expand."""
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=salt, info=info
    ).derive(ikm)


def kdf_rk(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    """Double Ratchet root KDF: returns ``(new_root_key, chain_key)``."""
    out = hkdf(dh_output, salt=root_key, info=ROOT_INFO, length=64)
    return out[:32], out[32:]


def kdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
    """Double Ratchet chain KDF: returns ``(message_key, next_chain_key)``."""
    message_key = hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
    next_chain_key = hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
    return message_key, next_chain_key


def sk_commitment(sk: bytes) -> bytes:
    """Binding value that proves knowledge of the X3DH session key."""
    return hashlib.sha256(SK_COMMIT_INFO + sk).digest()