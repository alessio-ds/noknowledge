"""Identity: an Ed25519 signing key and an X25519 key-agreement key.

Both keys are derived deterministically from a BIP39 mnemonic, so an identity
can be restored from 24 words. The derived ``identity_id`` is a cryptographic
fingerprint computed offline; it is never transmitted to a relay.
"""

from __future__ import annotations

import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature
from mnemonic import Mnemonic

from noknowledge.crypto.encoding import b32e, b64d, b64e, canonical_json
from noknowledge.crypto.kdf import ID_HASH_INFO, IDENTITY_INFO, hkdf

MNEMONIC_STRENGTH = 256  # 24 words
VAULT_VERSION = 1
PBKDF2_ITERATIONS = 600_000
ED_SEED_SIZE = 32
X_SEED_SIZE = 32


class IdentityError(Exception):
    """Raised for malformed keys, bad mnemonics or vault failures."""


def _raw_ed_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _raw_ed_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _raw_x_private(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _raw_x_public(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def derive_keys(seed: bytes) -> tuple[Ed25519PrivateKey, X25519PrivateKey]:
    """Derive the identity keypair from a BIP39 seed, with domain separation."""
    root = hkdf(seed, salt=b"", info=IDENTITY_INFO, length=64)
    ed = Ed25519PrivateKey.from_private_bytes(root[:32])
    x = X25519PrivateKey.from_private_bytes(root[32:64])
    return ed, x


def compute_identity_id(ed_public: bytes, x_public: bytes) -> str:
    """26-character Crockford base32 fingerprint of the public keys."""
    digest = hashlib.sha256(ID_HASH_INFO + ed_public + x_public).digest()
    return b32e(digest)[:26]


def _vault_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


class Identity:
    """A long-term identity. Pure data plus signing; performs no I/O."""

    def __init__(
        self,
        ed_private: Ed25519PrivateKey,
        x_private: X25519PrivateKey,
        label: str | None = None,
    ) -> None:
        self._ed = ed_private
        self._x = x_private
        self.label = label

    # -- construction -----------------------------------------------------

    @classmethod
    def generate(
        cls, label: str | None = None, passphrase: str | None = None
    ) -> tuple["Identity", str]:
        """Create a new identity. Returns ``(identity, mnemonic)``."""
        words = Mnemonic("english").generate(strength=MNEMONIC_STRENGTH)
        return cls.from_mnemonic(words, passphrase=passphrase, label=label), words

    @classmethod
    def from_mnemonic(
        cls,
        mnemonic: str,
        passphrase: str | None = None,
        label: str | None = None,
    ) -> "Identity":
        normalized = " ".join(mnemonic.split())
        if not Mnemonic("english").check(normalized):
            raise IdentityError("invalid BIP39 mnemonic")
        seed = Mnemonic.to_seed(normalized, passphrase or "")
        ed, x = derive_keys(seed)
        return cls(ed, x, label=label)

    @classmethod
    def from_private_bytes(
        cls,
        ed_seed: bytes,
        x_seed: bytes,
        label: str | None = None,
    ) -> "Identity":
        if len(ed_seed) != ED_SEED_SIZE or len(x_seed) != X_SEED_SIZE:
            raise IdentityError("invalid private key length")
        return cls(
            Ed25519PrivateKey.from_private_bytes(ed_seed),
            X25519PrivateKey.from_private_bytes(x_seed),
            label=label,
        )

    # -- public material --------------------------------------------------

    @property
    def ed_private_bytes(self) -> bytes:
        return _raw_ed_private(self._ed)

    @property
    def x_private_bytes(self) -> bytes:
        return _raw_x_private(self._x)

    @property
    def ed_public_bytes(self) -> bytes:
        return _raw_ed_public(self._ed)

    @property
    def x_public_bytes(self) -> bytes:
        return _raw_x_public(self._x)

    @property
    def identity_id(self) -> str:
        return compute_identity_id(self.ed_public_bytes, self.x_public_bytes)

    # -- signatures -------------------------------------------------------

    def sign(self, data: bytes) -> bytes:
        return self._ed.sign(data)

    @staticmethod
    def verify(ed_public: bytes, signature: bytes, data: bytes) -> bool:
        if len(ed_public) != 32 or len(signature) != 64:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(ed_public).verify(signature, data)
            return True
        except (InvalidSignature, ValueError):
            return False

    # -- vault persistence ------------------------------------------------

    def _secret_blob(self) -> bytes:
        return self.ed_private_bytes + self.x_private_bytes

    def to_vault(self, passphrase: str | None = None) -> bytes:
        """Serialise the identity, optionally encrypted under a passphrase."""
        secret = self._secret_blob()
        payload: dict = {
            "v": VAULT_VERSION,
            "id": self.identity_id,
            "label": self.label,
            "encrypted": bool(passphrase),
        }
        if passphrase:
            salt = os.urandom(16)
            iterations = PBKDF2_ITERATIONS
            key = _vault_key(passphrase, salt, iterations)
            nonce = os.urandom(12)
            blob = AESGCM(key).encrypt(nonce, secret, canonical_json({"id": self.identity_id}))
            payload["kdf"] = {"salt": b64e(salt), "iterations": iterations}
            payload["nonce"] = b64e(nonce)
            payload["secret"] = b64e(blob)
        else:
            payload["secret"] = b64e(secret)
        return json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")

    @classmethod
    def from_vault(cls, data: bytes | str, passphrase: str | None = None) -> "Identity":
        if isinstance(data, bytes):
            try:
                data = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise IdentityError("vault is not valid UTF-8") from exc
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as exc:
            raise IdentityError("vault is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise IdentityError("vault is not a JSON object")
        if payload.get("v") != VAULT_VERSION:
            raise IdentityError(f"unsupported vault version: {payload.get('v')}")
        blob = b64d(payload["secret"])
        if payload.get("encrypted"):
            if not passphrase:
                raise IdentityError("vault is encrypted but no passphrase was given")
            kdf_params = payload.get("kdf") or {}
            key = _vault_key(
                passphrase,
                b64d(kdf_params["salt"]),
                int(kdf_params["iterations"]),
            )
            try:
                secret = AESGCM(key).decrypt(
                    b64d(payload["nonce"]),
                    blob,
                    canonical_json({"id": payload["id"]}),
                )
            except Exception as exc:  # InvalidTag
                raise IdentityError("wrong passphrase or corrupted vault") from exc
        else:
            if passphrase:
                raise IdentityError("vault is not encrypted; remove the passphrase")
            secret = blob
        if len(secret) != ED_SEED_SIZE + X_SEED_SIZE:
            raise IdentityError("vault secret has the wrong length")
        identity = cls.from_private_bytes(
            secret[:ED_SEED_SIZE], secret[ED_SEED_SIZE:], label=payload.get("label")
        )
        if identity.identity_id != payload.get("id"):
            raise IdentityError("vault does not match its recorded identity id")
        return identity

    def save(self, path: str, passphrase: str | None = None) -> None:
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(self.to_vault(passphrase))

    @classmethod
    def load(cls, path: str, passphrase: str | None = None) -> "Identity":
        with open(path, "rb") as handle:
            return cls.from_vault(handle.read(), passphrase)