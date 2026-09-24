"""Double Ratchet.

Implements the Signal Double Ratchet over the X3DH root key: symmetric chain
keys for per-message forward secrecy, and a DH ratchet for post-compromise
security. Out-of-order messages are supported through a bounded skipped-key
cache; replays fail because message keys are consumed on use.

Decryption is **transactional**: if authentication fails, the session state is
rolled back exactly. A tampered or unrelated message therefore cannot desync an
otherwise healthy session.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from noknowledge.crypto import aead
from noknowledge.crypto.encoding import b64d, b64e, canonical_json
from noknowledge.crypto.kdf import kdf_ck, kdf_rk

MAX_SKIP = 1000
AD_DOMAIN = b"nk/v1/msg"


class RatchetError(Exception):
    """Base class for ratchet failures."""


class DuplicateMessage(RatchetError):
    """The message key was already consumed (replay or too-old message)."""


class SkippedTooFar(RatchetError):
    """Too many messages were skipped; refusing to derive an unbounded chain."""


def _new_keypair() -> tuple[bytes, bytes]:
    private = X25519PrivateKey.generate()
    priv = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return priv, pub


def _dh(private: bytes, public: bytes) -> bytes:
    """Raw X25519 agreement between a private and a public key."""
    return X25519PrivateKey.from_private_bytes(private).exchange(
        X25519PublicKey.from_public_bytes(public)
    )


@dataclass
class RatchetState:
    root_key: bytes = field(repr=False)
    sending_chain: bytes | None = field(default=None, repr=False)
    receiving_chain: bytes | None = field(default=None, repr=False)
    dh_self_private: bytes | None = field(default=None, repr=False)
    dh_self_public: bytes | None = None
    dh_remote: bytes | None = None
    send_count: int = 0
    recv_count: int = 0
    prev_send_count: int = 0
    skipped: dict[str, bytes] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict:
        return {
            "v": 1,
            "rk": b64e(self.root_key),
            "cks": b64e(self.sending_chain) if self.sending_chain else None,
            "ckr": b64e(self.receiving_chain) if self.receiving_chain else None,
            "dhs_priv": b64e(self.dh_self_private) if self.dh_self_private else None,
            "dhs_pub": b64e(self.dh_self_public) if self.dh_self_public else None,
            "dhr": b64e(self.dh_remote) if self.dh_remote else None,
            "ns": self.send_count,
            "nr": self.recv_count,
            "pn": self.prev_send_count,
            "skipped": {k: b64e(v) for k, v in self.skipped.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RatchetState":
        return cls(
            root_key=b64d(data["rk"]),
            sending_chain=b64d(data["cks"]) if data.get("cks") else None,
            receiving_chain=b64d(data["ckr"]) if data.get("ckr") else None,
            dh_self_private=b64d(data["dhs_priv"]) if data.get("dhs_priv") else None,
            dh_self_public=b64d(data["dhs_pub"]) if data.get("dhs_pub") else None,
            dh_remote=b64d(data["dhr"]) if data.get("dhr") else None,
            send_count=int(data.get("ns", 0)),
            recv_count=int(data.get("nr", 0)),
            prev_send_count=int(data.get("pn", 0)),
            skipped={k: b64d(v) for k, v in (data.get("skipped") or {}).items()},
        )


class Ratchet:
    """A bidirectional Double Ratchet session."""

    def __init__(self, state: RatchetState) -> None:
        self.state = state

    # -- construction -----------------------------------------------------

    @classmethod
    def initiator(cls, session_key: bytes, remote_ratchet_public: bytes) -> "Ratchet":
        """Start a session; performs the initial DH ratchet step."""
        priv, pub = _new_keypair()
        state = RatchetState(
            root_key=session_key,
            dh_self_private=priv,
            dh_self_public=pub,
            dh_remote=remote_ratchet_public,
        )
        state.root_key, state.sending_chain = kdf_rk(
            state.root_key, _dh(priv, remote_ratchet_public)
        )
        return cls(state)

    @classmethod
    def responder(
        cls, session_key: bytes, signed_prekey_private: bytes, signed_prekey_public: bytes
    ) -> "Ratchet":
        """Start the receiving side, rooted at our signed prekey."""
        state = RatchetState(
            root_key=session_key,
            dh_self_private=signed_prekey_private,
            dh_self_public=signed_prekey_public,
            dh_remote=None,
        )
        return cls(state)

    # -- encryption -------------------------------------------------------

    def encrypt(
        self, plaintext: bytes, ad_context: dict | None = None
    ) -> tuple[dict, bytes, bytes]:
        """Returns ``(header, nonce, ciphertext)``."""
        if self.state.sending_chain is None:
            raise RatchetError("no sending chain; receive a message first")
        message_key, self.state.sending_chain = kdf_ck(self.state.sending_chain)
        header = {
            "dh": b64e(self.state.dh_self_public),
            "pn": self.state.prev_send_count,
            "n": self.state.send_count,
        }
        nonce, ciphertext = aead.encrypt(
            message_key, plaintext, self._associated_data(header, ad_context)
        )
        self.state.send_count += 1
        return header, nonce, ciphertext

    # -- decryption -------------------------------------------------------

    def decrypt(
        self,
        header: dict,
        nonce: bytes,
        ciphertext: bytes,
        ad_context: dict | None = None,
    ) -> bytes:
        """Verify and decrypt. Session state only advances on success."""
        snapshot = copy.deepcopy(self.state)
        try:
            return self._decrypt(header, nonce, ciphertext, ad_context)
        except Exception:
            # Any failure — tampering, replay, or an unrelated message that
            # happens to share this mailbox — must leave the session usable.
            self.state = snapshot
            raise

    def _decrypt(
        self,
        header: dict,
        nonce: bytes,
        ciphertext: bytes,
        ad_context: dict | None = None,
    ) -> bytes:
        try:
            remote_dh = b64d(header["dh"])
            number = int(header["n"])
            prev_count = int(header["pn"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RatchetError("malformed header") from exc

        if self.state.dh_remote != remote_dh or self.state.receiving_chain is None:
            if self.state.receiving_chain is not None:
                self._skip_keys(prev_count)
            self._dh_ratchet(remote_dh)

        message_key = self.state.skipped.pop(self._skipped_key(remote_dh, number), None)
        if message_key is None:
            if number < self.state.recv_count:
                raise DuplicateMessage("message key already consumed")
            if number > self.state.recv_count + MAX_SKIP:
                raise SkippedTooFar(
                    f"would skip {number - self.state.recv_count} messages"
                )
            self._skip_keys(number)
            message_key, self.state.receiving_chain = kdf_ck(self.state.receiving_chain)
            self.state.recv_count += 1

        return aead.decrypt(
            message_key, nonce, ciphertext, self._associated_data(header, ad_context)
        )

    # -- internals --------------------------------------------------------

    def _dh_ratchet(self, remote_dh: bytes) -> None:
        self.state.prev_send_count = self.state.send_count
        self.state.send_count = 0
        self.state.recv_count = 0
        self.state.dh_remote = remote_dh
        if self.state.dh_self_private is None:
            raise RatchetError("ratchet has no local DH key")
        self.state.root_key, self.state.receiving_chain = kdf_rk(
            self.state.root_key, _dh(self.state.dh_self_private, remote_dh)
        )
        priv, pub = _new_keypair()
        self.state.dh_self_private = priv
        self.state.dh_self_public = pub
        self.state.root_key, self.state.sending_chain = kdf_rk(
            self.state.root_key, _dh(priv, remote_dh)
        )

    def _skip_keys(self, until: int) -> None:
        if self.state.receiving_chain is None:
            return
        if self.state.recv_count + MAX_SKIP < until:
            raise SkippedTooFar(f"skipped-key cache would exceed {MAX_SKIP}")
        while self.state.recv_count < until:
            message_key, self.state.receiving_chain = kdf_ck(self.state.receiving_chain)
            self.state.skipped[
                self._skipped_key(self.state.dh_remote, self.state.recv_count)
            ] = message_key
            self.state.recv_count += 1

    @staticmethod
    def _skipped_key(dh: bytes | None, number: int) -> str:
        return f"{b64e(dh or b'')}:{number}"

    @staticmethod
    def _associated_data(header: dict, ad_context: dict | None) -> bytes:
        return AD_DOMAIN + canonical_json(
            {"init": ad_context or {}, "hdr": header}
        )