"""A live Double Ratchet session bound to a contact."""

from __future__ import annotations

from dataclasses import dataclass

from noknowledge.crypto.encoding import b64d, b64e
from noknowledge.crypto.ratchet import Ratchet, RatchetState


@dataclass
class Session:
    sid: bytes
    ratchet: Ratchet
    sk: bytes | None = None
    init: dict | None = None
    established: bool = False

    @property
    def is_pending(self) -> bool:
        """True until the peer has confirmed the session by any message."""
        return not self.established

    def to_dict(self) -> dict:
        return {
            "sid": b64e(self.sid),
            "state": self.ratchet.state.to_dict(),
            "sk": b64e(self.sk) if self.sk else None,
            "init": self.init,
            "established": self.established,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        return cls(
            sid=b64d(data["sid"]),
            ratchet=Ratchet(RatchetState.from_dict(data["state"])),
            sk=b64d(data["sk"]) if data.get("sk") else None,
            init=data.get("init"),
            established=bool(data.get("established")),
        )