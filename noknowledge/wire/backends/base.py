"""Backend interface and shared value types for relay access."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

from noknowledge.crypto.encoding import b64d, b64e

MAILBOX_ID_SIZE = 16
TOKEN_SIZE = 32
CHUNK_ID_SIZE = 16


@dataclass
class MailboxCapability:
    """An address plus the capabilities needed to use it.

    A recipient holds both read and write tokens. A sender, who learns the
    address from a contact card, holds only the mailbox id and write token.
    """

    mailbox_id: str
    write_token: str
    read_token: str | None = None

    @classmethod
    def generate(cls) -> "MailboxCapability":
        return cls(
            mailbox_id=b64e(os.urandom(MAILBOX_ID_SIZE)),
            write_token=b64e(os.urandom(TOKEN_SIZE)),
            read_token=b64e(os.urandom(TOKEN_SIZE)),
        )

    def to_json(self) -> dict:
        payload = {"mailbox_id": self.mailbox_id, "write_token": self.write_token}
        if self.read_token is not None:
            payload["read_token"] = self.read_token
        return payload

    def card_view(self) -> dict:
        """The write-only view that goes into a contact card."""
        return {"id": self.mailbox_id, "w": self.write_token}

    @classmethod
    def from_card_view(cls, view: dict) -> "MailboxCapability":
        return cls(mailbox_id=str(view["id"]), write_token=str(view["w"]))

    @classmethod
    def from_json(cls, payload: dict, with_read: bool = True) -> "MailboxCapability":
        read = payload.get("read_token") if with_read else None
        capability = cls(
            mailbox_id=str(payload["mailbox_id"]),
            write_token=str(payload["write_token"]),
            read_token=str(read) if read else None,
        )
        capability.validate()
        return capability

    def validate(self) -> None:
        for name, token, size in (
            ("write_token", self.write_token, TOKEN_SIZE),
            ("read_token", self.read_token, TOKEN_SIZE),
        ):
            if token is None:
                continue
            try:
                raw = b64d(token)
            except Exception as exc:
                raise ValueError(f"{name} is not valid base64url") from exc
            if len(raw) != size:
                raise ValueError(f"{name} has the wrong length")

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        return f"MailboxCapability({self.mailbox_id})"


@dataclass
class FetchedMessage:
    """One blob as seen from one relay."""

    relay: str
    seq: int
    blob: bytes


class RelayBackend(Protocol):
    """A single relay's API surface."""

    base_url: str

    def create_mailbox(self, capability: MailboxCapability) -> None: ...
    def put(self, capability: MailboxCapability, envelope: bytes) -> None: ...
    def fetch(
        self, capability: MailboxCapability, after_seq: int = 0, wait: int = 0
    ) -> list[tuple[int, bytes]]: ...
    def ack(self, capability: MailboxCapability, upto_seq: int) -> int: ...
    def delete_mailbox(self, capability: MailboxCapability) -> None: ...
    def publish_bundle(self, bundle_id: str, bundle: bytes) -> str: ...
    def fetch_bundle(self, bundle_id: str) -> dict: ...
    def put_blob(
        self, capability: MailboxCapability, chunk_id: str, chunk: bytes
    ) -> str: ...
    def get_blob(self, capability: MailboxCapability, chunk_id: str) -> bytes: ...