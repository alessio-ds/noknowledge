"""HTTP backend for a single relay."""

from __future__ import annotations

from noknowledge.crypto.encoding import b64d
from noknowledge.wire.backends.base import MailboxCapability
from noknowledge.wire.errors import (
    RelayHTTPError,
    RelayNotFound,
    RelayQuotaExceeded,
    RelayUnauthorized,
)
from noknowledge.wire.transport import Transport


class HttpRelayBackend:
    def __init__(self, base_url: str, transport: Transport | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.transport = transport or Transport()

    # -- helpers ----------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self.base_url}/api{path}"

    @staticmethod
    def _raise_for_status(response) -> None:
        status = response.status_code
        if status < 400:
            return
        detail = ""
        try:
            detail = response.json().get("detail", "")
        except Exception:
            detail = response.text[:200]
        if status == 404:
            raise RelayNotFound(status, detail)
        if status in (401, 403):
            raise RelayUnauthorized(status, detail)
        if status == 429:
            raise RelayQuotaExceeded(status, detail)
        raise RelayHTTPError(status, detail)

    # -- mailboxes --------------------------------------------------------

    def create_mailbox(self, capability: MailboxCapability) -> None:
        response = self.transport.request(
            "POST", self._url("/mailbox"), json=capability.to_json()
        )
        self._raise_for_status(response)

    def put(self, capability: MailboxCapability, envelope: bytes) -> int:
        response = self.transport.request(
            "POST",
            self._url(f"/mailbox/{capability.mailbox_id}/messages"),
            headers={"X-NK-Write": capability.write_token},
            data=envelope,
        )
        self._raise_for_status(response)
        return int(response.json()["seq"])

    def fetch(
        self, capability: MailboxCapability, after_seq: int = 0, wait: int = 0
    ) -> list[tuple[int, bytes]]:
        if capability.read_token is None:
            raise RelayUnauthorized(401, "no read capability for this mailbox")
        response = self.transport.request(
            "GET",
            self._url(f"/mailbox/{capability.mailbox_id}"),
            headers={"X-NK-Read": capability.read_token},
            params={"after_seq": after_seq, "wait": wait},
        )
        self._raise_for_status(response)
        payload = response.json()
        return [(int(m["seq"]), b64d(m["blob"])) for m in payload.get("messages", [])]

    def ack(self, capability: MailboxCapability, upto_seq: int) -> int:
        if capability.read_token is None:
            raise RelayUnauthorized(401, "no read capability for this mailbox")
        response = self.transport.request(
            "POST",
            self._url(f"/mailbox/{capability.mailbox_id}/ack"),
            headers={"X-NK-Read": capability.read_token},
            json={"upto_seq": int(upto_seq)},
        )
        self._raise_for_status(response)
        return int(response.json().get("deleted", 0))

    def delete_mailbox(self, capability: MailboxCapability) -> None:
        if capability.read_token is None:
            raise RelayUnauthorized(401, "no read capability for this mailbox")
        response = self.transport.request(
            "DELETE",
            self._url(f"/mailbox/{capability.mailbox_id}"),
            headers={"X-NK-Read": capability.read_token},
        )
        self._raise_for_status(response)

    # -- prekeys ----------------------------------------------------------

    def publish_bundle(self, bundle_id: str, bundle: bytes) -> str:
        response = self.transport.request(
            "POST",
            self._url("/prekeys"),
            data=bundle,
            headers={"Content-Type": "application/json"},
        )
        self._raise_for_status(response)
        return str(response.json()["bundle_id"])

    def fetch_bundle(self, bundle_id: str) -> dict:
        response = self.transport.request("GET", self._url(f"/prekeys/{bundle_id}"))
        self._raise_for_status(response)
        return response.json()

    # -- blobs ------------------------------------------------------------

    def put_blob(
        self, capability: MailboxCapability, chunk_id: str, chunk: bytes
    ) -> str:
        response = self.transport.request(
            "POST",
            self._url("/blob"),
            headers={
                "X-NK-Write": capability.write_token,
                "X-NK-Mailbox": capability.mailbox_id,
                "X-NK-Chunk": chunk_id,
            },
            data=chunk,
        )
        self._raise_for_status(response)
        return str(response.json()["chunk_id"])

    def get_blob(self, capability: MailboxCapability, chunk_id: str) -> bytes:
        if capability.read_token is None:
            raise RelayUnauthorized(401, "no read capability for this mailbox")
        response = self.transport.request(
            "GET",
            self._url(f"/blob/{chunk_id}"),
            headers={
                "X-NK-Read": capability.read_token,
                "X-NK-Mailbox": capability.mailbox_id,
            },
        )
        self._raise_for_status(response)
        return response.content

    def health(self) -> dict:
        response = self.transport.request("GET", self._url("/health"))
        self._raise_for_status(response)
        return response.json()