"""A pool of relays with replication and failover.

Writes fan out to every relay in the set; reads aggregate whatever any relay can
answer. Because envelopes carry a client-generated id, duplicates across relays
are harmless and are filtered by the client core. Any single relay can fail
without losing data, which is what makes the relay set — rather than the relay —
the unit of availability.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor

from noknowledge.crypto.encoding import b64e
from noknowledge.wire.backends.base import (
    CHUNK_ID_SIZE,
    FetchedMessage,
    MailboxCapability,
)
from noknowledge.wire.backends.http_relay import HttpRelayBackend
from noknowledge.wire.errors import (
    AllRelaysFailed,
    RelayHTTPError,
    RelayNotFound,
)
from noknowledge.wire.transport import Transport


def normalize_relay_urls(urls: list[str]) -> list[str]:
    seen: list[str] = []
    for url in urls:
        cleaned = url.strip().rstrip("/")
        if not cleaned:
            continue
        if not cleaned.startswith(("http://", "https://")):
            cleaned = "https://" + cleaned
        if cleaned not in seen:
            seen.append(cleaned)
    return seen


class MultiRelayBackend:
    """Fan-out / fan-in across an ordered set of relays."""

    def __init__(
        self,
        urls: list[str],
        transport: Transport | None = None,
        max_workers: int = 8,
    ) -> None:
        self.transport = transport or Transport()
        self.relays = [
            HttpRelayBackend(url, self.transport) for url in normalize_relay_urls(urls)
        ]
        if not self.relays:
            raise ValueError("at least one relay URL is required")
        self.max_workers = max_workers
        self._pool = ThreadPoolExecutor(max_workers=max_workers)

    @property
    def urls(self) -> list[str]:
        return [relay.base_url for relay in self.relays]

    def shutdown(self) -> None:
        """Release the worker pool but keep the shared transport open.

        Used when swapping in a new backend for a changed relay set: peer
        backends share one transport, so closing it would break them too.
        """
        self._pool.shutdown(wait=False, cancel_futures=True)

    def close(self) -> None:
        self.shutdown()
        self.transport.close()

    # -- mailboxes --------------------------------------------------------

    def create_mailbox(self) -> MailboxCapability:
        """Create one capability and register it on every relay."""
        capability = MailboxCapability.generate()
        return self.register_mailbox(capability)

    def register_mailbox(self, capability: MailboxCapability) -> MailboxCapability:
        futures = [
            self._pool.submit(relay.create_mailbox, capability) for relay in self.relays
        ]
        succeeded = 0
        last_error: Exception | None = None
        for future in futures:
            try:
                future.result()
                succeeded += 1
            except Exception as exc:  # one bad relay must not block the rest
                last_error = exc
        if succeeded == 0:
            raise AllRelaysFailed(f"could not register mailbox: {last_error}")
        return capability

    def put(self, capability: MailboxCapability, envelope: bytes) -> None:
        futures = [
            self._pool.submit(relay.put, capability, envelope) for relay in self.relays
        ]
        succeeded = 0
        last_error: Exception | None = None
        for future in futures:
            try:
                future.result()
                succeeded += 1
            except RelayNotFound:
                continue  # this relay lost the mailbox; others still have it
            except Exception as exc:
                last_error = exc
        if succeeded == 0:
            if last_error is not None:
                raise AllRelaysFailed(f"no relay accepted the message: {last_error}")
            raise RelayNotFound(404, "mailbox not found on any relay")

    def fetch(
        self,
        capability: MailboxCapability,
        cursors: dict[str, int] | None = None,
        wait: int = 0,
    ) -> list[FetchedMessage]:
        """Fetch from all relays concurrently, tagging each blob with its origin."""
        cursors = cursors or {}
        futures = {
            relay.base_url: self._pool.submit(
                relay.fetch, capability, cursors.get(relay.base_url, 0), wait
            )
            for relay in self.relays
        }
        collected: list[FetchedMessage] = []
        for relay_url, future in futures.items():
            try:
                rows = future.result()
            except Exception:
                continue  # availability: one relay failing is not an error
            for seq, blob in rows:
                collected.append(FetchedMessage(relay=relay_url, seq=seq, blob=blob))
        return collected

    def ack(self, capability: MailboxCapability, cursors: dict[str, int]) -> None:
        futures = []
        for relay in self.relays:
            upto = cursors.get(relay.base_url)
            if upto is None:
                continue
            futures.append(self._pool.submit(relay.ack, capability, upto))
        for future in futures:
            try:
                future.result()
            except Exception:
                pass

    def delete_mailbox(self, capability: MailboxCapability) -> None:
        for relay in self.relays:
            try:
                relay.delete_mailbox(capability)
            except Exception:
                pass

    # -- prekeys ----------------------------------------------------------

    def publish_bundle(self, bundle_id: str, bundle: bytes) -> str:
        succeeded = 0
        last_error: Exception | None = None
        for relay in self.relays:
            try:
                relay.publish_bundle(bundle_id, bundle)
                succeeded += 1
            except Exception as exc:
                last_error = exc
        if succeeded == 0:
            raise AllRelaysFailed(f"could not publish prekey bundle: {last_error}")
        return bundle_id

    def fetch_bundle(self, bundle_id: str) -> dict:
        last_error: Exception | None = None
        for relay in self.relays:
            try:
                return relay.fetch_bundle(bundle_id)
            except RelayNotFound as exc:
                last_error = exc
                continue
            except Exception as exc:
                last_error = exc
                continue
        raise RelayNotFound(404, f"bundle not found on any relay: {last_error}")

    # -- blobs ------------------------------------------------------------

    def put_blob(self, capability: MailboxCapability, chunk: bytes) -> str:
        chunk_id = b64e(os.urandom(CHUNK_ID_SIZE))
        succeeded = 0
        last_error: Exception | None = None
        for relay in self.relays:
            try:
                relay.put_blob(capability, chunk_id, chunk)
                succeeded += 1
            except Exception as exc:
                last_error = exc
        if succeeded == 0:
            raise AllRelaysFailed(f"could not upload chunk: {last_error}")
        return chunk_id

    def get_blob(self, capability: MailboxCapability, chunk_id: str) -> bytes:
        last_error: Exception | None = None
        for relay in self.relays:
            try:
                return relay.get_blob(capability, chunk_id)
            except RelayHTTPError as exc:
                last_error = exc
                continue
            except Exception as exc:
                last_error = exc
                continue
        raise RelayNotFound(404, f"blob not found on any relay: {last_error}")

    def health(self) -> list[dict]:
        results = []
        for relay in self.relays:
            try:
                results.append({"url": relay.base_url, **relay.health()})
            except Exception as exc:
                results.append({"url": relay.base_url, "status": "unreachable", "error": str(exc)})
        return results