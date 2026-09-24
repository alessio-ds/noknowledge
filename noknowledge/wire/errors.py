"""Wire-layer error types."""


class WireError(Exception):
    """Base class for wire/transport failures."""


class TransportError(WireError):
    """The transport could not complete a request (network, proxy, timeout)."""


class RelayHTTPError(WireError):
    """A relay returned an error status."""

    def __init__(self, status: int, detail: str = "") -> None:
        super().__init__(f"relay returned {status}: {detail}")
        self.status = status
        self.detail = detail


class RelayNotFound(RelayHTTPError):
    """The mailbox, bundle or blob does not exist on this relay."""


class RelayUnauthorized(RelayHTTPError):
    """The capability token was missing or invalid."""


class RelayQuotaExceeded(RelayHTTPError):
    """The mailbox quota or a rate limit was exceeded."""


class AllRelaysFailed(WireError):
    """No relay in the configured set could satisfy the operation."""