"""Relay error types."""


class RelayError(Exception):
    """Base class for relay-side failures."""


class MailboxNotFound(RelayError):
    """No such mailbox. Writes to it store nothing and return 404."""


class BundleNotFound(RelayError):
    """No such prekey bundle."""


class BlobNotFound(RelayError):
    """No such blob."""


class QuotaExceeded(RelayError):
    """The mailbox has reached its message or byte quota."""


class TokenInvalid(RelayError):
    """The presented capability token does not match."""