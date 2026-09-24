"""noknowledge — a zero-knowledge, federated messenger.

The relay stores opaque, end-to-end encrypted blobs addressed by unguessable
mailbox capabilities. It never learns identities, senders, recipients, or
content. See PLAN.md, PROTOCOL.md and THREAT_MODEL.md.
"""

from noknowledge.version import __version__

__all__ = ["__version__"]