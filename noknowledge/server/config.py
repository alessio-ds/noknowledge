"""Relay configuration.

A relay is intentionally simple: a directory of opaque blobs and a prekey
noticeboard. Every knob here is about resource limits, never about content.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

MAX_BLOB_BYTES = 256 * 1024
MAX_CHUNK_BYTES = 1024 * 1024
MAX_MESSAGES_PER_MAILBOX = 1000
MAX_BYTES_PER_MAILBOX = 64 * 1024 * 1024
MAX_WAIT_SECONDS = 60
MAX_MESSAGES_PER_FETCH = 200


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_list(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass
class Settings:
    data_dir: str = "relay_data"
    host: str = "127.0.0.1"
    port: int = 8000

    max_blob_bytes: int = MAX_BLOB_BYTES
    max_chunk_bytes: int = MAX_CHUNK_BYTES
    max_messages_per_mailbox: int = MAX_MESSAGES_PER_MAILBOX
    max_bytes_per_mailbox: int = MAX_BYTES_PER_MAILBOX
    max_wait_seconds: int = MAX_WAIT_SECONDS
    max_messages_per_fetch: int = MAX_MESSAGES_PER_FETCH

    mailbox_ttl_seconds: int = 90 * 24 * 3600
    blob_ttl_seconds: int = 30 * 24 * 3600
    housekeeping_interval: int = 3600

    require_hashcash: bool = False
    hashcash_bits: int = 20

    mailbox_creates_per_hour: int = 30
    writes_per_minute: int = 240
    bundles_per_hour: int = 20

    # Discovery: what this relay tells clients about other relays. Clients merge
    # these into their own relay list after probing them, so a relay becomes a
    # seed for the rest of the network.
    advertise_url: str = ""
    known_relays: list[str] = field(default_factory=list)

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, "relay.db")

    @classmethod
    def from_env(cls, **overrides) -> "Settings":
        settings = cls(
            data_dir=os.environ.get("NK_DATA_DIR", "relay_data"),
            host=os.environ.get("NK_HOST", "127.0.0.1"),
            port=_env_int("NK_PORT", 8000),
            require_hashcash=os.environ.get("NK_REQUIRE_HASHCASH", "") not in ("", "0"),
            hashcash_bits=_env_int("NK_HASHCASH_BITS", 20),
            mailbox_ttl_seconds=_env_int("NK_MAILBOX_TTL", 90 * 24 * 3600),
            blob_ttl_seconds=_env_int("NK_BLOB_TTL", 30 * 24 * 3600),
            advertise_url=os.environ.get("NK_ADVERTISE_URL", "").rstrip("/"),
            known_relays=_env_list("NK_KNOWN_RELAYS"),
            mailbox_creates_per_hour=_env_int("NK_MAILBOXES_PER_HOUR", 30),
            writes_per_minute=_env_int("NK_WRITES_PER_MINUTE", 240),
            bundles_per_hour=_env_int("NK_BUNDLES_PER_HOUR", 20),
        )
        for key, value in overrides.items():
            if not hasattr(settings, key):
                raise TypeError(f"unknown setting: {key}")
            setattr(settings, key, value)
        return settings