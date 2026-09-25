"""Persisted GUI settings (relays, proxy, theme, discovery)."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field

#: The relay a fresh install starts with.
DEFAULT_RELAYS = ["https://noknowledge.remotewire.net"]

#: Comma-separated override, so a self-hoster can bake in their own relay and
#: tests never touch the public one.
DEFAULT_RELAYS_ENV = "NK_DEFAULT_RELAYS"

DEFAULT_DISCOVERY_INTERVAL = 900


def default_relays() -> list[str]:
    """Relays a new install starts with, honouring ``NK_DEFAULT_RELAYS``."""
    raw = os.environ.get(DEFAULT_RELAYS_ENV)
    if raw:
        relays = [item.strip() for item in raw.split(",") if item.strip()]
        if relays:
            return relays
    return list(DEFAULT_RELAYS)


def data_dir() -> str:
    return os.environ.get("NK_DATA_DIR") or os.path.join(
        os.path.expanduser("~"), ".noknowledge"
    )


@dataclass
class GuiSettings:
    relays: list[str] = field(default_factory=default_relays)
    proxy_url: str = ""
    proxy_enabled: bool = False
    fail_closed: bool = False
    theme: str = "dark"
    last_name: str = ""
    poll_seconds: int = 2
    #: Merge reachable relays advertised by our current relays into the list.
    auto_discover: bool = True
    discovery_interval: int = DEFAULT_DISCOVERY_INTERVAL

    def save(self, directory: str | None = None) -> None:
        directory = directory or data_dir()
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, "settings.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(asdict(self), handle, indent=2, sort_keys=True)

    @classmethod
    def load(cls, directory: str | None = None) -> "GuiSettings":
        directory = directory or data_dir()
        path = os.path.join(directory, "settings.json")
        if not os.path.exists(path):
            return cls()
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return cls()
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})