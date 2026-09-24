"""Persisted GUI settings (relays, proxy, theme)."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field

DEFAULT_RELAYS = ["http://127.0.0.1:8000"]


def data_dir() -> str:
    return os.environ.get("NK_DATA_DIR") or os.path.join(
        os.path.expanduser("~"), ".noknowledge"
    )


@dataclass
class GuiSettings:
    relays: list[str] = field(default_factory=lambda: list(DEFAULT_RELAYS))
    proxy_url: str = ""
    proxy_enabled: bool = False
    fail_closed: bool = False
    theme: str = "dark"
    last_name: str = ""
    poll_seconds: int = 2

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