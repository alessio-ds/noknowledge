"""Run a real relay (uvicorn) in a background thread for end-to-end tests."""

from __future__ import annotations

import socket
import threading
import time

import requests
import uvicorn

from noknowledge.server.app import create_app
from noknowledge.server.config import Settings


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class RelayProcess:
    def __init__(self, data_dir, **overrides) -> None:
        self.port = free_port()
        self.settings = Settings(
            data_dir=str(data_dir),
            host="127.0.0.1",
            port=self.port,
            housekeeping_interval=10**9,
            **overrides,
        )
        config = uvicorn.Config(
            create_app(self.settings),
            host="127.0.0.1",
            port=self.port,
            log_level="warning",
        )
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def db_path(self):
        from pathlib import Path

        return Path(self.settings.data_dir) / "relay.db"

    def start(self, timeout: float = 15.0) -> "RelayProcess":
        self.thread.start()
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                response = requests.get(f"{self.url}/api/health", timeout=1)
                if response.status_code == 200:
                    return self
            except requests.RequestException:
                time.sleep(0.05)
        raise RuntimeError(f"relay at {self.url} did not become healthy")

    def stop(self, timeout: float = 10.0) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=timeout)

    def __enter__(self) -> "RelayProcess":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()