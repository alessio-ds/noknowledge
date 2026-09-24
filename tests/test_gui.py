"""GUI tests. These run headless via the Qt ``offscreen`` platform.

If PyQt5 (or a system Qt library) is unavailable, this module is skipped rather
than failing: the core and relay suites must pass everywhere.
"""

import os
import threading

import pytest

pytest.importorskip("PyQt5")

from noknowledge.crypto.identity import Identity
from noknowledge.gui.session import build_transport
from noknowledge.gui.settings import GuiSettings
from noknowledge.gui.worker import Worker


# -- settings -------------------------------------------------------------


def test_settings_roundtrip(tmp_path):
    settings = GuiSettings(
        relays=["https://a.example", "https://b.example"],
        proxy_url="socks5://127.0.0.1:9050",
        proxy_enabled=True,
        fail_closed=True,
        theme="light",
        last_name="alice",
    )
    settings.save(str(tmp_path))
    loaded = GuiSettings.load(str(tmp_path))
    assert loaded == settings


def test_settings_defaults_when_missing(tmp_path):
    loaded = GuiSettings.load(str(tmp_path))
    assert loaded.relays == ["http://127.0.0.1:8000"]
    assert loaded.proxy_enabled is False


def test_settings_ignores_unknown_keys(tmp_path):
    (tmp_path / "settings.json").write_text('{"relays": ["x"], "bogus": 1}')
    loaded = GuiSettings.load(str(tmp_path))
    assert loaded.relays == ["x"]


def test_transport_is_fail_closed_with_proxy():
    transport = build_transport(GuiSettings(proxy_enabled=True, proxy_url="socks5://x:1"))
    assert transport.fail_closed is True
    assert transport.proxy_url == "socks5://x:1"


def test_transport_is_direct_by_default():
    transport = build_transport(GuiSettings())
    assert transport.fail_closed is False
    assert transport.proxy_url is None


# -- worker ---------------------------------------------------------------


class StubClient:
    def __init__(self) -> None:
        self.synced = 0
        self.done: list = []

    def sync(self, wait: int = 0):
        self.synced += 1
        return []

    def flush_outbox(self) -> int:
        return 0


def test_worker_runs_submitted_tasks(qapp):
    client = StubClient()
    worker = Worker(client, poll_seconds=1)
    event = threading.Event()

    def task(value):
        client.done.append(value)
        event.set()
        return value * 2

    worker.start()
    worker.submit("double", task, 21)
    assert event.wait(10), "worker did not run the submitted task"
    worker.stop()
    worker.wait(5000)
    assert client.done == [21]
    assert client.synced >= 1


def test_worker_survives_client_errors(qapp):
    class BrokenClient(StubClient):
        def sync(self, wait: int = 0):
            raise RuntimeError("relay down")

    worker = Worker(BrokenClient(), poll_seconds=1)
    errors: list = []
    worker.error_occurred.connect(errors.append)
    worker.start()
    worker.stop()
    worker.wait(5000)
    # the worker must not propagate the exception out of run()
    assert worker.isFinished()


# -- application ----------------------------------------------------------


def test_app_shows_welcome_without_identity(qapp, tmp_path, monkeypatch):
    monkeypatch.setenv("NK_DATA_DIR", str(tmp_path))
    from noknowledge.gui.app import App

    window = App()
    assert window.stack.currentWidget() is window.welcome
    window.close()


def test_app_unlocks_plaintext_identity(qapp, tmp_path, monkeypatch, relay):
    monkeypatch.setenv("NK_DATA_DIR", str(tmp_path))
    identity, _ = Identity.generate(label="alice")
    identity.save(str(tmp_path / "identity.nk"))

    from noknowledge.gui.app import App

    window = App()
    assert window.stack.currentWidget() is window.main_screen
    window.close()


def test_app_shows_unlock_screen_for_encrypted_identity(qapp, tmp_path, monkeypatch):
    monkeypatch.setenv("NK_DATA_DIR", str(tmp_path))
    identity, _ = Identity.generate(label="alice")
    identity.save(str(tmp_path / "identity.nk"), passphrase="secret")

    from noknowledge.gui.app import App

    window = App()
    assert window.stack.currentWidget() is window.unlock
    window.close()


def test_create_flow_reaches_seedphrase(qapp, tmp_path, monkeypatch):
    monkeypatch.setenv("NK_DATA_DIR", str(tmp_path))
    from noknowledge.gui.app import App

    window = App()
    window._on_create("alice", "")
    assert window.stack.currentWidget() is window.seedphrase
    words = window.seedphrase.words.toPlainText().split()
    assert len(words) == 24
    assert window.seedphrase.continue_button.isEnabled() is False
    window.seedphrase.ack.setChecked(True)
    assert window.seedphrase.continue_button.isEnabled() is True
    window.close()