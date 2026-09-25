"""GUI tests. These run headless via the Qt ``offscreen`` platform.

If PyQt5 (or a system Qt library) is unavailable, this module is skipped rather
than failing: the core and relay suites must pass everywhere.
"""

import os
import threading

import pytest

pytest.importorskip("PyQt5")

from PyQt5.QtCore import Qt

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


def test_settings_defaults_when_missing(tmp_path, monkeypatch):
    monkeypatch.delenv("NK_DEFAULT_RELAYS", raising=False)
    loaded = GuiSettings.load(str(tmp_path))
    assert loaded.relays == ["https://noknowledge.remotewire.net"]
    assert loaded.proxy_enabled is False
    assert loaded.auto_discover is True


def test_shipped_default_relay_is_the_public_one(monkeypatch):
    monkeypatch.delenv("NK_DEFAULT_RELAYS", raising=False)
    from noknowledge.gui.settings import DEFAULT_RELAYS, default_relays

    assert DEFAULT_RELAYS == ["https://noknowledge.remotewire.net"]
    assert default_relays() == DEFAULT_RELAYS


def test_default_relays_can_be_overridden(tmp_path, monkeypatch):
    monkeypatch.setenv("NK_DEFAULT_RELAYS", "http://a.example:1, http://b.example:2")
    assert GuiSettings.load(str(tmp_path)).relays == [
        "http://a.example:1",
        "http://b.example:2",
    ]


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
        self.synced_event = threading.Event()

    def sync(self, wait: int = 0):
        self.synced += 1
        self.synced_event.set()
        return []

    def flush_outbox(self) -> int:
        return 0


def test_worker_runs_submitted_tasks(qapp):
    client = StubClient()
    worker = Worker(client, poll_seconds=1)
    task_event = threading.Event()

    def task(value):
        client.done.append(value)
        task_event.set()
        return value * 2

    worker.start()
    # Let the poll loop run at least once before stopping: otherwise stop() can
    # win the race and sync() is never reached, which made this assertion flaky
    # (it failed on Windows/py3.11 and passed on py3.13).
    assert client.synced_event.wait(10), "worker never polled"
    worker.submit("double", task, 21)
    assert task_event.wait(10), "worker did not run the submitted task"
    worker.stop()
    worker.wait(5000)
    assert client.done == [21]
    assert not worker.isRunning()


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


def test_selecting_a_contact_does_not_recurse(qapp, tmp_path, monkeypatch, relay):
    """Regression: refresh() re-entered itself via currentRowChanged.

    Previously the contact list unblocked its signals and *then* called
    setCurrentRow(), so a single user click recursed
    _contact_changed -> select_contact -> refresh until the interpreter hit its
    recursion limit (which surfaced, confusingly, inside json.loads).

    The earlier GUI tests called contacts_data() directly and so never
    exercised the selection signal path.
    """
    from noknowledge.crypto.identity import Identity
    from noknowledge.gui.session import build_client, identity_path
    from noknowledge.gui.settings import GuiSettings

    monkeypatch.setenv("NK_DISABLE_KEYRING", "1")
    settings = GuiSettings(relays=[relay.url])

    alice_dir = tmp_path / "alice"
    alice_dir.mkdir()
    alice_identity, _ = Identity.generate(label="alice")
    alice_identity.save(identity_path(str(alice_dir)))
    settings.save(str(alice_dir))
    alice = build_client(alice_identity, settings, str(alice_dir))
    alice.provision()

    bob_dir = tmp_path / "bob"
    bob_dir.mkdir()
    bob_identity, _ = Identity.generate(label="bob")
    bob_identity.save(identity_path(str(bob_dir)))
    bob = build_client(bob_identity, settings, str(bob_dir))
    bob.provision()

    alice.add_contact(bob.card_string(), nickname="Bob")
    alice.close()
    bob.close()

    monkeypatch.setenv("NK_DATA_DIR", str(alice_dir))
    from noknowledge.gui.app import App

    window = App()
    try:
        assert window.stack.currentWidget() is window.main_screen
        assert window.main_screen.contacts.count() == 1
        # This emits currentRowChanged; before the fix it recursed forever.
        window.main_screen.contacts.setCurrentRow(0)
        assert window.current_contact == bob_identity.identity_id
        assert window.main_screen.header.text() == "Bob"
    finally:
        window.close()


# -- identity display -----------------------------------------------------

BOB_A = "3TPNKFSE2YY02FKNS7MFS51P7G"
BOB_B = "7QHXW2M4PKR9TVC3DZ8LNB5Y6A"


def _app_with_contacts(tmp_path, monkeypatch, contacts):
    """Build an App whose local store already holds the given contacts."""
    from noknowledge.crypto.identity import Identity
    from noknowledge.gui.session import build_client, identity_path
    from noknowledge.gui.settings import GuiSettings

    monkeypatch.setenv("NK_DISABLE_KEYRING", "1")
    directory = tmp_path / "me"
    directory.mkdir()
    identity, _ = Identity.generate(label="me")
    identity.save(identity_path(str(directory)))
    # Inert relay and discovery off, so no test touches the network.
    settings = GuiSettings(relays=["http://127.0.0.1:1"], auto_discover=False)
    settings.save(str(directory))

    client = build_client(identity, settings, str(directory))
    for index, contact in enumerate(contacts):
        client.store.upsert_contact(
            identity.identity_id,
            {
                "id": contact["id"],
                "isign": b"i" * 32,
                "idh": b"x" * 32,
                "bundle_id": "bundle",
                "inbox": {"id": f"mailbox{index}", "w": "write-token"},
                "relays": ["https://relay.example"],
                "session": None,
                "nickname": contact.get("nickname"),
                "created_at": index + 1,
            },
        )
    client.close()

    monkeypatch.setenv("NK_DATA_DIR", str(directory))
    from noknowledge.gui.app import App

    return App(), identity


def test_duplicate_nicknames_are_disambiguated(qapp, tmp_path, monkeypatch):
    window, _ = _app_with_contacts(
        tmp_path,
        monkeypatch,
        [{"id": BOB_A, "nickname": "Bob"}, {"id": BOB_B, "nickname": "Bob"}],
    )
    try:
        assert window.main_screen.contacts.count() == 2
        labels = [
            window.main_screen.contacts.item(row).text()
            for row in range(window.main_screen.contacts.count())
        ]
        assert len(set(labels)) == 2, f"rows are indistinguishable: {labels}"
        assert labels == ["Bob · 3TPNKFS", "Bob · 7QHXW2M"]
        # The stored contact id is untouched; only the label is decorated.
        ids = [
            window.main_screen.contacts.item(row).data(Qt.UserRole)
            for row in range(window.main_screen.contacts.count())
        ]
        assert ids == [BOB_A, BOB_B]
    finally:
        window.close()


def test_unique_nickname_is_left_alone(qapp, tmp_path, monkeypatch):
    window, _ = _app_with_contacts(
        tmp_path, monkeypatch, [{"id": BOB_A, "nickname": "Bob"}]
    )
    try:
        assert window.main_screen.contacts.item(0).text() == "Bob"
    finally:
        window.close()


def test_chat_header_shows_the_contact_id(qapp, tmp_path, monkeypatch):
    window, _ = _app_with_contacts(
        tmp_path,
        monkeypatch,
        [{"id": BOB_A, "nickname": "Bob"}, {"id": BOB_B, "nickname": "Bob"}],
    )
    try:
        window.main_screen.contacts.setCurrentRow(1)
        assert window.current_contact == BOB_B
        assert window.main_screen.header.text() == "Bob"
        assert window.main_screen.header_id.text() == BOB_B
    finally:
        window.close()


def test_toolbar_shows_your_own_identity_id(qapp, tmp_path, monkeypatch):
    window, identity = _app_with_contacts(tmp_path, monkeypatch, [])
    try:
        assert window.main_screen.identity_label.text() == identity.identity_id
        assert len(identity.identity_id) == 26
    finally:
        window.close()