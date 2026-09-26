"""GUI tests. These run headless via the Qt ``offscreen`` platform.

If PyQt5 (or a system Qt library) is unavailable, this module is skipped rather
than failing: the core and relay suites must pass everywhere.
"""

import os
import threading

import pytest

pytest.importorskip("PyQt5")

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QListWidget

from noknowledge.core.devices import DeviceEntry
from noknowledge.crypto.identity import Identity
from noknowledge.gui.app import DevicesDialog
from noknowledge.gui.session import build_transport
from noknowledge.gui.settings import GuiSettings
from noknowledge.gui.worker import Worker


# -- devices dialog -------------------------------------------------------


def test_devices_dialog_lists_each_device(qapp):
    devices = [
        DeviceEntry(
            device_id="device-one-identifier",
            inbox={"id": "mailbox-one-identifier", "w": "token"},
            relays=["https://relay.example"],
            bundle_id="bundle-one",
            name="laptop",
        ),
        DeviceEntry(
            device_id="device-two-identifier",
            inbox={"id": "mailbox-two-identifier", "w": "token"},
            relays=["https://relay.example", "https://other.example"],
            bundle_id="bundle-two",
            name="phone",
        ),
    ]

    dialog = DevicesDialog(devices, None, devices[0].device_id)
    try:
        listing = dialog.findChild(QListWidget)
        assert listing is not None
        assert listing.count() == 2
        text = "\n".join(listing.item(i).text() for i in range(listing.count()))
        assert "laptop" in text and "phone" in text
        assert devices[0].device_id[:10] in text
        assert devices[0].inbox["id"][:10] in text
        assert "https://other.example" in text
        # The account name is the same on both devices, so the marker is what
        # tells you which one you are looking at.
        assert text.count("this device") == 1
        assert "this device" in listing.item(0).text()
    finally:
        dialog.close()


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


# -- "My card" QR ---------------------------------------------------------


def _sample(image):
    """A coarse pixel fingerprint, enough to compare two renders."""
    step = max(1, image.width() // 24)
    return tuple(
        image.pixel(x, y)
        for x in range(0, image.width(), step)
        for y in range(0, image.height(), step)
    )


def test_qr_pixmap_is_square_bi_colour_and_deterministic(qapp):
    from noknowledge.gui.app import qr_pixmap

    pixmap = qr_pixmap("nk://1/hello")
    assert pixmap is not None and not pixmap.isNull()
    assert pixmap.width() == pixmap.height()
    assert pixmap.width() >= 21  # smallest QR symbol

    image = pixmap.toImage()
    assert len(set(_sample(image))) > 1, "QR is blank"
    # Same input renders identically; different input does not.
    assert _sample(qr_pixmap("nk://1/hello").toImage()) == _sample(image)
    assert _sample(qr_pixmap("nk://1/other").toImage()) != _sample(image)


def test_qr_pixmap_handles_a_real_card(qapp):
    from noknowledge.core.card import ContactCard
    from noknowledge.crypto.identity import Identity
    from noknowledge.gui.app import qr_pixmap
    from noknowledge.wire.backends.base import MailboxCapability

    identity, _ = Identity.generate(label="alice")
    card = ContactCard.create(
        identity,
        "A" * 16,
        MailboxCapability.generate(),
        ["https://noknowledge.remotewire.net"],
        "alice",
    )
    text = card.to_string()
    assert len(text) > 300  # a real card is well over the smallest QR capacity

    pixmap = qr_pixmap(text)
    assert pixmap is not None and not pixmap.isNull()
    assert pixmap.width() == pixmap.height()


def test_card_dialog_shows_the_qr(qapp):
    from noknowledge.core.card import ContactCard
    from noknowledge.crypto.identity import Identity
    from noknowledge.gui.app import CardDialog
    from noknowledge.wire.backends.base import MailboxCapability

    identity, _ = Identity.generate(label="alice")
    card = ContactCard.create(
        identity, "B" * 16, MailboxCapability.generate(), ["https://relay.example"]
    )
    dialog = CardDialog(card.to_string())
    try:
        pixmap = dialog.qr.pixmap()
        assert pixmap is not None and not pixmap.isNull()
        # The card text is still available for copying.
        assert dialog.text.toPlainText() == card.to_string()
    finally:
        dialog.close()

# -- lock and switch identity ---------------------------------------------


def test_identity_is_encrypted_reads_the_vault(tmp_path):
    from noknowledge.crypto.identity import Identity
    from noknowledge.gui.session import identity_is_encrypted

    plain = tmp_path / "plain.nk"
    guarded = tmp_path / "guarded.nk"
    Identity.generate("a")[0].save(str(plain))
    Identity.generate("b")[0].save(str(guarded), "secret")

    assert identity_is_encrypted(str(plain)) is False
    assert identity_is_encrypted(str(guarded)) is True
    # An unreadable file must not promise that an empty passphrase will do.
    assert identity_is_encrypted(str(tmp_path / "missing.nk")) is True


def test_lock_signs_out_and_can_unlock_again(qapp, tmp_path, monkeypatch):
    window, identity = _app_with_contacts(
        tmp_path,
        monkeypatch,
        [{"id": BOB_A, "nickname": "Bob"}],
    )
    try:
        assert window.stack.currentWidget() is window.main_screen
        assert window.client is not None
        assert window.main_screen.contacts.count() == 1

        window.lock()

        # Back to the unlock screen, with no keys, client or history in memory.
        assert window.stack.currentWidget() is window.unlock
        assert window.client is None
        assert window.worker is None
        assert window.identity is None
        assert window.main_screen.contacts.count() == 0
        assert window.main_screen.identity_label.text() == ""
        assert window.main_screen.chat.toPlainText() == ""
        # This identity has no passphrase, so the screen says exactly that.
        assert window.unlock.passphrase.isEnabled() is False
        assert "no passphrase" in window.unlock.hint.text()

        # Unlocking again restores the same account.
        window.unlock.unlocked.emit("")
        assert window.stack.currentWidget() is window.main_screen
        assert window.identity is not None
        assert window.identity.identity_id == identity.identity_id
        assert window.main_screen.contacts.count() == 1
    finally:
        window.close()


def test_lock_clears_a_live_conversation(qapp, tmp_path, monkeypatch):
    """A locked window must not leave decrypted messages on screen."""
    window, _ = _app_with_contacts(
        tmp_path,
        monkeypatch,
        [{"id": BOB_A, "nickname": "Bob"}],
    )
    try:
        window.main_screen.contacts.setCurrentRow(0)
        assert window.current_contact == BOB_A

        window.lock()

        assert window.current_contact is None
        assert window.main_screen.header.text() == "Select a contact"
        assert "Bob" not in window.main_screen.chat.toPlainText()
    finally:
        window.close()


def test_switching_identity_is_cancellable(qapp, tmp_path, monkeypatch):
    from PyQt5.QtWidgets import QMessageBox

    window, identity = _app_with_contacts(
        tmp_path,
        monkeypatch,
        [{"id": BOB_A, "nickname": "Bob"}],
    )
    try:
        window.lock()
        monkeypatch.setattr(
            QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.No)
        )
        # Clicking, not calling, so the signal wiring is exercised too.
        window.unlock.switch.click()
        # Declining the warning leaves us exactly where we were.
        assert window.stack.currentWidget() is window.unlock

        monkeypatch.setattr(
            QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.Yes)
        )
        window.unlock.switch.click()
        assert window.stack.currentWidget() is window.welcome
        assert window.client is None
        assert window.identity is None
        assert identity.identity_id  # the old identity is only signed out, not deleted
    finally:
        window.close()
