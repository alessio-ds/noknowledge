"""PyQt5 desktop client.

A thin view over :class:`Client`: all network work runs on the :class:`Worker`
thread and reaches the UI through Qt signals, so the interface never blocks.
"""

from __future__ import annotations

import html
import os
import sys
import time
from collections import Counter

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QFontDatabase, QKeySequence, QPainter, QPixmap
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QShortcut,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from noknowledge.core import history as history_mod
from noknowledge.crypto.identity import Identity, IdentityError
from noknowledge.gui.session import build_client, identity_is_encrypted, identity_path
from noknowledge.gui.settings import GuiSettings, data_dir
from noknowledge.gui.worker import Worker

STYLESHEET = """
QWidget { background: #1e1f22; color: #e6e6e6; font-size: 13px; }
QLineEdit, QPlainTextEdit, QTextBrowser, QListWidget {
    background: #2b2d31; border: 1px solid #3a3d43; border-radius: 6px; padding: 6px;
}
QPushButton {
    background: #3b82f6; color: white; border: none; border-radius: 6px;
    padding: 8px 14px;
}
QPushButton:disabled { background: #3a3d43; color: #8a8a8a; }
QPushButton#secondary { background: #3a3d43; }
QLabel#title { font-size: 22px; font-weight: 600; }
QLabel#subtitle { color: #9aa0a6; }
"""


# -- dialogs --------------------------------------------------------------


class AddContactDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add contact")
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Paste your contact's card (nk://1/...)"))
        self.card = QPlainTextEdit()
        self.card.setPlaceholderText("nk://1/...")
        layout.addWidget(self.card)
        layout.addWidget(QLabel("Nickname (optional)"))
        self.nickname = QLineEdit()
        layout.addWidget(self.nickname)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def values(self) -> tuple[str, str]:
        return self.card.toPlainText().strip(), self.nickname.text().strip()


#: Time windows offered for history export and device back-fill.
RANGE_CHOICES = [
    ("Last 30 days", 30),
    ("Last 60 days", 60),
    ("Last 90 days", 90),
    ("Everything", None),
]


def ask_range(parent, title: str) -> int | None | bool:
    """Ask how far back to go.

    Returns milliseconds-since-epoch for a bounded window, ``None`` for
    everything, or ``False`` when the user cancels.
    """
    labels = [label for label, _ in RANGE_CHOICES]
    choice, ok = QInputDialog.getItem(
        parent, title, "How much history?", labels, 0, False
    )
    if not ok:
        return False
    days = dict(RANGE_CHOICES)[choice]
    if days is None:
        return None
    return int((time.time() - days * 24 * 3600) * 1000)


def qr_pixmap(text: str, target: int = 300) -> QPixmap | None:
    """Render ``text`` as a QR code, or ``None`` if that is not possible.

    Drawn module-by-module with an integer scale rather than scaled from a
    bitmap, so the module edges stay crisp and the code remains scannable.
    """
    try:
        import segno

        matrix = list(segno.make(text, error="m").matrix_iter(border=2))
    except Exception:
        return None
    modules = len(matrix)
    if modules == 0 or not matrix[0]:
        return None
    scale = max(1, target // modules)
    side = modules * scale
    pixmap = QPixmap(side, side)
    pixmap.fill(Qt.white)
    painter = QPainter(pixmap)
    painter.setPen(Qt.NoPen)
    painter.setBrush(Qt.black)
    for y, row in enumerate(matrix):
        for x, dark in enumerate(row):
            if dark:
                painter.drawRect(x * scale, y * scale, scale, scale)
    painter.end()
    return pixmap


class CardDialog(QDialog):
    def __init__(self, card_text: str, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("My contact card")
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        layout.addWidget(
            QLabel("Share this with someone so they can message you. Anyone who\n"
                   "has it can write to your mailbox, but only you can read it.")
        )
        self.qr = QLabel()
        self.qr.setAlignment(Qt.AlignCenter)
        pixmap = qr_pixmap(card_text)
        if pixmap is not None:
            self.qr.setPixmap(pixmap)
            self.qr.setToolTip("Scan this with another noknowledge client")
        else:
            self.qr.hide()
        layout.addWidget(self.qr)
        self.text = QPlainTextEdit(card_text)
        self.text.setReadOnly(True)
        layout.addWidget(self.text)
        copy = QPushButton("Copy to clipboard")
        copy.clicked.connect(self._copy)
        layout.addWidget(copy)
        layout.addWidget(QDialogButtonBox(QDialogButtonBox.Close, rejected=self.reject))

    def _copy(self) -> None:
        QApplication.clipboard().setText(self.text.toPlainText())


class DevicesDialog(QDialog):
    """The devices that share this account, as advertised to senders."""

    def __init__(
        self,
        devices: list,
        parent=None,
        current_device_id: str | None = None,
        app=None,
        cache_bytes: int = 0,
        cache_chunks: int = 0,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("My devices")
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        layout.addWidget(
            QLabel(
                "Every device below receives its own encrypted copy of anything\n"
                "sent to you. To add one, restore your seed phrase on it — it gets\n"
                "a fresh mailbox and joins this list automatically."
            )
        )
        listing = QListWidget()
        for device in devices:
            relays = ", ".join(device.relays) or "(this device's relays)"
            mine = "   ← this device" if device.device_id == current_device_id else ""
            item = QListWidgetItem(
                f"{device.name or 'unnamed device'}  ·  {device.device_id[:10]}{mine}\n"
                f"    mailbox {device.inbox['id'][:10]}…  →  {relays}"
            )
            item.setToolTip(device.device_id)
            listing.addItem(item)
        layout.addWidget(listing)
        layout.addWidget(
            QLabel(
                "History is not synced automatically: a newly added device sees\n"
                "messages sent after it joined, plus whatever you hand it below."
            )
        )

        if app is not None:
            layout.addWidget(QLabel("History"))
            self.cache = QLabel(
                f"{cache_chunks} attachment chunk(s) cached locally "
                f"({cache_bytes / (1024 * 1024):.1f} MB)"
            )
            self.cache.setObjectName("subtitle")
            layout.addWidget(self.cache)
            row = QHBoxLayout()
            export = QPushButton("Export history…")
            export.clicked.connect(app.export_history)
            import_button = QPushButton("Import history…")
            import_button.clicked.connect(app.import_history)
            row.addWidget(export)
            row.addWidget(import_button)
            layout.addLayout(row)
            layout.addWidget(
                QLabel(
                    "The file is encrypted with a passphrase you choose, and carries\n"
                    "contacts, messages and any attachments cached here. Importing\n"
                    "merges it into this device without creating duplicates."
                )
            )

        layout.addWidget(QDialogButtonBox(QDialogButtonBox.Close, rejected=self.reject))


class SettingsDialog(QDialog):
    def __init__(self, settings: GuiSettings, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Relays (one URL per line — messages replicate to all)"))
        self.relays = QPlainTextEdit("\n".join(settings.relays))
        layout.addWidget(self.relays)

        self.proxy_enabled = QCheckBox("Route all traffic through a proxy (Tor/SOCKS5)")
        self.proxy_enabled.setChecked(settings.proxy_enabled)
        layout.addWidget(self.proxy_enabled)
        self.proxy_url = QLineEdit(settings.proxy_url)
        self.proxy_url.setPlaceholderText("socks5://127.0.0.1:9050")
        layout.addWidget(self.proxy_url)

        self.fail_closed = QCheckBox("Fail closed (never connect directly)")
        self.fail_closed.setChecked(settings.fail_closed or settings.proxy_enabled)
        layout.addWidget(self.fail_closed)

        self.auto_discover = QCheckBox(
            "Automatically discover new relays advertised by my relays"
        )
        self.auto_discover.setChecked(settings.auto_discover)
        layout.addWidget(self.auto_discover)

        layout.addWidget(QLabel("Poll interval (seconds)"))
        self.poll = QSpinBox()
        self.poll.setRange(1, 60)
        self.poll.setValue(settings.poll_seconds)
        layout.addWidget(self.poll)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def apply_to(self, settings: GuiSettings) -> GuiSettings:
        relays = [line.strip() for line in self.relays.toPlainText().splitlines()]
        settings.relays = [r for r in relays if r] or ["http://127.0.0.1:8000"]
        settings.proxy_enabled = self.proxy_enabled.isChecked()
        settings.proxy_url = self.proxy_url.text().strip()
        settings.fail_closed = self.fail_closed.isChecked()
        settings.auto_discover = self.auto_discover.isChecked()
        settings.poll_seconds = self.poll.value()
        return settings


# -- onboarding screens ---------------------------------------------------


class WelcomeScreen(QWidget):
    create_requested = pyqtSignal()
    recover_requested = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addStretch()
        title = QLabel("noknowledge")
        title.setObjectName("title")
        layout.addWidget(title, alignment=Qt.AlignCenter)
        subtitle = QLabel("Private messaging that even the relay cannot read")
        subtitle.setObjectName("subtitle")
        layout.addWidget(subtitle, alignment=Qt.AlignCenter)
        layout.addSpacing(20)
        create = QPushButton("Create a new identity")
        create.clicked.connect(self.create_requested.emit)
        recover = QPushButton("Recover from a seed phrase")
        recover.setObjectName("secondary")
        recover.clicked.connect(self.recover_requested.emit)
        for button in (create, recover):
            button.setFixedWidth(280)
            layout.addWidget(button, alignment=Qt.AlignCenter)
        layout.addStretch()


class CreateIdentityScreen(QWidget):
    created = pyqtSignal(str, str)
    cancelled = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        title = QLabel("Create identity")
        title.setObjectName("title")
        layout.addWidget(title)
        layout.addWidget(QLabel("Display name (local only — never sent to a relay)"))
        self.name = QLineEdit()
        layout.addWidget(self.name)
        layout.addWidget(QLabel("Passphrase (optional, encrypts your key on disk)"))
        self.passphrase = QLineEdit()
        self.passphrase.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.passphrase)
        self.confirm = QLineEdit()
        self.confirm.setEchoMode(QLineEdit.Password)
        self.confirm.setPlaceholderText("confirm passphrase")
        layout.addWidget(self.confirm)
        row = QHBoxLayout()
        back = QPushButton("Back")
        back.setObjectName("secondary")
        back.clicked.connect(self.cancelled.emit)
        create = QPushButton("Generate my seed phrase")
        create.clicked.connect(self._submit)
        row.addWidget(back)
        row.addWidget(create)
        layout.addLayout(row)
        layout.addStretch()

    def _submit(self) -> None:
        if self.passphrase.text() != self.confirm.text():
            QMessageBox.warning(self, "Passphrase", "The passphrases do not match.")
            return
        self.created.emit(self.name.text().strip(), self.passphrase.text())


class SeedphraseScreen(QWidget):
    confirmed = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        title = QLabel("Your seed phrase")
        title.setObjectName("title")
        layout.addWidget(title)
        layout.addWidget(
            QLabel("Write these 24 words down. They are the only way to recover\n"
                   "this identity. They never leave this device.")
        )
        self.words = QPlainTextEdit()
        self.words.setReadOnly(True)
        self.words.setFont(QFont("Menlo", 14))
        layout.addWidget(self.words)
        self.ack = QCheckBox("I have written my seed phrase down")
        self.ack.stateChanged.connect(self._update)
        layout.addWidget(self.ack)
        self.continue_button = QPushButton("Continue")
        self.continue_button.setEnabled(False)
        self.continue_button.clicked.connect(self.confirmed.emit)
        layout.addWidget(self.continue_button)

    def set_mnemonic(self, mnemonic: str) -> None:
        self.words.setPlainText(mnemonic)
        self.ack.setChecked(False)
        self._update()

    def _update(self) -> None:
        self.continue_button.setEnabled(self.ack.isChecked())


class RecoverScreen(QWidget):
    recovered = pyqtSignal(str, str, str)
    cancelled = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        title = QLabel("Recover identity")
        title.setObjectName("title")
        layout.addWidget(title)
        layout.addWidget(QLabel("Your 24-word seed phrase"))
        self.mnemonic = QPlainTextEdit()
        layout.addWidget(self.mnemonic)
        layout.addWidget(QLabel("Display name (optional)"))
        self.name = QLineEdit()
        layout.addWidget(self.name)
        layout.addWidget(QLabel("Passphrase (only if you set one)"))
        self.passphrase = QLineEdit()
        self.passphrase.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.passphrase)
        row = QHBoxLayout()
        back = QPushButton("Back")
        back.setObjectName("secondary")
        back.clicked.connect(self.cancelled.emit)
        recover = QPushButton("Recover")
        recover.clicked.connect(
            lambda: self.recovered.emit(
                self.mnemonic.toPlainText().strip(),
                self.name.text().strip(),
                self.passphrase.text(),
            )
        )
        row.addWidget(back)
        row.addWidget(recover)
        layout.addLayout(row)
        layout.addStretch()


class UnlockScreen(QWidget):
    unlocked = pyqtSignal(str)
    switch_requested = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addStretch()
        title = QLabel("Locked")
        title.setObjectName("title")
        layout.addWidget(title, alignment=Qt.AlignCenter)
        self.hint = QLabel("")
        self.hint.setObjectName("subtitle")
        layout.addWidget(self.hint, alignment=Qt.AlignCenter)
        self.passphrase = QLineEdit()
        self.passphrase.setEchoMode(QLineEdit.Password)
        self.passphrase.setPlaceholderText("passphrase")
        self.passphrase.returnPressed.connect(
            lambda: self.unlocked.emit(self.passphrase.text())
        )
        self.passphrase.setFixedWidth(320)
        layout.addWidget(self.passphrase, alignment=Qt.AlignCenter)
        button = QPushButton("Unlock")
        button.setFixedWidth(320)
        button.clicked.connect(lambda: self.unlocked.emit(self.passphrase.text()))
        layout.addWidget(button, alignment=Qt.AlignCenter)
        self.switch = QPushButton("Use a different identity…")
        self.switch.setObjectName("secondary")
        self.switch.setFixedWidth(320)
        # Not `self.switch_requested.emit` directly: Qt hands `clicked` a
        # `checked` bool, which a zero-argument signal's emit would reject.
        self.switch.clicked.connect(lambda: self.switch_requested.emit())
        layout.addWidget(self.switch, alignment=Qt.AlignCenter)
        layout.addStretch()
        self.prepare(encrypted=True)

    def prepare(self, encrypted: bool = True) -> None:
        """Describe what unlocking this identity actually takes."""
        if encrypted:
            self.hint.setText("Enter your passphrase to open your account.")
            self.passphrase.setEnabled(True)
            self.passphrase.setPlaceholderText("passphrase")
        else:
            self.hint.setText(
                "This identity has no passphrase, so it is locked only in memory.\n"
                "Press Unlock to continue."
            )
            self.passphrase.setEnabled(False)
            self.passphrase.setPlaceholderText("(no passphrase set)")
        self.passphrase.clear()


# -- main screen ----------------------------------------------------------


class MainScreen(QWidget):
    def __init__(self, app: "App") -> None:
        super().__init__()
        self.app = app
        layout = QVBoxLayout(self)

        toolbar = QHBoxLayout()
        self.my_card = QPushButton("My card")
        self.my_card.clicked.connect(app.show_my_card)
        add = QPushButton("Add contact")
        add.clicked.connect(app.add_contact)
        settings = QPushButton("Settings")
        settings.setObjectName("secondary")
        settings.clicked.connect(app.open_settings)
        self.status = QLabel("starting…")
        self.status.setObjectName("subtitle")

        # Your own identity ID. Nicknames are self-asserted, so the ID is the
        # only handle a contact can actually verify out of band.
        self.identity_label = QLabel("")
        self.identity_label.setObjectName("subtitle")
        self.identity_label.setFont(
            QFontDatabase.systemFont(QFontDatabase.FixedFont)
        )
        self.identity_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.identity_label.setToolTip(
            "Your identity ID — share it so a contact can verify you"
        )
        self.copy_id = QPushButton("Copy ID")
        self.copy_id.setObjectName("secondary")
        self.copy_id.clicked.connect(app.copy_identity_id)
        self.devices_button = QPushButton("Devices")
        self.devices_button.setObjectName("secondary")
        self.devices_button.setToolTip(
            "Every device on your account receives its own encrypted copy"
        )
        self.devices_button.clicked.connect(app.show_devices)
        self.lock_button = QPushButton("Lock")
        self.lock_button.setObjectName("secondary")
        self.lock_button.setToolTip(
            "Sign out: stop polling, drop your keys from memory and lock the app\n(Ctrl+L)"
        )
        self.lock_button.clicked.connect(app.lock)

        toolbar.addWidget(self.my_card)
        toolbar.addWidget(add)
        toolbar.addWidget(settings)
        toolbar.addSpacing(12)
        toolbar.addWidget(self.identity_label)
        toolbar.addWidget(self.copy_id)
        toolbar.addWidget(self.devices_button)
        toolbar.addStretch()
        toolbar.addWidget(self.lock_button)
        toolbar.addWidget(self.status)
        layout.addLayout(toolbar)

        splitter = QSplitter()
        self.contacts = QListWidget()
        self.contacts.currentRowChanged.connect(self._contact_changed)
        splitter.addWidget(self.contacts)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        self.header = QLabel("Select a contact")
        self.header.setObjectName("title")
        self.header_id = QLabel("")
        self.header_id.setObjectName("subtitle")
        self.header_id.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.header_id.setTextInteractionFlags(Qt.TextSelectableByMouse)
        header_box = QWidget()
        header_layout = QVBoxLayout(header_box)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(0)
        header_layout.addWidget(self.header)
        header_layout.addWidget(self.header_id)
        right_layout.addWidget(header_box)
        self.chat = QTextBrowser()
        right_layout.addWidget(self.chat, stretch=1)
        self.attachments = QListWidget()
        self.attachments.setMaximumHeight(90)
        right_layout.addWidget(self.attachments)
        row = QHBoxLayout()
        self.input = QLineEdit()
        self.input.setPlaceholderText("Type a message…")
        self.input.returnPressed.connect(app.send_text)
        attach = QPushButton("Attach file")
        attach.setObjectName("secondary")
        attach.clicked.connect(app.send_file)
        download = QPushButton("Download")
        download.setObjectName("secondary")
        download.clicked.connect(app.download_selected)
        row.addWidget(self.input)
        row.addWidget(attach)
        row.addWidget(download)
        right_layout.addLayout(row)
        splitter.addWidget(right)
        splitter.setStretchFactor(1, 3)
        layout.addWidget(splitter, stretch=1)

    def _contact_changed(self, row: int) -> None:
        self.app.select_contact(row)

    def set_status(self, text: str) -> None:
        self.status.setText(text)

    def reset(self) -> None:
        """Forget everything on screen, for locking or switching identity."""
        self.contacts.blockSignals(True)
        try:
            self.contacts.clear()
        finally:
            self.contacts.blockSignals(False)
        self.identity_label.setText("")
        self.header.setText("Select a contact")
        self.header_id.setText("")
        self.chat.setHtml("")
        self.attachments.clear()
        self.input.clear()
        self.status.setText("locked")


# -- controller -----------------------------------------------------------


class App(QWidget):
    attachment_ready = pyqtSignal(str, object)
    history_done = pyqtSignal(str, object)

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("noknowledge")
        self.resize(1040, 720)
        self.settings = GuiSettings.load()
        self.directory = data_dir()
        self.identity: Identity | None = None
        self.client = None
        self.worker: Worker | None = None
        self.current_contact: str | None = None
        self._pending_identity: Identity | None = None
        self._pending_passphrase = ""
        self._refreshing = False
        self._identity_encrypted = False

        self.stack = QStackedWidget()
        outer = QVBoxLayout(self)
        outer.addWidget(self.stack)

        self.welcome = WelcomeScreen()
        self.create_screen = CreateIdentityScreen()
        self.seedphrase = SeedphraseScreen()
        self.recover_screen = RecoverScreen()
        self.unlock = UnlockScreen()
        self.main_screen = MainScreen(self)
        for screen in (
            self.welcome,
            self.create_screen,
            self.seedphrase,
            self.recover_screen,
            self.unlock,
            self.main_screen,
        ):
            self.stack.addWidget(screen)

        self.welcome.create_requested.connect(
            lambda: self.stack.setCurrentWidget(self.create_screen)
        )
        self.welcome.recover_requested.connect(
            lambda: self.stack.setCurrentWidget(self.recover_screen)
        )
        self.create_screen.created.connect(self._on_create)
        self.create_screen.cancelled.connect(
            lambda: self.stack.setCurrentWidget(self.welcome)
        )
        self.seedphrase.confirmed.connect(self._on_seed_confirmed)
        self.recover_screen.recovered.connect(self._on_recover)
        self.recover_screen.cancelled.connect(
            lambda: self.stack.setCurrentWidget(self.welcome)
        )
        self.unlock.unlocked.connect(self._on_unlock)
        self.unlock.switch_requested.connect(self.switch_identity)
        self.attachment_ready.connect(self._save_attachment)
        self.history_done.connect(self._history_finished)
        self.lock_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        self.lock_shortcut.activated.connect(self.lock)

        self._bootstrap()

    # -- startup ----------------------------------------------------------

    def _bootstrap(self) -> None:
        path = identity_path(self.directory)
        if not os.path.exists(path):
            self.stack.setCurrentWidget(self.welcome)
            return
        try:
            identity = Identity.load(path)
        except IdentityError as exc:
            if "passphrase" in str(exc).lower():
                self.unlock.prepare(identity_is_encrypted(path))
                self.stack.setCurrentWidget(self.unlock)
                return
            QMessageBox.critical(self, "Identity", str(exc))
            self.stack.setCurrentWidget(self.welcome)
            return
        self._start_client(identity)

    # -- onboarding -------------------------------------------------------

    def _on_create(self, name: str, passphrase: str) -> None:
        if not name:
            name = "me"
        identity, mnemonic = Identity.generate(label=name, passphrase=passphrase or None)
        self._pending_identity = identity
        self._pending_passphrase = passphrase
        self.seedphrase.set_mnemonic(mnemonic)
        self.stack.setCurrentWidget(self.seedphrase)

    def _on_seed_confirmed(self) -> None:
        if self._pending_identity is None:
            return
        self._pending_identity.save(
            identity_path(self.directory), self._pending_passphrase or None
        )
        self._start_client(self._pending_identity)

    def _on_recover(self, mnemonic: str, name: str, passphrase: str) -> None:
        try:
            identity = Identity.from_mnemonic(
                mnemonic, passphrase or None, label=name or "recovered"
            )
        except IdentityError as exc:
            QMessageBox.warning(self, "Recover", str(exc))
            return
        identity.save(identity_path(self.directory), passphrase or None)
        self._start_client(identity)

    def _on_unlock(self, passphrase: str) -> None:
        try:
            identity = Identity.load(identity_path(self.directory), passphrase)
        except IdentityError as exc:
            QMessageBox.warning(self, "Unlock", str(exc))
            return
        self._start_client(identity)

    # -- client lifecycle -------------------------------------------------

    def _start_client(self, identity: Identity) -> None:
        self.identity = identity
        self._identity_encrypted = identity_is_encrypted(
            identity_path(self.directory)
        )
        self.main_screen.identity_label.setText(identity.identity_id)
        self.settings.last_name = identity.label or ""
        self.settings.save(self.directory)
        try:
            self.client = build_client(identity, self.settings, self.directory)
        except Exception as exc:
            QMessageBox.critical(self, "Startup", str(exc))
            self.stack.setCurrentWidget(self.welcome)
            return
        self._start_worker()
        self.stack.setCurrentWidget(self.main_screen)
        self.refresh()

    def _start_worker(self) -> None:
        if self.worker is not None:
            self.worker.stop()
            self.worker.wait(3000)
        self.worker = Worker(
            self.client,
            self.settings.poll_seconds,
            auto_discover=self.settings.auto_discover,
            discovery_interval=self.settings.discovery_interval,
        )
        self.worker.messages_received.connect(self._on_messages)
        self.worker.status_changed.connect(self.main_screen.set_status)
        self.worker.error_occurred.connect(self._on_error)
        self.worker.task_finished.connect(lambda *_: self.refresh())
        self.worker.relays_changed.connect(self._on_relays_changed)
        self.worker.submit("provision", self.client.provision)
        self.worker.start()

    def _restart_worker(self) -> None:
        if self.client is None:
            return
        try:
            self.client = build_client(self.identity, self.settings, self.directory)
        except Exception as exc:
            QMessageBox.critical(self, "Settings", str(exc))
            return
        self._start_worker()

    # -- lock and switch --------------------------------------------------

    def _teardown_client(self) -> None:
        """Stop polling and drop the keys and history from memory."""
        if self.worker is not None:
            self.worker.stop()
            self.worker.wait(3000)
            self.worker = None
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None
        self.identity = None
        self.current_contact = None
        self.main_screen.reset()

    def lock(self) -> None:
        """Sign out: back to the unlock screen, with nothing decrypted in RAM."""
        if self.client is None:
            return
        self._teardown_client()
        self.unlock.prepare(self._identity_encrypted)
        self.stack.setCurrentWidget(self.unlock)

    def switch_identity(self) -> None:
        """Sign out and offer to create or recover another identity.

        The desktop keeps one identity per data directory, so this replaces the
        stored one; the old account comes back from its seed phrase, and its
        history is still in local.db under that identity id.
        """
        answer = QMessageBox.question(
            self,
            "Use a different identity",
            "Your current account will be signed out and its identity file "
            "replaced if you create or recover another one.\n\n"
            "You can always come back with the old seed phrase, and its history "
            "stays on this machine.\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        self._teardown_client()
        self._pending_identity = None
        self._pending_passphrase = ""
        self.stack.setCurrentWidget(self.welcome)

    # -- actions ----------------------------------------------------------

    def show_my_card(self) -> None:
        if self.client is None:
            return
        try:
            card = self.client.card_string()
        except Exception as exc:
            QMessageBox.warning(self, "Card", str(exc))
            return
        CardDialog(card, self).exec_()

    def show_devices(self) -> None:
        """List the devices that share this account."""
        if self.client is None:
            return
        try:
            devices = self.client.devices()
        except Exception as exc:
            QMessageBox.warning(self, "Devices", str(exc))
            return
        DevicesDialog(
            devices,
            self,
            self.client.device_id(),
            app=self,
            cache_bytes=self.client.store.local_blob_bytes(),
            cache_chunks=self._cached_chunk_count(),
        ).exec_()

    def _cached_chunk_count(self) -> int:
        return self.client.store.local_blob_count()

    # -- history files ----------------------------------------------------

    def export_history(self) -> None:
        """Write an encrypted copy of this device's history to a file."""
        if self.client is None or self.worker is None:
            return
        since = ask_range(self, "Export history")
        if since is False:
            return
        passphrase, ok = QInputDialog.getText(
            self,
            "Export history",
            "Passphrase for the file (you will need it to import):\n"
            "Lose it and the file cannot be opened — there is no recovery.",
            QLineEdit.Password,
        )
        if not ok or not passphrase:
            return
        stamp = time.strftime("%Y%m%d")
        path, _ = QFileDialog.getSaveFileName(
            self, "Save history", f"noknowledge-history-{stamp}.nkx", "noknowledge history (*.nkx)"
        )
        if not path:
            return
        self.main_screen.set_status("exporting history…")
        self.worker.submit(
            "export_history",
            self._export_history_to,
            path,
            passphrase,
            since,
            callback=lambda result: self.history_done.emit("export", result),
        )

    def _export_history_to(self, path: str, passphrase: str, since_ms) -> dict:
        data = history_mod.export_history(self.client, passphrase, since_ms=since_ms)
        with open(path, "wb") as handle:
            handle.write(data)
        header = history_mod.read_export_header(data)
        return {"path": path, "bytes": len(data), "counts": header["counts"]}

    def import_history(self) -> None:
        """Merge an exported history file into this device."""
        if self.client is None or self.worker is None:
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Open history", "", "noknowledge history (*.nkx);;All files (*)"
        )
        if not path:
            return
        try:
            with open(path, "rb") as handle:
                preview = history_mod.read_export_header(handle.read())
        except Exception as exc:
            QMessageBox.warning(self, "Import history", str(exc))
            return
        counts = preview["counts"]
        answer = QMessageBox.question(
            self,
            "Import history",
            f"This file holds {counts['messages']} message(s), {counts['contacts']} "
            f"contact(s) and {counts['chunks']} attachment chunk(s)\n"
            f"({counts['skipped']} attachment(s) not included).\n\n"
            "Merge it into this device?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )
        if answer != QMessageBox.Yes:
            return
        passphrase, ok = QInputDialog.getText(
            self, "Import history", "Passphrase for this file:", QLineEdit.Password
        )
        if not ok or not passphrase:
            return
        self.main_screen.set_status("importing history…")
        self.worker.submit(
            "import_history",
            self._import_history_from,
            path,
            passphrase,
            callback=lambda result: self.history_done.emit("import", result),
        )

    def _import_history_from(self, path: str, passphrase: str) -> dict:
        with open(path, "rb") as handle:
            data = handle.read()
        return history_mod.import_history(self.client, data, passphrase)

    def _history_finished(self, kind: str, result) -> None:
        if result is None:
            self.main_screen.set_status("offline")
            return
        if kind == "export":
            self.main_screen.set_status(f"exported to {os.path.basename(result['path'])}")
            QMessageBox.information(
                self,
                "Export history",
                f"Wrote {result['bytes'] / 1024:.0f} KB to\n{result['path']}\n\n"
                f"{result['counts']['messages']} message(s), "
                f"{result['counts']['chunks']} attachment chunk(s).",
            )
        else:
            self.main_screen.set_status(
                f"imported {result['messages']} message(s)"
            )
            QMessageBox.information(
                self,
                "Import history",
                f"Merged {result['messages']} new message(s), "
                f"{result['contacts']} contact(s) and "
                f"{result['chunks']} attachment chunk(s).\n\n"
                "Anything already here was left untouched.",
            )
            self.refresh()

    def copy_identity_id(self) -> None:
        """Copy your identity ID, for verifying yourself with a contact."""
        if self.identity is None:
            return
        QApplication.clipboard().setText(self.identity.identity_id)
        self.main_screen.set_status("ID copied to clipboard")

    def add_contact(self) -> None:
        if self.client is None:
            return
        dialog = AddContactDialog(self)
        if dialog.exec_() != QDialog.Accepted:
            return
        card, nickname = dialog.values()
        try:
            self.client.add_contact(card, nickname or None)
        except Exception as exc:
            QMessageBox.warning(self, "Add contact", str(exc))
            return
        self.refresh()

    def open_settings(self) -> None:
        dialog = SettingsDialog(self.settings, self)
        if dialog.exec_() != QDialog.Accepted:
            return
        dialog.apply_to(self.settings)
        self.settings.save(self.directory)
        self._restart_worker()
        self.refresh()

    def select_contact(self, row: int) -> None:
        contacts = self.contacts_data()
        if row < 0 or row >= len(contacts):
            self.current_contact = None
            return
        self.current_contact = contacts[row]["id"]
        self.refresh()
        if self.worker is not None and self.client is not None:
            for message in self.client.messages(self.current_contact):
                if message["direction"] == "received" and message["state"] == "received":
                    self.worker.submit(
                        "mark_read", self.client.mark_read, self.current_contact, message["id"]
                    )

    def send_text(self) -> None:
        text = self.main_screen.input.text().strip()
        if not text or not self.current_contact or self.worker is None:
            return
        self.main_screen.input.clear()
        contact = self.current_contact
        self.worker.submit("send_text", self.client.send_text, contact, text)
        self.refresh()

    def send_file(self) -> None:
        if not self.current_contact or self.worker is None:
            return
        path, _ = QFileDialog.getOpenFileName(self, "Send file")
        if not path:
            return
        contact = self.current_contact
        self.worker.submit("send_file", self.client.send_file, contact, path)
        self.refresh()

    def download_selected(self) -> None:
        item = self.main_screen.attachments.currentItem()
        if item is None or self.worker is None:
            return
        message = item.data(Qt.UserRole)
        self.worker.submit(
            "download_attachment",
            self.client.download_attachment,
            message,
            callback=lambda data, name=item.text(): self.attachment_ready.emit(
                name, data
            ),
        )

    def _save_attachment(self, name: str, data) -> None:
        if not data:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save attachment", name)
        if not path:
            return
        with open(path, "wb") as handle:
            handle.write(data)
        QMessageBox.information(self, "Saved", f"Saved to {path}")

    # -- rendering --------------------------------------------------------

    def contacts_data(self) -> list[dict]:
        if self.client is None:
            return []
        return self.client.list_contacts()

    def refresh(self) -> None:
        if self.client is None or self._refreshing:
            return
        self._refreshing = True
        try:
            contacts = self.contacts_data()
            selected = self.current_contact
            # Nicknames are self-asserted, so two contacts can share one. Rows
            # whose display name collides get a short id suffix.
            bases = [contact["nickname"] or contact["id"][:8] for contact in contacts]
            collisions = Counter(bases)
            # Signals stay blocked for the whole rebuild, *including*
            # setCurrentRow. Unblocking first let the row change re-enter
            # _contact_changed -> select_contact -> refresh, recursing until
            # Python's recursion limit blew up inside json.loads.
            self.main_screen.contacts.blockSignals(True)
            try:
                self.main_screen.contacts.clear()
                for contact, base in zip(contacts, bases):
                    unread = sum(
                        1
                        for m in self.client.messages(contact["id"])
                        if m["direction"] == "received" and m["state"] == "received"
                    )
                    label = base
                    if collisions[base] > 1:
                        label = f"{base} · {contact['id'][:7]}"
                    if unread:
                        label = f"{label} ({unread})"
                    item = QListWidgetItem(label)
                    item.setData(Qt.UserRole, contact["id"])
                    self.main_screen.contacts.addItem(item)
                if selected:
                    for index, contact in enumerate(contacts):
                        if contact["id"] == selected:
                            self.main_screen.contacts.setCurrentRow(index)
                            break
            finally:
                self.main_screen.contacts.blockSignals(False)
            self._render_chat()
        finally:
            self._refreshing = False

    def _render_chat(self) -> None:
        if self.client is None or not self.current_contact:
            self.main_screen.header.setText("Select a contact")
            self.main_screen.header_id.setText("")
            self.main_screen.chat.setHtml("")
            self.main_screen.attachments.clear()
            return
        contact = self.client.store.get_contact(self.client.identity_id, self.current_contact)
        self.main_screen.header.setText(
            (contact or {}).get("nickname") or self.current_contact[:12]
        )
        # Always show the ID, so two same-named contacts are still tellable apart
        # and a contact's ID can be compared out of band.
        self.main_screen.header_id.setText(self.current_contact)
        rows = []
        attachments = []
        for message in self.client.messages(self.current_contact):
            body = message.get("body") or {}
            if message["type"] == "text":
                text = html.escape(body.get("text", ""))
            else:
                caption = html.escape(body.get("caption", "") or "")
                name = html.escape(
                    (body.get("attachment") or {}).get("name", "attachment")
                )
                text = f"[file: {name}] {caption}"
                attachments.append((message, name))
            mine = message["direction"] == "sent"
            align = "right" if mine else "left"
            colour = "#3b82f6" if mine else "#2b2d31"
            state = message.get("state") or ""
            meta = "sent" if mine else "received"
            if mine and state:
                meta = state
            rows.append(
                f'<div style="text-align:{align};margin:6px 0;">'
                f'<span style="background:{colour};padding:6px 10px;border-radius:8px;'
                f'display:inline-block;max-width:70%;">{text}</span><br>'
                f'<span style="color:#8a8a8a;font-size:10px;">{meta}</span></div>'
            )
        self.main_screen.chat.setHtml("".join(rows) or "<i>No messages yet.</i>")

        self.main_screen.attachments.clear()
        for message, name in attachments:
            item = QListWidgetItem(name)
            item.setData(Qt.UserRole, message)
            self.main_screen.attachments.addItem(item)

    # -- worker callbacks -------------------------------------------------

    def _on_messages(self, _messages: list) -> None:
        self.refresh()

    def _on_relays_changed(self, relays: list) -> None:
        """Discovery adopted new relays: persist them for the next launch."""
        relays = [str(relay) for relay in relays]
        if not relays or relays == self.settings.relays:
            return
        self.settings.relays = relays
        self.settings.save(self.directory)
        self.main_screen.set_status(f"online · {len(relays)} relays")

    def _on_error(self, message: str) -> None:
        self.main_screen.set_status(f"offline: {message[:60]}")

    def closeEvent(self, event) -> None:  # noqa: N802 (Qt override)
        self._teardown_client()
        super().closeEvent(event)


def run(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    application = QApplication(argv)
    application.setApplicationName("noknowledge")
    application.setStyleSheet(STYLESHEET)
    window = App()
    window.show()
    return application.exec_()