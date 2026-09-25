"""PyQt5 desktop client.

A thin view over :class:`Client`: all network work runs on the :class:`Worker`
thread and reaches the UI through Qt signals, so the interface never blocks.
"""

from __future__ import annotations

import html
import os
import sys

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont
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
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from noknowledge.crypto.identity import Identity, IdentityError
from noknowledge.gui.session import build_client, identity_path
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
        self.text = QPlainTextEdit(card_text)
        self.text.setReadOnly(True)
        layout.addWidget(self.text)
        copy = QPushButton("Copy to clipboard")
        copy.clicked.connect(self._copy)
        layout.addWidget(copy)
        layout.addWidget(QDialogButtonBox(QDialogButtonBox.Close, rejected=self.reject))

    def _copy(self) -> None:
        QApplication.clipboard().setText(self.text.toPlainText())


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

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addStretch()
        title = QLabel("Unlock")
        title.setObjectName("title")
        layout.addWidget(title, alignment=Qt.AlignCenter)
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
        layout.addStretch()


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
        toolbar.addWidget(self.my_card)
        toolbar.addWidget(add)
        toolbar.addWidget(settings)
        toolbar.addStretch()
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
        right_layout.addWidget(self.header)
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


# -- controller -----------------------------------------------------------


class App(QWidget):
    attachment_ready = pyqtSignal(str, object)

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
        self.attachment_ready.connect(self._save_attachment)

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
            # Signals stay blocked for the whole rebuild, *including*
            # setCurrentRow. Unblocking first let the row change re-enter
            # _contact_changed -> select_contact -> refresh, recursing until
            # Python's recursion limit blew up inside json.loads.
            self.main_screen.contacts.blockSignals(True)
            try:
                self.main_screen.contacts.clear()
                for contact in contacts:
                    unread = sum(
                        1
                        for m in self.client.messages(contact["id"])
                        if m["direction"] == "received" and m["state"] == "received"
                    )
                    label = contact["nickname"] or contact["id"][:8]
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
            self.main_screen.chat.setHtml("")
            self.main_screen.attachments.clear()
            return
        contact = self.client.store.get_contact(self.client.identity_id, self.current_contact)
        self.main_screen.header.setText(
            (contact or {}).get("nickname") or self.current_contact[:12]
        )
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
        if self.worker is not None:
            self.worker.stop()
            self.worker.wait(3000)
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass
        super().closeEvent(event)


def run(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    application = QApplication(argv)
    application.setApplicationName("noknowledge")
    application.setStyleSheet(STYLESHEET)
    window = App()
    window.show()
    return application.exec_()