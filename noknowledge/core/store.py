"""Encrypted local storage.

Everything sensitive — message bodies, ratchet state, prekey secrets, outbox
payloads — is stored as AEAD ciphertext under a local key. The key comes from
the OS keyring where available, otherwise from a passphrase or a 0600 key file.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Iterator

from noknowledge.crypto.aead import decrypt, encrypt
from noknowledge.crypto.encoding import b64d, b64e

LOCAL_KEY_SIZE = 32
KEYRING_SERVICE = "noknowledge"

#: Set ``NK_DISABLE_KEYRING=1`` to always use the 0600 key file. Useful for
#: headless servers, containers and CI where no OS keyring exists.
DISABLE_KEYRING_ENV = "NK_DISABLE_KEYRING"

SCHEMA = """
CREATE TABLE IF NOT EXISTS identities (
    id          TEXT PRIMARY KEY,
    label       TEXT,
    vault_path  TEXT,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
    identity_id TEXT NOT NULL,
    id          TEXT NOT NULL,
    nickname    TEXT,
    isign       BLOB NOT NULL,
    idh         BLOB NOT NULL,
    bundle_id   TEXT,
    inbox_json  TEXT NOT NULL,
    relays      TEXT NOT NULL,
    session_enc BLOB,
    verified    INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (identity_id, id)
);

CREATE TABLE IF NOT EXISTS messages (
    id          TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL,
    contact_id  TEXT NOT NULL,
    direction   TEXT NOT NULL,
    type        TEXT NOT NULL,
    body_enc    BLOB,
    remote_id   TEXT,
    ts          INTEGER NOT NULL,
    state       TEXT,
    meta_enc    BLOB
);
CREATE INDEX IF NOT EXISTS idx_messages_contact ON messages (identity_id, contact_id, ts);

CREATE TABLE IF NOT EXISTS prekeys (
    identity_id TEXT PRIMARY KEY,
    data_enc    BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS outbox (
    id          TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL,
    contact_id  TEXT NOT NULL,
    mailbox_id  TEXT NOT NULL,
    relay       TEXT,
    payload_enc BLOB NOT NULL,
    seq         INTEGER,
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_outbox_contact ON outbox (identity_id, contact_id);

CREATE TABLE IF NOT EXISTS cursors (
    identity_id TEXT NOT NULL,
    mailbox_id  TEXT NOT NULL,
    relay       TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    PRIMARY KEY (identity_id, mailbox_id, relay)
);

CREATE TABLE IF NOT EXISTS state (
    identity_id TEXT NOT NULL,
    key         TEXT NOT NULL,
    value_enc   BLOB NOT NULL,
    PRIMARY KEY (identity_id, key)
);
"""


def derive_key_from_passphrase(passphrase: str, salt: bytes, iterations: int = 600_000) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=LOCAL_KEY_SIZE, salt=salt, iterations=iterations
    ).derive(passphrase.encode("utf-8"))


def _load_key_file(path: str, passphrase: str | None) -> bytes:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if data.get("wrapped"):
        if not passphrase:
            raise ValueError("local store is passphrase-protected")
        wrapper = derive_key_from_passphrase(
            passphrase, b64d(data["salt"]), int(data["iterations"])
        )
        nonce, _, ciphertext = _split(b64d(data["wrapped"]))
        return decrypt(wrapper, nonce, ciphertext)
    return b64d(data["key"])


def _write_key_file(path: str, key: bytes, passphrase: str | None) -> None:
    if passphrase:
        salt = os.urandom(16)
        wrapper = derive_key_from_passphrase(passphrase, salt)
        nonce, ciphertext = encrypt(wrapper, key)
        payload = {
            "salt": b64e(salt),
            "iterations": 600_000,
            "wrapped": b64e(nonce + ciphertext),
        }
    else:
        payload = {"key": b64e(key)}
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def resolve_store_key(
    directory: str, identity_id: str, passphrase: str | None = None
) -> bytes:
    """Obtain the local storage key.

    An existing ``local.key`` file always wins. It may have been created with the
    keyring disabled (headless, containers, CI, or a scripted demo), and
    switching modes must never silently orphan the existing local database.
    Otherwise the OS keyring is preferred, unless ``NK_DISABLE_KEYRING=1`` is
    set, in which case a fresh 0600 key file is created.
    """
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "local.key")
    if os.path.exists(path):
        return _load_key_file(path, passphrase)

    if not os.environ.get(DISABLE_KEYRING_ENV):
        try:
            import keyring  # type: ignore

            stored = keyring.get_password(KEYRING_SERVICE, identity_id)
            if stored:
                return b64d(stored)
            key = os.urandom(LOCAL_KEY_SIZE)
            keyring.set_password(KEYRING_SERVICE, identity_id, b64e(key))
            return key
        except Exception:
            pass

    key = os.urandom(LOCAL_KEY_SIZE)
    _write_key_file(path, key, passphrase)
    return key


def _split(blob: bytes) -> tuple[bytes, bytes, bytes]:
    return blob[:12], b"", blob[12:]


class LocalStore:
    def __init__(self, path: str, key: bytes) -> None:
        if len(key) != LOCAL_KEY_SIZE:
            raise ValueError("local store key must be 32 bytes")
        self.path = path
        self.key = key

    # -- plumbing ---------------------------------------------------------

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(SCHEMA)

    def _seal(self, value: Any) -> bytes:
        nonce, ciphertext = encrypt(self.key, json.dumps(value).encode("utf-8"))
        return nonce + ciphertext

    def _open(self, blob: bytes | None) -> Any:
        if blob is None:
            return None
        nonce, _, ciphertext = _split(bytes(blob))
        return json.loads(decrypt(self.key, nonce, ciphertext).decode("utf-8"))

    # -- identities -------------------------------------------------------

    def register_identity(self, identity_id: str, label: str | None, vault_path: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO identities (id, label, vault_path, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (id) DO UPDATE SET label = excluded.label,
                                               vault_path = excluded.vault_path
                """,
                (identity_id, label, vault_path, int(time.time())),
            )

    def list_identities(self) -> list[dict]:
        with self._connect() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM identities ORDER BY created_at"
                ).fetchall()
            ]

    # -- contacts ---------------------------------------------------------

    def upsert_contact(self, identity_id: str, contact: dict) -> None:
        session = contact.get("session")
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO contacts
                    (identity_id, id, nickname, isign, idh, bundle_id, inbox_json,
                     relays, session_enc, verified, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (identity_id, id) DO UPDATE SET
                    nickname = excluded.nickname,
                    isign = excluded.isign,
                    idh = excluded.idh,
                    bundle_id = excluded.bundle_id,
                    inbox_json = excluded.inbox_json,
                    relays = excluded.relays,
                    session_enc = excluded.session_enc,
                    verified = excluded.verified
                """,
                (
                    identity_id,
                    contact["id"],
                    contact.get("nickname"),
                    contact["isign"],
                    contact["idh"],
                    contact.get("bundle_id"),
                    json.dumps(contact["inbox"]),
                    json.dumps(contact.get("relays") or []),
                    self._seal(session) if session is not None else None,
                    1 if contact.get("verified") else 0,
                    int(contact.get("created_at") or time.time()),
                ),
            )

    def _contact_from_row(self, row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "identity_id": row["identity_id"],
            "nickname": row["nickname"],
            "isign": bytes(row["isign"]),
            "idh": bytes(row["idh"]),
            "bundle_id": row["bundle_id"],
            "inbox": json.loads(row["inbox_json"]),
            "relays": json.loads(row["relays"]),
            "session": self._open(row["session_enc"]),
            "verified": bool(row["verified"]),
            "created_at": row["created_at"],
        }

    def get_contact(self, identity_id: str, contact_id: str) -> dict | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM contacts WHERE identity_id = ? AND id = ?",
                (identity_id, contact_id),
            ).fetchone()
            return self._contact_from_row(row) if row else None

    def list_contacts(self, identity_id: str) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM contacts WHERE identity_id = ? ORDER BY created_at",
                (identity_id,),
            ).fetchall()
            return [self._contact_from_row(row) for row in rows]

    def delete_contact(self, identity_id: str, contact_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM contacts WHERE identity_id = ? AND id = ?",
                (identity_id, contact_id),
            )

    def set_contact_session(self, identity_id: str, contact_id: str, session: dict | None) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE contacts SET session_enc = ? WHERE identity_id = ? AND id = ?",
                (
                    self._seal(session) if session is not None else None,
                    identity_id,
                    contact_id,
                ),
            )

    # -- messages ---------------------------------------------------------

    def add_message(self, message: dict) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO messages
                    (id, identity_id, contact_id, direction, type, body_enc,
                     remote_id, ts, state, meta_enc)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (id) DO UPDATE SET
                    body_enc = excluded.body_enc,
                    remote_id = excluded.remote_id,
                    state = excluded.state,
                    meta_enc = excluded.meta_enc
                """,
                (
                    message["id"],
                    message["identity_id"],
                    message["contact_id"],
                    message["direction"],
                    message["type"],
                    self._seal(message.get("body")) if message.get("body") is not None else None,
                    message.get("remote_id"),
                    int(message["ts"]),
                    message.get("state"),
                    self._seal(message.get("meta")) if message.get("meta") is not None else None,
                ),
            )

    def _message_from_row(self, row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "identity_id": row["identity_id"],
            "contact_id": row["contact_id"],
            "direction": row["direction"],
            "type": row["type"],
            "body": self._open(row["body_enc"]),
            "remote_id": row["remote_id"],
            "ts": row["ts"],
            "state": row["state"],
            "meta": self._open(row["meta_enc"]),
        }

    def get_message(self, message_id: str) -> dict | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM messages WHERE id = ?", (message_id,)
            ).fetchone()
            return self._message_from_row(row) if row else None

    def list_messages(self, identity_id: str, contact_id: str) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM messages
                WHERE identity_id = ? AND contact_id = ?
                ORDER BY ts ASC
                """,
                (identity_id, contact_id),
            ).fetchall()
            return [self._message_from_row(row) for row in rows]

    def find_by_remote_id(
        self, identity_id: str, remote_id: str, direction: str | None = None
    ) -> dict | None:
        """Look up a message by the peer-assigned envelope id."""
        query = "SELECT * FROM messages WHERE identity_id = ? AND remote_id = ?"
        params: list[Any] = [identity_id, remote_id]
        if direction:
            query += " AND direction = ?"
            params.append(direction)
        query += " LIMIT 1"
        with self._connect() as connection:
            row = connection.execute(query, params).fetchone()
            return self._message_from_row(row) if row else None

    def update_message(self, message_id: str, **fields) -> None:
        if not fields:
            return
        assignments = []
        values: list[Any] = []
        for name, value in fields.items():
            if name in ("body", "meta"):
                assignments.append(f"{name}_enc = ?")
                values.append(self._seal(value) if value is not None else None)
            else:
                assignments.append(f"{name} = ?")
                values.append(value)
        values.append(message_id)
        with self._connect() as connection:
            connection.execute(
                f"UPDATE messages SET {', '.join(assignments)} WHERE id = ?", values
            )

    # -- prekeys ----------------------------------------------------------

    def save_prekeys(self, identity_id: str, data: dict) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO prekeys (identity_id, data_enc) VALUES (?, ?)
                ON CONFLICT (identity_id) DO UPDATE SET data_enc = excluded.data_enc
                """,
                (identity_id, self._seal(data)),
            )

    def load_prekeys(self, identity_id: str) -> dict | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT data_enc FROM prekeys WHERE identity_id = ?", (identity_id,)
            ).fetchone()
            return self._open(row["data_enc"]) if row else None

    # -- outbox -----------------------------------------------------------

    def outbox_add(self, entry: dict) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO outbox
                    (id, identity_id, contact_id, mailbox_id, relay, payload_enc,
                     seq, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry["id"],
                    entry["identity_id"],
                    entry["contact_id"],
                    entry["mailbox_id"],
                    entry.get("relay"),
                    self._seal(entry.get("payload")),
                    entry.get("seq"),
                    int(entry.get("created_at") or time.time()),
                ),
            )

    def _outbox_from_row(self, row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "identity_id": row["identity_id"],
            "contact_id": row["contact_id"],
            "mailbox_id": row["mailbox_id"],
            "relay": row["relay"],
            "payload": self._open(row["payload_enc"]),
            "seq": row["seq"],
            "created_at": row["created_at"],
        }

    def outbox_list(self, identity_id: str, contact_id: str | None = None) -> list[dict]:
        with self._connect() as connection:
            if contact_id:
                rows = connection.execute(
                    "SELECT * FROM outbox WHERE identity_id = ? AND contact_id = ? ORDER BY created_at",
                    (identity_id, contact_id),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM outbox WHERE identity_id = ? ORDER BY created_at",
                    (identity_id,),
                ).fetchall()
            return [self._outbox_from_row(row) for row in rows]

    def outbox_remove(self, entry_id: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM outbox WHERE id = ?", (entry_id,))

    def outbox_mark_sent(self, entry_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE outbox SET seq = 1 WHERE id = ?", (entry_id,)
            )

    def outbox_count(self, identity_id: str) -> int:
        with self._connect() as connection:
            return int(
                connection.execute(
                    "SELECT COUNT(*) FROM outbox WHERE identity_id = ?", (identity_id,)
                ).fetchone()[0]
            )

    # -- cursors ----------------------------------------------------------

    def get_cursors(self, identity_id: str, mailbox_id: str) -> dict[str, int]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT relay, seq FROM cursors WHERE identity_id = ? AND mailbox_id = ?",
                (identity_id, mailbox_id),
            ).fetchall()
            return {row["relay"]: int(row["seq"]) for row in rows}

    def set_cursor(self, identity_id: str, mailbox_id: str, relay: str, seq: int) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO cursors (identity_id, mailbox_id, relay, seq)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (identity_id, mailbox_id, relay) DO UPDATE SET
                    seq = MAX(cursors.seq, excluded.seq)
                """,
                (identity_id, mailbox_id, relay, int(seq)),
            )

    # -- key/value state --------------------------------------------------

    def set_state(self, identity_id: str, key: str, value: Any) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO state (identity_id, key, value_enc) VALUES (?, ?, ?)
                ON CONFLICT (identity_id, key) DO UPDATE SET value_enc = excluded.value_enc
                """,
                (identity_id, key, self._seal(value)),
            )

    def get_state(self, identity_id: str, key: str, default: Any = None) -> Any:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value_enc FROM state WHERE identity_id = ? AND key = ?",
                (identity_id, key),
            ).fetchone()
            return self._open(row["value_enc"]) if row else default