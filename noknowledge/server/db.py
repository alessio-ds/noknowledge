"""SQLite persistence for the relay.

The schema deliberately has **no users table and no public keys**: the relay
knows mailbox ids, hashed capability tokens, opaque ciphertext and sizes. There
is nothing here that links a message to an identity.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator

from noknowledge.server.errors import (
    BlobNotFound,
    BundleNotFound,
    MailboxNotFound,
    QuotaExceeded,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS mailboxes (
    id                TEXT PRIMARY KEY,
    read_token_hash   BLOB NOT NULL,
    write_token_hash  BLOB NOT NULL,
    created_at        INTEGER NOT NULL,
    last_seen         INTEGER NOT NULL,
    max_messages      INTEGER NOT NULL,
    max_bytes         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox_id  TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    ciphertext  BLOB NOT NULL,
    created_at  INTEGER NOT NULL,
    size        INTEGER NOT NULL,
    UNIQUE (mailbox_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_messages_mailbox ON messages (mailbox_id, seq);

CREATE TABLE IF NOT EXISTS prekey_bundles (
    bundle_id   TEXT PRIMARY KEY,
    payload     TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS prekey_one_time (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    bundle_id  TEXT NOT NULL,
    opk_id     INTEGER NOT NULL,
    opk        TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    UNIQUE (bundle_id, opk_id)
);
CREATE INDEX IF NOT EXISTS idx_opk_bundle ON prekey_one_time (bundle_id, used);

CREATE TABLE IF NOT EXISTS blobs (
    chunk_id    TEXT PRIMARY KEY,
    mailbox_id  TEXT NOT NULL,
    ciphertext  BLOB NOT NULL,
    size        INTEGER NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_blobs_mailbox ON blobs (mailbox_id);
"""


class Database:
    def __init__(self, path: str) -> None:
        self.path = path

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
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
            connection.executescript(SCHEMA)

    # -- mailboxes --------------------------------------------------------

    def create_mailbox(
        self,
        mailbox_id: str,
        read_token_hash: bytes,
        write_token_hash: bytes,
        now: int,
        max_messages: int,
        max_bytes: int,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO mailboxes
                    (id, read_token_hash, write_token_hash, created_at, last_seen,
                     max_messages, max_bytes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mailbox_id,
                    read_token_hash,
                    write_token_hash,
                    now,
                    now,
                    max_messages,
                    max_bytes,
                ),
            )

    def get_mailbox(self, mailbox_id: str) -> sqlite3.Row | None:
        with self._connect() as connection:
            return connection.execute(
                "SELECT * FROM mailboxes WHERE id = ?", (mailbox_id,)
            ).fetchone()

    def require_mailbox(self, mailbox_id: str) -> sqlite3.Row:
        row = self.get_mailbox(mailbox_id)
        if row is None:
            raise MailboxNotFound(mailbox_id)
        return row

    def delete_mailbox(self, mailbox_id: str) -> tuple[int, int]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            messages = connection.execute(
                "DELETE FROM messages WHERE mailbox_id = ?", (mailbox_id,)
            ).rowcount
            blobs = connection.execute(
                "DELETE FROM blobs WHERE mailbox_id = ?", (mailbox_id,)
            ).rowcount
            connection.execute("DELETE FROM mailboxes WHERE id = ?", (mailbox_id,))
            return messages or 0, blobs or 0

    def touch_mailbox(self, mailbox_id: str, now: int) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE mailboxes SET last_seen = ? WHERE id = ?", (now, mailbox_id)
            )

    # -- messages ---------------------------------------------------------

    def usage(self, connection: sqlite3.Connection, mailbox_id: str) -> tuple[int, int]:
        count = connection.execute(
            "SELECT COUNT(*) FROM messages WHERE mailbox_id = ?", (mailbox_id,)
        ).fetchone()[0]
        message_bytes = connection.execute(
            "SELECT COALESCE(SUM(size), 0) FROM messages WHERE mailbox_id = ?",
            (mailbox_id,),
        ).fetchone()[0]
        blob_bytes = connection.execute(
            "SELECT COALESCE(SUM(size), 0) FROM blobs WHERE mailbox_id = ?",
            (mailbox_id,),
        ).fetchone()[0]
        return int(count), int(message_bytes + blob_bytes)

    def put_message(self, mailbox_id: str, ciphertext: bytes, now: int) -> int:
        size = len(ciphertext)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            mailbox = connection.execute(
                "SELECT max_messages, max_bytes FROM mailboxes WHERE id = ?",
                (mailbox_id,),
            ).fetchone()
            if mailbox is None:
                raise MailboxNotFound(mailbox_id)
            count, used = self.usage(connection, mailbox_id)
            if count >= mailbox["max_messages"] or used + size > mailbox["max_bytes"]:
                raise QuotaExceeded(mailbox_id)
            seq = (
                connection.execute(
                    "SELECT COALESCE(MAX(seq), 0) FROM messages WHERE mailbox_id = ?",
                    (mailbox_id,),
                ).fetchone()[0]
                + 1
            )
            connection.execute(
                """
                INSERT INTO messages (mailbox_id, seq, ciphertext, created_at, size)
                VALUES (?, ?, ?, ?, ?)
                """,
                (mailbox_id, seq, sqlite3.Binary(ciphertext), now, size),
            )
            connection.execute(
                "UPDATE mailboxes SET last_seen = ? WHERE id = ?", (now, mailbox_id)
            )
            return int(seq)

    def get_messages(
        self, mailbox_id: str, after_seq: int = 0, limit: int = 200
    ) -> list[sqlite3.Row]:
        with self._connect() as connection:
            return connection.execute(
                """
                SELECT seq, ciphertext, created_at, size FROM messages
                WHERE mailbox_id = ? AND seq > ?
                ORDER BY seq ASC LIMIT ?
                """,
                (mailbox_id, after_seq, limit),
            ).fetchall()

    def ack_messages(self, mailbox_id: str, upto_seq: int) -> int:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                "DELETE FROM messages WHERE mailbox_id = ? AND seq <= ?",
                (mailbox_id, upto_seq),
            )
            return int(result.rowcount or 0)

    # -- prekeys ----------------------------------------------------------

    def publish_bundle(
        self,
        bundle_id: str,
        payload: dict,
        opks: list[dict],
        now: int,
    ) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO prekey_bundles (bundle_id, payload, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT (bundle_id) DO UPDATE SET payload = excluded.payload
                """,
                (bundle_id, json.dumps(payload), now),
            )
            for opk in opks:
                # Republishing an existing bundle must not duplicate one-time
                # prekeys: handing the same OPK to two senders would reuse it.
                connection.execute(
                    """
                    INSERT OR IGNORE INTO prekey_one_time
                        (bundle_id, opk_id, opk, used)
                    VALUES (?, ?, ?, 0)
                    """,
                    (bundle_id, int(opk["opk_id"]), opk["opk"]),
                )

    def fetch_bundle(self, bundle_id: str) -> dict:
        """Return a bundle plus at most one unused one-time prekey (consumed)."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT payload FROM prekey_bundles WHERE bundle_id = ?", (bundle_id,)
            ).fetchone()
            if row is None:
                raise BundleNotFound(bundle_id)
            opk = connection.execute(
                """
                SELECT id, opk_id, opk FROM prekey_one_time
                WHERE bundle_id = ? AND used = 0 ORDER BY id ASC LIMIT 1
                """,
                (bundle_id,),
            ).fetchone()
            if opk is not None:
                connection.execute(
                    "UPDATE prekey_one_time SET used = 1 WHERE id = ?", (opk["id"],)
                )
            payload = json.loads(row["payload"])
            payload["opks"] = (
                [{"opk_id": opk["opk_id"], "opk": opk["opk"]}] if opk else []
            )
            return payload

    # -- blobs ------------------------------------------------------------

    def put_blob(
        self, chunk_id: str, mailbox_id: str, ciphertext: bytes, now: int
    ) -> None:
        size = len(ciphertext)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            mailbox = connection.execute(
                "SELECT max_bytes FROM mailboxes WHERE id = ?", (mailbox_id,)
            ).fetchone()
            if mailbox is None:
                raise MailboxNotFound(mailbox_id)
            _, used = self.usage(connection, mailbox_id)
            if used + size > mailbox["max_bytes"]:
                raise QuotaExceeded(mailbox_id)
            connection.execute(
                """
                INSERT INTO blobs (chunk_id, mailbox_id, ciphertext, size, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (chunk_id, mailbox_id, sqlite3.Binary(ciphertext), size, now),
            )

    def get_blob(self, chunk_id: str) -> sqlite3.Row:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM blobs WHERE chunk_id = ?", (chunk_id,)
            ).fetchone()
            if row is None:
                raise BlobNotFound(chunk_id)
            return row

    def delete_blob(self, chunk_id: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM blobs WHERE chunk_id = ?", (chunk_id,))

    # -- housekeeping -----------------------------------------------------

    def housekeeping(self, now: int, mailbox_ttl: int, blob_ttl: int) -> dict:
        """Remove abandoned mailboxes and stale blobs. Never inspects content."""
        stray_blob_cutoff = now - blob_ttl
        idle_cutoff = now - mailbox_ttl
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            stale = [
                row["id"]
                for row in connection.execute(
                    "SELECT id FROM mailboxes WHERE last_seen < ?", (idle_cutoff,)
                ).fetchall()
            ]
            removed_messages = 0
            removed_blobs = 0
            for mailbox_id in stale:
                removed_messages += connection.execute(
                    "DELETE FROM messages WHERE mailbox_id = ?", (mailbox_id,)
                ).rowcount or 0
                removed_blobs += connection.execute(
                    "DELETE FROM blobs WHERE mailbox_id = ?", (mailbox_id,)
                ).rowcount or 0
                connection.execute("DELETE FROM mailboxes WHERE id = ?", (mailbox_id,))
            stray = connection.execute(
                "DELETE FROM blobs WHERE created_at < ? AND mailbox_id NOT IN "
                "(SELECT id FROM mailboxes)",
                (stray_blob_cutoff,),
            ).rowcount
            removed_blobs += stray or 0
            return {
                "mailboxes": len(stale),
                "messages": removed_messages,
                "blobs": removed_blobs,
            }

    def stats(self) -> dict[str, Any]:
        with self._connect() as connection:
            mailboxes = connection.execute(
                "SELECT COUNT(*) FROM mailboxes"
            ).fetchone()[0]
            messages = connection.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
            blobs = connection.execute("SELECT COUNT(*) FROM blobs").fetchone()[0]
            byte_total = connection.execute(
                "SELECT COALESCE(SUM(size), 0) FROM messages"
            ).fetchone()[0]
            byte_total += connection.execute(
                "SELECT COALESCE(SUM(size), 0) FROM blobs"
            ).fetchone()[0]
            bundles = connection.execute(
                "SELECT COUNT(*) FROM prekey_bundles"
            ).fetchone()[0]
            return {
                "mailboxes": int(mailboxes),
                "messages": int(messages),
                "blobs": int(blobs),
                "bytes": int(byte_total),
                "prekey_bundles": int(bundles),
            }