"""Local storage: key resolution precedence and encryption at rest."""

import os
import sys

import pytest

from noknowledge.core.store import LocalStore, resolve_store_key


def test_key_file_takes_precedence_over_keyring(tmp_path, monkeypatch):
    monkeypatch.setenv("NK_DISABLE_KEYRING", "1")
    first = resolve_store_key(str(tmp_path), "identity-a")
    assert (tmp_path / "local.key").exists()

    # Re-enabling the keyring must not switch keys: that would silently orphan
    # the existing local database.
    monkeypatch.delenv("NK_DISABLE_KEYRING", raising=False)
    assert resolve_store_key(str(tmp_path), "identity-a") == first


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="os.chmod does not produce POSIX 0600 permissions on Windows",
)
def test_key_file_is_owner_only(tmp_path, monkeypatch):
    monkeypatch.setenv("NK_DISABLE_KEYRING", "1")
    resolve_store_key(str(tmp_path), "identity-a")
    mode = os.stat(tmp_path / "local.key").st_mode & 0o777
    assert mode == 0o600


def test_local_store_encrypts_at_rest(tmp_path):
    store = LocalStore(str(tmp_path / "local.db"), key=os.urandom(32))
    store.initialize()
    store.add_message(
        {
            "id": "m1",
            "identity_id": "id",
            "contact_id": "c1",
            "direction": "received",
            "type": "text",
            "body": {"text": "TOPSECRET-MARKER"},
            "remote_id": None,
            "ts": 1,
            "state": "received",
            "meta": None,
        }
    )
    store.set_state("id", "inbox", {"token": "TOPSECRET-MARKER"})

    raw = b""
    for suffix in ("", "-wal"):
        candidate = tmp_path / f"local.db{suffix}"
        if candidate.exists():
            raw += candidate.read_bytes()
    assert b"TOPSECRET-MARKER" not in raw

    assert store.get_message("m1")["body"]["text"] == "TOPSECRET-MARKER"
    assert store.get_state("id", "inbox")["token"] == "TOPSECRET-MARKER"