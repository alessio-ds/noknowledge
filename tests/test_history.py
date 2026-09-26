"""History bundles: the shape shared by export files and device back-fill."""

import os
import pathlib

import pytest

from noknowledge.core import history
from noknowledge.core.client import Client
from noknowledge.core.store import LocalStore
from noknowledge.crypto.encoding import b64e
from noknowledge.crypto.identity import Identity
from tests.conftest import fast_transport, make_client, make_device


def inert_client(tmp_path, name: str, identity: Identity | None = None) -> Client:
    """A client with a store but no relay: enough for bundle-level tests."""
    identity = identity or Identity.generate(label=name)[0]
    store = LocalStore(str(tmp_path / f"{name}.db"), key=os.urandom(32))
    store.initialize()
    return Client(identity, store, ["http://127.0.0.1:1"], name=name, transport=fast_transport())


def add_contact(client: Client, contact_id: str, nickname: str = "Bob", **overrides) -> None:
    row = {
        "id": contact_id,
        "isign": b"i" * 32,
        "idh": b"x" * 32,
        "bundle_id": "bundle",
        "inbox": {"id": "mailbox", "w": "write-token"},
        "relays": ["https://relay.example"],
        "session": None,
        "nickname": nickname,
        "verified": False,
        "created_at": 1,
    }
    row.update(overrides)
    client.store.upsert_contact(client.identity_id, row)


def add_message(client: Client, contact_id: str, **overrides):
    message = {
        "id": os.urandom(16).hex(),
        "identity_id": client.identity_id,
        "contact_id": contact_id,
        "direction": "received",
        "type": "text",
        "body": {"text": "hello"},
        "remote_id": "env-1",
        "ts": 1000,
        "state": "received",
        "meta": None,
    }
    message.update(overrides)
    client.store.add_message(message)
    return message


# -- collection and merge --------------------------------------------------


def test_bundle_round_trips_contacts_and_messages(tmp_path):
    source = inert_client(tmp_path, "source")
    add_contact(source, "bob-id")
    add_message(source, "bob-id")
    add_message(
        source, "bob-id", direction="sent", remote_id=None, body={"text": "mine"}, ts=2000
    )

    bundle = history.build_bundle(source)
    assert [item["id"] for item in bundle["contacts"]] == ["bob-id"]
    assert len(bundle["messages"]) == 2

    # Through the wire form and back, as an import would do.
    decoded = history.decode_bundle(history.encode_bundle(bundle))

    target = inert_client(tmp_path, "target")
    counts = history.merge_bundle(target, decoded)

    assert counts == {"contacts": 1, "messages": 2, "updates": 0, "chunks": 0}
    assert target.list_contacts()[0]["id"] == "bob-id"
    texts = sorted(message["body"]["text"] for message in target.messages("bob-id"))
    assert texts == ["hello", "mine"]


def test_merge_is_idempotent(tmp_path):
    source = inert_client(tmp_path, "source")
    add_contact(source, "bob-id")
    add_message(source, "bob-id")
    bundle = history.build_bundle(source)

    target = inert_client(tmp_path, "target")
    assert history.merge_bundle(target, bundle)["messages"] == 1
    # A carbon and a back-fill of the same message must collapse into one row.
    assert history.merge_bundle(target, bundle) == {
        "contacts": 0,
        "messages": 0,
        "updates": 0,
        "chunks": 0,
    }
    assert len(target.messages("bob-id")) == 1


def test_merge_never_downgrades_read_state(tmp_path):
    source = inert_client(tmp_path, "source")
    add_contact(source, "bob-id")
    add_message(source, "bob-id", state="read")
    bundle = history.build_bundle(source)

    target = inert_client(tmp_path, "target")
    add_contact(target, "bob-id")
    add_message(target, "bob-id", state="received")

    counts = history.merge_bundle(target, bundle)

    assert counts["messages"] == 0
    assert counts["updates"] == 1
    assert target.messages("bob-id")[0]["state"] == "read"

    # And the reverse direction must not resurrect "unread".
    stale = history.build_bundle(source)
    stale["messages"][0]["state"] = "received"
    history.merge_bundle(target, stale)
    assert target.messages("bob-id")[0]["state"] == "read"


def test_merge_keeps_local_nickname_and_routing(tmp_path):
    source = inert_client(tmp_path, "source")
    add_contact(source, "bob-id", nickname="Bob from source", relays=["https://old.example"])
    bundle = history.build_bundle(source)

    target = inert_client(tmp_path, "target")
    add_contact(target, "bob-id", nickname="My Bob", verified=True, relays=["https://new.example"])

    assert history.merge_bundle(target, bundle)["contacts"] == 0
    contact = target.store.get_contact(target.identity_id, "bob-id")
    assert contact["nickname"] == "My Bob"
    assert contact["verified"] is True
    assert contact["relays"] == ["https://new.example"]


def test_bundle_range_filters_messages(tmp_path):
    source = inert_client(tmp_path, "source")
    add_contact(source, "bob-id")
    add_message(source, "bob-id", ts=1_000, remote_id="old")
    add_message(source, "bob-id", ts=2_000, remote_id="new")

    bundle = history.build_bundle(source, since_ms=1_500, until_ms=2_500)

    assert [item["remote_id"] for item in bundle["messages"]] == ["new"]
    # Contacts always travel: the sync target needs the routing table.
    assert len(bundle["contacts"]) == 1


def test_attachments_over_budget_are_reported_not_dropped(tmp_path):
    source = inert_client(tmp_path, "source")
    add_contact(source, "bob-id")
    source.store.put_local_blob("chunk-small", b"a" * 10)
    source.store.put_local_blob("chunk-big", b"b" * 100)
    add_message(
        source,
        "bob-id",
        type="file",
        body={
            "caption": "",
            "attachment": {
                "chunks": [{"id": "chunk-small", "nonce": b64e(b"n" * 12)},
                           {"id": "chunk-big", "nonce": b64e(b"n" * 12)}]
            },
        },
    )

    bundle = history.build_bundle(source, budget_bytes=50)

    assert [chunk["id"] for chunk in bundle["chunks"]] == ["chunk-small"]
    assert bundle["skipped"] == [{"id": "chunk-big", "reason": "over budget"}]


def test_missing_local_chunks_are_reported(tmp_path):
    source = inert_client(tmp_path, "source")
    add_contact(source, "bob-id")
    add_message(
        source,
        "bob-id",
        type="file",
        body={"attachment": {"chunks": [{"id": "never-cached", "nonce": "x"}]}},
    )

    bundle = history.build_bundle(source)

    assert bundle["chunks"] == []
    assert bundle["skipped"] == [{"id": "never-cached", "reason": "not held here"}]


# -- export files ----------------------------------------------------------


def test_export_file_round_trip(tmp_path):
    source = inert_client(tmp_path, "source")
    add_contact(source, "bob-id")
    add_message(source, "bob-id")

    data = history.export_history(source, "correct horse")

    assert history.is_history_file(data) is True
    header = history.read_export_header(data)
    assert header["counts"]["messages"] == 1

    target = inert_client(tmp_path, "target")
    counts = history.import_history(target, data, "correct horse")

    assert counts["messages"] == 1
    assert target.messages("bob-id")[0]["body"]["text"] == "hello"


def test_export_file_rejects_a_wrong_passphrase(tmp_path):
    source = inert_client(tmp_path, "source")
    add_contact(source, "bob-id")
    data = history.export_history(source, "right")

    target = inert_client(tmp_path, "target")
    with pytest.raises(history.HistoryError, match="passphrase"):
        history.import_history(target, data, "wrong")


def test_export_file_rejects_tampering(tmp_path):
    source = inert_client(tmp_path, "source")
    add_contact(source, "bob-id")
    data = bytearray(history.export_history(source, "pw"))
    data[-1] ^= 0x01

    target = inert_client(tmp_path, "target")
    with pytest.raises(history.HistoryError):
        history.import_history(target, bytes(data), "pw")


def test_export_file_detects_truncation(tmp_path):
    source = inert_client(tmp_path, "source")
    add_contact(source, "bob-id")
    data = history.export_history(source, "pw")

    target = inert_client(tmp_path, "target")
    with pytest.raises(history.HistoryError, match="truncated"):
        history.import_history(target, data[:20], "pw")


def test_export_requires_a_passphrase(tmp_path):
    source = inert_client(tmp_path, "source")
    with pytest.raises(history.HistoryError):
        history.export_history(source, "")


def test_foreign_file_is_not_a_history_file(tmp_path):
    source = inert_client(tmp_path, "source")
    assert history.is_history_file(b"not a history file") is False
    with pytest.raises(history.HistoryError):
        history.read_export_header(b"nope")
    assert source.identity_id


# -- end to end, over a real relay -----------------------------------------


def test_history_moves_to_a_device_restored_from_the_seed(tmp_path, relay):
    import sqlite3

    alice = make_client(tmp_path / "a", "alice", [relay.url])
    bob = make_client(tmp_path / "b", "bob", [relay.url])
    alice.provision()
    bob.provision()
    alice.add_contact(bob.card_string(), nickname="Bob")

    alice.send_text(bob.identity_id, "one")
    bob.sync()
    bob.send_text(alice.identity_id, "two")
    alice.sync()
    source = tmp_path / "doc.bin"
    source.write_bytes(os.urandom(120_000))
    alice.send_file(bob.identity_id, str(source))
    received = bob.sync()[0]
    bob.download_attachment(received)
    bob.mark_read(alice.identity_id, received["id"])
    alice.sync()

    data = history.export_history(alice, "seed backup", budget_bytes=10**9)

    # A second device on the same account, with its own empty store.
    device = make_device(tmp_path / "a2", "alice-new", [relay.url], alice.identity)
    device.provision()
    counts = history.import_history(device, data, "seed backup")

    assert counts["messages"] == 3
    assert counts["chunks"] == 1

    messages = device.messages(bob.identity_id)
    assert sorted(message["type"] for message in messages) == ["file", "text", "text"]
    # Receipt state travelled, so ticks agree on both devices.
    assert {message["state"] for message in messages} == {"read", "received", "delivered"}

    # The attachment came with it and decodes without touching the relay.
    connection = sqlite3.connect(relay.db_path)
    try:
        connection.execute("DELETE FROM blobs")
        connection.commit()
    finally:
        connection.close()
    file_message = next(message for message in messages if message["type"] == "file")
    assert device.download_attachment(file_message) == (tmp_path / "doc.bin").read_bytes()

    # And importing again is a no-op.
    assert history.import_history(device, data, "seed backup")["messages"] == 0


def test_export_can_skip_attachments(tmp_path):
    client = inert_client(tmp_path, "source")
    add_contact(client, "bob-id")
    client.store.put_local_blob("chunk-1", b"c" * 40)
    add_message(
        client,
        "bob-id",
        type="file",
        body={"attachment": {"chunks": [{"id": "chunk-1", "nonce": "x"}]}},
    )

    bundle = history.build_bundle(client, include_attachments=False)

    assert bundle["chunks"] == []
    assert bundle["skipped"] == []


def test_export_never_contains_local_secrets(tmp_path):
    """A bundle carries conversation history, never ratchet or identity keys."""
    source = inert_client(tmp_path, "source")
    add_contact(source, "bob-id", session={"v": 2, "marker": "device-local-ratchet"})
    add_message(source, "bob-id")

    raw = history.encode_bundle(history.build_bundle(source)).decode("utf-8")

    assert "device-local-ratchet" not in raw
    assert b64e(source.identity.ed_private_bytes) not in raw
    assert pathlib.Path(source.store.path).name not in raw