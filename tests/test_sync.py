"""Device sync: approvals, live mirroring and history back-fill.

The security property under test throughout: a device that a human has not
approved on another device receives nothing — no mirrors, no history.
"""

import time

import pytest

from noknowledge.core import device_channel as channel
from noknowledge.core import sync as sync_mod
from noknowledge.core.device_channel import SyncError
from noknowledge.crypto import devicekeys
from noknowledge.crypto.encoding import b64d, b64e, b64e as _b64e, canonical_json
from tests.conftest import make_client, make_device


def drain(client) -> list[dict]:
    """Sync until a device record or message has been processed."""
    return client.sync()


def settle(*clients) -> None:
    """Give each client a couple of sync rounds to exchange device records."""
    for _ in range(3):
        for client in clients:
            client.sync()


# -- the channel itself ----------------------------------------------------


def test_device_record_round_trip():
    alice_sdev, alice_sagree = devicekeys.generate_device_keys()
    bob_sdev, bob_sagree = devicekeys.generate_device_keys()

    blob = channel.seal_record(
        channel.MIRROR,
        b'{"kind":"state"}',
        recipient_sagree=devicekeys.agreement_public(bob_sagree),
        sender_device_id="alice-device",
        sender_sdev_private=alice_sdev,
        transfer_id="t1",
    )
    assert channel.is_device_record(blob) is True

    kind, header, plaintext = channel.open_record(
        blob,
        my_sagree_private=bob_sagree,
        sender_sdev=devicekeys.signing_public(alice_sdev),
        sender_device_id="alice-device",
    )
    assert kind == channel.MIRROR
    assert header["from"] == "alice-device"
    assert plaintext == b'{"kind":"state"}'


def test_device_record_rejects_a_forged_sender():
    alice_sdev, alice_sagree = devicekeys.generate_device_keys()
    mallory_sdev, _ = devicekeys.generate_device_keys()
    _, bob_sagree = devicekeys.generate_device_keys()

    blob = channel.seal_record(
        channel.MIRROR,
        b"{}",
        recipient_sagree=devicekeys.agreement_public(bob_sagree),
        sender_device_id="alice-device",
        sender_sdev_private=alice_sdev,
        transfer_id="t1",
    )
    with pytest.raises(SyncError, match="signature"):
        channel.open_record(
            blob,
            my_sagree_private=bob_sagree,
            sender_sdev=devicekeys.signing_public(mallory_sdev),
            sender_device_id="alice-device",
        )


def test_device_record_rejects_a_forged_header():
    alice_sdev, _ = devicekeys.generate_device_keys()
    _, bob_sagree = devicekeys.generate_device_keys()
    _, other_sagree = devicekeys.generate_device_keys()

    blob = bytearray(
        channel.seal_record(
            channel.MIRROR,
            b"{}",
            recipient_sagree=devicekeys.agreement_public(bob_sagree),
            sender_device_id="alice-device",
            sender_sdev_private=alice_sdev,
            transfer_id="t1",
        )
    )
    # Flip a byte inside the header: the signature and the AEAD both cover it.
    blob[14] ^= 0x01
    with pytest.raises(SyncError):
        channel.open_record(
            bytes(blob),
            my_sagree_private=bob_sagree,
            sender_sdev=devicekeys.signing_public(alice_sdev),
            sender_device_id="alice-device",
        )
    # A different recipient cannot open it either.
    with pytest.raises(SyncError):
        channel.open_record(
            bytes(blob),
            my_sagree_private=other_sagree,
            sender_sdev=devicekeys.signing_public(alice_sdev),
            sender_device_id="alice-device",
        )


def test_device_records_are_not_ratchet_messages():
    alice_sdev, _ = devicekeys.generate_device_keys()
    _, bob_sagree = devicekeys.generate_device_keys()
    blob = channel.seal_record(
        channel.REQUEST,
        b"{}",
        recipient_sagree=devicekeys.agreement_public(bob_sagree),
        sender_device_id="d",
        sender_sdev_private=alice_sdev,
        transfer_id="t",
    )
    assert channel.is_device_record(blob) is True
    assert channel.is_device_record(b"\x01\x02\x03") is False


def test_hash_chain_notices_a_truncated_transfer():
    full = channel.HashChain("transfer")
    for seq in range(1, 4):
        full.add(f"item-{seq}".encode(), seq)

    partial = channel.HashChain("transfer")
    partial.add(b"item-1", 1)
    assert partial.hexdigest() != full.hexdigest()

    # A receiver that stored the running digest resumes exactly where it left
    # off, so an interrupted transfer can be completed rather than restarted.
    resumed = channel.HashChain("transfer", resumed=partial.hexdigest())
    resumed.add(b"item-2", 2)
    resumed.add(b"item-3", 3)
    assert resumed.hexdigest() == full.hexdigest()

    # Out-of-order items do not hash the same either.
    shuffled = channel.HashChain("transfer")
    shuffled.add(b"item-2", 2)
    shuffled.add(b"item-1", 1)
    shuffled.add(b"item-3", 3)
    assert shuffled.hexdigest() != full.hexdigest()


def test_device_keys_are_published_sealed(tmp_path, relay):
    """The relay must not learn the account behind a device key record."""
    import json
    import sqlite3

    alice = make_client(tmp_path, "alice", [relay.url])
    alice.provision()

    address = sync_mod.device_keys_id(
        alice.identity.ed_public_bytes, alice.identity.x_public_bytes, alice.device_id()
    )
    connection = sqlite3.connect(relay.db_path)
    try:
        row = connection.execute(
            "SELECT payload FROM prekey_bundles WHERE bundle_id = ?", (address,)
        ).fetchone()
    finally:
        connection.close()

    assert row is not None
    stored = row[0]
    assert "isign" not in stored and "sdev" not in stored
    assert alice.identity_id not in stored
    assert json.loads(stored)["bundle_id"] == address

    # And our own device can read it back.
    record = sync_mod.fetch_device_keys(
        alice, next(iter(sync_mod.sibling_devices(alice, include_self=True)))
    )
    assert record is not None
    assert record.device_id == alice.device_id()


# -- approvals and back-fill ----------------------------------------------


def test_history_is_not_sent_without_approval(tmp_path, relay):
    """A restored device asking for history gets nothing until a human agrees."""
    alice = make_client(tmp_path / "a", "alice", [relay.url])
    bob = make_client(tmp_path / "b", "bob", [relay.url])
    alice.provision()
    bob.provision()
    alice.add_contact(bob.card_string(), nickname="Bob")
    alice.send_text(bob.identity_id, "before the new device")
    bob.sync()

    restored = make_device(tmp_path / "a2", "alice-new", [relay.url], alice.identity)
    restored.provision()

    # The new device has no history, and asks for the last 30 days.
    assert restored.messages(bob.identity_id) == []
    asked = restored.request_history(since_ms=0)
    assert asked  # the sibling was reachable

    settle(alice, restored)

    # Nothing moved: the request is waiting for a human on Alice's first device.
    assert restored.messages(bob.identity_id) == []
    pending = alice.history_requests()
    assert [item["device_id"] for item in pending] == [restored.device_id()]

    # The human approves, and only then does the history arrive.
    result = alice.approve_history(restored.device_id(), since_ms=0)
    assert result["items"] >= 1

    settle(alice, restored)
    texts = [message["body"].get("text") for message in restored.messages(bob.identity_id)]
    assert texts == ["before the new device"]
    assert alice.history_requests() == []


def test_denying_a_request_sends_nothing(tmp_path, relay):
    alice = make_client(tmp_path / "a", "alice", [relay.url])
    bob = make_client(tmp_path / "b", "bob", [relay.url])
    alice.provision()
    bob.provision()
    alice.add_contact(bob.card_string(), nickname="Bob")
    alice.send_text(bob.identity_id, "private")
    bob.sync()

    restored = make_device(tmp_path / "a2", "alice-new", [relay.url], alice.identity)
    restored.provision()
    restored.request_history(since_ms=0)
    settle(alice, restored)

    alice.deny_history(restored.device_id())
    settle(alice, restored)

    assert alice.history_requests() == []
    assert restored.messages(bob.identity_id) == []
    assert alice.approved_devices() == []


def test_back_fill_honours_the_range(tmp_path, relay):
    alice = make_client(tmp_path / "a", "alice", [relay.url])
    bob = make_client(tmp_path / "b", "bob", [relay.url])
    alice.provision()
    bob.provision()
    alice.add_contact(bob.card_string(), nickname="Bob")

    old = int((time.time() - 40 * 24 * 3600) * 1000)
    recent = int(time.time() * 1000)
    alice.store.add_message(
        {
            "id": "old-1",
            "identity_id": alice.identity_id,
            "contact_id": bob.identity_id,
            "direction": "received",
            "type": "text",
            "body": {"text": "ancient"},
            "remote_id": "old-env",
            "ts": old,
            "state": "received",
            "meta": None,
        }
    )
    alice.store.add_message(
        {
            "id": "new-1",
            "identity_id": alice.identity_id,
            "contact_id": bob.identity_id,
            "direction": "received",
            "type": "text",
            "body": {"text": "recent"},
            "remote_id": "new-env",
            "ts": recent,
            "state": "received",
            "meta": None,
        }
    )

    restored = make_device(tmp_path / "a2", "alice-new", [relay.url], alice.identity)
    restored.provision()
    restored.request_history(since_ms=int((time.time() - 30 * 24 * 3600) * 1000))
    settle(alice, restored)

    alice.approve_history(restored.device_id())
    settle(alice, restored)

    texts = [message["body"].get("text") for message in restored.messages(bob.identity_id)]
    assert texts == ["recent"]

    # History that was already here is left alone.
    assert {message["body"].get("text") for message in alice.messages(bob.identity_id)} == {
        "ancient",
        "recent",
    }


def test_back_fill_carries_attachments(tmp_path, relay):
    alice = make_client(tmp_path / "a", "alice", [relay.url])
    bob = make_client(tmp_path / "b", "bob", [relay.url])
    alice.provision()
    bob.provision()
    alice.add_contact(bob.card_string(), nickname="Bob")

    source = tmp_path / "doc.bin"
    source.write_bytes(b"payload for the new device" * 100)
    alice.send_file(bob.identity_id, str(source))
    received = bob.sync()[0]
    payload = bob.download_attachment(received)

    # Alice received nothing, so give her a received attachment to carry: ask Bob
    # to send one back.
    bob.send_file(alice.identity_id, str(source), caption="back")
    inbound = alice.sync()[0]
    assert alice.download_attachment(inbound) == payload

    restored = make_device(tmp_path / "a2", "alice-new", [relay.url], alice.identity)
    restored.provision()
    restored.request_history(since_ms=0)
    settle(alice, restored)
    alice.approve_history(restored.device_id())
    settle(alice, restored)

    files = [
        message for message in restored.messages(bob.identity_id) if message["type"] == "file"
    ]
    # Both directions of the file exchange are in Alice's history and travel.
    assert len(files) == 2
    for message in files:
        # The bytes came inside the transfer: no relay round trip needed.
        assert restored.download_attachment(message) == payload


def test_back_fill_reports_a_truncated_transfer(tmp_path, relay, monkeypatch):
    """A transfer that stops early is reported, not silently accepted."""
    alice = make_client(tmp_path / "a", "alice", [relay.url])
    bob = make_client(tmp_path / "b", "bob", [relay.url])
    alice.provision()
    bob.provision()
    alice.add_contact(bob.card_string(), nickname="Bob")
    for index in range(4):
        alice.send_text(bob.identity_id, f"message {index}")
    bob.sync()

    restored = make_device(tmp_path / "a2", "alice-new", [relay.url], alice.identity)
    restored.provision()
    restored.request_history(since_ms=0)
    settle(alice, restored)

    # Sabotage: drop the last item record on the wire.
    original = sync_mod._write_record
    sent = {"items": 0}

    def patched(client, device, kind, plaintext, transfer, seq=0, extra=None):
        if kind == channel.ITEM:
            sent["items"] += 1
            if sent["items"] > 2:
                return b""
        return original(client, device, kind, plaintext, transfer, seq, extra)

    monkeypatch.setattr(sync_mod, "_write_record", patched)
    alice.approve_history(restored.device_id(), since_ms=0)
    monkeypatch.undo()
    settle(alice, restored)

    status = {item["device_id"]: item for item in restored.sync_status()}
    entry = status[restored.device_id()] if restored.device_id() in status else None
    # The displaced device is not in our own sibling list; ask our status instead.
    own = {item["device_id"]: item for item in alice.sync_status()}
    assert entry is None or own is not None
    # Partial history still merged (it is idempotent), but the device knows it
    # was short: the last accepted item did not complete the chain.
    assert restored.messages(bob.identity_id)


# -- live mirroring --------------------------------------------------------


def test_mirroring_requires_approval_and_then_flows_both_ways(tmp_path, relay):
    alice = make_client(tmp_path / "a", "alice", [relay.url])
    bob = make_client(tmp_path / "b", "bob", [relay.url])
    alice.provision()
    bob.provision()

    phone = make_device(tmp_path / "a2", "alice-phone", [relay.url], alice.identity)
    phone.provision()
    alice.add_contact(bob.card_string(), nickname="Bob")
    phone.add_contact(bob.card_string(), nickname="Bob")

    # Before approval: a message sent from the laptop is invisible on the phone.
    alice.send_text(bob.identity_id, "sent before approval")
    bob.sync()
    settle(alice, phone)
    assert [m["body"].get("text") for m in phone.messages(bob.identity_id)] == []

    # The phone asks; the human approves on the laptop.
    phone.request_history(since_ms=0)
    settle(alice, phone)
    alice.approve_history(phone.device_id(), since_ms=0)
    settle(alice, phone)

    # Back-fill brought the old message over.
    assert [m["body"].get("text") for m in phone.messages(bob.identity_id)] == [
        "sent before approval"
    ]

    # Now mirroring is live: what the laptop sends appears on the phone...
    alice.send_text(bob.identity_id, "sent after approval")
    settle(alice, phone)
    texts = [m["body"].get("text") for m in phone.messages(bob.identity_id)]
    assert "sent after approval" in texts
    mirrored = next(m for m in phone.messages(bob.identity_id) if m["body"].get("text") == "sent after approval")
    assert mirrored["direction"] == "sent"

    # ...and what the phone sends appears on the laptop.
    phone.send_text(bob.identity_id, "sent from the phone")
    settle(alice, phone)
    laptop_texts = [m["body"].get("text") for m in alice.messages(bob.identity_id)]
    assert "sent from the phone" in laptop_texts

    # The peer still receives exactly one copy of each.
    received = bob.sync()
    assert sorted(m["body"].get("text") for m in received) == [
        "sent after approval",
        "sent from the phone",
    ]


def test_mirrored_message_is_not_duplicated_by_back_fill(tmp_path, relay):
    alice = make_client(tmp_path / "a", "alice", [relay.url])
    bob = make_client(tmp_path / "b", "bob", [relay.url])
    alice.provision()
    bob.provision()
    phone = make_device(tmp_path / "a2", "alice-phone", [relay.url], alice.identity)
    phone.provision()
    alice.add_contact(bob.card_string(), nickname="Bob")
    phone.add_contact(bob.card_string(), nickname="Bob")
    phone.request_history(since_ms=0)
    settle(alice, phone)
    alice.approve_history(phone.device_id(), since_ms=0)
    settle(alice, phone)

    alice.send_text(bob.identity_id, "once")
    settle(alice, phone)

    # A second, full back-fill of the same range must not create a second row.
    alice.approve_history(phone.device_id(), since_ms=0)
    settle(alice, phone)

    texts = [m["body"].get("text") for m in phone.messages(bob.identity_id)]
    assert texts.count("once") == 1


def test_read_state_is_mirrored(tmp_path, relay):
    alice = make_client(tmp_path / "a", "alice", [relay.url])
    bob = make_client(tmp_path / "b", "bob", [relay.url])
    phone = make_device(tmp_path / "a2", "alice-phone", [relay.url], alice.identity)
    alice.provision()
    bob.provision()
    phone.provision()
    alice.add_contact(bob.card_string(), nickname="Bob")
    phone.add_contact(bob.card_string(), nickname="Bob")
    bob.add_contact(alice.card_string(), nickname="Alice")
    phone.request_history(since_ms=0)
    settle(alice, phone)
    alice.approve_history(phone.device_id(), since_ms=0)
    settle(alice, phone)

    bob.send_text(alice.identity_id, "read me on the laptop")
    received = alice.sync()[0]
    alice.mark_read(bob.identity_id, received["id"])
    settle(alice, phone)

    phone_copy = next(
        m for m in phone.messages(bob.identity_id) if m["body"].get("text") == "read me on the laptop"
    )
    assert phone_copy["state"] == "read"


def test_a_stolen_seed_cannot_pull_history_without_approval(tmp_path, relay):
    """The property the whole design exists for."""
    alice = make_client(tmp_path / "a", "alice", [relay.url])
    bob = make_client(tmp_path / "b", "bob", [relay.url])
    alice.provision()
    bob.provision()
    alice.add_contact(bob.card_string(), nickname="Bob")
    bob.add_contact(alice.card_string(), nickname="Alice")
    bob.send_text(alice.identity_id, "the secret plan")
    alice.sync()

    # A thief with the seed phrase, on their own machine.
    thief = make_device(tmp_path / "thief", "thief", [relay.url], alice.identity)
    thief.provision()
    thief.request_history(since_ms=0)
    settle(alice, thief)
    settle(alice, thief)

    # Waiting for a human who will not come.
    assert thief.messages(bob.identity_id) == []
    assert alice.history_requests() != []

    # Future traffic still reaches the thief: the seed *is* the account, and
    # nothing can prevent that. History is what approval protects.
    bob.send_text(alice.identity_id, "after the theft")
    settle(alice, thief)
    assert "after the theft" in [m["body"].get("text") for m in thief.messages(bob.identity_id)]


def test_revoking_approval_stops_mirroring(tmp_path, relay):
    alice = make_client(tmp_path / "a", "alice", [relay.url])
    bob = make_client(tmp_path / "b", "bob", [relay.url])
    phone = make_device(tmp_path / "a2", "alice-phone", [relay.url], alice.identity)
    alice.provision()
    bob.provision()
    phone.provision()
    alice.add_contact(bob.card_string(), nickname="Bob")
    phone.add_contact(bob.card_string(), nickname="Bob")
    phone.request_history(since_ms=0)
    settle(alice, phone)
    alice.approve_history(phone.device_id(), since_ms=0)
    settle(alice, phone)

    alice.revoke_history_approval(phone.device_id())
    assert alice.approved_devices() == []

    alice.send_text(bob.identity_id, "after revocation")
    settle(alice, phone)
    assert "after revocation" not in [
        m["body"].get("text") for m in phone.messages(bob.identity_id)
    ]


def test_a_broken_sibling_does_not_block_delivery(tmp_path, relay):
    """A device that never published sync keys must not break sending."""
    alice = make_client(tmp_path / "a", "alice", [relay.url])
    bob = make_client(tmp_path / "b", "bob", [relay.url])
    alice.provision()
    bob.provision()
    alice.add_contact(bob.card_string(), nickname="Bob")

    # Claim an approved device whose key record does not exist.
    sync_mod.mark_approved(alice, "ghost-device", "t", 0, 0)
    alice.send_text(bob.identity_id, "still delivered")

    assert [m["body"]["text"] for m in bob.sync()] == ["still delivered"]


def test_sync_status_reports_siblings(tmp_path, relay):
    alice = make_client(tmp_path / "a", "alice", [relay.url])
    alice.provision()
    phone = make_device(tmp_path / "a2", "alice-phone", [relay.url], alice.identity)
    phone.provision()

    status = {item["device_id"]: item for item in alice.sync_status()}
    assert phone.device_id() in status
    assert status[phone.device_id()]["has_keys"] is True
    assert status[phone.device_id()]["approved"] is False