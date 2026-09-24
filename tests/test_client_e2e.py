"""End-to-end tests against real relays running over real HTTP."""

import json
import os
import sqlite3

import pytest

from noknowledge.core.attachments import AttachmentError
from noknowledge.core.card import CardError, ContactCard
from noknowledge.wire.backends.multi_relay import MultiRelayBackend
from noknowledge.wire.transport import Transport
from tests.conftest import make_client


def contact_id_of(client, other):
    return other.identity_id


# -- the core promise -----------------------------------------------------


def test_handshake_and_text_delivery(alice_bob):
    alice, bob, relay = alice_bob
    assert bob.list_contacts() == []
    alice.send_text(bob.identity_id, "hello bob")

    received = bob.sync()
    assert len(received) == 1
    message = received[0]
    assert message["type"] == "text"
    assert message["body"]["text"] == "hello bob"
    assert message["direction"] == "received"

    contacts = bob.list_contacts()
    assert [c["id"] for c in contacts] == [alice.identity_id]


def test_bidirectional_conversation(alice_bob):
    alice, bob, _ = alice_bob
    alice.send_text(bob.identity_id, "one")
    assert bob.sync()[0]["body"]["text"] == "one"

    bob.send_text(alice.identity_id, "two")
    assert alice.sync()[0]["body"]["text"] == "two"

    alice.send_text(bob.identity_id, "three")
    assert bob.sync()[0]["body"]["text"] == "three"


def test_receipt_clears_outbox_and_marks_delivered(alice_bob):
    alice, bob, _ = alice_bob
    alice.send_text(bob.identity_id, "confirm me")
    assert alice.store.outbox_count(alice.identity_id) == 1

    bob.sync()  # decrypting sends an automatic delivery receipt
    events = alice.sync()
    assert events == []  # receipts are not surfaced as messages

    stored = alice.messages(bob.identity_id)[0]
    assert stored["state"] == "delivered"
    assert alice.store.outbox_count(alice.identity_id) == 0


def test_mark_read_sends_explicit_receipt(alice_bob):
    alice, bob, _ = alice_bob
    alice.send_text(bob.identity_id, "read me")
    received = bob.sync()[0]
    alice.sync()  # delivery receipt

    bob.mark_read(alice.identity_id, received["id"])
    alice.sync()
    assert alice.messages(bob.identity_id)[0]["state"] == "read"


def test_duplicate_delivery_is_ignored(alice_bob):
    alice, bob, _ = alice_bob
    alice.send_text(bob.identity_id, "only once")
    assert len(bob.sync()) == 1
    assert bob.sync() == []


def test_file_transfer(alice_bob, tmp_path):
    alice, bob, _ = alice_bob
    payload = os.urandom(300_000)  # spans more than one chunk
    source = tmp_path / "secret.bin"
    source.write_bytes(payload)

    alice.send_file(bob.identity_id, str(source), caption="the goods")
    received = bob.sync()
    assert len(received) == 1
    assert received[0]["type"] == "file"
    assert received[0]["body"]["caption"] == "the goods"

    downloaded = bob.download_attachment(received[0])
    assert downloaded == payload


def test_attachment_hash_is_verified(alice_bob, tmp_path):
    alice, bob, _ = alice_bob
    source = tmp_path / "x.bin"
    source.write_bytes(b"integrity matters")
    alice.send_file(bob.identity_id, str(source))
    message = bob.sync()[0]
    manifest = message["body"]["attachment"]
    manifest["sha256"] = "0" * 64
    bob.store.update_message(message["id"], body=message["body"])
    with pytest.raises(AttachmentError):
        bob.download_attachment(bob.store.get_message(message["id"]))


# -- what the relay can and cannot see ------------------------------------


def test_relay_stores_only_ciphertext(alice_bob):
    alice, bob, relay = alice_bob
    secret = "TOPSECRET-PHRASE-9d3f"
    alice.send_text(bob.identity_id, secret)
    bob.sync()

    connection = sqlite3.connect(relay.db_path)
    try:
        blobs = [
            bytes(row[0])
            for row in connection.execute("SELECT ciphertext FROM messages")
        ]
        chunks = [
            bytes(row[0]) for row in connection.execute("SELECT ciphertext FROM blobs")
        ]
    finally:
        connection.close()
    for stored in blobs + chunks:
        assert secret.encode() not in stored
        assert alice.identity.ed_public_bytes not in stored
        assert bob.identity.ed_public_bytes not in stored


def test_relay_stores_no_identity_keys_in_bundles(alice_bob):
    alice, bob, relay = alice_bob
    connection = sqlite3.connect(relay.db_path)
    try:
        payloads = [
            row[0] for row in connection.execute("SELECT payload FROM prekey_bundles")
        ]
    finally:
        connection.close()
    assert payloads
    for payload in payloads:
        data = json.loads(payload)
        assert "isign" not in data and "idh" not in data
        assert alice.identity.ed_public_bytes.hex() not in payload


def test_card_does_not_leak_read_capability(alice_bob):
    """A contact may write to your mailbox but must never be able to read it."""
    alice, bob, _ = alice_bob
    decoded = ContactCard.from_string(alice.card_string())
    assert decoded.inbox.read_token is None
    assert decoded.inbox.write_token == alice._own_inbox.write_token
    assert alice._own_inbox.read_token not in str(decoded.signed_dict())


def test_contact_card_tampering_is_rejected(alice_bob):
    alice, bob, _ = alice_bob
    data = ContactCard.from_string(bob.card_string()).signed_dict()
    data["relays"] = ["https://evil.example"]
    from noknowledge.crypto.encoding import card_encode

    with pytest.raises(CardError):
        ContactCard.from_dict(data)

    # and a card with a valid-looking but wrong signature
    tampered = ContactCard.from_string(bob.card_string()).signed_dict()
    tampered["name"] = "not bob"
    with pytest.raises(CardError):
        ContactCard.from_string(card_encode(tampered))


# -- availability ---------------------------------------------------------


def test_relay_failover_mid_conversation(tmp_path, two_relays):
    first, second = two_relays
    alice = make_client(tmp_path, "alice", [first.url, second.url])
    bob = make_client(tmp_path, "bob", [first.url, second.url])
    alice.provision()
    bob.provision()
    alice.add_contact(bob.card_string())

    alice.send_text(bob.identity_id, "before the outage")
    assert bob.sync()[0]["body"]["text"] == "before the outage"
    alice.sync()

    first.stop()  # one relay of two goes away

    alice.send_text(bob.identity_id, "after the outage")
    received = bob.sync()
    assert len(received) == 1
    assert received[0]["body"]["text"] == "after the outage"

    alice.send_text(bob.identity_id, "still working")
    assert bob.sync()[0]["body"]["text"] == "still working"


def test_replicated_mailbox_survives_relay_loss(tmp_path, two_relays):
    """Both relays hold the same message; dedupe hides the duplicate."""
    first, second = two_relays
    alice = make_client(tmp_path, "alice", [first.url, second.url])
    bob = make_client(tmp_path, "bob", [first.url, second.url])
    alice.provision()
    bob.provision()
    alice.add_contact(bob.card_string())

    alice.send_text(bob.identity_id, "replicated")
    received = bob.sync()
    assert len(received) == 1, "duplicates from two relays must be deduplicated"


# -- transport ------------------------------------------------------------


def test_fail_closed_refuses_direct_connections():
    transport = Transport(proxy_url=None, fail_closed=True, retries=1)
    with pytest.raises(Exception) as excinfo:
        transport.request("GET", "https://example.com")
    assert "fail-closed" in str(excinfo.value)


def test_fail_closed_allows_loopback():
    transport = Transport(proxy_url=None, fail_closed=True, retries=1)
    assert transport.proxies_for("http://127.0.0.1:1234") == {}


def test_proxy_is_used_for_remote_hosts():
    transport = Transport(proxy_url="socks5://127.0.0.1:9050")
    proxies = transport.proxies_for("https://relay.example")
    assert proxies["https"] == "socks5://127.0.0.1:9050"


def test_empty_relay_set_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        MultiRelayBackend([])