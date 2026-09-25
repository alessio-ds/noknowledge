"""Multi-device accounts.

An account is the seed; a device is one mailbox with its own prekeys and its own
Double Ratchet sessions. These tests pin down that a second device (a fresh
install, or one recovered from the seed phrase) really does start receiving, and
that contacts without a device list keep working through the card's inbox.
"""

import sqlite3

import pytest

from noknowledge.core.devices import (
    DeviceEntry,
    DeviceList,
    DeviceListError,
    device_list_id,
    open_device_list,
    seal_device_list,
)
from noknowledge.crypto.identity import Identity
from tests.conftest import make_client, make_device


# -- the device list itself ------------------------------------------------


def _identity():
    identity, _ = Identity.generate(label="listowner")
    return identity


def _entry(device_id: str = "dev-one") -> DeviceEntry:
    return DeviceEntry(
        device_id=device_id,
        inbox={"id": "inbox-id", "w": "write-token"},
        relays=["https://relay.example"],
        bundle_id="bundle-id",
        name="laptop",
    )


def test_device_list_address_is_derivable_from_public_keys():
    identity = _identity()
    expected = device_list_id(identity.ed_public_bytes, identity.x_public_bytes)
    listing = DeviceList.create(identity, [_entry()])
    assert listing.address() == expected


def test_sealed_device_list_round_trips():
    identity = _identity()
    listing = DeviceList.create(identity, [_entry()])

    stored = seal_device_list(listing)
    opened = open_device_list(stored, identity.ed_public_bytes, identity.x_public_bytes)

    assert opened.account == identity.identity_id
    assert [d.device_id for d in opened.devices] == ["dev-one"]
    assert opened.devices[0].relays == ["https://relay.example"]


def test_sealed_device_list_leaks_no_identity_keys():
    identity = _identity()
    stored = seal_device_list(DeviceList.create(identity, [_entry()]))
    text = stored.decode("utf-8") if isinstance(stored, bytes) else stored

    # What a relay operator can read: an opaque box and a public hash.
    assert "isign" not in text and "idh" not in text
    assert identity.identity_id not in text
    assert "relay.example" not in text


def test_sealed_device_list_rejects_a_wrong_key():
    identity = _identity()
    other = _identity()
    stored = seal_device_list(DeviceList.create(identity, [_entry()]))

    with pytest.raises(DeviceListError):
        open_device_list(stored, other.ed_public_bytes, other.x_public_bytes)


def test_sealed_device_list_rejects_tampering():
    identity = _identity()
    stored = seal_device_list(DeviceList.create(identity, [_entry()]))
    tampered = stored.replace(b'"box":"', b'"box":"A', 1)

    with pytest.raises(DeviceListError):
        open_device_list(tampered, identity.ed_public_bytes, identity.x_public_bytes)


def test_device_list_signature_binds_the_devices():
    identity = _identity()
    listing = DeviceList.create(identity, [_entry()])
    listing.devices.append(_entry("smuggled"))

    with pytest.raises(DeviceListError):
        DeviceList.from_bytes(listing.to_bytes())


def test_device_list_from_another_account_is_rejected():
    identity = _identity()
    stranger = _identity()
    listing = DeviceList.create(stranger, [_entry()])

    assert not listing.belongs_to(
        identity.identity_id, identity.ed_public_bytes, identity.x_public_bytes
    )


# -- end to end, against a real relay --------------------------------------


def test_second_device_receives_new_messages(tmp_path, relay):
    alice = make_client(tmp_path / "a", "alice", [relay.url])
    bob = make_client(tmp_path / "b1", "bob", [relay.url])
    alice.provision()
    bob.provision()

    # A second device on Bob's account: another mailbox, same identity.
    bob2 = make_device(tmp_path / "b2", "bob-phone", [relay.url], bob.identity)
    bob2.provision()

    devices = bob.devices()
    assert len(devices) == 2
    assert {d.device_id for d in devices} == {bob.device_id(), bob2.device_id()}
    # Each device keeps its own mailbox, which is the whole point.
    assert bob._own_inbox.mailbox_id != bob2._own_inbox.mailbox_id

    alice.add_contact(bob.card_string(), nickname="Bob")
    alice.send_text(bob.identity_id, "to every device")

    assert [m["body"]["text"] for m in bob.sync()] == ["to every device"]
    assert [m["body"]["text"] for m in bob2.sync()] == ["to every device"]


def test_recovered_device_joins_the_list(tmp_path, relay):
    alice = make_client(tmp_path / "a", "alice", [relay.url])
    bob = make_client(tmp_path / "b1", "bob", [relay.url])
    alice.provision()
    bob.provision()
    alice.add_contact(bob.card_string(), nickname="Bob")
    alice.send_text(bob.identity_id, "before recovery")
    assert [m["body"]["text"] for m in bob.sync()] == ["before recovery"]

    # Restoring the seed phrase on a new machine: same keys, brand new mailbox.
    recovered = make_device(tmp_path / "rec", "bob-new", [relay.url], bob.identity)
    recovered.provision()
    assert recovered.identity_id == bob.identity_id
    assert recovered._own_inbox.mailbox_id != bob._own_inbox.mailbox_id
    assert recovered.device_id() in {d.device_id for d in bob.devices()}
    # The messages sent before it existed are not magically on the new device.
    assert recovered.sync() == []

    alice.send_text(bob.identity_id, "after recovery")
    assert [m["body"]["text"] for m in recovered.sync()] == ["after recovery"]
    assert [m["body"]["text"] for m in bob.sync()] == ["after recovery"]


def test_receipts_reach_every_device_of_the_sender(tmp_path, relay):
    alice = make_client(tmp_path / "a1", "alice", [relay.url])
    alice2 = make_device(tmp_path / "a2", "alice-tablet", [relay.url], alice.identity)
    bob = make_client(tmp_path / "b", "bob", [relay.url])
    alice.provision()
    alice2.provision()
    bob.provision()

    alice.add_contact(bob.card_string(), nickname="Bob")
    alice2.add_contact(bob.card_string(), nickname="Bob")

    alice.send_text(bob.identity_id, "for bob only")
    bob.sync()  # decrypting emits the delivery receipt
    alice.sync()
    alice2.sync()

    assert alice.messages(bob.identity_id)[0]["state"] == "delivered"
    # Alice's tablet never sent anything, so it has no outbox row to clear; the
    # receipt simply must not blow up its state.
    assert alice2.store.outbox_count(alice2.identity_id) == 0


def test_legacy_contact_without_a_device_list(tmp_path, relay, monkeypatch):
    """A peer that never published a list is reached at the card's inbox."""
    alice = make_client(tmp_path / "a", "alice", [relay.url])
    bob = make_client(tmp_path / "b", "bob", [relay.url])
    alice.provision()
    monkeypatch.setattr(bob, "_ensure_device_registered", lambda: None)
    bob.provision()

    # Nothing is published at the derivable address.
    connection = sqlite3.connect(relay.db_path)
    try:
        rows = connection.execute(
            "SELECT COUNT(*) FROM prekey_bundles WHERE bundle_id = ?",
            (device_list_id(bob.identity.ed_public_bytes, bob.identity.x_public_bytes),),
        ).fetchone()
    finally:
        connection.close()
    assert rows[0] == 0

    alice.add_contact(bob.card_string(), nickname="Bob")
    alice.send_text(bob.identity_id, "legacy path")

    assert [m["body"]["text"] for m in bob.sync()] == ["legacy path"]


def test_single_device_cards_still_exchange_files(tmp_path, relay):
    """Fan-out must not break the ordinary one-device case."""
    alice = make_client(tmp_path / "a", "alice", [relay.url])
    bob = make_client(tmp_path / "b", "bob", [relay.url])
    alice.provision()
    bob.provision()
    alice.add_contact(bob.card_string(), nickname="Bob")

    source = tmp_path / "note.txt"
    source.write_bytes(b"one device, one copy")
    alice.send_file(bob.identity_id, str(source))

    received = bob.sync()
    assert len(received) == 1
    payload = bob.download_attachment(received[0])
    assert payload == b"one device, one copy"


def test_file_reaches_every_device(tmp_path, relay):
    alice = make_client(tmp_path / "a", "alice", [relay.url])
    bob = make_client(tmp_path / "b1", "bob", [relay.url])
    alice.provision()
    bob.provision()
    bob2 = make_device(tmp_path / "b2", "bob-phone", [relay.url], bob.identity)
    bob2.provision()

    alice.add_contact(bob.card_string(), nickname="Bob")
    source = tmp_path / "doc.txt"
    source.write_bytes(b"multi-device attachment")

    alice.send_file(bob.identity_id, str(source))

    first = bob.sync()
    second = bob2.sync()
    assert len(first) == 1 and len(second) == 1
    # Each device pulls its own copy of the chunks out of its own mailbox.
    assert bob.download_attachment(first[0]) == b"multi-device attachment"
    assert bob2.download_attachment(second[0]) == b"multi-device attachment"


def test_relay_cannot_link_devices_to_the_account(tmp_path, relay):
    """The sealed record is the only thing the relay stores for a list."""
    bob = make_client(tmp_path / "b", "bob", [relay.url])
    bob.provision()
    second = make_device(tmp_path / "b2", "bob-phone", [relay.url], bob.identity)
    second.provision()

    address = device_list_id(bob.identity.ed_public_bytes, bob.identity.x_public_bytes)
    connection = sqlite3.connect(relay.db_path)
    try:
        row = connection.execute(
            "SELECT payload FROM prekey_bundles WHERE bundle_id = ?", (address,)
        ).fetchone()
    finally:
        connection.close()

    assert row is not None
    stored = row[0]
    assert "isign" not in stored and "idh" not in stored
    assert bob.identity_id not in stored
    # Both mailboxes are advertised, but only inside the sealed box.
    for device in bob.devices():
        assert device.inbox["id"] not in stored
        assert device.inbox["w"] not in stored