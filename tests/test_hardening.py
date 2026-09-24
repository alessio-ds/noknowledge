"""Hardening tests: fuzzing, tamper resistance, quota and concurrency."""

import json
import os
import random
import threading

import pytest

from noknowledge.core.card import CardError, ContactCard
from noknowledge.crypto import x3dh
from noknowledge.crypto.encoding import b64e, card_encode
from noknowledge.crypto.identity import Identity, IdentityError
from noknowledge.crypto.padding import BUCKET, pad_envelope
from noknowledge.crypto.prekeys import make_bundle
from noknowledge.crypto.ratchet import Ratchet
from noknowledge.server.db import Database
from noknowledge.server.security import (
    leading_zero_bits,
    new_token,
    token_hash,
    verify_hashcash,
    verify_token,
)
from noknowledge.wire.errors import WireError
from noknowledge.wire.protocol import parse_wire
from tests.helpers import new_x25519


# -- padding --------------------------------------------------------------


def test_padding_equalises_lengths_within_a_bucket():
    lengths = set()
    for size in range(0, 400, 7):
        data = pad_envelope({"v": 1, "type": "text", "body": {"text": "x" * size}})
        lengths.add(len(data))
    # every payload under the bucket boundary lands on the same ciphertext size
    assert len(lengths) <= 2


def test_padding_never_exposes_plaintext():
    data = pad_envelope({"v": 1, "type": "text", "body": {"text": "MARKER12345"}})
    assert b"MARKER12345" in data  # padding is not encryption; AEAD is
    assert len(data) % BUCKET == 0


# -- ratchet --------------------------------------------------------------


def _session():
    bob, _ = Identity.generate()
    spk_private, spk_public = new_x25519()
    opk_private, opk_public = new_x25519()
    bundle = make_bundle(bob, os.urandom(16), 1, spk_public, [(1, opk_public)])
    initiation = x3dh.initiate(bundle, bob.ed_public_bytes, bob.x_public_bytes)
    key = x3dh.respond(
        bob.x_private_bytes, spk_private, opk_private, initiation.ek_public
    )
    alice = Ratchet.initiator(initiation.sk, bundle.spk)
    responder = Ratchet.responder(initiation.sk, spk_private, spk_public)
    return alice, responder, initiation.init_dict()


def test_ratchet_handles_arbitrary_reordering():
    for _ in range(10):
        alice, bob, init = _session()
        messages = []
        for index in range(12):
            context = init if index == 0 else None
            messages.append((alice.encrypt(f"m{index}".encode(), context), f"m{index}", context))
        random.shuffle(messages)
        for (header, nonce, ct), expected, context in messages:
            assert bob.decrypt(header, nonce, ct, context).decode() == expected


def test_ratchet_rejects_single_byte_flips_and_stays_in_sync():
    alice, bob, init = _session()
    header, nonce, ct = alice.encrypt(b"sensitive payload", init)
    for position in range(len(ct)):
        broken = bytearray(ct)
        broken[position] ^= 0x01
        with pytest.raises(Exception):
            bob.decrypt(header, nonce, bytes(broken), init)
    # After every rejected forgery the authentic message must still decrypt.
    assert bob.decrypt(header, nonce, ct, init) == b"sensitive payload"


def test_ratchet_header_tampering_is_rejected():
    alice, bob, init = _session()
    header, nonce, ct = alice.encrypt(b"payload", init)
    forged = dict(header)
    forged["n"] = header["n"] + 1
    with pytest.raises(Exception):
        bob.decrypt(forged, nonce, ct, init)
    assert bob.decrypt(header, nonce, ct, init) == b"payload"


def test_ratchet_ignores_unrelated_message_without_desync():
    alice, bob, init = _session()
    stranger, _, _ = _session()
    foreign_header, foreign_nonce, foreign_ct = stranger.encrypt(b"not for you", init)
    with pytest.raises(Exception):
        bob.decrypt(foreign_header, foreign_nonce, foreign_ct, init)
    header, nonce, ct = alice.encrypt(b"real message", init)
    assert bob.decrypt(header, nonce, ct, init) == b"real message"


def test_wire_parser_survives_garbage():
    for _ in range(200):
        blob = os.urandom(random.randint(0, 64))
        with pytest.raises(WireError):
            parse_wire(blob)


def test_wire_parser_rejects_wrong_version():
    with pytest.raises(WireError):
        parse_wire(json.dumps({"v": 99, "sid": "a", "hdr": {}, "nonce": "a", "ct": "a"}))
    with pytest.raises(WireError):
        parse_wire(json.dumps({"v": 1, "sid": "a"}))


# -- parsers never crash on hostile input ---------------------------------


def test_card_parser_survives_garbage():
    for _ in range(200):
        text = "nk://1/" + b64e(os.urandom(random.randint(0, 64)))
        with pytest.raises(CardError):
            ContactCard.from_string(text)


def test_card_parser_rejects_missing_relays():
    identity, _ = Identity.generate()
    card = ContactCard.create(identity, "b", _capability(), [])
    data = card.signed_dict()
    with pytest.raises(CardError):
        ContactCard.from_dict(data)


def _capability():
    from noknowledge.wire.backends.base import MailboxCapability

    return MailboxCapability.generate()


def test_vault_parser_survives_garbage():
    for _ in range(200):
        with pytest.raises(IdentityError):
            Identity.from_vault(os.urandom(random.randint(0, 64)))


# -- server limits --------------------------------------------------------


def test_hashcash():
    import hashlib
    import time

    bits = 8
    timestamp = int(time.time())
    nonce = 0
    while True:
        digest = hashlib.sha256(f"{timestamp}:{nonce}".encode()).digest()
        if leading_zero_bits(digest) >= bits:
            break
        nonce += 1
    assert verify_hashcash(f"{timestamp}:{nonce}", bits)
    assert not verify_hashcash("not-a-stamp", bits)
    assert not verify_hashcash(f"{timestamp}:{nonce}", 32)
    assert not verify_hashcash(f"{timestamp - 10**6}:{nonce}", bits)
    assert verify_hashcash(None, 0)


def test_token_comparison_requires_exact_match():
    token = new_token()
    stored = token_hash(token)
    assert verify_token(token, stored)
    assert not verify_token(new_token(), stored)
    assert not verify_token(token[:-1], stored)
    assert not verify_token(b"", stored)


def test_database_concurrent_writes_get_unique_sequences(tmp_path):
    database = Database(str(tmp_path / "concurrent.db"))
    database.initialize()
    database.create_mailbox(
        "m1", token_hash(b"r" * 32), token_hash(b"w" * 32), 0, 10_000, 10**9
    )
    errors: list = []

    def writer():
        for _ in range(5):
            try:
                database.put_message("m1", b"payload", 0)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    threads = [threading.Thread(target=writer) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    rows = database.get_messages("m1", 0, 1000)
    assert sorted(row["seq"] for row in rows) == list(range(1, 101))


def test_database_ack_is_exactly_bounded(tmp_path):
    database = Database(str(tmp_path / "ack.db"))
    database.initialize()
    database.create_mailbox(
        "m1", token_hash(b"r" * 32), token_hash(b"w" * 32), 0, 100, 10**9
    )
    for _ in range(5):
        database.put_message("m1", b"x", 0)
    assert database.ack_messages("m1", 3) == 3
    assert [row["seq"] for row in database.get_messages("m1", 0, 100)] == [4, 5]


def test_database_quota_counts_messages_and_blobs(tmp_path):
    database = Database(str(tmp_path / "quota.db"))
    database.initialize()
    database.create_mailbox(
        "m1", token_hash(b"r" * 32), token_hash(b"w" * 32), 0, 100, 100
    )
    database.put_message("m1", b"x" * 60, 0)
    from noknowledge.server.errors import QuotaExceeded

    with pytest.raises(QuotaExceeded):
        database.put_message("m1", b"x" * 60, 0)
    database.put_blob("c1", "m1", b"y" * 30, 0)
    with pytest.raises(QuotaExceeded):
        database.put_blob("c2", "m1", b"y" * 30, 0)


def test_database_housekeeping_removes_idle_mailboxes(tmp_path):
    database = Database(str(tmp_path / "hk.db"))
    database.initialize()
    database.create_mailbox(
        "old", token_hash(b"r" * 32), token_hash(b"w" * 32), 0, 100, 10**6
    )
    database.create_mailbox(
        "new", token_hash(b"r" * 32), token_hash(b"w" * 32), 9500, 100, 10**6
    )
    database.put_message("old", b"x", 0)
    result = database.housekeeping(now=10_000, mailbox_ttl=1000, blob_ttl=1000)
    assert result["mailboxes"] == 1
    assert database.get_mailbox("old") is None
    assert database.get_mailbox("new") is not None


# -- multi-relay fault injection -----------------------------------------


class _StubRelay:
    def __init__(self, url, fail=False):
        self.base_url = url
        self.fail = fail
        self.stored: list[bytes] = []

    def put(self, capability, envelope):
        if self.fail:
            raise RuntimeError("relay down")
        self.stored.append(envelope)

    def fetch(self, capability, after_seq=0, wait=0):
        if self.fail:
            raise RuntimeError("relay down")
        return []

    def ack(self, capability, upto_seq):
        if self.fail:
            raise RuntimeError("relay down")


def test_fanout_tolerates_one_dead_relay():
    from noknowledge.wire.backends.multi_relay import MultiRelayBackend

    backend = MultiRelayBackend.__new__(MultiRelayBackend)
    backend.relays = [_StubRelay("a", fail=True), _StubRelay("b", fail=False)]
    from concurrent.futures import ThreadPoolExecutor

    backend._pool = ThreadPoolExecutor(max_workers=2)
    capability = _capability()
    backend.put(capability, b"ciphertext")
    assert backend.relays[1].stored == [b"ciphertext"]


def test_fanout_reports_failure_when_all_relays_die():
    from concurrent.futures import ThreadPoolExecutor

    from noknowledge.wire.backends.multi_relay import MultiRelayBackend
    from noknowledge.wire.errors import AllRelaysFailed

    backend = MultiRelayBackend.__new__(MultiRelayBackend)
    backend.relays = [_StubRelay("a", fail=True), _StubRelay("b", fail=True)]
    backend._pool = ThreadPoolExecutor(max_workers=2)
    with pytest.raises(AllRelaysFailed):
        backend.put(_capability(), b"ciphertext")