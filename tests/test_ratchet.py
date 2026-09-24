import os

import pytest

from noknowledge.crypto import x3dh
from noknowledge.crypto.aead import AEADError
from noknowledge.crypto.identity import Identity
from noknowledge.crypto.prekeys import make_bundle
from noknowledge.crypto.ratchet import (
    MAX_SKIP,
    DuplicateMessage,
    Ratchet,
    RatchetError,
    RatchetState,
    SkippedTooFar,
)
from tests.helpers import new_x25519


def make_session():
    """Return a fully handshaken ``(alice_ratchet, bob_ratchet, init_dict)``."""
    bob, _ = Identity.generate()
    spk_priv, spk_pub = new_x25519()
    opk_priv, opk_pub = new_x25519()
    bundle = make_bundle(bob, os.urandom(16), 1, spk_pub, [(5, opk_pub)])
    initiation = x3dh.initiate(bundle, bob.ed_public_bytes, bob.x_public_bytes)
    responder_key = x3dh.respond(
        bob.x_private_bytes, spk_priv, opk_priv, initiation.ek_public
    )
    assert initiation.sk == responder_key
    alice = Ratchet.initiator(initiation.sk, bundle.spk)
    bob_ratchet = Ratchet.responder(initiation.sk, spk_priv, spk_pub)
    return alice, bob_ratchet, initiation.init_dict()


def test_first_message_roundtrip():
    alice, bob, init = make_session()
    header, nonce, ct = alice.encrypt(b"hello", init)
    assert bob.decrypt(header, nonce, ct, init) == b"hello"


def test_bidirectional_conversation():
    alice, bob, init = make_session()
    header, nonce, ct = alice.encrypt(b"one", init)
    assert bob.decrypt(header, nonce, ct, init) == b"one"
    header, nonce, ct = bob.encrypt(b"reply")
    assert alice.decrypt(header, nonce, ct) == b"reply"
    header, nonce, ct = alice.encrypt(b"two")
    assert bob.decrypt(header, nonce, ct) == b"two"


def test_out_of_order_delivery():
    alice, bob, init = make_session()
    header, nonce, ct = alice.encrypt(b"first", init)
    assert bob.decrypt(header, nonce, ct, init) == b"first"
    messages = [alice.encrypt(f"m{i}".encode()) for i in range(4)]
    for header, nonce, ct in reversed(messages):
        assert bob.decrypt(header, nonce, ct).startswith(b"m")


def test_replay_is_rejected():
    alice, bob, init = make_session()
    header, nonce, ct = alice.encrypt(b"once", init)
    assert bob.decrypt(header, nonce, ct, init) == b"once"
    with pytest.raises(DuplicateMessage):
        bob.decrypt(header, nonce, ct, init)


def test_tampered_ciphertext_is_rejected():
    alice, bob, init = make_session()
    header, nonce, ct = alice.encrypt(b"secret", init)
    broken = bytes([ct[0] ^ 0x01]) + ct[1:]
    with pytest.raises(AEADError):
        bob.decrypt(header, nonce, broken, init)


def test_wrong_ad_context_is_rejected():
    alice, bob, init = make_session()
    header, nonce, ct = alice.encrypt(b"secret", init)
    with pytest.raises(AEADError):
        bob.decrypt(header, nonce, ct, None)


def test_skip_too_far_is_rejected():
    alice, bob, init = make_session()
    header, nonce, ct = alice.encrypt(b"first", init)
    assert bob.decrypt(header, nonce, ct, init) == b"first"
    header, nonce, ct = alice.encrypt(b"far away")
    forged = dict(header)
    forged["n"] = MAX_SKIP + 10
    with pytest.raises(SkippedTooFar):
        bob.decrypt(forged, nonce, ct)


def test_dh_ratchet_advances_after_a_reply():
    alice, bob, init = make_session()
    first_header, nonce, ct = alice.encrypt(b"one", init)
    assert bob.decrypt(first_header, nonce, ct, init) == b"one"
    reply = bob.encrypt(b"reply")
    assert alice.decrypt(*reply) == b"reply"
    later_header, nonce, ct = alice.encrypt(b"two")
    assert later_header["dh"] != first_header["dh"]
    assert bob.decrypt(later_header, nonce, ct) == b"two"


def test_state_serialisation_roundtrip():
    alice, bob, init = make_session()
    header, nonce, ct = alice.encrypt(b"one", init)
    assert bob.decrypt(header, nonce, ct, init) == b"one"
    reply = bob.encrypt(b"reply")
    restored = Ratchet(RatchetState.from_dict(alice.state.to_dict()))
    assert restored.decrypt(*reply) == b"reply"


def test_responder_cannot_send_before_receiving():
    bob, _ = Identity.generate()
    spk_priv, spk_pub = new_x25519()
    ratchet = Ratchet.responder(os.urandom(32), spk_priv, spk_pub)
    with pytest.raises(RatchetError):
        ratchet.encrypt(b"too early")


def test_malformed_header_is_rejected():
    alice, bob, init = make_session()
    with pytest.raises(RatchetError):
        bob.decrypt({"n": 0}, b"0" * 12, b"ciphertext", init)


def test_skipped_keys_are_consumed_once():
    alice, bob, init = make_session()
    header, nonce, ct = alice.encrypt(b"first", init)
    bob.decrypt(header, nonce, ct, init)
    second = alice.encrypt(b"second")
    third = alice.encrypt(b"third")
    assert bob.decrypt(*third) == b"third"
    assert bob.decrypt(*second) == b"second"
    with pytest.raises(DuplicateMessage):
        bob.decrypt(*second)