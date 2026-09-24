import os

import pytest

from noknowledge.crypto import x3dh
from noknowledge.crypto.identity import Identity
from noknowledge.crypto.prekeys import make_bundle
from tests.helpers import new_x25519


def _bundle_and_initiator(with_opk=True):
    bob, _ = Identity.generate()
    spk_priv, spk_pub = new_x25519()
    opk_priv, opk_pub = new_x25519()
    opks = [(11, opk_pub)] if with_opk else []
    bundle = make_bundle(bob, os.urandom(16), 4, spk_pub, opks)
    initiation = x3dh.initiate(bundle, bob.ed_public_bytes, bob.x_public_bytes)
    return bob, spk_priv, opk_priv if with_opk else None, bundle, initiation


def test_both_sides_derive_the_same_key_with_opk():
    bob, spk_priv, opk_priv, _, initiation = _bundle_and_initiator(with_opk=True)
    responder_key = x3dh.respond(
        bob.x_private_bytes, spk_priv, opk_priv, initiation.ek_public
    )
    assert initiation.sk == responder_key
    assert initiation.opk_id == 11


def test_both_sides_derive_the_same_key_without_opk():
    bob, spk_priv, opk_priv, _, initiation = _bundle_and_initiator(with_opk=False)
    responder_key = x3dh.respond(
        bob.x_private_bytes, spk_priv, opk_priv, initiation.ek_public
    )
    assert initiation.sk == responder_key
    assert initiation.opk_id is None


def test_wrong_signed_prekey_does_not_agree():
    bob, _, opk_priv, _, initiation = _bundle_and_initiator()
    other_spk_priv, _ = new_x25519()
    assert x3dh.respond(bob.x_private_bytes, other_spk_priv, opk_priv, initiation.ek_public) != initiation.sk


def test_bundle_substitution_is_rejected():
    bob, _, _, _, _ = _bundle_and_initiator()
    eve, _ = Identity.generate()
    _, eve_spk = new_x25519()
    forged = make_bundle(eve, os.urandom(16), 1, eve_spk)
    with pytest.raises(x3dh.HandshakeError):
        x3dh.initiate(forged, bob.ed_public_bytes, bob.x_public_bytes)


def test_bundle_identity_mismatch_is_rejected():
    bob, _, _, bundle, _ = _bundle_and_initiator()
    wrong_idh = os.urandom(32)
    with pytest.raises(x3dh.HandshakeError):
        x3dh.initiate(bundle, bob.ed_public_bytes, wrong_idh)


def test_sessions_are_unique_per_run():
    _, _, _, _, first = _bundle_and_initiator()
    _, _, _, _, second = _bundle_and_initiator()
    assert first.sk != second.sk


def test_auth_roundtrip():
    alice, _ = Identity.generate()
    bob, spk_priv, opk_priv, _, initiation = _bundle_and_initiator()
    responder_key = x3dh.respond(
        bob.x_private_bytes, spk_priv, opk_priv, initiation.ek_public
    )
    sid = os.urandom(16)
    init_dict = initiation.init_dict()
    auth = x3dh.build_auth(alice, sid, init_dict, initiation.sk)
    assert x3dh.verify_auth(auth, sid, init_dict, responder_key)


def test_auth_rejects_wrong_session_key():
    alice, _ = Identity.generate()
    bob, spk_priv, opk_priv, _, initiation = _bundle_and_initiator()
    sid = os.urandom(16)
    init_dict = initiation.init_dict()
    auth = x3dh.build_auth(alice, sid, init_dict, initiation.sk)
    assert not x3dh.verify_auth(auth, sid, init_dict, os.urandom(32))


def test_auth_rejects_wrong_sid_or_init():
    alice, _ = Identity.generate()
    _, _, _, _, initiation = _bundle_and_initiator()
    sid = os.urandom(16)
    init_dict = initiation.init_dict()
    auth = x3dh.build_auth(alice, sid, init_dict, initiation.sk)
    assert not x3dh.verify_auth(auth, os.urandom(16), init_dict, initiation.sk)
    assert not x3dh.verify_auth(auth, sid, {"ek": "zz", "spk_id": 1, "opk_id": None}, initiation.sk)


def test_auth_rejects_tampered_signature():
    alice, _ = Identity.generate()
    _, _, _, _, initiation = _bundle_and_initiator()
    sid = os.urandom(16)
    init_dict = initiation.init_dict()
    auth = x3dh.build_auth(alice, sid, init_dict, initiation.sk)
    auth["sig"] = auth["sig"][:-2] + ("AA" if auth["sig"][-2:] != "AA" else "BB")
    assert not x3dh.verify_auth(auth, sid, init_dict, initiation.sk)


def test_auth_rejects_identity_id_mismatch():
    alice, _ = Identity.generate()
    _, _, _, _, initiation = _bundle_and_initiator()
    sid = os.urandom(16)
    init_dict = initiation.init_dict()
    auth = x3dh.build_auth(alice, sid, init_dict, initiation.sk)
    auth["id"] = "A" * 26
    assert not x3dh.verify_auth(auth, sid, init_dict, initiation.sk)