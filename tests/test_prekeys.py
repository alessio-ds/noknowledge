import os

import pytest

from noknowledge.crypto.identity import Identity
from noknowledge.crypto.prekeys import (
    PrekeyBundle,
    PrekeyError,
    make_bundle,
    verify_bundle,
)
from tests.helpers import new_x25519


def test_bundle_signs_and_verifies():
    identity, _ = Identity.generate()
    spk_priv, spk_pub = new_x25519()
    opk_priv, opk_pub = new_x25519()
    bundle = make_bundle(identity, os.urandom(16), 3, spk_pub, [(9, opk_pub)])
    verify_bundle(bundle, identity.ed_public_bytes)
    assert bundle.spk_id == 3
    assert bundle.opks == [(9, opk_pub)]


def test_bundle_rejects_wrong_identity():
    identity, _ = Identity.generate()
    other, _ = Identity.generate()
    _, spk_pub = new_x25519()
    bundle = make_bundle(identity, os.urandom(16), 1, spk_pub)
    with pytest.raises(PrekeyError):
        verify_bundle(bundle, other.ed_public_bytes)


def test_bundle_rejects_tampered_spk():
    identity, _ = Identity.generate()
    _, spk_pub = new_x25519()
    bundle = make_bundle(identity, os.urandom(16), 1, spk_pub)
    bundle.spk = bytes([bundle.spk[0] ^ 1]) + bundle.spk[1:]
    with pytest.raises(PrekeyError):
        verify_bundle(bundle, identity.ed_public_bytes)


def test_bundle_rejects_tampered_spk_id():
    identity, _ = Identity.generate()
    _, spk_pub = new_x25519()
    bundle = make_bundle(identity, os.urandom(16), 1, spk_pub)
    bundle.spk_id = 2
    with pytest.raises(PrekeyError):
        verify_bundle(bundle, identity.ed_public_bytes)


def test_bundle_serialisation_roundtrip():
    identity, _ = Identity.generate()
    _, spk_pub = new_x25519()
    _, opk_pub = new_x25519()
    bundle = make_bundle(identity, os.urandom(16), 5, spk_pub, [(1, opk_pub)])
    published = bundle.to_bytes()
    restored = PrekeyBundle.from_bytes(
        published, identity.ed_public_bytes, identity.x_public_bytes
    )
    assert restored.to_bytes() == published
    verify_bundle(restored, identity.ed_public_bytes)


def test_published_bundle_hides_identity_keys():
    identity, _ = Identity.generate()
    _, spk_pub = new_x25519()
    bundle = make_bundle(identity, os.urandom(16), 1, spk_pub)
    published = bundle.to_bytes()
    assert identity.ed_public_bytes not in published
    assert identity.x_public_bytes not in published
    assert identity.identity_id.encode() not in published


def test_bundle_rejects_bad_bundle_id_length():
    identity, _ = Identity.generate()
    _, spk_pub = new_x25519()
    with pytest.raises(PrekeyError):
        make_bundle(identity, b"short", 1, spk_pub)


def test_bundle_rejects_unknown_version():
    with pytest.raises(PrekeyError):
        PrekeyBundle.from_dict({"v": 99})