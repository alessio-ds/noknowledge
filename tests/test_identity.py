import json

import pytest

from noknowledge.crypto.identity import Identity, IdentityError, compute_identity_id

TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def test_deterministic_from_mnemonic():
    first = Identity.from_mnemonic(TEST_MNEMONIC)
    second = Identity.from_mnemonic(TEST_MNEMONIC)
    assert first.identity_id == second.identity_id
    assert first.ed_private_bytes == second.ed_private_bytes
    assert first.x_private_bytes == second.x_private_bytes


def test_generate_returns_24_words_and_matches_identity():
    identity, words = Identity.generate()
    assert len(words.split()) == 24
    assert Identity.from_mnemonic(words).identity_id == identity.identity_id


def test_different_identities_differ():
    first, _ = Identity.generate()
    second, _ = Identity.generate()
    assert first.identity_id != second.identity_id


def test_identity_id_is_26_chars():
    identity, _ = Identity.generate()
    assert len(identity.identity_id) == 26
    assert identity.identity_id == compute_identity_id(
        identity.ed_public_bytes, identity.x_public_bytes
    )


def test_invalid_mnemonic_rejected():
    with pytest.raises(IdentityError):
        Identity.from_mnemonic("this is not a valid mnemonic phrase at all")


def test_passphrase_changes_identity():
    plain = Identity.from_mnemonic(TEST_MNEMONIC)
    guarded = Identity.from_mnemonic(TEST_MNEMONIC, passphrase="secret")
    assert plain.identity_id != guarded.identity_id


def test_sign_and_verify():
    identity, _ = Identity.generate()
    signature = identity.sign(b"payload")
    assert Identity.verify(identity.ed_public_bytes, signature, b"payload")
    assert not Identity.verify(identity.ed_public_bytes, signature, b"other")
    assert not Identity.verify(b"\x00" * 32, signature, b"payload")


def test_vault_plain_roundtrip(tmp_path):
    identity, _ = Identity.generate(label="alice")
    path = tmp_path / "alice.nk"
    identity.save(str(path))
    loaded = Identity.load(str(path))
    assert loaded.identity_id == identity.identity_id
    assert loaded.label == "alice"


def test_vault_encrypted_roundtrip(tmp_path):
    identity, _ = Identity.generate(label="bob")
    path = tmp_path / "bob.nk"
    identity.save(str(path), passphrase="hunter2")
    loaded = Identity.load(str(path), passphrase="hunter2")
    assert loaded.identity_id == identity.identity_id


def test_vault_wrong_passphrase_rejected(tmp_path):
    identity, _ = Identity.generate()
    path = tmp_path / "x.nk"
    identity.save(str(path), passphrase="right")
    with pytest.raises(IdentityError):
        Identity.load(str(path), passphrase="wrong")


def test_vault_encrypted_needs_passphrase(tmp_path):
    identity, _ = Identity.generate()
    path = tmp_path / "x.nk"
    identity.save(str(path), passphrase="right")
    with pytest.raises(IdentityError):
        Identity.load(str(path))


def test_vault_plain_rejects_passphrase(tmp_path):
    identity, _ = Identity.generate()
    path = tmp_path / "x.nk"
    identity.save(str(path))
    with pytest.raises(IdentityError):
        Identity.load(str(path), passphrase="anything")


def test_vault_tamper_detected(tmp_path):
    identity, _ = Identity.generate()
    path = tmp_path / "x.nk"
    identity.save(str(path), passphrase="pw")
    payload = json.loads(path.read_text())
    payload["id"] = "A" * 26
    path.write_text(json.dumps(payload))
    with pytest.raises(IdentityError):
        Identity.load(str(path), passphrase="pw")


def test_vault_plaintext_secret_is_not_the_passphrase(tmp_path):
    identity, _ = Identity.generate()
    path = tmp_path / "x.nk"
    identity.save(str(path))
    assert b"passphrase" not in path.read_bytes()