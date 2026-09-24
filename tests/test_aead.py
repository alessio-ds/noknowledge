import pytest

from noknowledge.crypto.aead import AEADError, decrypt, encrypt


def test_roundtrip():
    key = b"k" * 32
    nonce, ct = encrypt(key, b"hello", b"ad")
    assert decrypt(key, nonce, ct, b"ad") == b"hello"


def test_roundtrip_without_ad():
    key = b"k" * 32
    nonce, ct = encrypt(key, b"")
    assert decrypt(key, nonce, ct) == b""


def test_ciphertext_hides_plaintext():
    key = b"k" * 32
    _, ct = encrypt(key, b"topsecret")
    assert b"topsecret" not in ct


def test_tampered_ciphertext_fails():
    key = b"k" * 32
    nonce, ct = encrypt(key, b"hello")
    broken = bytearray(ct)
    broken[0] ^= 0x01
    with pytest.raises(AEADError):
        decrypt(key, nonce, bytes(broken))


def test_wrong_associated_data_fails():
    key = b"k" * 32
    nonce, ct = encrypt(key, b"hello", b"ad-1")
    with pytest.raises(AEADError):
        decrypt(key, nonce, ct, b"ad-2")


def test_wrong_key_fails():
    nonce, ct = encrypt(b"k" * 32, b"hello")
    with pytest.raises(AEADError):
        decrypt(b"j" * 32, nonce, ct)


def test_bad_sizes_fail():
    with pytest.raises(AEADError):
        encrypt(b"short", b"hello")
    with pytest.raises(AEADError):
        decrypt(b"k" * 32, b"shortnonce", b"ct")


def test_nonces_are_unique():
    key = b"k" * 32
    nonces = {encrypt(key, b"x")[0] for _ in range(200)}
    assert len(nonces) == 200