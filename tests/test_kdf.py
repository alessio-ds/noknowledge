from noknowledge.crypto.kdf import hkdf, kdf_ck, kdf_rk, sk_commitment


def test_hkdf_rfc5869_case_1():
    # RFC 5869, Appendix A.1 (SHA-256)
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    assert hkdf(ikm, salt=salt, info=info, length=42) == expected


def test_kdf_rk_is_deterministic_and_split():
    rk = b"\x01" * 32
    dh = b"\x02" * 32
    first_root, first_chain = kdf_rk(rk, dh)
    second_root, second_chain = kdf_rk(rk, dh)
    assert (first_root, first_chain) == (second_root, second_chain)
    assert len(first_root) == 32 and len(first_chain) == 32
    assert first_root != first_chain


def test_kdf_rk_changes_with_inputs():
    rk = b"\x01" * 32
    assert kdf_rk(rk, b"\x02" * 32) != kdf_rk(rk, b"\x03" * 32)
    assert kdf_rk(rk, b"\x02" * 32) != kdf_rk(b"\x09" * 32, b"\x02" * 32)


def test_kdf_ck_is_deterministic_and_advances():
    ck = b"\x07" * 32
    mk1, ck1 = kdf_ck(ck)
    mk2, ck2 = kdf_ck(ck)
    assert (mk1, ck1) == (mk2, ck2)
    assert mk1 != ck1
    assert ck1 != ck
    mk3, _ = kdf_ck(ck1)
    assert mk3 != mk1


def test_sk_commitment_binds_key():
    assert sk_commitment(b"a" * 32) == sk_commitment(b"a" * 32)
    assert sk_commitment(b"a" * 32) != sk_commitment(b"b" * 32)