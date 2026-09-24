import json

import pytest

from noknowledge.crypto.encoding import (
    b32d,
    b32e,
    b64d,
    b64e,
    canonical_json,
    card_decode,
    card_encode,
)


def test_b64_roundtrip():
    for size in (0, 1, 15, 16, 31, 32, 100):
        data = bytes(range(size % 256)) or b"\x00" * size
        assert b64d(b64e(data)) == data


def test_b64_no_padding_characters():
    assert "=" not in b64e(b"hello world")


def test_b32_roundtrip():
    for data in (b"", b"\x00", b"foo", bytes(range(64)), b"\xff" * 33):
        assert b32d(b32e(data)) == data


def test_b32_tolerates_confusables_and_case():
    encoded = b32e(b"noknowledge")
    assert b32d(encoded.lower()) == b"noknowledge"
    assert b32d(encoded.replace("0", "O").replace("1", "I")) == b"noknowledge"


def test_b32_rejects_garbage():
    with pytest.raises(ValueError):
        b32d("!!!!")


def test_canonical_json_is_deterministic():
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert canonical_json({"a": 1}) == canonical_json({"a": 1})


def test_card_roundtrip():
    payload = {
        "v": 1,
        "id": "ABC",
        "relays": ["https://a.example", "https://b.example"],
        "inbox": {"id": "x", "w": "y"},
    }
    card = card_encode(payload)
    assert card.startswith("nk://1/")
    assert card_decode(card) == payload


def test_card_is_compact_via_deflate():
    payload = {"v": 1, "id": "A" * 26, "relays": ["https://relay.example"] * 3}
    raw = len(json.dumps(payload))
    assert len(card_encode(payload)) < raw


def test_card_rejects_foreign_input():
    with pytest.raises(ValueError):
        card_decode("https://example.com")