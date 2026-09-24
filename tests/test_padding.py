import pytest

from noknowledge.crypto.padding import (
    BUCKET,
    PaddingError,
    pad_envelope,
    padded_size,
    unpad_envelope,
)


def test_roundtrip_strips_padding():
    envelope = {"v": 1, "type": "text", "body": {"text": "hi"}}
    data = pad_envelope(envelope)
    assert unpad_envelope(data) == envelope


def test_padded_length_is_bucket_multiple():
    envelope = {"v": 1, "type": "text", "body": {"text": "x" * 500}}
    data = pad_envelope(envelope)
    assert len(data) % BUCKET == 0
    assert len(data) > len(envelope["body"]["text"])


def test_different_lengths_share_a_bucket():
    short = pad_envelope({"v": 1, "type": "text", "body": {"text": "a"}})
    slightly_longer = pad_envelope({"v": 1, "type": "text", "body": {"text": "a" * 100}})
    assert len(short) == len(slightly_longer)


def test_padding_is_random():
    envelope = {"v": 1, "type": "text", "body": {"text": "hi"}}
    assert pad_envelope(envelope) != pad_envelope(envelope)


def test_over_limit_raises():
    with pytest.raises(PaddingError):
        pad_envelope({"v": 1, "body": {"text": "x" * 5000}}, max_size=2048)


def test_padded_size_helper():
    assert padded_size(1) == BUCKET
    assert padded_size(BUCKET) == 2 * BUCKET
    assert padded_size(0) == BUCKET


def test_unpad_rejects_non_object():
    with pytest.raises(Exception):
        unpad_envelope(b"[1,2,3]")