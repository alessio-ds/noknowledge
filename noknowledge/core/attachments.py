"""Chunked attachment encryption.

A file is encrypted with a fresh key and split into independently nonced chunks.
Chunk ids come from the relay after upload. The manifest — key, nonces, hashes,
filename — travels inside the ratcheted message, so the relay never sees it.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from noknowledge.crypto.aead import decrypt, encrypt
from noknowledge.crypto.encoding import b64d, b64e

CHUNK_SIZE = 256 * 1024
KEY_SIZE = 32
MAX_FILE_SIZE = 25 * 1024 * 1024


class AttachmentError(Exception):
    """Raised when an attachment is too large or fails verification."""


@dataclass
class EncryptedChunk:
    nonce: bytes
    ciphertext: bytes


@dataclass
class Attachment:
    key: bytes
    chunks: list[EncryptedChunk]
    size: int
    sha256: str


def encrypt_attachment(data: bytes) -> Attachment:
    if len(data) > MAX_FILE_SIZE:
        raise AttachmentError(
            f"file is {len(data)} bytes; maximum is {MAX_FILE_SIZE}"
        )
    key = os.urandom(KEY_SIZE)
    chunks: list[EncryptedChunk] = []
    for offset in range(0, max(len(data), 1), CHUNK_SIZE):
        piece = data[offset : offset + CHUNK_SIZE]
        nonce, ciphertext = encrypt(key, piece)
        chunks.append(EncryptedChunk(nonce=nonce, ciphertext=ciphertext))
    return Attachment(
        key=key,
        chunks=chunks,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def decrypt_attachment(
    key: bytes, nonces: list[bytes], ciphertexts: list[bytes], expected_sha256: str
) -> bytes:
    if len(nonces) != len(ciphertexts):
        raise AttachmentError("chunk count mismatch")
    pieces = [
        decrypt(key, nonce, ciphertext)
        for nonce, ciphertext in zip(nonces, ciphertexts)
    ]
    data = b"".join(pieces)
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise AttachmentError("attachment hash mismatch")
    return data


def manifest_dict(attachment: Attachment, chunk_ids: list[str]) -> dict:
    if len(chunk_ids) != len(attachment.chunks):
        raise AttachmentError("chunk id count mismatch")
    return {
        "key": b64e(attachment.key),
        "size": attachment.size,
        "sha256": attachment.sha256,
        "chunks": [
            {"id": chunk_id, "nonce": b64e(chunk.nonce)}
            for chunk_id, chunk in zip(chunk_ids, attachment.chunks)
        ],
    }


def decode_manifest(manifest: dict) -> tuple[bytes, list[str], list[bytes], str]:
    try:
        key = b64d(manifest["key"])
        size = int(manifest["size"])
        sha = str(manifest["sha256"])
        chunk_ids = [str(c["id"]) for c in manifest["chunks"]]
        nonces = [b64d(c["nonce"]) for c in manifest["chunks"]]
    except (KeyError, TypeError, ValueError) as exc:
        raise AttachmentError("malformed attachment manifest") from exc
    if len(key) != KEY_SIZE:
        raise AttachmentError("bad attachment key")
    if size > MAX_FILE_SIZE:
        raise AttachmentError("attachment exceeds maximum size")
    return key, chunk_ids, nonces, sha