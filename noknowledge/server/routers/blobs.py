"""Encrypted attachment chunks.

Blobs are bound to the mailbox that uploaded them: both upload and download
require a capability for that same mailbox. This is what stops an anonymous
client from filling a relay's disk.
"""

from __future__ import annotations

import asyncio
import time

from fastapi import APIRouter, HTTPException, Request, Response

from noknowledge.crypto.encoding import b64d
from noknowledge.server.deps import (
    authenticate_mailbox,
    client_key,
    get_db,
    get_settings,
    mailbox_id_from_header,
)
from noknowledge.server.errors import (
    BlobNotFound,
    MailboxNotFound,
    QuotaExceeded,
)
from noknowledge.server.security import new_chunk_id

router = APIRouter(tags=["blobs"])

CHUNK_ID_SIZE = 16


def _chunk_id(request: Request) -> str:
    """Accept a client-chosen chunk id (needed for relay replication)."""
    provided = request.headers.get("x-nk-chunk")
    if not provided:
        return new_chunk_id()
    try:
        raw = b64d(provided)
    except Exception:
        raise HTTPException(status_code=400, detail="malformed chunk id")
    if len(raw) != CHUNK_ID_SIZE:
        raise HTTPException(status_code=400, detail="invalid chunk id length")
    return provided


@router.post("/blob", status_code=201)
async def upload_blob(request: Request) -> dict:
    settings = get_settings(request)
    db = get_db(request)
    mailbox_id = mailbox_id_from_header(request)
    authenticate_mailbox(request, mailbox_id, "write")
    if not request.app.state.limiters.write.allow(client_key(request)):
        raise HTTPException(status_code=429, detail="upload rate exceeded")

    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="empty chunk")
    if len(body) > settings.max_chunk_bytes:
        raise HTTPException(status_code=413, detail="chunk too large")

    chunk_id = _chunk_id(request)
    try:
        existing = await asyncio.to_thread(db.get_blob, chunk_id)
        if existing["mailbox_id"] == mailbox_id:
            return {"chunk_id": chunk_id}  # idempotent re-upload
        raise HTTPException(status_code=409, detail="chunk id already in use")
    except BlobNotFound:
        pass

    try:
        await asyncio.to_thread(
            db.put_blob, chunk_id, mailbox_id, body, int(time.time())
        )
    except MailboxNotFound:
        raise HTTPException(status_code=404, detail="mailbox not found")
    except QuotaExceeded:
        raise HTTPException(status_code=429, detail="mailbox quota exceeded")
    return {"chunk_id": chunk_id}


@router.get("/blob/{chunk_id}")
def download_blob(chunk_id: str, request: Request) -> Response:
    db = get_db(request)
    mailbox_id = mailbox_id_from_header(request)
    authenticate_mailbox(request, mailbox_id, "read")
    try:
        row = db.get_blob(chunk_id)
    except BlobNotFound:
        raise HTTPException(status_code=404, detail="blob not found")
    if row["mailbox_id"] != mailbox_id:
        raise HTTPException(status_code=404, detail="blob not found")
    return Response(content=bytes(row["ciphertext"]), media_type="application/octet-stream")