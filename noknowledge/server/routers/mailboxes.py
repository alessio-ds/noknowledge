"""Mailbox endpoints: capability-addressed store-and-forward."""

from __future__ import annotations

import asyncio
import json
import re
import time

from fastapi import APIRouter, HTTPException, Request

from noknowledge.crypto.encoding import b64d, b64e
from noknowledge.server.deps import (
    authenticate_mailbox,
    client_key,
    get_db,
    get_settings,
)
from noknowledge.server.errors import MailboxNotFound, QuotaExceeded
from noknowledge.server.security import (
    new_mailbox_id,
    new_token,
    token_hash,
    verify_hashcash,
    verify_token,
)

router = APIRouter(tags=["mailboxes"])

MAILBOX_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
TOKEN_SIZE = 32


def _provided_capability(data: dict) -> tuple[str, bytes, bytes]:
    try:
        mailbox_id = str(data["mailbox_id"])
        read_token = b64d(data["read_token"])
        write_token = b64d(data["write_token"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="malformed capability") from exc
    if not MAILBOX_ID_PATTERN.match(mailbox_id):
        raise HTTPException(status_code=400, detail="invalid mailbox id")
    if len(read_token) != TOKEN_SIZE or len(write_token) != TOKEN_SIZE:
        raise HTTPException(status_code=400, detail="invalid token length")
    return mailbox_id, read_token, write_token


@router.post("/mailbox", status_code=201)
async def create_mailbox(request: Request) -> dict:
    """Create a mailbox.

    The client may supply the mailbox id and tokens, which is what allows one
    logical mailbox to be replicated across several relays. Re-registering an
    identical capability is idempotent; conflicting tokens are rejected.
    """
    settings = get_settings(request)
    db = get_db(request)
    if not request.app.state.limiters.create.allow(client_key(request)):
        raise HTTPException(status_code=429, detail="mailbox creation rate exceeded")
    if settings.require_hashcash:
        stamp = request.headers.get("x-nk-hashcash")
        if not verify_hashcash(stamp, settings.hashcash_bits):
            raise HTTPException(status_code=400, detail="valid hashcash required")

    body = await request.body()
    if body:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="malformed request body")
        mailbox_id, read_token, write_token = _provided_capability(data)
        existing = await asyncio.to_thread(db.get_mailbox, mailbox_id)
        if existing is not None:
            if verify_token(read_token, existing["read_token_hash"]) and verify_token(
                write_token, existing["write_token_hash"]
            ):
                return {
                    "mailbox_id": mailbox_id,
                    "read_token": b64e(read_token),
                    "write_token": b64e(write_token),
                }
            raise HTTPException(
                status_code=409, detail="mailbox exists with different tokens"
            )
    else:
        mailbox_id = b64e(new_mailbox_id())
        read_token = new_token()
        write_token = new_token()

    await asyncio.to_thread(
        db.create_mailbox,
        mailbox_id,
        token_hash(read_token),
        token_hash(write_token),
        int(time.time()),
        settings.max_messages_per_mailbox,
        settings.max_bytes_per_mailbox,
    )
    return {
        "mailbox_id": mailbox_id,
        "read_token": b64e(read_token),
        "write_token": b64e(write_token),
    }


@router.get("/mailbox/{mailbox_id}")
def get_mailbox(
    mailbox_id: str,
    request: Request,
    after_seq: int = 0,
    wait: int = 0,
) -> dict:
    settings = get_settings(request)
    db = get_db(request)
    authenticate_mailbox(request, mailbox_id, "read")

    wait = max(0, min(int(wait), settings.max_wait_seconds))
    deadline = time.monotonic() + wait
    rows: list = []
    while True:
        rows = db.get_messages(
            mailbox_id, after_seq, settings.max_messages_per_fetch
        )
        if rows or time.monotonic() >= deadline:
            break
        time.sleep(0.2)

    next_seq = int(rows[-1]["seq"]) if rows else int(after_seq)
    return {
        "messages": [
            {"seq": int(row["seq"]), "blob": b64e(row["ciphertext"])} for row in rows
        ],
        "next_seq": next_seq,
    }


@router.post("/mailbox/{mailbox_id}/messages", status_code=201)
async def put_message(mailbox_id: str, request: Request) -> dict:
    settings = get_settings(request)
    db = get_db(request)
    authenticate_mailbox(request, mailbox_id, "write")
    if not request.app.state.limiters.write.allow(client_key(request)):
        raise HTTPException(status_code=429, detail="write rate exceeded")

    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="empty message")
    if len(body) > settings.max_blob_bytes:
        raise HTTPException(status_code=413, detail="message too large")

    try:
        seq = await asyncio.to_thread(db.put_message, mailbox_id, body, int(time.time()))
    except MailboxNotFound:
        raise HTTPException(status_code=404, detail="mailbox not found")
    except QuotaExceeded:
        raise HTTPException(status_code=429, detail="mailbox quota exceeded")
    return {"seq": seq}


@router.post("/mailbox/{mailbox_id}/ack")
async def ack_messages(mailbox_id: str, request: Request) -> dict:
    db = get_db(request)
    authenticate_mailbox(request, mailbox_id, "read")
    try:
        payload = await request.json()
        upto_seq = int(payload["upto_seq"])
    except Exception:
        raise HTTPException(status_code=400, detail="expected {upto_seq: int}")
    deleted = await asyncio.to_thread(db.ack_messages, mailbox_id, upto_seq)
    return {"deleted": deleted}


@router.delete("/mailbox/{mailbox_id}")
def delete_mailbox(mailbox_id: str, request: Request) -> dict:
    db = get_db(request)
    authenticate_mailbox(request, mailbox_id, "read")
    messages, blobs = db.delete_mailbox(mailbox_id)
    return {"deleted_messages": messages, "deleted_blobs": blobs}