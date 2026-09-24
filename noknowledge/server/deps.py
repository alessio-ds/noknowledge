"""Shared request helpers for relay routers."""

from __future__ import annotations

import sqlite3

from fastapi import HTTPException, Request

from noknowledge.crypto.encoding import b64d
from noknowledge.server.config import Settings
from noknowledge.server.db import Database
from noknowledge.server.security import verify_token

MAILBOX_HEADER = "x-nk-mailbox"


def get_db(request: Request) -> Database:
    return request.app.state.db


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _token_from_header(request: Request, header: str) -> bytes | None:
    raw = request.headers.get(header)
    if not raw:
        return None
    try:
        return b64d(raw)
    except Exception:
        return None


def authenticate_mailbox(
    request: Request, mailbox_id: str, capability: str
) -> sqlite3.Row:
    """Validate a read or write capability for a mailbox.

    Raises 404 when the mailbox does not exist (so a write to a mailbox that
    was never created stores nothing) and 401 when the token is wrong.
    """
    if capability not in ("read", "write"):
        raise ValueError(f"unknown capability: {capability}")
    header = "x-nk-read" if capability == "read" else "x-nk-write"
    token = _token_from_header(request, header)
    if token is None:
        raise HTTPException(status_code=401, detail="missing capability token")
    row = get_db(request).get_mailbox(mailbox_id)
    if row is None:
        raise HTTPException(status_code=404, detail="mailbox not found")
    stored = row["read_token_hash"] if capability == "read" else row["write_token_hash"]
    if not verify_token(token, stored):
        raise HTTPException(status_code=401, detail="invalid capability token")
    return row


def mailbox_id_from_header(request: Request) -> str:
    mailbox_id = request.headers.get(MAILBOX_HEADER)
    if not mailbox_id:
        raise HTTPException(status_code=400, detail="missing X-NK-Mailbox header")
    return mailbox_id