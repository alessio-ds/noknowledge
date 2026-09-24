"""Prekey noticeboard.

Bundles contain only a random ``bundle_id``, a signed prekey and one-time
prekeys. Identity keys are never published: the relay cannot learn who owns a
bundle, and the client verifies the signed prekey against the contact card.
"""

from __future__ import annotations

import asyncio
import time

from fastapi import APIRouter, HTTPException, Request

from noknowledge.crypto.prekeys import MAX_OPKS
from noknowledge.server.deps import client_key, get_db, get_settings
from noknowledge.server.errors import BundleNotFound

router = APIRouter(tags=["prekeys"])

MAX_BUNDLE_BYTES = 16 * 1024


@router.post("/prekeys", status_code=201)
async def publish_bundle(request: Request) -> dict:
    settings = get_settings(request)
    db = get_db(request)
    if not request.app.state.limiters.bundle.allow(client_key(request)):
        raise HTTPException(status_code=429, detail="prekey publish rate exceeded")

    body = await request.body()
    if not body or len(body) > MAX_BUNDLE_BYTES:
        raise HTTPException(status_code=413, detail="invalid bundle size")
    try:
        payload = await request.json()
        bundle_id = str(payload["bundle_id"])
        opks = list(payload.get("opks") or [])
    except Exception:
        raise HTTPException(status_code=400, detail="malformed bundle")
    if len(opks) > MAX_OPKS:
        raise HTTPException(status_code=400, detail="too many one-time prekeys")

    stored = {key: value for key, value in payload.items() if key != "opks"}
    stored["opks"] = []
    await asyncio.to_thread(
        db.publish_bundle, bundle_id, stored, opks, int(time.time())
    )
    return {"bundle_id": bundle_id}


@router.get("/prekeys/{bundle_id}")
def fetch_bundle(bundle_id: str, request: Request) -> dict:
    db = get_db(request)
    try:
        return db.fetch_bundle(bundle_id)
    except BundleNotFound:
        raise HTTPException(status_code=404, detail="bundle not found")