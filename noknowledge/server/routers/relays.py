"""Relay discovery endpoint.

``GET /api/relays`` advertises the other relays this instance knows about. It is
unauthenticated on purpose, exactly like ``/api/health``: it exposes no user
data, only the topology an operator chose to publish.

The list comes from ``NK_ADVERTISE_URL`` (this relay's own public URL, so it can
be discovered by others), ``NK_KNOWN_RELAYS`` (comma separated peers) and an
optional ``relays.json`` in the data directory:

    {"relays": ["https://relay-a.example", "https://relay-b.example"]}
"""

from __future__ import annotations

import json
import os

from fastapi import APIRouter, Request

from noknowledge.server.deps import get_settings

router = APIRouter(tags=["discovery"])


def _normalize(urls: list[str]) -> list[str]:
    seen: list[str] = []
    for url in urls:
        cleaned = str(url).strip().rstrip("/")
        if not cleaned:
            continue
        if not cleaned.startswith(("http://", "https://")):
            cleaned = "https://" + cleaned
        if cleaned not in seen:
            seen.append(cleaned)
    return seen


def _file_relays(settings) -> list[str]:
    path = os.path.join(settings.data_dir, "relays.json")
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, dict):
        data = data.get("relays", [])
    if not isinstance(data, list):
        return []
    return [str(item) for item in data]


@router.get("/relays")
def list_relays(request: Request) -> dict:
    settings = get_settings(request)
    own = [settings.advertise_url] if settings.advertise_url else []
    relays = _normalize(own + list(settings.known_relays) + _file_relays(settings))
    return {"relays": relays, "advertise": settings.advertise_url or None}