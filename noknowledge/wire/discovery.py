"""Relay discovery.

A relay advertises the other relays it knows about at ``GET /api/relays``. A
client unions those with its own list, keeps the ones that answer a health
check, and adds them. Relays are never removed by discovery, so a
user-configured relay always survives.

Discovery is deliberately conservative:

* candidates are de-duplicated by host, not by URL string;
* candidates pointing at loopback, private, link-local or reserved addresses
  are refused, so a hostile relay cannot use the client to probe its network;
* the number of candidates examined and the final relay count are capped.
"""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse

from noknowledge.wire.backends.multi_relay import normalize_relay_urls

RELAYS_PATH = "/api/relays"
HEALTH_PATH = "/api/health"

#: Set ``NK_ALLOW_PRIVATE_RELAYS=1`` to also discover relays on loopback, LAN or
#: other internal addresses. Off by default so a hostile relay cannot use the
#: client to probe its network; turn it on when you deliberately run relays
#: locally or on your own network.
ALLOW_PRIVATE_ENV = "NK_ALLOW_PRIVATE_RELAYS"

MAX_RELAYS = 8
MAX_CANDIDATES = 50
DEFAULT_TIMEOUT = 6.0


def _allow_private() -> bool:
    return bool(os.environ.get(ALLOW_PRIVATE_ENV))


def _host_is_internal(host: str) -> bool:
    host = host.strip("[]").lower()
    if not host or host == "localhost" or host.endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False  # an ordinary DNS name
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def is_discoverable(url: str) -> bool:
    """Whether an advertised URL is safe for us to probe automatically."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    if not parsed.hostname:
        return False
    try:
        port = parsed.port
    except ValueError:
        return False
    if port is not None and not 1 <= port <= 65535:
        return False
    if _host_is_internal(parsed.hostname) and not _allow_private():
        return False
    return True


def _host_key(url: str) -> tuple[str, str, int]:
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return (parsed.scheme, (parsed.hostname or "").lower(), port)


def fetch_known_relays(
    relay_url: str, transport, timeout: float = DEFAULT_TIMEOUT, limit: int = MAX_CANDIDATES
) -> list[str]:
    """Ask one relay which relays it knows about. Best effort."""
    try:
        response = transport.request("GET", f"{relay_url}{RELAYS_PATH}", timeout=timeout)
    except Exception:
        return []
    if response.status_code != 200:
        return []
    try:
        payload = response.json()
    except ValueError:
        return []
    advertised = payload.get("relays")
    if not isinstance(advertised, list):
        return []
    return [item for item in advertised[:limit] if isinstance(item, str)]


def probe_relay(url: str, transport, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """Whether a relay answers its health check."""
    try:
        response = transport.request("GET", f"{url}{HEALTH_PATH}", timeout=timeout)
    except Exception:
        return False
    if response.status_code != 200:
        return False
    try:
        return response.json().get("status") == "ok"
    except ValueError:
        return False


def discover_relays(
    current: list[str],
    transport,
    max_relays: int = MAX_RELAYS,
    timeout: float = DEFAULT_TIMEOUT,
    probe: bool = True,
    max_candidates: int = MAX_CANDIDATES,
) -> list[str]:
    """Return ``current`` plus any newly discovered relays that are alive.

    Never removes anything, never exceeds ``max_relays``, and keeps the caller's
    ordering so explicitly configured relays stay first.
    """
    known = normalize_relay_urls(list(current))
    seen = {_host_key(url) for url in known}
    candidates: list[str] = []

    for relay in known:
        for advertised in fetch_known_relays(relay, transport, timeout, max_candidates):
            normalized = normalize_relay_urls([advertised])
            if not normalized:
                continue
            candidate = normalized[0]
            if not is_discoverable(candidate):
                continue
            key = _host_key(candidate)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(candidate)
            if len(candidates) >= max_candidates:
                break
        if len(candidates) >= max_candidates:
            break

    result = list(known)
    for candidate in candidates:
        if len(result) >= max_relays:
            break
        if not probe or probe_relay(candidate, transport, timeout):
            result.append(candidate)
    return normalize_relay_urls(result)