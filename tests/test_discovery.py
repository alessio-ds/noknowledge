"""Relay discovery: the endpoint, the client algorithm, and its guard rails."""

import sqlite3

from noknowledge.core.card import ContactCard
from noknowledge.wire.discovery import discover_relays, is_discoverable
from noknowledge.wire.transport import Transport
from tests.conftest import make_client
from tests.relay_server import RelayProcess


class _Response:
    def __init__(self, status_code: int, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class StubTransport:
    """Maps exact URLs to responses; anything else is unreachable."""

    def __init__(self, routes):
        self.routes = routes
        self.requested: list[str] = []

    def request(self, method, url, timeout=None, **kwargs):
        self.requested.append(url)
        if url in self.routes:
            return self.routes[url]
        raise RuntimeError(f"unreachable: {url}")


# -- guard rails ----------------------------------------------------------


def test_internal_candidates_are_not_discoverable(monkeypatch):
    monkeypatch.delenv("NK_ALLOW_PRIVATE_RELAYS", raising=False)
    for url in (
        "http://127.0.0.1:8000",
        "http://localhost:9",
        "http://[::1]:9",
        "http://10.0.0.5",
        "http://192.168.1.10",
        "http://169.254.169.254",  # cloud metadata
        "http://printer.local",
    ):
        assert not is_discoverable(url), url


def test_internal_candidates_allowed_when_opted_in(monkeypatch):
    monkeypatch.setenv("NK_ALLOW_PRIVATE_RELAYS", "1")
    assert is_discoverable("http://127.0.0.1:8000")
    assert is_discoverable("http://192.168.1.10:9999")


def test_public_candidates_are_discoverable(monkeypatch):
    monkeypatch.delenv("NK_ALLOW_PRIVATE_RELAYS", raising=False)
    for url in ("https://relay.example", "http://relay.example:9999"):
        assert is_discoverable(url), url


def test_discover_refuses_to_probe_internal_addresses(monkeypatch):
    monkeypatch.delenv("NK_ALLOW_PRIVATE_RELAYS", raising=False)
    transport = StubTransport(
        {
            "https://seed.example/api/relays": _Response(
                200,
                {
                    "relays": [
                        "http://169.254.169.254",
                        "http://10.0.0.5",
                        "http://localhost:8000",
                        "https://good.example",
                    ]
                },
            ),
            "https://good.example/api/health": _Response(200, {"status": "ok"}),
        }
    )
    result = discover_relays(["https://seed.example"], transport, timeout=1)
    assert result == ["https://seed.example", "https://good.example"]
    assert not any("169.254" in url for url in transport.requested)
    assert not any("10.0.0.5" in url for url in transport.requested)


# -- algorithm ------------------------------------------------------------


def test_discover_adds_only_live_relays():
    transport = StubTransport(
        {
            "https://seed.example/api/relays": _Response(
                200, {"relays": ["https://alive.example", "https://dead.example"]}
            ),
            "https://alive.example/api/health": _Response(200, {"status": "ok"}),
            "https://dead.example/api/health": _Response(503, {}),
        }
    )
    assert discover_relays(["https://seed.example"], transport, timeout=1) == [
        "https://seed.example",
        "https://alive.example",
    ]


def test_discover_never_removes_configured_relays():
    transport = StubTransport({})  # nothing reachable at all
    assert discover_relays(["https://mine.example"], transport, timeout=1) == [
        "https://mine.example"
    ]


def test_discover_deduplicates_by_host():
    transport = StubTransport(
        {
            "https://seed.example/api/relays": _Response(
                200,
                {
                    "relays": [
                        "https://dup.example",
                        "https://dup.example/",
                        "https://dup.example:443",
                    ]
                },
            ),
            "https://dup.example/api/health": _Response(200, {"status": "ok"}),
        }
    )
    assert discover_relays(["https://seed.example"], transport, timeout=1) == [
        "https://seed.example",
        "https://dup.example",
    ]


def test_discover_respects_max_relays():
    listed = [f"https://r{index}.example" for index in range(20)]
    routes = {"https://seed.example/api/relays": _Response(200, {"relays": listed})}
    for url in listed:
        routes[f"{url}/api/health"] = _Response(200, {"status": "ok"})
    result = discover_relays(
        ["https://seed.example"], StubTransport(routes), max_relays=3, timeout=1
    )
    assert result == ["https://seed.example", "https://r0.example", "https://r1.example"]


def test_discover_survives_a_broken_advertisement():
    transport = StubTransport(
        {
            "https://seed.example/api/relays": _Response(200, {"relays": "not-a-list"}),
            "https://bad.example/api/relays": _Response(200, None),
        }
    )
    assert discover_relays(
        ["https://seed.example", "https://bad.example"], transport, timeout=1
    ) == ["https://seed.example", "https://bad.example"]


# -- against real relays --------------------------------------------------


def test_relay_advertises_its_peers(tmp_path):
    extra = RelayProcess(tmp_path / "extra").start()
    seed = RelayProcess(tmp_path / "seed", known_relays=[extra.url]).start()
    try:
        transport = Transport(retries=1, timeout=5, backoff=0.1)
        try:
            result = discover_relays([seed.url], transport, timeout=5)
            assert result == [seed.url, extra.url]
        finally:
            transport.close()
    finally:
        seed.stop()
        extra.stop()


def test_refresh_relays_adopts_peer_and_updates_card(tmp_path):
    extra = RelayProcess(tmp_path / "extra").start()
    seed = RelayProcess(tmp_path / "seed", known_relays=[extra.url]).start()
    try:
        client = make_client(tmp_path, "alice", [seed.url])
        try:
            client.provision()
            assert client.relay_urls() == [seed.url]

            assert client.refresh_relays(timeout=5) == [seed.url, extra.url]

            # The card now points contacts at the wider set...
            card = ContactCard.from_string(client.card_string())
            assert extra.url in card.relays

            # ...and our mailbox really was created on the new relay.
            connection = sqlite3.connect(extra.db_path)
            try:
                found = connection.execute(
                    "SELECT COUNT(*) FROM mailboxes WHERE id = ?",
                    (client._own_inbox.mailbox_id,),
                ).fetchone()[0]
            finally:
                connection.close()
            assert found == 1
        finally:
            client.close()
    finally:
        seed.stop()
        extra.stop()