"""HTTP transport with retries and fail-closed proxy support.

When ``fail_closed`` is set, any request to a non-loopback host without a
configured proxy is refused rather than silently sent in the clear. This is what
makes a Tor/proxy-only mode actually meaningful.
"""

from __future__ import annotations

import time
from urllib.parse import urlparse

import requests

from noknowledge.wire.errors import TransportError

_LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]"}


class Transport:
    def __init__(
        self,
        timeout: float = 30.0,
        retries: int = 3,
        backoff: float = 0.5,
        proxy_url: str | None = None,
        fail_closed: bool = False,
        session: requests.Session | None = None,
    ) -> None:
        self.timeout = timeout
        self.retries = max(1, retries)
        self.backoff = backoff
        self.proxy_url = proxy_url
        self.fail_closed = fail_closed
        self.session = session or requests.Session()

    def is_local(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        return host in _LOOPBACK or host.endswith(".local")

    def proxies_for(self, url: str) -> dict:
        if self.is_local(url):
            return {}
        if not self.proxy_url:
            if self.fail_closed:
                host = urlparse(url).hostname
                raise TransportError(
                    f"refusing direct connection to {host!r}: proxy required "
                    "(fail-closed mode)"
                )
            return {}
        return {"http": self.proxy_url, "https": self.proxy_url}

    def request(
        self, method: str, url: str, timeout: float | None = None, **kwargs
    ) -> requests.Response:
        proxies = self.proxies_for(url)
        last_error: Exception | None = None
        for attempt in range(self.retries):
            try:
                return self.session.request(
                    method,
                    url,
                    timeout=self.timeout if timeout is None else timeout,
                    proxies=proxies,
                    **kwargs,
                )
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_error = exc
                if attempt == self.retries - 1:
                    break
                time.sleep(self.backoff * (2**attempt))
        raise TransportError(f"{method} {url} failed: {last_error}") from last_error

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:
            pass