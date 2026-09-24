"""FastAPI application factory for a noknowledge relay."""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI

from noknowledge.server.config import Settings
from noknowledge.server.db import Database
from noknowledge.server.ratelimit import RateLimiters
from noknowledge.server.routers import blobs, mailboxes, prekeys
from noknowledge.version import __version__


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()

    async def housekeeping_loop(app: FastAPI) -> None:
        while True:
            await asyncio.sleep(max(1, app.state.settings.housekeeping_interval))
            try:
                await asyncio.to_thread(
                    app.state.db.housekeeping,
                    int(time.time()),
                    app.state.settings.mailbox_ttl_seconds,
                    app.state.settings.blob_ttl_seconds,
                )
            except Exception:  # housekeeping must never kill the relay
                pass

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.db.initialize()
        task = asyncio.create_task(housekeeping_loop(app))
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    app = FastAPI(title="noknowledge relay", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.db = Database(settings.db_path)
    app.state.limiters = RateLimiters(
        settings.mailbox_creates_per_hour,
        settings.writes_per_minute,
        settings.bundles_per_hour,
    )

    app.include_router(mailboxes.router, prefix="/api")
    app.include_router(prekeys.router, prefix="/api")
    app.include_router(blobs.router, prefix="/api")

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__, **app.state.db.stats()}

    return app