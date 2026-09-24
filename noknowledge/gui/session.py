"""Helpers that turn GUI state into a :class:`Client`."""

from __future__ import annotations

import os

from noknowledge.core.client import Client
from noknowledge.core.store import LocalStore, resolve_store_key
from noknowledge.crypto.identity import Identity
from noknowledge.gui.settings import GuiSettings, data_dir
from noknowledge.wire.transport import Transport


def identity_path(directory: str | None = None, name: str = "identity") -> str:
    return os.path.join(directory or data_dir(), f"{name}.nk")


def store_path(directory: str | None = None) -> str:
    return os.path.join(directory or data_dir(), "local.db")


def build_transport(settings: GuiSettings) -> Transport:
    """Proxy-only mode is fail-closed: no silent direct connections."""
    if settings.proxy_enabled and settings.proxy_url:
        return Transport(proxy_url=settings.proxy_url, fail_closed=True)
    if settings.fail_closed:
        return Transport(proxy_url=None, fail_closed=True)
    return Transport()


def build_client(
    identity: Identity,
    settings: GuiSettings,
    directory: str | None = None,
) -> Client:
    directory = directory or data_dir()
    os.makedirs(directory, exist_ok=True)
    key = resolve_store_key(directory, identity.identity_id)
    store = LocalStore(store_path(directory), key)
    store.initialize()
    store.register_identity(identity.identity_id, identity.label, identity_path(directory))
    return Client(
        identity,
        store,
        list(settings.relays),
        name=identity.label,
        transport=build_transport(settings),
    )