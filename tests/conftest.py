import os

import pytest

# Tests must be deterministic and must never touch a developer's real OS
# keyring: force the 0600 key-file fallback for the whole suite.
os.environ.setdefault("NK_DISABLE_KEYRING", "1")

from noknowledge.core.client import Client
from noknowledge.core.store import LocalStore
from noknowledge.crypto.identity import Identity
from noknowledge.wire.transport import Transport
from tests.relay_server import RelayProcess


def fast_transport() -> Transport:
    """Low retry counts keep failover tests quick."""
    return Transport(retries=1, timeout=10.0, backoff=0.1)


@pytest.fixture(scope="session")
def qapp():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt5.QtWidgets import QApplication

    application = QApplication.instance() or QApplication([])
    yield application


@pytest.fixture
def relay(tmp_path):
    relay = RelayProcess(tmp_path / "relay0").start()
    yield relay
    relay.stop()


@pytest.fixture
def two_relays(tmp_path):
    first = RelayProcess(tmp_path / "relay0").start()
    second = RelayProcess(tmp_path / "relay1").start()
    yield first, second
    first.stop()
    second.stop()


def make_client(tmp_path, name, relays):
    identity, _ = Identity.generate(label=name)
    store = LocalStore(str(tmp_path / f"{name}.db"), key=os.urandom(32))
    store.initialize()
    return Client(identity, store, relays, name=name, transport=fast_transport())


@pytest.fixture
def alice_bob(tmp_path, relay):
    alice = make_client(tmp_path, "alice", [relay.url])
    bob = make_client(tmp_path, "bob", [relay.url])
    alice.provision()
    bob.provision()
    alice.add_contact(bob.card_string(), nickname="Bob")
    return alice, bob, relay