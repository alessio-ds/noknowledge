#!/usr/bin/env python3
"""Two identities on one machine: exchange text, a file and read receipts.

    python scripts/demo_two_clients.py                 # starts a private relay
    python scripts/demo_two_clients.py --relay http://127.0.0.1:8000

Identities, message history and the local database are written to
``./demo_data/{alice,bob}``, so you can then open the very same accounts in the
GUI and continue the conversation by hand:

    NK_DATA_DIR=demo_data/alice NK_DISABLE_KEYRING=1 ./scripts/run_gui.sh
    NK_DATA_DIR=demo_data/bob   NK_DISABLE_KEYRING=1 ./scripts/run_gui.sh

Nothing here is a special test harness: it drives the same
``noknowledge.core.client.Client`` the GUI uses.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import sqlite3
import sys
import threading
import time

# Keep the script, the stored key file and the GUI on the same fallback, so the
# GUI can open what this script creates without touching the OS keyring.
os.environ.setdefault("NK_DISABLE_KEYRING", "1")

SECRET = "MEET-ME-AT-THE-DOCKS-9d3f"


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def start_relay(data_dir: str, port: int):
    """Run a real relay (uvicorn) in a background thread."""
    import requests
    import uvicorn

    from noknowledge.server.app import create_app
    from noknowledge.server.config import Settings

    settings = Settings(
        data_dir=data_dir, host="127.0.0.1", port=port, housekeeping_interval=10**9
    )
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(settings), host="127.0.0.1", port=port, log_level="warning"
        )
    )
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            if requests.get(f"http://127.0.0.1:{port}/api/health", timeout=1).status_code == 200:
                return server
        except Exception:
            time.sleep(0.1)
    raise SystemExit("relay did not become healthy")


def make_client(name: str, directory: str, relays: list[str]):
    """Create or reuse an identity, exactly as the GUI does."""
    from noknowledge.core.client import Client
    from noknowledge.core.store import LocalStore, resolve_store_key
    from noknowledge.crypto.identity import Identity

    os.makedirs(directory, exist_ok=True)
    vault = os.path.join(directory, "identity.nk")
    if os.path.exists(vault):
        identity = Identity.load(vault)
        print(f"  {name:5} reused identity {identity.identity_id[:12]}…")
    else:
        identity, mnemonic = Identity.generate(label=name)
        identity.save(vault)
        print(f"  {name:5} created identity {identity.identity_id[:12]}…")
        print(f"        seed phrase (keep it!): {mnemonic}")

    store = LocalStore(
        os.path.join(directory, "local.db"),
        resolve_store_key(directory, identity.identity_id),
    )
    store.initialize()
    client = Client(identity, store, relays, name=name)
    client.provision()  # mailbox + prekeys + bundle, idempotent
    return client


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--relay", default=None, help="use a running relay instead of starting one")
    parser.add_argument("--data-dir", default="demo_data")
    parser.add_argument("--relay-port", type=int, default=0)
    parser.add_argument("--fresh", action="store_true", help="delete demo_data/ first")
    args = parser.parse_args(argv)

    if args.fresh and os.path.isdir(args.data_dir):
        shutil.rmtree(args.data_dir)
        print(f"removed {args.data_dir}/")

    embedded = args.relay is None
    if embedded:
        port = args.relay_port or free_port()
        relays = [f"http://127.0.0.1:{port}"]
        print(f"1. starting a private relay on {relays[0]}")
        start_relay(os.path.join(args.data_dir, "_relay"), port)
    else:
        relays = [args.relay]
        print(f"1. using the relay at {args.relay}")

    print("2. creating two identities")
    alice = make_client("alice", os.path.join(args.data_dir, "alice"), relays)
    bob = make_client("bob", os.path.join(args.data_dir, "bob"), relays)

    print("3. exchanging contact cards")
    bob.add_contact(alice.card_string(), nickname="Alice")
    print("   bob added alice's card (alice will learn bob's card from his first message)")

    print("4. bob sends alice a text message")
    bob.send_text(alice.identity_id, f"Hi Alice, it's Bob. {SECRET}")
    for message in alice.sync():
        print(f"   alice received from {message['contact_id'][:12]}…: {message['body']['text'][:60]!r}")
    assert any(SECRET in (m["body"] or {}).get("text", "") for m in alice.messages(bob.identity_id))

    print("5. delivery receipt travels back to bob")
    alice.sync()
    bob.sync()
    state = bob.messages(alice.identity_id)[0]["state"]
    print(f"   bob's sent message is now marked: {state}")

    print("6. alice replies")
    alice.send_text(bob.identity_id, "Got it, Bob. Here's a file.")
    for message in bob.sync():
        print(f"   bob received: {message['body'].get('text', message['type'])!r}")

    print("7. alice sends a file")
    payload = os.urandom(300_000)  # spans more than one 256 KiB chunk
    path = os.path.join(args.data_dir, "attachment.bin")
    with open(path, "wb") as handle:
        handle.write(payload)
    alice.send_file(bob.identity_id, path, caption="the secret plans")
    print(f"   uploaded {len(payload):,} bytes as {os.path.basename(path)}")

    file_message = None
    for message in bob.sync():
        if message["type"] == "file":
            file_message = message
    assert file_message is not None, "bob did not receive the file"
    downloaded = bob.download_attachment(file_message)
    assert downloaded == payload, "downloaded bytes do not match the original"
    manifest = file_message["body"]["attachment"]
    print(
        f"   bob downloaded {len(downloaded):,} bytes; "
        f"sha256 verified ({manifest['sha256'][:16]}…)"
    )

    if embedded:
        print("8. what the relay actually stored")
        db_path = os.path.join(args.data_dir, "_relay", "relay.db")
        blobs: list[bytes] = []
        for suffix in ("", "-wal"):
            candidate = db_path + suffix
            if os.path.exists(candidate):
                with open(candidate, "rb") as handle:
                    blobs.append(handle.read())
        blob_bytes = b"".join(blobs)
        connection = sqlite3.connect(db_path)
        counts = {
            "mailboxes": connection.execute("SELECT COUNT(*) FROM mailboxes").fetchone()[0],
            "messages": connection.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
            "blobs": connection.execute("SELECT COUNT(*) FROM blobs").fetchone()[0],
            "prekey_bundles": connection.execute("SELECT COUNT(*) FROM prekey_bundles").fetchone()[0],
        }
        connection.close()
        print(f"   tables: {counts}")
        print(f"   relay sees no identity keys: {alice.identity.ed_public_bytes not in blob_bytes}")
        print(f"   relay sees no plaintext:     {SECRET.encode() not in blob_bytes}")

    print("\ndone. everything below can be opened in the GUI:")
    print(f"  NK_DATA_DIR={args.data_dir}/alice NK_DISABLE_KEYRING=1 ./scripts/run_gui.sh")
    print(f"  NK_DATA_DIR={args.data_dir}/bob   NK_DISABLE_KEYRING=1 ./scripts/run_gui.sh")
    if embedded:
        print("\nnote: the private relay was embedded and exits with this script.")
        print("for the GUI, start a standalone relay with ./scripts/run_server.sh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())