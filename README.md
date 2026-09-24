# noknowledge

A **zero-knowledge, federated messenger** in pure Python.

Relays store opaque, end-to-end encrypted blobs addressed by unguessable
mailbox capabilities. A relay never learns identities, senders, recipients, or
content. There is no central node, no account, and no directory.

```
 Alice                          Relay(s)                         Bob
 ─────                          ────────                         ───
 Ed25519 + X25519               no user table                    Ed25519 + X25519
 mailbox + tokens               only hashed capabilities         mailbox + tokens
      │                              │                               │
      │  1. Bob shares a signed contact card (QR / copy-paste)       │
      │◀────────────────────────────────────────────────────────────│
      │  2. fetch Bob's prekey bundle (one OPK consumed)             │
      │─────────────────────────────▶│                              │
      │  3. anonymous X3DH → Double Ratchet session                  │
      │  4. POST opaque blob to Bob's mailbox                        │
      │─────────────────────────────▶│  5. Bob fetches, decrypts, acks
      │                              │──────────────────────────────▶
      │  6. read receipt = an ordinary encrypted message back        │
      │◀────────────────────────────────────────────────────────────│
```

## Why it is different from a normal messenger server

A conventional server is a trusted directory: it knows who you are and who you
talk to. noknowledge splits **identity** (public, verifiable, derived from a
mnemonic) from **address** (a secret capability):

- Each identity creates a **mailbox** and hands out a signed **contact card**
  containing its public keys, a prekey bundle handle, a mailbox **write**
  capability, and a set of relays.
- The first message performs an **anonymous X3DH** handshake; identity is proven
  *inside* the ciphertext (sealed-sender style), so the relay never sees it.
- Every later message runs through a **Double Ratchet** for forward secrecy and
  post-compromise security.
- Relays see random mailbox ids and ciphertext, nothing else.
- Writing to a mailbox that does not exist is **rejected outright**, so
  undeliverable mail never accumulates — which is what removes the need for
  expiry-based queue cleanup.

## Install and run

```bash
uv venv --python 3.13
uv pip install -e ".[dev,gui]"
```

Run a relay:

```bash
python -m noknowledge.server --host 127.0.0.1 --port 8000 --data-dir ./relay_data
# or: ./scripts/run_server.sh
```

Run the desktop client:

```bash
python -m noknowledge.gui
# or: ./scripts/run_gui.sh
#     NK_DATA_DIR=/tmp/alice ./scripts/run_gui.sh   # isolated instance
```

Use the library directly:

```python
from noknowledge.core.client import Client
from noknowledge.core.store import LocalStore
from noknowledge.crypto.identity import Identity
import os

identity, mnemonic = Identity.generate(label="alice")
store = LocalStore("alice.db", key=os.urandom(32))
store.initialize()
alice = Client(identity, store, ["http://127.0.0.1:8000"], name="alice")

alice.provision()
print(alice.card_string())          # share this with a contact
alice.add_contact(bob_card_string)  # then message them
alice.send_text(bob_id, "hello")
for message in alice.sync():
    print(message["body"])
```

## Federation

Federation is a property of the design, not a feature to enable. A relay keeps
no global state and no user table, so a second instance is simply another relay.
Put several URLs in a contact card's relay list and messages replicate across
them: the sender writes to all, the recipient reads from whichever answers
first, and duplicates are deduplicated by envelope id. One relay failing is
invisible; there is no central authority to take down.

See [`docs/SELF_HOSTING.md`](docs/SELF_HOSTING.md) for systemd, TLS, Tor and
operations.

## Testing

```bash
QT_QPA_PLATFORM=offscreen python -m pytest -q
```

The suite covers the crypto core (including known-answer vectors for HKDF,
tamper and replay rejection, out-of-order delivery and ratchet rollback), the
relay API (quota, capability tokens, housekeeping, concurrency), full
end-to-end exchanges over real HTTP relays, and **relay failover** where one
relay is killed mid-conversation.

## Building standalone binaries

```bash
python scripts/build.py --all      # -> dist/nk-gui, dist/nk-server
```

`.github/workflows/build.yml` builds these on Windows, Ubuntu, Fedora and macOS
(`macos-latest` arm64 and `macos-26-intel` x86_64).

## Project layout

```
noknowledge/
  crypto/   identity, KDF, AEAD, padding, X3DH, Double Ratchet
  wire/     protocol framing, transport, relay backends (HTTP, multi-relay)
  core/     client, contact cards, sessions, attachments, encrypted store
  server/   FastAPI relay (mailboxes, prekeys, blobs)
  gui/      PyQt5 desktop client
tests/      crypto, server, end-to-end, failover, hardening and GUI tests
docs/       self-hosting and operations
```

## Documentation

| File | Contents |
|---|---|
| [`PLAN.md`](PLAN.md) | Architecture, decisions, phases, acceptance criteria |
| [`PROTOCOL.md`](PROTOCOL.md) | Wire format, crypto, handshake, ratchet, relay API |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Adversaries, guarantees, non-goals, verification plan |
| [`docs/SELF_HOSTING.md`](docs/SELF_HOSTING.md) | Running and federating relays |

## Scope

**In:** 1:1 text, read/delivery receipts, encrypted attachments, multi-relay
replication, federation, SOCKS5/Tor fail-closed mode.

**Not yet:** group chats, multi-device, a public lookup directory, full P2P/DHT,
and resistance to global traffic analysis.

## License

MIT — see [`LICENSE`](LICENSE).