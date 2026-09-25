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

The project is managed with [uv](https://docs.astral.sh/uv/). One command creates
the environment from `uv.lock`:

```bash
uv sync --extra gui          # add --extra build for PyInstaller
```

> On a slow connection uv's 30 s HTTP timeout can be too tight:
> `UV_HTTP_TIMEOUT=300 uv sync --extra gui`.
>
> `uv run` re-syncs to the default set, so pass `--extra gui` on any command
> that needs PyQt5. The `scripts/run_gui.sh` helper does this for you.

Run a relay:

```bash
uv run nk-server --host 127.0.0.1 --port 8000 --data-dir ./relay_data
# or: ./scripts/run_server.sh
```

Run the desktop client:

```bash
uv run nk-gui
# or: ./scripts/run_gui.sh
#     NK_DATA_DIR=/tmp/alice ./scripts/run_gui.sh   # isolated instance
```

Everything can also be run as a module, which is what the frozen binaries do:

```bash
uv run python -m noknowledge.server --host 127.0.0.1 --port 8000
uv run python -m noknowledge.gui
```

### Local key storage

The local database key is kept in the **OS keyring** by default. On headless
machines, in containers, or in CI — where no keyring exists — set
`NK_DISABLE_KEYRING=1` to use a `0600` key file in the data directory instead.
Either way, message bodies and ratchet state are encrypted at rest.

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

## Try it locally (two accounts, one machine)

One command runs a private relay and two identities that exchange a message, a
read receipt and a file:

```bash
uv run python scripts/demo_two_clients.py
```

It prints the relay's row counts and confirms the relay holds neither identity
keys nor plaintext. Identities and history land in `./demo_data/{alice,bob}`, so
you can open the *same* accounts in the GUI and keep talking by hand:

```bash
NK_DATA_DIR=demo_data/alice NK_DISABLE_KEYRING=1 ./scripts/run_gui.sh
NK_DATA_DIR=demo_data/bob   NK_DISABLE_KEYRING=1 ./scripts/run_gui.sh
```

To do it entirely by hand, start a relay and give each client its own data
directory (they must not share one):

```bash
# terminal 1
./scripts/run_server.sh

# terminal 2 and 3 — one per identity
NK_DATA_DIR=/tmp/nk-alice NK_DISABLE_KEYRING=1 ./scripts/run_gui.sh
NK_DATA_DIR=/tmp/nk-bob   NK_DISABLE_KEYRING=1 ./scripts/run_gui.sh
```

Then in one window: **Create a new identity** → save the seed phrase →
**My card** (shown as text *and* a scannable QR code) → *Copy to clipboard*. In
the other window: **Add contact** → paste the card → select the contact and send
a message or attach a file. The first message carries the sender's card, so the
other side learns the contact automatically; the reply then flows back.

Contacts are identified by their 26-character identity ID, shown under the
nickname in the chat header and in the toolbar for your own identity. Names are
self-asserted, so rows whose nickname collides get a short ID suffix
(`Bob · 3TPNKFS`) — compare IDs, not names, if it matters.

## Federation

Federation is a property of the design, not a feature to enable. A relay keeps
no global state and no user table, so a second instance is simply another relay.
Put several URLs in a contact card's relay list and messages replicate across
them: the sender writes to all, the recipient reads from whichever answers
first, and duplicates are deduplicated by envelope id. One relay failing is
invisible; there is no central authority to take down.

See [`docs/SELF_HOSTING.md`](docs/SELF_HOSTING.md) for systemd, TLS, Tor and
operations.

### Default relay and discovery

A new install starts with `https://noknowledge.remotewire.net` in its relay list.
Self-hosters can ship their own default with `NK_DEFAULT_RELAYS` (comma
separated). Relays can always be changed in **Settings → Relays**, one URL per
line.

Relays advertise the peers they know about at `GET /api/relays`. With
**Automatically discover new relays** enabled (the default), a client unions
those with its own list, keeps the ones that answer `/api/health`, and starts
using them — so the network grows without anyone editing settings. Discovery
never removes a relay, caps the list at 8, and **refuses candidates on loopback,
LAN or link-local addresses** so a hostile relay cannot use the client to probe
your network. Set `NK_ALLOW_PRIVATE_RELAYS=1` if you deliberately run relays
locally or on your own network.

Because your relay list is baked into your signed contact card, adopting a relay
also tells the people you talk to where to deliver.

## Testing

```bash
uv run --extra gui pytest
# or, to mirror CI exactly:
QT_QPA_PLATFORM=offscreen NK_DISABLE_KEYRING=1 uv run --no-sync pytest
```

The suite covers the crypto core (including known-answer vectors for HKDF,
tamper and replay rejection, out-of-order delivery and ratchet rollback), the
relay API (quota, capability tokens, housekeeping, concurrency), full
end-to-end exchanges over real HTTP relays, and **relay failover** where one
relay is killed mid-conversation.

## Building standalone binaries

```bash
uv sync --extra gui --extra build
uv run --no-sync python scripts/build.py --all   # -> dist/nk-gui, dist/nk-server
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
scripts/    run_server.sh, run_gui.sh, build.py, wipe.sh
docs/       self-hosting and operations
uv.lock     pinned, reproducible environment
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