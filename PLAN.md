# noknowledge — Rework Plan

Full rewrite of `Documents/pyzk` as a **pure-Python** zero-knowledge messenger.
No Rust, no Tauri, no Node/Svelte, no sidecar RPC. Server (FastAPI) and client
(PyQt5 GUI + core library) are both Python.

> **Status:** implemented. Phases 0–7 are complete; the test suite covers the
> crypto core, the relay API, end-to-end exchange over real HTTP relays, relay
> failover, hardening/fuzzing and the GUI. See `README.md` for usage and
> `docs/SELF_HOSTING.md` for federation.

Reference implementation for study only: `/Users/alessiodellasanta/Documents/pyzk`.

---

## 0. Decisions locked

| Topic | Decision |
|---|---|
| Delivery model | **Capability mailboxes** (no global broadcast, no expiry hack) |
| Addressing | **Invite / contact cards**, no public directory |
| Compatibility | **Greenfield** — no pyzk data migration, new identities |
| Forward secrecy | **X3DH + full Double Ratchet** |
| Scope v1 | 1:1 text + read receipts, file transfer, Tor/SOCKS5-only mode |
| Multi-device | **In v1**: account = seed, device = its own mailbox + prekeys + ratchet; signed sealed device list at a publicly derivable address, one ciphertext fanned out per device; fallback to the card inbox when no list exists |
| Threat model | Server must not learn **content** or **sender↔recipient linkage**; timing/IP metadata is out of scope for v1 (but proxy support is in) |
| Availability | Relays are **untrusted and replaceable**: replicated mailboxes across a configurable relay set + sender outbox with re-delivery (§8) |
| Federation | **In v1**: any relay instance is a federated node; cards point at arbitrary relay URLs; no shared state, no central directory, no inter-relay trust |
| History sync | **Planned, not built**: device-to-device transfer of plaintext history over an approval-gated ECIES channel — see [`docs/HISTORY_SYNC.md`](docs/HISTORY_SYNC.md) |
| Out of scope v1 | Group chats, public lookup directory, full P2P/DHT |

---

## 1. Why the rewrite (verified pyzk defects)

Read from source, not the README:

1. **No authentication exists.** `server/router/messages.py` imports
   `verify_signature` but never calls it; no endpoint reads `X-Signature` /
   `X-Public-Key` / `X-Timestamp`. The `signature` column is always empty.
2. **`read_key` leaks to the server.** `MessagingClient.send_message` injects
   `read_key` into the *plaintext* JSON envelope of `encrypted_content` before
   sending, and again as a body field. A hostile server can forge read receipts.
3. **Read messages are never deleted.** `cleanup_expired_messages()` deletes
   only `is_read == False AND expires_at <= now`; confirmed rows live forever.
4. **O(users × messages).** Every client downloads every unread broadcast and
   performs one RSA-OAEP private-key operation per message.
5. **RSA-2048 reused for signing and encryption**, from a hand-rolled
   deterministic prime generator. No forward secrecy; slow key generation.
6. **No padding, no replay protection, sequential global IDs** (volume/order leak).
7. **Local history and contacts stored in plaintext JSON.**
8. **Attachments** sit in an unauthenticated global blob store (disk-fill DoS).

The fix is conceptual: stop conflating **identity** (public, verifiable) with
**address** (secret capability). The server stores only opaque mailboxes and
never sees a public key at write or read time.

---

## 2. Threat model

**Server is honest-but-curious (and assumed compromisable).** It must be unable to:

- read message or attachment plaintext;
- learn which identity wrote to which mailbox;
- learn which identity read a mailbox;
- verify read receipts on its own (receipts are client-to-client messages).

**Server must be able to do only:** store opaque blobs per mailbox, enforce
existence/quotas/rate limits, and delete on ack. It is never trusted for
authenticity: all authenticity comes from end-to-end signatures and the ratchet.

**Explicitly not defended in v1:** traffic analysis by a global network observer
(padding mitigates length leaks; SOCKS5/Tor mode mitigates IP linkage). Mailbox
rotation exists as a hook but is off by default.

**Crypto non-negotiables:** never reuse a (key, nonce) pair; derive all keys via
HKDF with distinct `info` labels; zero out key material where practical;
constant-time comparison for all capability tokens.

---

## 3. Architecture

```
 Alice (PyQt5)                    Server (FastAPI + SQLite)              Bob (PyQt5)
 ─────────────                    ─────────────────────────              ───────────
 identity: Ed25519 + X25519       no user table                         identity: Ed25519 + X25519
 inbox: mailbox_id + tokens       mailboxes(id, H(read), H(write))      inbox: mailbox_id + tokens
        │                                 │                                    │
        │ 1. Bob shares contact card (out of band: QR / string)                   │
        │◀───────────────────────────────────────────────────────────────────────│
        │                                 │                                    │
        │ 2. fetch Bob prekey bundle      │  3. consume one-time prekey         │
        │────────────────────────────────▶│◀───────────────────────────────────│
        │ 4. X3DH → root key → Double Ratchet session                          │
        │                                 │                                    │
        │ 5. POST /mailbox/<bob>/messages (write token, opaque blob)           │
        │────────────────────────────────▶│  store row (mailbox_id only)        │
        │                                 │                                    │
        │                                 │  6. GET /mailbox/<bob> (read token) │
        │                                 │◀───────────────────────────────────│
        │                                 │  7. POST /mailbox/<bob>/ack         │
        │                                 │◀───────────────────────────────────│
        │                                 │                                    │
        │ 8. read receipt = normal ratcheted message into Alice's mailbox      │
        │◀───────────────────────────────────────────────────────────────────────│
```

Key property: the server sees `mailbox_id`, blob size and timestamps. It never
sees a public key, an identity, a sender, a recipient, or plaintext.

---

## 4. Cryptography

### 4.1 Primitives

| Purpose | Algorithm |
|---|---|
| Identity signing | Ed25519 |
| Key agreement | X25519 |
| AEAD | ChaCha20-Poly1305 (12-byte random nonce, 256-bit key) |
| KDF | HKDF-SHA256; HMAC-SHA256 for chain keys |
| Hash | SHA-256 (SHA-512 for BIP39 seed) |
| RNG | `os.urandom` / `secrets` |

### 4.2 Identity derivation (BIP39 → keys)

```
seed  = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" || passphrase, 2048, 64)   # BIP39
root  = HKDF-SHA256(ikm=seed, salt=b"", info=b"noknowledge/identity/v1", len=64)
ed_seed = root[0:32]   → Ed25519 signing key   (IK_sign)
x_seed  = root[32:64]  → X25519  agreement key (IK_dh)
identity_id = base32_crockford(SHA256(b"nk-id" || ed_pub || x_pub))[:26]
```

`identity_id` is offline-derivable from public keys and is the human-facing
fingerprint. It is **never sent to the server**.

### 4.3 Contact card

Compact, URL-safe, one line / QR:

```
nk://1/<identity_id>/<prekey_bundle_id>/<inbox_write_addr>/<relay1,relay2,...>
```

- `prekey_bundle_id` — random 128-bit handle; a relay stores the bundle under it.
- `inbox_write_addr` — `mailbox_id || write_token` (the write capability).
- `relays` — the recipient's relay set (§8); the sender replicates the envelope
  to all of them, so one operator vanishing is not an outage.
- Card is signed by `IK_sign`; the receiving client verifies before use. This
  lets cards survive untrusted relays/QR screenshots.

### 4.4 X3DH (first-contact key agreement)

Recipient publishes, under `prekey_bundle_id`:

- `IK_dh` (identity agreement key)
- `SPK` — signed prekey (X25519) + `SPK_id` + Ed25519 signature by `IK_sign`
- one or more `OPK` — one-time prekeys (X25519) with `OPK_id`

Initiator:

```
verify SPK signature with recipient IK_sign
EK = new X25519 keypair
DH1 = DH(IK_a_dh, SPK_b)
DH2 = DH(EK_a,   IK_b_dh)
DH3 = DH(EK_a,   SPK_b)
DH4 = DH(EK_a,   OPK_b)              # if an OPK was available
SK  = HKDF-SHA256(ikm = F || DH1||DH2||DH3||DH4,
                  salt = 0x00*32, info = b"noknowledge/x3dh/v1")
AD  = IK_a_pub || IK_b_pub           # associated data for the first AEAD
F   = 0xFF repeated 32 times         # X25519 domain separation
```

If no OPK remains, omit `DH4` and flag `no_opk` in the initial message.

### 4.5 Double Ratchet

Standard Signal Double Ratchet over the X3DH root key:

- State: `RK, CKs, CKr, DHs, DHr, Ns, Nr, PN, MKSKIPPED`.
- `KDF_RK(rk, dh_out) = HKDF-SHA256(ikm=dh_out, salt=rk, info=b"nk/ratchet-root/v1") → (new_RK, new_CK)`
- `KDF_CK(ck) = (HMAC(ck, 0x01) → mk, HMAC(ck, 0x02) → next_ck)`
- Header `{dh_pub, pn, n}` is serialized and authenticated as AEAD associated data.
- Out-of-order messages handled via `MKSKIPPED`; skipped-key cap (e.g. 1000) to
  bound memory; decrypt failure on a message is non-fatal to the session.
- Session state is persisted encrypted after every send/receive.

**Risk (highest in the project):** a from-scratch ratchet is easy to get subtly
wrong. Mitigation: implement against the published Double Ratchet specification,
write exhaustive state-transition tests, cross-check with published test vectors
where available, and fuzz out-of-order delivery.

### 4.6 Envelope & padding

Plaintext inside the ratchet is a JSON envelope:

```json
{
  "v": 1,
  "type": "text | file | receipt | typing",
  "id": "<uuid4>",
  "ts": 1730000000000,
  "body": { ... },
  "pad": "<random bytes, to size bucket>"
}
```

- Padded to the next multiple of 256 bytes (2 KiB cap for text) before AEAD.
- `id` gives idempotency/replay rejection; recipients keep a bounded seen-set.
- Types:
  - `text` → `{"text": "..."}`
  - `file` → `{"name","mime","size","sha256","chunks":[{"id","key","nonce"}]}`
  - `receipt` → `{"of": "<message-id>"}`
  - `typing` → optional transient state, no storage

---

## 5. Server

### 5.1 Schema (stdlib `sqlite3`, WAL)

```sql
mailboxes(
  id TEXT PRIMARY KEY,
  read_token_hash  BLOB NOT NULL,
  write_token_hash BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  max_messages INTEGER NOT NULL DEFAULT 1000,
  max_bytes    INTEGER NOT NULL DEFAULT 67108864
);

messages(
  rowid INTEGER PRIMARY KEY AUTOINCREMENT,
  mailbox_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  ciphertext BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  size INTEGER NOT NULL,
  UNIQUE(mailbox_id, seq)
);
CREATE INDEX idx_messages_mailbox ON messages(mailbox_id, seq);

prekey_bundles(
  bundle_id TEXT PRIMARY KEY,
  ik_sign_pub BLOB NOT NULL, ik_dh_pub BLOB NOT NULL,
  spk BLOB NOT NULL, spk_sig BLOB NOT NULL, spk_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

prekey_one_time(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bundle_id TEXT NOT NULL, opk_id INTEGER NOT NULL,
  opk_pub BLOB NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_opk_bundle ON prekey_one_time(bundle_id, used);

blobs(
  chunk_id TEXT PRIMARY KEY,
  mailbox_id TEXT NOT NULL,
  ciphertext BLOB NOT NULL, size INTEGER NOT NULL, created_at INTEGER NOT NULL
);
CREATE INDEX idx_blobs_mailbox ON blobs(mailbox_id);
```

**No** `users`, `public_key`, `read_key`, `notification_key`, `is_read`, `expires_at`.

### 5.2 API

| Method | Endpoint | Auth | Notes |
|---|---|---|---|
| POST | `/api/mailbox` | hashcash (optional) | returns `mailbox_id`, `read_token`, `write_token` **once** |
| GET | `/api/mailbox/{id}` | read token header | optional `?wait=<sec>` long-poll |
| POST | `/api/mailbox/{id}/messages` | write token header | 404 if mailbox gone, 429 if quota/rate exceeded |
| POST | `/api/mailbox/{id}/ack` | read token header | deletes rows `seq <= n` |
| DELETE | `/api/mailbox/{id}` | read token header | cascades pending messages + blobs |
| POST | `/api/prekeys` | none | publish bundle; PoW-gated |
| GET | `/api/prekeys/{bundle_id}` | none | returns bundle, atomically consumes one OPK |
| POST | `/api/blob` | write token header | chunk ≤ 1 MiB; counts toward mailbox quota |
| GET | `/api/blob/{chunk_id}` | read token header | mailbox ownership checked |
| GET | `/api/health` | none | version + queue depth (no identities) |

Tokens are sent as `X-NK-Read` / `X-NK-Write`; the server compares
`SHA256(token)` in constant time. No request contains a public key.

### 5.3 Anti-abuse (replaces expiry-as-spam-control)

- Write to a nonexistent mailbox → **404**. This is what kills the pyzk problem:
  undeliverable mail is never accepted, so nothing lingers in a queue.
- Per-mailbox quota (`max_messages`, `max_bytes`) → **429**; forces the owner to ack.
- Per-IP token bucket on create/write/upload.
- Optional hashcash on mailbox/prekey creation to make mass creation expensive.
- Housekeeping only (not a security control): delete mailboxes idle > 90 days,
  and orphan blobs older than 30 days. Configurable; no content is ever scanned.

### 5.4 Server-side non-functionality

- Single-process uvicorn, `sqlite3` in WAL mode, `check_same_thread=False` guarded
  by a write lock (or one connection per request via thread-local).
- Structured logging that never logs tokens, mailbox contents, or identity hashes.
- Hard request-size limits at the ASGI layer.

---

## 6. Client

### 6.1 Layers

- `noknowledge.crypto` — pure crypto, no I/O. Fully unit-tested.
- `noknowledge.wire` — envelope models, canonical encoding, transport (HTTP +
  retry/backoff + SOCKS5 with `fail_closed` mode).
- `noknowledge.core` — client orchestration: identity, contacts, sessions,
  mailbox sync, attachments, receipts.
- `noknowledge.gui` — PyQt5. Network runs on a `QThread` worker; UI only via
  Qt signals. No blocking call on the GUI thread.
- Local store — SQLite, message bodies and ratchet state encrypted with a
  local key held in the OS keyring (fallback: passphrase-derived key).

### 6.2 Local schema

```sql
identities(id TEXT PK, label TEXT, ed_priv_enc BLOB, x_priv_enc BLOB, created_at)
contacts(id TEXT PK, identity_id TEXT, nickname TEXT,
         ik_sign_pub BLOB, ik_dh_pub BLOB,
         bundle_id TEXT, their_inbox_addr TEXT,
         my_inbox_id TEXT, my_read_token_enc BLOB, my_write_token_enc BLOB,
         session_state_enc BLOB, verified INTEGER DEFAULT 0, created_at)
messages(id TEXT PK, contact_id TEXT, direction TEXT, type TEXT,
         body_enc BLOB, remote_id TEXT, ts INTEGER, state TEXT,
         attachment_json TEXT)
```

### 6.3 Tor / proxy-only mode

- `Transport(proxy="socks5://127.0.0.1:9050", fail_closed=True)`.
- When `fail_closed`, a `http(s)://` request to a non-loopback host with no
  usable proxy raises instead of falling back to a direct connection.
- Never proxy loopback/`.local` (so a self-hosted server works offline).

### 6.4 Client API surface

```python
Identity.create(label, passphrase=None) -> (Identity, mnemonic)
Identity.recover(mnemonic, passphrase=None, label=None) -> Identity
Identity.load(path, passphrase=None) -> Identity
Identity.id, .contact_card() -> str

Client(identity, server_url, transport)
  client.create_inbox()                      # ensures own mailbox
  client.add_contact(card: str, nickname: str) -> Contact
  client.accept_invitation(card) ...
  client.send_text(contact, text, receipt=True) -> str   # local msg id
  client.send_file(contact, path, caption="")
  client.download_attachment(contact, message) -> path
  client.sync(timeout=30) -> list[Message]   # long-poll + decrypt + receipt + ack
  client.mark_read(message)
  client.rotate_inbox()                      # future-proofing hook
```

### 6.5 PyQt5 screens (ported from the Svelte UI feature set)

Welcome · Create identity (mnemonic reveal + confirm) · Recover from mnemonic ·
Unlock (passphrase) · Main (contact list + chat) · Add contact (paste card / QR) ·
Settings (server URL, proxy, fail-closed, theme) · Attachment open/save.

---

## 7. Repository layout (new, in this folder)

```
noknowledge/
  PLAN.md  PROTOCOL.md  THREAT_MODEL.md  README.md
  pyproject.toml  requirements.txt
  noknowledge/
    crypto/    identity.py kdf.py aead.py x3dh.py ratchet.py padding.py
    wire/      protocol.py transport.py errors.py
               backends/ base.py http_relay.py multi_relay.py   # §8.1
    core/      client.py contact.py mailbox.py outbox.py attachments.py store.py paths.py
    server/    app.py config.py db.py security.py ratelimit.py
               routers/mailboxes.py prekeys.py blobs.py
    gui/       app.py worker.py screens/ widgets/
  tests/       test_kdf test_aead test_identity test_x3dh test_ratchet
               test_padding test_server test_backends test_outbox
               test_client_e2e test_relay_failover test_proxy
  scripts/     run_server.sh wipe.sh
```

Deleted relative to pyzk: `src-tauri/`, `src/`, `package.json`, `vite.config.js`,
`svelte.config.js`, `client/sidecar/`, all Rust/Node tooling, `server/db_files`
layout, `add_messages_to_queue.py` (nothing to seed), `uv.lock` (regenerate).

Dependencies (v1): `cryptography`, `mnemonic`, `fastapi`, `uvicorn`, `requests`,
`PySocks`, `PyQt5`, `keyring`, `pytest` (dev). Dropped: `sqlmodel`,
`python-multipart`, `pydantic` (request bodies are raw bytes/JSON via stdlib).
Verified locally: PyQt5 5.15.11 / Qt 5.15.14 imports on Python 3.14.3;
`cryptography` 46 present.

---

## 8. Availability & decentralization

The most valuable property of the capability-mailbox design is that a relay is
**dumb, untrusted and replaceable**: it holds opaque blobs and cannot link them
to anyone. Availability can therefore be bought with redundancy alone — no
consensus, no trust, no shared state. A directory server would have been a hard
single point of failure; a blob relay is not.

### 8.1 Transport abstraction (build in from Phase 2)

All client I/O goes through one interface, so "the server" is just one backend:

```python
class MailboxBackend(Protocol):
    def create_mailbox(self) -> MailboxCapability: ...
    def put(self, mailbox_id, write_token, envelope: bytes) -> int: ...
    def get(self, mailbox_id, read_token, after_seq=0, wait=0) -> list[tuple[int, bytes]]: ...
    def ack(self, mailbox_id, read_token, upto_seq: int) -> None: ...
    def publish_bundle(self, bundle: bytes) -> str: ...
    def fetch_bundle(self, bundle_id) -> bytes | None: ...
    def put_blob(self, mailbox_id, write_token, chunk: bytes) -> str: ...
    def get_blob(self, chunk_id, read_token) -> bytes: ...
```

Implementations, in order of effort:

1. `HttpRelayBackend` — the FastAPI server (v1).
2. `MultiRelayBackend` — fan-out write to N relays, read from whichever answers,
   ack everywhere (v1).
3. `NostrRelayBackend` / `FileSystemBackend` — v2, small, plug-in.
4. `DhtBackend` — deferred, large (§8.5).

### 8.2 Replicated mailboxes (v1)

- The contact card carries the recipient's **relay set**, not one URL.
- The sender writes each envelope to every relay in the set; the recipient polls
  all and deduplicates by envelope `id` (already required for replay protection).
- A mailbox is a random id plus tokens, so the recipient can recreate it on any
  relay. Because envelopes are idempotent, re-upload is always safe.
- Ack is sent to all replicas; housekeeping TTL clears any replica that missed it.
- Cost: N× storage/bandwidth on fan-out; N is configurable (default 2–3).

### 8.3 Sender outbox and re-delivery (v1)

- Every outgoing envelope stays in a local **outbox** until the peer's receipt
  arrives.
- On relay failure, mailbox rotation, or a peer's new card, the client re-uploads
  unacked envelopes to the currently reachable relay set.
- Relay loss becomes a *delay*, not a *loss*, and no globally consistent server
  is needed.

### 8.4 Federation (v1)

- **Federation is a consequence of the design, not a bolt-on.** The relay keeps
  no global state and no user table, so a second instance is simply another
  relay; `python -m noknowledge.server` *is* "running your own node".
- Cards point at arbitrary relay URLs. Nothing is registered centrally, and
  relays never need to know about or trust each other.
- A user can run a private relay for their own inbox, use public ones, or mix.
- Consequence: there is no central authority to take down. Removing one host
  (or every host you did not personally choose) cannot stop the network.
- v1 deliverable: documented self-hosting (TLS/reverse-proxy, config, systemd
  unit) and a relay-set field that accepts arbitrary URLs.

### 8.5 Full P2P — honest assessment

A Kademlia DHT could store `mailbox_id → blob` across peers, but it does not
solve the actual problem: **an offline recipient needs an always-on holder.**
It also drags in NAT traversal (STUN/TURN/hole-punching), Sybil resistance and
storage incentives, and pure Python makes all of that worse. It is a project in
its own right and buys little over 2–3 volunteer relays plus an outbox.

Recommendation: **not in v1**. If "no servers at all" ever becomes the goal, add
a `DhtBackend` behind the same interface rather than changing the protocol.

### 8.6 What actually breaks when a host goes down

| Failure | With this design | With pyzk's single server |
|---|---|---|
| One relay of three down | none (read/write the other two) | total outage |
| Operator quits permanently | peer re-cards / rotates mailbox; outbox replays; messages delayed, not lost | queued messages lost |
| Relay compromised | learns mailbox ids, blob sizes, timing; no content, no linkage | learns public keys, can forge receipts, sees read keys |

---

## 9. Phases & acceptance criteria

| # | Phase | Deliverable | Done when |
|---|---|---|---|
| 0 | Spec & skeleton | `THREAT_MODEL.md`, `PROTOCOL.md`, repo layout, pyproject, pytest config | docs reviewed; `pytest` runs green on an empty suite |
| 1 | Crypto core | identity, KDF, AEAD, padding, X3DH, Double Ratchet | unit tests incl. deterministic vectors, out-of-order, replay rejection, tamper detection |
| 2 | Server + backend interface | mailboxes, prekeys, blobs, ack, quotas, rate limit; `MailboxBackend` + `HttpRelayBackend` | server tests: 404 nonexistent, 401 bad token, 429 over quota, ack deletes, OPK consumed once; backend interface exercised against two fake relays |
| 3 | Client core | `MultiRelayBackend`, relay set in cards, sender outbox + re-delivery, sessions, send/sync/receipts, attachments, encrypted store | end-to-end two-client test with one relay deliberately killed mid-conversation; offline first contact; file round-trip |
| 4 | PyQt5 GUI | all screens in §6.5, background worker | two GUI instances exchange messages/files; UI never blocks; proxy + relay-set settings honored |
| 5 | Hardening | padding, rate-limit tuning, keyring fallback, rotating inbox docs, `NostrBackend`/`FileSystemBackend` hook | security review checklist complete; fuzz tests green |
| 6 | Packaging | PyInstaller spec, README, run/wipe scripts, self-hosting + federation docs | `python -m noknowledge.server` and packaged GUI start on macOS/Linux |
| 7 | CI | GitHub Actions: test matrix on Linux/macOS/Windows, packaged builds for Windows, Ubuntu, Fedora, macOS (latest + `macos-26-intel`) | a tag push produces downloadable artifacts for every target; test job green on all runners |

**Definition of done for v1:** two fresh identities, no directory, exchange
text, receipts and a file through relays that provably cannot decrypt or link
them, with one relay killed mid-conversation and delivery still completing. All
pure Python; pyzk left untouched as reference.

---

## 10. Open risks / watch items

1. **Double Ratchet correctness** — mitigate with spec-driven tests + fuzzing.
2. **X25519/Ed25519 key confusion** — separate keys with distinct HKDF labels; never reuse.
3. **DoS on mailbox creation** — hashcash gate + per-IP limits (no accounts, so no other handle).
4. **Blob orphan cleanup** — server can't see references inside ciphertext; use mailbox cascade + TTL.
5. **Python 3.14 is young** — pin `requires-python = ">=3.11"` for portability, test on 3.14 locally.
6. **PyQt5 packaging** — PyInstaller hooks for Qt are well-trodden but need a smoke test per OS.