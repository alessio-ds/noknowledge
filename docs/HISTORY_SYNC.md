# History sync and live device mirroring

**Status:** design agreed in outline, not implemented. Everything below needs no
server change and keeps the relay zero-knowledge: it learns no content and no
sender↔recipient linkage.

## 1. What the user gets (the Gajim/XMPP shape)

| Situation | Behaviour |
|---|---|
| Alice has two devices; Bob writes to Alice | **Both** of Alice's devices receive it (already shipped: one ciphertext per device). |
| Alice sends from her laptop | Her phone shows the sent message too, and its receipts/ticks follow. |
| Alice reads a message on her phone | Her laptop shows it as read. |
| Alice gets a new phone and restores the seed | It asks another device to back-fill the last **30 days** (selectable: 30/60/90 days or everything); when a device approves, history and attachments transfer. |
| Alice's seed leaks | The thief can read future traffic (the seed *is* the account) but **cannot pull the past** without a human on an existing device approving. |

Where this differs from XMPP, and why: XMPP servers keep your archive (MAM) and
your roster, so any client can query the past at any time. Our relay cannot read
anything, so it cannot be that archive. Past history therefore lives only on
devices that already have it, and one of them has to hand it over. The practical
consequence: **a new device needs an approved transfer from an existing device
once** — after that it is a full participant and stays in sync on its own.

## 2. Why the ciphertext cannot simply be replayed

- Every message was sealed with a one-time key from the ratchet chain of the
  device it was addressed to. Other devices hold no such key, and the keys that
  were used are gone. That is forward secrecy working, not a gap to route
  around.
- Asking the peer to re-send the past only works if the peer is online and kept
  the plaintext; it does not survive a wiped contact.
- Local stores are keyed per device: the desktop uses a keyring/`local.key`
  secret, the web derives a key from the *account password* with a per-device
  salt. Neither exists on another device.

So syncing means a device that holds plaintext actively handing it over.

## 3. Invariants

| Invariant | Consequence for the design |
|---|---|
| Relay sees no content | Transfer payloads are AEAD-sealed end to end; mailbox blobs stay opaque. |
| Relay sees no linkage | No new per-account derivable address; nothing plaintext identifies the account. |
| Per-device sessions stay separate | No ratchet state ever moves between devices. |
| No server change | Transfers ride the existing mailbox `POST /message` path. |
| Forward secrecy for live traffic | The device channel is a separate, one-purpose key agreement. |

## 4. Design

### 4.1 Device keys (the missing piece)

A device is currently just a mailbox. Give each device its own keypair, published
in the **account-signed device list**, so any device of the account can verify
another:

```json
{
  "device": "b64(16)",
  "inbox": {"id": "b64(16)", "w": "b64(32)"},
  "relays": ["https://relay.example"],
  "bundle": "b64(16)",
  "name": "laptop",
  "sdev":   "b64(32)",   // device Ed25519 key — authenticates records from it
  "sagree": "b64(32)"    // device X25519 key — lets siblings encrypt to it
}
```

Generated at provision; private halves live in the local encrypted store. The
account signature means a relay cannot inject a device and a device cannot
impersonate a sibling. Unknown fields are ignored by current parsers, so this is
additive; an entry without `sagree` simply cannot sync yet.

### 4.2 Live mirroring — "sent from one device, visible on both"

This is the part that makes the behaviour match XMPP carbons, and it is the piece
the first draft of this plan was missing.

When device A sends a message to Bob:

1. A seals the normal copy to each of Bob's devices (unchanged).
2. A also seals a **mirror record** to each of *its own* other devices, written to
   each sibling's mailbox: same envelope id, same plaintext body, plus Bob's
   signed contact card so a device that has never met Bob can create the contact.
3. A records the mirror writes in its **outbox** before considering the send
   done, so a sibling that is offline still gets the carbon when it next appears
   — store-and-forward at the sender, using the retry path that already exists.

Receipts and read state follow the same path in both directions: siblings mirror
their own state changes, and (because peers fan out their receipts to every device
of the account) a receipt often arrives directly anyway. Merge is
last-writer-wins on the state, so a replayed or out-of-order update cannot
resurrect "unread" on a device where it was already read.

Mirroring is the *future*: it needs no approval, because a device in the list is
already receiving the account's traffic — that is unavoidable, since the seed
*is* the account. What needs approval is anything that exists only as plaintext on
another device.

### 4.3 Approval, and what it unlocks

One approval per device, remembered, and revocable:

- It unlocks **back-fill** of the past within the chosen range.
- It unlocks **mirroring of sent messages** from that point on. (Until approved,
  a new device still receives incoming traffic — it cannot be stopped from doing
  so — but it shows a banner: "receive-only: your history and sent messages are
  not syncing yet".)

Mechanically: the approving device signs `(transfer_id, new_device_id, scopes)`
with its device key and returns that as an `approval` record. Siblings accept
mirror records from a device that is in their own last-known signed device list
*and* whose mirror writes carry a valid record signature — approval only gates
what a device is *given*, never what it is trusted to say.

Security rationale, stated plainly: without the gate, a stolen seed silently
exfiltrates every past conversation from every online device. With it, the worst
case is the same as today — future traffic only.

### 4.4 The device channel

Store-and-forward, because the sibling is usually offline:

1. Sender generates an ephemeral X25519 keypair `e`.
2. `shared = X25519(e_priv, sibling.sagree)`,
   `key = HKDF-SHA256(shared, salt=transfer_id, info=b"nk/history/v1", 32)`.
3. Per-chunk keys are HKDF-expanded from `key` with the chunk index; the transfer
   id and chunk index are the AEAD associated data, so chunks cannot be
   reordered, truncated, or spliced between transfers.
4. The record written to the sibling's mailbox is opaque:

```
"NKS1" | u8 version | u8 kind | u16 reserved | canonical JSON header | payload
```

| kind | name | payload |
|---|---|---|
| 1 | `request` | who is asking, wanted range |
| 2 | `offer` | chunk count, bytes, sha256 of the whole bundle, range |
| 3 | `chunk` | `nonce`, `ciphertext`; header carries `eph_pub`, `from_device` |
| 4 | `complete` | root hash, message/attachment counts |
| 5 | `approval` | signed approval with scopes |
| 6 | `mirror` | one sent message or one state change (small, single record) |

The header carries `eph_pub`, `from_device` and an Ed25519 signature by that
device's key over the header contents. A record is accepted only if
`from_device` appears in the recipient's own last-known account-signed device
list and the signature verifies.

Routing: `sync()` must tell a ratchet envelope from a device record before
attempting to decrypt; the `NKS1` magic does that. Unrecognized blobs keep the
current "retry a few times, then ack" behaviour, so a poison blob cannot wedge a
mailbox. The relay sees only opaque mailbox writes — sizes and timing, which the
threat model already excludes.

### 4.5 Bundle contents and merge rules

Canonical JSON, zlib-compressed, chunked to stay inside relay message limits:

```json
{
  "v": 1,
  "from_device": "b64(16)",
  "created": 1730000000000,
  "range": {"since": 0, "until": 1730000000000},
  "contacts": [{"id": "...", "isign": "...", "idh": "...", "bundle": "...",
                "inbox": {...}, "relays": [...], "nickname": "...",
                "verified": false, "created_at": 0}],
  "messages": [{"contact_id": "...", "direction": "received", "type": "text",
                "body": {...}, "remote_id": "...", "ts": 0, "state": "read"}],
  "attachments": [{"sha256": "...", "name": "doc.pdf", "mime": "...",
                   "bytes": "b64"}],
  "skipped": [{"sha256": "...", "reason": "over budget"}]
}
```

- **Contacts** merge by identity id; a locally chosen nickname and `verified` are
  never overwritten by a bundle.
- **Messages** dedup on `(contact_id, remote_id, direction)` — the key the clients
  already use to ignore duplicate deliveries — so a carbon and a back-fill of the
  same message collapse into one row.
- **State** is last-writer-wins, so ticks stay consistent in both directions.
- **Attachments** are content-addressed by sha256; identical bytes are stored
  once. Local message ids are regenerated on import.
- Everything is idempotent, so an interrupted and resumed transfer is harmless.

### 4.6 Attachments: included, bounded (decision taken)

A synced conversation with dangling attachments is a broken conversation, so
attachments transfer by default, bounded by three things: the chosen time range,
a total size budget per sync (default 100 MB), and the local content-addressed
cache. Anything over budget is listed as *"available on your other device"* rather
than silently missing, and the sync can be re-run for them alone.

Prerequisite, useful on its own: a **local attachment cache**. Today a device
cannot produce the bytes of a file *it sent* — the chunks are in the peer's
mailbox and it holds only a write token. Sending and downloading should keep the
chunk ciphertext locally (`local_blobs` on desktop, an IndexedDB store in the
web) and prefer it on download. That also makes old attachments survive relay TTL
and removes a network round trip.

### 4.7 Reliability

- Mirror writes go through the existing outbox, so a sibling that is offline, or
  a sender that is shut down mid-send, still delivers on reconnect.
- Back-fill is chunked and resumable: the offer carries the total and the root
  hash, so an interrupted transfer restarts where it left off or is discarded
  cleanly.
- Replays are idempotent by construction.
- Both clients cap what they will accept (range, total bytes, message count) and
  fail with an actionable message ("that needs 900 MB; try 30 days") rather than
  half-writing.

## 5. What a stolen seed gets, precisely

| Data | Stolen seed alone | With approval from an existing device |
|---|---|---|
| New incoming messages | yes (unavoidable: the seed is the account) | — |
| Messages sent from other devices (mirroring) | no | yes |
| Past history | no | yes, within the chosen range |
| Attachments | no | yes, subject to the budget |

This is the strongest statement the architecture allows without device admission
control, and it is strictly better than XMPP, where a compromised account simply
reads the server-side archive.

## 6. Rejected alternatives

**Server-side archive (the actual MAM model).** Impossible without breaking zero
knowledge: the relay would have to read, key, or at least address your messages
per account. Rejected outright.

**A shared encrypted log on the relays.** The account publishes an append-only
history log at an address derived from its public keys, encrypted under a key
derived from the seed; any device pulls it, no approval, works even if the old
device is gone. This is what "Phase 4 escrow" meant earlier, in plain terms:
*renting storage on a relay so your history outlives your devices.* Rejected as
the default because (a) the key comes from the seed, so a leaked seed decrypts
**all** past history — a single long-term secret guarding everything, which is the
opposite of what forward secrecy buys; (b) it leaves a permanent ciphertext
archive on someone else's server at an address anyone can compute and monitor for
size; (c) it reveals the account's total message volume. **Recommendation: do not
build it.** The encrypted export file covers the "no other device available"
case, and the user keeps the backup.

**Syncing ratchet state.** Impossible without discarding forward secrecy, and two
devices advancing one chain diverge.

**Re-encrypting the past from the peer.** Works only if the peer is online and
kept the plaintext; leaks the recovery to the peer and scales badly.

## 7. Phasing

| Phase | Work | Why in this order |
|---|---|---|
| 1 | Local attachment cache; **encrypted history export/import file** in both clients | Works today, no protocol change; is also the fallback when no other device is available, and the plumbing Phase 2 needs for attachments |
| 2 | Device keys in the device list; `NKS1` framing; ECIES records; approval flow; **live mirroring** | Delivers the visible XMPP-like behaviour (sent on one device, seen on the other) |
| 3 | Back-fill with the range picker (30/60/90/all, default 30), budget caps, progress, resume, approval UI in the Devices dialog | Turns mirroring into "restore and catch up" |
| 4 | (Optional, recommended against) relay-hosted escrow log with per-device key wrapping | Only if "restore with no other device online" ever outweighs the loss of forward secrecy |

## 8. Test plan

- **Format**: bundle round-trip; chunk reorder/truncation/tamper rejection;
  wrong-device key rejection; replay is idempotent.
- **Authority**: a record from a device absent from the signed list is rejected;
  an approval for a different `transfer_id` or with different scopes is rejected;
  an unapproved device cannot obtain back-fill (asserted directly — this is the
  security property).
- **Behaviour**: a carbon makes the sibling show a sent message; sibling read
  state converges both ways; a new device back-fills, then stays in sync on its
  own; a third device joining later gets the same.
- **Robustness**: sibling offline during a send, then reconnects; sender killed
  mid-send; transfer interrupted and resumed; duplicate carbon plus back-fill of
  the same message collapses to one row.
- **Bounds**: range caps, message caps, budget exhaustion, quota exhaustion, and
  a clean actionable failure for a bundle that cannot fit.
- **Interop**: Python↔web in both directions, including a carbon and an
  attachment, so the format is pinned like the rest of the protocol.

## 9. Remaining decisions

1. Range picker defaults are set (30 days; 30/60/90/all). Confirm the labels.
2. Attachment budget default: 100 MB per sync, or smaller for the web (IndexedDB
   quotas are tighter than a desktop disk)?
3. Should a device be able to mirror to siblings *without* approval once it is in
   the list, or only after an existing device approves it? (This plan says
   approval-gated, on the reasoning in §4.3.)