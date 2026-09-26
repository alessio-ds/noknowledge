# History sync across devices

**Status:** design proposal, not implemented. Everything below is compatible with
the current relay (no server change) and with the existing guarantees: the relay
learns no content and no sender↔recipient linkage.

## 1. The problem, stated precisely

An account is the seed phrase; a device is one mailbox with its own prekeys and
its own Double Ratchet sessions. A device restored from the seed therefore gets
*new* messages, and nothing else, because:

- **Ciphertext cannot be replayed.** Every message was sealed with a one-time key
  from the ratchet chain of the device it was sent to. A different device holds no
  such key, and the keys it consumed are gone by design. Forward secrecy is not a
  bug to route around; a second device fundamentally cannot read the first
  device's traffic.
- **The peer cannot be asked to re-send the past** for a general case (it may be
  offline, may not have kept it, and would be re-running key agreement at scale).
- **History is device-local and device-keyed.** The Python client seals
  `local.db` under a key from the OS keyring or `local.key`; the web client seals
  IndexedDB under a key derived from the *account password* with a per-device
  salt. Neither key exists on any other device.

So syncing history means **one device that holds plaintext actively handing it to
another**, over a channel that must be authenticated as "same account, different
device" and encrypted to that specific device.

## 2. What must not change

| Invariant | Why it constrains the design |
|---|---|
| Relay sees no content | The transfer must be AEAD-sealed end to end; mailbox blobs stay opaque. |
| Relay sees no linkage | No new derivable address per account, no plaintext account id in the blob header. |
| Per-device sessions stay separate | History must never be merged into ratchet state, and no session state moves between devices. |
| No server change | The transfer rides the existing mailbox `POST /message` path. |
| Forward secrecy for live traffic | Untouched: the sync channel is a separate key agreement, used once. |

## 3. Recommended design: device-to-device transfer, approval-gated

### 3.1 Device keys (the missing piece)

A device today is just a mailbox. Give each device its own keypair, published in
the **account-signed device list** so any device of the account can verify it:

```json
{
  "device": "b64(16)",
  "inbox": {"id": "b64(16)", "w": "b64(32)"},
  "relays": ["https://relay.example"],
  "bundle": "b64(16)",
  "name": "laptop",
  "sdev":   "b64(32)",   // device Ed25519 public key — authenticates the sender
  "sagree": "b64(32)"    // device X25519 public key — encrypts to this device
}
```

- Generated at provision, private halves stored in the local encrypted store.
- The account key signs the list, so a relay cannot inject a device, and a device
  cannot impersonate another.
- Unknown fields are ignored by existing parsers, so lists stay forward/backward
  compatible; a device whose entry lacks `sagree` simply cannot sync yet.
- Live messaging keeps using the current prekey bundles. This is additive.

### 3.2 Sync channel (ECIES, one transfer per offer)

The receiving device is often offline, so this is store-and-forward:

1. Sender generates an ephemeral X25519 keypair `e`.
2. `shared = X25519(e_priv, recipient.sagree)`,
   `key = HKDF-SHA256(shared, salt=transfer_id, info=b"nk/history/v1", 32)`.
3. Each chunk is `ChaCha20-Poly1305(key_chunk, nonce, plaintext)` where
   `key_chunk` is HKDF-expanded from `key` with the chunk index, and the
   transfer id + chunk index are the AEAD associated data (so chunks cannot be
   reordered, truncated or spliced between transfers).
4. The record written to the recipient's mailbox is opaque:

```
"NKS1" | u8 version | u8 kind | u16 reserved | canonical JSON header | payload
```

| kind | name | payload |
|---|---|---|
| 1 | `request` | who is asking, and what range |
| 2 | `offer` | total chunks, bytes, sha256 of the whole bundle, range |
| 3 | `chunk` | `nonce`, `ciphertext` (sealed), header carries `eph_pub`, `from_device` |
| 4 | `complete` | root hash, message count |
| 5 | `approval` | proof that an existing device approved this transfer |

The header carries `eph_pub`, `from_device`, and an Ed25519 signature by the
sender's device key over `(kind, transfer_id, header fields)`. The recipient
accepts a record only if `from_device` is in its **own last-known account-signed
device list** and the signature checks out.

Routing: the mailbox already carries opaque blobs, so `sync()` needs to tell a
ratchet envelope from a sync record before attempting to decrypt. The `NKS1`
magic prefix does that; unrecognized blobs keep the existing "retry a few times,
then ack" behaviour so a poison blob cannot wedge a mailbox.

### 3.3 Approval is the security decision, not an afterthought

The seed phrase already lets anyone register a device and read **new** messages —
that is unavoidable, because the seed *is* the account. History is different: it
exists only as plaintext on devices that already have it. So:

- A freshly restored device may **ask**.
- An existing device must **approve** before any bundle leaves it, and the
  approval is a signature by that device's key over `(transfer_id, new_device_id)`.
- A request with no valid approval is ignored; the requesting device shows
  "waiting for approval on another device".

Without this, a stolen seed silently exfiltrates every past conversation from
every device that is online — strictly worse than the current situation, where a
stolen seed yields future messages only.

### 3.4 What is in a bundle

Canonical JSON, zlib-compressed, then chunked (target ~3 MiB per chunk, bounded by
the relay's chunk/message limits):

```json
{
  "v": 1,
  "from_device": "b64(16)",
  "created": 1730000000000,
  "contacts":  [{"id": "...", "isign": "...", "idh": "...", "bundle": "...",
                 "inbox": {...}, "relays": [...], "nickname": "...",
                 "verified": false, "created_at": 0}],
  "messages":  [{"contact_id": "...", "direction": "received",
                 "type": "text", "body": {...}, "remote_id": "...",
                 "ts": 0, "state": "read"}],
  "attachments": [{"sha256": "...", "name": "doc.pdf", "mime": "...",
                   "chunks": ["b64", "..."]}],
  "range": {"since": 0, "until": 1730000000000}
}
```

Merge rules (both clients):

- **Contacts**: by identity id. Keep the local nickname if the user set one;
  never overwrite `verified`.
- **Messages**: dedup on `(contact_id, remote_id, direction)` — the same key the
  clients already use to ignore duplicate deliveries. Local ids are regenerated.
- **Receipt state**: last writer wins by the newer of the two, so syncing does
  not resurrect "unread" on a device where it was read.
- **Attachments**: content-addressed by sha256 into the local cache; identical
  bytes on both sides are stored once.
- Everything is idempotent, so a replayed or resumed transfer is harmless.

### 3.5 Prerequisite: a local attachment cache

Today the attachment *manifest* (key, nonces, chunk ids, sha256) is in the message
body, but the ciphertext chunks live in a *mailbox* — the peer's, for a file we
sent. So a device cannot produce the bytes of a file it sent, which would make
synced messages reference attachments nobody can fetch.

Fix, useful on its own: when sending or downloading, keep the chunk ciphertext in
a local blob table (`local_blobs(chunk_id, ciphertext, size, created_at)`) and
prefer it on download. This also makes old attachments survive relay TTL and
removes a network round trip.

## 4. Why not the alternatives

**A shared encrypted log on the relays.** The account publishes an append-only,
seed-encrypted history log at a derivable address; any device pulls it, no
approval, works when the source device is gone. Rejected as the default because
(a) the log key is derivable from the seed, so a leaked seed decrypts *all* past
history, converting a forward-secret system into one with a single long-term
secret; (b) it leaves a permanent ciphertext archive on relays; (c) it reveals
the account's message volume at one address. It is a reasonable **opt-in**
feature (Phase 4) for users who value "restore anywhere" over those properties,
and it can be built on the same bundle format with the bundle key wrapped per
device instead of ECIES.

**Syncing ratchet state.** Impossible without discarding forward secrecy, and two
devices advancing one chain diverge.

**Re-sending the old ciphertext.** No device holds another device's message keys.

**Peer re-encryption ("ask your contact to resend").** Works only if the peer is
online and kept the plaintext, scales badly, and leaks the recovery to the peer.

## 5. Phasing

| Phase | Work | Value | Rough size |
|---|---|---|---|
| 1 | Local attachment cache; manual **encrypted history export/import file** (passphrase- or seed-keyed) in both clients | Moves history to a new machine today, no protocol change, no new threats | ~1 day |
| 2 | Device keys in the device list; `NKS1` sync records; ECIES bundle transfer; approval flow | Real sync, one-shot, source device must be online once | ~2–3 days |
| 3 | UI in both clients: "Request history" on the new device, prompt on the old one, progress, resume, range picker (all / 30 days / 7 days), and per-device caps | Makes it usable and bounded | ~2 days |
| 4 | Optional relay-hosted escrow log, per-device key wrapping | Restore without any other device online | ~2–3 days, opt-in only |

Phase 1 is worth doing regardless: it is the fallback whenever no other device is
available, and it is the plumbing Phase 2 needs for attachments.

## 6. Client-specific notes

**Python GUI.** The transfer runs on the existing `Worker` thread with a progress
signal; the approval prompt is a modal in the Devices dialog. `local.db` gains
`local_blobs`; the export file is written through `QFileDialog` like any
attachment. Store-key source (keyring vs `local.key`) is irrelevant to sync, since
the channel does not use it.

**Web.** Same protocol, same bundle format. Constraints to respect: IndexedDB
quotas (cap the default range and surface `QuotaExceededError` as "sync the last
30 days instead"), no filesystem (export is a download; import is a file input),
and the page can be closed mid-transfer (so transfers must be resumable and the
UI must show partial progress honestly). The store key is password-derived and
per-device, so it must not be involved in the transfer key.

**Interop.** The bundle format, `NKS1` framing and ECIES construction go into
`PROTOCOL.md` and get vectors, so web↔desktop sync works like the rest of the
protocol. The interop test would gain a case: Python device A → web device B.

## 7. Test plan

- Format: bundle round-trip, chunk reorder/truncation rejection, tamper
  rejection, wrong-device key rejection, replay is idempotent.
- Authority: a record whose `from_device` is absent from the signed list is
  rejected; an approval signature for a different `transfer_id` is rejected.
- Behaviour: two devices converge on the same history; a third device joining
  later gets the same; a *seed-only* device cannot obtain history without
  approval (the security property, asserted directly).
- Robustness: interrupt mid-transfer and resume; chunk delivered twice; source
  device goes offline after the offer.
- Bounds: range caps, message caps, quota exhaustion, and a bundle larger than
  the mailbox quota fails cleanly with a smaller-range suggestion.
- Interop: Python↔web both directions, including an attachment.

## 8. Decisions needed

1. Approval-gated (recommended) or automatic sync?
2. Default range: last 30 days, or everything up to a size cap?
3. Attachments included by default, or metadata only with on-demand fetch?
4. Is the Phase 4 relay escrow wanted at all, given it trades forward secrecy for
   convenience?