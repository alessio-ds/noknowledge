# noknowledge Threat Model

Status: **draft, implementation target**.

---

## 1. Scope and security goals

noknowledge lets two parties exchange messages and files through relays that
learn **nothing about who is talking to whom or what they say**. Relays are
untrusted infrastructure — anyone may run one, and the system must remain secure
even if every relay is hostile.

### Primary goals

| # | Goal |
|---|---|
| G1 | **Confidentiality** — a relay (or any network observer) cannot read message or attachment plaintext. |
| G2 | **Sender anonymity** — a relay cannot determine which identity sent a message. |
| G3 | **Recipient anonymity** — a relay cannot determine which identity owns/reads a mailbox. |
| G4 | **No linkage** — a relay cannot construct an identity graph (who talks to whom). |
| G5 | **Integrity & authenticity** — recipients can verify who sent a message, and messages cannot be modified undetected. |
| G6 | **Forward secrecy & post-compromise security** — compromise of long-term keys does not expose past sessions, and an active session heals after a compromise. |
| G7 | **Availability under relay failure** — loss of one or more relays does not lose messages. |
| G8 | **Censorship resistance** — there is no central node whose seizure disables the network. |

### Explicit non-goals (v1)

- **Traffic analysis resistance.** A global network observer can still correlate
  mailbox traffic by timing and volume. SOCKS5/Tor mode mitigates IP linkage but
  the design does not add cover traffic or per-message delays.
- **Endpoint security.** Malware or an attacker with the device and an unlocked
  vault defeats all of this. Local storage encryption protects data at rest only.
- **Groups and metadata-private discovery.** See `PLAN.md` §0. History sync *is*
  supported, but under human control: see A8 below for what a stolen seed gets.
- **Deniability against a recipient.** A recipient can prove to a third party who
  sent a message, because the first message carries an Ed25519 signature.

---

## 2. Assets

| Asset | Where it lives | Protection |
|---|---|---|
| Identity private keys (`IK_sign`, `IK_dh`) | client only | vault encryption at rest |
| Prekey private keys (`SPK`, `OPK`) | client only | vault encryption at rest |
| Session/ratchet state | client only | vault encryption at rest |
| Message plaintext | client only | E2E AEAD |
| Attachment plaintext | client only | E2E AEAD |
| Mailbox read/write tokens | client + relay (hash only) | bearer capability |
| Relay-visible metadata | relay | mailbox id, blob size, timing only |

---

## 3. Adversaries

### A1 — Honest-but-curious relay (primary)
Follows the protocol but records everything it can. **Must learn:** mailbox ids,
blob sizes, timestamps, IPs. **Must not learn:** content, identities, or linkage.
Mitigated by: opaque blobs, hashed tokens, capability addressing, anonymous X3DH,
and a **sealed device list** (§9 of the protocol) that carries the account's
mailboxes only inside a box keyed by the account's public keys — so a relay
cannot group one account's mailboxes or tie the record to an identity id.

### A2 — Malicious relay
May tamper with, drop, reorder, replay, or fabricate traffic; may substitute
prekey bundles; may return forged mailbox contents.
Mitigated by:
- card and bundle signatures (relay cannot substitute prekeys — client verifies
  `spk_sig` against the `isign` from the signed card);
- AEAD with header binding (tamper → decryption failure);
- replay rejection via ratchet state + envelope `id` seen-set;
- **multi-relay replication**: dropping an entire relay only delays delivery,
  and the recipient can cross-check replicas.

### A3 — Network attacker (MITM)
Bit-for-bit tampering or observation of transport. Confirmed by: E2E AEAD and
signatures; TLS is defense-in-depth only, never relied upon. Tampered blobs fail
authentication.

### A4 — Spammer / DoS
No account required, so abuse must be handled by capability + quota:
- writes to a nonexistent mailbox are rejected (404) — the pyzk problem;
- per-mailbox message/byte quotas force ack before more can land;
- per-IP token bucket on create/write/upload;
- optional hashcash on mailbox and prekey creation.
Residual: an attacker holding a valid write capability can spam that one mailbox
up to its quota. Inherent to "possession of the card authorizes contact."

### A5 — Malicious contact
Holds a valid card and session. Can send abusive content. Mitigated by local
blocking and mailbox rotation; not a protocol problem.

### A6 — Relay collusion
Multiple relays comparing logs. Because there is no identity mapping at any
relay and `sid`/mailbox ids are pseudonymous, collusion yields a set of
pseudonymous mailboxes and their traffic patterns, not real identities. Residual:
statistical linkage if a party is deanonymized out of band.

### A8 — Thief with the seed phrase

Someone who obtains the 24 words can restore the identity, register a device and
read everything sent to the account from then on. That is inherent: the seed *is*
the account, and no protocol can distinguish the rightful owner from a holder of
the key.

What the design can do is keep the **past** out of their hands:

| Data | Seed alone | Seed plus a human clicking Approve on an existing device |
|---|---|---|
| New incoming messages | yes (unavoidable) | — |
| Messages sent from other devices (mirrors) | no | yes |
| Past history | no | yes, within the approved range |
| Attachments | no | yes, subject to the budget |

The gate is the `approval` record in §10 of the protocol: a device sends data only
to devices its human approved. A thief's device may ask, and the legitimate
devices will show the request — including the device id and the name it claims,
which is what the owner compares against — but nothing moves until a person on
that device approves. Revoking approval stops mirrors immediately.

**Residual risk.** A thief can still: read future traffic, send messages as the
account, register devices (which the owner will see in *My devices* and can
identify as unknown), and be approved by a careless owner who clicks Approve on a
request they did not expect. The defence is the same as for any seed: keep it
safe, and treat an unexpected approval prompt as an incident.

---

### A7 — Relay operator who is also the recipient
If you talk to someone who runs the relay, they can see that a mailbox is
receiving traffic (though not the sender's identity). Mailbox rotation is the
mitigation, deferred to hardening.

---

## 4. Protocol-specific threats and mitigations

| Threat | Mitigation |
|---|---|
| Relay substitutes recipient prekeys | Bundle signed; `spk_sig` verified against card `isign` |
| Relay injects a message into a session | AEAD + ratchet; forgery requires session keys |
| Relay replays a ciphertext | Ratchet one-time keys deleted on use; envelope `id` seen-set |
| Relay reorders messages | Out-of-order keys cached (`MKSKIPPED`, cap 1000) |
| Relay drops messages | Sender outbox re-delivers until receipt; multi-relay |
| Relay correlates messages into one conversation | `sid` is pseudonymous; note that same-`sid` messages are groupable (accepted, G4 is about identity linkage) |
| Length leaks plaintext size | Padding to 256-byte buckets |
| Nonce reuse | 12-byte random nonces per message with per-message keys (key uniqueness makes reuse moot) |
| Key/nonce reuse across purposes | Distinct HKDF `info` labels and separate Ed25519/X25519 keys |
| Silent downgrade | Version field in every structure; unknown major versions rejected |
| Mailbox squatting | Mailbox ids are unguessable random values distributed only via cards |
| Disk-fill via blobs | Blob upload requires a write capability; per-mailbox byte quota |
| Prekey exhaustion | Bundles replenish; X3DH tolerates missing OPK (3-DH fallback) |
| Relay injects a device into an account | Device list is signed by the account key; a relay cannot add a mailbox |
| Relay links an account's mailboxes | Device list is sealed under a key derived from the account's public keys; the relay sees only a hash address and an opaque box |
| Relay forges or alters a device record | Every device record is signed by the sending device and every header byte is AEAD associated data; ordering is bound by a per-item key label |
| Relay truncates a history transfer | Item count and a running hash chain are checked against the `complete` record; a short transfer is reported, not accepted silently |
| A thief with the seed pulls history | A device sends data only to devices its human approved; a request alone transfers nothing |
| A record is replayed | Transfer ids are remembered; every merge is idempotent, so a replay changes nothing |

---

## 5. Cryptographic guarantees and their limits

- **Forward secrecy** holds from the moment a ratchet step occurs; the initial
  session key is derived from X3DH and a fresh ratchet key.
- **Post-compromise security** holds after the next DH ratchet step, as in
  Signal's Double Ratchet.
- **Sender authentication is inside the ciphertext** (`auth` block). The relay
  never sees the sender's identity; the recipient verifies it after decryption
  (sealed-sender style).
- **Anonymous X3DH trades initiator authentication-in-handshake for sender
  anonymity.** The first message is unauthenticated *until decrypted*; identity
  is proven by the Ed25519 `auth` signature bound to the session key
  (`sk_commit`). A recipient must discard any first message whose `auth` fails.
- **No deniability**: the `auth` signature is a transferable proof of authorship.
  This is a deliberate trade-off to get recipient-verifiable identity without a
  directory; it is listed as a non-goal.

---

## 6. What a fully compromised relay can still do

Even with root on every relay, an adversary can:

1. deny service (drop or withhold blobs);
2. observe mailbox-level traffic volumes and timing;
3. link IP addresses to mailbox polling (unless Tor/proxy mode is used);
4. create their own cards and identities like anyone else.

They **cannot**: read content, learn identities from protocol traffic, forge
messages or receipts, substitute prekeys undetected, or prevent peers from
migrating to other relays and re-delivering from the outbox.

---

## 7. Verification plan

| Claim | How it is tested |
|---|---|
| Confidentiality | relay stores only ciphertext; test asserts plaintext absent from DB |
| No identity on the wire | test greps all relay request bodies for identity/prekey bytes |
| Prekey substitution fails | test flips a bundle byte, expects verification failure |
| Tamper detection | test mutates each ciphertext byte, expects decryption failure |
| Replay rejected | test re-sends a captured blob, expects rejection |
| Out-of-order delivery | test shuffles and skips messages, expects correct plaintext |
| Forward secrecy (behavioral) | test that a new ratchet key appears after a reply |
| Availability | `test_relay_failover`: kill one relay mid-conversation, delivery completes |
| Quota/spam | test 404 nonexistent, 429 over quota, 401 bad token |
| Padding | test that two different-length plaintexts produce equal ciphertext length |
| Multi-device delivery | test that a second device on one account receives a copy, and that a recovered device joins the list and starts receiving |
| Device list privacy | test that the stored record leaks no identity keys, mailbox ids or write tokens |
| Legacy fallback | test that a peer with no published device list is still reached at the card inbox |
| Stolen seed cannot pull history | test that a restored device's request transfers nothing until a human approves, and that future traffic still arrives |
| Device channel integrity | tests flip header bytes, forge the sender key, use the wrong recipient key, and truncate a transfer |
| Mirroring | tests assert a sent message and a read state appear on the sibling device, in both directions, exactly once |