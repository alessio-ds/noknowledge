# noknowledge Protocol Specification v1

Status: **draft, implementation target**.
Companion documents: `PLAN.md`, `THREAT_MODEL.md`.

---

## 1. Conventions

| Symbol | Meaning |
|---|---|
| `b64(x)` | base64url without padding, of bytes `x` |
| `b32(x)` | Crockford base32, uppercase, no padding |
| `\|\|` | concatenation |
| `JSONc(x)` | canonical JSON: UTF-8, sorted keys, `(",", ":")` separators, no NaN |
| `0^32` | 32 zero bytes |
| `F` | 32 bytes of `0xFF` (X25519 domain separation) |
| `DH(sk, pk)` | X25519 scalar multiplication |
| `AEAD(k, n, pt, ad)` | ChaCha20-Poly1305 encrypt |

All binary fields on the wire are `b64`.

### 1.1 Wire message = relay blob

The relay stores exactly one opaque blob per message. Its structure is:

```json
{
  "v": 1,
  "sid": "b64(16 random bytes)",
  "init": {                     // present only on the first message of a session
    "ek": "b64(32)",            // initiator ephemeral X25519 public key
    "spk_id": 7,                // recipient signed-prekey id
    "opk_id": 42                // recipient one-time-prekey id, or null
  },
  "hdr": {                      // Double Ratchet header, authenticated as AEAD AD
    "dh": "b64(32)",            // sender's current ratchet public key
    "pn": 0,                    // messages in previous sending chain
    "n": 0                      // index in current sending chain
  },
  "nonce": "b64(12)",
  "ct": "b64(ciphertext)"
}
```

`sid` is a random pseudonymous session handle. It lets the recipient route a
message to a session **before** decryption. It is not derived from any identity.

The AEAD associated data is:

```
ad = b"nk/v1/msg" || JSONc(init or {}) || JSONc(hdr)
```

which binds the plaintext to the header, session and protocol version.

---

## 2. Primitives

| Purpose | Algorithm |
|---|---|
| Identity signature | Ed25519 |
| Key agreement | X25519 |
| KDF | HKDF-SHA256 |
| Chain KDF | HMAC-SHA256 |
| AEAD | ChaCha20-Poly1305 |
| Hash | SHA-256 |

---

## 3. Identity

```
seed  = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" || passphrase, 2048, 64)   # BIP39
root  = HKDF-SHA256(ikm=seed, salt=b"", info=b"noknowledge/identity/v1", len=64)
ed_seed = root[0:32]   -> Ed25519 private key   (IK_sign)
x_seed  = root[32:64]  -> X25519  private key   (IK_dh)
id      = b32(SHA256(b"nk-id" || ed_pub || x_pub))[:26]
```

An identity is `(IK_sign, IK_dh, id)`. `id` is derived offline from public keys
and is **never transmitted to a relay**.

### 3.1 Prekey bundle

A recipient publishes, under a random 16-byte `bundle_id`:

```json
{
  "v": 1,
  "bundle_id": "b64(16)",
  "idh": "b64(32)",          // recipient IK_dh public key
  "isign": "b64(32)",        // recipient IK_sign public key
  "spk_id": 7,
  "spk": "b64(32)",          // signed prekey, X25519
  "spk_sig": "b64(64)",      // Ed25519(IK_sign, b"nk/spk/v1" || bundle_id || spk_id || spk)
  "opks": [                  // one-time prekeys
    {"opk_id": 42, "opk": "b64(32)"}
  ]
}
```

The relay returns a bundle plus **at most one** unused OPK, which it marks used
atomically. If none remain, `opk` is `null` and X3DH proceeds without `DH3`.

The `spk_sig` is verified against the `isign` **taken from the contact card**,
never from the relay response. A malicious relay therefore cannot substitute
keys.

---

## 4. Contact card

Cards are exchanged out of band (QR, copy/paste, any channel).

```
nk://1/<b64( DEFLATE( JSONc(payload) ) )>
```

```json
{
  "v": 1,
  "id": "26-char identity id",
  "isign": "b64(32)",
  "idh": "b64(32)",
  "bundle": "b64(16)",
  "inbox": {"id": "b64(16)", "w": "b64(32)"},
  "relays": ["https://relay1.example", "https://relay2.example"],
  "name": "optional self-chosen label",
  "sig": "b64(64)"
}
```

`sig` = `Ed25519(IK_sign, b"nk/card/v1" || JSONc(payload without "sig"))`.

- `inbox` is the recipient's write capability: `id` + write token `w`.
- `relays` is the recipient's **relay set** (PLAN §8.2). The sender replicates
  the first message to all of them.
- A card is self-authenticating: IDs, prekeys and relay URLs are all covered by
  `sig`. Possession of the card is what authorizes contact.

---

## 5. Handshake (sender-anonymous X3DH)

Classic X3DH puts the initiator's identity key `IK_a` in the clear, which would
hand the relay the sender's identity. noknowledge therefore uses an
**anonymous X3DH** variant: the initiator contributes only an ephemeral key,
and proves its identity *inside* the encrypted payload (sealed-sender style).

Initiator A, given B's card:

```
verify card signature with card.isign
fetch bundle(bundle_id) from any relay in card.relays
verify spk_sig with card.isign
EK = new X25519 keypair
RK = new X25519 keypair            # initial Double Ratchet key

DH1 = DH(EK, B.IK_dh)
DH2 = DH(EK, B.SPK)
DH3 = DH(EK, B.OPK)                # omitted if no OPK available
SK  = HKDF-SHA256(ikm = F || DH1 || DH2 || DH3,
                  salt = 0^32, info = b"noknowledge/x3dh/v1", len = 32)
```

Then Alice initialises the Double Ratchet (§6):

```
RK_root, CKs = KDF_RK(SK, DH(RK, B.SPK))
DHs = RK ; DHr = B.SPK ; Ns = 0 ; Nr = 0 ; PN = 0
sid = random 16 bytes
```

The first wire message carries `init = {ek: EK_pub, spk_id, opk_id}` and
`hdr = {dh: RK_pub, pn: 0, n: 0}`.

Recipient B, on receiving a message with `init`:

```
DH1 = DH(B.IK_dh_priv, EK)
DH2 = DH(B.SPK_priv,  EK)
DH3 = DH(B.OPK_priv,  EK)          # if opk_id present and unused
SK  = same HKDF
RK_root, CKr = KDF_RK(SK, DH(B.SPK_priv, init_hdr.dh))
DHs = B.SPK ; DHr = init_hdr.dh
```

Both sides now share a root key and a sending/receiving chain.

### 5.1 Sender authentication (inside the ciphertext)

The first envelope of a session includes:

```json
"auth": {
  "id": "26-char sender identity id",
  "isign": "b64(32)",
  "idh": "b64(32)",
  "sk_commit": "b64(32)",
  "sig": "b64(64)"
}
```

- `sk_commit = SHA256(b"nk/sk-commit/v1" || SK)`.
- `sig = Ed25519(IK_sign_a, b"nk/auth/v1" || sid || JSONc(init) || sk_commit)`.

The recipient recomputes `SK` from the handshake and checks `sk_commit`, then
verifies `sig`. This proves the sender knew both the session key and the private
identity key, binding identity to session. The relay never sees either.

Recipients **must** reject a first message whose `auth` fails to verify.

---

## 6. Double Ratchet

State: `RK, CKs, CKr, DHs, DHr, Ns, Nr, PN, MKSKIPPED`.

```
KDF_RK(rk, dh_out) = HKDF-SHA256(ikm=dh_out, salt=rk, info=b"nk/ratchet-root/v1", len=64)
                     -> (first 32 = new RK, last 32 = new CK)

KDF_CK(ck) = (mk = HMAC-SHA256(ck, 0x01),
              next_ck = HMAC-SHA256(ck, 0x02))

AEAD key = mk, nonce = 12 random bytes (transmitted)
```

### 6.1 Encrypt

```
mk, CKs = KDF_CK(CKs)
hdr = {dh: DHs_pub, pn: PN, n: Ns}
ct  = AEAD(mk, nonce, envelope_plaintext, AD(hdr))
Ns += 1
```

### 6.2 Decrypt

1. If `hdr.dh != DHr` and this is not a skipped key: perform a DH ratchet step
   (`PN = Ns`, `Nr = 0`, `DHr = hdr.dh`, `RK, CKr = KDF_RK(RK, DH(DHs, DHr))`,
   then generate a new `DHs` and `RK, CKs = KDF_RK(RK, DH(DHs_new, DHr))`).
2. If `hdr.n < Nr`, look the key up in `MKSKIPPED`; reject if absent (replay or
   too-old message).
3. If `hdr.n > Nr`, derive and cache up to `MAX_SKIP` (1000) skipped message
   keys; cache overflow is a hard error.
4. Derive `mk`, `Nr += 1`, decrypt.
5. On AEAD failure, the session state is **not** advanced and the message is
   dropped (it may be an unrelated message sharing the mailbox).

### 6.3 Replay and idempotency

- `MKSKIPPED` keys are deleted once used, so a replayed ciphertext fails.
- Envelope `id` (UUID4) is kept in a bounded seen-set per contact; duplicates are
  dropped before decryption.

---

## 7. Envelope (plaintext inside the ratchet)

```json
{
  "v": 1,
  "type": "text | file | receipt | typing",
  "id": "uuid4-hex",
  "ts": 1730000000000,
  "auth": { ... },              // first message of a session only
  "body": { ... },
  "pad": "b64(random)"
}
```

Padded so `len(JSONc(envelope))` is a multiple of 256 bytes, minimum 256,
maximum for `text` 2048. The `pad` field is filled with random base64 to reach
the bucket, hiding plaintext length.

Bodies:

| type | body |
|---|---|
| `text` | `{"text": "..."}` |
| `file` | `{"name","mime","size","sha256","chunks":[{"id","key","nonce"}]}` |
| `receipt` | `{"of": "<envelope id>"}` |
| `typing` | `{}` — never stored, no receipt |

---

## 8. Relay HTTP API

Base path `/api`. Tokens are sent as headers, never in URLs or logs:

- `X-NK-Read: b64(read_token)`
- `X-NK-Write: b64(write_token)`

The relay stores `SHA256(token)` and compares in constant time.

| Method | Path | Auth | Body / Response |
|---|---|---|---|
| `POST` | `/api/mailbox` | optional hashcash | → `{mailbox_id, read_token, write_token}` |
| `GET` | `/api/mailbox/{id}?after_seq=&wait=` | read | → `{messages:[{seq,blob}], next_seq}` |
| `POST` | `/api/mailbox/{id}/messages` | write | raw blob → `{seq}` |
| `POST` | `/api/mailbox/{id}/ack` | read | `{upto_seq}` → `{deleted}` |
| `DELETE` | `/api/mailbox/{id}` | read | → `{deleted_messages, deleted_blobs}` |
| `POST` | `/api/prekeys` | none | bundle JSON → `{bundle_id}` |
| `GET` | `/api/prekeys/{bundle_id}` | none | → bundle JSON with ≤1 consumed OPK |
| `POST` | `/api/blob` | write + `X-NK-Mailbox` | raw chunk → `{chunk_id}` |
| `GET` | `/api/blob/{chunk_id}` | read + `X-NK-Mailbox` | → raw chunk |
| `GET` | `/api/health` | none | `{status, version, mailboxes, messages, bytes}` |

### 8.1 Errors

| Status | Meaning |
|---|---|
| 400 | malformed request |
| 401 | missing/invalid capability token |
| 404 | mailbox, bundle or blob does not exist |
| 405 | wrong HTTP method |
| 413 | payload too large |
| 429 | mailbox quota or rate limit exceeded |
| 503 | relay temporarily unavailable |

A write to a nonexistent mailbox returns **404** and stores nothing. This is the
mechanism that replaces pyzk's expiry queue: undeliverable mail is never accepted.

### 8.2 Limits (defaults)

| Limit | Value |
|---|---|
| max blob per message | 256 KiB |
| max chunk | 1 MiB |
| max messages per mailbox | 1000 |
| max bytes per mailbox | 64 MiB |
| long-poll max wait | 60 s |
| prekey bundles | 10 per source / hour |
| mailbox idle TTL (housekeeping) | 90 days |
| blob TTL (housekeeping) | 30 days |

---

## 9. Versioning

`v` appears in the card, wire message, bundle and envelope. A receiver rejects
unknown major versions. Additive fields are ignored; semantics changes bump `v`.
The relay stores blobs opaquely and never parses them, so protocol evolution
does not require relay upgrades.