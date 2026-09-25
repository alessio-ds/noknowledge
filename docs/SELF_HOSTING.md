# Self-hosting a relay

A noknowledge **relay** is a dumb, untrusted blob store. It holds opaque
ciphertext addressed by unguessable mailbox ids and a prekey noticeboard. It
never sees an identity, a sender, a recipient, or any plaintext. That is what
makes self-hosting safe and federation trivial: **any relay instance is a
federated node**, and no relay trusts or coordinates with any other.

## Quick start

```bash
git clone <your-fork> noknowledge && cd noknowledge
uv sync --frozen --extra gui

./scripts/run_server.sh --host 0.0.0.0 --port 8000 --data-dir /var/lib/noknowledge
```

`uv sync --frozen` installs exactly the pinned versions from `uv.lock` — use it
on servers so a deployment is reproducible. `uv sync --extra gui` is only needed
if you also run the desktop client on this machine; a relay needs no extras
beyond the base dependencies.

The relay listens on `http://127.0.0.1:8000` by default. Check it:

```bash
curl -s http://127.0.0.1:8000/api/health
# {"status":"ok","version":"0.1.0","mailboxes":0,"messages":0,...}
```

## Configuration

Environment variables (or CLI flags):

| Variable | Default | Meaning |
|---|---|---|
| `NK_HOST` | `127.0.0.1` | bind address |
| `NK_PORT` | `8000` | bind port |
| `NK_DATA_DIR` | `relay_data` | directory holding `relay.db` |
| `NK_MAILBOX_TTL` | `7776000` (90 d) | delete mailboxes idle this long |
| `NK_BLOB_TTL` | `2592000` (30 d) | delete orphan blobs older than this |
| `NK_REQUIRE_HASHCASH` | off | require proof-of-work on mailbox/prekey creation |
| `NK_HASHCASH_BITS` | `20` | difficulty when enabled |
| `NK_ADVERTISE_URL` | *(empty)* | this relay's public URL, published for discovery |
| `NK_KNOWN_RELAYS` | *(empty)* | comma-separated peers to advertise |
| `NK_MAILBOXES_PER_HOUR` | `30` | mailbox creations allowed per client IP per hour |
| `NK_WRITES_PER_MINUTE` | `240` | message/attachment writes per client IP per minute |
| `NK_BUNDLES_PER_HOUR` | `20` | prekey records published per client IP per hour |

`NK_BUNDLES_PER_HOUR` counts both a prekey bundle and a device list (both live on
the prekey noticeboard), so a client that starts up repeatedly publishes at most
two records per start. Raise it only if you front the relay with your own abuse
controls, or run it behind a proxy that hides client IPs.

Per-mailbox message/byte quotas and maximum message sizes live in
`noknowledge/server/config.py` (`Settings`). They are **resource limits only** —
the relay never inspects content.

## Publishing your relay for discovery

Clients learn about relays from the relays they already use. Publish yours so it
propagates:

```bash
NK_ADVERTISE_URL=https://relay.example.com \
NK_KNOWN_RELAYS=https://relay-b.example,https://relay-c.example \
python -m noknowledge.server --host 0.0.0.0 --port 8000
```

or drop a `relays.json` in the data directory (useful for long lists):

```json
{"relays": ["https://relay-b.example", "https://relay-c.example"]}
```

`GET /api/relays` then returns all of them, unauthenticated on purpose:

```bash
curl -s https://relay.example.com/api/relays
# {"relays":["https://relay.example.com","https://relay-b.example", ...],"advertise":"https://relay.example.com"}
```

Clients merge that into their own relay list after probing each candidate's
`/api/health`, up to 8 relays. Discovery is additive — it never removes a relay
someone configured by hand.

Two consequences worth knowing as an operator:

- Your advertised peers become part of other people's relay sets, so only list
  relays you are willing to vouch for.
- Candidates on loopback, LAN or link-local addresses are ignored by clients by
  default (they can opt in with `NK_ALLOW_PRIVATE_RELAYS=1`), so a private relay
  must be added manually by whoever wants to use it.

## systemd

```ini
# /etc/systemd/system/noknowledge-relay.service
[Unit]
Description=noknowledge relay
After=network-online.target

[Service]
User=noknowledge
WorkingDirectory=/opt/noknowledge
Environment=NK_HOST=127.0.0.1
Environment=NK_PORT=8000
Environment=NK_DATA_DIR=/var/lib/noknowledge
ExecStart=/opt/noknowledge/.venv/bin/nk-server
Restart=on-failure
# Harden the service: it needs nothing but its data directory.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/noknowledge

[Install]
WantedBy=multi-user.target
```

## TLS behind a reverse proxy

Clients never rely on TLS for confidentiality — everything is end-to-end
encrypted — but TLS is still worth having for transport integrity and to avoid
looking like an odd plaintext service.

Caddy:

```
relay.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name relay.example.com;

    ssl_certificate     /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;

    client_max_body_size 2m;   # chunks are 1 MiB; messages 256 KiB

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

> Do not enable request bodies larger than the limits in `config.py`; the relay
> enforces them itself, but a smaller proxy limit saves bandwidth.

## Tor hidden service

Because a relay only ever sees mailbox ids and ciphertext, running one as an
onion service is straightforward and hides the operator from clients.

`/etc/tor/torrc`:

```
HiddenServiceDir /var/lib/tor/noknowledge/
HiddenServicePort 80 127.0.0.1:8000
```

Then use `http://<your-onion-address>` in a contact card's relay list. For the
client side, enable **Settings → Route all traffic through a proxy** with
`socks5://127.0.0.1:9050`. Proxy mode is **fail-closed**: if the proxy is
unreachable, the client refuses to connect directly.

## Federation

There is nothing to enable. A relay keeps no global state and no user table, so:

1. run as many relays as you like, anywhere;
2. put their URLs in the relay list of your contact card;
3. the sender writes every message to **all** of them, and the recipient reads
   from whichever answers first.

Consequences:

- Taking one relay down cannot stop a conversation.
- There is no central directory, no account server, and no inter-relay trust.
- A relay operator cannot read, forge, or link anything.
- Relays can be run by friends, by a community, or by you alone.

Relay URLs must be **globally reachable** for your contacts to use them
(`localhost` only works when both peers are on the same machine).

## What the relay stores

```
relay.db
├── mailboxes         id, SHA-256(read token), SHA-256(write token), limits
├── messages          mailbox_id, seq, ciphertext, size, created_at
├── prekey_bundles    bundle_id, signed prekey, signature (no identity keys)
├── prekey_one_time   bundle_id, opk_id, prekey, used
└── blobs             chunk_id, mailbox_id, encrypted chunk, size
```

There is no users table, no public key table, no read receipts table, and no
send/read metadata linking two parties.

## Operations

- **Backups**: copy `relay.db` (and its `-wal`/`-shm` siblings) while the relay
  is stopped, or use `sqlite3 relay.db ".backup backup.db"`.
- **Migration**: copy the data directory to the new host and update your contact
  card's relay list. Because messages replicate, contacts reading from other
  relays are unaffected during the move.
- **Housekeeping** runs hourly: idle mailboxes and orphan blobs are deleted.
  This is garbage collection, never content inspection.
- **Abuse**: the only handle a relay needs is resource limits. Writes to
  nonexistent mailboxes are rejected outright, per-mailbox quotas cap storage,
  and per-IP rate limits cap request volume.

## Security notes for operators

- Keep Python and dependencies patched; run as an unprivileged user.
- The relay is designed to be compromised without consequence, but a compromised
  relay can still deny service and observe traffic volume. Treat it accordingly.
- Serve over TLS or an onion service so that clients' IP addresses are not
  trivially exposed to a network observer.
- Never add content inspection or logging of request bodies — it would break the
  entire security model for no operational benefit.