# Architecture

## Overview

Three processes talk over TCP: two `client/client.py` (or `gui/chat_gui.py`) instances
and one `server/server.py` relay. Every connection is wrapped in TLS (Phase 6) end to
end between each client and the server — but the server is a **relay, not a trusted
third party for message content**: it routes envelopes by username and stores
passwords (hashed) and public keys, but the AES-GCM session key and RSA private keys
never reach it. The diagram below shows both boundaries at once: the outer TLS tunnels
(what protects the pipe) and the inner end-to-end layer (what protects the content,
even from the server itself).

![Architecture diagram: Client A and Client B each run SecureChatClient with local RSA and per-session ECDH keys, connected to server/server.py's relay over two separately TLS-pinned tunnels; the relay's envelope router and user store (dark green) only ever see routing metadata, password hashes, and RSA public keys, while a direct dotted line shows the end-to-end signed-ECDH-handshake-then-AES-GCM-and-RSA-PSS layer running between the two clients, invisible to the server.](architecture_diagram.png)

A high-resolution version is also at [`architecture_diagram.png`](architecture_diagram.png)
(2352px wide) and as a zoomable vector at [`architecture_diagram.svg`](architecture_diagram.svg).

<details>
<summary>Mermaid source (for future edits — re-render with `npx @mermaid-js/mermaid-cli`)</summary>

```mermaid
flowchart LR
    subgraph ClientA["Client A (client.py / chat_gui.py)"]
        A_UI["Conversation + Wire Log UI"]
        A_Logic["SecureChatClient\n(register/login, ECDH handshake,\nAES-GCM encrypt/decrypt, RSA sign/verify)"]
        A_Keys["Local keys:\n- RSA private key (data/keys/*.pem)\n- ECDH private key (per-session, in memory only)"]
        A_UI --- A_Logic
        A_Logic --- A_Keys
    end

    subgraph ClientB["Client B (client.py / chat_gui.py)"]
        B_UI["Conversation + Wire Log UI"]
        B_Logic["SecureChatClient\n(register/login, ECDH handshake,\nAES-GCM encrypt/decrypt, RSA sign/verify)"]
        B_Keys["Local keys:\n- RSA private key (data/keys/*.pem)\n- ECDH private key (per-session, in memory only)"]
        B_UI --- B_Logic
        B_Logic --- B_Keys
    end

    subgraph Server["server/server.py (relay)"]
        S_Route["Envelope router\n(register/login/handshake/chat by 'to' field)"]
        S_Store["server/db.py (SQLAlchemy)\nSQLite / PostgreSQL:\n- PBKDF2 hashes + RSA PUBLIC keys\n- durable lockouts + security events\n- bounded ciphertext + routing history"]
        S_Route --- S_Store
    end

    A_Logic <-->|"TLS tunnel #1\n(certs/server.crt pinned)"| Server
    Server <-->|"TLS tunnel #2\n(certs/server.crt pinned)"| B_Logic

    A_Logic -.->|"end-to-end: signed ECDH handshake,\nthen AES-256-GCM + RSA-PSS\nsigned chat envelopes"| B_Logic

    classDef canSee fill:#1a3d1a,color:#e8e8e8,stroke:#2f6b2f;
    classDef cannotSee fill:#3d1a1a,color:#e8e8e8,stroke:#6b2f2f;
    class S_Route,S_Store canSee;
```

</details>

## What the server CAN see

These values now also feed the SQL persistence described under
[What the server stores](#what-the-server-stores); no end-to-end decryption is added.

- Usernames and the routing metadata of every envelope (who is talking to whom, and
  when — it decides delivery by the `to` field).
- Each user's PBKDF2 password *hash* (never the plaintext password — see
  `auth/password_hash.py`) and RSA *public* key (`server/user_store.py`), both
  submitted once at registration.
- Opaque ECDH public keys during the handshake, and opaque AES-GCM ciphertext/tag for
  every chat message — bytes it can relay but not read, since it never holds the
  session key.
- The plaintext of the register/login envelope *as JSON, before TLS encrypts it for
  transit* — i.e. the server, as the TLS endpoint, necessarily decrypts the connection
  to read routing envelopes. This is why the AES-GCM/RSA layer for chat *content*
  matters even though TLS is also present: TLS protects data in transit to the server,
  not from the server itself. A password is the one piece of data that has no
  additional application-layer protection beyond TLS — see "Known limitations" in the
  main [README.md](../README.md).

## What the server stores

`server/db.py` creates schema v1 on startup, selected by `DATABASE_URL` (default:
`data/securechat.db`; PostgreSQL uses `postgresql+psycopg://...`). The shared SQLAlchemy
Core schema and transaction adapter can be reused by later transports without changing
client cryptography. See [Database](../README.md#database) for the full column schema,
configuration, migration commands and versioning policy.

- `users`: the existing PBKDF2 encoded hashes, RSA public PEM keys, usernames and
  account creation timestamps. Legacy JSON imports preserve hashes exactly.
- `login_lockouts`: failure counts, exact sliding-window failure timestamps, most
  recent failure time, lock expiry and backoff tier. Restarting preserves locks, and
  the relay still checks lock status **before PBKDF2**. Source-address limits remain
  in memory.
- `security_events`: timestamps, event types, usernames, peer addresses and structured
  metadata in JSON, plus an import identity for idempotent legacy migration. The JSONL
  mirror remains the read-only dashboard's source; SQL and file writes are separate.
- `relayed_envelopes`: a bounded audit history of online chat/handshake forwarding,
  containing time, sender, recipient, type and byte size, plus only the chat's opaque
  base64 ciphertext. Handshake rows contain no ciphertext; their public key/signature
  payloads are not archived. Unknown extra fields are never serialized into SQL.
  Capture defaults on, can be disabled with `SECURECHAT_STORE_ENVELOPES=0`, and has a
  `SECURECHAT_ENVELOPE_MAX_ROWS` cap (default 10000), pruned on each insert.
- `schema_version`: schema version `1`. Startup rejects unsupported versions;
  future table alterations require an explicit versioned migration.

These stored fields are part of **what the server CAN see**: a database reader can
learn account and traffic metadata and retain ciphertext, but has no chat decryption
keys. `tests/test_database.py` sends a unique message through two real TLS clients,
confirms the recipient receives it, and scans every table/column for its plaintext.
The database does not provide message delivery, encrypted media or another transport.

## What the server CANNOT see (by design, verified in `tests/`)

- The plaintext of any chat message, ever — only AES-256-GCM ciphertext
  (`tests/test_aes_gcm.py`, `tests/test_tls_setup.py`).
- Either side's ECDH private key, or the derived AES-256 session key
  (`crypto_engine/dh_exchange.py`; the private key is deleted from memory immediately
  after use, never serialized, never sent).
- Either side's RSA private key — only the public key, submitted once at registration
  (`auth/keystore.py`, `crypto_engine/signatures.py`).
- A user's plaintext password — only its PBKDF2 hash is ever persisted
  (`auth/password_hash.py`; `tests/test_password_hash.py::test_hash_does_not_contain_plaintext_password`).

## Threat model this maps to

| Attacker position | What stops them | Where |
|---|---|---|
| On the network, between a client and the server | TLS (Phase 6) — connection is opaque | `certs/`, `connect_tls()` in `client/client.py` |
| Controls/compromises the relay server itself | AES-256-GCM (content), RSA-PSS (handshake + message authenticity) — the server never holds the keys needed to read or forge either | `crypto_engine/aes_gcm.py`, `crypto_engine/signatures.py` |
| Captures a valid envelope and resends it later | Signed timestamp + freshness window + per-sender nonce tracking (Phase 7b) | `client/client.py`'s `is_timestamp_fresh`, `_seen_nonces` |
| Tries to brute-force a captured password hash | PBKDF2, 200,000+ iterations, per-user random salt | `auth/password_hash.py` |

See the main [README.md](../README.md) for the full wire protocol, the live demo
scripts that exercise each of these rows against the real code, and the honest list of
what's *not* covered by this threat model.
