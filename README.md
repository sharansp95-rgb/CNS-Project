# Secure Chat Application with Encryption

> ## At a glance
>
> **What it is.** A two-party chat where neither the relay server nor a network observer can read or silently alter messages. Every session starts with an RSA-signed ECDH (X25519) handshake, every message is signed and AES-256-GCM encrypted, the connection is TLS 1.3, logins are PBKDF2-hashed and rate-limited, and replayed, tampered, dropped or reordered messages are detected by the receiving client. A signed, independently verifiable evidence export proves who said what. Includes a Tkinter GUI, a separate sandbox Attack Lab and a read-only Security Dashboard (Team 15, course 26ECSC403).
>
> | Measured (see [Evaluation results](#evaluation-results)) | |
> |---|---|
> | Automated tests | **416 passing Python tests + 32 Vitest + 26 Chromium/WebKit Playwright** |
> | Attacks detected (tamper, replay, drop, MITM, edited evidence, password burst; 20 each) | **120 / 120**, 0 false rejections in 200 normal messages |
> | End-to-end message latency (real TLS server, loopback) | **~1.9 ms** median (requirement: < 1 s) |
>
> **Run it in 3 commands** (macOS/Linux, Python 3.10+):
>
> ```
> python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
> .venv/bin/python certs/generate_certs.py        # one-time TLS certificate
> demo/start_demo.sh                              # server + two chat windows + dashboard
> ```
>
> Then Register a user in each chat window (name the other user as Peer) and send a message. Stop with `demo/stop_demo.sh`; run the tests with `.venv/bin/python -m pytest tests/ -q`.

---

**CNS course project — Team 15.**

A client-server chat application in which two peers exchange messages that the relay
server and any network observer can never read in plaintext: each session starts with
an RSA-signed ECDH (X25519) handshake between the two peers (never trusting the server
to broker keys), derives a fresh AES-256-GCM session key, signs and encrypts every
message with it, wraps the whole client↔server connection in TLS, gates every
connection behind a PBKDF2-hashed login, rejects replayed or tampered messages, detects
a relay dropping or reordering messages via a hash-chained conversation log, and locks
out repeated failed logins — all properties covered by the automated suite (416 Python tests, plus browser tests) and five
live attack-and-defense demo scripts, plus a Tkinter GUI whose "Wire Log" panel makes
the cryptography visible during a demo instead of invisible, a separate **Attack Lab**
that triggers those same attacks for real with one click, and a live **Security
Dashboard**.

PDF copies of this documentation are available in [`docs/pdf/`](docs/pdf/) for offline
viewing or printing.

## How this differs from WhatsApp/Signal

WhatsApp and Signal are built to be **deniable**: after a conversation, nobody can
prove to a third party who wrote what, and that is a feature for private
messaging. This project makes the opposite, deliberate trade: an **auditable secure
messenger** where every message is **provably attributable**, the conversation as a
whole is **tamper-evident**, and the evidence can be **verified offline by someone who
trusts neither user nor server**.

| | WhatsApp / Signal | This project |
|---|---|---|
| **Who wrote it** | Deniable by design: no transferable proof of authorship | **Non-repudiation**: every message is signed with the sender's long-term RSA key; anyone holding the public key can verify it |
| **Relay drops or reorders a message** | Each message is authentic on its own; conversation integrity isn't a surfaced, auditable guarantee | **Detected**: a per-sender hash chain (sequence number + hash of the previous message, inside the signed payload) flags "message(s) missing, possible deletion by the relay" |
| **Evidence for a third party** | None: nothing exportable that proves anything | **Signed evidence file** plus a standalone verifier (`tools/verify_transcript.py`) that imports no client or server code |
| **What the user can see** | Opaque; at most a safety number | **Security receipt** on every message (click a bubble) and a live **Wire Log** of what actually crosses the network |
| **Live attacks, on demand** | Not applicable (no equivalent feature) | **Separate Attack Lab site**: hostile relay, two unchanged browser clients, seven attacks and genuine client/lockout reports |
| **Account abuse / intrusion visibility** | Not applicable | **Login lockout** with exponential backoff, and a live **Security Dashboard** showing event counts, a colour-coded feed, and currently-locked accounts |

**Target use cases:** regulated environments where "who said what, and was anything
removed?" must have a defensible answer: healthcare instructions (a dosage order, and
proof that a later "stop" order was not silently dropped), financial approvals,
legal and compliance communication, and command chains where orders must be
attributable and complete. It is **not** the right tool where plausible deniability
matters (e.g. whistleblowing or dissent): there, use Signal.

The separate **Attack Lab** site makes attacks and defenses visible with two real
browser clients. Its hostile relay and sandbox database are isolated from the product.
The read-only **Security Dashboard** remains available for normal service events.

## Quick start (clean clone → working two-GUI demo)

**On a Mac, one command:** double-click [`demo/start_demo.command`](demo/start_demo.command)
in Finder (or run `demo/start_demo.sh` in a terminal). It stops any leftover server of
ours, checks the TLS certificate, then opens clearly titled Terminal windows for the
normal server, two chat windows and the security dashboard, and waits until
the server is really accepting connections before launching them. Options:
`--lab` (separate sandbox site), `--port N`, `--simple` (only the two chat windows, server in
the background) and `--wireshark` (start a live Wireshark capture first). Stop everything again with
`demo/stop_demo.sh`, which touches only this project's own processes (never macOS
AirPlay, which also listens on port 5000).

Or step by step:

```
git clone <this repo's URL>
cd CNSProject
pip install -r requirements.txt
python certs/generate_certs.py     # one-time: generates certs/server.crt + server.key
python server/server.py            # terminal 1 — leave this running
python gui/chat_gui.py             # terminal 2
python gui/chat_gui.py             # terminal 3
```

In each GUI window: fill in a username, the *other* window's username as the peer, and
a password, then click **Register** (the first time) or **Login** (afterward). Once
both windows show a fingerprint at the top, type a message and click **Send** — it
appears in the **Conversation** panel on both sides, and its encrypted form appears in
the **Wire Log** panel. For the exact, click-by-click version of this (what a teammate
who's never run it before should do, live in front of the professor), see
[`demo/full_walkthrough.md`](demo/full_walkthrough.md). Click any message bubble
to open its **security receipt**, and use **Export Evidence** (top bar) to write a
signed evidence file you can check with `python tools/verify_transcript.py`.

## Web client

The browser and Tkinter clients use the same envelope protocol and end-to-end
cryptography. They can talk to each other through one shared relay roster. The browser
has registration/login, message bubbles, signed peer fingerprints, a Wire Log,
clickable security receipts, dark/light themes, wrapped key backups, and offline
signed evidence exports. Layouts adapt to phone widths.

The compiled frontend in `web/static/` is **committed** so a Python-only installation
can serve the browser client immediately. Source lives in `web/frontend/`, with exact
npm versions and a lockfile. Building requires Node.js 20.19+ (20.x) or 22.12+;
this phase was verified with Node.js 26.10. After editing frontend source, rebuild and commit the
updated static assets alongside it:

```sh
.venv/bin/python -m pip install -r requirements.txt
cd web/frontend
npm ci
npm run build
# Return to the project root:
cd ../..
```

Local shared-roster mode (use a free TCP port if macOS AirPlay owns 5000):

```sh
.venv/bin/python server/server.py --web-port 8080
# Or: .venv/bin/python server/server.py --port 5055 --web-port 8080
# Browser: http://localhost:8080; Tkinter: the selected TCP port.
# Full existing desktop demo plus browser gateway:
demo/start_demo.sh --web
# Optional: demo/start_demo.sh --web-port 8081 --port 5055
```

HTTP/WS-only mode, with no TCP listener and no Attack Lab imports:

```sh
PORT=8080 .venv/bin/python -m web
```

It binds `0.0.0.0` by default (`WEB_HOST` overrides). Run a **single process/worker**:
rosters and per-address rate limits are process-local. For deployment, provision
HTTPS at a trusted reverse proxy, set `DATABASE_URL` as described below, and set production
`ALLOWED_ORIGINS=https://your-chat-host.example` and the remaining required values in
[DEPLOY.md](docs/DEPLOY.md). Browsers then automatically
use WSS. Local loopback HTTP uses WS: **chat stays end-to-end encrypted, but login
passwords require HTTPS/WSS for network transport protection**. WebCrypto requires a
secure browser context (HTTPS, or trusted localhost). Do not expose local HTTP mode
as a public password-protected service. The relay still sees a login password before
hashing it, exactly as with the desktop TLS login.

Gateway policy (defaults):

| Environment variable | Default / meaning |
|---|---|
| `SECURECHAT_ALLOWED_ORIGINS` | Exact comma-separated origins: `http://localhost:8080,http://127.0.0.1:8080`; missing/unlisted Origin is rejected, wildcards forbidden |
| `SECURECHAT_WS_MAX_BYTES` | `65536` UTF-8 bytes per text message; binary messages rejected |
| `SECURECHAT_WS_RATE_LIMIT` | `60` received frames per connection per rolling 10 seconds |
| `SECURECHAT_WS_IDLE_SECONDS` | `120` seconds without an incoming frame |

PBKDF2 and SQL operations run in worker threads. The synchronous shared core protects
roster/auth changes with a lock; WebSocket peers use a bounded asyncio outbox scheduled
with `call_soon_threadsafe`. Slow consumers are disconnected. Unknown envelope types
(including `lab_control`) are rejected. All normal auth and relay events use the same
Phase 1 DB adapters. HTTP assets have CSP without inline scripts/styles, `nosniff`,
`no-referrer`, frame denial and disabled camera/microphone permissions.

To develop with Vite, run `npm exec vite -- --host 127.0.0.1` from `web/frontend/` and
start the gateway with `SECURECHAT_ALLOWED_ORIGINS=http://127.0.0.1:5173`; Vite proxies
`/ws` to port 8080. Production headers apply to the built app served by FastAPI.

Browser identities are generated locally. The private PKCS8 bytes are wrapped with
AES-256-GCM under PBKDF2-HMAC-SHA256 (600,000 iterations, random 16-byte salt, random
12-byte nonce); the wrapped object is stored in IndexedDB. Username and public PEM
are authenticated as wrapping AAD. Native runtime signing keys are non-extractable. WebKit RSA-PSS compatibility uses
a client-local forge key in a private WeakMap when native MAX_LENGTH signing fails;
that fallback has JavaScript private-key material in memory and cannot provide the
same native non-extractability property. It never sends or persists an unwrapped key. Use
**Download key backup** before clearing browser data; on another browser enter the
same username/password, import that wrapped JSON backup, then log in. Import verifies
that the private key matches the backup's public key; login also checks the account's
server-stored public key. Passwords, wrapping keys and private keys never appear in
chat envelopes, Wire Log or SQL. Register/login passwords are the necessary exception:
they are sent only for authentication and redacted from Wire Log.

Browser storage trade-offs: a lost backup/cleared IndexedDB loses the identity; there
is no recovery or password-change flow. Backups permit offline password guessing, so
use a strong password. An unlocked key and plaintext messages exist in browser memory;
XSS, malicious extensions, or a compromised server serving altered JavaScript can
access that session. CSP reduces injection risk but cannot eliminate this trust in
the delivered client code. Desktop identities remain in the existing local PEM store;
a browser login needs a matching browser backup, not just an account password.

Exact compatibility parameters:

| Primitive | Browser and Python wire contract |
|---|---|
| Identity signatures | RSA-2048, exponent 65537, PSS SHA-256 / MGF1-SHA256, **222-byte salt** (`PSS.MAX_LENGTH`, not digest length); native WebCrypto with pinned forge fallback for WebKit |
| Handshake | Fresh X25519, RSA signature over raw 32-byte public key; native WebCrypto with `@noble/curves` fallback; verify before derivation |
| Derivation | HKDF-SHA256, 32-byte output, zero/absent salt, info `CNSProject secure-chat ECDH session key v1` |
| Chat encryption | AES-256-GCM, random 12-byte nonce, 16-byte tag, no AAD; ciphertext and tag split into the existing base64 fields |
| Canonical records | Python-compatible recursively sorted, compact ASCII JSON, Unicode escaped, integer epoch seconds; SHA-256 chain hashes |
| Replay / chain | Inclusive 30-second past / 5-second future window; 35-second nonce memory; per-sender genesis and sequence; authenticated gaps warn/resync, broken chains reject |

Evidence exports intentionally contain verified plaintext and remain browser-local.
`tools/verify_transcript.py` is unchanged. Browser protocol handlers and the UI action
area can be extended in later phases; media and calls remain future work. The separate web Attack Lab is described below.

Run browser tests from `web/frontend/` after installing Python requirements:

```sh
npm test
npx playwright install chromium
npm run test:e2e
```

Playwright starts a throwaway shared relay, temporary DB/certificates/logs, two isolated
browser contexts and a real Python TLS peer. It checks receipts, valid evidence,
wrapped-key restoration and mobile fit. Avoid running GUI pytest concurrently with
browser launches because native keyboard focus is shared on macOS. Chromium and WebKit are now tested. Firefox is configured but its Playwright build
fails to launch a profile on the development Mac; see the deployment report.

## Live deployment

Both services are provisioned on Render Free in Singapore, with main storage on
Neon Free Postgres in the same region. Live Chromium and WebKit verification passes
for both sites. Firefox could not launch its local test profile. Results are in
[the live deployment report](docs/live_deployment_report.md); setup instructions are in
[docs/DEPLOY.md](docs/DEPLOY.md).

- Main site: [team15-securechat.onrender.com](https://team15-securechat.onrender.com)
- Attack Lab: [team15-attack-lab.onrender.com](https://team15-attack-lab.onrender.com)
  (separate origin and access code)

`render.yaml` uses the committed frontend builds and one Python process/instance per
service. Main data lives in Neon; the lab uses ephemeral SQLite. Production requires
`APP_ENV=production`, explicit HTTPS `ALLOWED_ORIGINS` and trusted
`FORWARDED_ALLOW_IPS`. Main additionally requires PostgreSQL `DATABASE_URL` and a
persistent `TSA_PRIVATE_KEY`; the lab requires `LAB_ACCESS_CODE` and
`MAIN_SITE_ORIGIN` and refuses a main `DATABASE_URL`. Both expose DB-backed `/healthz`.
Generate the TSA value locally with `tools/generate_tsa_key.py --print-env`; keep it
unchanged across redeploys. Secrets belong in Render, never Git.

Free services sleep after 15 minutes idle, lose local files on restart and share a
750-hour/month workspace budget. Open both URLs about two minutes before a demo and
close them afterward. No keep-alive pinger was added. The in-memory roster permits
**one instance/worker only**. Tkinter remains a local TCP/TLS demo; Render exposes
only the browser HTTP/WS gateway. Live smoke tests verify HTTPS/WSS, chat, encrypted evidence and sandbox detections.

Browser reconnect discards old session keys and bearer tokens, retries the transport,
and asks for login plus a fresh signed handshake. It retains no password for silent
re-authentication. Explicit Disconnect cancels retries.

Neon verification uses a separate disposable `TEST_DATABASE_URL`, with per-test
schemas and a guard against the main database; see the exact command in DEPLOY.md.
Those external tests are prepared and have not been run without your Neon account.

## Voice calls (Phase 7)

One-to-one **audio** calls in the web client, peer to peer with WebRTC (DTLS-SRTP).

- **Signaling is end-to-end encrypted.** Invite, accept, decline, busy, cancel, hang-up and
  call records are ordinary chat messages (`securechat-call/v1:{...}`): signed with the
  sender's RSA identity, AES-GCM encrypted, hash-chained, freshness/replay checked. The relay
  sees ciphertext only. Non-trickle ICE keeps each call to a handful of messages.
- **No certificate swapping.** The SDP, including `a=fingerprint`, is inside the signed message.
  After connecting, the client reads the *real* remote DTLS certificate fingerprint with
  `getStats()` and compares it with the signed one; a mismatch ends the call with a security
  alert. Both screens also show four words derived from both fingerprints and the call id
  (read them aloud: "Call verified" after both confirm).
- **NAT traversal.** STUN, plus TURN from Metered's free plan when configured. The server hands
  each logged-in user short-lived (<= 10 minute) TURN credentials through a rate-limited
  endpoint; the long-term key never reaches a browser, a log or an error message. The UI says
  "direct" or "via relay (TURN)" (a relay only forwards encrypted SRTP). If TURN is unavailable
  (e.g. quota used up) calls still work when a direct path exists, with a note.
- **Evidence.** Each side signs a call record (outcome, start/end, duration, connection type,
  fingerprint check, whether the words were confirmed). Records and signaling are in the hash
  chain, evidence exports, the PDF and `tools/verify_transcript.py`; audio is never recorded.
  No evidence format change was needed. Note: signed SDP contains network addresses, so evidence
  files are confidential (the PDF omits SDP).
- **Keepalive.** Logged-in tabs ping the server so sessions survive idle periods (anonymous sockets still
  time out; pings stop 30 minutes after the last input).
- **Desktop client:** shows `[call — web client only]`; chain verification is unchanged.
- **Attack Lab:** "Substitute DTLS fingerprint in SDP", "Inject forged call offer", "Replay old
  call offer" and a simulated "MITM media path" are all caught by the real client checks.

Details: [docs/voice_phase_report.md](docs/voice_phase_report.md) and
[DEPLOY.md](docs/DEPLOY.md#10-voice-calls-and-turn-phase-7).

## Encrypted images and video (Phase 6)

The web client sends JPEG, PNG, WebP, GIF, MP4 and WebM files **end to end
encrypted**. The relay and the storage provider only ever hold ciphertext.

1. The browser sniffs the file's magic bytes (declared MIME/extension are ignored;
   SVG/HTML/scripts are refused), optionally strips EXIF/GPS from images, and makes
   a small thumbnail.
2. It encrypts the file in 1 MiB chunks with a fresh AES-256-GCM key. Each chunk
   has its own random nonce and AAD = (file id, chunk index, is-last), so chunks
   cannot be reordered, dropped, truncated or moved between files.
3. The ciphertext goes **directly** from the browser to object storage through a
   short-lived presigned URL (the app server never proxies file bytes). The
   server records only ciphertext size and SHA-256.
4. The file key, id, name, type, size, both hashes and the thumbnail travel inside
   a normal chat message (`securechat-attachment/v1:{...}`), so attachments are
   signed, AES-GCM encrypted, hash-chained, replay-protected and part of evidence.
5. The recipient downloads, checks the ciphertext hash, decrypts every chunk,
   checks the plaintext hash and re-sniffs the type before rendering a `blob:` URL.
   Any mismatch shows "Attachment tampered or corrupted" and is reported like other
   client-detected attacks.

Limits (configurable): images 10 MB, videos 50 MB, 200 MB live storage per uploader,
7-day retention, 20 uploads/min and 120 download URLs/min per user, 5-minute URL
lifetime. Expired and never-finalised objects are removed lazily on later requests
(no cron, no pinger). Production uses **Neon Object Storage** (private bucket, CORS
limited to the main origin); development, tests and the lab use a local directory.
The desktop client shows `[attachment — open in web client]` and its chain
verification is unchanged. Details: [docs/media_phase_report.md](docs/media_phase_report.md),
[architecture](docs/architecture.md) and [DEPLOY.md](docs/DEPLOY.md#9-attachment-storage-phase-6).

Privacy notes: the server learns that an attachment exists, who exchanged it, its
approximate size and whether it is an image or video. Video metadata is **not**
stripped. Evidence files contain file keys (they contain message plaintext too), so
keep them confidential; the companion PDF lists names and hashes only. `/verify`
can check a file against the hashes in an evidence file, locally.

## Evidence

Signed evidence is now available as v1 or v2 JSON, with optional server-clock receipts,
a password-encrypted owner-only vault, a local public verifier at `/verify`, and a
browser-generated companion PDF. The relay still cannot read chat or evidence content.
The **signed JSON is authoritative; the PDF is an unsigned companion**.

In chat, select **Save evidence**, enter your password and a non-sensitive title, then
**Encrypt and save**. Open **Evidence** to list, unlock/download, verify or delete your
bundles. Keep the exact downloaded JSON, receipt, and a trusted TSA public key together.
`/verify` accepts dropped/local files without login and verifies entirely in the browser;
no evidence files are uploaded there. It names the failing message for edited records.

V2 adds an exporter-signed SHA-256 of each canonical ciphertext envelope. Timestamp
receipts sign the exact file SHA-256, server UTC time, key ID and retained-traffic match
count. V1 remains verifiable; its corroboration is “not available.” A server cannot
inspect the encrypted file to validate the submitted manifest, so corroboration is
supporting metadata, not proof that a ciphertext encodes a claimed plaintext.

```sh
# Persist this separate key outside a deployment's disposable filesystem:
export TSA_KEY_PATH=/persistent/private/securechat-tsa.key
.venv/bin/python tools/generate_tsa_key.py
# Default if unset: data/tsa_signing.key; generated lazily if missing.
.venv/bin/python tools/verify_transcript.py evidence.json \
  --receipt receipt.json --tsa-pubkey tsa-public.pem
```

`GET /api/timestamp-key` serves the Ed25519 public key. Trust it and participant
fingerprints independently. Receipts use the server clock, not an accredited timestamp
authority. Browser vault encryption uses purpose-separated PBKDF2-SHA256 (600,000
iterations) and AES-256-GCM, before upload. No vault password/decryption key reaches the
server. Titles, hashes, sizes, owner and receipt metadata remain visible.

Legal admissibility in India may additionally need a certificate under **Section 63
of the Bharatiya Sakshya Adhiniyam, 2023**. This app provides technical integrity, not
legal certification. See the [official Act](https://www.indiacode.nic.in/indiacode/bitstream/123456789/20063/1/aa202347.pdf)
and [docs/evidence.md](docs/evidence.md) for formats, exact crypto/canonicalization,
API/auth limits, migration, proof limitations, key rotation, and verification commands.

## Database

Install the pinned dependencies with `.venv/bin/python -m pip install -r requirements.txt`
(or `uv pip install --python .venv/bin/python -r requirements.txt` when using a uv-created
virtualenv). SQLAlchemy 2.x uses SQLite locally and psycopg 3 for PostgreSQL.
Starting `python server/server.py` (also via `demo/start_demo.sh`) creates the tables
automatically; no database service is required for SQLite.

The default URL is `sqlite:///<absolute-project-path>/data/securechat.db`, independent
of the working directory. Override it before starting the server or migration tool:

```sh
export DATABASE_URL='sqlite:////absolute/path/to/securechat.db'
# Deployment alternative (provision the PostgreSQL database/user separately):
export DATABASE_URL='postgresql+psycopg://user:password@localhost:5432/securechat'
```

For an existing installation, stop the old relay and import the legacy files **before
logging in** (new installations need no import):

```sh
.venv/bin/python tools/migrate_json_to_db.py
# Optional source/target overrides:
.venv/bin/python tools/migrate_json_to_db.py --users /path/users.json \
  --events /path/security_events.jsonl --database-url sqlite:////path/securechat.db
```

The tool prints imported/skipped counts, preserves encoded PBKDF2 hashes exactly,
never replaces an existing database account, leaves source files untouched, and is
safe to rerun. Identical repeated event lines are preserved, while reruns and events
already written to both SQL and JSONL are not duplicated. Missing source files are
allowed; malformed input aborts the import. Previous in-memory lockout state cannot
be recovered from the old process.

Schema v2 uses these tables (timestamps are UTC Unix seconds):

| Table | Columns |
|---|---|
| `users` | `username` TEXT PK, `password_hash` TEXT, `public_key_pem` TEXT nullable, `created_at` FLOAT |
| `login_lockouts` | `username` TEXT PK, `failure_count` INTEGER, `locked_until` FLOAT, `last_failure_at` FLOAT nullable, `lock_level` INTEGER, `failure_timestamps` JSON |
| `security_events` | `id` INTEGER auto PK, `ts` FLOAT indexed, `event_type` TEXT, `username` TEXT nullable, `peer_addr` TEXT nullable, `details` JSON, `import_key` VARCHAR(100) nullable UNIQUE |
| `relayed_envelopes` | `id` INTEGER auto PK, `ts` FLOAT indexed, `sender` TEXT, `recipient` TEXT nullable, `envelope_type` TEXT, `size_bytes` INTEGER, `ciphertext_b64` TEXT nullable, `envelope_sha256` VARCHAR(64) nullable indexed |
| `evidence_bundles` | `id` VARCHAR(36) PK, `owner` TEXT indexed, `created_at` FLOAT, `title` TEXT, `size_bytes` INTEGER, `file_sha256` VARCHAR(64), `ciphertext_b64` TEXT, `timestamp_receipt` JSON |
| `schema_version` | `version` INTEGER PK (currently `2`) |

All columns are required unless marked nullable. Lockouts also cover unknown usernames,
so they deliberately have no user foreign key; routing/event history likewise has no
account-deletion dependency. Failure timestamps preserve the exact sliding window,
and `lock_level` preserves exponential backoff across restarts.

A version table plus SQLAlchemy `create_all` keeps the schema simple without
Alembic scaffolding. An explicit transactional upgrade from v1 to v2 preserves existing
rows, adds the vault and nullable relay hashes, and leaves historical hashes NULL. An unsupported version stops startup; `create_all` does not alter
existing tables. Future phases must supply explicit versioned migrations for schema
changes. Short write transactions are serialized with SQLite `BEGIN IMMEDIATE` or a
PostgreSQL transaction advisory lock, including concurrent registrations, lockout
updates and retention pruning. This prioritizes correctness for a single relay;
write throughput should be revisited before scaling.

`SECURECHAT_STORE_ENVELOPES=0` disables new relay-history rows (default `1`, enabled).
`SECURECHAT_ENVELOPE_MAX_ROWS` sets the positive row cap (default `10000`); each insert
prunes the oldest IDs in the same transaction. Lowering the cap takes effect on the
next enabled insert; disabling capture does not erase existing rows. Only online
chat/handshake forwarding is recorded: sender, recipient, type, time and serialized
byte size, plus validated base64 ciphertext for chat. Handshake ciphertext is NULL;
public handshake keys/signatures and arbitrary extra envelope fields are not archived.
This is an audit history, not offline delivery or a plaintext transcript.

Security events also continue to append to `logs/security_events.jsonl` because the
read-only Security Dashboard tails that file. Keep the mirror for the dashboard;
SQL is the durable event store, and JSONL is a separate write, not an atomic part of
the SQL transaction. Deleting the mirror hides its history from the dashboard.
No plaintext chats, passwords, private keys or session keys enter the database.
`data/`, `logs/`, local keys and exports remain gitignored. Demo scripts and the
security evaluation harness use temporary databases.

## Architecture

Two clients, one relay server, TLS wrapping every connection, and an inner
end-to-end layer (ECDH + AES-GCM + RSA) the server itself cannot see into:

![Architecture diagram](docs/architecture_diagram.png)

See [`docs/architecture.md`](docs/architecture.md) for the full-resolution diagram,
the Mermaid source, and a breakdown of exactly what the server can and cannot see at
each point.

## Security properties

Every row names the module that implements the property and a real, currently-passing
test that exercises it (verified — see "Running the tests" below):

| Property | What guarantees it | Module | Real test |
|---|---|---|---|
| **Confidentiality** | AES-256-GCM encrypts every chat message with a per-session key the server never holds; TLS additionally wraps the whole connection | `crypto_engine/aes_gcm.py`, `certs/` + `connect_tls()` in `client/client.py` | `tests/test_aes_gcm.py::test_ciphertext_is_not_plaintext` |
| **Integrity** | AES-GCM's authentication tag detects any bit-flip in transit; a compromised relay that tampers a message cannot get it accepted | `crypto_engine/aes_gcm.py` | `tests/test_aes_gcm.py::test_tampered_ciphertext_is_rejected` |
| **Authentication** | The ECDH handshake itself is signed with each side's RSA identity key and verified before any session key is derived, stopping a relay from substituting its own key mid-handshake | `crypto_engine/signatures.py`, signed-handshake logic in `client/client.py` | `tests/test_handshake_auth.py::test_handshake_signed_with_wrong_key_is_rejected` |
| **Non-repudiation** | Every chat message is signed with the sender's long-term RSA private key; a message can't be forged as if signed by someone else's key | `crypto_engine/signatures.py` | `tests/test_signatures.py::test_wrong_public_key_fails_verification` |
| **Key management** | A brand-new ECDH keypair is generated for every session (forward secrecy — compromising one session's key reveals nothing about any other); each identity's long-term RSA private key never leaves its own machine | `crypto_engine/dh_exchange.py`, `auth/keystore.py` | `tests/test_dh_exchange.py::test_fresh_keypairs_produce_different_session_keys` |
| **Access control** | A connection is not admitted to the roster or allowed to route any handshake/chat envelope until it completes a successful PBKDF2-checked login | `auth/password_hash.py`, `server/server.py` (`_authenticate`) | `tests/test_tls_setup.py::test_tls_client_wrong_password_login_rejected` |
| **Integrity of conversation** | A per-sender SHA-256 hash chain (`seq` + `prev_hash`, inside the signed and encrypted payload) lets the receiver detect a relay silently dropping, reordering or injecting messages | `crypto_engine/hash_chain.py`, chain check in `client/client.py` | `tests/test_hash_chain.py::test_real_pipeline_detects_relay_dropping_a_message` |
| **Evidence** | Both directions of a session can be exported as one JSON file, signed by the exporter, and checked offline by an independent verifier (signatures, both hash chains, chain heads, export signature) | `client/evidence.py`, `tools/verify_transcript.py` | `tests/test_evidence_export.py::test_editing_one_message_makes_it_invalid_and_names_that_message` |
| **Attack Lab containment** | Separate app/origin, database, roster and controls; production has no attack flags, routes or imports, and logs unknown envelope types | `attack_lab/`, neutral `RelayCore.interceptor` | `tests/test_attack_lab.py`, `tests/test_gui_attack_lab.py` |
| **Login lockout** | After repeated failed logins, an account is locked with exponential backoff; a locked attempt is rejected *before* PBKDF2 runs, so hammering a locked account cannot be used to burn CPU | `server/lockout.py` | `tests/test_security_events.py::test_full_lockout_flow_end_to_end` |

Run any single one directly, e.g. `pytest tests/test_aes_gcm.py::test_ciphertext_is_not_plaintext -v`.

## Known limitations

Said out loud, not buried — these are the honest edges of this project's scope:

- **Per-address request limits remain in memory.** Account lockouts, failure windows
  and backoff tiers persist in the database across server restarts; the separate
  per-source-address limiter resets on restart.
- **The register/login password is not protected beyond TLS.** The AES-GCM/RSA layer
  only exists between two chat *peers*, after a handshake; it doesn't cover the
  client↔server login exchange, which relies entirely on TLS. If the server itself
  were compromised, it would see plaintext passwords (never plaintext chat content,
  and never anyone's private key) at the moment of login, before hashing. See
  [`docs/architecture.md`](docs/architecture.md#what-the-server-can-see).
- **RSA private keys are stored unencrypted on disk** (`data/keys/<username>_private.pem`).
  A production system would wrap this file under a key derived from the user's
  password; this project deliberately scoped that out — see the comment in
  `auth/keystore.py`.
- **No account recovery.** If a user's private key file is lost, their account cannot
  send verifiable messages again without re-registering under a new username — there
  is no re-keying or password-reset flow.
- **Self-signed cert trust is manual and local.** Each teammate must run
  `certs/generate_certs.py` and the *same* generated `certs/server.crt` must be present
  on every machine the server and clients run on; there's no certificate authority or
  distribution mechanism beyond "share the file."
- **The server trusts a client's claimed `from` field for routing.** It does not
  cryptographically bind a connection's authenticated username to the `from` field on
  every envelope that connection sends — the handshake/message signatures are what
  actually prevent forgery (the receiver always verifies against the *real* sender's
  RSA key, not whatever the envelope claims), but this is worth knowing rather than
  assuming the server enforces it.
- **Hash chains are per direction.** Each sender's messages are chained to each
  other, so a dropped, reordered or edited message is caught. The *interleaving* of
  alice's and bob's messages relative to each other is not cryptographically bound
  (timestamps give only a rough order).
- **Evidence proves consistency, not identity, unless you pin a fingerprint.** Anyone
  can fabricate a complete, self-consistent evidence file with their own keys. An
  auditor must obtain a participant's key fingerprint out of band and pass it with
  `--expect-fingerprint`; the verifier then rejects any file that doesn't contain it.
- **Non-repudiation is the opposite of deniability.** By design, a participant cannot
  later deny having sent a signed message. That is the point for audit use cases, and
  a drawback for anything needing deniability.
- **Single relay server, no redundancy.** Accounts, lockouts, security events and
  bounded ciphertext history persist in SQL, but online rosters, source-address limits
  and client replay windows are not synchronized for horizontal deployment.
- **Wireshark capture is a single short session** (`demo/capture_normal_session.pcapng`),
  not a comprehensive traffic sample — see `demo/capture_instructions.md` if you want
  to record a longer one.

## Live demo scripts

`demo/run_*.py` are standalone scripts that each start their own real mini relay
server and two real clients to demonstrate one attack being stopped — meant to be run
live for a demo or in front of the professor, not just as passing tests. Each prints a
clear `[PASS]`/`[FAIL]` per check and an overall result:

| Script | What it proves |
|---|---|
| `demo/run_tamper_demo.py` | A malicious/compromised relay flipping a ciphertext byte in transit cannot get a tampered message displayed — AES-GCM's tag catches it. |
| `demo/run_replay_demo.py` | A relay resending a captured chat message a second time cannot get it displayed twice — the timestamp + duplicate-nonce tracking rejects the replay. |
| `demo/run_mitm_handshake_demo.py` | A malicious relay substituting its own ECDH public key during the handshake is stopped by the signed handshake — no session key is ever derived, and the fingerprint that would result doesn't match either. |
| `demo/run_drop_demo.py` | A relay silently dropping one valid message mid-conversation is caught: the receiver sees message #3 where #2 was expected and warns "possible deletion by the relay". |
| `demo/run_evidence_demo.py` | A real conversation is exported as signed evidence and verified (VALID) by the independent verifier; then one word in one message of a copy is changed and the verifier reports INVALID, naming that message. |

```
python certs/generate_certs.py   # once, if you haven't already
python demo/run_tamper_demo.py
python demo/run_replay_demo.py
python demo/run_mitm_handshake_demo.py
python demo/run_drop_demo.py
python demo/run_evidence_demo.py
```

See [`demo/README.md`](demo/README.md) for more detail, and
[`demo/full_walkthrough.md`](demo/full_walkthrough.md) for the full click-by-click
live demo script (GUI + these demo scripts + the Wireshark capture + the Attack Lab
and Security Dashboard, with talking points and timing).

## Running the Attack Lab

For the deployed lab, enter `LAB_ACCESS_CODE` before UI/assets/controls/WebSocket
admission. Production requires a strong code; sessions use Secure HttpOnly cookies.
Both meta robots and X-Robots-Tag discourage indexing. Locally the gate is optional:
set `LAB_ACCESS_CODE` to exercise it. Existing sandbox account passwords are not the
access code. [Production setup](docs/DEPLOY.md).

Run the **separate sandbox site**, never the production server with an attack flag:

```sh
.venv/bin/python -m attack_lab             # http://localhost:8090 ($PORT supported)
# macOS launcher alternative; also opens a local TCP listener:
demo/start_demo.sh --lab --port 5056
```

The persistent banner reads **ATTACK LAB — sandbox, not the real service**. Start a
lab session, Reset lab, then Connect victims. Both panes load the exact production
HTML and JavaScript bundle, pointed at the sandbox WebSocket endpoint. Private keys
are generated locally. Arm tamper, replay, drop, reorder or injection and send a message;
drop/reorder need a follow-up. MITM must be armed **before** connecting victims.
Replay needs a previously delivered message. The brute-force button attacks only the
fixed `lab_lockout` account and shows the real client login being rejected as locked.

The console shows the relay's ciphertext/public routing values and attempted actions.
The detection feed displays actual client `security_alert` reports and real lockout
events; arming or firing an attack alone is never labeled a successful detection.
Injected garbage fails GCM; a forged RSA signature cannot be constructed without the
victim's private key. Dropping the final message alone is undetectable until a later
message reveals the chain gap.

`LAB_DATABASE_URL` defaults to `sqlite:///<project>/data/attack_lab.db`, with own logs
and optional TLS material under `LAB_STATE_DIR` (default `data/attack_lab/`). It must
identify a different database from `DATABASE_URL`. `LAB_ALLOWED_ORIGINS` must be explicit
and disjoint from production `SECURECHAT_ALLOWED_ORIGINS`. Controls require a lab
session cookie, exact Origin on writes and rate limits. Reset wipes **only the lab DB**,
clears connected sandbox peers and reseeds two victim accounts plus the lockout account.
One process hosts one shared sandbox; resetting affects all its visitors.

See [`attack_lab/README.md`](attack_lab/README.md) for configuration, optional TCP,
build/test commands and containment limits. Production has no `--lab`, lab routes or
lab UI. A `lab_control` envelope is an unknown type and is logged and rejected.
The normal dashboard still runs with `python gui/security_dashboard.py`; it reads
`logs/security_events.jsonl` without issuing controls.

## Evaluation results

Measured, not claimed: `tools/evaluate_security.py` drives the real code against a separate local sandbox relay
(temporary data, logs and exports; your real `data/` is never touched) and writes
[`docs/evaluation_results.md`](docs/evaluation_results.md) (all tables, parameters, machine) and
`docs/evaluation_results.json` (raw numbers). Reproduce: `python tools/evaluate_security.py` (about a minute;
`--quick` for a short run). Headline numbers from an Apple M2, Python 3.12, loopback:

| Measure | Result |
|---|---|
| Python suite in the last full attack evaluation | 396 / 396 pass; deployment suite below |
| Attacks detected (tamper, replay, drop, MITM key swap, edited evidence, wrong-password burst; 20 each) | 120 / 120 (100%) |
| False rejections on 200 normal messages | 0 (0.0%) |
| End-to-end message latency through the real TLS server | median 1.859 ms, p95 1.985 ms |
| Full session setup (TLS + login + signed handshake) | median 48.1 ms, p95 49.6 ms |
| Review 1 requirement, encryption overhead < 1 s | PASS (every p95 is far below 1 s) |

**Caveats.** (1) For the repeated wrong-password trials the lockout duration was shortened to **0.5 s**; the
production schedule is 30 s, 60 s, 120 s, 300 s, 900 s (capped at 15 min). (2) All timings are on loopback on one
machine (Apple M2), so real network latency would be added to the end-to-end figures. Also, small fixed attack
counts show the checks work on these attacks, not that no attack could evade them.

![Evaluation summary](docs/screenshots/10_evaluation_results.png)

## Screenshots

**Historical assets:** screenshots 01, 03, 04, 05 and 09 show the former in-app lab
layout or server mode; 03 is explicitly obsolete. `demo/full_walkthrough.md` and
`docs/UI_REDESIGN_PROGRESS.md` describe that older UI. Existing evaluation screenshot
10 predates this run. PDFs under `docs/pdf/` and local PowerPoint review files have
not been refreshed or edited. Use the commands above for the current lab.

Screenshots 01-06b were retaken after the front-end redesign (GUI only; 07-10 are terminal output and 12-13 are Wireshark). For a projector, press **Cmd+Shift+P** in any window (or start with `demo/start_demo.sh --presentation`) for ~25% larger text; the launcher tiles the windows to fit your screen (`demo/layout.py`). Every window has a **jet-black (dark) and a white (light) theme**: switch with the ◐ button, the View / ⚙ menu, or **Cmd+Shift+L** (Ctrl+Shift+L elsewhere); the choice is remembered in `~/.securechat/ui.json`, and `--theme dark|light` overrides it at launch.

Every file in [`docs/screenshots/`](docs/screenshots/), in demo order. (There is no `11`; the numbering
skips it.)

| # | File | What it shows |
|---|---|---|
| 01 | [`01_overview_two_chats_and_dashboard.png`](docs/screenshots/01_overview_two_chats_and_dashboard.png) | The whole demo at a glance: sender and receiver chat windows plus the Security Dashboard. |
| 02 | [`02_security_receipt.png`](docs/screenshots/02_security_receipt.png) | A message's per-message security receipt: encrypted, signed, chained and fresh. |
| 03 | [`03_attack_lab_panel.png`](docs/screenshots/03_attack_lab_panel.png) | The Attack Lab panel (amber LAB MODE) with the one-shot relay attacks: tamper, replay, drop, MITM. |
| 04 | [`04_tamper_caught.png`](docs/screenshots/04_tamper_caught.png) | A tampered message rejected by the receiver (AES-GCM tag check failed); nothing is displayed. |
| 05 | [`05_dashboard_after_attacks.png`](docs/screenshots/05_dashboard_after_attacks.png) | The Security Dashboard's event feed and counters after the Attack Lab attacks. |
| 06a | [`06a_lockout_message.png`](docs/screenshots/06a_lockout_message.png) | The login screen after repeated wrong passwords: the account is temporarily locked. |
| 06b | [`06b_lockout_dashboard.png`](docs/screenshots/06b_lockout_dashboard.png) | The same lockout on the dashboard: failed-login events and the "Locked accounts" panel with the time remaining. |
| 07 | [`07_evidence_valid.png`](docs/screenshots/07_evidence_valid.png) | An exported evidence file checked by the independent verifier: RESULT VALID. |
| 08 | [`08_evidence_invalid.png`](docs/screenshots/08_evidence_invalid.png) | The same file after one word is edited: RESULT INVALID, naming the exact record and failed check. |
| 09 | [`09_server_and_tls_fingerprint.png`](docs/screenshots/09_server_and_tls_fingerprint.png) | The server terminal listening over TLS, with the certificate fingerprint clients pin. |
| 10 | [`10_evaluation_results.png`](docs/screenshots/10_evaluation_results.png) | Terminal summary of `tools/evaluate_security.py`: tests, attack detection, false rejections, timings. |
| 12 | [`12_wireshark_tls13_packets.png`](docs/screenshots/12_wireshark_tls13_packets.png) | Wireshark packet list from `demo/run_wireshark_demo.py`: Client Hello and Server Hello labelled TLSv1.3, then only Application Data. |
| 13 | [`13_wireshark_hex_ciphertext.png`](docs/screenshots/13_wireshark_hex_ciphertext.png) | One Application Data packet selected: the hex/ASCII pane is unreadable ciphertext, with no usernames, passwords or message text. |

## Running the tests

```
pip install -r requirements.txt
pytest tests/ -v
```

Keyboard-focus GUI tests on Linux require a running window manager.

Browser-phase validation (2026-11-16): initial baseline **361 passed, 6 failed**;
after the GUI fixes **367 passed, 0 failed**; final Python suite **382 passed, 0 failed** at the end of Phase 2.
Evidence phase: **394 pytest passed**, **27 Vitest passed**, **5 Playwright/Chromium passed**. The six original GUI failures
were caused by double font scaling at 96 DPI, a presentation test racing a real socket
failure, and missing focus preconditions for synthetic keyboard events. Font scaling
now accounts for Tk's reported DPI; presentation tests control their worker/events and
keyboard focus. Assertions were preserved. Starlette currently emits a deprecation
warning for its httpx test-client adapter; no tests fail or are skipped.

Attack Lab separation: **396 pytest passed, 0 failed, 0 skipped**; **27 Vitest**;
**5 production + 7 lab Playwright/Chromium**. The old Tk panel assertions were migrated
to the separate site; real crypto/detection, chain recovery and evidence assertions
remain. The lab suite checks every attack through the unchanged production bundle.
Full evaluator: **120/120**, **0/200 false rejections**, **real data unchanged**.
See [the phase report](docs/attack_lab_phase_report.md) for files, verification limits
and the estimate-versus-elapsed-time record.

Live deployment: **417 local pytest passed**, **1 local opt-in Postgres skip**;
**68 passed against disposable Neon Postgres**, **32 Vitest passed**. Live Chromium
and WebKit each pass **5 main + 7 lab tests**; each skips the local-only TCP interop
case because Render exposes HTTPS/WSS. Firefox could not launch its profile on this
Mac and remains unverified. See [the live report](docs/live_deployment_report.md),
[preparation report](docs/deployment_phase_report.md) and [DEPLOY.md](docs/DEPLOY.md).

The WebSocket suite covers admission, persistent lockout before PBKDF2, origin/frame/
rate/idle/type policies, security headers, a DB plaintext scan after encrypted chat,
and real combined CLI startup. Browser vectors run both directions against Python;
Playwright exchanges messages between isolated browser contexts and with a real
Python TCP/TLS client. Browser evidence is checked by the unmodified offline verifier.

416 passing tests plus an opt-in Postgres test across 33 test files, including 15 database tests, 15 gateway tests and 12 evidence/vault tests (the first seven one per project phase): `test_aes_gcm.py`
(encryption), `test_dh_exchange.py` (key exchange), `test_password_hash.py` (login),
`test_signatures.py` (non-repudiation), `test_handshake_auth.py` (signed-handshake
MITM fix), `test_replay_protection.py` (replay defenses), `test_tls_setup.py`
(transport security), plus `test_hash_chain.py` (dropped/reordered-message detection),
`test_evidence_export.py` (signed export + offline verifier, including tampered files),
`test_attack_lab.py` (separate hostile-relay attacks and product isolation),
`test_lockout.py` (login lockout + per-address rate limiting),
`test_security_events.py` (the security event log end to end, including the full
lockout flow and that a locked attempt never runs PBKDF2), `test_entrypoints.py`
(the documented ways of starting the project, run as real scripts),
`test_gui_layout.py` (header, input row, login card and dashboard fit their windows;
skipped automatically without a display) and `test_reset_environment.py` (the reset
script only ever kills our own `server.py`).

The server-based tests are deterministic: each starts its server on an OS-chosen port,
waits on real conditions instead of sleeping, tears everything down afterwards, and
gets its own lockout state, user store, key directory and event log, so no test touches
your real `data/`. (An earlier intermittent timeout was traced to a real bug --
sharing one TLS socket between threads -- fixed in `transport/locked_tls.py`.)

## How to run (detail)

Requires Python 3.8+.

**0. One-time per teammate: generate a local TLS certificate.** The server and client
both need `certs/server.crt` / `certs/server.key`, which are gitignored (a committed
private key would let anyone with repo access impersonate the server) and must be
generated locally, once, by each person running this project:

```
python certs/generate_certs.py
```

This writes a self-signed cert for `CN=localhost`, valid 365 days. Re-run with
`--force` to regenerate (then restart the server and re-run this on every client, too
— an old cert and a new one won't match).

**1. Start the server** (one terminal):

```
python server/server.py
```

Defaults to `127.0.0.1:5000`; override with `--host` / `--port`. It prints
`Server listening on 127.0.0.1:5000 over TLS ...` once ready.

**2a. Terminal client** — start two clients, each naming the other as its peer (one in
each of two more terminals):

```
python client/client.py --peer bob
python client/client.py --peer alice
```

Each client first asks you to **register** a new account or **login** to an existing
one — pick `1) Register` the first time for each username, `2) Login` afterward. The
password prompt hides your input (it won't echo to the terminal).

**2b. GUI client** — see "Quick start" above, or `demo/full_walkthrough.md` for the
click-by-click version.

Registering also generates a long-term RSA-2048 identity keypair for that account (see
"Design details" below) — the private key is saved locally, and only the public key is
sent to the server. Once both peers are authenticated and online, they automatically
perform the signed ECDH handshake, fetch each other's RSA public key, and from then on
every message is signed, AES-256-GCM encrypted before it leaves the client, and
decrypted + signature-verified on arrival.

Registered accounts (PBKDF2 password hashes and RSA public keys only) persist in
`data/securechat.db` by default; each account's RSA private key is saved separately as
`data/keys/<username>_private.pem`. The entire `data/` directory is
gitignored since they hold real credentials and private key material from local
testing.

## Troubleshooting: certificate mismatch

**Symptom:** a client fails to connect with something like
`[!] Server certificate verification failed -- refusing to connect. ([SSL:
CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate ...)`.

**Cause:** `certs/server.crt` was regenerated (e.g. `python certs/generate_certs.py
--force`) while an *old* `server.py` process was still running — that process loaded
its certificate into memory at startup and keeps using it until restarted, so it's now
serving a different cert than the one on disk that clients trust.

**How to tell at a glance (no guessing required):** both the server and any connecting
client print a short cert fingerprint — the server at startup
(`Server listening on ... (cert fingerprint: XXXX XXXX XXXX XXXX)`) and the client
right before it attempts the handshake (`[tls] trusting server cert fingerprint: XXXX
XXXX XXXX XXXX` — shown in the terminal client's output, or in the GUI's **Wire Log**
panel). If these two don't match, that's the stale-server bug, confirmed instantly
instead of debugged manually.

**Fix:**
```
python demo/reset_environment.py
```
This detects a leftover process on the server's port (asking before killing anything —
it never kills silently), regenerates `certs/server.crt`/`server.key`, and prints the
new fingerprint. Restart the server (`python server/server.py`) and confirm its
startup line shows that *same* fingerprint before launching any clients. It does not
touch `data/securechat.db` or `data/keys/` — registered accounts and identity keys are
unaffected by a cert reset.

Or manually: stop the server (Ctrl+C its terminal), regenerate certs
(`python certs/generate_certs.py --force`), then start the server again *before*
starting any clients.

## Wire protocol

One JSON object per line (newline-terminated), carried inside the TLS tunnel. Every
envelope has a `"type"` field:

| type | direction | carries |
|---|---|---|
| `register` | client → server | `username`, `password`, `public_key` (RSA PEM text) |
| `register_result` | server → client | `success`, `reason` |
| `login` | client → server | `username`, `password` |
| `login_result` | server → client | `success`, `reason` |
| `roster` | server → client | list of currently-online usernames |
| `system` | server → client | human-readable join/leave/error text |
| `user_joined` | server → client | `username` of a newly-connected peer |
| `handshake_init` | client ↔ client (via server) | `from`, `to`, `pubkey` (base64, 32 raw bytes), `handshake_sig` (base64, RSA-PSS signature over `pubkey`) |
| `handshake_response` | client ↔ client (via server) | `from`, `to`, `pubkey` (base64, 32 raw bytes), `handshake_sig` (base64, RSA-PSS signature over `pubkey`) |
| `get_pubkey` | client → server | `username` (whose RSA public key to look up) |
| `pubkey_result` | server → client | `username`, `public_key` (RSA PEM text or null), `success` |
| `chat` | client ↔ client (via server) | `from`, `to`, `nonce`, `ciphertext`, `tag` (all base64); the plaintext AES-GCM decrypts to is itself `{"message", "timestamp", "seq", "prev_hash", "signature"}` JSON, where `signature` covers the canonical record `{sender, recipient, seq, timestamp, message, prev_hash}` (see "How the hash chain works") |

A connection must complete a successful `register` or `login` exchange before the
server admits it to the roster or accepts any handshake/chat envelope from it. The
server routes `handshake_init` / `handshake_response` / `chat` envelopes to the named
`to` recipient only, based on the sender's own claimed `from` field; it never inspects
or needs to understand their payload beyond that routing. `get_pubkey` is answered
directly by the server from its user store (the requested user doesn't need to be
online — a public key is public information regardless of presence).

## Design details

<details>
<summary>Why two crypto libraries (PyCryptodome and cryptography)?</summary>

AES-256-GCM comes from **PyCryptodome** (`crypto_engine/aes_gcm.py`); ECDH/X25519, HKDF, RSA-PSS
signatures and the TLS certificate come from the **`cryptography`** package (OpenSSL-backed).
This is a historical split, not a security one: the course's encryption phase was built first with
PyCryptodome's `AES.MODE_GCM`, whose interface (separate nonce, ciphertext and 16-byte tag, and a
clear MAC-check failure) is easy to test and to show in the Wire Log. The later phases needed
X25519, HKDF, RSA-PSS and X.509 handling, which `cryptography` provides well and PyCryptodome does
not (X25519/HKDF/X.509 are absent or far less convenient). Both are maintained, widely used
libraries and nothing is hand-rolled. Keeping one wrapper module per primitive
(`aes_gcm.py`, `dh_exchange.py`, `signatures.py`) means either library could be swapped without
touching the protocol code. `cryptography` could do AES-GCM too; the cost of consolidating
would be re-validating the tests and the wire format for no change in security.

</details>

<details>
<summary>How the handshake works (ECDH + forward secrecy)</summary>

Each client generates a brand-new X25519 (elliptic-curve Diffie-Hellman) keypair for
every chat session — never reused across logins, so compromising one session's key
reveals nothing about any other session (forward secrecy). When two named peers are
both online, the client whose username sorts alphabetically first automatically sends
its public key to the other, relayed through the server inside a `handshake_init`
JSON envelope; the second client generates its own keypair and replies with a
`handshake_response` carrying its own public key. Both sides then independently run
`compute_shared_key()` — each combining *their own* private key with the *other's*
public key — which by the math of Diffie-Hellman produces the identical raw shared
secret on both ends without either private key ever crossing the network. That raw
secret is then passed through HKDF-SHA256 to derive a clean, uniformly random 32-byte
AES-256 key (the raw ECDH output itself is never used directly as a cipher key). From
that point on, every chat message is encrypted with `aes_gcm.encrypt()` before being
sent and decrypted with `aes_gcm.decrypt()` after being received; the relay server only
ever forwards opaque public-key bytes and encrypted (nonce/ciphertext/tag) envelopes —
it never computes, stores, or sees the shared secret, and a tampered or forged message
is rejected with a warning instead of being decrypted into garbage.

</details>

<details>
<summary>How the signed handshake stops a relay-server MITM</summary>

The handshake above has a gap: `handshake_init`/`handshake_response` carry a raw ECDH
public key, and nothing about the handshake itself ties that key to a particular long-
term identity. A malicious or **compromised relay server** — a different threat than a
network eavesdropper; TLS does not help here, since the server is the trusted TLS
endpoint — could substitute its own ECDH public key for either peer's, completing two
separate handshakes (attacker↔A, attacker↔B) while both clients believe they're
talking directly to each other. Since each client already has a long-term RSA identity,
the fix reuses it: the ECDH public key is signed with the sender's RSA private key
before sending (`handshake_sig`), and the receiver verifies that signature against the
sender's already-known RSA public key **before** computing the shared secret. If
verification fails — or the ECDH key was swapped after signing, or the signature was
produced by the wrong RSA key — the handshake **aborts with a clear error and no
session key is ever derived**; nothing gets silently trusted. After a *successful*
handshake, both clients also print a short human-readable **fingerprint** of the
peer's RSA public key (`crypto_engine/signatures.fingerprint`, the first 16 hex
characters of SHA-256 of the key's PEM bytes) — the "check key fingerprints"
mitigation: two people can read this aloud to each other (voice call, in person) to
independently confirm they hold the same identity for their peer, catching a MITM even
if some future bug let a forged handshake slip past the automated check. See
`demo/run_mitm_handshake_demo.py` for a live demonstration.

</details>

<details>
<summary>How replay protection works</summary>

A captured, validly-encrypted, validly-signed chat envelope could otherwise be resent
later (or twice) and would still pass both AES-GCM and the RSA signature check, since
neither says anything about *when* the message is being presented. Two independent
defenses close this: first, a Unix timestamp is included in what gets **signed**
(inside the canonical record built by `crypto_engine/hash_chain.canonical_record`) before encryption, so it travels tamper-
evident — an attacker can't just bump the timestamp on a captured message to make it
look fresh again, since that invalidates the signature. On receipt, a message is
rejected if its timestamp is more than `REPLAY_WINDOW_SECONDS` (30s) old or more than
`CLOCK_SKEW_SECONDS` (5s) in the future. Second, belt-and-suspenders: each client
tracks recently-seen `(sender, nonce)` pairs in memory (nonces are already fresh random
values per `aes_gcm.encrypt()` call, so a genuine resend from the sender would carry a
*different* nonce) and rejects an exact repeat outright, even if it somehow fell inside
the freshness window; old entries are pruned automatically once they're old enough that
the timestamp check alone would catch them anyway. See `demo/run_replay_demo.py`.

</details>

<details>
<summary>How the hash chain works (dropped / reordered message detection)</summary>

Per-message AES-GCM and RSA signatures prove each message is authentic, but they can't
notice a message that **never arrives**: a malicious relay can drop or reorder valid
messages and every message that does arrive still verifies. So each sender keeps a
chain over its own messages. Every outgoing message carries `seq` (1, 2, 3, ...) and
`prev_hash` (the SHA-256 of that sender's previous canonical record; for the first
message, a **genesis** value derived from both public ECDH keys of the handshake plus
the sender's name, so no two sessions or directions share a start). Both fields sit
inside the RSA-signed, AES-GCM-encrypted payload, so the relay can neither read nor
alter them. The canonical record is
`canonical_json({sender, recipient, seq, timestamp, message, prev_hash})` where
`canonical_json` is sorted-key, no-whitespace, ASCII-escaped JSON; the signature and the
record hash are both taken over exactly those bytes (`crypto_engine/hash_chain.py`).

On receipt, after decrypt, signature, freshness and duplicate checks, the chain check
runs: `seq` exactly as expected and `prev_hash` matching is **OK**; `seq` ahead of
expected is a **gap** ("N message(s) missing, possible deletion by the relay": the
authentic message is still shown and the chain resyncs, but a warning is raised);
`seq` behind expected, or a wrong `prev_hash`, is **broken** ("possible reordering,
replay or injection": the message is not shown). Gaps and rejections are recorded and
exported with the evidence. See `demo/run_drop_demo.py`.

</details>

<details>
<summary>How the signed evidence export and offline verifier work</summary>

Each client keeps an in-memory transcript of every message that passed all checks
(both directions, with the sender's signature), plus a separate list of rejected
events that is never mixed into it. **Export Evidence** (header button, or
`client.export_evidence()`) writes `exports/evidence_<you>_<peer>_<time>.json`
(gitignored): participants with their RSA public keys and fingerprints, session
start and end, the public signed handshake values, the ordered records, each side's
final chain head, the rejected events, and the exporter's RSA signature over the
canonical bytes of everything else.

`python tools/verify_transcript.py exports/<file>.json` then checks, without importing
any client or server code: fingerprints against keys, the handshake signatures,
every message's signature, `record_hash` and chain link (recomputing both chains from
genesis), the final chain heads, and the exporter's whole-file signature. It prints a
per-message report and an overall **VALID** or **INVALID** that names the exact
record and check that failed. `--expect-fingerprint "XXXX XXXX XXXX XXXX"` pins a key
you trust out of band (see Known limitations). See `demo/run_evidence_demo.py`.

</details>

<details>
<summary>How signing works (non-repudiation)</summary>

The ECDH session key proves a message was encrypted for this pair of peers, but it's
symmetric — both sides hold it, so it can never by itself prove *which* of them
actually wrote a given message to a third party. A separate, long-term RSA-2048
keypair per user identity closes that gap: at registration a client generates its own
RSA keypair, keeps the private key on disk locally (see `auth/keystore.py`), and sends
only the public key to the server, which stores it next to that user's password hash.
Before sending a chat message, the sender signs the plaintext with its own RSA private
key (RSA-PSS + SHA-256), then wraps `{message, signature}` together as the payload
that gets AES-256-GCM encrypted — **sign, then encrypt** — so the signature travels
protected inside the same ciphertext as the message, never sent in the clear. On the
receiving side the order reverses: **decrypt, then verify** — the client AES-GCM-
decrypts the envelope, unwraps `{message, signature}`, and only then checks the
signature against the sender's RSA public key (fetched once via a `get_pubkey` request
to the server and cached for the session). A message whose signature doesn't check out
— tampered content, a forged signature, or a signature checked against the wrong
public key — is never displayed; the client prints a clear warning and discards it.

</details>

<details>
<summary>How TLS layers with the app-level crypto</summary>

TLS (`ssl.PROTOCOL_TLS_SERVER` / `PROTOCOL_TLS_CLIENT`) wraps the whole client↔server
TCP connection, wrapping every socket **before** any envelope — including the very
first register/login — is read or written. This is a **transport-layer** protection:
it makes the connection itself opaque to anyone on the network path, so an observer
between a client and the server can no longer see the JSON structure, field names, or
content of anything at all, not even metadata like `"type": "login"`. It sits
alongside, not in place of, the **application-layer** crypto — AES-GCM session keys
and RSA signatures — which protect message content and identity end-to-end between
the two chat *peers themselves*, independent of transport. The distinction that
matters: TLS protects data only while it's in transit to/from the server; the server
itself sees the connection in the clear once TLS terminates there (it's the trusted
relay, not an untrusted network link — see "Known limitations" above for what that
means for the login password specifically). AES-GCM + RSA signatures, by contrast,
protect a chat message even from the server — the server only ever sees opaque
ciphertext and routing metadata, never plaintext content, a private key, or a session
key, whether or not TLS is present. The client does not use `check_hostname=False` or
`CERT_NONE` to sidestep certificate verification — that would accept a certificate
from literally anyone, which defeats the point of using TLS at all. Instead it pins
trust to exactly the one self-signed certificate this project generated
(`certs/server.crt`, loaded via `load_verify_locations`), so a different server
presenting a different certificate is rejected at the TLS handshake, before any
envelope is ever sent.

</details>

<details>
<summary>Crypto modules — quick reference</summary>

`crypto_engine/aes_gcm.py` — standalone AES-256-GCM module:

```python
from crypto_engine import generate_key, encrypt, decrypt

key = generate_key()                       # 32 random bytes (testing only)
box = encrypt(key, b"hello")               # {"nonce", "ciphertext", "tag"}
decrypt(key, box["nonce"], box["ciphertext"], box["tag"])  # b"hello"
```

Tampered ciphertext or a wrong key raises `DecryptionError` rather than returning
garbage plaintext.

`crypto_engine/dh_exchange.py` — ECDH (X25519) key exchange + HKDF-SHA256 key
derivation:

```python
from crypto_engine.dh_exchange import generate_keypair, compute_shared_key

priv_a, pub_a = generate_keypair()
priv_b, pub_b = generate_keypair()
assert compute_shared_key(priv_a, pub_b) == compute_shared_key(priv_b, pub_a)
```

`auth/password_hash.py` — PBKDF2-HMAC-SHA256 password hashing, 200,000+ iterations, a
fresh random salt per password, and a constant-time comparison
(`hmac.compare_digest`) on verify:

```python
from auth.password_hash import hash_password, verify_password

stored = hash_password("correct horse battery staple")
# stored == "pbkdf2_sha256$200000$<salt_b64>$<hash_b64>"
assert verify_password("correct horse battery staple", stored)
assert not verify_password("wrong guess", stored)
```

`server/user_store.py` persists only that encoded hash string per username, in
the `users` database table — the plaintext password is never written to disk.

`crypto_engine/signatures.py` — RSA-2048 signatures, RSA-PSS padding + SHA-256, with
PEM (de)serialization helpers and the `fingerprint()` helper:

```python
from crypto_engine.signatures import generate_keypair, sign, verify, fingerprint, serialize_public_key

private_key, public_key = generate_keypair()
signature = sign(private_key, b"hello")
assert verify(public_key, b"hello", signature) is True
assert verify(public_key, b"tampered", signature) is False  # never raises
print(fingerprint(serialize_public_key(public_key)))  # e.g. "A1B2 C3D4 E5F6 A7B8"
```

`auth/keystore.py` saves each account's RSA private key locally as an unencrypted PEM
file under `data/keys/<username>_private.pem` (gitignored) — see "Known limitations".

`certs/generate_certs.py` generates the self-signed TLS cert + key used by
`server.py`/`client.py`, using the `cryptography` library directly (not the `openssl`
CLI), so it produces an identical result on every teammate's machine:

```
python certs/generate_certs.py           # writes certs/server.key + certs/server.crt
python certs/generate_certs.py --force   # regenerate, overwriting existing certs
```

</details>

<details>
<summary>GUI chat client — how it's built</summary>

`gui/chat_gui.py` is a Tkinter GUI over the exact same client logic the terminal
client uses — `client/client.py`'s `SecureChatClient`, `connect_tls`, and the
signature/keystore helpers are imported and reused directly; the GUI contains no
protocol, crypto, or networking logic of its own. Besides a normal-looking chat
window (dark theme, WhatsApp-style message bubbles), it has a second **"Wire Log"**
panel that shows a live, timestamped feed of exactly what's crossing the network —
handshake public keys and signatures, each message's nonce/ciphertext/tag (truncated
for readability), and any rejected/tampered message in red. Passwords are redacted in
the wire log with a note that TLS (not the GUI) is what actually protects them in
transit; chat plaintext never appears there at all, only its ciphertext.

**On the refactor this required:** `SecureChatClient`'s logic methods (register/login,
handshake, send/receive) were already separate from the terminal-only presentation
code (`authenticate()`/`main()`, which use `input()`/`print()`) — the GUI calls
`SecureChatClient` directly rather than those two functions, so no duplication of the
protocol was needed. What *was* mixed into `SecureChatClient` itself was `print()`
calls inside its own logic methods. Rather than remove those (risking a subtle change
to the terminal client's exact behavior), an optional structured `event_callback` was
added to `SecureChatClient.__init__`: every one of those `print()` sites also emits a
`(kind, data)` event through it, if one was supplied. The terminal client passes none,
so it's unaffected. The GUI's callback only ever does `queue.Queue.put(...)`
(thread-safe), and drains that queue on a `root.after()` timer to do all actual widget
updates on Tkinter's main thread — `SecureChatClient`'s background `receive_loop`
thread never touches a widget directly.

</details>
