# Separate Attack Lab

This is a hostile relay sandbox. Production deployment is documented in
[DEPLOY.md](../docs/DEPLOY.md): use `APP_ENV=production`, your HTTPS `ALLOWED_ORIGINS`,
verified `FORWARDED_ALLOW_IPS`, `MAIN_SITE_ORIGIN`, and a strong `LAB_ACCESS_CODE`.
Production binds 0.0.0.0:$PORT, refuses main DATABASE_URL credentials and exposes no
TCP listener. An HttpOnly Secure access session is required before UI, assets,
controls or WebSocket admission. Both meta robots and X-Robots-Tag specify noindex.
`/healthz` checks the isolated DB. Locally set LAB_ACCESS_CODE to enable the gate.

This is a hostile relay sandbox. Run it separately from the real chat service:

```sh
.venv/bin/python -m attack_lab
# Open http://localhost:8090
# Optional local TLS transport for the normal Tkinter / CLI client:
.venv/bin/python -m attack_lab --port 8090 --tcp-port 5056
# Equivalent macOS launcher:
demo/start_demo.sh --lab --port 5056
```

The product has no attack flags, controls or UI. The dependency is one way:
`attack_lab` imports the real relay/core/gateway; product imports never load the lab.
Only the optional neutral `RelayCore.interceptor` is used to change forwarding.

## Run a demonstration

Start a lab session, Reset lab, then Connect victims. The accounts are `lab_alice`
and `lab_bob`, password `Lab-Password-1234!`; a third `lab_lockout` account is reserved
for the fixed brute-force demonstration. These are public sandbox credentials.
Private RSA identities are generated in the browser and wrapped with the real
keystore module. Only public PEM keys are uploaded.

Both victim panes load the exact production HTML and JavaScript bundle. The lab
controller fills normal login/composer forms; it never alters client verification.
There is a separate Vite console entry so lab controls cannot enter product assets.

| Attack | Operation and genuine detection |
|---|---|
| Tamper | Flip a ciphertext byte; victim rejects the GCM tag |
| Replay | Resend a captured envelope; nonce/freshness check rejects it |
| Drop | Suppress next chat; send a follow-up to reveal the hash-chain gap |
| Reorder | Hold one envelope, then send the next first; chain ordering fails |
| Inject | Insert random ciphertext/tag/nonce; GCM rejects the forged envelope |
| MITM | Arm before connecting; replace a public ECDH key while retaining its old signature; handshake verification aborts |
| Brute force | Wrong passwords against only `lab_lockout`; real guard locks it, and a real victim login shows rejection |

A final dropped message cannot be detected until another message arrives. RSA
signature verification still runs for validly decrypted messages; the relay lacks
the session key to construct a new GCM-valid forged signed payload. The feed shows
actual `security_alert` reports and real account lockouts, not inferred success.

The relay console allowlists routing/ciphertext and public handshake values. It
never receives chat plaintext or private/session keys. As in the real app, login
passwords terminate at the gateway and must use HTTPS outside localhost.

## Network attacker demo ("fake Wi-Fi")

Mallory controls the network between two real users and the real server, like a rogue
hotspot. This runs locally and shows what TLS does to a network attacker. It is
separate from the Attack Lab website above: there the *relay* is hostile (a different
threat, stopped by end-to-end crypto); here only the *network* is hostile.

```bash
demo/start_demo.sh --network-attack              # server :5000, proxy :5001, Mallory :8095
demo/start_demo.sh --network-attack --port 5055  # avoid macOS AirPlay on 5000 (proxy :5056)
demo/start_demo.sh --network-attack --wireshark  # also a live Wireshark capture of the proxy port
demo/stop_demo.sh                                # stops everything of ours
```

### The windows

| Window | What it is |
|---|---|
| **Alice** and **Bob** | The normal desktop clients, started with `--port <proxy port>`, so every byte they send goes through Mallory. They still pin `certs/server.crt` and verify it. |
| **Mallory** (browser, `http://localhost:8095`) | Live list of captured TLS records: direction, record type, size, first bytes in hex and as text (visibly unreadable), status. **Intercept ON/OFF**, per-record **Forward / Alter / Drop / Replay / Delay**, a feed of the real outcomes, the one-line lesson, **Open in Wireshark** and **Download .pcap**. |
| **Real server** | `server/server.py`, unchanged. Log: `logs/demo_server.log`. |

Mallory's proxy (`python -m attack_lab.netproxy`) holds **no TLS key** and never
terminates TLS. It cuts the TCP byte stream into TLS records and relays them. Alter
flips one ciphertext byte, Drop withholds a record, Replay sends the same bytes a
second time, Delay holds a record. **The outcome is never simulated**: whatever
happens next is what the real TLS stacks of the clients and the server do; Mallory's
feed only reports which side closed the connection and how soon after the attack.

TLS 1.3 detail: after the ServerHello everything is wrapped as "Application Data", so
Mallory cannot even tell a chat message from a handshake message. The first
application-data record of each connection (TLS Finished) is always forwarded; with
Intercept ON, later records wait for your decision. After an Alter, Replay or Drop the
proxy switches Intercept OFF (checkbox "resume forwarding after an attack") because
otherwise Mallory would also be holding the TLS alert the victim sends back.

### Live review script

1. Run `demo/start_demo.sh --network-attack`. Say: "Alice and Bob think they talk to
   the server; Mallory is the Wi-Fi."
2. In Alice's and Bob's windows register one user each, naming the other as Peer.
   Mallory's window fills with records. Point at the hex: nothing readable, not even
   the usernames or the password. (Optional: **Open in Wireshark**.)
3. Intercept **OFF**: Alice sends "hello". Bob receives it. Mallory forwarded
   untouched and read nothing.
4. Intercept **ON**, Alice sends "pay 500". A record is waiting. Press **Forward**
   (and Forward the server's copy towards Bob): delivered normally.
5. Alice sends again; press **Alter**. Mallory's feed shows `ALTER ... closed by the
   server ... bad_record_mac`, and **Alice's window** shows the real error
   (`SSLError ... bad record mac`) and goes to "Disconnected".
6. Log in again (Intercept ON), send, press **Replay** on that record: it is
   delivered once, the duplicate breaks the connection (TLS sequence numbers).
   Or use **Replay now** on any older record.
7. Send and press **Drop**: the message never arrives, nothing tells Alice
   (`STALLED` in the feed). Send another message: now the sequence numbers no longer
   match and the connection breaks.
8. **Delay** (3 s): the message arrives late but intact, because TLS only cares about
   order and integrity.
9. Lesson on the page: *TLS stops a network attacker: he sees only ciphertext, and any
   change breaks the connection.*

Things to say if asked: Mallory *can* still drop the connection or the traffic (TLS
does not give availability), and he can see sizes and timing (traffic analysis). He
cannot read or silently change anything. A malicious **server** is a different
problem, handled by the end-to-end layer (Attack Lab website).

### Browsers (HTTPS / WSS)

The proxy only moves TLS records, so it works for the web client too. The gateway must
serve HTTPS locally (uses the project certificate, which has `localhost` in its SAN):

```bash
SECURECHAT_ALLOWED_ORIGINS=https://localhost:8443 \
  .venv/bin/uvicorn web.app:create_app --factory --port 8444 \
  --ssl-certfile certs/server.crt --ssl-keyfile certs/server.key
.venv/bin/python -m attack_lab.netproxy --upstream 127.0.0.1:8444 --listen-port 8443 --ui-port 8095
# victims open https://localhost:8443  (click through the self-signed certificate warning)
```

A browser does not pin `certs/server.crt`, so it warns once about the self-signed
certificate; adding the certificate to the macOS keychain as trusted removes that.
Verified with real Chromium (page and WSS open through the proxy) and with pytest (HTTPS
plus WSS, plaintext scan, altered record closes the socket). The full chat UI flow
through the proxy was not automated.

### Wireshark

**Open in Wireshark** writes the records Mallory captured to a `.pcap` (each record as one
TCP segment, bytes exactly as the proxy received them, decoded as TLS on the proxy port)
and opens it with the helper from `attack_lab/scripts/run_wireshark_demo.py`. It needs no
capture privileges. `--wireshark` additionally starts a live capture of the proxy port
before anything connects, so the handshakes are recorded too.

### Limits and honest notes

- Victim labels ("Alice", "Bob") come from the `CNS_DEMO_LABEL` environment variable of
  the GUI processes (macOS/Linux, via `lsof`); otherwise connections are "Client N".
- The desktop GUI does not reconnect by itself: after any attack that breaks TLS the
  victim shows "Disconnected ... restart to reconnect". A dropped message therefore
  stalls first and fails on the *next* message, as described above.
- `client/client.py` now passes the real exception text (for example the SSL error) into
  the "disconnected" event instead of the fixed text "connection lost". No protocol change.
- Tests: `tests/test_network_attacker.py`.

## Isolation and configuration

- `$PORT` selects HTTP port (default 8090); `--port` overrides it. `--host` defaults
  to 127.0.0.1. No deployment or public exposure is performed by this phase.
- `LAB_DATABASE_URL`: default `sqlite:///<project>/data/attack_lab.db`. It is passed
  explicitly to user storage, lockout, relay persistence and logging. `DATABASE_URL`
  is never reassigned. PostgreSQL URLs use the same SQLAlchemy adapter.
- The lab refuses the configured/default production database, including resolved
  SQLite symlink/hardlink aliases and SQLite URI aliases. Use separate PostgreSQL
  databases and credentials. A trusted operator remains responsible for configuring
  distinct infrastructure; source/config changes by an administrator are outside
  this containment boundary.
- `LAB_STATE_DIR`: own JSONL log and TCP certificate/key directory; defaults to
  `data/attack_lab`. TCP clients must trust that directory's `certs/server.crt`
  using `SECURECHAT_CERT_DIR=<absolute-path>/data/attack_lab/certs`. Never replace
  the production certificate to connect to the lab.
- `LAB_ALLOWED_ORIGINS`: explicit comma-separated origins, default localhost and
  127.0.0.1 on the lab port; must be disjoint from `SECURECHAT_ALLOWED_ORIGINS`.
  Production retains its normal frame denial; only the lab permits same-origin
  victim embedding.
- Lab controls require a one-hour HttpOnly, SameSite=Strict session cookie; writes
  require exact Origin. Limits per minute: 10 session starts per source address,
  30 control writes per session, 120 state reads per session. There are no external
  host, URL or arbitrary account inputs to the brute-force endpoint.
- Reset closes sandbox connections, deletes lab DB rows except schema version,
  clears captures/armed actions/address limits and reseeds accounts. It leaves the
  independent production DB and roster untouched. Reset does not erase old JSONL
  audit lines or browser keystore backups.
- One process is one shared sandbox; visitors can affect each other's experiments.
  A session restricts controls to lab visitors, not to individually owned labs.
  Use a single worker. General web login/registration still uses the isolated DB.

Legacy authenticated localhost-only TCP `lab_control` exists only in the rogue
relay for compatible scripts. Production rejects this as an unknown envelope type.
The `demo/run_*_demo.py` wrappers now execute implementations under
`attack_lab/scripts/`; these use throwaway databases, logs, keys and exports.

## Build and verify

```sh
npm --prefix web/frontend ci
npm --prefix web/frontend run build
npm --prefix web/frontend run build:lab
.venv/bin/python -m pytest tests/ -q
npm --prefix web/frontend test
npm --prefix web/frontend run test:e2e
npm --prefix web/frontend run test:lab
.venv/bin/python tools/evaluate_security.py
```

The lab Playwright suite uses a temporary DB/state directory and seven real victim
flows. Its harness asserts that the production DB sentinel was never created.
Product HTML/JS byte equality, database isolation/reset, owner-independent lab
controls, request limits, import separation and unknown-type rejection are covered
by Python tests. The evaluator still performs 20 trials of each original category
(120 total) and checks false rejection on 200 normal messages.

Older GUI screenshots 01/03/04/05/09, evaluation screenshot 10,
`docs/history/full_walkthrough.md`, `docs/history/UI_REDESIGN_PROGRESS.md`, documentation PDFs and
local PowerPoint review files predate this separation. PDFs/PowerPoints were not
edited. Current usage is documented here and in the root README.
