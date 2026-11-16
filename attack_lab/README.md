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
`demo/full_walkthrough.md`, `docs/UI_REDESIGN_PROGRESS.md`, documentation PDFs and
local PowerPoint review files predate this separation. PDFs/PowerPoints were not
edited. Current usage is documented here and in the root README.
