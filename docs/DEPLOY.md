# Deploy Team 15 Secure Chat: Phase 5A → your deployment → Phase 5B

The live deployment is provisioned: two Render Free Python services in Singapore,
a private GitHub repository and Neon Free Postgres in AWS Singapore. Results and
URLs are in [live_deployment_report.md](reports/live_deployment_report.md). The services
were created through the Render API using the validated render.yaml settings;
they are not attached to a managed Blueprint. The steps below also document how to
reproduce the deployment. Replace every `<placeholder>` when reproducing it.

## 1. Understand the layout

| Service | Render command | Storage |
|---|---|---|
| Main chat | `python -m web` | Neon Postgres, persistent TSA key in Render environment |
| Separate Attack Lab | `python -m attack_lab` | Own ephemeral SQLite file; resettable sandbox |

Both are **Free Python Web Services**, one process and one instance each. No Docker
is required: FastAPI/Uvicorn run natively. The checked-in frontend bundles are served
by Python, so the Render build installs Python requirements and validates those
bundles. Render does not need Node or a frontend build tool at runtime. Rebuild both
bundles locally before pushing frontend changes. See [Render's Python deployment
instructions](https://render.com/docs/deploy-fastapi).

Render's free services sleep after 15 minutes without inbound traffic and lose local
filesystem changes on restart/redeploy/spin-down. The workspace shares 750 free
instance hours/month. Two continuously running services exceed that budget. There
is **no keep-alive pinger, cron task or background heartbeat** in this setup. Close
both sites after your demo; the open lab console polls while you use it. Open both
URLs **about two minutes before the demo**. This is a course demonstration on free
tiers, with cold starts rather than an availability guarantee. [Render free limits](https://render.com/docs/free).

The roster, lab access sessions, per-IP counters and vault bearer tokens are
process-local. **Do not increase instance count or Uvicorn workers above one.**
A restart loses those connections/tokens. Main users, account locks, encrypted vault
files, relay history and security events persist in Neon. Lab data can disappear.
The Tkinter/CLI TLS transport stays a **local-only demo**: these Render services do
not publish a raw TCP chat listener. Both deployed sites use HTTPS/WSS.

## 2. Prepare your private GitHub repository

1. Check [the phase report](reports/deployment_phase_report.md), especially browser limits
   and the history scan. Do not upload local `data/`, `.env`, keys, logs or evidence.
2. From the project root, install and rebuild:

   ```sh
   .venv/bin/python -m pip install -r requirements-dev.txt
   npm --prefix web/frontend ci
   npm --prefix web/frontend run setup:lint
   npm --prefix web/frontend run build
   npm --prefix web/frontend run build:lab
   .venv/bin/python tools/check_static_assets.py
   .venv/bin/python -m pytest tests/ -q
   npm --prefix web/frontend test
   ```

   To run all browser engines, install them and run the suites:

   ```sh
   npm --prefix web/frontend exec -- playwright install chromium firefox webkit
   npm --prefix web/frontend run test:e2e
   npm --prefix web/frontend run test:lab
   ```

   On the development Mac, Chromium/WebKit pass; Firefox currently fails before
   opening a page with “Could not find profile folder”. To reproduce the verified
   subset use `-- --project=chromium --project=webkit` on each test command. Firefox
   remains configured and should be run on a host where its Playwright build starts.
3. Choose unique Render service names in `render.yaml` (defaults are
   `team15-securechat` and `team15-attack-lab`). Commit any local changes, including
   rebuilt `web/static/` and `attack_lab/static/`.
4. On GitHub, click **+ → New repository**. Name it `CNS-Project`, choose **Private**,
   and leave README/.gitignore/license initialization unchecked. Create it.
5. For a new deployment, copy the repository's SSH or HTTPS remote URL. The current
   private repository already has origin/main configured and pushed; do not repeat
   repository/remote creation against the existing checkout. Example commands:

   ```sh
   git status --short
   git remote -v
   git remote add origin <your-private-repository-URL>
   git push -u origin main
   ```

   If `origin` already exists, inspect it and use `git remote set-url origin ...`
   only if you intend to replace it. GitHub authentication happens through your
   normal SSH key or credential manager; never put a token into a committed URL.

## 3. Create Neon main and disposable test databases

1. Sign in at [Neon](https://console.neon.tech), create a **Free** project, and choose
   an available region near the Render region you will use.
2. On the main branch create/select the `securechat` database and its application
   role. Click **Connect**, select that branch/database/role, choose **Direct**
   (connection pooling off), and copy the PostgreSQL connection string. Store it
   privately; this is the main Render service's `DATABASE_URL`.
3. Preserve `sslmode=require` (or `verify-full` if you configure certificate trust).
   `postgres://` and `postgresql://` are normalized to `postgresql+psycopg://`.
   Insecure SSL modes are rejected. The engine uses pre-ping, a 240-second recycle,
   a two-connection pool plus one overflow connection, and a connection timeout.
   [Neon connection strings](https://neon.com/docs/connect/connect-from-any-app).
4. In **Branches → Create branch**, create a disposable branch such as `cns-tests`.
   Create/select a **separate empty database** such as `securechat_test` there.
   Copy its **Direct/unpooled** connection string. It must differ from main's
   host/branch/database identity. Never use main's URL as `TEST_DATABASE_URL`.
5. On your local machine, enter both URLs through your shell/password manager;
   do not save them in the repository. For example, zsh prompts avoid literal
   secrets in command history:

   ```sh
   read -rs 'DATABASE_URL?Main Neon URL (hidden): '; echo
   read -rs 'TEST_DATABASE_URL?Disposable Neon URL (hidden): '; echo
   export DATABASE_URL TEST_DATABASE_URL
   .venv/bin/python -m pytest tests/test_database.py tests/test_lockout.py \
     tests/test_security_events.py tests/test_web_gateway.py \
     tests/test_evidence_vault.py tests/test_attachments.py tests/postgres/ -q
   unset TEST_DATABASE_URL DATABASE_URL
   ```

   DB-related tests use an isolated generated schema per test and drop that schema
   afterward. Existing local-path tests remain SQLite; backend-dependent core tests
   run on the disposable Postgres branch. `tests/postgres/` additionally exercises
   a real Postgres schema 1→2 upgrade with retained rows. URL guards run **before**
   schema creation and reject main/test equality, role-only differences and pooled
   aliases of the same main database. The test URL must not have custom `options`.
   A missing test URL skips the explicit Postgres upgrade test; it does not claim
   successful Neon verification. The current disposable Neon run passed all **85**
   tests on 17 November 2026; see the live report.

A first main-service start creates schema v3. Existing schemas v1/v2 upgrade additively
inside a transaction/advisory lock. No manual SQL is needed for the app schema.
Main application data is never sent to the disposable branch by the test harness.

## 4. Generate the two secrets locally

Generate the TSA key **once**, before first deployment:

```sh
.venv/bin/python tools/generate_tsa_key.py --print-env
```

The output is the **value** for `TSA_PRIVATE_KEY`, base64-encoded Ed25519 PKCS8 PEM.
Do not paste it into chat, GitHub or logs. On macOS you can append `| pbcopy` to copy
without displaying it. Save the same value in a password manager. `--print-env`
writes no file unless you explicitly supply `--path`; `--path` can export a
previously generated local TSA key if you need to preserve its receipt identity.
Production loads only `TSA_PRIVATE_KEY` and never creates/replaces a disk signing key.

Generate a separate access code:

```sh
.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Paste that value into the lab service's `LAB_ACCESS_CODE`. This is not a chat-account
password or a TSA key. Production requires at least 24 bytes; the command generates
32 random bytes encoded as a longer URL-safe string. Share the code only with lab
visitors. Do not use the public seeded sandbox password as the access code.

## 5. Create the Render Blueprint

1. Sign in at [Render](https://dashboard.render.com). Connect GitHub and grant access
   to **only the private repository you created**.
2. Click **New → Blueprint**, select that repository and the `main` branch, and use
   `render.yaml` at the repository root. Review that there are exactly **two Free
   Python Web Services** and no database, disk, cron or worker resource.
3. Use matching regions for the services where available. Check that each service
   has exactly one instance. The Blueprint supplies Python `3.12.14`, production
   mode, build/start commands and `/healthz` health checks.
4. Fill in the prompted values below. The expected URL is usually based on your
   chosen unique service name; after creation use the **actual URL shown by Render**.
   If it differs, update origins on both services and redeploy.

| Variable | Main service | Attack Lab service |
|---|---|---|
| `APP_ENV` | `production` (Blueprint) | `production` (Blueprint) |
| `PYTHON_VERSION` | `3.12.14` (Blueprint) | `3.12.14` (Blueprint) |
| `PORT` | supplied by Render; leave unset | supplied by Render; leave unset |
| `ALLOWED_ORIGINS` | `https://<actual-main-host>.onrender.com` | `https://<actual-lab-host>.onrender.com` |
| `FORWARDED_ALLOW_IPS` | verified Render ingress IPs/CIDRs; see next section | independently verified lab ingress IPs/CIDRs |
| `DATABASE_URL` | main Neon URL, secret | **unset**; lab refuses this variable in production |
| `TSA_PRIVATE_KEY` | persistent generated value, secret | **unset** |
| `LAB_ACCESS_CODE` | unset | generated access code, secret |
| `MAIN_SITE_ORIGIN` | unset | exact main HTTPS origin |
| `LAB_DATABASE_URL` | unset | `sqlite:///data/attack_lab.db` (Blueprint) |

Origins have no trailing slash, path or wildcard. For a custom domain add that exact
HTTPS origin to the corresponding comma-separated list, while keeping main and lab
disjoint. The old `SECURECHAT_ALLOWED_ORIGINS` and `LAB_ALLOWED_ORIGINS` remain local
compatibility settings; production requires **ALLOWED_ORIGINS**. Do not create a
shared Render environment group containing main DB/TSA secrets and attach it to the lab.
Do not set `TSA_KEY_PATH` as a production persistence mechanism.

5. Click **Apply/Create Blueprint**. Missing secrets, insecure origins, universal
   proxy trust, a main SQLite URL, a shared main/lab database variable or missing lab
   access code cause startup to fail. Use the service's **Logs** and **Environment**
   tabs to correct values, then **Save, rebuild, and deploy**.

[Render Blueprint reference](https://render.com/docs/blueprint-spec).

## 6. Verify the trusted proxy boundary before using logins

The app uses Uvicorn's `ProxyHeadersMiddleware` with **only** the addresses/networks
in `FORWARDED_ALLOW_IPS`. It reads X-Forwarded-For/Proto only when the socket peer is
trusted, taking the rightmost untrusted address in the forwarding chain. Entrypoints
disable the duplicate automatic Uvicorn wrapper. Tests prove that a direct visitor
cannot spoof IP/HTTPS and that two real forwarded clients have different rate buckets.
[Uvicorn's proxy implementation](https://github.com/Kludex/uvicorn/blob/main/uvicorn/middleware/proxy_headers.py).

Phase 5A did not verify ingress peers. Live observations and the owner's approved
configuration now appear below. For a new deployment, do not guess an allowlist or use `*`, `0.0.0.0/0`, `::/0`, or all private ranges.
The application rejects universal trust. Use these fail-closed setup steps:

1. Obtain Render's trusted ingress peer addresses/CIDRs for the service from its
   network configuration/support. If not yet available, `127.0.0.1,::1` is a
   conservative **bootstrap-only** value, not a claim that Render uses loopback.
2. Deploy. `/healthz` can be checked over the internal HTTP connection and checks
   the database. Open the public **HTTPS** URL. If the proxy is not trusted, root
   requests fail with **403 HTTPS required**, and Logs report
   `HTTPS required; untrusted/direct peer <socket-IP>`.
3. Confirm that socket peer belongs to Render's ingress before adding its exact
   address or a Render-confirmed ingress CIDR. Do this independently on both
   services. Do not trust a value from a visitor-supplied forwarding header.
4. Save the verified `FORWARDED_ALLOW_IPS` values and redeploy. Recheck after a
   redeploy if ingress addresses change; use a provider-confirmed stable range
   instead of broadening trust indiscriminately. This check is part of Phase 5B.

This deliberately favors rejection over accepting forged client IPs or treating
all visitors as one proxy address. A successful health check alone does not prove
that public HTTPS/WebSocket proxy configuration is correct.

### Approved live configuration (17 November 2026)

The owner approved loopback plus **10.0.0.0/8**, because observed Render forwarding
hosts rotated between 10.24.95.43, 10.28.53.189 and 10.28.187.27 across redeploys.
This is an explicit deployment decision, not a hard-coded application default or
independent provider confirmation that every address in that range is ingress.
Do **not** add 172.16.0.0/12 or 192.168.0.0/16. The validator accepts this range;
it rejects universal IPv4/IPv6 trust (prefix length zero), not individual private
networks. Direct connections must still come through a trusted socket peer before
forwarding headers are used.

The **full official Cloudflare IPv4 and IPv6 lists** were fetched on 17 November
2026 from [ips-v4](https://www.cloudflare.com/ips-v4) and
[ips-v6](https://www.cloudflare.com/ips-v6), using their trailing-slash variants for
the successful HTTP fetch. The fetched snapshot contains 15 IPv4 and 7 IPv6 CIDRs.
Both services use the following combined value:

```text
127.0.0.1,::1,10.0.0.0/8,173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22,2400:cb00::/32,2606:4700::/32,2803:f800::/32,2405:b500::/32,2405:8100::/32,2a06:98c0::/29,2c0f:f248::/32
```

**Refresh both lists if Cloudflare changes them.** Before refreshing, fetch both
HTTPS endpoints again, validate every entry as a CIDR, retain the approved loopback
and 10/8 entries, and replace the Cloudflare portion with both complete lists. Set
the resulting FORWARDED_ALLOW_IPS on each service, redeploy, and repeat the
forwarding/spoofing and separate-client rate-limit checks. Do not copy IPs from
visitor-supplied headers into this list or broaden other private networks.

The observed direct socket peer was 127.0.0.1, with additional private and
Cloudflare forwarding hops. Thus public HTTPS returned 200 under bootstrap trust,
rather than the anticipated 403; trusting only loopback still resolved the client
to an intermediary. Diagnostic root requests log the original socket peer and
IP-only forwarding chain before normalization, without arbitrary header content.
See [live_deployment_report.md](reports/live_deployment_report.md) for verification status.

## 7. Your initial verification and Phase 5B handoff

1. Open `https://<main>/healthz` and `https://<lab>/healthz`; both should return
   `{"status":"ok"}`. Database failures return a generic 503, with no credentials.
2. On main, check HTTPS, HSTS and CSP in browser developer tools. Open two separate
   browser profiles, register two test identities and exchange a message. Download
   wrapped key backups. A lost browser identity has no recovery service.
3. On lab, confirm the banner and access-code screen. Before entering a code,
   `/victim`, assets, controls and WebSocket admission must be unavailable. Enter
   the access code, start a lab session, reset, connect the victims and try attacks.
   The seed passwords are public sandbox values, never credentials for main.
4. Fetch main `/api/timestamp-key`, save its **public** key/key_id, save/download
   encrypted evidence, and verify the signed JSON. Redeploy main and ensure the
   public key_id is unchanged. Do not regenerate `TSA_PRIVATE_KEY` for redeploys.
5. After startup passes, send the two public URLs and the **test results**, not DB
   passwords or the TSA key, for Phase 5B smoke testing.

Playwright can target live URLs without starting local servers. Use a sandbox/test
window: main tests create uniquely named test users/evidence; lab tests **reset the
shared sandbox**. The TCP interoperability case is explicitly local-only and is
skipped with `BASE_URL` because Render has no raw TCP listener.

```sh
BASE_URL='https://<main>.onrender.com' \
  npm --prefix web/frontend run test:e2e -- --project=chromium
# Set LAB_ACCESS_CODE privately in your shell, not as a literal in shell history.
LAB_URL='https://<lab>.onrender.com' \
  npm --prefix web/frontend run test:lab -- --project=chromium
```

Repeat with `--project=webkit` and `--project=firefox` on a host where those engines
start. Wait at least 60 seconds between lab runs on the same live service to respect
its 10 access-session starts/minute per-IP limit. Local suites use one isolated
throwaway service per browser, so their limits/state do not interfere. Live test
expectations allow longer cold starts, but open both URLs first to avoid Render's
loading page. Phase 5A predates live testing; current verification is recorded in [the final report](reports/final_report.md).

## 8. Redeploy, secrets and demo operation

For frontend changes, run both build commands locally, commit the new static assets,
and push yourself. In each Render service choose **Manual Deploy → Deploy latest
commit** (or use your configured automatic deployment setting). The build validates
committed entry assets, installs pinned Python dependencies, then starts one process.
No secret-generation command runs during build or startup.

Changing environment secrets triggers/requires a redeploy. Keep the TSA key stable:
rotating it changes `key_id`; old receipts still require their saved old public key.
Changing the lab access code plus restarting invalidates the in-memory lab sessions.
The lab is intentionally ephemeral; reset/restart can erase its DB, captures and
sandbox identities. No main credentials belong in that service.

After any redeploy, test health, proxy trust, HTTPS/WSS, receipt key identity and one
fresh chat. A dropped browser connection discards session keys/tokens, retries the
transport with bounded exponential backoff, then requires password login and a fresh
signed handshake. It never silently resumes the old key. Explicit Disconnect stops
retrying, and an unauthenticated idle socket does not loop forever to keep Render awake.

Before the demo: open both URLs roughly two minutes early, enter the lab code,
connect victims, and keep key/evidence backups locally. After the demo: close both
tabs, avoid external uptime pingers, and review free-hour/bandwidth/database usage.

## 9. Attachment storage (Phase 6)

The main service stores encrypted attachments in a **private Neon Object Storage
bucket** (free plan: 5 GB per project, egress shared with Postgres). The lab uses a
local directory and receives no S3 settings.

1. Create the bucket on the main Neon branch: `neonctl buckets create cns-attachments
   --project-id <project> --branch main` (private; the access level cannot be changed
   later). Create a credential with `neonctl credentials create --scope storage:read
   --scope storage:write --name cns-render-main -o json` and capture its output
   directly into Keychain (`cns-s3-access-key-id`, `cns-s3-secret-access-key`;
   endpoint/bucket/region as `cns-s3-endpoint|bucket|region`). Never print or commit
   it; `neonctl credentials reveal` can read it again. Use `neonctl env pull -e
   AWS_ENDPOINT_URL_S3,AWS_REGION` outside the repository for the (non-secret) endpoint.
2. Set the bucket CORS to the main origin only (S3 `PutBucketCors`; Neon has no CLI for it):
   `tools/configure_bucket_cors.py https://<main>.onrender.com` with the five `S3_*`
   variables in the environment.
3. Main service environment: `STORAGE_BACKEND=s3`, `S3_ENDPOINT`, `S3_BUCKET`,
   `S3_REGION`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`. Production start fails
   if any is missing or the endpoint is not HTTPS. Optional: `ATTACHMENT_IMAGE_MAX_BYTES`
   (10 MiB), `ATTACHMENT_VIDEO_MAX_BYTES` (50 MiB), `ATTACHMENT_USER_QUOTA_BYTES`
   (200 MiB), `ATTACHMENT_RETENTION_DAYS` (7), `ATTACHMENT_URL_TTL_SECONDS` (300),
   `ATTACHMENT_INIT_PER_MINUTE` (20), `ATTACHMENT_URLS_PER_MINUTE` (120).
4. The first start upgrades schema v2 → v3 transactionally. Test it on the disposable
   branch (section 3 command; the safety comparison only needs a different placeholder
   `DATABASE_URL`).
5. Rotating the credential: create a new one, update the Render variables, redeploy,
   then `neonctl credentials revoke` the old token.

Free-tier caveat: Neon's free egress (5 GB) is shared by Postgres and the bucket; the
50 MB video limit and 7-day retention keep demo usage small.

## 10. Voice calls and TURN (Phase 7)

Calls are peer to peer. STUN needs no account (`CALL_STUN_URLS`, default Cloudflare and Google
STUN). TURN (needed when a NAT blocks direct paths, typically mobile data) uses the **Metered
free plan** (no card; 500 MB/month, unlimited STUN). Cloudflare Realtime TURN was rejected: its
free 1,000 GB converts to $0.05/GB overage and its docs do not rule out a payment method.

1. Sign up at dashboard.metered.ca, note the app name (`<name>.metered.live`) and the secret key.
2. Keychain (account `team15`): `cns-turn-app` (app name) and `cns-turn-secret-key`.
3. **Main service only**: `METERED_APP` and `METERED_SECRET_KEY` (optional `CALL_STUN_URLS`,
   `CALL_TURN_TTL_SECONDS` (max 600), `CALL_ICE_PER_MINUTE` (10)). Never on the lab.
4. Redeploy. Verify `/api/calls/ice` (logged in) reports `"turn": "available"`; the response
   contains per-call credentials only. The secret key never appears in logs: httpx request
   logging is silenced and exceptions are logged by type only.
5. If the Metered quota runs out, the endpoint reports `"turn": "unavailable"` and calls fall
   back to direct-only, with a note in the call screen.

Browsers need HTTPS and microphone permission; the CSP is unchanged (WebRTC is not governed by
`connect-src`). Local tests use host candidates only (`CALL_STUN_URLS=`) and Chromium's fake
microphone; WebKit has no fake-device switch, so its call media tests are skipped.

### Keepalive and TURN propagation notes

- Logged-in browsers send an authenticated WebSocket `ping` about every 30 s (the server announces its
  idle limit in `session_policy`), so sessions are not dropped after `SECURECHAT_WS_IDLE_SECONDS`
  (default 120). Unauthenticated sockets still time out and an anonymous `ping` is refused. Pings stop 30
  minutes after the last user input, so an abandoned tab does not hold the free instance awake.
- Metered rejects a brand-new credential for up to about a minute. The client fetches and refreshes the
  ICE configuration in the background; wait about a minute after logging in before the first relayed call.
- Metered's credential API needed the plan to be subscribed in the **old** dashboard
  (dashboard.metered.ca, "Old dashboard"): the new dashboard showing the Free plan as active was not enough.
- Force relay-only (hides IP addresses from the peer) by opening the site as `/?relay=1`.


## 11. Final release maintenance (Phase 8)

Install `requirements-dev.txt` for pytest, Ruff and auditing. The runtime deployment
still installs only `requirements.txt`. ESLint has its own pinned TypeScript parser
under `web/frontend/lint/`: run `npm --prefix web/frontend run setup:lint` once after
`npm ci`. This avoids replacing the application’s pinned TypeScript 7 compiler to
satisfy the lint parser’s TypeScript 6 peer dependency. Run `lint`, `format:check`,
`typecheck`, `test`, `build` and `build:lab` from that frontend package.

QuickTime MOV is accepted by magic bytes, using the existing encryption and limits.
Codec support varies: an unsupported video still offers the verified original as a
download. Simultaneous calls converge on the smaller username’s outgoing call; the
other party must still accept it. Logged-in keepalive remains bounded by activity;
no uptime pinger has been added.

Generate current documentation screenshots with `node tools/capture_screenshots.mjs`.
It starts disposable local services and uses synthetic accounts; it does not read
Keychain or contact production. The companion PDF is written only under `/tmp`.
Existing `docs/pdf/` and PowerPoints are historical submission artifacts.
