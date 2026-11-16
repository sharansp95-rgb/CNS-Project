# Phase 5A: deployment preparation report

Prepared locally on **17 November 2026 (IST)**. Target: separate Render Free Python
web services plus Neon for main. No GitHub repository was created, no push was run,
no cloud account was changed and neither service was deployed. The next steps are
in [DEPLOY.md](DEPLOY.md); live verification remains Phase 5B.

## Time

Initial estimate: **100 minutes** (10 baseline, 20 config/proxy/HTTPS, 15 DB/TSA/test
support, 20 reconnect/access, 25 verification, 10 docs/commits). Actual: approximately
**38 minutes**, from 00:48 IST to about 01:26 IST on 17 November. The main realized
risk was browser crypto compatibility; Firefox was additionally blocked by its local
browser launcher. No account/deployment waiting time is included because none was done.

## Validation

| Suite / engine | Before | After |
|---|---:|---:|
| pytest | 396 passed | **416 passed, 1 skipped, 0 failed** |
| Vitest | 27 passed | **32 passed** |
| Chromium main | 5 passed | **6 passed** |
| Chromium lab | 7 passed | **7 passed** |
| WebKit main | not previously run | **6 passed** |
| WebKit lab | not previously run | **7 passed** |
| Firefox main/lab | not previously run | **unverified: browser process fails before any test body** |

The Python baseline was rerun before changes. Before browser/Vitest counts are the
recorded 42e1007 baseline. Final available-browser total is **26 passing**. The full
Python suite emits the existing Starlette/httpx test-client deprecation warning.
The skipped case is the opt-in real Postgres schema upgrade, because no disposable
Neon TEST_DATABASE_URL was supplied. DB-related existing tests are ready to run with
that URL; they continue to pass on isolated SQLite locally. No assertion was weakened. The final bounded-request hardening also passed a
39-test focused production/lab regression run after the full suite.

Firefox 159 / Playwright build 1572 downloaded, but launch exits with
**“Could not find profile folder.”** Both suites were attempted. Canonical temporary
paths, persistent temporary profiles and additional launch diagnostics did not make
this binary start. Firefox remains configured; its failures are not reported as
application passes. Chromium and WebKit suite bodies all pass. The production TCP
interop test is explicitly local-only and skipped only when BASE_URL selects a live
service, since the target Render services do not expose raw TCP.

Both frontend builds and the committed-asset validator pass. Render YAML parses in
Prettier. Render's account/API Blueprint validation and actual build have not been
run. The build uses checked-in bundles, so the Python runtime does not require Node.

Additional regression evaluation (`--skip-tests`, with pytest run separately):
**120/120 attack detections**, **0/200 false rejections**, **real data unchanged**.
Message median 1.893 ms / p95 2.215 ms; setup median 48.7 ms. These remain loopback
measurements with the evaluator's shortened lockout schedule, not deployed latency.

## What changed

- Shared strict production configuration: explicit HTTPS origins, trusted ingress
  IPs/CIDRs, HSTS, HTTPS/WSS enforcement, no debug and DB-backed /healthz. Uvicorn's
  proxy middleware is installed once at the app boundary; automatic duplicate
  wrapping is disabled. Forwarding headers from other socket peers are ignored.
- Main production startup requires Postgres and a valid dedicated environment TSA
  key. PostgreSQL URLs normalize to psycopg 3 and require TLS; the pool pre-pings,
  recycles after 240 seconds and caps at two normal plus one overflow connection.
- TSA_PRIVATE_KEY accepts base64 PEM or PEM. Production never generates a disk TSA
  key. `generate_tsa_key.py --print-env` prints a value without writing local state,
  unless an explicit --path is supplied. Environment key identities remain stable
  across signer reconstruction; actual Render redeploy persistence awaits Phase 5B.
- LAB_ACCESS_CODE gates sandbox HTML/assets/controls/WS admission using constant-time
  comparison, per-source attempt limits and opaque HttpOnly sessions. Production
  cookies are Secure. The lab has noindex metadata/header, rejects a main DATABASE_URL,
  enforces its own SQLite storage and requires a distinct MAIN_SITE_ORIGIN.
- Main and lab origin/DB/roster separation remains intact, including URL alias checks
  after introducing postgres:// normalization. The lab's shared core/client bundle
  still performs genuine crypto and detections.
- A dropped client connection discards keys, pending ECDH state and bearer tokens;
  bounded retries restore transport, then password login and a new signed handshake
  are required. Passwords are not retained for silent login. Explicit disconnect
  cancels retries. Generation checks prevent stale async work from restoring old keys.
  A peer leaving also invalidates that peer session. Browser tests prove the new
  handshake public key differs and subsequent messages verify.
- WebKit's native RSA-PSS cannot sign with the existing protocol's **222-byte salt**.
  Pinned `node-forge==1.4.3` provides a client-local fallback with SHA-256/MGF1-SHA256
  and the same 222-byte CSPRNG salt; no crypto parameter or verifier was downgraded.
  Native-capable engines keep WebCrypto signing. Native runtime private CryptoKeys
  are non-extractable; the WebKit fallback additionally keeps a JavaScript RSA key
  in a private WeakMap, so it cannot promise native non-extractability for that key.
  This memory trade-off is documented in README. Unwrapped keys are never uploaded
  or persisted to browser storage/DB. Python interoperability, valid evidence and
  tamper rejection pass on WebKit as well as Chromium.
- Long names now wrap in the mobile chat header rather than widening the viewport.
- BASE_URL/LAB_URL select external Playwright targets without launching local servers.
  Local test services are isolated per browser to avoid DB/account/rate-limit mixing.
- Disposable Postgres tests use unique schemas on a separate branch/database, with
  safety checks before schema creation and cleanup afterward. A real v1→v2 Postgres
  upgrade test is provided but not falsely counted as verified without Neon.
- render.yaml declares exactly two free Python services, one instance/worker each,
  health checks, secret/config prompts and no pinger, disk, database resource or cron.
  DEPLOY.md covers private GitHub push, Neon, secrets, Render, proxy bootstrap,
  verification, redeploy and cold-start limitations. Only the owner performs those steps.

## Secrets/history scan

`tools/scan_git_history.py` scans **all refs plus local reflogs**, not just HEAD, and
also checks non-ignored working-tree files. The initial scan covered 15 reachable
commits, 16 including the local reflog, and 270 historical blobs. No sensitive findings.

After the three implementation commits, the pre-documentation snapshot covers
**18 reachable commits, 19 including reflogs, 312 unique historical blobs**, plus the
working tree. See [secret_scan_report.json](secret_scan_report.json). A final scan
also runs after the documentation commit. No history was rewritten.

The only historical PEM is **tests/fixtures/evidence_corpus/tsa_public.pem**, a public
verification key. Flagged DB URLs in README and tests contain explicit localhost or
synthetic placeholders. Synthetic evidence fixtures/test access codes are deliberate
public test data. No tracked private key, real credential, .env, cert key, users DB,
data/, logs/ or exports/ was found. This is a pattern/path review, not an exhaustive
proof or OCR inspection of document images. No secret values are printed by the tool.

## Environment values per service

| Main | Lab |
|---|---|
| APP_ENV=production | APP_ENV=production |
| PYTHON_VERSION=3.12.14 | PYTHON_VERSION=3.12.14 |
| PORT supplied by Render | PORT supplied by Render |
| ALLOWED_ORIGINS=exact main HTTPS origin | ALLOWED_ORIGINS=exact lab HTTPS origin |
| FORWARDED_ALLOW_IPS=verified ingress IPs/CIDRs | FORWARDED_ALLOW_IPS=verified ingress IPs/CIDRs |
| DATABASE_URL=main Neon URL (secret) | LAB_DATABASE_URL=sqlite:///data/attack_lab.db |
| TSA_PRIVATE_KEY=persistent base64/PEM (secret) | LAB_ACCESS_CODE=strong generated code (secret) |
| no lab secrets | MAIN_SITE_ORIGIN=exact main HTTPS origin |
| single worker/instance | DATABASE_URL and TSA_PRIVATE_KEY unset |

Local compatibility settings remain documented. There is no shared secret environment
group between services. Production does not use TSA_KEY_PATH for persistent identity.

## Not verified / operational limits

- No live Render URLs, actual ingress peer ranges, HTTPS proxy route, cold start,
  redeploy, persistent environment configuration or free-tier usage has been tested.
  Proxy trust must be verified by the owner using the fail-closed steps in DEPLOY.md;
  universal trust is refused. A health check alone does not verify public WSS.
- No real Neon/Postgres test branch exists in this session; Docker is unavailable.
  PostgreSQL runtime schema creation and 1→2 upgrade need the documented opt-in run.
- Firefox application behavior remains unverified because the browser cannot start.
- One process/instance is required. Reconnect does not migrate an existing transcript
  into a new evidence session or silently replay unsent messages.
- Lab restart/reset may erase sandbox data. The access session and tokens are in
  memory; restarting invalidates them. The active lab console's normal state polling
  uses free instance hours, so close both sites when finished. No artificial uptime
  pinger was added. Main durable data is stored in Neon, not the ephemeral filesystem.
- Desktop Tkinter/CLI TCP remains local-only; no Render TCP listener is configured.
- PDFs, PowerPoints and historical screenshots were not edited.

## Files added, changed or replaced

The complete list relative to 42e1007 follows. Generated bundles are replaced by
content hash; the original Python offline verifier and wire/evidence formats remain
unchanged. Schema version stays 2.

| Status | Path |
|---|---|
| Changed | `README.md` |
| Changed | `attack_lab/README.md` |
| Changed | `attack_lab/__main__.py` |
| Added | `attack_lab/access.html` |
| Added | `attack_lab/access.py` |
| Changed | `attack_lab/app.py` |
| Changed | `attack_lab/e2e/lab.spec.ts` |
| Changed | `attack_lab/frontend/index.html` |
| Changed | `attack_lab/relay.py` |
| Changed | `attack_lab/static/index.html` |
| Changed | `attack_lab/tests/run_server.py` |
| Added | `docs/DEPLOY.md` |
| Changed | `docs/architecture.md` |
| Added | `docs/deployment_phase_report.md` |
| Added | `docs/secret_scan_report.json` |
| Added | `render.yaml` |
| Changed | `server/db.py` |
| Changed | `server/timestamp.py` |
| Changed | `tests/conftest.py` |
| Added | `tests/postgres/test_postgres_upgrade.py` |
| Added | `tests/test_production_config.py` |
| Added | `tools/check_static_assets.py` |
| Changed | `tools/generate_tsa_key.py` |
| Added | `tools/postgres_test_support.py` |
| Added | `tools/scan_git_history.py` |
| Changed | `web/__main__.py` |
| Changed | `web/app.py` |
| Changed | `web/frontend/e2e/chat.spec.ts` |
| Changed | `web/frontend/package-lock.json` |
| Changed | `web/frontend/package.json` |
| Changed | `web/frontend/playwright.config.ts` |
| Changed | `web/frontend/playwright.lab.config.ts` |
| Changed | `web/frontend/src/crypto.ts` |
| Changed | `web/frontend/src/main.tsx` |
| Changed | `web/frontend/src/session.ts` |
| Changed | `web/frontend/src/style.css` |
| Changed | `web/frontend/tests/crypto.test.ts` |
| Changed | `web/frontend/tests/run_server.py` |
| Changed | `web/frontend/tests/session.test.ts` |
| Added | `web/settings.py` |
| Removed | `web/static/assets/index-BAhF9pdI.js` |
| Renamed/rebuilt | `web/static/assets/index-pwx9hb5V.css → web/static/assets/index-DbOtNzsy.css` |
| Added | `web/static/assets/index-DjGwI8Ft.js` |
| Added | `web/static/assets/lib-CiZnxx6k.js` |
| Renamed/rebuilt | `web/static/assets/pdfReport-bDgB53ka.js → web/static/assets/pdfReport-BAEIKt6X.js` |
| Added | `web/static/assets/rolldown-runtime-WkwZ5CU-.js` |
| Changed | `web/static/index.html` |

## Owner checklist

1. Create a private GitHub repository and push the local main branch yourself.
2. Create Neon main and disposable test databases; run the opt-in Postgres tests.
3. Generate/store the persistent TSA key and a separate strong lab access code.
4. Deploy the two Free Python services with render.yaml, correct origins and verified proxy trust.
5. Verify health, HTTPS/WSS, unchanged TSA key_id and one chat; return the two URLs for Phase 5B.
