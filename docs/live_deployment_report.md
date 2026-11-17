# Live deployment report — 17 November 2026

Completed provisioning and available-browser live verification. Everything remains
on Free plans. Firefox was attempted but cannot launch its profile on this Mac.

## Timing

Initial estimate: **60–100 minutes excluding login/approval waits**.
Report prepared at **10:46 IST**, about **65 minutes** after
09:40:53 IST, including browser logins, phone checks and proxy approval waits.
The main extra work was diagnosing the actual proxy chain, a cold-load lab button
race, and synchronizing the restore test with the relay's disconnect acknowledgment.

## Resources and URLs

- Main: https://team15-securechat.onrender.com
- Separate Attack Lab: https://team15-attack-lab.onrender.com
- Private GitHub repository: `sharansp95-rgb/CNS-Project`, branch `main`, pushed.
- Render: two Free Python web services, Singapore, one instance/process each;
  Python 3.12.14 built successfully. No disk, paid database, worker, scheduler,
  keep-alive pinger or paid plan was created.
- Neon: Free project `CNS-Project`, AWS Singapore (`aws-ap-southeast-1`), PostgreSQL
  17, 0.25 CU; main database `securechat`; disposable branch `cns-tests` with an
  empty `securechat_test` database provisioned for isolated test schemas.
- Existing unrelated Neon project and unrelated local/global configuration preserved.
- Main retains Neon DB/TSA secrets; lab has its own ephemeral SQLite DB and access
  code, with no main DATABASE_URL or TSA_PRIVATE_KEY.
- Render Blueprint validation passed. Services were created through the API using
  render.yaml settings, rather than attached to a managed Blueprint resource.
  Future manifest edits require explicit API/config synchronization or Blueprint
  adoption; they do not automatically reconfigure these services.

## Test counts and acceptance

| Suite / check | Before | After / live |
|---|---|---|
| Local pytest | Phase 5A: 416 passed, 1 opt-in skip | **417 passed, 1 opt-in skip**, 70.33 seconds |
| Disposable real Neon Postgres, DEPLOY.md section 3 command | Not run | **68 passed**, 420.75 seconds |
| Focused production configuration | 20 tests before added diagnostic case | **21 passed** |
| Vitest | 32 passed | **32 passed** |
| Main Chromium | Local Phase 5A: 6 passed | **5 passed, 1 local-only TCP skip**, 38.4 seconds |
| Lab Chromium | Local Phase 5A: 7 passed | **7 passed**, 47.1 seconds |
| Main WebKit | Local Phase 5A: 6 passed | **5 passed, 1 local-only TCP skip**, 42.4 seconds |
| Lab WebKit | Local Phase 5A: 7 passed | **7 passed**, 47.4 seconds |
| Main Firefox | Profile launcher failed locally | Attempted live suite: launch failed before test body; 1 failed setup, 5 not run |
| Lab Firefox | Profile launcher failed locally | Attempted live suite: launch failed before test body; 1 failed setup, 6 not run |
| Static artifact validator | Passed | Passed after lab rebuild |

Available-browser live total: **24 passed, 2 intentional local-TCP skips**.
Firefox is **unverified**, not counted as a passing or skipped browser. Both attempts
failed with “Could not find profile folder” in Playwright Firefox build 1572 before
any page opened. This host limitation was present before deployment.

The Postgres command used unique schemas on the disposable database and cleaned
them afterward; no test harness schema was created on main. The full local suite
intentionally lacks the opt-in URL and skips that one case; real Neon verification
is the separate 68-test run. Existing Starlette/httpx deprecation warnings remain.

Live checks passed:

- Both DB-backed /healthz responses return 200/ok; public HTTPS has HSTS and CSP.
- Real WSS chat, two-user signed handshakes, encrypted bidirectional messages,
  receipt inspection, wrapped identity export/import, reconnect and fresh session.
- Encrypted evidence save/list/download/delete, companion PDF download, signed
  receipt verification, and local-only /verify with tampered-message detection.
- Lab code screen gates victim HTML, assets and controls before entry (401);
  unauthenticated lab WSS and wrong-origin main WSS fail admission (403).
- All seven lab attacks produce the real victim/lockout detections in both engines.
- Main timestamp key identity survived the approved-proxy redeploy unchanged:
  `fddef29a1a2e7691f2bc5c1736b271d7770f0d7fa6c60560c44dae0b7c27b436`.
- A count-only scan of every application table/column found **zero matches** for
  four known synthetic plaintext message markers from the real live browser tests.
  This includes users, login_lockouts, security_events, relayed_envelopes,
  evidence_bundles and schema_version. No live user conversations were retrieved.

## Proxy observations, approval and final value

Five root probes per service before and after a redeploy showed:

| Service | Raw socket peer | Private forwarding hops | Cloudflare forwarding hops |
|---|---|---|---|
| Main | 127.0.0.1 | 10.24.95.43, 10.28.53.189, 10.28.187.27 | 162.158.162.11, 162.158.41.50, 172.68.79.147 |
| Lab | 127.0.0.1 | 10.24.95.43, 10.28.53.189, 10.28.187.27 | 162.158.41.31, 172.68.79.182, 172.71.124.112 |

Expected bootstrap 403 was absent on public HTTPS because the socket peer already
was loopback. With only loopback trusted, the derived client was an intermediary.
Added IP-only diagnostics before normalization to expose this boundary accurately;
arbitrary header strings, URLs and secrets are excluded from those diagnostics.

The owner rejected the initial individual-host proposal and explicitly approved
loopback, **10.0.0.0/8**, and the **complete official Cloudflare IPv4 + IPv6 lists**.
The validator accepts 10/8; it rejects universal /0 trust. Neither 172.16.0.0/12 nor
192.168.0.0/16 was added. No universal IPv4/IPv6 range or wildcard is trusted.

Fetched fresh on 17 November 2026: [Cloudflare IPv4](https://www.cloudflare.com/ips-v4)
and [Cloudflare IPv6](https://www.cloudflare.com/ips-v6), using their trailing-slash
variants for the HTTP fetch. The snapshot has 15 IPv4 and 7 IPv6 entries.
Both services were independently checked against this exact final value:

```text
127.0.0.1,::1,10.0.0.0/8,173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22,2400:cb00::/32,2606:4700::/32,2803:f800::/32,2405:b500::/32,2405:8100::/32,2a06:98c0::/29,2c0f:f248::/32
```

**Refresh both lists if Cloudflare changes them.** DEPLOY.md section 6 documents
the authoritative sources and refresh/redeploy/reverification procedure. The 10/8
scope is the owner's explicit deployment choice based on rotating private hops;
it is not a newly claimed provider-confirmed ingress CIDR. No other private network
was broadened or inferred.

Real-client verification used the Mac and the owner's phone on mobile data:

- The Mac sent a forged X-Forwarded-For value of 198.51.100.77. Its authentication
  audit events used its real public address, never that spoofed address or a proxy.
  A second WebSocket probe with 198.51.100.88 was also ignored.
- The phone's actual authentication/registration audit records use a different
  public address from the Mac. Public visitor IPs are omitted from this report.
- During the final controlled Mac rate-limit run, **226** attempts were rejected.
  The phone simultaneously registered the dedicated test identity successfully;
  the nearest Mac rate-limit rejection was **5.07 seconds** from that registration.
  This verifies distinct live rate-limit buckets rather than a shared proxy bucket.
- The owner supplied a mobile-data screenshot confirming authenticated phone chat.
  No password or private key was requested for the check.

## Application/test changes

- Production root-request diagnostics record the original socket peer and only
  validated forwarding IP literals before Uvicorn normalization.
- render.yaml explicitly pins Singapore; service plans remain Free/one instance.
- Live Playwright traces are disabled to avoid recording the lab admission secret;
  local trace behavior is preserved. Live runner output was captured and redacted,
  with sanitized diagnostics/artifacts outside the repository.
- Fixed a real cold-load lab race: Start lab session is disabled in the static HTML
  until its module installs handlers. Rebuilt and committed lab static assets.
  Initially 6/7 live Chromium lab cases passed; all 7 passed after the fix.
- Strengthened the restore E2E test by waiting for the existing peer-disconnected
  notice before closing contexts and logging the restored identity in. The first
  live run reached restore too early and saw already logged in elsewhere. All
  original assertions remain; one acknowledgment assertion was added. No sleeps,
  weakened crypto parameters, disabled detections or forced login replacement.
- Added a production diagnostic test for original peer preservation and exclusion
  of arbitrary header text. No assertion was weakened or deleted.
- Updated README URLs/results, DEPLOY.md proxy sources/refresh procedure,
  architecture deployment notes and the historical preparation report cross-link.
  No PDF or PowerPoint was edited; main static crypto bundle did not change.

## Neon skills, CLIs and preserved configuration

Installed neonctl 9.5.1 and Render CLI 2.37.0; existing git/gh/Homebrew/npm preserved.
Installed the project Neon and Neon Postgres skills (14 files), skills-lock.json,
OAuth Neon MCP configuration and AGENTS.md deployment guardrails. Existing unrelated
global Codex configuration was preserved. Neon CLI uses profile cns-team15 and the
OS keyring; MCP OAuth login succeeded with credential storage set to keyring, and
Neon MCP tools are now exposed in the session. No new app framework/ORM/driver,
Neon Auth, Functions or other backend product was introduced.

The Neon CLI falsely reported freshly installed skills as outdated while its updater
found no updates. All 14 files were independently compared with upstream commit
60b9a53fdd08c3be22781c5e51f6b689a77d3e39 and matched exactly; the requested skill URL
also matched. No lock metadata/version was fabricated and the CLI was not patched.

## Secret inventory — item names only

All project Keychain items below use account team15:

| Keychain item | Secret purpose |
|---|---|
| cns-database-url | Direct main Neon connection, sslmode=require |
| cns-test-database-url | Direct disposable test Neon connection, sslmode=require |
| cns-tsa-key | Persistent Ed25519 TSA material, generated once and reused |
| cns-lab-access-code | Random lab admission code |
| cns-render-api-key | Render API access |
| cns-render-cli-token | Render CLI login credential |
| cns-render-cli-refresh-token | Render CLI refresh credential |

Render CLI credentials were moved out of its newly created YAML config into Keychain;
workspace and other settings were retained. Later CLI calls receive the Keychain API
key via process environment. Neon CLI/MCP OAuth credentials use their Keychain stores.
No connection string, private key, lab code or API key was put into this repository,
a chat message or a committed command/config. TSA generation was not repeated.

## Files changed since the deployment-preparation baseline

```text
A	.agents/skills/neon-postgres/SKILL.md
A	.agents/skills/neon-postgres/references/branching.md
A	.agents/skills/neon-postgres/references/egress-optimization.md
A	.agents/skills/neon-postgres/references/full-text-search.md
A	.agents/skills/neon-postgres/references/hybrid-search.md
A	.agents/skills/neon-postgres/references/lakebase-search-drizzle.md
A	.agents/skills/neon-postgres/references/vector-search.md
A	.agents/skills/neon/SKILL.md
A	.agents/skills/neon/references/auth.md
A	.agents/skills/neon/references/claimable-neon.md
A	.agents/skills/neon/references/function-triggers.md
A	.agents/skills/neon/references/logs-loki.md
A	.agents/skills/neon/references/parse-env.md
A	.agents/skills/neon/references/sdk.md
A	.codex/config.toml
A	AGENTS.md
M	README.md
M	attack_lab/frontend/index.html
M	attack_lab/frontend/main.ts
R099	attack_lab/static/console-assets/index-BtWmFAYV.js	attack_lab/static/console-assets/index-Do076U0j.js
M	attack_lab/static/index.html
M	docs/DEPLOY.md
M	docs/architecture.md
M	docs/deployment_phase_report.md
A	docs/live_deployment_report.md
M	render.yaml
A	skills-lock.json
M	tests/test_production_config.py
M	web/frontend/e2e/chat.spec.ts
M	web/frontend/playwright.config.ts
M	web/frontend/playwright.lab.config.ts
M	web/settings.py

```

## Limits / not verified

- Firefox application behavior is unverified because the browser cannot launch.
- Public Render services intentionally do not expose TCP; two live TCP skips are
  expected. Previous local TCP interop remains the applicable coverage.
- Future Cloudflare list changes require manual refresh; no background updater was
  added. Long-term Render ingress ownership/stability beyond observed probes is not
  independently provider-certified; the final trust scope is owner-approved.
- Services were API-provisioned from the manifest, not linked to a managed Blueprint.
- No availability/load guarantee is claimed. Free Render services can sleep after
  idle time and share the workspace's 750 instance-hours/month; no pinger was added.
- Controlled test identities/audit records remain as demonstration/test data. No
  existing live identities or conversations were deleted during deployment.

Commit log snapshot before the final report commit (the final chat prints current
`git log --oneline -5` after the push):

```text
70d5372 Apply approved proxy deployment guidance and fix lab startup readiness
b25cfce Document live service URLs and pending proxy trust review
ebc0eaf Record raw ingress boundary and protect live test credentials
e6e1acf Configure project Neon skills and Keychain-backed OAuth MCP
6b26fc3 Document Render and Neon deployment handoff and verification limits

```
