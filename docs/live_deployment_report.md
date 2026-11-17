# Live deployment progress — 17 November 2026

Status: services provisioned; owner approval of proxy trust and live browser
verification remain pending. This is a progress report, not a completed acceptance.

## Resources

- Private GitHub repository: `sharansp95-rgb/CNS-Project`, current branch `main`.
- Main: https://team15-securechat.onrender.com
- Separate lab: https://team15-attack-lab.onrender.com
- Both Render services: Free Python plan, Singapore, one instance/process.
- Neon: Free project `CNS-Project`, AWS Singapore, PostgreSQL 17, 0.25 CU.
  Main database `securechat`; disposable `cns-tests` branch/database
  `securechat_test`. Existing unrelated Neon projects were preserved.
- Python 3.12.14 deployed successfully; both DB-backed health checks return 200.
- Main DB and timestamp secrets are absent from the lab environment.

## Validation so far

| Suite | Result |
|---|---|
| Local Python before deployment changes | 416 passed, 1 opt-in Postgres skip |
| Local Python after ingress diagnostic | 417 passed, 1 opt-in Postgres skip |
| Disposable Neon Postgres command in DEPLOY.md section 3 | 68 passed in 420.75 seconds |
| Focused production configuration | 21 passed |
| Vitest | 32 passed |
| Committed static asset validation | Passed |
| Render API Blueprint validation | Passed |
| Live Chromium/WebKit/Firefox | Pending proxy review |

The Postgres suite uses isolated schemas on the disposable database. Main service
data was not used as test storage. The full local suite intentionally omits the
opt-in Postgres URL; its skip does not negate the separately completed Neon run.
The existing Starlette/httpx deprecation warning remains. No assertions were removed
or weakened. One test was added for raw socket-peer diagnostics and exclusion of
arbitrary forwarding header text from logs.

## Configuration and secret handling

Installed `neonctl` 9.5.1 and Render CLI 2.37.0. Existing GitHub authentication and
unrelated global Codex configuration were preserved. Installed project Neon and
Neon Postgres skills, their lock file, OAuth MCP configuration with Keychain-backed
credentials, and project deployment guardrails in AGENTS.md. OAuth authentication
completed for Neon CLI, Neon MCP and Render CLI.

The Neon CLI immediately reported its freshly installed skills as outdated, while
its updater reported no updates. All 14 installed skill files were independently
compared with the current upstream commit and matched exactly. The requested Neon
overview URL also matched. No versions or lock metadata were fabricated.

Keychain project items use account `team15`:

| Item | Purpose |
|---|---|
| `cns-database-url` | Direct main Neon connection |
| `cns-test-database-url` | Direct disposable Neon test connection |
| `cns-tsa-key` | Persistent Ed25519 receipt key, generated once |
| `cns-lab-access-code` | Lab admission secret |
| `cns-render-api-key` | Render API access |
| `cns-render-cli-token` | Render CLI login credential |
| `cns-render-cli-refresh-token` | Render CLI refresh credential |

CLI login credentials were moved out of Render YAML configuration into Keychain;
workspace and other configuration were preserved. Subsequent CLI commands receive
the API key through process environment. No secret values were written to this
repository. Credential-bearing API/CLI output was captured rather than displayed.
Live Playwright traces are disabled to prevent recording the lab admission code.
Local traces retain their previous setting.

## Proxy review

Both services retain bootstrap `FORWARDED_ALLOW_IPS=127.0.0.1,::1`.
Public root requests unexpectedly return 200 rather than the anticipated 403.
Added production-only root-request diagnostics before proxy processing to capture
socket peer and IP-only forwarding chains. These show a loopback socket connection
and additional private ingress and Cloudflare hops. Without trusting those hops,
client rate limits may use an intermediary address. No additional proxy addresses
have been trusted. Comparison across redeploys is complete; explicit owner approval is
required before the remaining live verification.

Five root probes per service were made before and after a redeploy. Diagnostics
showed the following proxy hops (actual visitor addresses are omitted here):

| Service | Raw socket peer | Private forwarding hops | Cloudflare forwarding hops |
|---|---|---|---|
| Main | 127.0.0.1 | 10.24.95.43, 10.28.53.189, 10.28.187.27 | 162.158.162.11, 162.158.41.50, 172.68.79.147 |
| Lab | 127.0.0.1 | 10.24.95.43, 10.28.53.189, 10.28.187.27 | 162.158.41.31, 172.68.79.182, 172.71.124.112 |

Proposed value for both services, **not applied**:

```text
127.0.0.1,::1,10.24.95.43,10.28.53.189,10.28.187.27,162.158.0.0/15,172.64.0.0/13
```

The two public CIDRs are the [Cloudflare-published ranges](https://www.cloudflare.com/ips-v4/)
containing the observed Cloudflare hops. Private addresses are individual observed
hosts, not a guessed private CIDR. Their stability beyond these probes/redeploys
is not established. Future ingress changes may require another review; this is not
a provider-confirmed permanent Render allowlist. Only loopback remains configured.
The expected bootstrap 403 did not occur for public HTTPS because the direct socket
is already loopback; internal root probes without forwarding headers were rejected.

## Remaining acceptance work

- Obtain explicit approval of the recorded proxy-trust proposal.
- Set only the approved addresses, redeploy and verify headers, WSS, lab gate,
  chat, encrypted evidence and stable TSA key identity.
- Run live browser suites, attempt Firefox, and verify client-IP rate separation.
- Complete final timing, test results, observed/final proxy values and commit log.

Initial estimate: 60–100 minutes excluding login and approval waits. Deployment
work began at 09:40:53 IST. Completion time remains pending the approval gate.
