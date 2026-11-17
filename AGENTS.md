# CNS-Project deployment guardrails

Read docs/DEPLOY.md, docs/reports/deployment_phase_report.md, render.yaml and README.md
before deployment work. Preserve the existing application, SQLAlchemy driver,
custom authentication, E2E crypto and separate Attack Lab architecture.

- Only FREE plans are authorized. If a step requires a paid plan or a card,
  stop and ask the owner. Never upgrade a plan as a quota-reset workaround.
- Target two separate Render Python services and a Neon project in Singapore.
  Keep one process/instance per service. Add no keep-alive pinger.
- Never print, log, echo or commit connection strings, private keys, access codes,
  API keys or OAuth credentials. Never write secrets to any file in this repo.
- Project secrets belong in macOS Keychain, using service cns-<name> and account
  team15. Read them into process memory or pipes/subshells, without displaying them.
- Reuse the cns-tsa-key Keychain item. Generate TSA_PRIVATE_KEY with
  tools/generate_tsa_key.py --print-env only if that item does not exist; capture
  its output directly into Keychain and never regenerate it for a redeploy.
- Use --no-env-pull for Neon link/checkout. Do not run Neon init, env pull or
  config apply/deploy if it would write an environment file in the repository.
- Prefer explicit Neon CLI project/profile/branch arguments. Use --no-secrets
  where available and capture all credential-bearing command output privately.
- Project MCP configuration uses OAuth, with credential storage set to keyring.
  Keep API keys out of MCP TOML/JSON files. Preserve unrelated existing settings.
- Keep main DATABASE_URL/TSA secrets out of the lab service. Lab storage is its
  own ephemeral SQLite database; the lab requires LAB_ACCESS_CODE.
- Bootstrap FORWARDED_ALLOW_IPS is 127.0.0.1,::1. Observe ingress peers across
  requests/redeploys and obtain explicit owner approval before changing trust.
  Never trust *, 0.0.0.0/0, ::/0 or all private ranges.
- Push the current Git branch without renaming it. Do not rewrite history.
  Scan history and working-tree files for secrets before pushing.

- On 17 November 2026 the owner explicitly approved loopback plus 10.0.0.0/8
  and both complete official Cloudflare IPv4/IPv6 lists for these two services.
  Apply this approved configuration without asking again; see DEPLOY.md section 6.
  Do not add 172.16.0.0/12 or 192.168.0.0/16. Refresh Cloudflare ranges if changed.
