> Historical phase report, moved during Phase 8. Results and path inventories describe that phase; links point to their current locations. See [final_report.md](final_report.md) for the final state.

# Attack Lab separation phase report

Completed locally on 16 November 2026. No push or deployment performed.

## Estimate versus elapsed time

The initial plan estimated 95 minutes: product separation 25, sandbox 35,
verification 25, docs/commits 10. Start recorded at 09:56 UTC (15:26 IST);
completion around 14:30 UTC (20:00 IST): approximately 274 minutes elapsed.
This includes the long gap between the earlier status update and the request to
resume; it is not a measure of continuous execution. Active time was not instrumented.

The material risks were explicit database scoping, preserving genuine client checks,
and migrating GUI/demo tests. Verification found and corrected two TLS adapter error
logging calls that bypassed the supplied logger. An intermediate evaluator therefore
reported real-data changes (three synthetic TLS-error metadata events reached the
normal audit DB/log). Existing audit history was not deleted. After correction, the
full evaluator confirms real data unchanged, and a regression forbids the fallback.

## Test counts and measured results

| Suite | Before | After |
|---|---:|---:|
| pytest | 394 passed | 396 passed, 0 failed, 0 skipped |
| Vitest | 27 passed | 27 passed |
| Product Playwright / Chromium | 5 passed | 5 passed |
| Separate lab Playwright / Chromium | absent | 7 passed |

The full evaluator ran pytest and 20 trials of each original attack category:
**120/120 detected**, **0/200 false rejections**, **real data unchanged**.
Message latency median 1.859 ms, p95 1.985 ms; full two-user session setup median
48.1 ms, p95 49.6 ms. These are loopback results, with the evaluator's shortened
0.5-second lockout schedule and disabled source-address throttle for repeated trials.
Detailed parameters/raw outcomes are in `evaluation_results.md` and
`evaluation_results.json`. The seven browser flows separately cover reorder and
injection as well as tamper, replay, drop, MITM and sandbox brute force.

Both static builds completed. Rebuilding production assets was byte-identical,
so `web/static` has no content diff. Tests compare the sandbox victim HTML and
JavaScript byte-for-byte with those production assets. A read-only AST comparison
against dca237f confirmed that the Python crypto, handshake and verification methods
were unchanged; only lab state/control/event handling was removed.

Compatibility tamper/evidence demos passed in pytest. Replay, drop and MITM scripts
were also run directly and passed. The launcher passed shell syntax checks and a
real HTTP/optional-TCP smoke run with temporary state and an absent production DB
sentinel. Production script startup is covered in pytest.

## Implementation and boundaries

- `attack_lab` is a separate site/process with a separate Vite console entry, explicit
  SQL user-store/lockout/logger dependencies, own roster, database, log and TLS state.
- Victims use the unchanged production client bundle. Controls fill real forms;
  no client cryptography, detection or rejection is substituted. The console only
  displays actual victim reports and real lockout events as detections.
- Production has no attack flag, routes, control dispatch or Tk panel. One neutral
  optional envelope interceptor remains, defaulting to None. Unknown product
  envelope types are rejected and logged, including former lab controls.
- Authenticated lab controls have Origin checks, sandbox-only targets and separate
  read/write rate limits. Reset closes lab peers, wipes only lab rows, clears pending
  attacks/captures and reseeds the two victims plus the lockout-only account.
- Database URL guards reject configured/default production DB aliases. SQLite path
  resolution and same-file checks also reject symlinks/hardlinks; SQLite URI aliases
  are refused. PostgreSQL database names must differ. Operator-controlled config
  and database credentials remain a trusted deployment responsibility.
- The DB schema remains version 2. Lab storage reuses the schema in its own DB;
  the evidence formats and cryptographic parameters from the evidence phase did
  not change. No chat plaintext, private keys or session keys are added to relay
  storage. As before, authentication passwords terminate at the gateway.
- The former GUI explanation helpers were moved to `attack_lab/presentation.py` for
  compatibility tests. The normal read-only dashboard can still describe historical
  audit events; it cannot arm attacks.

## Tests migrated and why

`tests/conftest.py` removes the obsolete server constructor flag. The Attack Lab
and GUI Attack Lab tests now exercise the separate relay/site, preserving one-shot,
real detection, no false detection and guardrail coverage. The chain-after-attacks
suite now uses that isolated relay; its gap counts, recovery and evidence findings
are unchanged. The banner test now proves an attempted attack cannot create a
victim detection report on the separate site. Layout/presentation tests remove
controls that no longer exist and verify the product has no lab panel. Script
entrypoint tests start the normal server and assert the old mode banner is absent.

Added coverage includes every real client attack path, separate DB/reset, exact
victim bundle equality, lab session/Origin/rate restrictions, fixed-account lockout
before PBKDF2, product import/route/flag separation, unknown envelope rejection and
scoped logging for TLS failures. No crypto or evidence assertions were relaxed.

## Verification limits and historical assets

No public deployment, HTTPS reverse-proxy test, Firefox/Safari run, or fresh
PostgreSQL integration run was performed. Docker is unavailable on this machine.
The ordinary macOS Terminal/window-tiling launcher was checked by syntax and its
existing GUI/entrypoint tests; a fresh interactive multiwindow demo was not opened.
Wireshark capture was not rerun; its script was moved with a compatibility wrapper.

One process hosts one shared sandbox. Reset affects all its visitors and leaves
old lab JSONL audit records/browser keystore backups intact. A dropped last message
requires a later message to expose its gap. Random injected ciphertext is rejected
by GCM; the relay cannot produce a GCM-valid new payload without the session key.

Historical screenshots 01, 03, 04, 05 and 09 show the old GUI layout/lab mode;
evaluation screenshot 10 predates this run. `demo/full_walkthrough.md` is marked
historical and `docs/UI_REDESIGN_PROGRESS.md` describes that prior UI. PDFs under
`docs/pdf/` and local PowerPoint files were not edited.

## Files moved, added and changed

The six `demo/run_*_demo.py` implementations and `_demo_common.py` moved to
`attack_lab/scripts/`; their original paths remain as compatibility wrappers.
No whole source file was deleted. Attack hooks, control handling, flags, client lab
events, Tk panel and lab-only theme styles were removed from production files.
The complete path list relative to the evidence-phase baseline follows.

| Status | Path |
|---|---|
| Changed | `.gitattributes` |
| Changed | `.gitignore` |
| Changed | `README.md` |
| Added | `attack_lab/README.md` |
| Added | `attack_lab/__init__.py` |
| Added | `attack_lab/__main__.py` |
| Added | `attack_lab/app.py` |
| Added | `attack_lab/e2e/lab.spec.ts` |
| Added | `attack_lab/frontend/index.html` |
| Added | `attack_lab/frontend/main.ts` |
| Added | `attack_lab/frontend/style.css` |
| Added | `attack_lab/presentation.py` |
| Added | `attack_lab/relay.py` |
| Added | `attack_lab/scripts/__init__.py` |
| Added | `attack_lab/scripts/_demo_common.py` |
| Added | `attack_lab/scripts/run_drop_demo.py` |
| Added | `attack_lab/scripts/run_evidence_demo.py` |
| Added | `attack_lab/scripts/run_mitm_handshake_demo.py` |
| Added | `attack_lab/scripts/run_replay_demo.py` |
| Added | `attack_lab/scripts/run_tamper_demo.py` |
| Added | `attack_lab/scripts/run_wireshark_demo.py` |
| Added | `attack_lab/static/console-assets/index-Bfr2Ie7N.css` |
| Added | `attack_lab/static/console-assets/index-BtWmFAYV.js` |
| Added | `attack_lab/static/index.html` |
| Added | `attack_lab/tests/run_server.py` |
| Changed | `client/client.py` |
| Changed | `demo/README.md` |
| Changed | `demo/_demo_common.py` |
| Changed | `demo/_demo_lib.sh` |
| Changed | `demo/full_walkthrough.md` |
| Changed | `demo/run_drop_demo.py` |
| Changed | `demo/run_evidence_demo.py` |
| Changed | `demo/run_mitm_handshake_demo.py` |
| Changed | `demo/run_replay_demo.py` |
| Changed | `demo/run_tamper_demo.py` |
| Changed | `demo/run_wireshark_demo.py` |
| Changed | `demo/start_demo.sh` |
| Changed | `docs/architecture.md` |
| Changed | `docs/architecture_diagram.png` |
| Changed | `docs/architecture_diagram.svg` |
| Added | `docs/attack_lab_phase_report.md` |
| Changed | `docs/evaluation_results.json` |
| Changed | `docs/evaluation_results.md` |
| Changed | `gui/chat_gui.py` |
| Changed | `gui/explain.py` |
| Changed | `gui/theme.py` |
| Changed | `gui/widgets.py` |
| Changed | `server/lockout.py` |
| Changed | `server/relay_core.py` |
| Changed | `server/security_log.py` |
| Changed | `server/server.py` |
| Changed | `server/user_store.py` |
| Changed | `tests/conftest.py` |
| Changed | `tests/test_attack_lab.py` |
| Changed | `tests/test_chain_after_attacks.py` |
| Changed | `tests/test_entrypoints.py` |
| Changed | `tests/test_gui_attack_lab.py` |
| Changed | `tests/test_gui_banners.py` |
| Changed | `tests/test_gui_layout.py` |
| Changed | `tests/test_gui_presentation.py` |
| Changed | `tools/evaluate_security.py` |
| Changed | `web/app.py` |
| Changed | `web/frontend/package.json` |
| Added | `web/frontend/playwright.lab.config.ts` |
| Added | `web/frontend/vite.lab.config.ts` |

Local logical commits separate the implementation/tests from documentation and
refreshed evaluation. The final response includes the complete `git log --oneline`.
