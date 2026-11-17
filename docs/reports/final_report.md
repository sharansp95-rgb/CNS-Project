# Final release report — Team 15 Secure Chat

Release work dated 17 November 2026 (Asia/Kolkata). Baseline: `d52ab4d`, annotated
rollback tag `pre-phase8`. No history was rewritten. The release tag is `v1.0-final`.

## Features and boundaries

The project combines Python/Tkinter and React browser clients with a transport-neutral
relay, SQL persistence, signed/exportable evidence, an encrypted vault, encrypted
attachments and authenticated WebRTC voice. The separate Attack Lab uses the same
production victim bundle against a hostile relay and its own database/roster/origin.
The main service contains no attack controls. Media-certificate substitution is a
labeled browser observation simulation; the remaining relay attacks mutate real traffic.

Chat encryption, signature/KDF parameters, wire and evidence formats, persistent TSA
material and approved proxy trust were preserved. Database schema remains **3**;
evidence remains **v1/v2**, attachment and call payloads remain their existing v1
formats. The task brief's “evidence v1–v3” confused the database and evidence versions.

## Estimated and actual time

Initial estimate: **180–300 minutes** including baseline, cleanup, UI, fixes,
documentation, all local/disposable/live tests and deployment. Work started around
18:07 IST. Final actual elapsed time is recorded after live verification below.
Status questions interrupted the conversation; answering them should not have paused
execution. No estimate is presented as completed work.

## Measured test results

| Suite | Before | After cleanup/fixes/UI |
|---|---|---|
| Full local pytest | 463 passed, 2 skipped, 0 failed | **464 passed, 2 skipped, 0 failed**; 83.6 s in evaluator |
| Disposable Neon/Postgres subset | 84 passed, 1 failed | **85 passed, 0 failed**, 522.31 s |
| Vitest | 76 passed | **83 passed**, 6 files |
| Main local Chromium + WebKit | 34 passed, 6 skipped | **43 passed, 7 skipped**, 133 s |
| Lab local Chromium + WebKit | 26 passed, 4 skipped | **26 passed, 4 skipped**, 158 s, with added AA assertions |
| Security evaluator | 120/120 attacks, 0/200 false rejections | **120/120 attacks, 0/200 false rejections** |
| Main/lab live | Prior phase's results are historical | Release run recorded below after deployment |

The two local pytest skips are explicit disposable-Postgres upgrade cases, both run
in the Neon subset. Main browser skips: no fake microphone for five WebKit call-media
cases, and local runs skip the two live-TURN cases. Live runs additionally skip the
local-only raw TCP interoperability case per engine; Chromium runs the real TURN case.
Lab skips four WebKit call-media cases; forged-offer and non-media cases still run.
Firefox was attempted again and failed before opening a page on this Mac.

The baseline Postgres failure was the existing one-second lockout test: PG round
trips could outlast the lock, allowing PBKDF2 as designed after expiry. Its test-only
clock is now deterministic; no assertion, production threshold or duration was weakened.

### Existing test changes

Python tests and TypeScript fixtures/specs received lint/import/format cleanup.
Intentional pytest fixture imports and public aliases were preserved. The meaningful
fixture changes were:

- `tests/test_lockout.py`: freeze only the lockout module's clock, advance it explicitly
  for expiry, retain all pre-PBKDF2 and post-expiry assertions.
- `tests/test_gui_chat.py`: explicitly focus the test window before synthetic typing
  on macOS, preserving all keystroke/message assertions.
- `tests/test_gui_banners.py`: import the existing display-error helper for the
  headless fixture error path.
- `tests/test_attachment_tools.py`: add QuickTime descriptor/reference coverage.
- Browser attachment/call specs: add MOV authenticated download/fallback and genuine
  simultaneous-call convergence, matching fingerprints/words and flowing audio.
- New accessibility specs: both-theme automated AA checks, keyboard skip link, modal
  trap/restoration and session-preserving browser Back. Safari uses Option+Tab for
  link navigation according to its macOS keyboard setting. A real Safari focus-return
  bug and the lab log's invalid ARIA label were fixed in product markup.
- New CallManager/session unit cases exercise glare and stale microphone/setup work,
  cancellation, activity cleanup and authenticated keepalive after peer departure.

### Evaluation and demos

Fresh [measured results](../evaluation_results.md) include all 464 passing local
pytest cases, six attack types × 20, ten normal sessions × 20 messages, clean evidence
and post-lockout controls. No production data was used. Median end-to-end local
message latency: **1.999 ms**, p95 **2.378 ms**; session setup median **50.0 ms**.
All measured p95 costs satisfy the course's <1 s requirement. Loopback timings do
not include real network latency; evaluator-only repeated-lock duration is 0.5 s.

All compatibility demo entrypoints exited 0: tamper, replay, handshake MITM, drop,
evidence and Wireshark. The last made a fresh TLS 1.3 loopback capture under `/tmp`,
exchanged five messages and found no searched plaintext in the capture. Launcher
shell syntax passes. The interactive multi-window launcher was not opened during
automated verification; entrypoint/GUI tests and its underlying demos passed.

## Cleanup and tooling

- Ruff **0.17.5**, configured E4/E7/E9/F/I plus formatting: all 137 Python files pass.
- ESLint **10.15.0**, typescript-eslint **8.73.0**, Prettier **3.10.1**, strict
  TypeScript **7.0.2**: checks pass. ESLint's standalone parser package pins
  TypeScript **6.0.3**, keeping compatible peers without downgrading the build compiler
  or bypassing peer checks. Run `setup:lint` after `npm ci`.
- pytest moved from production requirements to pinned `requirements-dev.txt`;
  httpx2 **2.16.2** removes the Starlette/httpx warning. Runtime HTTPX remains because
  the TURN provider client uses it.
- `pip-audit` on runtime + development requirements: **no known vulnerabilities**.
  `npm audit` on both the main frontend and isolated lint package: **0 vulnerabilities**
  at all severities. These are point-in-time advisory checks, not security proofs.
- Removed unused imports and replaced safe lint findings; clarified core public API
  documentation/type hints. Preserved deliberate exports and every demo wrapper
  referenced by docs/tests. No runtime dependency was removed without evidence.
- Deferred broad dynamic-envelope typing, a wholesale module reorganization and
  cryptographic/session refactors: these risk changing the existing security behavior.
  Narrow lint exceptions document runtime-validated legacy wire/RTC structures.
- The lazy-loaded PDF library still causes Vite's >500 kB chunk warning (about
  510 kB gzip). It is requested only when a PDF is generated; the warning is reported.

## UI and small fixes

Shared design tokens now cover dark/light chat, onboarding, evidence, public verifier,
media, calls and lab console. Clear steps/empty states and WebSocket wake-up feedback
explain waiting without claiming the platform's pre-JavaScript loading page is under
app control. Fingerprints, receipts, Wire Log, call words and the sandbox banner remain
visible. Focus rings, labeled controls, reduced motion, modal focus containment and
restoration, mobile wrapping and call-panel scrolling improve access. Automated axe
checks cover major flows in both themes; they do not certify complete WCAG compliance.

QuickTime major brand `qt  ` after `ftyp` is accepted as `video/quicktime`. Existing
file limits, chunk/AAD/key/hash behavior are unchanged. Unsupported codecs keep the
verified original available for download. The fixture intentionally has no playable
codec and proves fallback; a new physical iPhone recording was not tested this phase.

Glare resolves to the lexicographically smaller username's outgoing call. The other
caller cancels its abandoned call and receives the winning invite, which still needs
acceptance. Late microphone/setup results cannot overwrite the winning/canceled call.
DTLS fingerprint comparison and word confirmation retain their original requirements.

Authenticated keepalive already existed; no new uptime pinger was added. User activity
listeners now clean up correctly, and an authenticated session can keep its transport
alive after its peer leaves while session keys are discarded. Anonymous policy/ping
cannot extend its idle deadline.

## Documentation, screenshots and files

README was rewritten around the deployed product, setup, tests, schema, security
boundaries and honest limitations. Architecture source/PNG/SVG now show web/local
clients, separate lab, Neon Postgres/Object Storage and TURN. Password visibility is
correctly distinguished from plaintext persistence. Evidence docs clarify schema 3
versus evidence v1/v2. DEPLOY preserves the approved proxy configuration and key rules,
updates current setup/test commands and documents lint maintenance.

Five `docs/*_report.md` files moved into `docs/reports/`, each labeled historical.
`docs/UI_REDESIGN_PROGRESS.md` and `demo/full_walkthrough.md` moved to `docs/history/`.
Thirteen older screenshots moved to `docs/screenshots/history/`. Links were repaired;
old reports retain their historical file inventories rather than claiming current paths.
Existing PDFs and PowerPoints were not modified.

Twelve current images show chat/Wire Log in both themes, accepted-message receipt,
encrypted vault, valid/tampered public verification, verified attachment, real call
fingerprint/words, mobile call, real lab detection and both pages of the companion PDF.
They use disposable local users/keys only. See [screenshot inventory](../screenshots/README.md).
A new native dashboard capture was unavailable: this conversation has no desktop
capture tools. Its historical image remains explicitly labeled; native GUI tests pass.

[Complete changed-file inventory](phase8_changed_files.md) lists cleanup, source,
assets, test and documentation paths. Broad test changes there are mostly formatter
changes; meaningful fixture/assertion additions are explained above.

## Deployment verification

Release deployment and live-test results are pending at this documentation commit.
The next release-report commit records observed outcomes; this is not a live-pass claim.

Both existing services were checked to still use **Free**, Singapore, branch main,
auto-deploy off. Environment values were hashed in process memory for before/after
comparison; no values or connection strings are written into this report/repository.
The persistent Ed25519 key and approved proxy trust must remain unchanged.

## Limitations and future work

The project has no professional external audit, legal identity proof, double ratchet,
key transparency, offline delivery queue, group chat, account recovery or multi-worker
roster/token service. Login passwords are transiently visible to the TLS endpoint;
server metadata and evidence titles/digests remain visible. Browser-delivered code,
endpoints, extensions and the receipt signer's clock/key custody are trusted.
Signed evidence does not establish truth, completeness or legal admissibility; an
India Section 63 certificate may additionally be required. Evidence may contain
sensitive attachment keys and call addresses; handle it privately.

Free-service cold starts, quotas and ephemeral lab data remain operational limits.
No extra paid resources, plan upgrades or card requirements were introduced. Future
work could add an independently reviewed key-verification design, durable routing,
stronger operational monitoring within budget, cross-device codec/manual access
checks and a documented retention/backup policy. Security changes need separate
review rather than being hidden in a UI cleanup.
