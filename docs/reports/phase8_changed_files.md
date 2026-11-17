# Phase 8 changed files

Relative to `pre-phase8`; R denotes a rename and its similarity score. Built assets
are included. This inventory omits its own later report-only updates.

```text
M	.gitignore
M	AGENTS.md
M	README.md
M	attack_lab/README.md
M	attack_lab/__main__.py
M	attack_lab/access.py
M	attack_lab/app.py
M	attack_lab/e2e/lab.spec.ts
M	attack_lab/frontend/index.html
M	attack_lab/frontend/main.ts
M	attack_lab/frontend/style.css
M	attack_lab/presentation.py
M	attack_lab/relay.py
M	attack_lab/scripts/_demo_common.py
M	attack_lab/scripts/run_drop_demo.py
M	attack_lab/scripts/run_evidence_demo.py
M	attack_lab/scripts/run_mitm_handshake_demo.py
M	attack_lab/scripts/run_replay_demo.py
M	attack_lab/scripts/run_tamper_demo.py
M	attack_lab/scripts/run_wireshark_demo.py
D	attack_lab/static/console-assets/index-Bfr2Ie7N.css
D	attack_lab/static/console-assets/index-Bm8QzeSM.js
A	attack_lab/static/console-assets/index-DXOykXIl.css
A	attack_lab/static/console-assets/index-DvQfPRUK.js
M	attack_lab/static/index.html
M	attack_lab/tests/run_server.py
M	auth/keystore.py
M	certs/generate_certs.py
M	client/client.py
M	client/evidence.py
M	client/evidence_vault.py
M	crypto_engine/aes_gcm.py
M	crypto_engine/attachment_tools.py
M	crypto_engine/call_tools.py
M	crypto_engine/dh_exchange.py
M	crypto_engine/evidence_tools.py
M	crypto_engine/hash_chain.py
M	crypto_engine/signatures.py
M	demo/README.md
M	demo/_demo_common.py
M	demo/layout.py
M	demo/reset_environment.py
M	demo/run_drop_demo.py
M	demo/run_evidence_demo.py
M	demo/run_mitm_handshake_demo.py
M	demo/run_replay_demo.py
M	demo/run_tamper_demo.py
M	demo/run_wireshark_demo.py
M	docs/DEPLOY.md
M	docs/architecture.md
A	docs/architecture.mmd
M	docs/architecture_diagram.png
M	docs/architecture_diagram.svg
M	docs/evaluation_results.json
M	docs/evaluation_results.md
M	docs/evidence.md
R099	docs/UI_REDESIGN_PROGRESS.md	docs/history/UI_REDESIGN_PROGRESS.md
R098	demo/full_walkthrough.md	docs/history/full_walkthrough.md
A	docs/reports/README.md
R098	docs/attack_lab_phase_report.md	docs/reports/attack_lab_phase_report.md
R097	docs/deployment_phase_report.md	docs/reports/deployment_phase_report.md
A	docs/reports/final_report.md
R098	docs/live_deployment_report.md	docs/reports/live_deployment_report.md
R096	docs/media_phase_report.md	docs/reports/media_phase_report.md
R097	docs/voice_phase_report.md	docs/reports/voice_phase_report.md
A	docs/screenshots/README.md
A	docs/screenshots/current/01-chat-wire-dark.png
A	docs/screenshots/current/02-chat-wire-light.png
A	docs/screenshots/current/03-security-receipt.png
A	docs/screenshots/current/04-encrypted-evidence-vault.png
A	docs/screenshots/current/05-verify-valid.png
A	docs/screenshots/current/06-verify-tampered.png
A	docs/screenshots/current/07-verified-attachment.png
A	docs/screenshots/current/08-call-verification-words.png
A	docs/screenshots/current/09-mobile-call.png
A	docs/screenshots/current/10-lab-genuine-detection.png
A	docs/screenshots/current/11-companion-pdf-page-1.png
A	docs/screenshots/current/11-companion-pdf-page-2.png
R100	docs/screenshots/01_overview_two_chats_and_dashboard.png	docs/screenshots/history/01_overview_two_chats_and_dashboard.png
R100	docs/screenshots/02_security_receipt.png	docs/screenshots/history/02_security_receipt.png
R100	docs/screenshots/03_attack_lab_panel.png	docs/screenshots/history/03_attack_lab_panel.png
R100	docs/screenshots/04_tamper_caught.png	docs/screenshots/history/04_tamper_caught.png
R100	docs/screenshots/05_dashboard_after_attacks.png	docs/screenshots/history/05_dashboard_after_attacks.png
R100	docs/screenshots/06a_lockout_message.png	docs/screenshots/history/06a_lockout_message.png
R100	docs/screenshots/06b_lockout_dashboard.png	docs/screenshots/history/06b_lockout_dashboard.png
R100	docs/screenshots/07_evidence_valid.png	docs/screenshots/history/07_evidence_valid.png
R100	docs/screenshots/08_evidence_invalid.png	docs/screenshots/history/08_evidence_invalid.png
R100	docs/screenshots/09_server_and_tls_fingerprint.png	docs/screenshots/history/09_server_and_tls_fingerprint.png
R100	docs/screenshots/10_evaluation_results.png	docs/screenshots/history/10_evaluation_results.png
R100	docs/screenshots/12_wireshark_tls13_packets.png	docs/screenshots/history/12_wireshark_tls13_packets.png
R100	docs/screenshots/13_wireshark_hex_ciphertext.png	docs/screenshots/history/13_wireshark_hex_ciphertext.png
A	eslint.config.mjs
M	gui/chat_gui.py
M	gui/explain.py
M	gui/macos.py
M	gui/rounded.py
M	gui/security_dashboard.py
M	gui/theme.py
M	gui/widgets.py
A	pyproject.toml
A	requirements-dev.txt
M	requirements.txt
M	server/db.py
M	server/lockout.py
M	server/relay_core.py
M	server/security_log.py
M	server/server.py
M	server/storage.py
M	server/timestamp.py
M	server/user_store.py
M	tests/conftest.py
M	tests/fixtures/evidence_corpus/generate.py
M	tests/fixtures/evidence_corpus/generate_attachment.py
M	tests/fixtures/evidence_corpus/generate_calls.py
M	tests/postgres/test_postgres_upgrade.py
M	tests/test_aes_gcm.py
M	tests/test_attachment_tools.py
M	tests/test_attachments.py
M	tests/test_attack_lab.py
M	tests/test_call_tools.py
M	tests/test_calls_api.py
M	tests/test_chain_after_attacks.py
M	tests/test_database.py
M	tests/test_demo_isolation.py
M	tests/test_dh_exchange.py
M	tests/test_entrypoints.py
M	tests/test_evidence_export.py
M	tests/test_evidence_vault.py
M	tests/test_gui_attack_lab.py
M	tests/test_gui_banners.py
M	tests/test_gui_chat.py
M	tests/test_gui_dashboard.py
M	tests/test_gui_layout.py
M	tests/test_gui_login.py
M	tests/test_gui_presentation.py
M	tests/test_gui_receipt.py
M	tests/test_handshake_auth.py
M	tests/test_hash_chain.py
M	tests/test_lockout.py
M	tests/test_macos_name.py
M	tests/test_password_hash.py
M	tests/test_production_config.py
M	tests/test_replay_protection.py
M	tests/test_security_events.py
M	tests/test_signatures.py
M	tests/test_theme.py
M	tests/test_theme_switch.py
M	tests/test_tls_setup.py
M	tests/test_web_gateway.py
M	tests/test_window_layout.py
A	tools/capture_screenshots.mjs
M	tools/check_static_assets.py
M	tools/configure_bucket_cors.py
M	tools/evaluate_security.py
M	tools/generate_tsa_key.py
M	tools/migrate_json_to_db.py
M	tools/postgres_test_support.py
M	tools/scan_git_history.py
M	tools/verify_transcript.py
M	transport/locked_tls.py
M	web/__main__.py
M	web/app.py
M	web/attachments_api.py
M	web/calls_api.py
A	web/frontend/e2e/accessibility.spec.ts
M	web/frontend/e2e/attachments.spec.ts
M	web/frontend/e2e/calls.spec.ts
M	web/frontend/e2e/chat.spec.ts
A	web/frontend/e2e/fixtures/unsupported-codec.mov
M	web/frontend/e2e/keepalive.spec.ts
A	web/frontend/lint/README.md
A	web/frontend/lint/check.mjs
A	web/frontend/lint/index.mjs
A	web/frontend/lint/package-lock.json
A	web/frontend/lint/package.json
M	web/frontend/package-lock.json
M	web/frontend/package.json
M	web/frontend/src/AttachmentUI.tsx
M	web/frontend/src/CallUI.tsx
M	web/frontend/src/ProofUI.tsx
M	web/frontend/src/attachments/descriptor.ts
M	web/frontend/src/attachments/fileCrypto.ts
M	web/frontend/src/attachments/media.ts
M	web/frontend/src/attachments/thumbnail.ts
M	web/frontend/src/attachments/transfer.ts
M	web/frontend/src/calls/manager.ts
M	web/frontend/src/calls/sas.ts
M	web/frontend/src/calls/sdp.ts
M	web/frontend/src/calls/signal.ts
M	web/frontend/src/crypto.ts
A	web/frontend/src/design-system.css
M	web/frontend/src/main.tsx
M	web/frontend/src/pdfReport.ts
M	web/frontend/src/session.ts
M	web/frontend/src/style.css
A	web/frontend/src/useDialog.ts
M	web/frontend/tests/attachments.test.ts
A	web/frontend/tests/calls-manager.test.ts
M	web/frontend/tests/calls.test.ts
M	web/frontend/tests/run_server.py
M	web/frontend/tests/session.test.ts
M	web/frontend/tests/vector_bridge.py
M	web/frontend/tsconfig.json
M	web/settings.py
A	web/static/assets/index-CIVGs0W4.css
D	web/static/assets/index-DQtgZETe.css
D	web/static/assets/index-cEgd-LqR.js
A	web/static/assets/index-gxRuxC26.js
R099	web/static/assets/pdfReport-BLvn9MIp.js	web/static/assets/pdfReport-BLJkM6eb.js
M	web/static/index.html
M	web/tokens.py
M	web/vault_api.py
```
