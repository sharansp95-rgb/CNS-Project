# Screenshots

`current/` was regenerated on 17 November 2026 with local disposable servers and
synthetic demo_alice/demo_bob accounts using `node tools/capture_screenshots.mjs`.
No production conversation, persistent TSA key, access code or provider credential
is included. The local receipt signer is temporary and its public identity differs
from the deployed signer.

| File | View |
|---|---|
| [01-chat-wire-dark.png](current/01-chat-wire-dark.png) | Chat and actual redacted ciphertext Wire Log |
| [02-chat-wire-light.png](current/02-chat-wire-light.png) | Same conversation in light theme |
| [03-security-receipt.png](current/03-security-receipt.png) | Real accepted-message checks |
| [04-encrypted-evidence-vault.png](current/04-encrypted-evidence-vault.png) | Saved encrypted file and local VALID verdict |
| [05-verify-valid.png](current/05-verify-valid.png) | Local file plus temporary receipt verification |
| [06-verify-tampered.png](current/06-verify-tampered.png) | Edited record rejected, failing message named |
| [07-verified-attachment.png](current/07-verified-attachment.png) | Decrypted/verified image viewer |
| [08-call-verification-words.png](current/08-call-verification-words.png) | Connected Chromium call and real fingerprint check |
| [09-mobile-call.png](current/09-mobile-call.png) | Same call on a 390px viewport |
| [10-lab-genuine-detection.png](current/10-lab-genuine-detection.png) | Ciphertext attack and real decryption rejection |
| [11-companion-pdf-page-1.png](current/11-companion-pdf-page-1.png), [11-companion-pdf-page-2.png](current/11-companion-pdf-page-2.png) | Browser-generated PDF rendered and inspected; original signed JSON remains authoritative |

The PDF itself is a temporary synthetic artifact under `/tmp`, not an edited
submission PDF. The dashboard is still covered by native GUI pytest; a new native
screenshot was unavailable because this session has no desktop-capture tools.
`history/05_dashboard_after_attacks.png` and all other `history/` images are labeled
**historical**, including the removed in-app Attack Lab panel. Do not use them as
proof of the current deployed UI. Existing `docs/pdf/` and review PowerPoints remain
unchanged; the old walkthrough and redesign progress are in `docs/history/`.
