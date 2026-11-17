# Phase 7 report — secure 1:1 voice calling (17 November 2026)

Status: **built, deployed and tested; TURN and the real Mac→phone call are pending** (they need the
owner's Metered account; see "Still to do").

## What was built
- Signed, encrypted signaling as normal chat messages (`securechat-call/v1:`): invite, accept,
  decline, busy, cancel, hangup and per-party call records; all hash-chained and replay-protected.
- WebRTC DTLS-SRTP audio, non-trickle ICE, one call at a time, 30 s ring timeout, mute, output
  select where supported, timer, quality indicator, "direct / via relay (TURN)" indicator,
  explained microphone errors, ringtone with on-screen fallback, user-gesture-driven audio start.
- DTLS check: the remote certificate fingerprint from `getStats` must equal the fingerprint in the
  signed SDP, else the call ends with a security alert (also sent to the relay as `security_alert`).
- Four-word authentication string from both fingerprints and the call id; "Call verified" after
  fingerprint match and both-sides confirmation.
- Evidence: call records and signaling are ordinary signed records (no format change; v1/v2 still
  verify); PDF has a "Voice calls" section and omits SDP; `verify_transcript.py` lists calls;
  new corpus files `valid_v2_call.json` and `edited_call_record.json`.
- `/api/calls/ice`: STUN list + short-lived Metered TURN credentials (TTL <= 600 s, 10/min/user);
  secret key server-side only, never logged (httpx logging silenced, exceptions by type only),
  graceful STUN-only fallback with a UI note.
- Attack Lab: "Substitute DTLS fingerprint in SDP", "Inject forged call offer", "Replay old call
  offer", plus a simulated "MITM media path". The first three act at the relay (which cannot read
  calls, so it picks offers by size) and are caught as `decryption_failed` / `replay_duplicate`.
  The media-path attack is **simulated in the victim's browser** (getStats reports another
  certificate); it exercises the real fingerprint-comparison check, which cannot otherwise be
  triggered because the SDP is signed.

## TURN provider
Metered free plan (500 MB/month, unlimited STUN, "no credit card required", REST API for
short-lived credentials). Cloudflare Realtime TURN rejected: 1,000 GB free but $0.05/GB overage,
payment-method requirement not ruled out, credential API not documented on the pages read.
At ~32 kbps audio, 500 MB is on the order of 30 relayed calls of 10 minutes.

## Tests (before → after)
| Suite | Result |
|---|---|
| pytest | 443 → **458 passed, 2 skipped** (adds TURN endpoint authz/expiry/rate-limit/secret-leak tests, call-tools tests) |
| Vitest | 62 → **76** (SDP/fingerprint parsing, SAS, signal validation) |
| Playwright main, local, Chromium + WebKit | **32 passed, 4 skipped** (WebKit call media skipped: no fake microphone) |
| Playwright lab, local | **26 passed, 4 skipped** (same reason) |
| Live main (Chromium) calls spec | 5 passed; WebKit 1 passed, 4 skipped |
| Live lab, Chromium + WebKit | 25 passed + 1 WebKit flake that passed on rerun, 4 skipped |

Call tests cover: two users connect, matching words on both screens, DTLS fingerprint check, audio
bytes > 0 both ways (`getStats`), mute disables the track, hang-up recorded in both parties' signed
records and in verifiable evidence, decline, cancel, 30 s timeout (Playwright clock), microphone
errors, mobile viewport; lab: control call + four attacks.

## Still to do / not verified
- **Metered account, TURN env vars and live TURN check** (waiting for the Keychain items).
- **Real Mac (Wi-Fi) → phone (mobile data) call**: not yet done; connection type, TURN use, SAS match
  and quality are unreported.
- WebKit/Safari call media is untested (no fake device); mobile Safari/Chrome behaviour unverified.
- Glare (both users calling at once) ends both calls with "busy" by design.
- Ringtone may be blocked by browser autoplay rules (on-screen prompt always shown).
- Evidence JSON contains SDP (network addresses); treat evidence files as confidential.
