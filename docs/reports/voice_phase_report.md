> Historical phase report, moved during Phase 8. Results and path inventories describe that phase; links point to their current locations. See [final_report.md](final_report.md) for the final state.

# Phase 7 report — secure 1:1 voice calling (17 November 2026)

## Time
Estimated about 6.5 hours (plan printed before coding). Actual: roughly 5.5 hours of work, spread over
the session, plus waiting for the owner's Metered signup, plan activation and the real-device calls. The
estimate held for the build; the extra time went into the Metered account/plan problem, the credential
propagation delay and the idle-timeout/keepalive work.

## What was built
- **Signed, encrypted signaling.** Invite, accept, decline, busy, cancel, hangup and per-party call
  records are ordinary chat messages (`securechat-call/v1:{...}`): RSA-signed, AES-GCM encrypted,
  hash-chained, freshness/replay-checked. The relay sees ciphertext only. Non-trickle ICE keeps a call to
  a handful of messages.
- **DTLS-SRTP media, peer to peer.** One call at a time, busy replies, 30 s ring timeout, mute, output
  select where supported, call timer, network-quality indicator, "direct / via relay (TURN)" indicator
  (with the note that TURN only relays encrypted SRTP), explained microphone errors, ringtone with an
  on-screen fallback, audio started from user gestures (mobile autoplay rules).
- **No certificate swapping.** The SDP (with `a=fingerprint`) is inside the signed message. After
  connecting, the client reads the real remote certificate fingerprint via `getStats` and compares it
  with the signed one; a mismatch ends the call, shows a security alert and reports it to the relay log.
- **Short authentication string.** Four words from both fingerprints and the call id (256-word list);
  "Call verified" after the fingerprint check and both people confirm the words.
- **Evidence.** Both parties sign their own call record (outcome, start/end, duration, connection type,
  fingerprint check, words confirmed). Records are in the chain, evidence exports, the PDF (SDP omitted)
  and `tools/verify_transcript.py`. No evidence format change; v1/v2 files still verify. New corpus
  files `valid_v2_call.json` and `edited_call_record.json`. Desktop Tk shows `[call — web client only]`.
- **TURN credential endpoint** `/api/calls/ice`: STUN list plus per-call Metered credentials (TTL capped
  at 600 s, opaque random label, 10 requests/min/user, secret key server-side only, never logged or
  returned, exceptions logged by type only, httpx request logging silenced). If TURN fails (e.g. the
  free quota is used up) it degrades to STUN-only and the UI says so.
- **Relay-only mode:** open the site as `/?relay=1` to force all media through TURN.
- **Authenticated keepalive** (this step): after login the server announces its idle limit
  (`session_policy`); the client sends `ping` every min(30 s, idle/3) and the server answers `pong`.
  Anonymous sockets still time out and an unauthenticated `ping` is refused (close 1008). Pings stop after
  30 minutes without user input (unless a call is active), so a forgotten tab cannot keep a free-tier
  instance awake indefinitely. Pings/pongs are kept out of the Wire Log.
- **Attack Lab:** "Substitute DTLS fingerprint in SDP", "Inject forged call offer", "Replay old call
  offer" (relay-level; the relay cannot read calls so it picks offers by ciphertext size; caught as
  `decryption_failed` / `replay_duplicate`) and "MITM media path (other DTLS certificate)", which is
  **simulated in the victim's browser** (getStats reports a different certificate) and exercises the real
  fingerprint-comparison check. The lab uses STUN/host candidates only and has no TURN secret.

## TURN provider
**Metered, free "TURN TRIAL GLOBAL 500MB" plan** ($0; no card; renews 17 Dec 2026). Chosen over Cloudflare
Realtime TURN (1,000 GB free but $0.05/GB overage, payment method not ruled out) and Metered's Open Relay
(public static secret, not allowed). Limits: 500 MB/month relayed traffic (about 30 ten-minute relayed
audio calls at ~32 kbps), credentials live <= 10 minutes. Two real-world findings:
1. The credential API reported "please subscribe to a TURN Server plan" until the plan was subscribed in
   Metered's **old** dashboard; the new dashboard showed "Free — ACTIVE" without that being enough.
2. A **brand-new credential is rejected for up to about a minute** (`400 allocate` errors, then relay
   candidates appear). The client therefore fetches the ICE configuration when the secure session starts,
   reuses it for 8 minutes and refreshes it every 5 minutes. A call placed in the first minute after
   login may not get relay candidates yet.

## Tests (before → after this phase)
| Suite | Result |
|---|---|
| pytest, local | 443 → **463 passed, 2 skipped** (TURN endpoint authz/expiry cap/rate limit/secret-leak, call tools, keepalive) |
| Vitest | 62 → **76** (SDP/fingerprint parsing, SAS, signaling validation) |
| Playwright main, local (Chromium + WebKit) | **34 passed, 6 skipped** |
| Playwright lab, local | **26 passed, 4 skipped** |
| Playwright main, **live** (Chromium + WebKit, `LIVE_TURN=1`) | **33 passed, 7 skipped** |
| Playwright lab, **live** (Chromium + WebKit) | **26 passed, 4 skipped** |

Skips are intentional: WebKit has no fake microphone, so its call-media tests (5 in the main suite, 4 in
the lab) are skipped; the Python-TCP interoperability case is local-only. WebKit still runs the microphone
error test, the lab's forged-offer attack and everything non-media. The live main run includes a relay-only
call through the real Metered TURN (both ends "via relay (TURN)", audio bytes flowing) and a 135-second
idle session that survives thanks to the keepalive.

Call coverage: connect, matching four words on both screens, DTLS certificate check, audio bytes > 0 both
ways, mute really disables the track, hang-up recorded for both parties and verifiable offline, decline,
cancel, ring timeout (Playwright clock), microphone errors, mobile viewport. Lab: control call plus the four
attacks.

## Real-device calls (Mac on Wi-Fi ⇄ phone on mobile data)
The owner reported that **all three calls worked** (Mac → phone, phone → Mac, and a relay-forced call).
The owner did not supply the per-call details, so these are **not recorded here and not verified by me**:
connection type of calls 1–2, whether the words matched on both screens, audio quality, and the phone
browser. (Call 3 was relay-forced via `/?relay=1`; the automated live test independently confirmed the
relay path.)

## Not verified / caveats
- Per-call details of the real-device calls (see above).
- WebKit/Safari call media is not covered by automated tests (no fake device); mobile Safari/Chrome call
  behaviour depends on the owner's manual calls.
- Metered quota behaviour once 500 MB is exhausted was not exercised (the fallback is unit-tested with a
  failing provider).
- Both parties calling at the same moment ends both calls with "busy" by design.
- The ringtone may be blocked by browser autoplay rules; the on-screen prompt is always shown.
- Evidence JSON contains SDP (network addresses); treat evidence files as confidential.
- While a tab is logged in and active, the keepalive keeps the free Render instance awake (it counts
  against the shared 750 free hours); it stops 30 minutes after the last user input.
- Firefox cannot launch on this Mac; not run.
