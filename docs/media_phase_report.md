# Phase 6 report — end-to-end encrypted image and video sharing (17 November 2026)

## Time

Estimated about 6.5 hours (plan printed before coding). Actual: roughly 3.5 hours of
work, including a Neon test-database run of about 8 minutes and live runs. The
estimate was high because the storage provider worked on the first try (presigned PUT
with a signed `content-length`, CORS and HEAD all behaved as the S3 documentation says)
and the AAD/chunk format needed no redesign.

## What was built

- Browser: magic-byte sniffing (JPEG, PNG, WebP, GIF, MP4, WebM; SVG/HTML refused),
  EXIF/GPS/XMP/IPTC/comment stripping by byte rewriting (no re-encode, animation kept,
  JPEG orientation preserved as a one-tag Exif), 1 MiB chunked AES-256-GCM with random
  per-chunk nonces and AAD (file id, index, is-last), SHA-256 of ciphertext and plaintext,
  encrypted thumbnails (<= 12 KB), progress with cancel, drag-and-drop, paste, lightbox,
  inline video, `blob:` rendering only, sanitised file names.
- Message layer: the descriptor is the text of a normal chat message
  (`securechat-attachment/v1:{...}`), so signatures, AES-GCM, hash chain, replay window
  and evidence all apply unchanged. No evidence format bump was needed: v1/v2 files verify
  as before.
- Server: `server/storage.py` (local + dependency-free SigV4 S3 backend), schema v3
  `attachments` table (transactional 1→2→3 upgrade), `web/attachments_api.py` (init /
  finalize / download / delete, uploader+recipient only, uniform 404, per-user quota,
  per-kind limits, rate limits, lazy sweep of expired and orphaned objects).
- Evidence: PDF lists attachments with hashes (never keys); `/verify` can check a file
  against recorded hashes locally; `tools/verify_transcript.py --check-file`; new corpus
  files (`valid_v2_attachment.json`, edited-descriptor case, sample plaintext and encrypted
  object). Existing corpus files were not regenerated.
- Desktop: shows `[attachment — open in web client]`; transcripts, chain and evidence keep
  the verbatim message.
- Attack Lab: "Tamper stored attachment" and "Swap attachment object", detected by the real
  client (`attachment_rejected` security alerts), plus an untouched-attachment control.

## Storage setup (no secrets)

Neon Object Storage, private bucket `cns-attachments` on the main branch of the existing
project (AWS Singapore, free plan: 5 GB; egress shared with Postgres). A scoped
`storage:read`+`storage:write` credential is in Keychain as `cns-s3-*` (key id, secret,
endpoint, bucket, region). Bucket CORS allows only
`https://team15-securechat.onrender.com` (GET/PUT/HEAD); an evil origin preflight is
refused. Render main has `STORAGE_BACKEND=s3` and the five `S3_*` variables; the lab has
none of them and uses its own local directory. Uploads and downloads go browser ⇄ bucket
directly (verified live: upload host differs from the app host). Auto-deploy is off, so
both services were redeployed through the Render API (commit `0b2e619`).

## Limits chosen

Images 10 MB, video 50 MB, 200 MB live storage per uploader, retention 7 days, presigned
URL life 5 minutes, 20 uploads/min and 120 download URLs/min per user, unfinalised uploads
expire after 1 hour. All configurable by environment variable (DEPLOY.md section 9).
Envelope ciphertext above 8 KB (attachment messages) is not copied into `relayed_envelopes`
(hash and size are kept), to protect the 0.5 GB Neon database.

## Tests

| Suite | Before | After |
|---|---|---|
| pytest (local) | 417 passed, 1 skipped | **443 passed, 2 skipped** |
| pytest on disposable Neon branch (incl. v1→v3 and v2→v3 upgrades, attachments) | 68 | **85 passed** (462 s) |
| Vitest | 32 | **62** (chunk crypto, AAD reorder/drop/truncation, EXIF/PNG/GIF/WebP stripping, magic bytes, Python⇄browser file compatibility) |
| Playwright main, local (Chromium + WebKit) | 12 | **24 passed, 2 skipped** (TCP interop is local-only per engine; 2 skips) |
| Playwright lab, local (Chromium + WebKit) | 14 | **20 passed** |
| Playwright main, live (Chromium + WebKit) | 10 | **24 passed, 2 skipped** |
| Playwright lab, live | 14 | **Chromium 10 passed; WebKit 10 passed** (one control test was made more robust and re-run) |

Existing assertions were not weakened. Changes to existing tests: schema version
expectations 2→3 (three places), production-config tests now set dummy `S3_*` variables,
and `tests/conftest.py` also runs `test_attachments.py` on Postgres when a test URL is set.

## Live verification

After the tests, a scan of the live bucket found **30 objects**, none beginning with an
image/video magic number or containing any fixture marker (`JFIF`, `IHDR`, `Exif`,
`ftyp`, fixture byte runs, `<svg`), byte entropy 7.92–7.97 bits. The main database is at
schema 3; `attachments` has only the ten metadata columns (no names/keys); no text/JSON
column in any table contains test file names or the descriptor prefix. TSA `key_id`
unchanged (`fddef29a…`). `FORWARDED_ALLOW_IPS` untouched.

## Not verified / caveats

- Firefox cannot launch on this Mac; not run.
- MP4 playback was not exercised in a browser (no encoder available; only WebM was
  played). MP4 detection is covered by magic-byte unit tests.
- Video metadata (e.g. GPS in MP4) is **not** stripped; the UI says so. PNG/WebP orientation
  tags are dropped (rotation is not preserved there).
- Neon documents no maximum presigned expiry; we use 5 minutes. Neon free-tier egress/quota
  exhaustion behaviour was not tested.
- Evidence JSON contains file keys (it already contains message plaintext); the
  vault-encrypted copy is the safe one to store.
- Live test objects (30) remain until lazy expiry (7 days).
- The relay learns attachment existence, parties, image/video kind, size and timing.
