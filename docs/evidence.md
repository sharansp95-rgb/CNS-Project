# Evidence: integrity, receipts and encrypted storage

The **signed JSON file is authoritative**. The browser PDF is an unsigned companion
for reading and supporting documentation. Keep the original JSON bytes, optional
receipt JSON, and independently trusted public keys together.

## What this proves — and what it does not

Verification checks that each sender signed its canonical message record, each
per-sender hash chain and final head is consistent, the signed handshake verifies,
and the exporter signed the complete evidence object. An edited, missing, reordered
or substituted record is reported with the failing message index when one exists.
An export with a detected chain gap remains INVALID; an explained rejection does not
turn missing evidence into a valid chain.

A valid file demonstrates consistency **with its embedded keys**, not a person's legal
identity, whether a statement is true, or whether omitted conversations exist. Pin a
participant fingerprint obtained independently. Participants can fabricate a new,
self-consistent conversation under their own keys. Per-direction chains do not bind
the full interleaving of both directions to an external clock.

V2 adds the exporter's attestation of observed ciphertext-envelope hashes. The message
sender's original signature remains over the existing plaintext record; it does not
sign this new hash. The server cannot decrypt an upload, so it cannot independently
check that the uploaded encrypted file contains the submitted hash manifest, or that
a matching ciphertext actually encodes a claimed plaintext. A receipt is supporting
corroboration, **not a mathematical ciphertext-to-plaintext proof**.

A receipt signs a submitted file digest, the server's current clock, and a count of
matching retained traffic hashes. It is not an accredited TSA/RFC 3161 timestamp,
proof of delivery, proof of authorship by a legal person, or proof of a transaction's
legality. Relay rows record forwarding attempts; a socket can fail after logging.
Server clock accuracy, key custody, and honest receipt issuance remain trust
assumptions. No key, timestamp or receipt can recover missing messages.

Legal admissibility in India may additionally require a certificate under **Section
63 of the Bharatiya Sakshya Adhiniyam, 2023**. This application supplies technical
integrity checks, not legal certification. See the [official Act, Section 63 and its
Schedule](https://www.indiacode.nic.in/indiacode/bitstream/123456789/20063/1/aa202347.pdf).

## Evidence v1 and v2

V1 (`format: "securechat-evidence/v1"`) remains supported without alteration. Python
exports v1 by default; select v2 with `build_evidence(client, format_version=2)` or
`client.export_evidence(directory, format_version=2)`. The browser exports v2 by
default and its exporter retains an explicit v1 option.

V2 uses `format: "securechat-evidence/v2"` and `format_version: 2`. It retains v1's
participants, handshake, records, directional chain heads, rejected events, and
exporter signature. Every verified record additionally has `envelope_sha256`, a
lowercase 64-character SHA-256 digest. The exporter signature covers this field along
with every other field except `exporter_signature` itself. Sessions without captured
hashes must export v1; they are never assigned invented hashes.

### Exact envelope hash

```
envelope_sha256 = SHA256(canonical_json(actual_chat_envelope))
```

Canonical JSON is recursively sorted by Unicode code point, has no insignificant
whitespace (`separators=(",", ":")`), uses Python `ensure_ascii=True` escaping
(including lowercase `\uXXXX` surrogate pairs), and is encoded as ASCII. Normal chat
envelopes contain `type`, `from`, `to`, `nonce`, `ciphertext`, and `tag`. Hash the
entire original object, including any additional fields, before adding local UI
fields. Base64 strings retain their original spelling. JSON wire key order is not
significant. Transport newline, TLS records, WS framing and Wire Log decorations are
excluded. The sending and receiving clients retain their observed envelope hash; the
relay hashes the envelope it attempts to forward, after any existing lab mutation.
A dropped message has no recipient record. Tampered/rejected messages stay separate
from verified evidence records.

Client signatures, AES-GCM, HKDF, genesis and replay rules remain unchanged. Original
RSA-PSS uses SHA-256/MGF1-SHA256 with a 222-byte salt for RSA-2048. The new v2 field
is outside the original sender-signed record and inside the exporter-signed evidence.

## Timestamp key and receipt

The dedicated **Ed25519** signing key is separate from TLS and users' RSA identities.
Ed25519 provides deterministic 64-byte signatures and avoids RSA-PSS salt-length
configuration ambiguity between WebCrypto and Python. Existing user signatures remain
RSA-PSS. The receipt signature is standard Ed25519 over canonical ASCII JSON of all
receipt fields except `signature`; the signature is padded standard base64.

```
{
  "receipt_version": 1,
  "file_sha256": "<SHA-256 of exact plaintext JSON file bytes>",
  "server_time": "2026-11-16T10:00:00Z",
  "key_id": "<SHA-256 of raw 32-byte Ed25519 public key>",
  "corroborated": 3,
  "total": 3,
  "signature": "<base64 Ed25519 signature>"
}
```

`server_time` is UTC ISO-8601 with a `Z` suffix. V1 submissions use
`corroborated: "not available"`; this is informational, not an error. `total` is the
client-declared number of records; offline verification checks it against the signed
file’s actual record count and checks v1/v2 corroboration types. For v2, matching is restricted to the authenticated
owner's retained chat traffic as sender or recipient. Repeated claims cannot exceed
retained occurrences of a hash. Missing, pruned, disabled-capture and pre-upgrade rows
do not match; `0 / N` can mean unavailable history rather than tampering.

The server cannot determine whether the manifest describes the encrypted file. It
stores/signs the supplied digest and metadata without receiving the plaintext JSON.
The browser verifies the downloaded exact file bytes and the receipt; use the vault's
**Download exact signed JSON**, not a newly regenerated export, with that receipt.
Reformatting JSON can preserve its exporter signature while invalidating an existing
receipt, because the receipt binds exact bytes.

`GET /api/timestamp-key` returns `algorithm`, `key_id`, and `public_key_pem`. This
public endpoint requires no login. For third-party trust, obtain/pin that PEM through
an independent channel; fetching it from the same server is not independent proof.

```sh
export TSA_KEY_PATH=/persistent/private/securechat-tsa.key
.venv/bin/python tools/generate_tsa_key.py
```

Default: `data/tsa_signing.key`. The generator atomically publishes a complete 0600
PKCS8 key and never overwrites an existing one. The web service lazily generates it
through the same helper if missing. Keep this key on persistent storage and back it
up securely. Corrupt/wrong-type keys fail; they are not silently replaced. Protect it
separately from `certs/server.key`. Private keys are gitignored. Key rotation changes
`key_id`; keep older **public** PEMs to verify older receipts. The endpoint exposes
only the current public key; there is no public-key history service in this phase.

## Password-encrypted vault protocol

The browser serializes the signed file once as pretty JSON plus a trailing newline,
computes its SHA-256, and encrypts those exact bytes locally. It asks for the user's
password again and validates the local wrapped identity before saving. Passwords and
evidence decryption keys never go to the vault API. `client/evidence_vault.py` is the
byte-compatible Python reference.

| Parameter | Value |
|---|---|
| Container | `securechat-vault/v1` |
| KDF | PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte result |
| KDF salt | UTF-8 `CNSProject evidence vault v1` + NUL + 16 random salt bytes |
| Encryption | AES-256-GCM, independent fresh 12-byte nonce, 16-byte appended tag |
| AAD | ASCII `securechat-vault/v1` + NUL + lowercase plaintext-file SHA-256 |
| Encoding | Standard padded base64 for salt, nonce and ciphertext-plus-tag |

This purpose/salt is separate from identity wrapping; neither its key nor its random
salt/nonce is reused. The portable package contains only `format`, `iterations`,
`salt`, `nonce`, `file_sha256`, and `ciphertext`. `ciphertext_b64` in the API and DB is
base64 of the package's UTF-8 JSON, not a plaintext transcript. Salt, nonce, KDF
parameters and file digest are public metadata, while the evidence body is encrypted.
The outer packaging is not itself a second encryption layer.

The server can see owner, title, creation time, encrypted size, file SHA-256, receipt,
and the submitted envelope hash manifest during saving. It does not retain that
manifest as a separate field. Do not put confidential chat text in the title.
Strong passwords matter: an encrypted backup permits offline password guessing.
An unlocked browser, malicious extension, XSS or compromised delivered JavaScript can
expose plaintext/passwords in browser memory. Clearing a browser does not erase a
server copy; use Delete evidence. Database/backups are not guaranteed forensic erasure.

## API, authentication and storage limits

A successful browser WebSocket register/login result includes a random 256-bit bearer
token. It is redacted in Wire Log, held only in browser memory, expires after an hour,
and is revoked when that WebSocket closes (including the gateway's idle timeout).
HTTP vault requests use `Authorization: Bearer <token>`. No authentication cookies,
query-string passwords or public bundle sharing are used. All owner predicates are
applied in SQL; another owner's ID returns the same 404 as a missing ID.

| Endpoint | Behavior |
|---|---|
| `POST /api/evidence` | Save encrypted package + title + file digest + version/manifest; return ID, metadata and signed `timestamp_receipt` |
| `GET /api/evidence` | List owner's metadata/receipts without ciphertext |
| `GET /api/evidence/{id}` | Download owner's encrypted container and receipt |
| `DELETE /api/evidence/{id}` | Delete owner's bundle |

Saving is capped at a 12 MiB request, 8 MiB encrypted payload, 10,000 declared records
and 100 bundles per account. Titles are limited to 120 characters. HTTPS/WSS is needed
outside localhost. The existing WebSocket Origin/size/rate/idle policies still apply.
Tokens and rosters are process-local, so use one worker. Password changes/recovery,
sharing links and multi-worker auth are outside this phase.

Schema version **2** adds `evidence_bundles` (`id`, `owner`, `created_at`, `title`,
`size_bytes`, `file_sha256`, `ciphertext_b64`, `timestamp_receipt` JSON), an owner index,
and nullable indexed `relayed_envelopes.envelope_sha256`. The explicit additive v1→v2
upgrade runs inside the existing serialized transaction, preserving users, locks,
logs and relay rows. Historical hashes stay NULL: v1 never stored the nonce/tag/full
envelope needed to recompute them. Unsupported future versions still stop startup.
The current database is schema v3, which subsequently adds attachment metadata;
evidence exports remain v1/v2. There is no evidence/v3 wire format. Back up an
existing DB before deploying a new schema; use a maintenance window.

## Browser workflow, offline verification and PDF

- In a verified chat, click **Save evidence**, enter the password and a non-sensitive
  title, and choose **Encrypt and save**.
- **Evidence** opens the owner-only vault. Unlock to download/verify a stored JSON;
  download its receipt and TSA public PEM separately. List entries remain explicitly
  unverified until local decryption/verification. Delete removes the owner copy.
- `/verify` is public, with file/drop input, optional receipt JSON, optional trusted
  participant fingerprint, and trusted TSA PEM text. Verification runs entirely in
  the browser and does not upload files. A receipt supplied without a valid trusted
  key is INVALID. Client code/assets must first be loaded; the verification routine
  makes no network calls. PDF generation may fetch bundled same-origin font assets.
- **Download companion PDF** renders participants/fingerprints, every message with UTC
  time and verification status, chain status, exact file digest, optional receipt and
  verification instructions. It is generated locally with pdf-lib. Noto Sans Latin
  and Devanagari are bundled under the SIL Open Font License; unsupported characters
  are represented as explicit `\u{...}` escapes. JSON retains exact Unicode text.
  The PDF library is lazy-loaded (roughly 0.5 MB gzipped); the chat does not load it
  until a report is requested.

Standalone verification (imports no client/server/auth/GUI code):

```sh
.venv/bin/python tools/verify_transcript.py evidence.json
.venv/bin/python tools/verify_transcript.py evidence.json \
  --expect-fingerprint 'AAAA BBBB CCCC DDDD' \
  --receipt receipt.json --tsa-pubkey tsa-public.pem
```

Return values remain 0=VALID, 1=INVALID, 2=unreadable inputs/usage error. Supplying
`--receipt` requires `--tsa-pubkey`; every legacy v1 invocation remains valid.

## Tests and reproducibility

`tests/fixtures/evidence_corpus/generate.py` regenerates synthetic v1/v2 evidence,
edited/removed/reordered records, bad exporter signatures, valid/tampered/wrong-file
receipts, public TSA PEM and `expected_verdicts.json`. Private fixture keys are never
written. Both verifiers consume the same corpus; Vitest compares Python/browser
verdicts and first failing message indexes. Python tests also cover owner isolation,
DB-wide plaintext absence, real-session corroboration, key persistence/concurrency,
receipt tampering, vault crypto and schema upgrade. Playwright covers the complete
save/list/download/verify/delete workflow, PDF download and public tamper detection.
All original v1 evidence tests remain unchanged.
