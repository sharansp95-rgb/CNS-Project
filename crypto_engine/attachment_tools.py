"""Attachment descriptors and the chunked file format, in Python.

The browser encrypts files; this module is the reference implementation used by
tests, ``tools/verify_transcript.py`` and the desktop client. The descriptor is
the *text of an ordinary chat message*, so it is signed, encrypted, hash-chained
and part of evidence like any other message. The desktop client never opens
attachments: it shows :data:`PLACEHOLDER`, while the verbatim message text is kept
for chain verification and evidence.

File format (identical to ``web/frontend/src/attachments/fileCrypto.ts``)::

    per chunk:  nonce(12) || AES-256-GCM ciphertext || tag(16)
    AAD:        b"securechat-attachment/v1\\0<id>\\0<index>\\0<1 if last else 0>"
"""

import base64
import hashlib
import json
import os
import re

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_engine.hash_chain import canonical_json

PREFIX = "securechat-attachment/v1:"
PLACEHOLDER = "[attachment — open in web client]"
CHUNK = 1024 * 1024
OVERHEAD = 28
ALLOWED_MIME = ("image/jpeg", "image/png", "image/webp", "image/gif", "video/mp4", "video/webm")
MAX_THUMB = 12 * 1024
_HEX32, _HEX64 = re.compile(r"[0-9a-f]{32}"), re.compile(r"[0-9a-f]{64}")


class AttachmentError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def is_attachment_message(message):
    return isinstance(message, str) and message.startswith(PREFIX)


def display_text(message):
    """What a client that cannot open attachments or calls should show for this message."""
    from crypto_engine import call_tools

    if is_attachment_message(message):
        return PLACEHOLDER
    return call_tools.PLACEHOLDER if call_tools.is_call_message(message) else message


def chunk_count(size, chunk=CHUNK):
    return max(1, -(-size // chunk))


def ciphertext_size(size, chunk=CHUNK):
    return size + chunk_count(size, chunk) * OVERHEAD


def parse_descriptor(message):
    """Strictly validate an untrusted descriptor; returns a dict or None."""
    if not is_attachment_message(message) or len(message) > 64 * 1024:
        return None
    try:
        d = json.loads(message[len(PREFIX):])
        isint = lambda v: type(v) is int
        ok = (
            isinstance(d, dict) and d.get("v") == 1
            and isinstance(d.get("id"), str) and _HEX32.fullmatch(d["id"])
            and isinstance(d.get("key"), str) and len(d["key"]) == 44
            and isinstance(d.get("name"), str) and len(d["name"]) <= 200
            and d.get("mime") in ALLOWED_MIME and d.get("kind") in ("image", "video")
            and d["mime"].startswith(d["kind"] + "/")
            and isint(d.get("size")) and d["size"] > 0
            and isint(d.get("chunk")) and 4096 <= d["chunk"] <= 8 * CHUNK
            and d.get("ct_size") == ciphertext_size(d["size"], d["chunk"])
            and isinstance(d.get("ct_sha256"), str) and _HEX64.fullmatch(d["ct_sha256"])
            and isinstance(d.get("pt_sha256"), str) and _HEX64.fullmatch(d["pt_sha256"])
            and (d.get("thumb") is None or (
                isinstance(d["thumb"], str) and len(d["thumb"]) <= MAX_THUMB * 4 // 3 + 4
                and re.fullmatch(r"[A-Za-z0-9+/=]*", d["thumb"])))
        )
        return d if ok else None
    except (ValueError, TypeError, RecursionError):
        return None


def encode_descriptor(d):
    return PREFIX + canonical_json(d).decode()


def _aad(file_id, index, last):
    return f"securechat-attachment/v1\0{file_id}\0{index}\0{1 if last else 0}".encode()


def encrypt_file(plain, file_id=None, chunk=CHUNK):
    """Returns (ciphertext, secrets-dict) in the browser's exact format."""
    file_id = file_id or os.urandom(16).hex()
    key = AESGCM.generate_key(256)
    aes, n, parts = AESGCM(key), chunk_count(len(plain), chunk), []
    for i in range(n):
        part, nonce = plain[i * chunk:(i + 1) * chunk], os.urandom(12)
        parts.append(nonce + aes.encrypt(nonce, part, _aad(file_id, i, i == n - 1)))
    out = b"".join(parts)
    return out, dict(
        id=file_id, key=base64.b64encode(key).decode(), chunk=chunk, size=len(plain),
        ct_size=len(out), ct_sha256=hashlib.sha256(out).hexdigest(),
        pt_sha256=hashlib.sha256(plain).hexdigest(),
    )


def decrypt_file(ciphertext, s):
    """Verify ciphertext hash, authenticate each chunk, verify plaintext hash."""
    if len(ciphertext) != s["ct_size"] or s["ct_size"] != ciphertext_size(s["size"], s["chunk"]):
        raise AttachmentError("size", "Attachment tampered or corrupted: size does not match the signed message")
    if hashlib.sha256(ciphertext).hexdigest() != s["ct_sha256"]:
        raise AttachmentError("ciphertext_hash", "Attachment tampered or corrupted: ciphertext hash mismatch")
    aes, n, at, plain = AESGCM(base64.b64decode(s["key"])), chunk_count(s["size"], s["chunk"]), 0, []
    for i in range(n):
        length = min(s["chunk"], s["size"] - i * s["chunk"])
        nonce, box = ciphertext[at:at + 12], ciphertext[at + 12:at + 12 + length + 16]
        try:
            plain.append(aes.decrypt(nonce, box, _aad(s["id"], i, i == n - 1)))
        except InvalidTag:
            raise AttachmentError("chunk_auth", f"Attachment tampered or corrupted: chunk {i + 1} failed authentication")
        at += 12 + length + 16
    data = b"".join(plain)
    if hashlib.sha256(data).hexdigest() != s["pt_sha256"]:
        raise AttachmentError("plaintext_hash", "Attachment tampered or corrupted: plaintext hash mismatch")
    return data
