"""Evidence-only hashes and receipt verification, independent of clients/server."""

import base64
import hashlib
import json
import re
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from crypto_engine.hash_chain import canonical_json

V1 = "securechat-evidence/v1"
V2 = "securechat-evidence/v2"
RECEIPT_FIELDS = {
    "receipt_version",
    "file_sha256",
    "server_time",
    "key_id",
    "corroborated",
    "total",
    "signature",
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def envelope_sha256(envelope):
    """SHA-256 of canonical ASCII JSON of the entire actual JSON chat envelope.

    No transport newline, WS framing, TLS bytes, or local Wire Log fields.
    """
    return sha256(canonical_json(envelope))


def valid_hash(value):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) is not None


def key_id(public_key):
    return sha256(
        public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def verify_receipt(receipt, file_bytes, public_pem):
    """Verify exact file bytes, receipt structure/time, key pin and Ed25519 signature."""
    try:
        if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
            return False
        key = serialization.load_pem_public_key(public_pem)
        if not isinstance(key, Ed25519PublicKey) or (
            type(receipt["receipt_version"]) is not int or receipt["receipt_version"] != 1
        ):
            return False
        if receipt["file_sha256"] != sha256(file_bytes) or receipt["key_id"] != key_id(key):
            return False
        if not isinstance(receipt["server_time"], str) or not receipt["server_time"].endswith("Z"):
            return False
        stamp = datetime.fromisoformat(receipt["server_time"].replace("Z", "+00:00"))
        if stamp.utcoffset() != timezone.utc.utcoffset(stamp):
            return False
        total, count = receipt["total"], receipt["corroborated"]
        if type(total) is not int or total < 0:
            return False
        if count != "not available" and (type(count) is not int or not 0 <= count <= total):
            return False
        file = json.loads(file_bytes)
        if isinstance(file, dict) and file.get("format") in (V1, V2):
            if not isinstance(file.get("records"), list) or total != len(file["records"]):
                return False
            if file["format"] == V1 and count != "not available":
                return False
            if file["format"] == V2 and type(count) is not int:
                return False
        body = {k: v for k, v in receipt.items() if k != "signature"}
        key.verify(base64.b64decode(receipt["signature"], validate=True), canonical_json(body))
        return True
    except Exception:
        return False
