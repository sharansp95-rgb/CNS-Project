"""Regenerate synthetic public evidence fixtures; no private keys are written."""

import base64
import contextlib
import copy
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from client.client import SecureChatClient
from client.evidence import build_evidence
from crypto_engine.evidence_tools import key_id, sha256
from crypto_engine.hash_chain import canonical_json
from crypto_engine.signatures import generate_keypair, serialize_public_key

ROOT = Path(__file__).resolve().parent


class Socket:
    def __init__(self):
        self.sent = []

    def sendall(self, data):
        self.sent.append(json.loads(data))


def generate():
    a, b = SecureChatClient(Socket(), "alice", "bob"), SecureChatClient(Socket(), "bob", "alice")
    a.rsa_private_key, ap = generate_keypair()
    b.rsa_private_key, bp = generate_keypair()
    a.peer_public_key = bp
    b.peer_public_key = ap
    a.peer_public_key_pem = serialize_public_key(bp).decode()
    b.peer_public_key_pem = serialize_public_key(ap).decode()
    with contextlib.redirect_stdout(io.StringIO()):
        a.initiate_handshake()
        b._handle_handshake_init(a.sock.sent[-1])
        a._handle_handshake_response(b.sock.sent[-1])
        for sender, receiver, message in [
            (a, b, "Approve transfer 500"),
            (b, a, "Approved"),
            (a, b, "Completed — नमस्ते 🙂"),
        ]:
            sender.send_message(message)
            receiver._handle_chat(sender.sock.sent[-1])
    v1 = build_evidence(b, now=1800000000)
    v2 = build_evidence(b, now=1800000000, format_version=2)

    def save(name, data):
        raw = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode()
        (ROOT / name).write_bytes(raw)
        return raw

    v1bytes = save("valid_v1.json", v1)
    v2bytes = save("valid_v2.json", v2)
    key = Ed25519PrivateKey.generate()
    (ROOT / "tsa_public.pem").write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    def receipt(raw, total=3):
        body = dict(
            receipt_version=1,
            file_sha256=sha256(raw),
            server_time="2026-11-16T10:00:00Z",
            key_id=key_id(key.public_key()),
            corroborated=total,
            total=total,
        )
        body["signature"] = base64.b64encode(key.sign(canonical_json(body))).decode()
        return body

    clean = receipt(v2bytes)
    save("valid_receipt.json", clean)
    changed = copy.deepcopy(v2)
    changed["records"][0]["message"] = "Approve transfer 5000"
    save("edited_message.json", changed)
    removed = copy.deepcopy(v2)
    removed["records"].pop(0)
    save("removed_message.json", removed)
    reordered = copy.deepcopy(v2)
    reordered["records"][0], reordered["records"][2] = (
        reordered["records"][2],
        reordered["records"][0],
    )
    save("reordered.json", reordered)
    wrong = copy.deepcopy(v2)
    wrong["exporter_signature"] = base64.b64encode(b"wrong-signature").decode()
    save("wrong_export_signature.json", wrong)
    tampered = copy.deepcopy(clean)
    tampered["server_time"] = "2030-01-01T00:00:00Z"
    save("tampered_receipt.json", tampered)
    save("receipt_another_file.json", receipt(v1bytes))
    expected = {
        "valid_v1": dict(file="valid_v1.json", valid=True, index=None),
        "valid_v2": dict(
            file="valid_v2.json", receipt="valid_receipt.json", valid=True, index=None
        ),
        "edited_message": dict(file="edited_message.json", valid=False, index=1),
        "removed_message": dict(file="removed_message.json", valid=False, index=2),
        "reordered": dict(file="reordered.json", valid=False, index=1),
        "wrong_export_signature": dict(file="wrong_export_signature.json", valid=False, index=None),
        "tampered_receipt": dict(
            file="valid_v2.json",
            receipt="tampered_receipt.json",
            valid=False,
            index=None,
        ),
        "receipt_another_file": dict(
            file="valid_v2.json",
            receipt="receipt_another_file.json",
            valid=False,
            index=None,
        ),
    }
    save("expected_verdicts.json", expected)


if __name__ == "__main__":
    generate()
