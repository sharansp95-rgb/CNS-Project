"""Add the attachment fixtures only; existing corpus files are never regenerated.

Creates a real two-party v2 evidence file whose second message is an attachment
descriptor, the matching plaintext sample file and its encrypted object. All keys
are synthetic and the outputs are public.
"""

import contextlib
import io
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from client.client import SecureChatClient
from client.evidence import build_evidence
from crypto_engine.attachment_tools import encode_descriptor, encrypt_file
from crypto_engine.signatures import generate_keypair, serialize_public_key

ROOT = Path(__file__).resolve().parent
# A real 1x1 PNG.
PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000d49444154789c6360f8cfc0f01f0005000201a5f6458a0000000049454e44ae426082"
)


class Socket:
    def __init__(self):
        self.sent = []

    def sendall(self, data):
        self.sent.append(json.loads(data))


def generate():
    ciphertext, secrets = encrypt_file(PNG)
    descriptor = dict(v=1, **secrets, name="sample.png", mime="image/png", kind="image")
    (ROOT / "attachment_sample.png").write_bytes(PNG)
    (ROOT / "attachment_sample.enc").write_bytes(ciphertext)
    a, b = SecureChatClient(Socket(), "alice", "bob"), SecureChatClient(Socket(), "bob", "alice")
    a.rsa_private_key, ap = generate_keypair()
    b.rsa_private_key, bp = generate_keypair()
    a.peer_public_key, b.peer_public_key = bp, ap
    a.peer_public_key_pem = serialize_public_key(bp).decode()
    b.peer_public_key_pem = serialize_public_key(ap).decode()
    with contextlib.redirect_stdout(io.StringIO()):
        a.initiate_handshake()
        b._handle_handshake_init(a.sock.sent[-1])
        a._handle_handshake_response(b.sock.sent[-1])
        for sender, receiver, message in [
            (a, b, "Sending the photo"),
            (a, b, encode_descriptor(descriptor)),
            (b, a, "Got it"),
        ]:
            sender.send_message(message)
            receiver._handle_chat(sender.sock.sent[-1])
    evidence = build_evidence(b, now=1800000000, format_version=2)
    raw = (json.dumps(evidence, ensure_ascii=False, indent=2) + "\n").encode()
    (ROOT / "valid_v2_attachment.json").write_bytes(raw)
    # An attacker rewrites the recorded plaintext hash: the sender's signature breaks.
    forged = json.loads(raw)
    forged["records"][1]["message"] = forged["records"][1]["message"].replace(
        secrets["pt_sha256"], "0" * 64
    )
    (ROOT / "edited_attachment_descriptor.json").write_bytes(
        (json.dumps(forged, ensure_ascii=False, indent=2) + "\n").encode()
    )
    manifest = json.loads((ROOT / "expected_verdicts.json").read_text())
    manifest["valid_v2_attachment"] = dict(file="valid_v2_attachment.json", valid=True, index=None)
    manifest["edited_attachment_descriptor"] = dict(
        file="edited_attachment_descriptor.json", valid=False, index=2
    )
    (ROOT / "expected_verdicts.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    generate()
