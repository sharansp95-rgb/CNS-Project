"""Add the voice-call evidence fixtures only (existing corpus files are untouched).

A real two-party v2 evidence file containing invite/accept/hangup signalling and
both parties' call records, plus a copy whose recorded outcome was edited. Keys
and SDP fingerprints are synthetic.
"""

import contextlib
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from client.client import SecureChatClient
from client.evidence import build_evidence
from crypto_engine.signatures import generate_keypair, serialize_public_key

ROOT = Path(__file__).resolve().parent
CALL = "c" * 32
FP = ":".join(f"{(i * 7 + 3) % 256:02X}" for i in range(32))
FP2 = ":".join(f"{(i * 11 + 5) % 256:02X}" for i in range(32))


def sdp(fp):
    return "\r\n".join(
        [
            "v=0",
            "o=- 1 2 IN IP4 127.0.0.1",
            "s=-",
            "t=0 0",
            "m=audio 9 UDP/TLS/RTP/SAVPF 111",
            "c=IN IP4 0.0.0.0",
            f"a=fingerprint:sha-256 {fp}",
            "a=setup:actpass",
            "",
        ]
    )


def msg(**fields):
    return "securechat-call/v1:" + json.dumps(
        {"v": 1, "call": CALL, **fields}, sort_keys=True, separators=(",", ":")
    )


def record(role, outcome="completed"):
    return msg(
        type="record",
        role=role,
        outcome=outcome,
        started=1800000005,
        ended=1800000065,
        duration=60,
        fp_match="yes",
        sas_confirmed=True,
        conn="direct",
    )


class Socket:
    def __init__(self):
        self.sent = []

    def sendall(self, data):
        self.sent.append(json.loads(data))


def generate():
    a, b = SecureChatClient(Socket(), "alice", "bob"), SecureChatClient(Socket(), "bob", "alice")
    a.rsa_private_key, ap = generate_keypair()
    b.rsa_private_key, bp = generate_keypair()
    a.peer_public_key, b.peer_public_key = bp, ap
    a.peer_public_key_pem, b.peer_public_key_pem = (
        serialize_public_key(bp).decode(),
        serialize_public_key(ap).decode(),
    )
    with contextlib.redirect_stdout(io.StringIO()):
        a.initiate_handshake()
        b._handle_handshake_init(a.sock.sent[-1])
        a._handle_handshake_response(b.sock.sent[-1])
        for sender, receiver, message in [
            (a, b, msg(type="invite", sdp=sdp(FP))),
            (b, a, msg(type="accept", sdp=sdp(FP2))),
            (a, b, msg(type="hangup", reason="user")),
            (a, b, record("caller")),
            (b, a, record("callee")),
        ]:
            sender.send_message(message)
            receiver._handle_chat(sender.sock.sent[-1])
    evidence = build_evidence(b, now=1800000000, format_version=2)
    (ROOT / "valid_v2_call.json").write_bytes(
        (json.dumps(evidence, ensure_ascii=False, indent=2) + "\n").encode()
    )
    forged = json.loads(json.dumps(evidence))
    forged["records"][3]["message"] = forged["records"][3]["message"].replace(
        '"duration":60', '"duration":3600'
    )
    (ROOT / "edited_call_record.json").write_bytes(
        (json.dumps(forged, ensure_ascii=False, indent=2) + "\n").encode()
    )
    manifest = json.loads((ROOT / "expected_verdicts.json").read_text())
    manifest["valid_v2_call"] = dict(file="valid_v2_call.json", valid=True, index=None)
    manifest["edited_call_record"] = dict(file="edited_call_record.json", valid=False, index=4)
    (ROOT / "expected_verdicts.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    generate()
