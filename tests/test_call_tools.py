"""Call signaling in Python: validation, desktop placeholder, chain/evidence compatibility."""

import contextlib
import io
import json
import subprocess
import sys
from pathlib import Path

from client.client import SecureChatClient
from client.evidence import build_evidence
from crypto_engine.attachment_tools import display_text
from crypto_engine.call_tools import (
    PLACEHOLDER,
    PREFIX,
    parse_signal,
    signed_fingerprint,
    valid_sdp,
)
from crypto_engine.signatures import generate_keypair, serialize_public_key
from tools import verify_transcript

CORPUS = Path(__file__).parent / "fixtures/evidence_corpus"
sys.path.insert(0, str(CORPUS))
import generate_calls as gen  # noqa: E402


def test_sdp_and_signal_validation():
    assert signed_fingerprint(gen.sdp(gen.FP)) == gen.FP
    assert valid_sdp(gen.sdp(gen.FP))
    assert not valid_sdp(gen.sdp(gen.FP) + "m=video 9 X\r\n")
    assert not valid_sdp("v=0\r\nm=audio 9 X\r\n")
    assert not valid_sdp(gen.sdp(gen.FP).replace("sha-256", "sha-1"))
    assert parse_signal(gen.msg(type="invite", sdp=gen.sdp(gen.FP)))["type"] == "invite"
    assert parse_signal(gen.record("caller"))["outcome"] == "completed"
    for bad in (
        gen.msg(type="invite"),
        gen.msg(type="invite", sdp="junk"),
        gen.msg(type="decline", sdp=gen.sdp(gen.FP)),
        gen.msg(type="record", role="caller", outcome="won"),
        gen.msg(type="bogus"),
        PREFIX + "{bad",
        PREFIX + json.dumps({"v": 1, "call": "x", "type": "decline"}),
    ):
        assert parse_signal(bad) is None, bad


def test_desktop_placeholder_for_calls():
    assert display_text(gen.record("caller")) == PLACEHOLDER == "[call — web client only]"
    assert display_text(gen.msg(type="invite", sdp=gen.sdp(gen.FP))) == PLACEHOLDER
    assert display_text("hello") == "hello"


class Socket:
    def __init__(self):
        self.sent = []

    def sendall(self, data):
        self.sent.append(json.loads(data))


def test_real_clients_keep_chain_and_evidence_valid_with_call_messages():
    a, b = SecureChatClient(Socket(), "alice", "bob"), SecureChatClient(Socket(), "bob", "alice")
    a.rsa_private_key, ap = generate_keypair()
    b.rsa_private_key, bp = generate_keypair()
    a.peer_public_key, b.peer_public_key = bp, ap
    a.peer_public_key_pem, b.peer_public_key_pem = (
        serialize_public_key(bp).decode(),
        serialize_public_key(ap).decode(),
    )
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        a.initiate_handshake()
        b._handle_handshake_init(a.sock.sent[-1])
        a._handle_handshake_response(b.sock.sent[-1])
        for text in (
            "hi",
            gen.msg(type="invite", sdp=gen.sdp(gen.FP)),
            gen.record("caller"),
            "bye",
        ):
            a.send_message(text)
            b._handle_chat(a.sock.sent[-1])
    shown = out.getvalue()
    assert PLACEHOLDER in shown and gen.FP not in shown and PREFIX not in shown
    report = verify_transcript.verify_evidence(build_evidence(b, now=1800000000, format_version=2))
    assert report.valid and [i for i, _, _ in report.calls] == [2, 3]


def test_corpus_call_evidence_and_cli():
    result = subprocess.run(
        [sys.executable, "tools/verify_transcript.py", str(CORPUS / "valid_v2_call.json")],
        capture_output=True,
        text=True,
    )
    assert (
        result.returncode == 0
        and "Voice calls" in result.stdout
        and "connection direct" in result.stdout
    )
    forged = json.loads((CORPUS / "edited_call_record.json").read_text())
    assert not verify_transcript.verify_evidence(forged).valid
