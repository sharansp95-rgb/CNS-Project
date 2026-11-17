"""Python reference for attachment descriptors/files, the desktop placeholder and
evidence tooling. Browser <-> Python byte compatibility is covered in Vitest."""

import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tkinter as tk

import pytest

from client.client import SecureChatClient
from client.evidence import build_evidence
from crypto_engine.attachment_tools import (
    PLACEHOLDER, PREFIX, AttachmentError, chunk_count, ciphertext_size, decrypt_file,
    display_text, encode_descriptor, encrypt_file, parse_descriptor,
)
from crypto_engine.signatures import generate_keypair, serialize_public_key
from tools import verify_transcript

CORPUS = Path(__file__).parent / "fixtures/evidence_corpus"
SMALL = 4096


def descriptor(plain=b"x" * 5000, **over):
    ct, s = encrypt_file(plain, chunk=SMALL)
    d = dict(v=1, **s, name="a.png", mime="image/png", kind="image")
    d.update(over)
    return ct, s, d


def test_file_roundtrip_sizes_and_tamper_detection():
    plain = bytes(range(256)) * 50
    ct, s = encrypt_file(plain, chunk=SMALL)
    assert len(ct) == ciphertext_size(len(plain), SMALL) == len(plain) + chunk_count(len(plain), SMALL) * 28
    assert decrypt_file(ct, s) == plain
    bad = bytearray(ct)
    bad[100] ^= 1
    with pytest.raises(AttachmentError) as e:
        decrypt_file(bytes(bad), s)
    assert e.value.code == "ciphertext_hash"
    import hashlib
    forged = dict(s, ct_sha256=hashlib.sha256(bytes(bad)).hexdigest())
    with pytest.raises(AttachmentError) as e:
        decrypt_file(bytes(bad), forged)
    assert e.value.code == "chunk_auth"


def test_reorder_and_truncation_are_rejected():
    import hashlib
    plain = b"p" * (SMALL * 3)
    ct, s = encrypt_file(plain, chunk=SMALL)
    rec = SMALL + 28
    swapped = ct[rec:2 * rec] + ct[:rec] + ct[2 * rec:]
    with pytest.raises(AttachmentError) as e:
        decrypt_file(swapped, dict(s, ct_sha256=hashlib.sha256(swapped).hexdigest()))
    assert e.value.code == "chunk_auth"
    short = ct[:2 * rec]
    forged = dict(s, size=SMALL * 2, ct_size=len(short), ct_sha256=hashlib.sha256(short).hexdigest(),
                  pt_sha256=hashlib.sha256(plain[:SMALL * 2]).hexdigest())
    with pytest.raises(AttachmentError) as e:
        decrypt_file(short, forged)
    assert e.value.code == "chunk_auth"


def test_descriptor_validation():
    _, _, d = descriptor()
    assert parse_descriptor(encode_descriptor(d)) == d
    assert parse_descriptor("hello") is None
    for patch in (dict(mime="image/svg+xml"), dict(kind="video"), dict(id="../x"), dict(size=0),
                  dict(ct_size=1), dict(thumb="<script>"), dict(v=2), dict(key="short"), dict(chunk=1)):
        assert parse_descriptor(PREFIX + json.dumps({**d, **patch})) is None, patch
    assert parse_descriptor(PREFIX + "{bad json") is None


def test_desktop_placeholder_does_not_alter_the_verbatim_message():
    _, _, d = descriptor()
    message = encode_descriptor(d)
    assert display_text(message) == PLACEHOLDER == "[attachment — open in web client]"
    assert display_text("plain text") == "plain text"
    assert d["key"] not in PLACEHOLDER


class Socket:
    def __init__(self):
        self.sent = []

    def sendall(self, data):
        self.sent.append(json.loads(data))


def test_real_clients_keep_chain_and_evidence_valid_with_an_attachment_message():
    a, b = SecureChatClient(Socket(), "alice", "bob"), SecureChatClient(Socket(), "bob", "alice")
    a.rsa_private_key, ap = generate_keypair()
    b.rsa_private_key, bp = generate_keypair()
    a.peer_public_key, b.peer_public_key = bp, ap
    a.peer_public_key_pem, b.peer_public_key_pem = serialize_public_key(bp).decode(), serialize_public_key(ap).decode()
    events = []
    b.on_event = lambda kind, data: events.append((kind, data))
    _, _, d = descriptor()
    message = encode_descriptor(d)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        a.initiate_handshake()
        b._handle_handshake_init(a.sock.sent[-1])
        a._handle_handshake_response(b.sock.sent[-1])
        for text in ("before", message, "after"):
            a.send_message(text)
            b._handle_chat(a.sock.sent[-1])
    shown = out.getvalue()
    assert PLACEHOLDER in shown and d["key"] not in shown and PREFIX not in shown
    received = [data for kind, data in events if kind == "message_received"]
    assert [r["message"] for r in received] == ["before", message, "after"]
    assert all(r["receipt"]["chain_link"] == "ok" for r in received)
    report = verify_transcript.verify_evidence(build_evidence(b, now=1800000000, format_version=2))
    assert report.valid and [i for i, _ in report.attachments] == [2]


def run(*args):
    return subprocess.run([sys.executable, "tools/verify_transcript.py", *map(str, args)],
                          capture_output=True, text=True)


def test_verify_cli_lists_attachments_and_checks_files(tmp_path):
    evidence = CORPUS / "valid_v2_attachment.json"
    result = run(evidence, "--check-file", CORPUS / "attachment_sample.png",
                 "--check-file", CORPUS / "attachment_sample.enc")
    assert result.returncode == 0, result.stdout
    assert "sample.png" in result.stdout and "original (decrypted) file" in result.stdout
    assert "stored encrypted object" in result.stdout
    other = tmp_path / "other.png"
    other.write_bytes(b"not the recorded file")
    result = run(evidence, "--check-file", other)
    assert result.returncode == 1 and "matches NO attachment hash" in result.stdout


def test_corpus_attachment_object_decrypts_with_the_recorded_descriptor():
    data = json.loads((CORPUS / "valid_v2_attachment.json").read_text())
    d = parse_descriptor(data["records"][1]["message"])
    assert d is not None
    plain = decrypt_file((CORPUS / "attachment_sample.enc").read_bytes(), d)
    assert plain == (CORPUS / "attachment_sample.png").read_bytes()
    assert plain[:4] == b"\x89PNG"
    # The signed record covers the descriptor: editing it invalidates evidence.
    forged = json.loads((CORPUS / "edited_attachment_descriptor.json").read_text())
    assert not verify_transcript.verify_evidence(forged).valid


def test_gui_bubble_shows_placeholder_not_descriptor():
    import gui.chat_gui as chat_gui
    from gui.theme import is_no_display_error
    try:
        window = chat_gui.ChatGUI()
    except tk.TclError as exc:
        if is_no_display_error(exc):
            pytest.skip("no display")
        raise
    try:
        window.geometry("1040x660+10000+10000")
        window.update()
        window.username, window.peer = "alice", "bob"
        window._handle_event("auth_success", {"username": "alice", "peer": "bob", "lab_mode": True,
                                              "own_fingerprint": "AAAA", "peer_key_found": True})
        window._handoff_to_chat()
        _, _, d = descriptor()
        window._handle_event("message_received", {"message": encode_descriptor(d), "sender": "bob",
                                                  "timestamp": 1, "receipt": {"chain_link": "ok"}})
        window.update()
        texts = []

        def walk(widget):
            for child in widget.winfo_children():
                if isinstance(child, tk.Label):
                    texts.append(str(child.cget("text")))
                elif isinstance(child, tk.Canvas):
                    texts.extend(str(child.itemcget(i, "text")) for i in child.find_all()
                                 if child.type(i) == "text")
                walk(child)

        walk(window.bubble_list)
        joined = "\n".join(texts)
        assert PLACEHOLDER in joined and PREFIX not in joined and d["key"] not in joined
    finally:
        window.update()
        window.destroy()
