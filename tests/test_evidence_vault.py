"""Proof format, encrypted storage, ownership, migration and exact-byte receipts."""

import hashlib
import json
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from sqlalchemy import select

import server.server as sm
from client.evidence import build_evidence
from server import db
from server.relay_core import RelayCore
from server.timestamp import TimestampSigner
from tools import verify_transcript
from web.app import create_app

CORPUS = Path(__file__).parent / "fixtures/evidence_corpus"
ORIGIN = "http://localhost:8080"


def app():
    return create_app(RelayCore(logger=lambda *a, **kw: sm.log_event(*a, **kw)))


def test_v2_real_session_corroboration(net):
    import _demo_common as dc

    server, _, port = net.start_server()
    alice = net.register_client(port, "proof_alice", "proof_bob")
    bob = net.register_client(port, "proof_bob", "proof_alice")
    assert dc.establish_signed_handshake(alice, bob)
    alice.send_message("Real relayed confidential text")
    deadline = time.time() + 10
    while time.time() < deadline and not bob.transcript:
        time.sleep(0.02)
    assert bob.transcript
    evidence = build_evidence(bob, format_version=2)
    assert evidence["format_version"] == 2
    assert verify_transcript.verify_evidence(evidence).valid
    hashes = [row["envelope_sha256"] for row in evidence["records"]]
    assert len(hashes) == 1
    signer = TimestampSigner()
    with server.database.engine.connect() as conn:
        receipt = signer.receipt(
            conn,
            "proof_bob",
            hashlib.sha256(json.dumps(evidence).encode()).hexdigest(),
            2,
            hashes,
            len(hashes),
        )
        assert receipt["corroborated"] == receipt["total"] == 1
        assert (
            signer.receipt(conn, "unrelated", receipt["file_sha256"], 2, hashes, 1)["corroborated"]
            == 0
        )
        assert (
            signer.receipt(conn, "proof_bob", receipt["file_sha256"], 2, hashes * 500, 500)[
                "corroborated"
            ]
            == 1
        )


def test_schema_upgrade_v1_to_v2_keeps_existing_rows(tmp_path):
    target = tmp_path / "old.db"
    with sqlite3.connect(target) as conn:
        conn.executescript("""CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
        INSERT INTO schema_version VALUES(1);
        CREATE TABLE users (username TEXT PRIMARY KEY,password_hash TEXT NOT NULL,public_key_pem TEXT,created_at FLOAT NOT NULL);
        INSERT INTO users VALUES('legacy','UNCHANGED_ENCODED_PBKDF2',NULL,1);
        CREATE TABLE relayed_envelopes (id INTEGER PRIMARY KEY,ts FLOAT NOT NULL,sender TEXT NOT NULL,recipient TEXT,envelope_type TEXT NOT NULL,size_bytes INTEGER NOT NULL,ciphertext_b64 TEXT);
        INSERT INTO relayed_envelopes VALUES(1,1,'legacy','bob','chat',10,'YWJj');""")
    database = db.get_database("sqlite:///" + str(target))
    with database.engine.connect() as conn:
        assert conn.execute(select(db.schema_version.c.version)).scalar_one() == 3
        assert (
            conn.execute(select(db.users.c.password_hash)).scalar_one()
            == "UNCHANGED_ENCODED_PBKDF2"
        )
        assert conn.execute(select(db.relayed_envelopes.c.envelope_sha256)).scalar_one() is None
        assert conn.execute(select(db.evidence_bundles)).all() == []
    db.dispose_databases()
    assert db.get_database("sqlite:///" + str(target))


def test_corpus_verdicts_and_receipt_cli(tmp_path):
    manifest = json.loads((CORPUS / "expected_verdicts.json").read_text())
    for case in manifest.values():
        command = [
            sys.executable,
            "tools/verify_transcript.py",
            str(CORPUS / case["file"]),
        ]
        if case.get("receipt"):
            command += [
                "--receipt",
                str(CORPUS / case["receipt"]),
                "--tsa-pubkey",
                str(CORPUS / "tsa_public.pem"),
            ]
        result = subprocess.run(command, capture_output=True, text=True)
        assert result.returncode == (0 if case["valid"] else 1), result.stdout + result.stderr
    result = subprocess.run(
        [
            sys.executable,
            "tools/verify_transcript.py",
            str(CORPUS / "valid_v2.json"),
            "--receipt",
            str(CORPUS / "valid_receipt.json"),
            "--tsa-pubkey",
            str(CORPUS / "tsa_public.pem"),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_tsa_key_is_separate_persistent_and_not_overwritten(tmp_path, monkeypatch):
    from tools.generate_tsa_key import generate

    path = tmp_path / "separate-tsa.key"
    monkeypatch.setenv("TSA_KEY_PATH", str(path))
    signer = TimestampSigner()
    original = path.read_bytes()
    assert TimestampSigner().key_id == signer.key_id
    assert generate() == path and path.read_bytes() == original
    assert path.stat().st_mode & 0o077 == 0


def test_v2_missing_envelope_hash_is_invalid_and_v1_still_verifies():
    original = json.loads((CORPUS / "valid_v1.json").read_text())
    assert verify_transcript.verify_evidence(original).valid
    evidence = json.loads((CORPUS / "valid_v2.json").read_text())
    del evidence["records"][0]["envelope_sha256"]
    report = verify_transcript.verify_evidence(evidence)
    assert not report.valid and (1, "envelope hash") in {
        (idx, check) for idx, check, _ in report.failures
    }


def test_concurrent_key_creation_publishes_one_complete_private_key(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    path = tmp_path / "concurrent.key"
    monkeypatch.setenv("TSA_KEY_PATH", str(path))
    with ThreadPoolExecutor(max_workers=6) as pool:
        ids = list(pool.map(lambda _: TimestampSigner().key_id, range(6)))
    assert len(set(ids)) == 1
    assert not list(tmp_path.glob(".tsa-*"))
