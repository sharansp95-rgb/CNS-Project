"""Proof format, encrypted storage, ownership, migration and exact-byte receipts."""

import base64
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import MetaData, select
from client.evidence_vault import encrypt_evidence, decrypt_evidence
from client.evidence import build_evidence
from crypto_engine.evidence_tools import verify_receipt, envelope_sha256
from server import db
from server.timestamp import TimestampSigner
from server.relay_core import RelayCore
import server.server as sm
from tools import verify_transcript
from web.app import create_app

CORPUS = Path(__file__).parent / "fixtures/evidence_corpus"
ORIGIN = "http://localhost:8080"


def request_body(raw, version=2, hashes=None):
    package = encrypt_evidence(raw, "vault-password")
    return dict(
        title="Evidence test",
        file_sha256=package["file_sha256"],
        ciphertext_b64=base64.b64encode(json.dumps(package).encode()).decode(),
        format_version=version,
        envelope_hashes=hashes or [],
        total=(len(hashes or []) if version == 2 else len(json.loads(raw).get("records", []))),
    )


def authed(ws, name):
    ws.send_json(dict(type="register", username=name, password="password"))
    result = ws.receive_json()
    assert result["success"]
    return {"Authorization": "Bearer " + result["api_token"]}


def app():
    return create_app(RelayCore(logger=lambda *a, **kw: sm.log_event(*a, **kw)))


def test_owner_isolation_and_no_plaintext_in_any_database_column():
    marker = "Approve transfer 500"
    raw = (CORPUS / "valid_v2.json").read_bytes()
    with TestClient(app()) as client, client.websocket_connect(
        "/ws", headers={"origin": ORIGIN}
    ) as alice, client.websocket_connect("/ws", headers={"origin": ORIGIN}) as bob:
        a, b = authed(alice, "alice"), authed(bob, "bob")
        saved = client.post("/api/evidence", headers=a, json=request_body(raw)).json()
        identifier = saved["id"]
        assert len(client.get("/api/evidence", headers=a).json()) == 1
        assert client.get("/api/evidence", headers=b).json() == []
        assert client.get("/api/evidence/" + identifier, headers=b).status_code == 404
        assert (
            client.delete("/api/evidence/" + identifier, headers=b).status_code == 404
        )
        result = client.get("/api/evidence/" + identifier, headers=a).json()
        package = json.loads(base64.b64decode(result["ciphertext_b64"]))
        assert decrypt_evidence(package, "vault-password") == raw
        reflected = MetaData()
        reflected.reflect(bind=db.get_database().engine)
        with db.get_database().engine.connect() as conn:
            for table in reflected.sorted_tables:
                for row in conn.execute(select(table)):
                    for value in row:
                        assert marker not in str(value)
                        assert "vault-password" not in str(value)
        assert (
            client.delete("/api/evidence/" + identifier, headers=a).status_code == 200
        )
        assert client.get("/api/evidence", headers=a).json() == []


def test_api_requires_auth_and_revokes_on_disconnect():
    with TestClient(app()) as client:
        assert client.get("/api/evidence").status_code == 401
        assert client.post("/api/evidence", json={}).status_code == 401
        with client.websocket_connect("/ws", headers={"origin": ORIGIN}) as ws:
            headers = authed(ws, "alice")
            assert client.get("/api/evidence", headers=headers).status_code == 200
        assert client.get("/api/evidence", headers=headers).status_code == 401


def test_receipt_signature_tamper_exact_file_and_v1_unavailable():
    raw = (CORPUS / "valid_v1.json").read_bytes()
    with TestClient(app()) as client, client.websocket_connect(
        "/ws", headers={"origin": ORIGIN}
    ) as ws:
        headers = authed(ws, "alice")
        saved = client.post(
            "/api/evidence", headers=headers, json=request_body(raw, version=1)
        ).json()
        key = client.get("/api/timestamp-key").json()
        receipt = saved["timestamp_receipt"]
        assert receipt["corroborated"] == "not available"
        assert verify_receipt(receipt, raw, key["public_key_pem"].encode())
        assert not verify_receipt(receipt, raw + b"\n", key["public_key_pem"].encode())
        bad = copy.deepcopy(receipt)
        bad["corroborated"] = 1
        assert not verify_receipt(bad, raw, key["public_key_pem"].encode())
        bad = copy.deepcopy(receipt)
        bad["signature"] = base64.b64encode(b"fake").decode()
        assert not verify_receipt(bad, raw, key["public_key_pem"].encode())


def test_reference_vault_wrong_password_and_hash_binding():
    package = encrypt_evidence(b"private evidence", "correct")
    assert decrypt_evidence(package, "correct") == b"private evidence"
    with pytest.raises(Exception):
        decrypt_evidence(package, "wrong")
    package["file_sha256"] = "0" * 64
    with pytest.raises(Exception):
        decrypt_evidence(package, "correct")


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
            signer.receipt(conn, "unrelated", receipt["file_sha256"], 2, hashes, 1)[
                "corroborated"
            ]
            == 0
        )
        assert (
            signer.receipt(
                conn, "proof_bob", receipt["file_sha256"], 2, hashes * 500, 500
            )["corroborated"]
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
        assert conn.execute(select(db.schema_version.c.version)).scalar_one() == 2
        assert (
            conn.execute(select(db.users.c.password_hash)).scalar_one()
            == "UNCHANGED_ENCODED_PBKDF2"
        )
        assert (
            conn.execute(select(db.relayed_envelopes.c.envelope_sha256)).scalar_one()
            is None
        )
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
        assert result.returncode == (0 if case["valid"] else 1), (
            result.stdout + result.stderr
        )
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


def test_invalid_upload_rejected_without_storage():
    with TestClient(app()) as client, client.websocket_connect(
        "/ws", headers={"origin": ORIGIN}
    ) as ws:
        headers = authed(ws, "alice")
        response = client.post(
            "/api/evidence", headers=headers, json={"plaintext": "DO_NOT_STORE"}
        )
        assert response.status_code == 400
        assert client.get("/api/evidence", headers=headers).json() == []


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


def test_vault_manifest_and_frame_validation():
    with TestClient(app()) as client, client.websocket_connect(
        "/ws", headers={"origin": ORIGIN}
    ) as ws:
        headers = authed(ws, "validator")
        body = request_body(b"private file")
        body["envelope_hashes"] = ["not a hash"]
        body["total"] = 1
        assert (
            client.post("/api/evidence", headers=headers, json=body).status_code == 400
        )
        body = request_body(b"private file")
        body["ciphertext_b64"] = "not base64"
        assert (
            client.post("/api/evidence", headers=headers, json=body).status_code == 400
        )


def test_concurrent_key_creation_publishes_one_complete_private_key(
    tmp_path, monkeypatch
):
    from concurrent.futures import ThreadPoolExecutor

    path = tmp_path / "concurrent.key"
    monkeypatch.setenv("TSA_KEY_PATH", str(path))
    with ThreadPoolExecutor(max_workers=6) as pool:
        ids = list(pool.map(lambda _: TimestampSigner().key_id, range(6)))
    assert len(set(ids)) == 1
    assert not list(tmp_path.glob(".tsa-*"))
