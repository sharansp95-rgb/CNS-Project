"""Persistence contracts, real TLS chat confidentiality, and legacy import."""
import json
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import patch

import pytest
from sqlalchemy import MetaData, insert, select
from sqlalchemy.exc import IntegrityError

import _demo_common as dc
from server import db, user_store
from server.lockout import LockoutGuard
from server.security_log import log_event
from tools.migrate_json_to_db import migrate


def rows(table):
    with db.get_database().engine.connect() as conn:
        return conn.execute(select(table)).mappings().all()


def test_database_url_override(tmp_path, monkeypatch):
    target = tmp_path / "custom" / "overridden.db"
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + str(target))
    assert user_store.register_user("alice", "pw", "public-pem")
    assert target.exists()
    assert db.get_database().engine.url.database == str(target)
    assert user_store.verify_user("alice", "pw")
    assert user_store.get_public_key("alice") == "public-pem"
    assert rows(db.schema_version) == [{"version": 1}]


def test_duplicate_username_rejected_by_database():
    database = db.get_database()
    assert user_store.register_user("unique", "pw")
    with pytest.raises(IntegrityError), database.transaction() as conn:
        conn.execute(insert(db.users).values(username="unique", password_hash="x", created_at=0))
    assert not user_store.register_user("unique", "different")
    assert user_store.verify_user("unique", "pw")


def test_lockout_survives_real_server_restart(net):
    guard = LockoutGuard(threshold=2, backoff_schedule=(60, 120))
    server, _, port = net.start_server(lockout=guard)
    client = net.register_client(port, "restart_user", "nobody")
    net.disconnect(server, client)
    assert not net.login_attempt(port, "restart_user", "wrong")["success"]
    assert not net.login_attempt(port, "restart_user", "wrong")["success"]
    server.shutdown()
    db.dispose_databases()
    _, _, new_port = net.start_server(lockout=LockoutGuard(threshold=2, backoff_schedule=(60, 120)))
    with patch("server.user_store.verify_password") as spy:
        result = net.login_attempt(new_port, "restart_user", dc.DEMO_PASSWORD)
    spy.assert_not_called()
    assert not result["success"] and "locked" in result["reason"]


def test_partial_failure_window_and_backoff_survive_restart():
    now = time.time()
    LockoutGuard(threshold=2).record_failure("a", now=now)
    db.dispose_databases()
    assert LockoutGuard(threshold=2).record_failure("a", now=now + 1).retry_after == 30
    db.dispose_databases()
    guard = LockoutGuard(threshold=2)
    assert not guard.status("a", now=now + 32).locked
    guard.record_failure("a", now=now + 32)
    assert guard.record_failure("a", now=now + 33).retry_after == 60
    guard.record_success("a")
    db.dispose_databases()
    assert not LockoutGuard().status("a", now=now + 34).locked
    assert rows(db.login_lockouts) == []


def test_chat_round_trip_stores_no_plaintext_in_any_column(net):
    received = []
    server, _, port = net.start_server()
    alice = net.register_client(port, "db_alice", "db_bob")
    bob = net.register_client(port, "db_bob", "db_alice",
                              event_callback=lambda kind, data: received.append((kind, data)))
    assert dc.establish_signed_handshake(alice, bob)
    message = "DATABASE_PLAINTEXT_SENTINEL_9d5d6430_hello"
    alice.send_message(message)
    deadline = time.time() + 10
    def delivered():
        return any(kind == "message_received" and data.get("message") == message
                   for kind, data in received)
    while time.time() < deadline and not delivered():
        time.sleep(0.02)
    assert delivered(), "real receiver must decrypt, verify and display"
    archived = rows(db.relayed_envelopes)
    assert any(r["envelope_type"] == "chat" and r["ciphertext_b64"] for r in archived)
    assert {r["envelope_type"] for r in archived} >= {"handshake_init", "handshake_response", "chat"}
    reflected = MetaData()
    reflected.reflect(bind=db.get_database().engine)
    for table in reflected.sorted_tables:
        for row in rows(table):
            for value in row.values():
                assert message not in str(value), (table.name, row)
    # Also ensure persistence survives engine disposal.
    net.disconnect(server, alice)
    net.disconnect(server, bob)
    db.dispose_databases()
    assert len(rows(db.relayed_envelopes)) == len(archived)


def test_migration_cli_imports_unchanged_hashes_and_is_idempotent(tmp_path):
    from auth.password_hash import hash_password
    encoded = hash_password("original_password")
    source = tmp_path / "users.json"
    source.write_text(json.dumps({"legacy": {"password_hash": encoded, "public_key": "PUBLIC PEM"}}))
    events = tmp_path / "events.jsonl"
    record = {"ts": 123.5, "event": "failed_login", "username": "legacy", "from_addr": "127.0.0.1"}
    # Identical repeated lines represent two real events, preserved on import.
    events.write_text((json.dumps(record) + "\n") * 2)
    command = [sys.executable, "tools/migrate_json_to_db.py", "--users", str(source), "--events", str(events)]
    first = subprocess.run(command, capture_output=True, text=True, check=True)
    assert "users_imported=1" in first.stdout and "events_imported=2" in first.stdout
    second = subprocess.run(command, capture_output=True, text=True, check=True)
    assert "users_imported=0" in second.stdout and "events_imported=0" in second.stdout
    assert "users_skipped=1" in second.stdout and "events_skipped=2" in second.stdout
    assert user_store.verify_user("legacy", "original_password")
    assert rows(db.users)[0]["password_hash"] == encoded
    assert user_store.get_public_key("legacy") == "PUBLIC PEM"
    assert len(rows(db.security_events)) == 2
    assert json.loads(source.read_text())["legacy"]["password_hash"] == encoded


def test_migration_does_not_duplicate_live_dual_written_events(tmp_path):
    path = tmp_path / "events.jsonl"
    log_event("user_login", path=str(path), username="a")
    counts = migrate(tmp_path / "missing.json", path)
    assert counts["events_imported"] == 0 and counts["events_skipped"] == 1
    assert len(rows(db.security_events)) == 1


def test_migration_invalid_input_is_atomic(tmp_path):
    source = tmp_path / "users.json"
    source.write_text(json.dumps({"a": {"password_hash": "existing_encoded_hash"}}))
    events = tmp_path / "events.jsonl"
    events.write_text('{"event": "bad_missing_timestamp"}\n')
    with pytest.raises(ValueError):
        migrate(source, events)
    assert rows(db.users) == []


def test_event_metadata_written_to_database_and_jsonl(tmp_path):
    path = tmp_path / "events.jsonl"
    record = log_event("failed_login", path=str(path), username="a", from_addr="127.0.0.1", retry_after=2)
    event = rows(db.security_events)[0]
    assert event["event_type"] == "failed_login" and event["ts"] == record["ts"]
    assert event["username"] == "a" and event["peer_addr"] == "127.0.0.1"
    assert event["details"]["retry_after"] == 2
    assert json.loads(path.read_text()) == record


def test_relay_retention_flag_and_allowlist(monkeypatch):
    monkeypatch.setenv("SECURECHAT_ENVELOPE_MAX_ROWS", "2")
    for i in range(5):
        db.record_relay({"type": "chat", "to": "b", "ciphertext": "YWJj", "message": "DO_NOT_STORE"}, "a")
    archived = rows(db.relayed_envelopes)
    assert len(archived) == 2
    assert "DO_NOT_STORE" not in str(archived)
    assert [r["id"] for r in archived] == sorted(r["id"] for r in archived)
    monkeypatch.setenv("SECURECHAT_STORE_ENVELOPES", "0")
    db.record_relay({"type": "chat", "to": "b", "ciphertext": "YWJj"}, "a")
    assert len(rows(db.relayed_envelopes)) == 2
    monkeypatch.setenv("SECURECHAT_STORE_ENVELOPES", "1")
    db.record_relay({"type": "login", "password": "DO_NOT_STORE"}, "a")
    assert len(rows(db.relayed_envelopes)) == 2


def test_legacy_path_argument_selects_isolated_database(tmp_path):
    path = str(tmp_path / "legacy.json")
    assert user_store.register_user("legacy_path", "pw", path=path)
    assert user_store.verify_user("legacy_path", "pw", path=path)
    assert not user_store.user_exists("legacy_path")
    assert not Path(path).exists()
    assert Path(path).with_suffix(".db").exists()


def test_independent_guards_cannot_lose_concurrent_failures():
    from concurrent.futures import ThreadPoolExecutor
    guards = [LockoutGuard(threshold=5) for _ in range(5)]
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(lambda guard: guard.record_failure("concurrent"), guards))
    assert sum(result.newly_locked for result in results) == 1
    assert LockoutGuard().status("concurrent").locked


def test_concurrent_registration_has_one_winner():
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _: user_store.register_user("race", "pw"), range(4)))
    assert results.count(True) == 1
    assert len(rows(db.users)) == 1


def test_schema_version_is_checked():
    from sqlalchemy import update
    database = db.get_database()
    with database.transaction() as conn:
        conn.execute(update(db.schema_version).values(version=999))
    db.dispose_databases()
    with pytest.raises(RuntimeError, match="Unsupported database schema version"):
        db.get_database()


def test_postgresql_driver_and_schema_compile_without_sqlite_specific_sql():
    from sqlalchemy import create_engine
    from sqlalchemy.schema import CreateTable
    engine = create_engine("postgresql+psycopg://user:password@localhost/test")
    try:
        assert engine.dialect.driver == "psycopg"
        for table in db.metadata.sorted_tables:
            assert str(CreateTable(table).compile(dialect=engine.dialect))
    finally:
        engine.dispose()
