"""Separate hostile relay, genuine clients, one-shot semantics and product separation."""

import json
import subprocess
import sys
import time

import _demo_common as dc
import pytest

from attack_lab.relay import RogueRelay, lab_database
from server.lockout import LockoutGuard
from server.security_log import log_event, read_events


def wait(predicate, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return
        time.sleep(0.01)
    assert predicate(), "Expected real client detection did not arrive"


@pytest.fixture()
def rogue(net, tmp_path, security_log_path):
    database = lab_database("sqlite:///" + str(tmp_path / "separate_lab.db"))

    def logger(event, **fields):
        return log_event(event, path=security_log_path, database=database, **fields)

    server, _, port = net.start_server(
        server_cls=RogueRelay,
        database=database,
        lockout=LockoutGuard(database=database),
        logger=logger,
    )
    return server, port


def pair(net, rogue):
    server, port = rogue
    a = net.register_client(port, "alice", "bob")
    b = net.register_client(port, "bob", "alice")
    assert dc.establish_signed_handshake(a, b)
    events = []
    b.on_event = lambda kind, data: events.append((kind, data))
    return server, a, b, events


@pytest.mark.parametrize(
    "action,reason",
    [
        ("tamper_next", "decryption_failed"),
        ("drop_next", "chain_gap"),
        ("reorder_next", "chain_broken"),
        ("inject_next", "decryption_failed"),
    ],
)
def test_attacks_are_caught_by_real_unmodified_clients(net, rogue, action, reason):
    server, a, b, events = pair(net, rogue)
    server.arm(action, "alice")
    a.send_message("first confidential message")
    if action in ("drop_next", "reorder_next"):
        a.send_message("second confidential message")
    wait(lambda: any(d.get("reason") == reason for _, d in events))
    assert "alice" not in server.pending
    if action in ("tamper_next", "drop_next"):
        assert not any(r["message"] == "first confidential message" for r in b.transcript)
    if action == "inject_next":
        assert all(r["message"] == "first confidential message" for r in b.transcript)
    if action == "reorder_next":
        assert [r["message"] for r in b.transcript] == ["second confidential message"]
    a.send_message("third, unmodified")
    wait(lambda: any(r["message"] == "third, unmodified" for r in b.transcript))


def test_replay_rejected_and_only_displayed_once(net, rogue):
    server, a, b, events = pair(net, rogue)
    a.send_message("captured")
    wait(lambda: any(r["message"] == "captured" for r in b.transcript))
    server.arm("replay_last", "alice")
    wait(lambda: any(d.get("reason") == "replay_duplicate" for _, d in events))
    assert sum(r["message"] == "captured" for r in b.transcript) == 1


def test_mitm_stops_key_derivation(net, rogue):
    server, port = rogue
    a = net.register_client(port, "alice", "bob")
    server.arm("mitm_next_handshake", "alice")
    events = []
    b = net.register_client(port, "bob", "alice", event_callback=lambda k, d: events.append((k, d)))
    wait(lambda: any(k == "handshake_aborted" for k, _ in events))
    assert b.session_key is None and a.session_key is None
    assert "alice" not in server.pending


def test_one_shot_tamper_does_not_mutate_sender_envelope(rogue):
    server, _ = rogue
    envelope = dict(
        type="chat",
        **{"from": "alice", "to": "bob"},
        nonce="bg==",
        ciphertext="Y2lwaGVy",
        tag="dA==",
    )
    original = dict(envelope)
    server.arm("tamper_next", "alice")
    first = server.intercept(envelope, "alice")
    second = server.intercept(envelope, "alice")
    assert first[0]["ciphertext"] != envelope["ciphertext"]
    assert second == [original] and envelope == original
    assert len([e for e in server.events if e["event"] == "lab_attack_performed"]) == 1


def test_drop_is_silent_and_disarms(rogue):
    server, _ = rogue
    server.arm("drop_next", "alice")
    envelope = dict(type="chat", ciphertext="YQ==", to="bob")
    assert server.intercept(envelope, "alice") == []
    assert server.intercept(envelope, "alice") == [envelope]
    assert not server.pending


def test_no_replay_before_capture_and_unknown_actions_rejected(rogue):
    server, _ = rogue
    with pytest.raises(ValueError, match="No captured"):
        server.arm("replay_last", "alice")
    with pytest.raises(ValueError, match="Unknown"):
        server.arm("format_disk", "alice")
    assert server.pending == {}


def test_nonlocal_legacy_tcp_control_is_rejected(rogue):
    server, _ = rogue

    class Conn:
        def sendall(self, data):
            self.result = json.loads(data)

    conn = Conn()
    server.handle_authenticated(
        conn, ("203.0.113.5", 1), "alice", dict(type="lab_control", action="drop_next")
    )
    assert not conn.result["armed"] and not server.pending
    assert server.events[-1]["event"] == "lab_control_rejected"


def test_production_control_is_unknown_and_logged(net, security_log_path):
    server, _, port = net.start_server()
    c = net.register_client(port, "real_user", "nobody")
    events = []
    c.on_event = lambda k, d: events.append((k, d))
    c.send_envelope(dict(type="lab_control", action="tamper_next"))
    wait(
        lambda: any(
            e.get("event") == "unsupported_envelope" for e in read_events(security_log_path)
        )
    )
    event = [e for e in read_events(security_log_path) if e["event"] == "unsupported_envelope"][-1]
    assert event["envelope_type"] == "lab_control"
    wait(
        lambda: any(
            k == "envelope_received" and d.get("envelope", {}).get("type") == "error"
            for k, d in events
        )
    )
    errors = [
        d["envelope"]
        for k, d in events
        if k == "envelope_received" and d.get("envelope", {}).get("type") == "error"
    ]
    assert errors[-1]["reason"] == "unknown envelope type"
    assert not hasattr(server, "arm") and not hasattr(server, "_apply_lab_tamper_or_drop")
    assert server.interceptor is None


def test_product_imports_never_import_attack_lab():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            'import sys,web,server.server; assert not any(n=="attack_lab" or n.startswith("attack_lab.") for n in sys.modules)',
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_production_flag_is_removed():
    result = subprocess.run(
        [sys.executable, "server/server.py", "--lab"], capture_output=True, text=True
    )
    assert result.returncode != 0 and "unrecognized arguments: --lab" in result.stderr


def test_raw_tls_failure_uses_only_the_supplied_lab_logger(rogue):
    import ssl
    from unittest.mock import Mock, patch

    server, _ = rogue
    raw = Mock()
    with patch.object(server.ssl_context, "wrap_socket", side_effect=ssl.SSLError("invalid TLS")):
        with patch(
            "server.server.log_event",
            side_effect=AssertionError("default service logger used"),
        ):
            server._handle_raw_connection(raw, ("127.0.0.1", 12345))
    raw.close.assert_called_once()
    assert server.events[-1]["event"] == "non_tls_connection"
