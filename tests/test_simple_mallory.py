"""Simple Mallory: DROP / TAMPER / REPLAY on the lab relay, judged by genuine unmodified clients."""

import subprocess
import time
from pathlib import Path

import _demo_common as dc
import pytest
from fastapi.testclient import TestClient

from attack_lab.relay import lab_database
from attack_lab.simple.app import create_app
from attack_lab.simple.core import SimpleRelay
from server.lockout import LockoutGuard

ROOT = Path(__file__).parents[1]


def wait(predicate, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture()
def scene(net, tmp_path):
    database = lab_database("sqlite:///" + str(tmp_path / "simple_lab.db"))
    server, _, port = net.start_server(
        server_cls=SimpleRelay,
        database=database,
        lockout=LockoutGuard(database=database),
        logger=lambda *a, **k: None,
    )
    alice = net.register_client(port, "alice", "bob")
    bob = net.register_client(port, "bob", "alice")
    assert dc.establish_signed_handshake(alice, bob)
    seen = []
    bob.on_event = lambda kind, data: seen.append((kind, data))
    return server, alice, bob, seen


def got(seen, text):
    return any(k == "message_received" and d.get("message") == text for k, d in seen)


def reasons(seen):
    return [d.get("reason") for k, d in seen if k in ("message_rejected", "chain_warning")]


def test_untouched_messages_are_rows_with_short_ciphertext_and_arrive(scene):
    server, alice, bob, seen = scene
    alice.send_message("plain hello")
    assert wait(lambda: got(seen, "plain hello"))
    (row,) = server.state()["rows"]
    assert (row["from"], row["to"], row["status"]) == ("alice", "bob", "delivered")
    assert len(row["ct"]) <= 27 and "plain hello" not in str(server.state())
    assert not reasons(seen)


def test_drop_is_noticed_by_the_receivers_own_chain_check(scene):
    server, alice, bob, seen = scene
    alice.send_message("first")
    assert wait(lambda: got(seen, "first"))
    server.arm_simple("drop", "alice")
    assert server.state()["armed"] == {"alice": "drop"}
    alice.send_message("lost")
    assert wait(lambda: server.state()["rows"][-1]["status"] == "dropped")
    time.sleep(0.3)
    assert not got(seen, "lost") and not reasons(seen)
    assert server.state()["armed"] == {}  # one click, one message
    alice.send_message("next")
    assert wait(lambda: got(seen, "next"))
    assert "chain_gap" in reasons(seen)


def test_tamper_is_rejected_by_the_aes_gcm_tag(scene):
    server, alice, bob, seen = scene
    alice.send_message("first")
    assert wait(lambda: got(seen, "first"))
    server.arm_simple("tamper", "alice")
    alice.send_message("pay 500")
    assert wait(lambda: "decryption_failed" in reasons(seen))
    assert not got(seen, "pay 500")
    assert server.state()["rows"][-1]["status"] == "tampered"
    alice.send_message("after")
    assert wait(lambda: got(seen, "after"))  # session continues


def test_replay_delivers_once_and_the_duplicate_is_rejected(scene):
    server, alice, bob, seen = scene
    server.arm_simple("replay", "alice")
    alice.send_message("once")
    assert wait(lambda: "replay_duplicate" in reasons(seen))
    assert sum(1 for k, d in seen if k == "message_received" and d.get("message") == "once") == 1
    assert server.state()["rows"][-1]["status"] == "replayed"


def test_feed_never_claims_a_result_the_clients_did_not_report(scene):
    server, alice, bob, seen = scene
    alice.send_message("first")
    assert wait(lambda: got(seen, "first"))
    server.arm_simple("tamper", "alice")
    texts = [f["text"] for f in server.state()["feed"]]
    assert any("TAMPER armed" in t for t in texts)
    assert not any("own client" in t for t in texts)  # nobody has reported anything yet
    alice.send_message("x")
    assert wait(lambda: "decryption_failed" in reasons(seen))
    assert wait(
        lambda: any("own client: message was altered" in f["text"] for f in server.state()["feed"])
    )


def test_reset_and_arm_validation_and_control_page_guards(scene):
    server, alice, bob, seen = scene
    alice.send_message("a")
    assert wait(lambda: got(seen, "a"))
    server.arm_simple("drop", "alice")
    server.reset_view()
    state = server.state()
    assert state["rows"] == [] and state["armed"] == {} and state["feed"] == []
    with pytest.raises(ValueError):
        server.arm_simple("explode", "alice")
    api = TestClient(create_app(server, 8095), base_url="http://localhost:8095")
    ok = {"origin": "http://localhost:8095"}
    assert api.get("/").status_code == 200
    assert api.get("/api/state", headers={"host": "evil.example"}).status_code == 403
    assert api.post("/api/reset", headers={"origin": "http://evil.example"}).status_code == 403
    assert (
        api.post("/api/arm", json={"action": "nope", "sender": "alice"}, headers=ok).status_code
        == 400
    )
    assert (
        api.post("/api/arm", json={"action": "drop", "sender": "alice"}, headers=ok).status_code
        == 200
    )


def test_mallory_page_has_only_three_buttons_per_row_and_a_reset():
    page = (ROOT / "attack_lab/simple/static/index.html").read_text()
    assert page.count('id="reset"') == 1
    for name in ("drop", "tamper", "replay"):
        assert f'b("{name}")' in page
    for banned in ("Intercept", "hex", "pcap", "Wireshark", "Delay", "TLS record"):
        assert banned not in page


def test_launcher_has_mallory_mode_with_lan_and_stop_covers_it():
    helptext = subprocess.run(
        ["bash", "demo/start_demo.sh", "--help"], cwd=ROOT, capture_output=True, text=True
    ).stdout
    assert "--mallory" in helptext
    clash = subprocess.run(
        ["bash", "demo/start_demo.sh", "--mallory", "--desktop"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert clash.returncode == 2 and "own demo" in clash.stderr
    lib = (ROOT / "demo/_demo_lib.sh").read_text()
    assert "attack_lab\\.(netproxy|simple)" in lib
    for script in ("demo/start_demo.sh", "demo/_demo_lib.sh"):
        assert subprocess.run(["bash", "-n", script], cwd=ROOT).returncode == 0
