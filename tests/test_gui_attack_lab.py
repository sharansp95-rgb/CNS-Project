"""The Attack Lab panel: one card per attack, with the expected defence, and a live result
that comes from the VICTIM's own report of a real detection (read from the security log).

Presentation only: nothing here fires or detects an attack. The relay attacks are armed by
the server (see tests/test_attack_lab.py) and caught by the receiving client's real checks;
the card only displays a `security_alert` record that client sent. Skipped where Tk has no
display."""

import json
import threading
import time
import tkinter as tk

import pytest

import gui.chat_gui as chat_gui
from attack_lab.presentation import (
    HANDSHAKE_SIGNATURE,
    LAB_ATTACKS,
    REJECTIONS,
    find_lab_detection,
    lab_status,
)
from gui.theme import is_no_display_error

# ---- pure logic -----------------------------------------------------------------------


def test_three_attacks_in_demo_order_each_with_an_expected_defence():
    assert [a["action"] for a in LAB_ATTACKS] == [
        "tamper_next",
        "replay_last",
        "drop_next",
    ]
    for a in LAB_ATTACKS:
        assert a["glyph"] and a["desc"] and a["check"] and a["label"] and a["title"]
    checks = {a["action"]: a["check"] for a in LAB_ATTACKS}
    assert checks["tamper_next"] == REJECTIONS["decryption_failed"]["check"]
    assert checks["replay_last"] == REJECTIONS["replay_duplicate"]["check"]
    assert checks["drop_next"] == REJECTIONS["chain_gap"]["check"]


def alert(**kw):
    base = {
        "event": "security_alert",
        "reported_by": "bob",
        "ts": 1000.0,
        "alert": "message_rejected",
        "reason": "decryption_failed",
    }
    return {**base, **kw}


@pytest.mark.parametrize(
    "action,event",
    [
        ("tamper_next", alert()),
        ("replay_last", alert(reason="replay_duplicate")),
        ("drop_next", alert(alert="chain_warning", reason="chain_gap")),
    ],
)
def test_detection_matches_the_victims_own_report(action, event):
    assert find_lab_detection(action, [event], "bob", 999.0) == event


@pytest.mark.parametrize(
    "event",
    [
        alert(reported_by="alice"),  # the attacker's own report is not the victim's
        alert(ts=900.0),  # before the attack fired
        alert(reason="replay_duplicate"),  # a different check fired
        alert(alert="chain_warning"),  # a different kind of alert
        {"event": "lab_attack_performed", "ts": 1000.0},  # not a detection at all
    ],
)
def test_unrelated_records_are_not_detections(event):
    assert find_lab_detection("tamper_next", [event], "bob", 999.0) is None


def test_status_wording_for_every_state():
    assert lab_status("idle", "tamper_next", "bob") == ("off", "Not armed")
    assert lab_status("arming", "tamper_next", "bob")[0] == "warn"
    assert "send a message" in lab_status("armed", "tamper_next", "bob")[1]
    assert lab_status("fired", "tamper_next", "bob") == (
        "warn",
        "Fired. Waiting for bob's check...",
    )
    assert lab_status("caught", "tamper_next", "bob") == (
        "ok",
        "Caught by AES-256-GCM authentication tag (reported by bob)",
    )
    kind, text = lab_status("silent", "tamper_next", "bob")
    assert (
        kind == "warn"
        and "No report from bob yet" in text
        and "Watch bob's window" in text
    )
    assert lab_status("rejected", "tamper_next", "bob", "lab mode is off") == (
        "bad",
        "Rejected: lab mode is off",
    )


from fastapi.testclient import TestClient
from sqlalchemy import select
from attack_lab.app import create_app, ACCOUNTS
from attack_lab.relay import lab_database
from server.db import users, get_database
from web.app import create_app as product_app

ORIGIN = "http://localhost:8090"


@pytest.fixture()
def site(tmp_path):
    app = create_app(
        database_url="sqlite:///" + str(tmp_path / "lab.db"),
        state_dir=tmp_path / "state",
        origins=[ORIGIN],
    )
    with TestClient(app) as client:
        yield client, app


def start(client):
    result = client.post("/lab/session", json={}, headers={"origin": ORIGIN})
    assert result.status_code == 200
    return result.json()


def test_site_has_persistent_banner_and_separate_control_entry(site):
    client, app = site
    html = client.get("/").text
    assert "ATTACK LAB — sandbox, not the real service" in html
    assert html.count("<iframe") == 2
    assert "/victim" in html
    assert client.get("/victim").status_code == 200


def test_victim_html_and_bundle_are_identical_to_product(site):
    from web.app import STATIC
    import re

    client, _ = site
    assert client.get("/victim").content == (STATIC / "index.html").read_bytes()
    script = re.search(r'src="(/assets/[^"]+\.js)"', client.get("/victim").text).group(
        1
    )
    assert (
        client.get(script).content == (STATIC / script.removeprefix("/")).read_bytes()
    )


def test_controls_need_session_and_separate_origin(site):
    client, _ = site
    assert (
        client.post(
            "/lab/arm",
            json={"action": "drop_next", "target": "lab_alice"},
            headers={"origin": ORIGIN},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/lab/session", json={}, headers={"origin": "http://localhost:8080"}
        ).status_code
        == 403
    )
    start(client)
    assert (
        client.post(
            "/lab/arm",
            json={"action": "drop_next", "target": "real_user"},
            headers={"origin": ORIGIN},
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/lab/arm",
            json={"action": "unknown", "target": "lab_alice"},
            headers={"origin": ORIGIN},
        ).status_code
        == 400
    )

    assert (
        client.post(
            "/lab/arm",
            json={"action": [], "target": "lab_alice"},
            headers={"origin": ORIGIN},
        ).status_code
        == 400
    )


def test_reset_wipes_only_lab_db_and_reseeds_accounts(site):
    from server.user_store import register_user

    client, app = site
    start(client)
    assert register_user("real_marker", "pw")
    client.post(
        "/lab/arm",
        json={"action": "drop_next", "target": "lab_alice"},
        headers={"origin": ORIGIN},
    )
    reset = client.post("/lab/reset", json={}, headers={"origin": ORIGIN})
    assert reset.status_code == 200 and reset.json()["accounts"] == list(ACCOUNTS)
    assert app.state.relay.pending == {} and app.state.relay.events == []
    with app.state.database.engine.connect() as conn:
        assert set(conn.execute(select(users.c.username)).scalars()) == {
            "lab_alice",
            "lab_bob",
            "lab_lockout",
        }
    with get_database().engine.connect() as conn:
        assert conn.execute(
            select(users.c.username).where(users.c.username == "real_marker")
        ).first()


def test_real_bruteforce_locks_sandbox_account_and_skips_pbkdf2(site):
    from unittest.mock import patch

    client, app = site
    start(client)
    response = client.post("/lab/brute-force", json={}, headers={"origin": ORIGIN})
    assert response.status_code == 200 and response.json()["locked"]
    replies = response.json()["results"]
    assert replies[0]["reason"] == "invalid username or password"
    assert replies[-2]["reason"] == "invalid username or password"
    assert "locked" in replies[-1]["reason"]
    assert any(e["event"] == "lockout_rejected" for e in app.state.relay.events)
    with patch("server.user_store.verify_password") as verify:
        assert app.state.relay.lockout.status("lab_lockout").locked

        class Peer:
            def send_envelope(self, e):
                pass

        app.state.relay.authenticate(
            Peer(),
            ("127.0.0.1", 0),
            {"type": "login", "username": "lab_lockout", "password": "wrong"},
        )
        verify.assert_not_called()


def test_control_rate_limit_and_polling_are_separate(site):
    client, _ = site
    start(client)
    for _ in range(35):
        assert client.get("/lab/state").status_code == 200
    codes = [
        client.post(
            "/lab/arm",
            json={"action": "drop_next", "target": "lab_alice"},
            headers={"origin": ORIGIN},
        ).status_code
        for _ in range(31)
    ]
    assert codes[:30] == [200] * 30 and codes[30] == 429


def test_production_has_no_lab_routes_or_controls():
    with TestClient(product_app()) as client:
        for path in (
            "/lab/session",
            "/lab/arm",
            "/lab/state",
            "/lab/reset",
            "/lab/brute-force",
        ):
            assert client.get(path).status_code == 404


def test_same_real_database_and_origin_are_refused(tmp_path, monkeypatch):
    real = tmp_path / "real.db"
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + str(real))
    with pytest.raises(ValueError, match="separate database"):
        lab_database("sqlite:///" + str(real))
    with pytest.raises(ValueError, match="different from"):
        create_app(
            database_url="sqlite:///" + str(tmp_path / "lab.db"),
            origins=["http://localhost:8080"],
            state_dir=tmp_path / "state",
        )


def test_product_gui_has_no_attack_panel():
    assert not hasattr(chat_gui.ChatGUI, "_open_attack_lab")
