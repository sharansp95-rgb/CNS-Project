"""Authenticated WebSocket keepalive: keeps logged-in sessions, never anonymous ones."""

import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from server.relay_core import RelayCore
from web.app import create_app

ORIGIN = "http://localhost:8080"


def make(idle):
    return TestClient(create_app(RelayCore(logger=lambda *a, **kw: None), idle_timeout=idle))


def login(ws, name="alice"):
    ws.send_json(dict(type="register", username=name, password="password"))
    seen = []
    while True:
        m = ws.receive_json()
        seen.append(m)
        if m["type"] == "session_policy":
            return seen


def test_login_announces_the_idle_policy():
    with make(7) as client, client.websocket_connect("/ws", headers={"origin": ORIGIN}) as ws:
        seen = login(ws)
        assert seen[-1] == {"type": "session_policy", "idle_seconds": 7.0}


def test_pings_keep_an_authenticated_session_past_the_idle_limit():
    with make(1.0) as client, client.websocket_connect("/ws", headers={"origin": ORIGIN}) as ws:
        login(ws)
        for _ in range(6):  # 6 x 0.4 s = 2.4 s, far beyond the 1 s idle limit
            time.sleep(0.4)
            ws.send_json({"type": "ping"})
            assert ws.receive_json() == {"type": "pong"}


def test_an_authenticated_session_without_pings_still_times_out():
    with make(0.6) as client, client.websocket_connect("/ws", headers={"origin": ORIGIN}) as ws:
        login(ws)
        time.sleep(1.2)
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
        assert closed.value.code == 1001


def test_unauthenticated_ping_is_refused_and_does_not_keep_the_socket_open():
    with make(5) as client, client.websocket_connect("/ws", headers={"origin": ORIGIN}) as ws:
        ws.send_json({"type": "ping"})
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
        assert closed.value.code == 1008


def test_unauthenticated_idle_socket_still_times_out():
    with make(0.5) as client, client.websocket_connect("/ws", headers={"origin": ORIGIN}) as ws:
        time.sleep(1.0)
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
        assert closed.value.code == 1001
