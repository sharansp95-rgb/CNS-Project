"""TURN credential endpoint: authz, expiry cap, rate limit, secret never exposed or logged."""

import json
import logging

import httpx
import pytest
from fastapi.testclient import TestClient

from server.relay_core import RelayCore
from web.app import create_app

ORIGIN = "http://localhost:8080"
SECRET = "SECRET-KEY-VALUE-do-not-leak-0123456789"


def authed(ws, name):
    ws.send_json(dict(type="register", username=name, password="password"))
    result = ws.receive_json()
    assert result["success"]
    return {"Authorization": "Bearer " + result["api_token"]}


class Metered:
    """A fake Metered API that records what it was asked."""

    def __init__(self, fail=None):
        self.requests, self.fail = [], fail

    def handler(self, request):
        self.requests.append(request)
        if self.fail == "exception":
            raise httpx.ConnectError("boom " + str(request.url))
        if self.fail:
            return httpx.Response(self.fail, json={"error": "quota"})
        if request.method == "POST":
            return httpx.Response(
                200,
                json={
                    "username": "u-temp",
                    "password": "p-temp",
                    "apiKey": "key-for-this-credential",
                },
            )
        return httpx.Response(
            200,
            json=[
                {"urls": "stun:stun.relay.metered.ca:80"},
                {
                    "urls": "turn:global.relay.metered.ca:443",
                    "username": "u-temp",
                    "credential": "p-temp",
                },
            ],
        )

    def factory(self):
        return httpx.Client(transport=httpx.MockTransport(self.handler))


def make(monkeypatch, metered=None, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    app = create_app(
        RelayCore(logger=lambda *a, **kw: None),
        call_client_factory=metered.factory if metered else None,
    )
    return TestClient(app)


def test_requires_login(monkeypatch):
    with make(monkeypatch) as client:
        assert client.get("/api/calls/ice").status_code == 401


def test_stun_only_when_turn_is_not_configured(monkeypatch):
    monkeypatch.setenv("CALL_STUN_URLS", "stun:stun.example:3478")
    with (
        make(monkeypatch) as client,
        client.websocket_connect("/ws", headers={"origin": ORIGIN}) as ws,
    ):
        r = client.get("/api/calls/ice", headers=authed(ws, "alice"))
        assert r.status_code == 200
        assert r.json() == {
            "iceServers": [{"urls": "stun:stun.example:3478"}],
            "turn": "not_configured",
        }


def test_no_stun_configured_gives_host_only(monkeypatch):
    with (
        make(monkeypatch, CALL_STUN_URLS="") as client,
        client.websocket_connect("/ws", headers={"origin": ORIGIN}) as ws,
    ):
        assert client.get("/api/calls/ice", headers=authed(ws, "alice")).json()["iceServers"] == []


def test_short_lived_credentials_secret_never_returned(monkeypatch):
    metered = Metered()
    with (
        make(
            monkeypatch,
            metered,
            METERED_APP="team15-test",
            METERED_SECRET_KEY=SECRET,
            CALL_TURN_TTL_SECONDS="999999",
        ) as client,
        client.websocket_connect("/ws", headers={"origin": ORIGIN}) as ws,
    ):
        r = client.get("/api/calls/ice", headers=authed(ws, "alice"))
        body = r.json()
        assert body["turn"] == "available"
        turn = [s for s in body["iceServers"] if str(s["urls"]).startswith("turn")]
        assert turn and turn[0]["username"] == "u-temp" and turn[0]["credential"] == "p-temp"
        assert SECRET not in r.text and SECRET not in json.dumps(dict(r.headers))
        post = next(x for x in metered.requests if x.method == "POST")
        assert post.url.host == "team15-test.metered.live"
        sent = json.loads(post.content)
        assert 0 < sent["expiryInSeconds"] <= 600  # capped even though the env asked for 999999
        assert "alice" not in post.content.decode()  # no user identity goes to the provider
        assert sent["label"].startswith("call-")
        # The secret goes only to the credential-creation call; the list call uses the per-credential key.
        listing = next(x for x in metered.requests if x.method == "GET")
        assert SECRET not in str(listing.url)


@pytest.mark.parametrize("fail", [500, 402, 429, "exception"])
def test_provider_failure_degrades_to_direct_only_and_leaks_nothing(monkeypatch, caplog, fail):
    caplog.set_level(logging.DEBUG)
    metered = Metered(fail)
    with (
        make(monkeypatch, metered, METERED_APP="team15-test", METERED_SECRET_KEY=SECRET) as client,
        client.websocket_connect("/ws", headers={"origin": ORIGIN}) as ws,
    ):
        r = client.get("/api/calls/ice", headers=authed(ws, "alice"))
        assert r.status_code == 200 and r.json()["turn"] == "unavailable"
        assert all(not str(s["urls"]).startswith("turn") for s in r.json()["iceServers"])
        assert SECRET not in r.text
    assert SECRET not in caplog.text
    assert "secretKey" not in caplog.text


def test_rate_limit_is_per_user(monkeypatch):
    with (
        make(monkeypatch, CALL_ICE_PER_MINUTE="3") as client,
        client.websocket_connect("/ws", headers={"origin": ORIGIN}) as a,
        client.websocket_connect("/ws", headers={"origin": ORIGIN}) as b,
    ):
        ha, hb = authed(a, "alice"), authed(b, "bob")
        codes = [client.get("/api/calls/ice", headers=ha).status_code for _ in range(5)]
        assert codes == [200, 200, 200, 429, 429]
        assert client.get("/api/calls/ice", headers=hb).status_code == 200


def test_rejects_a_malformed_provider_app_name(monkeypatch):
    with pytest.raises(ValueError, match="METERED_APP"):
        make(monkeypatch, METERED_APP="evil.example/x?", METERED_SECRET_KEY=SECRET)


def test_permissions_policy_allows_microphone_for_self_only(monkeypatch):
    with make(monkeypatch) as client:
        policy = client.get("/healthz").headers["permissions-policy"]
        assert "microphone=(self)" in policy and "camera=()" in policy
