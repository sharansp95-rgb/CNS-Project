"""Fail-closed deployment policy, proxy trust, persistent receipt keys and sandbox gate."""

import base64
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from server import db
from server.relay_core import RelayCore
from server.timestamp import TimestampSigner
from tools.postgres_test_support import disposable_test_url
from web.app import create_app
from web.settings import Settings


def production_env(monkeypatch, origin="https://chat.example"):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("ALLOWED_ORIGINS", origin)
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "10.2.0.0/16,127.0.0.1")
    key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    monkeypatch.setenv("TSA_PRIVATE_KEY", base64.b64encode(key).decode())
    return key


def main_app(monkeypatch):
    core = RelayCore(logger=lambda *a, **kw: None)
    production_env(monkeypatch)
    monkeypatch.setenv(
        "DATABASE_URL", "postgres://placeholder:placeholder@db.invalid/main"
    )
    return create_app(core)


@pytest.mark.parametrize(
    "key,value",
    [
        ("ALLOWED_ORIGINS", ""),
        ("ALLOWED_ORIGINS", "http://chat.example"),
        ("FORWARDED_ALLOW_IPS", ""),
        ("FORWARDED_ALLOW_IPS", "*"),
        ("FORWARDED_ALLOW_IPS", "0.0.0.0/0"),
    ],
)
def test_production_configuration_refuses_unsafe_defaults(monkeypatch, key, value):
    production_env(monkeypatch)
    monkeypatch.setenv(key, value)
    with pytest.raises(ValueError):
        Settings.load()


def test_production_missing_tsa_never_generates_a_file(monkeypatch, tmp_path):
    production_env(monkeypatch)
    monkeypatch.delenv("TSA_PRIVATE_KEY")
    target = tmp_path / "never-created.key"
    monkeypatch.setenv("TSA_KEY_PATH", str(target))
    with patch(
        "server.timestamp.generate", side_effect=AssertionError("disk key generation")
    ):
        with pytest.raises(ValueError, match="TSA_PRIVATE_KEY"):
            TimestampSigner()
    assert not target.exists()


def test_production_main_refuses_sqlite_and_missing_key_before_db_connect(monkeypatch):
    production_env(monkeypatch)
    with pytest.raises(ValueError, match="PostgreSQL"):
        create_app()
    monkeypatch.setenv(
        "DATABASE_URL", "postgres://placeholder:placeholder@db.invalid/main"
    )
    monkeypatch.delenv("TSA_PRIVATE_KEY")
    with patch(
        "server.db.create_engine", side_effect=AssertionError("database accessed")
    ):
        with pytest.raises(ValueError, match="TSA_PRIVATE_KEY"):
            create_app()


def test_env_key_is_stable_across_signer_restarts_and_accepts_pem(monkeypatch):
    pem = production_env(monkeypatch)
    first = TimestampSigner()
    monkeypatch.setenv("TSA_PRIVATE_KEY", pem.decode())
    assert TimestampSigner().key_id == first.key_id
    with patch("server.timestamp.generate", side_effect=AssertionError()):
        TimestampSigner()


def test_https_headers_health_and_database_failure(monkeypatch):
    app = main_app(monkeypatch)
    with TestClient(app, base_url="https://chat.example") as client:
        response = client.get("/")
        assert response.status_code == 200
        assert response.headers["strict-transport-security"] == "max-age=31536000"
        assert "script-src 'self'" in response.headers["content-security-policy"]
        assert not app.debug
        assert client.get("/healthz").json() == {"status": "ok"}
        with patch.object(
            app.state.relay.database.engine,
            "connect",
            side_effect=RuntimeError("private diagnostic"),
        ):
            result = client.get("/healthz")
        assert result.status_code == 503 and "private diagnostic" not in result.text
    with TestClient(app, base_url="http://chat.example") as client:
        assert client.get("/").status_code == 403
        assert client.get("/healthz").status_code == 200
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                "ws://chat.example/ws", headers={"origin": "https://chat.example"}
            ):
                pass


@pytest.mark.parametrize("trusted", [True, False])
def test_forwarded_client_ip_only_from_explicit_trusted_proxy(monkeypatch, trusted):
    app = main_app(monkeypatch)
    address = "10.2.3.4" if trusted else "203.0.113.40"
    with TestClient(app, client=(address, 123)) as client:
        for ip, name in [("198.51.100.1", "one"), ("198.51.100.2", "two")]:
            with client.websocket_connect(
                "wss://chat.example/ws",
                headers={
                    "origin": "https://chat.example",
                    "x-forwarded-for": "192.0.2.99, " + ip,
                    "x-forwarded-proto": "https",
                },
            ) as ws:
                ws.send_json(dict(type="register", username=name, password="pw"))
                assert ws.receive_json()["success"]
    keys = set(app.state.relay.lockout._by_addr)
    assert keys == ({"198.51.100.1", "198.51.100.2"} if trusted else {address})


def test_untrusted_forwarded_https_cannot_bypass_wss_policy(monkeypatch):
    app = main_app(monkeypatch)
    with TestClient(app, client=("203.0.113.4", 123)) as client:
        assert (
            client.get("/", headers={"x-forwarded-proto": "https"}).status_code == 403
        )
    with TestClient(app, client=("10.2.3.4", 123)) as client:
        assert (
            client.get("/", headers={"x-forwarded-proto": "https"}).status_code == 200
        )


@pytest.mark.parametrize("scheme", ["postgres", "postgresql", "postgresql+psycopg"])
def test_neon_url_normalization_and_pool_settings(scheme):
    url = db.normalize_url(f"{scheme}://test:placeholder@db.invalid/test")
    assert url.drivername == "postgresql+psycopg" and url.query["sslmode"] == "require"
    from sqlalchemy import create_engine

    created = []

    def factory(*args, **kwargs):
        engine = create_engine(*args, **kwargs)
        created.append(engine)
        return engine

    with (
        patch("server.db.create_engine", side_effect=factory),
        patch.object(
            db.Database,
            "transaction",
            side_effect=RuntimeError("no external connection"),
        ),
    ):
        with pytest.raises(RuntimeError, match="no external connection"):
            db.Database(url)
    try:
        engine = created[0]
        assert (
            engine.pool.size() == 2
            and engine.pool._recycle == 240
            and engine.pool._pre_ping
        )
        assert engine.pool._max_overflow == 1
    finally:
        engine.dispose()
    with pytest.raises(ValueError, match="sslmode"):
        db.normalize_url(f"{scheme}://db.invalid/test?sslmode=disable")


@pytest.mark.parametrize(
    "test,real",
    [
        (
            "postgres://a:p@ep-main.neon.tech/app",
            "postgresql://a:p@ep-main.neon.tech/app",
        ),
        (
            "postgresql://b:other@ep-main.neon.tech/app",
            "postgresql://a:p@ep-main-pooler.neon.tech/app",
        ),
    ],
)
def test_postgres_test_guard_rejects_service_database_aliases(test, real, monkeypatch):
    with pytest.raises(ValueError, match="separate disposable"):
        disposable_test_url(test, real)
    with pytest.raises(ValueError, match="both"):
        disposable_test_url(test, None)
    from attack_lab.relay import lab_database

    monkeypatch.setenv("DATABASE_URL", real)
    with pytest.raises(ValueError, match="separate database"):
        lab_database(test)


def test_lab_access_gate_protects_assets_controls_and_websocket(monkeypatch, tmp_path):
    from attack_lab.app import create_app as lab_app

    production_env(monkeypatch, "https://lab.example")
    monkeypatch.delenv("DATABASE_URL")
    monkeypatch.setenv("MAIN_SITE_ORIGIN", "https://chat.example")
    code = "access-code-generated-for-tests-only"
    monkeypatch.setenv("LAB_ACCESS_CODE", code)
    app = lab_app(
        database_url="sqlite:///" + str(tmp_path / "lab.db"),
        state_dir=tmp_path / "state",
    )
    with TestClient(app, base_url="https://lab.example") as client:
        gate = client.get("/")
        assert "Lab access code" in gate.text and "noindex" in gate.text
        assert gate.headers["x-robots-tag"] == "noindex, nofollow"
        assert client.get("/victim").status_code == 401
        assert client.get("/healthz").status_code == 200
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                "wss://lab.example/ws", headers={"origin": "https://lab.example"}
            ):
                pass
        assert (
            client.post(
                "/lab/session",
                json={"access_code": "wrong"},
                headers={"origin": "https://lab.example"},
            ).status_code
            == 403
        )
        result = client.post(
            "/lab/session",
            json={"access_code": code},
            headers={"origin": "https://lab.example"},
        )
        assert result.status_code == 200
        cookie = result.headers["set-cookie"].lower()
        assert (
            "httponly" in cookie
            and "secure" in cookie
            and "samesite=strict" in cookie
            and "path=/" in cookie
        )
        assert "Try the attack" in client.get("/").text
        assert client.get("/victim").status_code == 200
        with client.websocket_connect(
            "wss://lab.example/ws", headers={"origin": "https://lab.example"}
        ) as ws:
            ws.send_json(dict(type="login", username="lab_alice", password="wrong"))
            assert not ws.receive_json()["success"]


def test_lab_code_rate_limit_and_missing_secret(monkeypatch, tmp_path):
    from attack_lab.app import create_app as lab_app

    production_env(monkeypatch, "https://lab.example")
    monkeypatch.setenv("MAIN_SITE_ORIGIN", "https://chat.example")
    monkeypatch.delenv("DATABASE_URL")
    monkeypatch.delenv("LAB_ACCESS_CODE", raising=False)
    with pytest.raises(ValueError, match="LAB_ACCESS_CODE"):
        lab_app()
    monkeypatch.setenv("LAB_ACCESS_CODE", "a-strong-test-only-access-code")
    app = lab_app(
        database_url="sqlite:///" + str(tmp_path / "lab.db"),
        state_dir=tmp_path / "state",
    )
    with TestClient(app, base_url="https://lab.example") as client:
        codes = [
            client.post(
                "/lab/session",
                json={"access_code": "wrong"},
                headers={"origin": "https://lab.example"},
            ).status_code
            for _ in range(11)
        ]
        assert codes[:10] == [403] * 10 and codes[-1] == 429
    monkeypatch.setenv("DATABASE_URL", "postgresql://x:y@db.invalid/main")
    with pytest.raises(ValueError, match="main DATABASE_URL"):
        lab_app()


def test_print_env_produces_a_key_without_writing_local_state(tmp_path):
    import subprocess, sys, os

    result = subprocess.run(
        [sys.executable, "tools/generate_tsa_key.py", "--print-env"],
        capture_output=True,
        text=True,
        env=dict(os.environ, TSA_KEY_PATH=str(tmp_path / "not-created.key")),
        check=True,
    )
    key = serialization.load_pem_private_key(
        base64.b64decode(result.stdout.strip(), validate=True), password=None
    )
    assert isinstance(key, Ed25519PrivateKey)
    assert not (tmp_path / "not-created.key").exists()
