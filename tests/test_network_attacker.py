"""Network attacker ("fake Wi-Fi") proxy: real clients, real TLS 1.3 server, real failures.

Nothing here is simulated: the victims talk TLS to the real ChatServer through
attack_lab.netproxy, which only forwards/alters/drops/replays/delays ciphertext records.
"""

import ast
import os
import shutil
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import _demo_common as dc
import pytest

from attack_lab.netproxy import records as tls
from attack_lab.netproxy.core import NetProxy, ProxyRunner
from attack_lab.netproxy.pcap import write_pcap

SECRET = "NETWORK-ATTACKER-SECRET-3f9a"


class Rig:
    def __init__(self, net):
        self.server, _, self.server_port = net.start_server()
        self.proxy = NetProxy(("127.0.0.1", 0), ("127.0.0.1", self.server_port), stall_seconds=0.6)
        self.runner = ProxyRunner(self.proxy)
        self.port = self.runner.start()
        self.events = {"alice": [], "bob": []}
        self.net = net

    def pair(self):
        """Alice and Bob connect THROUGH the proxy and complete the signed handshake."""
        self.alice = self.net.register_client(
            self.port,
            "net_alice",
            "net_bob",
            event_callback=lambda k, d: self.events["alice"].append((k, d)),
        )
        self.bob = self.net.register_client(
            self.port,
            "net_bob",
            "net_alice",
            event_callback=lambda k, d: self.events["bob"].append((k, d)),
        )
        assert dc.establish_signed_handshake(self.alice, self.bob)
        return self.alice, self.bob

    def wait(self, cond, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            if cond():
                return True
            time.sleep(0.02)
        return False

    def pending(self, direction=None):
        assert self.wait(
            lambda: any(
                r["status"] == "pending" and (direction is None or r["dir"] == direction)
                for r in self.proxy.snapshot()["records"]
            )
        )
        return [
            r
            for r in self.proxy.snapshot()["records"]
            if r["status"] == "pending" and (direction is None or r["dir"] == direction)
        ][-1]

    def received(self, who, text):
        return any(
            k == "message_received" and d.get("message") == text for k, d in self.events[who]
        )

    def disconnected(self, who):
        return [d for k, d in self.events[who] if k == "disconnected"]

    def feed(self):
        return " | ".join(f["text"] for f in self.proxy.snapshot()["feed"])

    def close(self):
        self.runner.stop()


@pytest.fixture()
def rig(net):
    r = Rig(net)
    yield r
    r.close()


def test_untouched_chat_works_through_the_proxy_and_is_all_ciphertext(rig):
    alice, bob = rig.pair()
    rig.proxy.set_intercept(True)
    alice.send_message(SECRET)
    rec = rig.pending("c2s")
    assert rec["kind"] == "Application Data" and rec["status"] == "pending"
    rig.proxy.decide(rec["id"], "forward")
    rig.proxy.decide(rig.pending("s2c")["id"], "forward")  # the relay's copy towards Bob
    assert rig.wait(lambda: rig.received("bob", SECRET)), "forwarded untouched = delivered"
    assert not rig.disconnected("alice") and not rig.disconnected("bob")
    # Everything Mallory captured: no plaintext, anywhere.
    raw = b"".join(r[4] for r in rig.proxy.raw_records())
    for needle in (
        SECRET,
        "net_alice",
        "net_bob",
        dc.DEMO_PASSWORD,
        '"type"',
        "password",
        "register",
    ):
        assert needle.encode() not in raw, needle
    snap = rig.proxy.snapshot()
    assert {r["dir"] for r in snap["records"]} == {"c2s", "s2c"}
    assert all(r["hex"] and r["size"] > 5 for r in snap["records"])


def test_alter_c2s_makes_the_real_server_reject_and_close(rig):
    alice, bob = rig.pair()
    rig.proxy.set_intercept(True)
    alice.send_message(SECRET)
    rig.proxy.decide(rig.pending("c2s")["id"], "alter")
    ok = rig.wait(lambda: rig.disconnected("alice"))
    assert ok, rig.feed() + str(rig.proxy.snapshot()["records"][-3:])
    time.sleep(0.2)
    assert not rig.received("bob", SECRET)
    assert rig.wait(lambda: "bad_record_mac" in rig.feed())
    assert "by the server" in rig.feed()


def test_alter_s2c_shows_the_real_ssl_error_in_the_victim(rig):
    alice, bob = rig.pair()
    rig.proxy.set_intercept(True)
    alice.send_message(SECRET)
    rig.proxy.decide(rig.pending("c2s")["id"], "forward")
    rig.proxy.decide(rig.pending("s2c")["id"], "alter")
    assert rig.wait(lambda: rig.disconnected("bob"))
    reason = rig.disconnected("bob")[0]["reason"]
    assert "SSLError" in reason and "record layer failure" in reason
    assert not rig.received("bob", SECRET)


def test_replay_is_rejected_by_real_tls_sequence_numbers(rig):
    alice, bob = rig.pair()
    rig.proxy.set_intercept(True)
    alice.send_message(SECRET)
    rig.proxy.decide(rig.pending("c2s")["id"], "replay")
    assert rig.wait(lambda: rig.disconnected("alice"))
    assert rig.wait(lambda: "REPLAY" in rig.feed() and "bad_record_mac" in rig.feed())


def test_replay_of_an_old_captured_record_breaks_the_connection(rig):
    alice, bob = rig.pair()
    alice.send_message("first")
    assert rig.wait(lambda: rig.received("bob", "first"))
    old = [r for r in rig.proxy.snapshot()["records"] if r["dir"] == "c2s" and r["app_phase"]][-1]
    rig.proxy.replay(old["id"])
    assert rig.wait(lambda: rig.disconnected("alice"))


def test_drop_loses_the_message_stalls_and_later_desyncs(rig):
    alice, bob = rig.pair()
    rig.proxy.set_intercept(True)
    alice.send_message(SECRET)
    rig.proxy.decide(rig.pending("c2s")["id"], "drop")
    rig.proxy.set_intercept(False)
    assert rig.wait(lambda: "STALLED" in rig.feed())
    assert not rig.received("bob", SECRET) and not rig.disconnected("alice")
    alice.send_message("after the gap")
    assert rig.wait(lambda: rig.disconnected("alice")), "sequence gap must break TLS"
    assert not rig.received("bob", "after the gap")


def test_delay_postpones_but_delivers(rig):
    alice, bob = rig.pair()
    rig.proxy.set_intercept(True)
    started = time.time()
    alice.send_message(SECRET)
    rig.proxy.decide(rig.pending("c2s")["id"], "delay", delay=1.0)
    rig.proxy.set_intercept(False)
    assert rig.wait(lambda: rig.received("bob", SECRET), 8)
    assert time.time() - started >= 1.0
    assert not rig.disconnected("alice")


def test_handshake_runs_untouched_while_intercept_is_on(rig):
    rig.proxy.set_intercept(True)
    result = {}

    def connect():
        result["a"] = rig.net.register_client(rig.port, "early_alice", "early_bob")

    t = threading.Thread(target=connect)
    t.start()
    # The register request itself (first application record after Finished) is held.
    assert rig.wait(lambda: rig.proxy.pending_ids())
    rig.proxy.set_intercept(False)
    t.join(20)
    assert "a" in result


def test_record_parser_and_flip():
    buf = bytearray(b"\x17\x03\x03\x00\x03abc\x17\x03\x03\x00\x02a")
    assert tls.take_record(buf) == b"\x17\x03\x03\x00\x03abc"
    assert tls.take_record(buf) is None and bytes(buf) == b"\x17\x03\x03\x00\x02a"
    assert tls.take_record(bytearray(b"GET / HTTP/1.1\r\n")) is False
    record = b"\x17\x03\x03\x00\x10" + bytes(range(16))
    changed = tls.flip_bytes(record)
    assert changed[:5] == record[:5] and sum(a != b for a, b in zip(record, changed)) == 1


def test_proxy_has_no_tls_and_listens_on_loopback_only():
    source = (Path(__file__).parents[1] / "attack_lab/netproxy/core.py").read_text()
    imported = {
        n.names[0].name.split(".")[0]
        for n in ast.walk(ast.parse(source))
        if isinstance(n, (ast.Import,))
    }
    assert "ssl" not in imported
    assert "load_cert_chain" not in source and "server.key" not in source
    with pytest.raises(ValueError):
        NetProxy(("0.0.0.0", 0), ("127.0.0.1", 1))


def test_pcap_export_is_a_valid_capture_of_the_captured_records(rig, tmp_path):
    alice, bob = rig.pair()
    alice.send_message(SECRET)
    assert rig.wait(lambda: rig.received("bob", SECRET))
    out = tmp_path / "mallory.pcap"
    count = write_pcap(rig.proxy.raw_records(), out, rig.port)
    data = out.read_bytes()
    assert struct.unpack("<I", data[:4])[0] == 0xA1B2C3D4 and count > 5
    assert SECRET.encode() not in data and b"net_alice" not in data


def test_mallory_window_api_drives_a_real_attack(rig):
    """Same path the browser page uses: HTTP control API of the window."""
    from fastapi.testclient import TestClient

    from attack_lab.netproxy.app import create_app

    client = TestClient(create_app(rig.proxy, 8095), base_url="http://localhost:8095")
    h = {"origin": "http://localhost:8095"}
    assert client.get("/").status_code == 200
    assert client.get("/api/state", headers={"host": "evil.example"}).status_code == 403
    assert (
        client.post(
            "/api/intercept", json={"on": True}, headers={"origin": "http://evil.example"}
        ).status_code
        == 403
    )
    alice, bob = rig.pair()
    assert client.post("/api/intercept", json={"on": True}, headers=h).json()["intercept"]
    alice.send_message(SECRET)
    rid = rig.pending("c2s")["id"]
    assert (
        client.post(f"/api/records/{rid}/action", json={"action": "bogus"}, headers=h).status_code
        == 400
    )
    assert (
        client.post(f"/api/records/{rid}/action", json={"action": "alter"}, headers=h).status_code
        == 200
    )
    assert rig.wait(lambda: rig.disconnected("alice"))
    state = client.get("/api/state").json()
    assert "TLS stops a network attacker" in state["lesson"]
    assert any(f["level"] == "result" for f in state["feed"])
    pcap = client.get("/api/capture.pcap")
    assert pcap.status_code == 200 and SECRET.encode() not in pcap.content


@pytest.fixture()
def https_gateway(monkeypatch, _test_certs):
    """The real web gateway served over HTTPS/WSS (uvicorn + the project's certificate)."""
    import json as _json
    import socket

    import uvicorn

    from attack_lab.netproxy.core import NetProxy, ProxyRunner
    from server.relay_core import RelayCore
    from web.app import create_app

    cert, key = _test_certs
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        gw_port = s.getsockname()[1]
    proxy = NetProxy(("127.0.0.1", 0), ("127.0.0.1", gw_port), stall_seconds=0.6)
    runner = ProxyRunner(proxy)
    port = runner.start()
    origin = f"https://localhost:{port}"
    monkeypatch.setenv("SECURECHAT_ALLOWED_ORIGINS", origin)
    import server.server as sm

    app = create_app(RelayCore(logger=lambda *a, **kw: sm.log_event(*a, **kw)))
    srv = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=gw_port,
            ssl_certfile=cert,
            ssl_keyfile=key,
            log_level="error",
            lifespan="on",
        )
    )
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    end = time.time() + 15
    while not srv.started and time.time() < end:
        time.sleep(0.05)
    assert srv.started
    yield proxy, port, origin, cert, _json
    srv.should_exit = True
    thread.join(10)
    runner.stop()


def test_browser_path_https_and_wss_through_the_proxy(https_gateway):
    """Browsers use the same TLS: HTTPS + WSS pass through, alteration kills the socket."""
    import ssl

    import httpx
    from websockets.sync.client import connect

    proxy, port, origin, cert, json = https_gateway
    ctx = ssl.create_default_context(cafile=cert)
    assert httpx.get(origin + "/", verify=ctx, timeout=10).status_code == 200
    with connect(f"wss://localhost:{port}/ws", ssl=ctx, origin=origin, open_timeout=10) as ws:
        ws.send(
            json.dumps({"type": "register", "username": "wss_user", "password": "password-1234!"})
        )
        assert json.loads(ws.recv(timeout=20))["success"]
        raw = b"".join(r[4] for r in proxy.raw_records())
        assert b"wss_user" not in raw and b"password-1234" not in raw and b"register" not in raw
        proxy.set_intercept(True)
        ws.send(json.dumps({"type": "ping"}))
        end = time.time() + 10
        while not proxy.pending_ids() and time.time() < end:
            time.sleep(0.02)
        proxy.decide(proxy.pending_ids()[0], "alter")
        from websockets.exceptions import ConnectionClosed

        with pytest.raises((ConnectionClosed, OSError)):
            for _ in range(20):
                ws.recv(timeout=5)


@pytest.mark.skipif(shutil.which("lsof") is None, reason="needs lsof")
def test_victim_process_is_named_from_its_environment(rig):
    from attack_lab.netproxy.core import identify_label

    code = (
        "import socket,time,sys;s=socket.create_connection(('127.0.0.1',int(sys.argv[1])));"
        "print(s.getsockname()[1],flush=True);time.sleep(5)"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", code, str(rig.port)],
        stdout=subprocess.PIPE,
        text=True,
        env={**os.environ, "CNS_DEMO_LABEL": "Alice"},
    )
    try:
        client_port = int(proc.stdout.readline())
        assert identify_label(client_port, rig.port) == "Alice"
    finally:
        proc.kill()


@pytest.mark.skipif(shutil.which("lsof") is None, reason="needs lsof")
def test_browser_profile_directory_names_the_victim_through_a_parent_process(rig):
    """Chrome hides its environment: the label comes from --user-data-dir up the process tree."""
    from attack_lab.netproxy.core import identify_label

    child = (
        "import socket,time,sys;s=socket.create_connection(('127.0.0.1',int(sys.argv[1])));"
        "print(s.getsockname()[1],flush=True);time.sleep(5)"
    )
    parent = "import subprocess,sys;subprocess.run([sys.executable,'-c',sys.argv[2],sys.argv[1]])"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            parent,
            str(rig.port),
            child,
            "--user-data-dir=/tmp/cns-netattack.AbC123/Bob",
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        client_port = int(proc.stdout.readline())
        assert identify_label(client_port, rig.port) == "Bob"
    finally:
        proc.kill()


def test_web_certificate_is_generated_once_with_localhost_san_and_stable_spki(tmp_path):
    import base64
    import hashlib

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from attack_lab.netproxy import webcert

    mode, cert, key = webcert.generate(tmp_path)
    first = cert.read_bytes()
    assert mode in ("mkcert", "selfsigned") and key.stat().st_mode & 0o077 == 0
    assert webcert.generate(tmp_path)[0] == mode and cert.read_bytes() == first  # not regenerated
    parsed = x509.load_pem_x509_certificate(first)
    names = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "localhost" in names.get_values_for_type(x509.DNSName)
    der = parsed.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert webcert.spki_hash(first) == base64.b64encode(hashlib.sha256(der).digest()).decode()
