"""Gateway policies and encrypted TCP/WebSocket interoperability on one roster."""
import base64
import json
import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from sqlalchemy import MetaData, select

import _demo_common as dc
import server.server as sm
from server import db
from server.relay_core import RelayCore
from server.lockout import LockoutGuard
from crypto_engine.signatures import generate_keypair, serialize_public_key, sign, verify
from crypto_engine.dh_exchange import generate_keypair as ecdh, compute_shared_key
from crypto_engine.aes_gcm import encrypt, decrypt
from crypto_engine.hash_chain import canonical_record, genesis_hash
from web.app import create_app

ORIGIN = 'http://localhost:8080'
b64 = lambda data: base64.b64encode(data).decode('ascii')
unb64 = base64.b64decode


def app_for(core=None):
    return create_app(core or RelayCore(logger=lambda *a, **kw: sm.log_event(*a, **kw)))


def until(ws, kind):
    for _ in range(30):
        event = ws.receive_json()
        if event['type'] == kind:
            return event
    raise AssertionError(f'no {kind} envelope')


def connect(client):
    return client.websocket_connect('/ws', headers={'origin': ORIGIN})


def test_authentication_required_before_routing():
    with TestClient(app_for()) as client, connect(client) as ws:
        ws.send_json({'type': 'chat', 'from': 'intruder', 'to': 'nobody', 'ciphertext': 'YWJj'})
        assert ws.receive_json()['type'] == 'system'
        with db.get_database().engine.connect() as conn:
            assert conn.execute(select(db.relayed_envelopes)).all() == []
        ws.send_json({'type': 'get_pubkey', 'username': 'alice'})
        assert ws.receive_json()['type'] == 'system'


def test_websocket_lockout_skips_pbkdf2_and_persists():
    core = RelayCore(lockout=LockoutGuard(threshold=2), logger=lambda *a, **kw: sm.log_event(*a, **kw))
    assert core.register_user('locked_web', 'correct')
    with TestClient(app_for(core)) as client, connect(client) as ws:
        for _ in range(2):
            ws.send_json({'type': 'login', 'username': 'locked_web', 'password': 'wrong'})
            assert ws.receive_json()['reason'] == 'invalid username or password'
        with patch('server.user_store.verify_password') as spy:
            ws.send_json({'type': 'login', 'username': 'locked_web', 'password': 'correct'})
            assert 'locked' in ws.receive_json()['reason']
        spy.assert_not_called()
    assert LockoutGuard().status('locked_web').locked


def test_origin_rejection():
    with TestClient(app_for()) as client:
        for headers in ({}, {'origin': 'https://evil.invalid'}, {'origin':'null'}):
            with pytest.raises(WebSocketDisconnect) as caught:
                with client.websocket_connect('/ws', headers=headers):
                    pass
            assert caught.value.code == 1008


def test_frame_size_limit(monkeypatch):
    monkeypatch.setenv('SECURECHAT_WS_MAX_BYTES','256')
    with TestClient(app_for()) as client, connect(client) as ws:
        ws.send_text('x' * 257)
        with pytest.raises(WebSocketDisconnect) as caught:
            ws.receive_json()
        assert caught.value.code == 1009


@pytest.mark.parametrize('envelope',[{'type':'unknown'},{'type':'lab_control','action':'drop_next'},[],{'type':['chat']}])
def test_unknown_or_invalid_type_rejected(envelope):
    with TestClient(app_for()) as client, connect(client) as ws:
        ws.send_json(envelope)
        with pytest.raises(WebSocketDisconnect) as caught:
            ws.receive_json()
        assert caught.value.code == 1008


def test_connection_rate_limit(monkeypatch):
    monkeypatch.setenv('SECURECHAT_WS_RATE_LIMIT','2')
    with TestClient(app_for()) as client, connect(client) as ws:
        for _ in range(2):
            ws.send_json({'type':'get_pubkey','username':'nobody'})
            assert ws.receive_json()['type']=='system'
        ws.send_json({'type':'get_pubkey','username':'nobody'})
        with pytest.raises(WebSocketDisconnect) as caught:
            ws.receive_json()
        assert caught.value.code==1008


def test_idle_timeout(monkeypatch):
    monkeypatch.setenv('SECURECHAT_WS_IDLE_SECONDS','0.05')
    with TestClient(app_for()) as client, connect(client) as ws:
        with pytest.raises(WebSocketDisconnect) as caught:
            ws.receive_json()
        assert caught.value.code == 1001


def test_security_headers():
    with TestClient(app_for()) as client:
        response = client.get('/')
        assert response.status_code == 200
        assert "script-src 'self'" in response.headers['content-security-policy']
        assert "frame-ancestors 'none'" in response.headers['content-security-policy']
        assert "'unsafe-inline'" not in response.headers['content-security-policy']
        assert response.headers['x-content-type-options']=='nosniff'
        assert response.headers['referrer-policy']=='no-referrer'


def test_tcp_websocket_chat_shares_roster_and_never_stores_plaintext(net):
    server, _, port = net.start_server()
    alice = net.register_client(port, 'a_tcp', 'z_web')
    private, public = generate_keypair()
    with TestClient(app_for(server)) as client, connect(client) as ws:
        ws.send_json({'type':'register','username':'z_web','password':'web-password',
                      'public_key':serialize_public_key(public).decode()})
        assert until(ws,'register_result')['success']
        roster=until(ws,'roster')
        assert 'a_tcp' in roster['users']
        ws.send_json({'type':'get_pubkey','username':'a_tcp'})
        received = {}
        while not {'pubkey_result', 'handshake_init'} <= received.keys():
            event = ws.receive_json()
            received[event['type']] = event
        assert received['pubkey_result']['success']
        init=received['handshake_init']
        assert verify(alice.rsa_private_key.public_key(),unb64(init['pubkey']),unb64(init['handshake_sig']))
        secret,pub=ecdh()
        key=compute_shared_key(secret,unb64(init['pubkey']))
        ws.send_json({'type':'handshake_response','from':'z_web','to':'a_tcp',
                      'pubkey':b64(pub),'handshake_sig':b64(sign(private,pub))})
        marker='WS_DATABASE_PLAINTEXT_MARKER_196240'
        stamp=int(time.time());prev=genesis_hash(unb64(init['pubkey']),pub,'z_web')
        rec=canonical_record('z_web','a_tcp',1,stamp,marker,prev)
        box=encrypt(key,json.dumps({'message':marker,'timestamp':stamp,'seq':1,'prev_hash':prev,
                                   'signature':b64(sign(private,rec))}).encode())
        ws.send_json({'type':'chat','from':'z_web','to':'a_tcp',**{k:b64(v) for k,v in box.items()}})
        deadline=time.time()+10
        while time.time()<deadline and not any(r['message']==marker for r in alice.transcript):
            time.sleep(.02)
        assert any(r['message']==marker for r in alice.transcript)
        alice.send_message('TCP_REPLY_PLAINTEXT_MARKER_258')
        response=until(ws,'chat')
        inner=json.loads(decrypt(key,unb64(response['nonce']),unb64(response['ciphertext']),unb64(response['tag'])))
        assert inner['message']=='TCP_REPLY_PLAINTEXT_MARKER_258'
        assert verify(alice.rsa_private_key.public_key(),
                      canonical_record('a_tcp','z_web',inner['seq'],inner['timestamp'],inner['message'],inner['prev_hash']),unb64(inner['signature']))
        reflected=MetaData();reflected.reflect(bind=db.get_database().engine)
        with db.get_database().engine.connect() as conn:
            for table in reflected.sorted_tables:
                for row in conn.execute(select(table)):
                    for value in row:
                        assert marker not in str(value)
                        assert 'TCP_REPLY_PLAINTEXT_MARKER_258' not in str(value)
        assert server.clients.get('z_web') is not None


def test_origin_allowlist_override(monkeypatch):
    monkeypatch.setenv('SECURECHAT_ALLOWED_ORIGINS','https://chat.example')
    with TestClient(app_for()) as client:
        with client.websocket_connect('/ws',headers={'origin':'https://chat.example'}) as ws:
            ws.send_json({'type':'get_pubkey','username':'nobody'})
            assert ws.receive_json()['type']=='system'
        with pytest.raises(WebSocketDisconnect):
            with connect(client):
                pass


def test_deployment_entrypoint_imports_no_tcp_or_lab_code():
    import subprocess
    import sys
    result=subprocess.run([sys.executable,'-c',
        'import sys, web.__main__; assert "server.server" not in sys.modules; print("HTTP/WS only")'],
        capture_output=True,text=True,check=True)
    assert 'HTTP/WS only' in result.stdout


def test_combined_cli_runs_both_real_transports_on_one_roster(net):
    import re
    import subprocess
    import sys
    import urllib.request
    from websockets.sync.client import connect as websocket_connect
    process=subprocess.Popen([sys.executable,'-u','server/server.py','--port','0','--web-port','0'],
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    try:
        tcp_port=web_port=None
        for _ in range(40):
            line=process.stdout.readline()
            assert line, 'combined server exited early'
            match=re.search(r'Server listening on 127.0.0.1:(\d+)',line)
            if match:
                tcp_port=int(match.group(1))
            match=re.search(r'Uvicorn running on http://127.0.0.1:(\d+)',line)
            if match:
                web_port=int(match.group(1))
            if tcp_port and web_port:
                break
        assert tcp_port and web_port
        assert urllib.request.urlopen(f'http://127.0.0.1:{web_port}/',timeout=5).status==200
        tcp=net.register_client(tcp_port,'cli_tcp','cli_web')
        with websocket_connect(f'ws://127.0.0.1:{web_port}/ws',origin=ORIGIN,open_timeout=5) as ws:
            ws.send(json.dumps({'type':'register','username':'cli_web','password':'cli-password'}))
            result=json.loads(ws.recv(timeout=5))
            assert result['type']=='register_result' and result['success']
            roster=json.loads(ws.recv(timeout=5))
            assert roster['type']=='roster' and 'cli_tcp' in roster['users']
        tcp.stop_event.set()
        tcp.sock.close()
    finally:
        process.terminate()
        process.wait(timeout=10)
