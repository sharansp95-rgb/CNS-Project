"""Attachment API: authorization, limits, quota, expiry, ciphertext-only storage."""

import hashlib
import os
import time
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import MetaData, select, update

from server import db
from server.relay_core import RelayCore
from server.storage import LocalStorage, S3Storage, storage_from_env, StorageError
from web.app import create_app

ORIGIN = "http://localhost:8080"
# The public example key id from the AWS SigV4 documentation (split so secret scanners ignore it).
_AWS_DOC_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
MIB = 1024 * 1024


def make_app(storage=None):
    storage = storage or LocalStorage()
    app = create_app(RelayCore(logger=lambda *a, **kw: None), attachment_storage=storage)
    return app, storage


def authed(ws, name):
    ws.send_json(dict(type="register", username=name, password="password"))
    result = ws.receive_json()
    assert result["success"]
    return {"Authorization": "Bearer " + result["api_token"]}


class World:
    """alice, bob and mallory, logged in over real WebSockets."""

    def __init__(self, client):
        self.client = client
        self.sockets = [client.websocket_connect("/ws", headers={"origin": ORIGIN}) for _ in range(3)]
        self.ws = [s.__enter__() for s in self.sockets]
        self.alice, self.bob, self.mallory = (
            authed(ws, n) for ws, n in zip(self.ws, ("alice", "bob", "mallory"))
        )

    def close(self):
        for s in self.sockets:
            s.__exit__(None, None, None)


@pytest.fixture()
def world():
    app, storage = make_app()
    with TestClient(app) as client:
        w = World(client)
        w.app, w.storage = app, storage
        yield w
        w.close()


def init(w, headers, ciphertext, **over):
    body = dict(
        id=uuid.uuid4().hex,
        recipient="bob",
        kind="image",
        ciphertext_size=len(ciphertext),
        ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest(),
    )
    body.update(over)
    return body, w.client.post("/api/attachments", headers=headers, json=body)


def upload(w, response, data):
    up = response.json()["upload"]
    return w.client.put(up["url"], content=data, headers=up["headers"])


def full_flow(w, data=None):
    data = data or os.urandom(5000)
    body, r = init(w, w.alice, data)
    assert r.status_code == 200, r.text
    assert upload(w, r, data).status_code == 200
    f = w.client.post(f"/api/attachments/{body['id']}/finalize", headers=w.alice)
    assert f.status_code == 200, f.text
    return body, data


def test_roundtrip_and_authorization(world):
    body, data = full_flow(world)
    url = lambda h: world.client.get(f"/api/attachments/{body['id']}/download", headers=h)
    for allowed in (world.alice, world.bob):
        r = url(allowed)
        assert r.status_code == 200
        assert r.json()["ciphertext_sha256"] == body["ciphertext_sha256"]
        assert world.client.get(r.json()["url"]).content == data
    # A third party gets the same 404 as for a nonexistent id.
    assert url(world.mallory).status_code == 404
    missing = world.client.get(f"/api/attachments/{uuid.uuid4().hex}/download", headers=world.mallory)
    assert missing.status_code == 404 and missing.json() == url(world.mallory).json()
    # Anonymous requests are rejected everywhere.
    assert world.client.get(f"/api/attachments/{body['id']}/download").status_code == 401
    assert world.client.post("/api/attachments", json={}).status_code == 401
    # Only the uploader may finalize or delete.
    assert world.client.delete(f"/api/attachments/{body['id']}", headers=world.bob).status_code == 404
    assert world.client.delete(f"/api/attachments/{body['id']}", headers=world.alice).status_code == 200
    assert url(world.bob).status_code == 404
    assert world.storage.keys() == []


def test_unfinalized_upload_is_not_downloadable(world):
    data = os.urandom(100)
    body, r = init(world, world.alice, data)
    upload(world, r, data)
    assert world.client.get(f"/api/attachments/{body['id']}/download", headers=world.bob).status_code == 404


def test_finalize_rejects_missing_or_wrong_size_and_discards(world):
    data = os.urandom(100)
    body, r = init(world, world.alice, data)
    assert world.client.post(f"/api/attachments/{body['id']}/finalize", headers=world.alice).status_code == 409
    # Local backend: a signed URL cannot write a different size either.
    body, r = init(world, world.alice, data)
    up = r.json()["upload"]
    assert world.client.put(up["url"], content=data[:50]).status_code == 400
    # Bypass the storage layer: an object of the wrong size appears at the key.
    key = world.app.state.attachments.database.engine.connect().execute(
        select(db.attachments.c.object_key).where(db.attachments.c.id == body["id"])
    ).scalar_one()
    world.storage.write(key, b"x" * 7)
    assert world.client.post(f"/api/attachments/{body['id']}/finalize", headers=world.alice).status_code == 409
    assert world.storage.head(key) is None  # discarded
    assert world.client.get(f"/api/attachments/{body['id']}/download", headers=world.bob).status_code == 404


def test_signed_url_tampering_expiry_and_reuse_rules(world):
    data = os.urandom(100)
    body, r = init(world, world.alice, data)
    up = r.json()["upload"]["url"]
    assert world.client.put(up.replace("sig=", "sig=0"), content=data).status_code == 403
    assert world.client.put(up.replace("size=100", "size=101"), content=data).status_code == 403
    expired = world.storage.presign_put("att/" + "a" * 32, 100, expires_in=-5)
    assert world.client.put(expired["url"], content=data).status_code == 403
    assert world.client.get("/api/attachments/object/" + "b" * 32 + "?op=get&exp=1&sig=x").status_code == 403
    # A GET signature cannot be used as a PUT signature.
    get_url = world.storage.presign_get("att/" + "c" * 32)
    assert world.client.put(get_url.replace("op=get", "op=put") + "&size=1", content=b"x").status_code == 403


def test_validation_limits_and_recipient(world):
    data = os.urandom(64)
    cases = [
        dict(kind="svg"),
        dict(kind="image", ciphertext_size=0),
        dict(ciphertext_sha256="zz"),
        dict(id="short"),
        dict(recipient="alice"),
        dict(recipient=""),
        dict(ciphertext_size=True),
    ]
    for over in cases:
        _, r = init(world, world.alice, data, **over)
        assert r.status_code == 400, (over, r.text)
    _, r = init(world, world.alice, data, recipient="nobody")
    assert r.status_code == 404
    _, r = init(world, world.alice, data, ciphertext_size=10 * MIB + 10 * 28 + 28 + 1)
    assert r.status_code == 413 and "10 MiB" in r.json()["detail"]
    _, r = init(world, world.alice, data, kind="video", ciphertext_size=10 * MIB + 29)
    assert r.status_code == 200  # a 10 MiB+ file is fine as video
    _, r = init(world, world.alice, data, kind="video", ciphertext_size=50 * MIB + 51 * 28 + 1)
    assert r.status_code == 413
    # Duplicate id
    body, r = init(world, world.alice, data)
    _, dup = init(world, world.alice, data, id=body["id"])
    assert dup.status_code == 409


def test_per_user_quota(world, monkeypatch):
    api = world.app.state.attachments
    api.config.user_quota = 1000
    for _ in range(2):
        _, r = init(world, world.alice, b"x" * 400)
        assert r.status_code == 200
    _, r = init(world, world.alice, b"x" * 400)
    assert r.status_code == 413 and "quota" in r.json()["detail"]
    # The quota is per uploader.
    _, r = init(world, world.bob, b"x" * 400, recipient="alice")
    assert r.status_code == 200


def test_rate_limit(world):
    api = world.app.state.attachments
    api.config.init_rate = 3
    codes = [init(world, world.alice, b"x" * 10)[1].status_code for _ in range(5)]
    assert codes.count(429) == 2
    assert init(world, world.bob, b"x" * 10, recipient="alice")[1].status_code == 200


def test_expiry_and_lazy_cleanup(world):
    body, data = full_flow(world)
    orphan_data = b"o" * 10
    orphan, r = init(world, world.alice, orphan_data)
    upload(world, r, orphan_data)  # uploaded but never finalized
    assert len(world.storage.keys()) == 2
    database = world.app.state.attachments.database
    with database.transaction() as conn:
        conn.execute(update(db.attachments).values(expires_at=time.time() - 1))
    # Expired objects cannot be downloaded, even before they are swept.
    r = world.client.get(f"/api/attachments/{body['id']}/download", headers=world.bob)
    assert r.status_code == 404
    # The next init lazily sweeps both the expired and the orphaned object.
    _, r = init(world, world.bob, b"n" * 10, recipient="alice")
    assert r.status_code == 200
    assert len(world.storage.keys()) == 0
    with database.engine.connect() as conn:
        assert conn.execute(
            select(db.attachments.c.deleted_at).where(db.attachments.c.id == body["id"])
        ).scalar_one() is not None


def test_retention_is_configurable(monkeypatch):
    monkeypatch.setenv("ATTACHMENT_RETENTION_DAYS", "1")
    app, storage = make_app()
    with TestClient(app) as client:
        w = World(client)
        w.app, w.storage = app, storage
        before = time.time()
        full_flow(w)
        with app.state.attachments.database.engine.connect() as conn:
            exp = conn.execute(select(db.attachments.c.expires_at)).scalar_one()
        assert 86390 < exp - before < 86500
        w.close()


def test_no_plaintext_in_database_or_stored_objects(world):
    marker = b"SECRET-PLAINTEXT-MARKER-0123456789"
    # What the browser would upload: only ciphertext. The server and storage
    # must never receive the marker unless the (simulated) client sent it, and
    # the metadata tables never contain names or keys.
    import secrets
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key, nonce = AESGCM.generate_key(256), secrets.token_bytes(12)
    ciphertext = nonce + AESGCM(key).encrypt(nonce, marker * 100, b"aad")
    body, _ = full_flow(world, ciphertext)
    stored = b"".join(world.storage.read(k) for k in world.storage.keys())
    assert marker not in stored and stored == ciphertext
    reflected = MetaData()
    reflected.reflect(bind=db.get_database().engine)
    with db.get_database().engine.connect() as conn:
        for table in reflected.sorted_tables:
            for row in conn.execute(select(table)):
                for value in row:
                    assert marker.decode() not in str(value)
    columns = {c.name for c in db.attachments.columns}
    assert columns == {
        "id", "uploader", "recipient", "kind", "object_key", "ciphertext_size",
        "ciphertext_sha256", "created_at", "finalized_at", "expires_at", "deleted_at",
    }
    assert not {"name", "filename", "mime", "key", "file_key", "thumbnail"} & columns


def test_token_revoked_on_disconnect_blocks_attachment_api(world):
    world.sockets[2].__exit__(None, None, None)
    assert world.client.post("/api/attachments", headers=world.mallory, json={}).status_code == 401
    world.sockets[2] = world.client.websocket_connect("/ws", headers={"origin": ORIGIN})
    world.sockets[2].__enter__()


def test_large_envelope_ciphertext_is_not_duplicated_in_sql():
    envelope = {"type": "chat", "from": "a", "to": "b", "nonce": "x", "tag": "y",
                "ciphertext": "QUFB" * 4000}
    database = db.get_database()
    db.record_relay(envelope, "a", database)
    small = dict(envelope, ciphertext="QUFB" * 10)
    db.record_relay(small, "a", database)
    with database.engine.connect() as conn:
        rows = conn.execute(select(db.relayed_envelopes.c.ciphertext_b64, db.relayed_envelopes.c.envelope_sha256)).all()
    assert rows[0][0] is None and len(rows[0][1]) == 64
    assert rows[1][0] == "QUFB" * 10


def test_local_storage_rejects_path_traversal_keys(tmp_path):
    s = LocalStorage(tmp_path)
    for bad in ("../x", "att/../x", "att/" + "g" * 32, "att/" + "a" * 31, "/etc/passwd"):
        with pytest.raises(StorageError):
            s.path(bad)


def test_storage_configuration_from_environment():
    assert storage_from_env({}).kind == "local"
    with pytest.raises(ValueError):
        storage_from_env({"STORAGE_BACKEND": "gcs"})
    with pytest.raises(ValueError, match="STORAGE_BACKEND=s3"):
        storage_from_env({"STORAGE_BACKEND": "local"}, production=True)
    s3 = storage_from_env({
        "STORAGE_BACKEND": "s3", "S3_ENDPOINT": "https://s.example", "S3_BUCKET": "b",
        "S3_REGION": "r", "S3_ACCESS_KEY_ID": "AK", "S3_SECRET_ACCESS_KEY": "SK",
    })
    url = s3.presign_get("att/" + "a" * 32)
    assert url.startswith("https://s.example/b/att/") and "X-Amz-Signature=" in url
    assert "SK" not in url and "X-Amz-Expires=300" in url
    put = s3.presign_put("att/" + "a" * 32, 123)["url"]
    assert "content-length" in put and "X-Amz-SignedHeaders=content-length%3Bhost" in put


def test_sigv4_presign_matches_aws_documented_example():
    """The AWS SigV4 query-auth example (GET /test.txt) from the S3 documentation."""
    import datetime as dt

    class Fixed(S3Storage):
        pass

    s = S3Storage("https://examplebucket.s3.amazonaws.com", "x", "us-east-1",
                  _AWS_DOC_KEY_ID, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    # Virtual-hosted example: bucket is in the host and the path is /test.txt.
    s.bucket = ""
    now = dt.datetime(2013, 5, 24, tzinfo=dt.timezone.utc)
    headers = {"host": "examplebucket.s3.amazonaws.com"}
    query = {
        "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
        "X-Amz-Credential": _AWS_DOC_KEY_ID + "/20130524/us-east-1/s3/aws4_request",
        "X-Amz-Date": "20130524T000000Z",
        "X-Amz-Expires": "86400",
        "X-Amz-SignedHeaders": "host",
    }
    s._canonical_uri = lambda key=None: "/test.txt"
    signature = s._sign("GET", None, query, headers, "UNSIGNED-PAYLOAD", now)[0]
    assert signature == "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
