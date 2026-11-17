"""Metadata + presigned-URL API for end-to-end encrypted attachments.

The server only ever handles ciphertext. Browsers encrypt a file with a fresh
key (carried inside the signed chat message, never here), upload the ciphertext
straight to object storage with a short-lived presigned URL, and the recipient
downloads it the same way. This module authorises those URLs, enforces size /
quota / rate limits and expires objects lazily (no cron, no background thread).
"""

import asyncio
from collections import defaultdict, deque
import os
import re
import secrets
import threading
import time

from fastapi import HTTPException, Request, Response
from sqlalchemy import func, insert, select, update

from server.db import attachments, users
from server.storage import StorageError

MIB = 1024 * 1024
CHUNK = MIB
GCM_OVERHEAD = 28  # 12-byte nonce + 16-byte tag per chunk
HEX32 = re.compile(r"^[0-9a-f]{32}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _int_env(name, default, minimum=1):
    value = int(os.environ.get(name, default))
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


class AttachmentConfig:
    def __init__(self):
        self.image_max = _int_env("ATTACHMENT_IMAGE_MAX_BYTES", 10 * MIB)
        self.video_max = _int_env("ATTACHMENT_VIDEO_MAX_BYTES", 50 * MIB)
        self.user_quota = _int_env("ATTACHMENT_USER_QUOTA_BYTES", 200 * MIB)
        self.retention = _int_env("ATTACHMENT_RETENTION_DAYS", 7) * 86400
        self.url_ttl = _int_env("ATTACHMENT_URL_TTL_SECONDS", 300, 30)
        self.pending_ttl = _int_env("ATTACHMENT_PENDING_TTL_SECONDS", 3600, 60)
        self.init_rate = _int_env("ATTACHMENT_INIT_PER_MINUTE", 20)
        self.url_rate = _int_env("ATTACHMENT_URLS_PER_MINUTE", 120)

    def limit(self, kind):
        return self.image_max if kind == "image" else self.video_max

    def max_ciphertext(self, kind):
        plain = self.limit(kind)
        return plain + (plain // CHUNK + 1) * GCM_OVERHEAD

    def public(self):
        return {
            "image_max": self.image_max,
            "video_max": self.video_max,
            "user_quota": self.user_quota,
            "retention_seconds": self.retention,
            "chunk": CHUNK,
        }


class AttachmentAPI:
    def __init__(self, app, database, storage, tokens, config=None):
        self.database, self.storage, self.tokens = database, storage, tokens
        self.config = config or AttachmentConfig()
        self._rates = defaultdict(deque)
        self._rate_lock = threading.Lock()
        app.state.attachments = self

        @app.get("/api/attachments/config")
        async def get_config(request: Request):
            self.tokens.owner(request)
            return self.config.public()

        @app.post("/api/attachments")
        async def init(request: Request):
            owner = self.tokens.owner(request)
            data = await self._json(request)
            return await asyncio.to_thread(self.init, owner, data)

        @app.post("/api/attachments/{attachment_id}/finalize")
        async def finalize(attachment_id: str, request: Request):
            owner = self.tokens.owner(request)
            return await asyncio.to_thread(self.finalize, owner, attachment_id)

        @app.get("/api/attachments/{attachment_id}/download")
        async def download(attachment_id: str, request: Request):
            owner = self.tokens.owner(request)
            return await asyncio.to_thread(self.download, owner, attachment_id)

        @app.delete("/api/attachments/{attachment_id}")
        async def remove(attachment_id: str, request: Request):
            owner = self.tokens.owner(request)
            return await asyncio.to_thread(self.remove, owner, attachment_id)

        if not storage.direct:
            self._install_local_objects(app)

    # ---- helpers -------------------------------------------------------
    async def _json(self, request):
        import json

        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 4096:
                raise HTTPException(413, "Request too large")
        try:
            data = json.loads(raw)
        except (ValueError, RecursionError):
            raise HTTPException(400, "Expected a JSON object")
        if not isinstance(data, dict):
            raise HTTPException(400, "Expected a JSON object")
        return data

    def _limited(self, owner, bucket, limit):
        now = time.monotonic()
        with self._rate_lock:
            times = self._rates[(owner, bucket)]
            while times and now - times[0] > 60:
                times.popleft()
            if len(times) >= limit:
                raise HTTPException(429, "Too many attachment requests; slow down")
            times.append(now)

    def sweep(self, limit=25):
        """Lazily delete expired and orphaned (never finalised) objects."""
        now = time.time()
        with self.database.engine.connect() as conn:
            rows = conn.execute(
                select(attachments.c.id, attachments.c.object_key)
                .where(attachments.c.deleted_at.is_(None), attachments.c.expires_at < now)
                .order_by(attachments.c.expires_at)
                .limit(limit)
            ).all()
        done = []
        for att_id, key in rows:
            try:
                self.storage.delete(key)
                done.append(att_id)
            except StorageError:
                continue  # retried by a later request
        if done:
            with self.database.transaction() as conn:
                conn.execute(
                    update(attachments)
                    .where(attachments.c.id.in_(done))
                    .values(deleted_at=now)
                )
        return len(done)

    def _row(self, conn, attachment_id):
        if not isinstance(attachment_id, str) or not HEX32.match(attachment_id):
            raise HTTPException(404, "Attachment not found")
        return (
            conn.execute(select(attachments).where(attachments.c.id == attachment_id))
            .mappings()
            .first()
        )

    # ---- operations ----------------------------------------------------
    def init(self, owner, data):
        cfg = self.config
        self._limited(owner, "init", cfg.init_rate)
        try:
            att_id, recipient, kind = data["id"], data["recipient"], data["kind"]
            size, digest = data["ciphertext_size"], data["ciphertext_sha256"]
            ok = (
                isinstance(att_id, str) and HEX32.match(att_id)
                and isinstance(recipient, str) and 0 < len(recipient) <= 200
                and kind in ("image", "video")
                and type(size) is int and 0 < size
                and isinstance(digest, str) and HEX64.match(digest)
            )
        except KeyError:
            ok = False
        if not ok:
            raise HTTPException(400, "Invalid attachment request")
        if recipient == owner:
            raise HTTPException(400, "Choose a different recipient")
        if size > cfg.max_ciphertext(kind):
            raise HTTPException(
                413, f"{kind.title()} exceeds the {cfg.limit(kind) // MIB} MiB limit"
            )
        self.sweep()
        now = time.time()
        key = "att/" + secrets.token_hex(16)
        with self.database.transaction() as conn:
            if not conn.execute(
                select(users.c.username).where(users.c.username == recipient)
            ).first():
                raise HTTPException(404, "Recipient not found")
            if self._row(conn, att_id) is not None:
                raise HTTPException(409, "Attachment id already used")
            used = conn.execute(
                select(func.coalesce(func.sum(attachments.c.ciphertext_size), 0)).where(
                    attachments.c.uploader == owner,
                    attachments.c.deleted_at.is_(None),
                    attachments.c.expires_at >= now,
                )
            ).scalar_one()
            if used + size > cfg.user_quota:
                raise HTTPException(
                    413,
                    f"Storage quota of {cfg.user_quota // MIB} MiB reached; "
                    "wait for older attachments to expire",
                )
            expires = now + cfg.pending_ttl
            conn.execute(
                insert(attachments).values(
                    id=att_id, uploader=owner, recipient=recipient, kind=kind,
                    object_key=key, ciphertext_size=size, ciphertext_sha256=digest,
                    created_at=now, expires_at=expires,
                )
            )
        upload = self.storage.presign_put(key, size, cfg.url_ttl)
        return {"id": att_id, "upload": upload, "expires_at": expires}

    def finalize(self, owner, attachment_id):
        self._limited(owner, "init", self.config.init_rate)
        with self.database.engine.connect() as conn:
            row = self._row(conn, attachment_id)
        if row is None or row["uploader"] != owner or row["deleted_at"] is not None:
            raise HTTPException(404, "Attachment not found")
        if row["finalized_at"] is not None:
            return {"id": attachment_id, "expires_at": row["expires_at"]}
        if row["expires_at"] < time.time():
            raise HTTPException(410, "Upload window expired")
        # The storage round trip happens outside any database transaction.
        try:
            actual = self.storage.head(row["object_key"])
        except StorageError:
            raise HTTPException(502, "Storage unavailable; retry finalize")
        now = time.time()
        if actual != row["ciphertext_size"]:
            # Wrong/missing size: never expose the object to a recipient.
            try:
                self.storage.delete(row["object_key"])
            except StorageError:
                pass
            with self.database.transaction() as conn:
                conn.execute(
                    update(attachments)
                    .where(attachments.c.id == attachment_id)
                    .values(deleted_at=now)
                )
            raise HTTPException(409, "Uploaded size does not match; upload discarded")
        expires = now + self.config.retention
        with self.database.transaction() as conn:
            conn.execute(
                update(attachments)
                .where(attachments.c.id == attachment_id)
                .values(finalized_at=now, expires_at=expires)
            )
        return {"id": attachment_id, "expires_at": expires}

    def download(self, owner, attachment_id):
        self._limited(owner, "url", self.config.url_rate)
        with self.database.engine.connect() as conn:
            row = self._row(conn, attachment_id)
        now = time.time()
        # Same 404 for "not yours", "missing", "expired" and "not finalised":
        # a third party learns nothing about which ids exist.
        if (
            row is None
            or owner not in (row["uploader"], row["recipient"])
            or row["finalized_at"] is None
            or row["deleted_at"] is not None
            or row["expires_at"] < now
        ):
            raise HTTPException(404, "Attachment not found or expired")
        return {
            "id": attachment_id,
            "url": self.storage.presign_get(row["object_key"], self.config.url_ttl),
            "ciphertext_size": row["ciphertext_size"],
            "ciphertext_sha256": row["ciphertext_sha256"],
            "expires_at": row["expires_at"],
        }

    def remove(self, owner, attachment_id):
        with self.database.transaction() as conn:
            row = self._row(conn, attachment_id)
            if row is None or row["uploader"] != owner or row["deleted_at"] is not None:
                raise HTTPException(404, "Attachment not found")
            try:
                self.storage.delete(row["object_key"])
            except StorageError:
                raise HTTPException(502, "Storage unavailable; retry")
            conn.execute(
                update(attachments)
                .where(attachments.c.id == attachment_id)
                .values(deleted_at=time.time())
            )
        return {"deleted": True}

    # ---- local backend object endpoints (dev, tests and the Attack Lab) --
    def _install_local_objects(self, app):
        storage = self.storage

        @app.put("/api/attachments/object/{name}")
        async def put_object(name: str, request: Request):
            key = "att/" + name
            q = request.query_params
            try:
                size = int(q.get("size", ""))
            except ValueError:
                raise HTTPException(403, "Invalid signed URL")
            if not HEX32.match(name) or not storage.verify("put", key, q.get("exp"), q.get("sig"), size):
                raise HTTPException(403, "Invalid or expired signed URL")
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > size:
                    raise HTTPException(413, "Body larger than signed size")
            if len(body) != size:
                raise HTTPException(400, "Body size differs from signed size")
            await asyncio.to_thread(storage.write, key, bytes(body))
            return Response(status_code=200)

        @app.get("/api/attachments/object/{name}")
        async def get_object(name: str, request: Request):
            key = "att/" + name
            q = request.query_params
            if not HEX32.match(name) or not storage.verify("get", key, q.get("exp"), q.get("sig")):
                raise HTTPException(403, "Invalid or expired signed URL")
            try:
                data = await asyncio.to_thread(storage.read, key)
            except FileNotFoundError:
                raise HTTPException(404, "Object not found")
            return Response(data, media_type="application/octet-stream")
