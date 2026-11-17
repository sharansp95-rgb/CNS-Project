"""Owner-only encrypted evidence storage. No evidence decryption on the server."""

import asyncio
import base64
import json
import secrets
import threading
import time
import uuid
from fastapi import HTTPException, Request
from sqlalchemy import select, insert, delete, func
from crypto_engine.evidence_tools import valid_hash
from server.db import evidence_bundles
from server.timestamp import TimestampSigner
from web.tokens import TokenStore

MAX_UPLOAD = 12 * 1024 * 1024


class VaultAPI(TokenStore):
    def __init__(self, app, database):
        super().__init__()
        self.database = database
        self.signer = None
        self.signer_lock = threading.Lock()

        @app.get("/api/timestamp-key")
        async def timestamp_key():
            return await asyncio.to_thread(lambda: self.get_signer().public_info())

        @app.post("/api/evidence")
        async def save(request: Request):
            owner = self.owner(request)
            raw = bytearray()
            async for chunk in request.stream():
                if len(raw) + len(chunk) > MAX_UPLOAD:
                    raise HTTPException(413, "Evidence package exceeds 12 MiB")
                raw.extend(chunk)
            try:
                body = json.loads(raw)
                version, hashes, total = (
                    body["format_version"],
                    body.get("envelope_hashes", []),
                    body["total"],
                )
                if (
                    type(version) is not int
                    or version not in (1, 2)
                    or type(total) is not int
                    or not 0 <= total <= 10000
                ):
                    raise ValueError()
                if (
                    not isinstance(hashes, list)
                    or (version == 2 and len(hashes) != total)
                    or (version == 1 and hashes)
                ):
                    raise ValueError()
                if not all(valid_hash(h) for h in hashes) or not valid_hash(
                    body["file_sha256"]
                ):
                    raise ValueError()
                title = body["title"]
                if not isinstance(title, str) or not 1 <= len(title.strip()) <= 120:
                    raise ValueError()
                encoded = body["ciphertext_b64"]
                if not isinstance(encoded, str):
                    raise ValueError()
                packed = base64.b64decode(encoded, validate=True)
                package = json.loads(packed)
                if set(package) != {
                    "format",
                    "iterations",
                    "salt",
                    "nonce",
                    "file_sha256",
                    "ciphertext",
                }:
                    raise ValueError()
                if (
                    package["format"] != "securechat-vault/v1"
                    or package["iterations"] != 600000
                    or package["file_sha256"] != body["file_sha256"]
                ):
                    raise ValueError()
                if (
                    len(base64.b64decode(package["salt"], validate=True)) != 16
                    or len(base64.b64decode(package["nonce"], validate=True)) != 12
                ):
                    raise ValueError()
                cipher = base64.b64decode(package["ciphertext"], validate=True)
                if not 17 <= len(cipher) <= 8 * 1024 * 1024:
                    raise ValueError()
            except (ValueError, TypeError, KeyError, RecursionError):
                raise HTTPException(
                    400, "Invalid encrypted evidence package or manifest"
                )

            def store():
                with self.database.transaction() as conn:
                    if (
                        conn.execute(
                            select(func.count())
                            .select_from(evidence_bundles)
                            .where(evidence_bundles.c.owner == owner)
                        ).scalar_one()
                        >= 100
                    ):
                        raise HTTPException(
                            409, "Vault limit: delete an older bundle before saving"
                        )
                    receipt = self.get_signer().receipt(
                        conn, owner, body["file_sha256"], version, hashes, total
                    )
                    bundle = dict(
                        id=str(uuid.uuid4()),
                        owner=owner,
                        created_at=time.time(),
                        title=title.strip(),
                        size_bytes=len(cipher),
                        file_sha256=body["file_sha256"],
                        ciphertext_b64=encoded,
                        timestamp_receipt=receipt,
                    )
                    conn.execute(insert(evidence_bundles).values(**bundle))
                    return {k: v for k, v in bundle.items() if k != "ciphertext_b64"}

            return await asyncio.to_thread(store)

        @app.get("/api/evidence")
        async def list_bundles(request: Request):
            owner = self.owner(request)

            def read():
                with database.engine.connect() as conn:
                    return [
                        dict(row)
                        for row in conn.execute(
                            select(
                                *[
                                    c
                                    for c in evidence_bundles.c
                                    if c.name != "ciphertext_b64"
                                ]
                            )
                            .where(evidence_bundles.c.owner == owner)
                            .order_by(evidence_bundles.c.created_at.desc())
                        ).mappings()
                    ]

            return await asyncio.to_thread(read)

        @app.get("/api/evidence/{bundle_id}")
        async def download(bundle_id: str, request: Request):
            owner = self.owner(request)

            def read():
                with database.engine.connect() as conn:
                    row = (
                        conn.execute(
                            select(evidence_bundles).where(
                                evidence_bundles.c.id == bundle_id,
                                evidence_bundles.c.owner == owner,
                            )
                        )
                        .mappings()
                        .first()
                    )
                    if row is None:
                        raise HTTPException(404, "Evidence not found")
                    return dict(row)

            return await asyncio.to_thread(read)

        @app.delete("/api/evidence/{bundle_id}")
        async def remove(bundle_id: str, request: Request):
            owner = self.owner(request)

            def erase():
                with database.transaction() as conn:
                    result = conn.execute(
                        delete(evidence_bundles).where(
                            evidence_bundles.c.id == bundle_id,
                            evidence_bundles.c.owner == owner,
                        )
                    )
                    if not result.rowcount:
                        raise HTTPException(404, "Evidence not found")
                return {"deleted": True}

            return await asyncio.to_thread(erase)

    def get_signer(self):
        with self.signer_lock:
            if self.signer is None:
                self.signer = TimestampSigner()
            return self.signer
