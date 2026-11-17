"""Separate sandbox site; product clients are embedded as opaque unchanged assets."""

import asyncio
from collections import deque
from contextlib import asynccontextmanager
import json
import hmac
import os
from pathlib import Path
import secrets
import threading
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete, insert, select, update
from auth.password_hash import hash_password
from server.db import attachments, metadata, users, PROJECT_ROOT
from web.app import create_app as product_gateway, STATIC as PRODUCT_STATIC
from attack_lab.relay import RogueRelay, lab_database
from attack_lab.access import LabAccessGate
from server.storage import LocalStorage
from web.settings import Settings, install_transport

ROOT = Path(__file__).resolve().parent
ACCOUNTS = ("lab_alice", "lab_bob")
PASSWORD = "Lab-Password-1234!"


def certificates(root):
    """Own TLS certificate for optional local TCP; no mutable cert-module globals."""
    from datetime import datetime, timedelta, timezone
    import ipaddress
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    root.mkdir(parents=True, exist_ok=True)
    key_path, cert_path = root / "server.key", root / "server.crt"
    if not key_path.exists() or not cert_path.exists():
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .sign(private, hashes.SHA256())
        )
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(
                private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(cert_path), str(key_path)


def create_app(*, database_url=None, origins=None, state_dir=None, tcp_port=None):
    port = int(os.environ.get("PORT", "8090"))
    settings = Settings.load(
        origins,
        os.environ.get(
            "LAB_ALLOWED_ORIGINS", f"http://localhost:{port},http://127.0.0.1:{port}"
        ),
    )
    origins = set(settings.origins)
    access_code = os.environ.get("LAB_ACCESS_CODE", "")
    if settings.production:
        if len(access_code.encode()) < 24:
            raise ValueError(
                "A strong LAB_ACCESS_CODE (at least 24 bytes) is required in production"
            )
        if not os.environ.get("MAIN_SITE_ORIGIN"):
            raise ValueError(
                "MAIN_SITE_ORIGIN is required to enforce separate lab origins"
            )
        Settings.load([os.environ["MAIN_SITE_ORIGIN"]])
        if os.environ.get("DATABASE_URL"):
            raise ValueError("Do not give the sandbox the main DATABASE_URL")
        from sqlalchemy.engine import make_url

        if (
            make_url(
                database_url
                or os.environ.get("LAB_DATABASE_URL", "sqlite:///data/attack_lab.db")
            ).get_backend_name()
            != "sqlite"
        ):
            raise ValueError(
                "Production sandbox must use its own ephemeral SQLite database"
            )
        if tcp_port is not None:
            raise ValueError(
                "Production sandbox exposes HTTP/WS only; TCP is a local demo"
            )
    real_origins = {
        x.strip()
        for x in os.environ.get(
            "SECURECHAT_ALLOWED_ORIGINS", "http://localhost:8080,http://127.0.0.1:8080"
        ).split(",")
        if x.strip()
    }
    if os.environ.get("MAIN_SITE_ORIGIN"):
        real_origins.add(os.environ["MAIN_SITE_ORIGIN"])
    if not origins or "*" in origins or origins & real_origins:
        raise ValueError(
            "Lab origins must be explicit and different from the real service"
        )
    database = lab_database(database_url)
    state = Path(
        state_dir or os.environ.get("LAB_STATE_DIR") or PROJECT_ROOT / "data/attack_lab"
    )
    cert, key = (
        certificates(state / "certs")
        if tcp_port is not None or not settings.production
        else (None, None)
    )
    from server.security_log import log_event

    logger = lambda event, **fields: log_event(
        event, path=str(state / "security_events.jsonl"), database=database, **fields
    )
    # The rogue TLS adapter needs a context even with no listener; local sandbox
    # certificates are separate from identity/TSA keys and may be ephemeral.
    if cert is None:
        cert, key = certificates(state / "certs")
    relay = RogueRelay(certfile=cert, keyfile=key, database=database, logger=logger)
    # Attachments in the sandbox use the local backend only, in the lab's own
    # state directory; the lab never receives main's S3 credentials.
    storage = LocalStorage(state / "attachments")
    sessions = {}
    rates = {}
    guard = threading.RLock()
    generation = secrets.token_hex(8)

    def seed():
        nonlocal generation
        with relay._lock:
            for conn in list(relay.clients.values()):
                conn.close()
            relay.clients.clear()
            with database.transaction() as conn:
                for table in reversed(metadata.sorted_tables):
                    if table.name != "schema_version":
                        conn.execute(delete(table))
                for username in ACCOUNTS + ("lab_lockout",):
                    conn.execute(
                        insert(users).values(
                            username=username,
                            password_hash=hash_password(PASSWORD),
                            public_key_pem=None,
                            created_at=time.time(),
                        )
                    )
            with relay.attack_lock:
                relay.events.clear()
                relay.wire.clear()
                relay.pending.clear()
                relay.held.clear()
                relay.last.clear()
                relay.last_large.clear()
            storage.purge()
            with relay.lockout._lock:
                relay.lockout._by_addr.clear()
            generation = secrets.token_hex(8)
        return dict(generation=generation, accounts=list(ACCOUNTS), password=PASSWORD)

    # Seed on first start; all identities remain browser-generated, never uploaded privately.
    with database.engine.connect() as conn:
        initialized = all(
            conn.execute(
                select(users.c.username).where(users.c.username == name)
            ).first()
            for name in ACCOUNTS + ("lab_lockout",)
        )
    if not initialized:
        seed()

    @asynccontextmanager
    async def lifespan(app):
        thread = None
        if tcp_port is not None:
            relay.port = tcp_port
            relay.listen()
            thread = threading.Thread(target=relay.serve_forever, daemon=True)
            thread.start()
        yield
        for conn in list(relay.clients.values()):
            conn.close()
        relay.shutdown()
        if thread:
            thread.join(timeout=5)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.relay = relay
    app.state.database = database
    app.state.seed = seed
    app.state.storage = storage

    def authorized(token):
        with guard:
            return bool(token and sessions.get(token, 0) > time.monotonic())

    app.add_middleware(LabAccessGate, enabled=bool(access_code), authorized=authorized)

    def limited(key, limit=30):
        now = time.monotonic()
        with guard:
            times = rates.setdefault(key, deque())
            while times and now - times[0] > 60:
                times.popleft()
            if len(times) >= limit:
                raise HTTPException(429, "Lab control rate limit reached")
            times.append(now)

    def allowed(request):
        if request.headers.get("origin") not in origins:
            raise HTTPException(403, "Separate lab origin required")

    def session(request, write=False):
        if write:
            allowed(request)
        token = request.cookies.get("lab_session")
        with guard:
            if token not in sessions or sessions[token] < time.monotonic():
                raise HTTPException(401, "Start a lab session first")
        limited((token, write), 120 if not write else 30)
        return token

    async def bounded_body(request, limit):
        raw = bytearray()
        async for chunk in request.stream():
            if len(raw) + len(chunk) > limit:
                raise HTTPException(413, "Lab request too large")
            raw.extend(chunk)
        return bytes(raw)

    async def body(request):
        raw = await bounded_body(request, 16384)
        try:
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ValueError()
            return result
        except (ValueError, TypeError):
            raise HTTPException(400, "Expected a control object")

    @app.middleware("http")
    async def headers(request, call_next):
        response = await call_next(request)
        # Only this sandbox permits same-origin victim embedding; production keeps DENY.
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-src 'self'; frame-ancestors 'self'; img-src 'self' data: blob:; media-src blob:; font-src 'self'; base-uri 'none'; form-action 'self'"
        )
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        return response

    @app.get("/")
    async def index():
        return FileResponse(ROOT / "static/index.html")

    @app.get("/victim")
    async def victim():
        return FileResponse(PRODUCT_STATIC / "index.html")

    @app.post("/lab/session")
    async def start(request: Request):
        allowed(request)
        existing = request.cookies.get("lab_session")
        if authorized(existing):
            limited((existing, True), 30)
            return JSONResponse(
                dict(generation=generation, accounts=list(ACCOUNTS), password=PASSWORD)
            )
        limited(("start", request.client.host), 10)
        form = request.headers.get("content-type", "").startswith(
            "application/x-www-form-urlencoded"
        )
        if access_code and not authorized(request.cookies.get("lab_session")):
            if form:
                from urllib.parse import parse_qs

                raw = await bounded_body(request, 2048)
                provided = parse_qs(raw.decode("utf-8")).get("access_code", [""])[0]
            else:
                provided = (await body(request)).get("access_code", "")
            if not isinstance(provided, str) or not hmac.compare_digest(
                provided.encode(), access_code.encode()
            ):
                raise HTTPException(403, "Invalid lab access code")
        token = secrets.token_urlsafe(32)
        with guard:
            now = time.monotonic()
            expired = [k for k, v in sessions.items() if v <= now]
            for k in expired:
                sessions.pop(k)
            sessions[token] = now + 3600
        response = (
            RedirectResponse("/", status_code=303)
            if form
            else JSONResponse(
                dict(generation=generation, accounts=list(ACCOUNTS), password=PASSWORD)
            )
        )
        response.set_cookie(
            "lab_session",
            token,
            httponly=True,
            samesite="strict",
            secure=settings.production or request.url.scheme == "https",
            path="/",
            max_age=3600,
        )
        return response

    @app.post("/lab/reset")
    async def reset(request: Request):
        session(request, True)
        return await asyncio.to_thread(seed)

    @app.post("/lab/identity")
    async def identity(request: Request):
        session(request, True)
        data = await body(request)
        if data.get("generation") != generation:
            raise HTTPException(409, "Lab reset; reconnect victims")
        username, pem = data.get("username"), data.get("public_key")
        if (
            username not in ACCOUNTS + ("lab_lockout",)
            or not isinstance(pem, str)
            or len(pem) > 4096
        ):
            raise HTTPException(400, "Sandbox identity only")
        from crypto_engine.signatures import deserialize_public_key

        try:
            deserialize_public_key(pem.encode())
        except Exception:
            raise HTTPException(400, "Invalid public key")
        with relay._lock:
            if username in relay.clients:
                raise HTTPException(
                    409, "Disconnect the victim before replacing its identity"
                )
            with database.transaction() as conn:
                conn.execute(
                    update(users)
                    .where(users.c.username == username)
                    .values(public_key_pem=pem)
                )
        return {"ready": True}

    @app.post("/lab/arm")
    async def arm(request: Request):
        session(request, True)
        data = await body(request)
        if data.get("target") not in ACCOUNTS:
            raise HTTPException(400, "Sandbox targets only")
        try:
            return await asyncio.to_thread(
                relay.arm, data.get("action"), data["target"]
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.post("/lab/attachment-attack")
    async def attachment_attack(request: Request):
        """Corrupt or swap a stored *ciphertext* object; the victim's own checks must catch it."""
        session(request, True)
        data = await body(request)
        action = data.get("action")
        if action not in ("tamper_attachment", "swap_attachment"):
            raise HTTPException(400, "Unknown attachment attack")

        def run():
            with database.engine.connect() as conn:
                rows = conn.execute(
                    select(attachments.c.id, attachments.c.object_key)
                    .where(attachments.c.finalized_at.is_not(None), attachments.c.deleted_at.is_(None))
                    .order_by(attachments.c.created_at.desc())
                ).all()
            if not rows:
                raise HTTPException(400, "Send an attachment first")
            target = rows[0]
            if action == "tamper_attachment":
                blob = bytearray(storage.read(target.object_key))
                blob[len(blob) // 2] ^= 0xFF
                storage.write(target.object_key, bytes(blob))
            else:
                if len(rows) < 2:
                    raise HTTPException(400, "Send two attachments first")
                # Replace the newest object with another genuine ciphertext object.
                storage.write(target.object_key, storage.read(rows[1].object_key))
            relay.log_event("lab_attack_performed", action=action, target="stored attachment")
            return dict(performed=True, action=action)

        return await asyncio.to_thread(run)

    @app.get("/lab/state")
    async def state_view(request: Request):
        session(request)
        with relay.attack_lock:
            return dict(
                events=list(relay.events),
                wire=list(relay.wire),
                pending=dict(relay.pending),
                generation=generation,
            )

    @app.post("/lab/brute-force")
    async def brute_force(request: Request):
        session(request, True)

        def run():
            class Probe:
                def __init__(self):
                    self.sent = []

                def send_envelope(self, e):
                    self.sent.append(e)

                def close(self):
                    pass

            # Repeated real core login decisions and PBKDF2 against only this fixed
            # sandbox account. No URL, host, password list or external target input.
            relay.lockout.record_success("lab_lockout")
            results = []
            for _ in range(relay.lockout.threshold + 1):
                probe = Probe()
                relay.authenticate(
                    probe,
                    ("127.0.0.1", 0),
                    dict(
                        type="login",
                        username="lab_lockout",
                        password="deliberately-wrong",
                    ),
                )
                results.append(probe.sent[0])
            return dict(
                results=results, locked=relay.lockout.status("lab_lockout").locked
            )

        return await asyncio.to_thread(run)

    if (ROOT / "static/console-assets").exists():
        app.mount(
            "/console-assets", StaticFiles(directory=ROOT / "static/console-assets")
        )
    # Reuse the real gateway unchanged, scoped to this relay and origin. The lab
    # disables the unrelated evidence vault; no real receipt keys are touched.
    app.mount(
        "/",
        product_gateway(
            relay, origins=origins, include_vault=False, attachment_storage=storage
        ),
    )
    install_transport(app, settings)
    return app
