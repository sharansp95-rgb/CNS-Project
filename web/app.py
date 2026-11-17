"""Hardened WebSocket transport; crypto remains exclusively in the clients."""

import asyncio
from collections import deque
from contextlib import asynccontextmanager, suppress
import json
import os
from pathlib import Path
import threading
import time

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from server.relay_core import RelayCore, RELAYED_TYPES
from web.settings import Settings, install_transport

STATIC = Path(__file__).with_name("static")
ALLOWED_TYPES = RELAYED_TYPES | {"register", "login", "get_pubkey", "security_alert"}


class WebSocketPeer:
    """Bounded async outbox; synchronous relay threads never touch the ASGI socket.

    call_soon_threadsafe only schedules work, so the relay never waits for its
    own event loop while holding a roster lock. Slow peers are disconnected.
    """

    def __init__(self, websocket, vault=None):
        self.vault = vault  # any TokenStore: issues HTTP bearer tokens at login
        self.token = None
        self.attempted_username = None
        self.websocket = websocket
        self.loop = asyncio.get_running_loop()
        self.outbox = asyncio.Queue(maxsize=128)
        self.closed = threading.Event()

    def send_envelope(self, envelope):
        if self.closed.is_set():
            return
        if (
            self.vault
            and envelope.get("type") in ("register_result", "login_result")
            and envelope.get("success")
        ):
            self.token = self.vault.issue(self.attempted_username)
            envelope = dict(envelope, api_token=self.token)

        def put():
            if self.closed.is_set():
                return
            try:
                self.outbox.put_nowait(envelope)
            except asyncio.QueueFull:
                self.close(1013)

        self.loop.call_soon_threadsafe(put)

    def close(self, code=1000):
        if not self.closed.is_set():
            self.closed.set()

            async def close_socket():
                with suppress(RuntimeError, WebSocketDisconnect):
                    await self.websocket.close(code=code)

            self.loop.call_soon_threadsafe(lambda: asyncio.create_task(close_socket()))

    async def write_loop(self):
        while True:
            await self.websocket.send_json(await self.outbox.get())


def create_app(
    relay=None,
    *,
    origins=None,
    max_frame_size=None,
    rate_limit=None,
    idle_timeout=None,
    include_vault=True,
    attachment_storage=None,
):
    settings = Settings.load(
        origins,
        os.environ.get(
            "SECURECHAT_ALLOWED_ORIGINS", "http://localhost:8080,http://127.0.0.1:8080"
        ),
    )
    allowed_origins = settings.origins
    signer = None
    if settings.production and include_vault:
        from server.db import normalize_url
        from server.timestamp import TimestampSigner

        if (
            not os.environ.get("DATABASE_URL")
            or normalize_url(os.environ["DATABASE_URL"]).get_backend_name()
            != "postgresql"
        ):
            raise ValueError(
                "Production main service requires a PostgreSQL DATABASE_URL"
            )
        signer = TimestampSigner()  # validate before opening the database
    max_size = int(max_frame_size or os.environ.get("SECURECHAT_WS_MAX_BYTES", "65536"))
    rate = int(rate_limit or os.environ.get("SECURECHAT_WS_RATE_LIMIT", "60"))
    idle = float(idle_timeout or os.environ.get("SECURECHAT_WS_IDLE_SECONDS", "120"))
    if not allowed_origins or "*" in allowed_origins or min(max_size, rate, idle) <= 0:
        raise ValueError("Explicit origins and positive WebSocket limits are required")
    core = relay or RelayCore()

    @asynccontextmanager
    async def lifespan(app):
        yield
        # A standalone core owns only WS peers; shared TCP lifecycle belongs
        # to server.main. Close just this app's sockets during shutdown.
        for peer in list(app.state.peers):
            peer.close(1001)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.relay = core
    app.state.peers = set()
    from web.vault_api import VaultAPI

    vault = VaultAPI(app, core.database) if include_vault else None
    if vault and signer:
        vault.signer = signer
    app.state.vault = vault
    # Attachments reuse the login-issued bearer tokens. The Attack Lab runs
    # without the evidence vault but still gets a (local-storage) attachment API.
    from web.tokens import TokenStore
    from web.attachments_api import AttachmentAPI
    from server.storage import storage_from_env

    tokens = vault or TokenStore()
    storage = attachment_storage or storage_from_env(production=settings.production and include_vault)
    app.state.storage = storage
    AttachmentAPI(app, core.database, storage, tokens)
    connect_src = "'self'" + (f" {storage.origin}" if storage.kind == "s3" else "")
    csp = (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data: blob:; media-src blob:; font-src 'self'; "
        f"connect-src {connect_src}; object-src 'none'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    app.state.csp = csp

    @app.get("/healthz")
    async def health():
        from sqlalchemy import text
        from fastapi.responses import JSONResponse

        def check():
            with core.database.engine.connect() as connection:
                connection.execute(text("SELECT 1"))

        try:
            await asyncio.to_thread(check)
            return {"status": "ok"}
        except Exception:
            return JSONResponse({"status": "unavailable"}, status_code=503)

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers.update(
            {
                "Content-Security-Policy": csp,
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "X-Frame-Options": "DENY",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                "Cache-Control": "no-store",
            }
        )
        return response

    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket):
        if ws.headers.get("origin") not in allowed_origins:
            await ws.close(code=1008)
            return
        await ws.accept()
        peer = WebSocketPeer(ws, tokens)
        app.state.peers.add(peer)
        writer = asyncio.create_task(peer.write_loop())
        addr = (ws.client.host if ws.client else "unknown", 0)
        name = None
        attempts = deque()
        try:
            while not peer.closed.is_set():
                incoming = await asyncio.wait_for(ws.receive(), timeout=idle)
                if incoming["type"] == "websocket.disconnect":
                    break
                raw = incoming.get("text")
                if raw is None:
                    await ws.close(code=1003)
                    break
                if len(raw.encode("utf-8")) > max_size:
                    await ws.close(code=1009)
                    break
                now = time.monotonic()
                while attempts and now - attempts[0] > 10:
                    attempts.popleft()
                if len(attempts) >= rate:
                    await ws.close(code=1008)
                    break
                attempts.append(now)
                try:
                    envelope = json.loads(raw)
                except (ValueError, RecursionError):
                    await ws.close(code=1008)
                    break
                if (
                    not isinstance(envelope, dict)
                    or not isinstance(envelope.get("type"), str)
                    or envelope["type"] not in ALLOWED_TYPES
                ):
                    await asyncio.to_thread(
                        core.log_event,
                        "unsupported_envelope",
                        username=name,
                        from_addr=addr[0],
                        envelope_type="unknown type",
                    )
                    await ws.close(code=1008)
                    break
                if any(
                    field in envelope and not isinstance(envelope[field], str)
                    for field in ("to", "from", "username", "password", "public_key")
                ):
                    await ws.close(code=1008)
                    break
                if name is None:
                    peer.attempted_username = envelope.get("username")
                    name = await asyncio.to_thread(
                        core.authenticate, peer, addr, envelope
                    )
                else:
                    await asyncio.to_thread(
                        core.handle_authenticated, peer, addr, name, envelope
                    )
        except asyncio.TimeoutError:
            await ws.close(code=1001)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            tokens.revoke(peer.token)
            peer.closed.set()
            writer.cancel()
            with suppress(asyncio.CancelledError, RuntimeError, WebSocketDisconnect):
                await writer
            app.state.peers.discard(peer)
            removed = await asyncio.to_thread(core.remove_client, peer)
            if removed:
                await asyncio.to_thread(
                    core.broadcast_system, f"*** {removed} left the chat ***"
                )
                await asyncio.to_thread(
                    core.broadcast_event, {"type": "user_left", "username": removed}
                )

    @app.get("/verify")
    @app.get("/evidence")
    @app.get("/")
    async def index():
        if not (STATIC / "index.html").exists():
            from fastapi.responses import PlainTextResponse

            return PlainTextResponse(
                "Build the frontend: cd web/frontend && npm ci && npm run build",
                status_code=503,
            )
        return FileResponse(STATIC / "index.html")

    if (STATIC / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=STATIC / "assets"), name="assets")
    install_transport(app, settings)
    return app
