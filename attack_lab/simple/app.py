"""Mallory's simple window: loopback only, three buttons per message, a Reset button, a feed."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

from .core import ACTIONS, SimpleRelay

STATIC = Path(__file__).parent / "static"


def create_app(relay: SimpleRelay, ui_port: int) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    hosts = {f"localhost:{ui_port}", f"127.0.0.1:{ui_port}"}
    origins = {f"http://{h}" for h in hosts}

    @app.middleware("http")
    async def guard(request: Request, call_next):
        # Local control page: refuse DNS rebinding and cross-site requests.
        if request.headers.get("host") not in hosts:
            return JSONResponse({"error": "bad host"}, status_code=403)
        if request.method == "POST" and request.headers.get("origin") not in origins:
            return JSONResponse({"error": "bad origin"}, status_code=403)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; "
            "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def page():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/state")
    def state():
        return relay.state()

    @app.post("/api/arm")
    async def arm(request: Request):
        body = await request.json()
        action, sender = body.get("action"), body.get("sender")
        if action not in ACTIONS:
            raise HTTPException(400, "unknown action")
        try:
            return relay.arm_simple(action, sender)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None

    @app.post("/api/reset")
    def reset():
        relay.reset_view()
        return {"ok": True}

    return app
