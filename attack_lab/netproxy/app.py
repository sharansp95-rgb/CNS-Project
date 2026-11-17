"""Mallory's window: a loopback-only control page for the NetProxy."""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

from .core import ACTIONS, NetProxy
from .pcap import write_pcap

STATIC = Path(__file__).parent / "static"
LESSON = (
    "TLS stops a network attacker: he sees only ciphertext, and any change breaks the connection."
)


def create_app(proxy: NetProxy, ui_port: int) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    hosts = {f"localhost:{ui_port}", f"127.0.0.1:{ui_port}"}
    origins = {f"http://{h}" for h in hosts}

    @app.middleware("http")
    async def guard(request: Request, call_next):
        # DNS-rebinding / cross-site protection for a local control page.
        if request.headers.get("host") not in hosts:
            return JSONResponse({"error": "bad host"}, status_code=403)
        if request.method == "POST":
            if request.headers.get("origin") not in origins:
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
        data = proxy.snapshot()
        data["lesson"] = LESSON
        return data

    @app.post("/api/intercept")
    async def intercept(request: Request):
        body = await request.json()
        proxy.set_intercept(bool(body.get("on")))
        return {"intercept": proxy.intercept}

    @app.post("/api/auto-resume")
    async def auto_resume(request: Request):
        proxy.auto_resume = bool((await request.json()).get("on"))
        return {"auto_resume": proxy.auto_resume}

    @app.post("/api/records/{record_id}/action")
    async def action(record_id: int, request: Request):
        body = await request.json()
        name = body.get("action")
        if name not in ACTIONS:
            raise HTTPException(400, "unknown action")
        delay = body.get("delay")
        if delay is not None:
            delay = max(0.0, min(float(delay), 30.0))
        try:
            proxy.decide(record_id, name, delay)
        except KeyError:
            raise HTTPException(409, "that record is not waiting for a decision") from None
        return {"ok": True}

    @app.post("/api/records/{record_id}/replay")
    def replay(record_id: int):
        try:
            proxy.replay(record_id)
        except (KeyError, ValueError) as exc:
            raise HTTPException(409, str(exc)) from None
        return {"ok": True}

    @app.post("/api/connections/{conn_id}/label")
    async def label(conn_id: int, request: Request):
        proxy.label_conn(conn_id, str((await request.json()).get("label", "")))
        return {"ok": True}

    @app.post("/api/clear")
    def clear():
        proxy.clear()
        return {"ok": True}

    @app.get("/api/capture.pcap")
    def capture():
        path = Path(tempfile.gettempdir()) / f"mallory-{ui_port}.pcap"
        write_pcap(proxy.raw_records(), path, proxy.port)
        return FileResponse(
            path, media_type="application/vnd.tcpdump.pcap", filename="mallory.pcap"
        )

    @app.post("/api/wireshark")
    def wireshark():
        path = Path(tempfile.gettempdir()) / f"mallory-{ui_port}.pcap"
        count = write_pcap(proxy.raw_records(), path, proxy.port)
        if not count:
            raise HTTPException(409, "nothing captured yet")
        try:
            from attack_lab.scripts.run_wireshark_demo import find_wireshark, open_in_wireshark

            if not find_wireshark():
                raise HTTPException(
                    404, "Wireshark is not installed; download /api/capture.pcap instead"
                )
            open_in_wireshark(
                str(path), proxy.port
            )  # existing demo helper: Decode-As TLS, filter tls
        except OSError as exc:
            raise HTTPException(500, f"could not start Wireshark: {type(exc).__name__}") from None
        proxy.event(
            "info",
            f"Opened {count} captured records in Wireshark (port {proxy.port} decoded as TLS)",
        )
        return {"ok": True, "packets": count}

    return app
