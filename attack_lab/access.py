"""Access-code gate for the sandbox, before static assets or WebSocket admission."""

from http.cookies import SimpleCookie
from pathlib import Path

from fastapi.responses import FileResponse, JSONResponse


class LabAccessGate:
    def __init__(self, app, enabled, authorized):
        self.app, self.enabled, self.authorized = app, enabled, authorized

    async def __call__(self, scope, receive, send):
        if self.enabled and scope["type"] in ("http", "websocket"):
            path = scope.get("path")
            cookie = SimpleCookie()
            try:
                cookie.load(dict(scope.get("headers", [])).get(b"cookie", b"").decode("latin-1"))
                token = cookie["lab_session"].value if "lab_session" in cookie else None
            except Exception:
                token = None
            if path not in ("/healthz", "/lab/session") and not self.authorized(token):
                if scope["type"] == "websocket":
                    await send({"type": "websocket.close", "code": 1008})
                elif path == "/" and scope.get("method") == "GET":
                    await FileResponse(Path(__file__).with_name("access.html"))(
                        scope, receive, send
                    )
                else:
                    await JSONResponse(
                        {"detail": "Enter the lab access code first"}, status_code=401
                    )(scope, receive, send)
                return
        await self.app(scope, receive, send)
