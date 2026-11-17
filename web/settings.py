"""Shared deployment policy, with no service-specific secrets or attack logic."""

from dataclasses import dataclass
import ipaddress
import logging
import os
from urllib.parse import urlsplit

from fastapi.responses import PlainTextResponse
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware


def production():
    value = os.environ.get("APP_ENV", "development")
    if value not in ("development", "test", "production"):
        raise ValueError("APP_ENV must be development, test or production")
    return value == "production"


@dataclass(frozen=True)
class Settings:
    production: bool
    origins: frozenset[str]
    proxies: tuple[str, ...]

    @classmethod
    def load(
        cls, origins=None, default_origins="http://localhost:8080,http://127.0.0.1:8080"
    ):
        prod = production()
        configured = os.environ.get("ALLOWED_ORIGINS")
        if prod and not configured:
            raise ValueError("ALLOWED_ORIGINS is required in production")
        allowed = frozenset(
            origins
            if origins is not None
            else (
                x.strip()
                for x in (configured or default_origins).split(",")
                if x.strip()
            )
        )
        if not allowed:
            raise ValueError("Explicit origins are required")
        for origin in allowed:
            parsed = urlsplit(origin)
            if (
                parsed.scheme not in (("https",) if prod else ("https", "http"))
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.path
                or parsed.query
                or parsed.fragment
                or "*" in origin
            ):
                raise ValueError(
                    "Origins must be exact HTTP(S) origins; production requires HTTPS"
                )
        proxies = tuple(
            x.strip()
            for x in os.environ.get("FORWARDED_ALLOW_IPS", "").split(",")
            if x.strip()
        )
        if prod and not proxies:
            raise ValueError(
                "FORWARDED_ALLOW_IPS must name trusted ingress proxies in production"
            )
        for proxy in proxies:
            network = ipaddress.ip_network(proxy, strict=False)
            if network.prefixlen == 0:
                raise ValueError(
                    "Trust explicit proxy addresses/networks, never all IPs"
                )
        return cls(prod, allowed, proxies)


class TransportPolicy:
    def __init__(self, app, enabled):
        self.app, self.enabled = app, enabled

    async def __call__(self, scope, receive, send):
        if self.enabled and scope["type"] in ("http", "websocket"):
            secure = scope.get("scheme") in ("https", "wss")
            if not secure and not (
                scope["type"] == "http" and scope.get("path") == "/healthz"
            ):
                logging.getLogger("uvicorn.error").warning(
                    "HTTPS required; untrusted/direct peer %s",
                    (scope.get("client") or ("unknown",))[0],
                )
                if scope["type"] == "websocket":
                    await send({"type": "websocket.close", "code": 1008})
                else:
                    await PlainTextResponse("HTTPS required", status_code=403)(
                        scope, receive, send
                    )
                return

            async def secure_send(message):
                if message["type"] == "http.response.start":
                    message = dict(
                        message,
                        headers=list(message.get("headers", []))
                        + [(b"strict-transport-security", b"max-age=31536000")],
                    )
                await send(message)

            await self.app(scope, receive, secure_send)
            return
        await self.app(scope, receive, send)


class IngressDiagnostics:
    """Record the socket boundary before forwarding headers change the scope."""

    def __init__(self, app, enabled):
        self.app, self.enabled = app, enabled

    async def __call__(self, scope, receive, send):
        if self.enabled and scope["type"] == "http" and scope.get("path") == "/":
            # Log IP literals only: never arbitrary header text, URLs or credentials.
            chain = []
            for key, value in scope.get("headers", []):
                if key.lower() == b"x-forwarded-for":
                    for address in value.decode("latin-1").split(",")[:16]:
                        try:
                            chain.append(str(ipaddress.ip_address(address.strip())))
                        except ValueError:
                            chain.append("invalid")
            logging.getLogger("uvicorn.error").info(
                "Transport ingress peer %s; original scheme %s; forwarded IP chain %s",
                (scope.get("client") or ("unknown",))[0],
                scope.get("scheme"),
                ",".join(chain) or "none",
            )
        await self.app(scope, receive, send)


def install_transport(app, settings):
    app.add_middleware(TransportPolicy, enabled=settings.production)
    # Apply the actual Uvicorn middleware once, including under TestClient.
    # Entrypoints disable Uvicorn's automatic duplicate wrapper.
    app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=list(settings.proxies))
    app.add_middleware(IngressDiagnostics, enabled=settings.production)
