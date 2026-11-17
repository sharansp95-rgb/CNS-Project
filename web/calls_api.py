"""ICE server configuration for voice calls, with short-lived TURN credentials.

The long-term Metered secret key lives only in this process's environment. It is
sent to Metered in a query string (their API requires that), so this module:
  * never logs or formats a URL/exception that could contain it (only the
    exception *type* is logged, and the httpx/httpcore loggers are silenced),
  * never returns it to browsers: clients receive only a per-call username and
    credential that Metered expires after at most MAX_TTL seconds,
  * rate-limits the endpoint per authenticated user.
If TURN is unconfigured or Metered fails (for example the free quota is used up)
the endpoint degrades to STUN only and says so; calls still work when a direct
path exists.
"""

from collections import defaultdict, deque
import logging
import os
import re
import secrets
import threading
import time

import httpx
from fastapi import HTTPException, Request

# httpx logs every request URL at INFO: that would include the secret key.
for _name in ("httpx", "httpcore", "httpcore.http11", "httpcore.connection"):
    logging.getLogger(_name).setLevel(logging.WARNING)

MAX_TTL = 600
DEFAULT_STUN = "stun:stun.cloudflare.com:3478,stun:stun.l.google.com:19302"
_APP = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
log = logging.getLogger("securechat.calls")


class CallsAPI:
    def __init__(self, app, tokens, client_factory=None, rate=None):
        self.tokens = tokens
        self.client_factory = client_factory or (lambda: httpx.Client(timeout=8.0))
        self.rate = int(rate or os.environ.get("CALL_ICE_PER_MINUTE", "10"))
        self._rates = defaultdict(deque)
        self._lock = threading.Lock()
        stun = os.environ.get("CALL_STUN_URLS", DEFAULT_STUN)
        self.stun = [u.strip() for u in stun.split(",") if u.strip()]
        self.app_name = os.environ.get("METERED_APP", "").strip().lower()
        self._secret = os.environ.get("METERED_SECRET_KEY", "")
        if self._secret and not _APP.match(self.app_name):
            raise ValueError("METERED_APP must be your Metered app name (letters, digits, hyphens)")
        self.ttl = min(MAX_TTL, int(os.environ.get("CALL_TURN_TTL_SECONDS", MAX_TTL)))

        @app.get("/api/calls/ice")
        async def ice(request: Request):
            import asyncio

            owner = self.tokens.owner(request)
            self._limit(owner)
            return await asyncio.to_thread(self.ice_servers)

    @property
    def turn_configured(self):
        return bool(self._secret and self.app_name)

    def _limit(self, owner):
        now = time.monotonic()
        with self._lock:
            times = self._rates[owner]
            while times and now - times[0] > 60:
                times.popleft()
            if len(times) >= self.rate:
                raise HTTPException(429, "Too many call setups; wait a minute")
            times.append(now)

    def ice_servers(self):
        servers = [{"urls": u} for u in self.stun]
        if not self.turn_configured:
            return {"iceServers": servers, "turn": "not_configured"}
        try:
            servers += self._turn_servers()
            return {"iceServers": servers, "turn": "available"}
        except Exception as exc:  # never include the exception text: it can contain the URL
            log.warning("TURN credentials unavailable (%s); calls fall back to direct only", type(exc).__name__)
            return {"iceServers": servers, "turn": "unavailable"}

    def _turn_servers(self):
        base = f"https://{self.app_name}.metered.live/api/v1/turn"
        with self.client_factory() as client:
            made = client.post(
                f"{base}/credential",
                params={"secretKey": self._secret},
                # An opaque random label: no user name is ever sent to the provider.
                json={"expiryInSeconds": self.ttl, "label": "call-" + secrets.token_hex(6)},
            )
            if made.status_code != 200:
                raise RuntimeError(f"credential request status {made.status_code}")
            cred = made.json()
            username, password, api_key = cred["username"], cred["password"], cred["apiKey"]
            if not all(isinstance(x, str) and x for x in (username, password, api_key)):
                raise RuntimeError("malformed credential")
            listed = client.get(f"{base}/credentials", params={"apiKey": api_key})
            if listed.status_code == 200 and isinstance(listed.json(), list):
                servers = [
                    {"urls": s["urls"], "username": s.get("username", username), "credential": s.get("credential", password)}
                    for s in listed.json()
                    if isinstance(s, dict) and "urls" in s and str(s["urls"]).startswith(("turn:", "turns:"))
                ]
                if servers:
                    return servers
        return [{
            "urls": ["turn:global.relay.metered.ca:80", "turn:global.relay.metered.ca:80?transport=tcp",
                     "turn:global.relay.metered.ca:443", "turns:global.relay.metered.ca:443?transport=tcp"],
            "username": username, "credential": password,
        }]
