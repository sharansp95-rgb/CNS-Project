"""In-memory bearer tokens issued at WebSocket login and used for HTTP APIs.

Tokens are never persisted, logged or shown in the Wire Log; they die with the
process and are revoked when the issuing socket closes.
"""

import secrets
import threading
import time

from fastapi import HTTPException, Request


class TokenStore:
    def __init__(self):
        self.tokens = {}
        self.lock = threading.Lock()

    def issue(self, owner):
        token = secrets.token_urlsafe(32)
        with self.lock:
            now = time.monotonic()
            self.tokens = {t: v for t, v in self.tokens.items() if v[1] > now}
            self.tokens[token] = (owner, now + 3600)
        return token

    def revoke(self, token):
        with self.lock:
            self.tokens.pop(token, None)

    def owner(self, request: Request):
        header = request.headers.get("authorization", "")
        token = header[7:] if header.startswith("Bearer ") else ""
        with self.lock:
            value = self.tokens.get(token)
            if value is None or value[1] <= time.monotonic():
                raise HTTPException(401, "Log in over WebSocket to access this API")
            return value[0]
