"""Login-issued API tokens plus the public timestamp-key endpoint."""

import asyncio
import threading

from server.timestamp import TimestampSigner
from web.tokens import TokenStore


class VaultAPI(TokenStore):
    def __init__(self, app, database):
        super().__init__()
        self.database = database
        self.signer = None
        self.signer_lock = threading.Lock()

        @app.get("/api/timestamp-key")
        async def timestamp_key():
            return await asyncio.to_thread(lambda: self.get_signer().public_info())

    def get_signer(self):
        with self.signer_lock:
            if self.signer is None:
                self.signer = TimestampSigner()
            return self.signer
