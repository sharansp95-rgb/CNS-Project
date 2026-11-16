"""Server-clock receipts, not an accredited timestamping authority."""

import base64
from collections import Counter
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select, or_
from crypto_engine.hash_chain import canonical_json
from crypto_engine.evidence_tools import key_id
from tools.generate_tsa_key import generate
from server.db import relayed_envelopes


class TimestampSigner:
    def __init__(self):
        self.private = serialization.load_pem_private_key(
            generate().read_bytes(), password=None
        )
        if not isinstance(self.private, Ed25519PrivateKey):
            raise ValueError("TSA key must be a dedicated Ed25519 private key")
        self.public = self.private.public_key()
        self.key_id = key_id(self.public)

    def public_info(self):
        return dict(
            algorithm="Ed25519",
            key_id=self.key_id,
            public_key_pem=self.public.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii"),
        )

    def receipt(self, conn, owner, file_sha256, version, hashes, total):
        count = "not available"
        if version == 2:
            # Match only the owner's retained traffic; consume duplicate rows
            # at most once. A claim is not proof of the encrypted file's contents.
            found = []
            unique = list(set(hashes))
            for offset in range(0, len(unique), 400):
                found.extend(
                    conn.execute(
                        select(relayed_envelopes.c.envelope_sha256).where(
                            relayed_envelopes.c.envelope_type == "chat",
                            relayed_envelopes.c.envelope_sha256.in_(
                                unique[offset : offset + 400]
                            ),
                            or_(
                                relayed_envelopes.c.sender == owner,
                                relayed_envelopes.c.recipient == owner,
                            ),
                        )
                    )
                    .scalars()
                    .all()
                )
            observed = Counter(found)
            claimed = Counter(hashes)
            count = sum(min(n, observed[h]) for h, n in claimed.items())
        body = dict(
            receipt_version=1,
            file_sha256=file_sha256,
            server_time=datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            key_id=self.key_id,
            corroborated=count,
            total=total,
        )
        body["signature"] = base64.b64encode(
            self.private.sign(canonical_json(body))
        ).decode("ascii")
        return body
