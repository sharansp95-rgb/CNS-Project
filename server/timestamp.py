"""Server-clock receipts, not an accredited timestamping authority."""

import base64
import os
from collections import Counter
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import or_, select

from crypto_engine.evidence_tools import key_id
from crypto_engine.hash_chain import canonical_json
from server.db import relayed_envelopes
from tools.generate_tsa_key import generate


class TimestampSigner:
    def __init__(self):
        from web.settings import production

        supplied = os.environ.get("TSA_PRIVATE_KEY")
        if production() and not supplied:
            raise ValueError(
                "TSA_PRIVATE_KEY is required in production; disk generation is disabled"
            )
        if supplied:
            try:
                data = (
                    supplied.encode("ascii")
                    if "-----BEGIN" in supplied
                    else base64.b64decode(supplied, validate=True)
                )
            except (ValueError, UnicodeError) as exc:
                raise ValueError("TSA_PRIVATE_KEY must be PEM or base64 PEM") from exc
        else:
            data = generate().read_bytes()
        self.private = serialization.load_pem_private_key(data, password=None)
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
                            relayed_envelopes.c.envelope_sha256.in_(unique[offset : offset + 400]),
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
        body["signature"] = base64.b64encode(self.private.sign(canonical_json(body))).decode(
            "ascii"
        )
        return body
