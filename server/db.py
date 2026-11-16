"""SQLAlchemy 2 persistence shared by server adapters and migration tooling.

No network or filesystem work at import time. Schema v1 is intentionally small;
future schema changes must add an explicit migration, not rely on create_all.
"""
import base64
import binascii
from contextlib import contextmanager
import json
import os
from pathlib import Path
import threading
import time

from sqlalchemy import (JSON, Column, Float, Integer, MetaData, String, Table, Text,
                        create_engine, delete, event, insert, select, text)
from sqlalchemy.engine import URL, make_url
from sqlalchemy.pool import StaticPool

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE_URL = URL.create("sqlite", database=str(PROJECT_ROOT / "data" / "securechat.db"))
SCHEMA_VERSION = 1
metadata = MetaData()
users = Table("users", metadata,
    Column("username", Text, primary_key=True),
    Column("password_hash", Text, nullable=False),
    Column("public_key_pem", Text),
    Column("created_at", Float, nullable=False))
login_lockouts = Table("login_lockouts", metadata,
    Column("username", Text, primary_key=True),
    Column("failure_count", Integer, nullable=False),
    Column("locked_until", Float, nullable=False),
    Column("last_failure_at", Float),
    Column("lock_level", Integer, nullable=False),
    Column("failure_timestamps", JSON, nullable=False))
security_events = Table("security_events", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ts", Float, nullable=False, index=True),
    Column("event_type", Text, nullable=False),
    Column("username", Text), Column("peer_addr", Text),
    Column("details", JSON, nullable=False),
    # Canonical event digest + occurrence ordinal: idempotent JSONL import,
    # including repeated identical lines. Live events use this same identity.
    Column("import_key", String(100), unique=True))
relayed_envelopes = Table("relayed_envelopes", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ts", Float, nullable=False, index=True),
    Column("sender", Text, nullable=False), Column("recipient", Text),
    Column("envelope_type", Text, nullable=False),
    Column("size_bytes", Integer, nullable=False), Column("ciphertext_b64", Text))
schema_version = Table("schema_version", metadata,
    Column("version", Integer, primary_key=True))


class Database:
    def __init__(self, url):
        url = make_url(url)
        kwargs = {"pool_pre_ping": True}
        if url.get_backend_name() == "sqlite":
            if url.database and url.database != ":memory:":
                Path(url.database).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
            if not url.database or url.database == ":memory:":
                kwargs["poolclass"] = StaticPool
        self.engine = create_engine(url, **kwargs)
        self._lock = threading.RLock()
        if self.engine.dialect.name == "sqlite":
            @event.listens_for(self.engine, "connect")
            def sqlite_options(conn, _record):
                conn.execute("PRAGMA foreign_keys=ON")
                conn.execute("PRAGMA busy_timeout=30000")
        with self.transaction() as conn:
            schema_version.create(conn, checkfirst=True)
            versions = conn.execute(select(schema_version.c.version)).scalars().all()
            if not versions:
                conn.execute(insert(schema_version).values(version=SCHEMA_VERSION))
            elif versions != [SCHEMA_VERSION]:
                raise RuntimeError(f"Unsupported database schema version: {versions}")
            metadata.create_all(conn)

    @contextmanager
    def transaction(self):
        """Serialize short mutations, also across processes on either backend.

        This single-relay phase favors correctness over write throughput. Postgres
        uses a transaction advisory lock; SQLite reserves its writer up front.
        PBKDF2 is always performed outside this transaction.
        """
        with self._lock, self.engine.connect() as conn:
            try:
                if self.engine.dialect.name == "sqlite":
                    conn.exec_driver_sql("BEGIN IMMEDIATE")
                elif self.engine.dialect.name == "postgresql":
                    conn.execute(text("SELECT pg_advisory_xact_lock(1515001)"))
                yield conn
                conn.commit()
            except BaseException:
                conn.rollback()
                raise


_databases = {}
_cache_lock = threading.Lock()


def get_database(url=None):
    url = make_url(url or os.environ.get("DATABASE_URL") or DEFAULT_DATABASE_URL)
    with _cache_lock:
        if url not in _databases:
            _databases[url] = Database(url)
        return _databases[url]


def dispose_databases():
    """Release cached engines (tests, tooling, or a simulated process restart)."""
    with _cache_lock:
        for database in _databases.values():
            database.engine.dispose()
        _databases.clear()


def record_relay(envelope, sender, database=None):
    """Store only allowlisted relay metadata and validated base64 ciphertext.

    Handshakes have no ciphertext; their public keys/signatures are not archived.
    Never serialize whole envelopes: unexpected fields must not enter storage.
    """
    if os.environ.get("SECURECHAT_STORE_ENVELOPES", "1").lower() in ("0", "false", "no", "off"):
        return
    if envelope.get("type") not in ("chat", "handshake_init", "handshake_response"):
        return
    cap = int(os.environ.get("SECURECHAT_ENVELOPE_MAX_ROWS", "10000"))
    if cap < 1:
        raise ValueError("SECURECHAT_ENVELOPE_MAX_ROWS must be positive")
    ciphertext = envelope.get("ciphertext") if envelope.get("type") == "chat" else None
    if ciphertext is not None:
        try:
            base64.b64decode(ciphertext, validate=True)
        except (ValueError, TypeError, binascii.Error):
            ciphertext = None
    database = database or get_database()
    with database.transaction() as conn:
        conn.execute(insert(relayed_envelopes).values(
            ts=time.time(), sender=sender, recipient=envelope.get("to"),
            envelope_type=envelope["type"],
            size_bytes=len((json.dumps(envelope) + "\n").encode("utf-8")),
            ciphertext_b64=ciphertext))
        cutoff = conn.execute(select(relayed_envelopes.c.id).order_by(
            relayed_envelopes.c.id.desc()).offset(cap).limit(1)).scalar_one_or_none()
        if cutoff is not None:
            conn.execute(delete(relayed_envelopes).where(relayed_envelopes.c.id <= cutoff))
