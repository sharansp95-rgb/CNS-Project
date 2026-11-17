"""Run only with a distinct disposable TEST_DATABASE_URL; default suite stays offline."""

import os
import pytest
from sqlalchemy import create_engine, select
from server.db import (
    get_database,
    users,
    schema_version,
    relayed_envelopes,
    evidence_bundles,
)

pytestmark = pytest.mark.skipif(
    not os.environ.get("TEST_DATABASE_URL"),
    reason="Disposable Neon TEST_DATABASE_URL not supplied",
)


def test_postgres_upgrade_v1_to_v2_preserves_rows():
    engine = create_engine(os.environ["DATABASE_URL"])
    try:
        with engine.begin() as conn:
            conn.exec_driver_sql(
                "CREATE TABLE schema_version (version INTEGER PRIMARY KEY)"
            )
            conn.exec_driver_sql("INSERT INTO schema_version VALUES (1)")
            conn.exec_driver_sql(
                "CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, public_key_pem TEXT, created_at FLOAT NOT NULL)"
            )
            conn.exec_driver_sql(
                "INSERT INTO users VALUES ('legacy', 'UNCHANGED_PBKDF2', NULL, 1)"
            )
            conn.exec_driver_sql(
                "CREATE TABLE relayed_envelopes (id SERIAL PRIMARY KEY, ts FLOAT NOT NULL, sender TEXT NOT NULL, recipient TEXT, envelope_type TEXT NOT NULL, size_bytes INTEGER NOT NULL, ciphertext_b64 TEXT)"
            )
            conn.exec_driver_sql(
                "INSERT INTO relayed_envelopes (ts,sender,envelope_type,size_bytes) VALUES (1,'legacy','chat',1)"
            )
    finally:
        engine.dispose()
    database = get_database()
    with database.engine.connect() as conn:
        assert conn.execute(select(schema_version.c.version)).scalar_one() == 3
        assert (
            conn.execute(select(users.c.password_hash)).scalar_one()
            == "UNCHANGED_PBKDF2"
        )
        assert (
            conn.execute(select(relayed_envelopes.c.envelope_sha256)).scalar_one()
            is None
        )
        assert conn.execute(select(evidence_bundles)).all() == []


def test_postgres_upgrade_v2_to_v3_adds_attachments_and_preserves_rows():
    from sqlalchemy import inspect
    from server.db import attachments

    engine = create_engine(os.environ["DATABASE_URL"])
    try:
        with engine.begin() as conn:
            conn.exec_driver_sql("CREATE TABLE schema_version (version INTEGER PRIMARY KEY)")
            conn.exec_driver_sql("INSERT INTO schema_version VALUES (2)")
            conn.exec_driver_sql(
                "CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, public_key_pem TEXT, created_at FLOAT NOT NULL)"
            )
            conn.exec_driver_sql("INSERT INTO users VALUES ('legacy', 'UNCHANGED_PBKDF2', NULL, 1)")
            conn.exec_driver_sql(
                "CREATE TABLE relayed_envelopes (id SERIAL PRIMARY KEY, ts FLOAT NOT NULL, sender TEXT NOT NULL, recipient TEXT, envelope_type TEXT NOT NULL, size_bytes INTEGER NOT NULL, ciphertext_b64 TEXT, envelope_sha256 VARCHAR(64))"
            )
            conn.exec_driver_sql(
                "INSERT INTO relayed_envelopes (ts,sender,envelope_type,size_bytes,envelope_sha256) VALUES (1,'legacy','chat',1,'" + "a" * 64 + "')"
            )
    finally:
        engine.dispose()
    database = get_database()
    with database.engine.connect() as conn:
        assert conn.execute(select(schema_version.c.version)).scalar_one() == 3
        assert conn.execute(select(users.c.password_hash)).scalar_one() == "UNCHANGED_PBKDF2"
        assert conn.execute(select(relayed_envelopes.c.envelope_sha256)).scalar_one() == "a" * 64
        assert conn.execute(select(attachments)).all() == []
        names = {i["name"] for i in inspect(conn).get_indexes("attachments")}
        assert any("uploader" in n for n in names) and any("expires_at" in n for n in names)
    # A second startup is a no-op and a real row round-trips.
    from server.db import dispose_databases
    import time
    dispose_databases()
    database = get_database()
    with database.transaction() as conn:
        conn.execute(attachments.insert().values(
            id="a" * 32, uploader="legacy", recipient="x", kind="image", object_key="att/" + "b" * 32,
            ciphertext_size=10, ciphertext_sha256="c" * 64, created_at=time.time(), expires_at=time.time() + 1))
    with database.engine.connect() as conn:
        assert conn.execute(select(attachments.c.id)).scalar_one() == "a" * 32
