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
        assert conn.execute(select(schema_version.c.version)).scalar_one() == 2
        assert (
            conn.execute(select(users.c.password_hash)).scalar_one()
            == "UNCHANGED_PBKDF2"
        )
        assert (
            conn.execute(select(relayed_envelopes.c.envelope_sha256)).scalar_one()
            is None
        )
        assert conn.execute(select(evidence_bundles)).all() == []
