"""Opt-in, disposable PostgreSQL schemas; never select the service database."""

from contextlib import contextmanager
import uuid
from sqlalchemy import create_engine
from server.db import normalize_url


def disposable_test_url(test_url, service_url):
    if not test_url or not service_url:
        raise ValueError(
            "Set both TEST_DATABASE_URL and DATABASE_URL for the safety comparison"
        )
    test, service = normalize_url(test_url), normalize_url(service_url)
    if test.get_backend_name() != "postgresql":
        raise ValueError("TEST_DATABASE_URL must be PostgreSQL")

    def identity(url):
        return (
            url.get_backend_name(),
            (url.host or "").lower().replace("-pooler.", "."),
            url.port or 5432,
            url.database,
        )

    if identity(test) == identity(service):
        raise ValueError(
            "TEST_DATABASE_URL must use a separate disposable database/Neon branch"
        )
    if "-pooler." in (test.host or ""):
        raise ValueError(
            "Use the direct (unpooled) Neon test connection for schema isolation"
        )
    if test.query.get("options"):
        raise ValueError("TEST_DATABASE_URL must not supply session options")
    return test


@contextmanager
def postgres_schema(test_url, service_url):
    url = disposable_test_url(test_url, service_url)
    name = "cns_test_" + uuid.uuid4().hex
    engine = create_engine(
        url,
        pool_pre_ping=True,
        pool_size=1,
        max_overflow=0,
        connect_args={"connect_timeout": 15},
    )
    try:
        with engine.begin() as conn:
            conn.exec_driver_sql(f'CREATE SCHEMA "{name}"')
        try:
            yield url.update_query_dict(
                {"options": f"-csearch_path={name}"}
            ).render_as_string(hide_password=False)
        finally:
            with engine.begin() as conn:
                conn.exec_driver_sql(f'DROP SCHEMA "{name}" CASCADE')
    finally:
        engine.dispose()
