"""Database-backed accounts; PBKDF2 encoding and public API are unchanged.

The legacy `path` argument selects a sibling .db file for isolated callers.
JSON files are imported explicitly with tools/migrate_json_to_db.py.
"""

import os
import time
from pathlib import Path

from sqlalchemy import insert, select
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError

from auth.password_hash import hash_password, verify_password

try:
    from .db import Database, get_database, users
except ImportError:  # python server/server.py
    from db import Database, get_database, users

DEFAULT_STORE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "users.json"
)


def _database(path):
    if os.fspath(path) == DEFAULT_STORE_PATH:
        return get_database()
    target = Path(path).resolve()
    if target.suffix == ".json":
        target = target.with_suffix(".db")
    return get_database(URL.create("sqlite", database=str(target)))


class DatabaseUserStore:
    """Account adapter bound to one explicit database; never changes process globals."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def register_user(
        self, username: str, password: str, public_key_pem: str | None = None
    ) -> bool:
        """Hash and insert a nonempty unique account; return whether it was stored."""
        if not username or not password or self.user_exists(username):
            return False
        encoded = hash_password(password)
        try:
            with self.database.transaction() as conn:
                conn.execute(
                    insert(users).values(
                        username=username,
                        password_hash=encoded,
                        public_key_pem=public_key_pem,
                        created_at=time.time(),
                    )
                )
        except IntegrityError:
            return False
        return True

    def verify_user(self, username: str, password: str) -> bool:
        """Check a password against the unchanged stored PBKDF2 encoding."""
        with self.database.engine.connect() as conn:
            encoded = conn.execute(
                select(users.c.password_hash).where(users.c.username == username)
            ).scalar_one_or_none()
        if encoded is None:
            return False
        try:
            return verify_password(password, encoded)
        except Exception:
            return False

    def user_exists(self, username: str) -> bool:
        """Return whether the username exists in this store."""
        with self.database.engine.connect() as conn:
            return (
                conn.execute(select(users.c.username).where(users.c.username == username)).first()
                is not None
            )

    def get_public_key(self, username: str) -> str | None:
        """Return the stored public PEM, or None when unavailable."""
        with self.database.engine.connect() as conn:
            return conn.execute(
                select(users.c.public_key_pem).where(users.c.username == username)
            ).scalar_one_or_none()


def register_user(
    username: str, password: str, public_key_pem: str = None, path: str = DEFAULT_STORE_PATH
) -> bool:
    """Register through the legacy path-selecting account API."""
    return DatabaseUserStore(_database(path)).register_user(username, password, public_key_pem)


def verify_user(username: str, password: str, path: str = DEFAULT_STORE_PATH) -> bool:
    """Verify a password in the selected store."""
    return DatabaseUserStore(_database(path)).verify_user(username, password)


def user_exists(username: str, path: str = DEFAULT_STORE_PATH) -> bool:
    """Return whether the selected store contains the username."""
    return DatabaseUserStore(_database(path)).user_exists(username)


def get_public_key(username: str, path: str = DEFAULT_STORE_PATH) -> str | None:
    """Return the selected account's public PEM, never private material."""
    return DatabaseUserStore(_database(path)).get_public_key(username)
