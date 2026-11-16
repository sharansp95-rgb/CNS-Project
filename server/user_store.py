"""Database-backed accounts; PBKDF2 encoding and public API are unchanged.

The legacy `path` argument selects a sibling .db file for isolated callers.
JSON files are imported explicitly with tools/migrate_json_to_db.py.
"""
import os
from pathlib import Path
import time

from sqlalchemy import insert, select
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError

from auth.password_hash import hash_password, verify_password
try:
    from .db import get_database, users
except ImportError:  # python server/server.py
    from db import get_database, users

DEFAULT_STORE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "users.json")


def _database(path):
    if os.fspath(path) == DEFAULT_STORE_PATH:
        return get_database()
    target = Path(path).resolve()
    if target.suffix == ".json":
        target = target.with_suffix(".db")
    return get_database(URL.create("sqlite", database=str(target)))


def register_user(username: str, password: str, public_key_pem: str = None,
                  path: str = DEFAULT_STORE_PATH) -> bool:
    """Register an account, returning False for empty credentials/duplicates."""
    if not username or not password:
        return False
    database = _database(path)
    if user_exists(username, path):
        return False
    encoded = hash_password(password)
    try:
        with database.transaction() as conn:
            conn.execute(insert(users).values(username=username, password_hash=encoded,
                public_key_pem=public_key_pem, created_at=time.time()))
    except IntegrityError:
        return False
    return True


def verify_user(username: str, password: str, path: str = DEFAULT_STORE_PATH) -> bool:
    with _database(path).engine.connect() as conn:
        encoded = conn.execute(select(users.c.password_hash).where(
            users.c.username == username)).scalar_one_or_none()
    if encoded is None:
        return False
    try:
        return verify_password(password, encoded)
    except Exception:
        return False


def user_exists(username: str, path: str = DEFAULT_STORE_PATH) -> bool:
    with _database(path).engine.connect() as conn:
        return conn.execute(select(users.c.username).where(
            users.c.username == username)).first() is not None


def get_public_key(username: str, path: str = DEFAULT_STORE_PATH):
    with _database(path).engine.connect() as conn:
        return conn.execute(select(users.c.public_key_pem).where(
            users.c.username == username)).scalar_one_or_none()
