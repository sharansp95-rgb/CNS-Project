"""Database security events with an append-only JSONL dashboard mirror.

Events are JSON lines in logs/security_events.jsonl (gitignored -- see
.gitignore): one compact JSON object per line, each carrying at least `ts`
(Unix seconds) and `event` (a short event-type string). This file is
used by authentication, protocol rejection and client security alerts.

Never logs a password, a private key, a session key, or message plaintext --
every call site here passes only metadata (usernames, addresses, counts,
reasons). gui/security_dashboard.py reads this file read-only and never
connects to the server.
"""

import hashlib
import json
import os
import threading
import time

from sqlalchemy import func, insert, select
try:
    from .db import get_database, security_events
except ImportError:
    from db import get_database, security_events


def event_digest(record):
    return hashlib.sha256(json.dumps(record, sort_keys=True, default=str,
                                     separators=(",", ":")).encode()).hexdigest()


def store_event(conn, record, import_key=None):
    """Write the same structured metadata as JSONL, never a raw envelope."""
    record = json.loads(json.dumps(record, default=str))
    details = {k: v for k, v in record.items() if k not in ("ts", "event")}
    conn.execute(insert(security_events).values(
        ts=record["ts"], event_type=record["event"],
        username=record.get("username") or record.get("from_user") or record.get("reported_by"),
        peer_addr=record.get("from_addr"), details=details, import_key=import_key))


DEFAULT_LOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "security_events.jsonl")

# One process-wide lock: multiple client-handler threads can log concurrently,
# and a plain append is not atomic across threads without it.
_lock = threading.Lock()


def log_event(event: str, path: str = DEFAULT_LOG_PATH, database=None, **fields) -> dict:
    """Append one event and return the record that was written (useful for
    tests). `fields` are arbitrary metadata -- callers must not pass
    passwords, keys, or plaintext message content."""
    record = {"ts": time.time(), "event": event}
    record.update(fields)
    line = json.dumps(record, sort_keys=True, default=str)
    with _lock:
        with (database if database is not None else get_database()).transaction() as conn:
            digest = event_digest(record)
            ordinal = conn.execute(select(func.count()).select_from(security_events).where(
                security_events.c.import_key.like(digest + ":%"))).scalar_one()
            store_event(conn, record, f"{digest}:{ordinal + 1}")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    return record


def read_events(path: str = DEFAULT_LOG_PATH):
    """Read every event currently in the log, skipping any trailing partial
    line (e.g. a writer caught mid-append). Used by tests and the dashboard's
    initial load; the dashboard otherwise tails new lines as they appear."""
    if not os.path.exists(path):
        return []
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events
