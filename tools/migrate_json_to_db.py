#!/usr/bin/env python3
"""Explicit, transactional and repeatable legacy account/event import.

Existing DB accounts win (never overwrite credentials). Malformed input aborts
before writing; missing files are allowed. Source files are left untouched.
"""

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import insert, select

from server.db import PROJECT_ROOT, get_database, security_events, users
from server.security_log import event_digest, store_event


def migrate(users_path, events_path, database=None):
    accounts = json.loads(Path(users_path).read_text()) if Path(users_path).exists() else {}
    if not isinstance(accounts, dict):
        raise ValueError("users.json must contain an object")
    for username, record in accounts.items():
        if (
            not username
            or not isinstance(record, dict)
            or not isinstance(record.get("password_hash"), str)
        ):
            raise ValueError("each account must have a username and encoded password_hash")
    events = []
    if Path(events_path).exists():
        for number, line in enumerate(Path(events_path).read_text().splitlines(), 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                if (
                    not isinstance(record, dict)
                    or not isinstance(record.get("ts"), (int, float))
                    or not isinstance(record.get("event"), str)
                ):
                    raise ValueError("expected ts and event")
            except (ValueError, TypeError) as exc:
                raise ValueError(f"invalid security event on line {number}: {exc}") from exc
            events.append(record)
    database = database or get_database()
    counts = dict(users_imported=0, users_skipped=0, events_imported=0, events_skipped=0)
    with database.transaction() as conn:
        existing = set(conn.execute(select(users.c.username)).scalars())
        for username, record in accounts.items():
            if username in existing:
                counts["users_skipped"] += 1
                continue
            conn.execute(
                insert(users).values(
                    username=username,
                    password_hash=record["password_hash"],
                    public_key_pem=record.get("public_key"),
                    created_at=time.time(),
                )
            )
            counts["users_imported"] += 1
        occurrences = Counter()
        for record in events:
            digest = event_digest(record)
            occurrences[digest] += 1
            key = f"{digest}:{occurrences[digest]}"
            if conn.execute(
                select(security_events.c.id).where(security_events.c.import_key == key)
            ).first():
                counts["events_skipped"] += 1
                continue
            store_event(conn, record, key)
            counts["events_imported"] += 1
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--users", type=Path, default=PROJECT_ROOT / "data/users.json")
    parser.add_argument("--events", type=Path, default=PROJECT_ROOT / "logs/security_events.jsonl")
    parser.add_argument("--database-url", help="overrides DATABASE_URL")
    args = parser.parse_args()
    counts = migrate(args.users, args.events, get_database(args.database_url))
    print(" ".join(f"{name}={count}" for name, count in counts.items()))


if __name__ == "__main__":
    main()
