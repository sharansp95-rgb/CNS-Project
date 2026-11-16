"""Login lockout / rate limiting (Stage D).

Two independent mechanisms:

1. **Per-account lockout with exponential backoff.** Each failed login is
   tracked per username (with the source address recorded alongside it, for
   forensics -- see `account_locked` event logging in server.py). Once a
   username accumulates `threshold` failures within `window` seconds, it is
   locked: further login attempts for that username are rejected *without
   running PBKDF2* (`LockStatus.locked`, checked by the caller *before* it
   ever calls `auth.password_hash.verify_password`) -- this matters because
   PBKDF2 is deliberately slow (200,000 iterations, see
   auth/password_hash.py), so verifying it on every one of an attacker's
   repeated guesses against a locked account would itself be a CPU-exhaustion
   opening. A successful login resets the account's failure count and lock
   level to zero. Lock duration follows `backoff_schedule` and grows each
   time the account is locked again after a previous lock has expired
   (e.g. 30s, then 60s, then 120s, ... capped at the schedule's last entry),
   reset back to the first tier by a successful login.

   **Enumeration trade-off (deliberate, documented here because it's easy to
   get backwards):** every rejection for a *not-yet-locked* account says the
   same generic "invalid username or password" — including the exact
   failure that pushes the account over the threshold — so an attacker
   cannot distinguish "wrong password for a real account" from "no such
   account" by timing or wording alone. Only once an account is *already*
   locked does a login attempt get the more specific "account temporarily
   locked" message; by then the attacker already knows the account exists
   (they have been guessing against it long enough to lock it), so this
   message leaks nothing a patient attacker couldn't already infer from the
   lockout itself, and the lockout message is genuinely useful to the real
   owner of the account.

2. **Per-source-address rate limiting**, independent of any one username:
   `check_address_rate` caps how many register+login *attempts* (successful
   or not) one source address may make in a sliding window, to slow
   scripted abuse that spreads guesses across many different usernames
   rather than hammering one account (which mechanism 1 alone would not
   catch, since no single username would ever reach its own threshold).
"""

import threading
import time
from dataclasses import dataclass

from sqlalchemy import delete, insert, select, update
try:
    from .db import get_database, login_lockouts
except ImportError:
    from db import get_database, login_lockouts

DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_SECONDS = 300          # failures must fall within this window to count
DEFAULT_BACKOFF_SCHEDULE = (30, 60, 120, 300, 900)   # seconds; last entry is the cap (15 min)
DEFAULT_ADDR_LIMIT = 20
DEFAULT_ADDR_WINDOW_SECONDS = 60


@dataclass
class LockStatus:
    locked: bool
    retry_after: float = 0.0       # seconds remaining, if locked
    newly_locked: bool = False     # True only on the record_failure() call that triggered it
    lock_level: int = 0            # which backoff tier was used (0-indexed)


class LockoutGuard:
    """Persistent per-account lockout; source-address limits remain per process."""

    def __init__(self, threshold=DEFAULT_THRESHOLD, window=DEFAULT_WINDOW_SECONDS,
                 backoff_schedule=DEFAULT_BACKOFF_SCHEDULE,
                 addr_limit=DEFAULT_ADDR_LIMIT, addr_window=DEFAULT_ADDR_WINDOW_SECONDS):
        self.threshold = threshold
        self.window = window
        self.backoff_schedule = tuple(backoff_schedule)
        self.addr_limit = addr_limit
        self.addr_window = addr_window
        self._lock = threading.Lock()
        self.database = get_database()
        self._by_addr = {}       # addr -> [timestamp, ...]

    # --- per-account lockout -------------------------------------------------

    def status(self, username, now=None):
        """Current lock state for `username`, WITHOUT recording an attempt.
        The caller checks this BEFORE verifying a password, so a locked
        account's PBKDF2 is never run."""
        now = time.time() if now is None else now
        with self.database.engine.connect() as conn:
            st = conn.execute(select(login_lockouts).where(
                login_lockouts.c.username == username)).mappings().first()
        if st is None or st["locked_until"] <= now:
            return LockStatus(locked=False)
        return LockStatus(locked=True, retry_after=st["locked_until"] - now,
                          lock_level=max(st["lock_level"] - 1, 0))

    def record_failure(self, username, addr=None, now=None):
        """Persist the exact sliding-window streak and escalating backoff tier."""
        now = time.time() if now is None else now
        with self.database.transaction() as conn:
            st = conn.execute(select(login_lockouts).where(
                login_lockouts.c.username == username)).mappings().first()
            # A concurrent failure may already have locked this account.
            if st and st["locked_until"] > now:
                return LockStatus(locked=True, retry_after=st["locked_until"] - now,
                                  lock_level=max(st["lock_level"] - 1, 0))
            failures = [t for t in (st["failure_timestamps"] if st else [])
                        if now - t <= self.window]
            failures.append(now)
            level = st["lock_level"] if st else 0
            until = st["locked_until"] if st else 0.0
            result = LockStatus(locked=False)
            if len(failures) >= self.threshold:
                tier = min(level, len(self.backoff_schedule) - 1)
                duration = self.backoff_schedule[tier]
                until = now + duration
                level += 1
                failures = []
                result = LockStatus(locked=True, retry_after=duration,
                                    newly_locked=True, lock_level=tier)
            values = dict(failure_count=len(failures), locked_until=until,
                          last_failure_at=now, lock_level=level,
                          failure_timestamps=failures)
            if st:
                conn.execute(update(login_lockouts).where(
                    login_lockouts.c.username == username).values(**values))
            else:
                conn.execute(insert(login_lockouts).values(username=username, **values))
        return result

    def record_success(self, username):
        """Reset failures and backoff tier on successful login."""
        with self.database.transaction() as conn:
            conn.execute(delete(login_lockouts).where(login_lockouts.c.username == username))

    def locked_accounts(self, now=None):
        """Read currently locked accounts, including locks from earlier processes."""
        now = time.time() if now is None else now
        with self.database.engine.connect() as conn:
            rows = conn.execute(select(login_lockouts).where(
                login_lockouts.c.locked_until > now)).mappings().all()
        return [{"username": st["username"], "locked_until": st["locked_until"],
                 "remaining": st["locked_until"] - now, "lock_level": st["lock_level"]}
                for st in rows]

    # --- per-source-address rate limit ---------------------------------------

    def check_address_rate(self, addr, now=None):
        """True if `addr` may make another register/login attempt right
        now; False if it has exceeded `addr_limit` attempts within
        `addr_window` seconds. Every call that returns True also counts as
        one of those attempts (call this once per incoming register/login
        envelope, regardless of whether it later succeeds)."""
        now = time.time() if now is None else now
        with self._lock:
            times = self._by_addr.setdefault(addr, [])
            times[:] = [t for t in times if now - t <= self.addr_window]
            if len(times) >= self.addr_limit:
                return False
            times.append(now)
            return True
