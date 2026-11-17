"""Rogue relay attacks, outside all product transports and cryptographic clients."""

import base64
import os
import threading
from copy import deepcopy
from pathlib import Path

from crypto_engine.dh_exchange import generate_keypair
from server.db import DEFAULT_DATABASE_URL, PROJECT_ROOT, get_database, normalize_url
from server.lockout import LockoutGuard
from server.security_log import log_event
from server.server import ChatServer
from server.user_store import DatabaseUserStore

ACTIONS = frozenset(
    (
        "tamper_next",
        "replay_last",
        "drop_next",
        "reorder_next",
        "inject_next",
        "mitm_next_handshake",
        "tamper_call_offer",
        "inject_call_offer",
        "replay_call_offer",
    )
)
# The relay cannot read a call offer (it is inside an end-to-end encrypted message),
# so the call attacks identify "probably an offer" by size: an SDP offer/answer is
# well over a kilobyte, ordinary chat text is not.
LARGE_CIPHERTEXT = 1500


def _identity(url):
    url = normalize_url(url)
    if url.get_backend_name() == "sqlite":
        if url.query.get("uri") or str(url.database).startswith("file:"):
            raise ValueError("SQLite URI aliases are not allowed for lab databases")
        return ("sqlite", str(Path(url.database).expanduser().resolve()))
    return (url.get_backend_name(), url.host, url.port or 5432, url.database)


def lab_database(url=None):
    url = (
        url
        or os.environ.get("LAB_DATABASE_URL")
        or ("sqlite:///" + str(PROJECT_ROOT / "data/attack_lab.db"))
    )
    selected = _identity(url)
    for real in (
        DEFAULT_DATABASE_URL,
        os.environ.get("DATABASE_URL") or DEFAULT_DATABASE_URL,
    ):
        real_identity = _identity(real)
        same_file = False
        if selected[0] == real_identity[0] == "sqlite":
            try:
                same_file = Path(selected[1]).samefile(real_identity[1])
            except FileNotFoundError:
                pass
        if (
            selected == real_identity
            or same_file
            or (
                selected[0] != "sqlite"
                and selected[0] == real_identity[0]
                and selected[-1] == real_identity[-1]
            )
        ):
            raise ValueError(
                "LAB_DATABASE_URL must identify a separate database from the real service"
            )
    return get_database(url)


class RogueRelay(ChatServer):
    """The normal TLS transport/core plus exactly one neutral interceptor.

    The optional legacy TCP lab_control protocol exists only in this subclass.
    Web lab controls use separate authenticated HTTP endpoints instead.
    """

    def __init__(
        self,
        host="127.0.0.1",
        port=0,
        certfile=None,
        keyfile=None,
        database=None,
        lockout=None,
        logger=None,
    ):
        if database is not None:
            lab_database(database.engine.url)  # enforce the same isolation guard for injections
        database = database if database is not None else lab_database()
        if lockout is not None and lockout.database.engine.url != database.engine.url:
            raise ValueError("Lab lockout must use the sandbox database")
        self.events = []
        self.wire = []
        self.pending = {}
        self.last = {}
        self.last_large = {}
        self.held = {}
        self.attack_lock = threading.RLock()

        def record(event, **fields):
            # Only metadata ever enters the attacker feed. security_alert
            # records are real clients' own reports, never inferred success.
            with self.attack_lock:
                import time

                self.events.append(dict(ts=time.time(), event=event, **fields))
                self.events[:] = self.events[-500:]
            if logger:
                logger(event, **fields)
            else:
                log_event(
                    event,
                    path=str(
                        Path(os.environ.get("LAB_STATE_DIR") or PROJECT_ROOT / "data/attack_lab")
                        / "security_events.jsonl"
                    ),
                    database=database,
                    **fields,
                )

        super().__init__(
            host,
            port,
            certfile,
            keyfile,
            database=database,
            store=DatabaseUserStore(database),
            lockout=lockout or LockoutGuard(database=database),
            logger=record,
            interceptor=self.intercept,
        )

    def arm(self, action, target):
        if not isinstance(action, str) or action not in ACTIONS:
            raise ValueError("Unknown attack")
        if not isinstance(target, str) or not target:
            raise ValueError("Choose a sandbox sender")
        replay = None
        forged = None
        with self.attack_lock:
            if action == "inject_call_offer":
                peers = [name for name in self.clients if name != target]
                if not peers:
                    raise ValueError("Connect the second victim first")
                forged = dict(
                    type="chat",
                    **{"from": target},
                    to=peers[0],
                    nonce=base64.b64encode(os.urandom(12)).decode(),
                    ciphertext=base64.b64encode(os.urandom(2600)).decode(),
                    tag=base64.b64encode(os.urandom(16)).decode(),
                )
                self.log_event("lab_attack_performed", action=action, target=target)
            elif action == "replay_call_offer":
                last = self.last_large.get(target)
                if last is None:
                    raise ValueError("No call offer captured yet: place a call first")
                replay = deepcopy(last)
                self.log_event("lab_attack_performed", action=action, target=target)
            elif action == "replay_last":
                last = self.last.get(target)
                if last is None:
                    raise ValueError("No captured message from this sender yet")
                replay = deepcopy(last)
                self.log_event("lab_attack_performed", action=action, target=target)
            else:
                self.pending[target] = action
                self.log_event("lab_attack_armed", action=action, target=target)
        # Never take the roster lock while holding the interceptor lock: reset
        # takes them in the opposite order to close peers and clear the sandbox.
        if replay is not None:
            self.deliver(replay, target)
        if forged is not None:
            self.deliver(forged, target)
        return dict(armed=True, action=action, target=target)

    def intercept(self, envelope, sender):
        original = deepcopy(envelope)
        etype = original.get("type")
        with self.attack_lock:
            # Explicit allowlist: don't expose arbitrary extension fields,
            # user login passwords, decrypted messages, or client secrets.
            self.wire.append(
                {
                    k: original[k]
                    for k in (
                        "type",
                        "from",
                        "to",
                        "nonce",
                        "ciphertext",
                        "tag",
                        "pubkey",
                        "handshake_sig",
                    )
                    if k in original
                }
            )
            self.wire[:] = self.wire[-100:]
            if etype == "chat":
                self.last[sender] = deepcopy(original)
                if len(original.get("ciphertext", "")) > LARGE_CIPHERTEXT:
                    self.last_large[sender] = deepcopy(original)
            action = self.pending.get(sender)
            if action == "tamper_call_offer":
                if etype != "chat" or len(original.get("ciphertext", "")) <= LARGE_CIPHERTEXT:
                    return [original]  # keep waiting for the (large) call offer

            if sender in self.held and etype == "chat":
                saved = self.held.pop(sender)
                return [original, saved]
            if (
                not action
                or (
                    action == "mitm_next_handshake"
                    and etype not in ("handshake_init", "handshake_response")
                )
                or (action != "mitm_next_handshake" and etype != "chat")
            ):
                return [original]
            self.pending.pop(sender)
            self.log_event("lab_attack_performed", action=action, target=sender)
            if action in ("tamper_next", "tamper_call_offer"):
                data = bytearray(base64.b64decode(original["ciphertext"]))
                data[0] ^= 0xFF
                original["ciphertext"] = base64.b64encode(data).decode()
                return [original]
            if action == "drop_next":
                return []
            if action == "reorder_next":
                self.held[sender] = original
                return []
            if action == "inject_next":
                forged = deepcopy(original)
                forged.update(
                    nonce=base64.b64encode(os.urandom(12)).decode(),
                    ciphertext=base64.b64encode(os.urandom(32)).decode(),
                    tag=base64.b64encode(os.urandom(16)).decode(),
                )
                return [forged, original]
            if action == "mitm_next_handshake":
                _, pub = generate_keypair()
                original["pubkey"] = base64.b64encode(pub).decode()
                return [original]
            return [original]

    def handle_authenticated(self, conn, addr, name, envelope):
        if envelope.get("type") == "lab_control":
            if addr[0] not in ("127.0.0.1", "::1"):
                self.log_event(
                    "lab_control_rejected",
                    requested_by=name,
                    from_addr=addr[0],
                    reason="localhost only",
                )
                self._send(
                    conn,
                    dict(type="lab_control_result", armed=False, reason="localhost only"),
                )
                return
            try:
                result = self.arm(envelope.get("action"), envelope.get("target") or name)
            except ValueError as exc:
                result = dict(armed=False, action=envelope.get("action"), reason=str(exc))
                self.log_event("lab_control_rejected", requested_by=name, reason=str(exc))
            self._send(conn, dict(type="lab_control_result", **result))
            return
        return super().handle_authenticated(conn, addr, name, envelope)
