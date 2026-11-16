"""Transport-independent synchronous relay, shared by TCP and WebSockets.

Transports supply send_envelope/close, or override _send in a legacy adapter.
No TLS, socket, asyncio, or attack-lab dependencies belong in this module.
All roster/auth state changes are protected by the same reentrant lock.
"""
import threading
from server.db import get_database, record_relay
from server.lockout import LockoutGuard
from server.security_log import log_event
from server.user_store import DatabaseUserStore

RELAYED_TYPES = frozenset(("chat", "handshake_init", "handshake_response"))


class RelayCore:
    def __init__(self, lockout=None, register=None, verify=None, public_key=None, logger=None, database=None, interceptor=None):
        self.clients = {}
        self._lock = threading.RLock()
        self.database = database if database is not None else get_database()
        self.interceptor = interceptor
        scoped = DatabaseUserStore(self.database)
        self.lockout = lockout if lockout is not None else LockoutGuard(database=self.database)
        self.register_user = register or scoped.register_user
        self.verify_user = verify or scoped.verify_user
        self.get_public_key = public_key or scoped.get_public_key
        self.log_event = logger or (lambda event, **fields: log_event(event, database=self.database, **fields))

    def _send(self, conn, envelope):
        conn.send_envelope(envelope)

    def _send_system(self, conn, text):
        self._send(conn, {"type": "system", "text": text})

    def broadcast_event(self, envelope, exclude=None):
        with self._lock:
            targets = [c for c in self.clients.values() if c is not exclude]
        for conn in targets:
            self._send(conn, envelope)

    def broadcast_system(self, text, exclude=None):
        self.broadcast_event({"type": "system", "text": text}, exclude)

    def authenticate(self, conn, addr, envelope):
        # Serialize account admission with roster insertion. PBKDF2 runs in a
        # worker thread on the WS transport, never on its event loop.
        with self._lock:
            name = self._authenticate_envelope(conn, addr, envelope)
            if name is not None:
                self.join(conn, name)
            return name

    def _authenticate_envelope(self, conn, addr, envelope):
        etype = envelope.get("type")
        if etype not in ("register", "login"):
            self._send_system(conn, "[!] Please register or login first.")
            return None
        for field in ("username", "password", "public_key"):
            value = envelope.get(field)
            if value is not None and (not isinstance(value, str) or len(value) > 16384):
                self._send(conn, {"type": f"{etype}_result", "success": False,
                                  "reason": "invalid credentials"})
                return None
        # Stage D: a per-source-address rate limit covers BOTH register
        # and login attempts, independent of any one username -- this is
        # what catches an attacker spreading guesses across many
        # usernames, which the per-account lockout below alone would not.
        if not self.lockout.check_address_rate(addr[0]):
            self._send(conn, {
                "type": f"{etype}_result", "success": False,
                "reason": "too many requests from this address -- slow down and retry shortly",
            })
            self.log_event("address_rate_limited", from_addr=addr[0], attempted_type=etype)
            return None

        username = envelope.get("username")
        password = envelope.get("password")
        public_key_pem = envelope.get("public_key")
        result_type = f"{etype}_result"
        if not username or not password:
            self._send(conn, {
                "type": result_type, "success": False,
                "reason": "username and password are required",
            })
            return None

        if etype == "login":
            # Checked BEFORE self.verify_user() -- and therefore before any
            # PBKDF2 work -- so repeatedly hammering an already-locked
            # account cannot be used to burn CPU. See server/lockout.py's
            # module docstring for the enumeration-safety trade-off this
            # implies (the generic "invalid username or password" is
            # used right up through the failure that triggers the lock;
            # only an attempt against an ALREADY-locked account gets
            # this more specific message).
            lock_status = self.lockout.status(username)
            if lock_status.locked:
                retry_after = int(lock_status.retry_after) + 1
                self._send(conn, {
                    "type": "login_result", "success": False,
                    "reason": f"account temporarily locked, retry in {retry_after}s",
                })
                self.log_event("lockout_rejected", username=username, from_addr=addr[0],
                         retry_after=retry_after)
                return None

        with self._lock:
            already_online = username in self.clients
        if already_online:
            self._send(conn, {
                "type": result_type, "success": False,
                "reason": f"'{username}' is already logged in elsewhere",
            })
            return None

        if etype == "register":
            if not self.register_user(username, password, public_key_pem=public_key_pem):
                self._send(conn, {
                    "type": "register_result", "success": False,
                    "reason": f"username '{username}' is already taken",
                })
                return None
            self._send(conn, {
                "type": "register_result", "success": True,
                "reason": "registered and logged in",
            })
            print(f"[+] {username} registered from {addr[0]}:{addr[1]}")
            self.log_event("user_registered", username=username, from_addr=addr[0])
            return username
        else:  # login
            if not self.verify_user(username, password):
                status = self.lockout.record_failure(username, addr=addr[0])
                self.log_event("failed_login", username=username, from_addr=addr[0])
                if status.newly_locked:
                    print(f"[!] {username} locked out after repeated failed logins "
                          f"(retry in {int(status.retry_after)}s)")
                    self.log_event("account_locked", username=username, from_addr=addr[0],
                             retry_after=status.retry_after, lock_level=status.lock_level)
                self._send(conn, {
                    "type": "login_result", "success": False,
                    "reason": "invalid username or password",
                })
                return None
            self.lockout.record_success(username)
            self._send(conn, {
                "type": "login_result", "success": True,
                "reason": "login successful",
            })
            print(f"[+] {username} logged in from {addr[0]}:{addr[1]}")
            self.log_event("user_login", username=username, from_addr=addr[0])
            return username

        return None

    def join(self, conn, name):
        with self._lock:
            self.clients[name] = conn
            roster = [u for u in self.clients if u != name]
        self._send(conn, {"type": "roster", "users": roster})
        self.broadcast_system(f"*** {name} joined the chat ***", exclude=conn)
        self.broadcast_event({"type": "user_joined", "username": name}, exclude=conn)

    def remove_client(self, conn):
        with self._lock:
            name = next((u for u, c in self.clients.items() if c is conn), None)
            if name:
                del self.clients[name]
        conn.close()
        return name

    def route(self, envelope, sender_name):
        """The optional neutral interceptor returns zero or more routed envelopes.

        All normal calls use None and deliver one original envelope. A supplied
        interceptor owns its synchronization and must not mutate caller data.
        """
        outgoing = self.interceptor(envelope, sender_name) if self.interceptor else [envelope]
        for item in outgoing:
            self.deliver(item, sender_name)

    def deliver(self, envelope, sender_name):
        with self._lock:
            target = self.clients.get(envelope.get("to"))
            sender = self.clients.get(sender_name)
        if target is None:
            if sender is not None:
                self._send_system(sender, f"[!] {envelope.get('to')} is not online -- message not delivered.")
            return
        record_relay(envelope, sender_name, self.database)
        self._send(target, envelope)

    def _handle_get_pubkey(self, conn, envelope):
        name = envelope.get("username")
        public = self.get_public_key(name) if isinstance(name, str) and name else None
        self._send(conn, {"type": "pubkey_result", "username": name,
                          "public_key": public, "success": public is not None})

    def handle_authenticated(self, conn, addr, name, envelope):
        etype = envelope.get("type")
        if isinstance(etype, str) and etype in RELAYED_TYPES:
            self.route(envelope, name)
        elif etype == "get_pubkey":
            self._handle_get_pubkey(conn, envelope)
        elif etype == "security_alert":
            self.log_event("security_alert", reported_by=name, from_addr=addr[0],
                           alert=envelope.get("alert"), reason=envelope.get("reason"),
                           peer=envelope.get("peer"), seq=envelope.get("seq"))
        else:
            self.log_event("unsupported_envelope", username=name, from_addr=addr[0],
                           envelope_type=etype if isinstance(etype, str) else "invalid type")
            self._send(conn, {"type": "error", "reason": "unknown envelope type"})
