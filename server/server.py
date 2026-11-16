"""Relay server: threaded TCP, JSON-line envelope protocol.

Phase 1 broadcast raw plaintext lines to everyone. Phase 3 replaced that with
a small JSON envelope protocol (see README.md "How the handshake works") so
the server can route ECDH handshake messages and encrypted chat messages to a
*specific* named peer instead of broadcasting them to the whole room. Phase 4
adds a "register"/"login" step in front of that: a client must authenticate
with a username + password (checked against server/user_store.py, which
stores only a PBKDF2 hash -- see auth/password_hash.py) before it is admitted
to the roster or allowed to send anything else.

Crucially, the server is a dumb relay for these envelope types:
  - "handshake_init" / "handshake_response": carry only public key bytes
    (base64-encoded). Public keys are, by design, safe for the server to see.
  - "chat": carries only nonce/ciphertext/tag (base64-encoded AES-GCM output).
    The server never sees plaintext, never sees a private key, and never sees
    (or computes) the derived shared session key -- it just forwards opaque
    bytes from sender to the named recipient.

Phase 5 adds long-term RSA identities for message signing (non-repudiation --
see crypto_engine/signatures.py and client.py). Each user's RSA *public* key
is submitted at registration and stored in server/user_store.py alongside
their password hash; the matching private key never leaves the client. A
"get_pubkey" envelope lets one client fetch another's public key by username
so it can verify that user's signatures -- the server just looks up and
returns what was already public by design.

Phase 6 wraps every connection in TLS, so even the first register/login envelope
is protected (before it, the whole protocol -- including passwords -- crossed the
network as plain JSON): every accepted connection is now wrapped in TLS (ssl.PROTOCOL_TLS_SERVER)
*before* a single byte of the envelope protocol is read, so even the very
first "register"/"login" envelope travels inside the TLS tunnel. This is a
transport-layer protection, layered on top of (not instead of) the
application-layer crypto from Phases 2/3/5: TLS keeps the connection itself
opaque to a network observer (nobody outside can even see "type": "login" or
the JSON structure), while AES-GCM + the RSA signatures still protect chat
content and identity even in a scenario where the relay server itself is
compromised (TLS only protects data in transit to/from the server, not what
the server does with it once decrypted at that endpoint). Certs are
generated locally by each teammate via certs/generate_certs.py -- see
README.md -- and are never committed (a shared private key would let anyone
with repo access impersonate the server).

Later stages added, on the same relay design: a hash-chained conversation log and
signed evidence export (clients; the server only forwards the extra fields),
account lockout (server/lockout.py), a security event log (server/security_log.py)
and the opt-in Attack Lab (--lab). The server still never sees plaintext or keys.

Wire format: one UTF-8 JSON object per line (newline-terminated), now
carried inside the TLS tunnel. Every envelope has a "type" field. Envelopes
that name a "to" recipient are unicast to that user if online; everything
else (register, login, roster) is handled directly by the server.
"""

import argparse
import base64
import json
import os
import socket
import ssl
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from user_store import get_public_key, register_user, verify_user
except ImportError:  # running as part of the `server` package (e.g. tests)
    from server.user_store import get_public_key, register_user, verify_user

from certs.generate_certs import cert_fingerprint_from_file  # noqa: E402
from crypto_engine.dh_exchange import generate_keypair as generate_ecdh_keypair  # noqa: E402
from crypto_engine.signatures import generate_keypair as generate_rsa_keypair  # noqa: E402
from crypto_engine.signatures import sign  # noqa: E402
# Same dual-mode import as user_store above: run as a script
# (`python server/server.py`, the documented way) the server/ directory is on
# sys.path and `import server` would find THIS FILE rather than the package,
# so the sibling modules must be imported top-level there; imported as part
# of the `server` package (tests, demos) they come from the package.
try:
    from db import get_database, record_relay
    from lockout import LockoutGuard
    from security_log import log_event
except ImportError:
    from server.db import get_database, record_relay
    from server.lockout import LockoutGuard  # noqa: E402
    from server.security_log import log_event  # noqa: E402
from server.relay_core import RelayCore
from transport import LockedTLSSocket  # noqa: E402

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CERT_PATH = os.path.join(_PROJECT_ROOT, "certs", "server.crt")
DEFAULT_KEY_PATH = os.path.join(_PROJECT_ROOT, "certs", "server.key")
CERT_DIR_ENV = "SECURECHAT_CERT_DIR"


def default_cert_paths():
    """Return the normal cert paths, or the test-only override when set.

    Resolving this at connection-server construction time keeps subprocesses
    hermetic too: pytest's environment is inherited by their Python process.
    """
    cert_dir = os.environ.get(CERT_DIR_ENV)
    if cert_dir:
        return os.path.join(cert_dir, "server.crt"), os.path.join(cert_dir, "server.key")
    return DEFAULT_CERT_PATH, DEFAULT_KEY_PATH


class CertsMissingError(Exception):
    """Raised when certs/server.crt or certs/server.key can't be found."""


def build_server_ssl_context(certfile=None, keyfile=None):
    """Build the server-side TLS context, loaded with our self-signed cert.

    Raises CertsMissingError with a clear, actionable message rather than
    letting a raw FileNotFoundError/SSLError surface if the certs haven't
    been generated yet.
    """
    default_certfile, default_keyfile = default_cert_paths()
    certfile = default_certfile if certfile is None else certfile
    keyfile = default_keyfile if keyfile is None else keyfile
    if not os.path.exists(certfile) or not os.path.exists(keyfile):
        raise CertsMissingError(
            f"TLS certificate/key not found at {certfile} / {keyfile}.\n"
            f"Run `python certs/generate_certs.py` once to generate them "
            f"before starting the server."
        )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    except ssl.SSLError as exc:
        raise CertsMissingError(
            f"Failed to load TLS certificate/key from {certfile} / {keyfile}: {exc}\n"
            f"Try regenerating them with `python certs/generate_certs.py --force`."
        ) from exc
    return context

# Envelope types relayed verbatim to a specific "to" recipient without the
# server inspecting their payload beyond routing fields.
_RELAYED_TYPES = {"handshake_init", "handshake_response", "chat"}


# Stage C: Attack Lab. One-shot, opt-in attacks performed BY THE RELAY --
# the threat model this whole project defends against -- so the professor
# can watch a real attack happen and get caught live, in the same two chat
# windows, instead of only through a separate script. Every safety
# restriction below is enforced server-side, never trusted to the GUI:
#   * the server must be started with --lab (default: disabled, and in that
#     default state the server behaves exactly as it always has)
#   * even in --lab mode, a lab_control envelope is honored only from a
#     connection whose PEER ADDRESS is 127.0.0.1, so it can never be
#     triggered over a real network
#   * only from a connection that has already completed register/login
#     (the lab_control case in handle_client's main loop runs only after
#     _authenticate() has returned a name -- the same gate every chat/
#     handshake envelope is already behind)
# A rejected attempt (wrong mode, wrong address, or unknown action) is
# always logged as "lab_control_rejected" -- including when --lab was never
# passed at all -- so a real attacker probing for this feature leaves a
# trace. A performed attack is logged as "lab_attack_performed" and reported
# ONLY to the client that armed it, as "armed" / "performed" -- never as a
# claim that the attack succeeded. Whether it was actually caught is left
# entirely to the real, unmodified client-side checks (AES-GCM tag, RSA
# signature, replay window/nonce, hash chain, handshake signature) on
# whichever client receives the attacked envelope -- the server never
# announces a detection result, because in the real world a malicious relay
# obviously wouldn't either.
_LAB_ACTIONS = {"tamper_next", "replay_last", "drop_next"}


class ChatServer(RelayCore):
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT,
                 certfile=None, keyfile=None,
                 lab_mode=False, lockout=None):
        super().__init__(lockout=lockout,
            register=lambda *a, **kw: register_user(*a, **kw),
            verify=lambda *a, **kw: verify_user(*a, **kw),
            public_key=lambda *a, **kw: get_public_key(*a, **kw),
            logger=lambda *a, **kw: log_event(*a, **kw))
        self.host = host
        self.port = port
        self.lab_mode = lab_mode
        default_certfile, default_keyfile = default_cert_paths()
        certfile = default_certfile if certfile is None else certfile
        keyfile = default_keyfile if keyfile is None else keyfile
        # Stage D: login lockout + per-address rate limiting (server/lockout.py).
        # `lockout` is injectable so tests can use tiny thresholds/windows
        # instead of the real 5-failures/5-minute defaults.
        # Built eagerly (not lazily in serve_forever) so a missing-certs
        # error surfaces immediately when the server is constructed, not
        # buried inside the accept loop.
        self.ssl_context = build_server_ssl_context(certfile, keyfile)
        # Fingerprint the cert we actually just loaded into memory -- printed
        # at startup (see serve_forever) so a stale server (still holding an
        # old cert after certs/server.crt was regenerated on disk without
        # restarting it) is diagnosable by comparing fingerprints, instead of
        # a bare CERTIFICATE_VERIFY_FAILED that gives no hint why.
        self.cert_fingerprint = cert_fingerprint_from_file(certfile)
        self.database = get_database()  # create/check schema before accepting clients
        # username -> conn (the TLS-wrapped socket). Guarded by _lock: every
        # client thread mutates it on join/leave and reads it on every
        # route/broadcast.

        # Listening socket + lifecycle (see listen()/shutdown()). `_open_conns`
        # tracks EVERY accepted TLS connection (not just authenticated ones in
        # self.clients) so shutdown() can force them all closed.
        self._srv = None
        self._stop = threading.Event()
        self._open_conns = set()

        # Stage C lab state, all guarded by _lab_lock (separate from _lock,
        # which is purely about self.clients, to avoid widening that lock's
        # critical sections). _lab_pending maps a TARGET username (whose
        # next matching outgoing envelope gets acted on) -> (action, armer
        # username). _last_chat_envelope maps a sender username -> the most
        # recent chat envelope genuinely relayed from them (used by
        # replay_last). _lab_attacker_key is a throwaway RSA identity
        # generated on first use -- signed with
        # this key, never with the real target's, so the victim's signature
        # check still fails exactly as it would for a real attacker.
        self._lab_lock = threading.Lock()
        self._lab_pending = {}
        self._last_chat_envelope = {}
        self._lab_attacker_key = None

    def _send(self, conn, envelope):
        try:
            if hasattr(conn, "send_envelope"):
                conn.send_envelope(envelope)
                return
            conn.sendall((json.dumps(envelope) + "\n").encode("utf-8"))
        except OSError:
            pass  # peer vanished; its own thread will clean it up

    def _send_system(self, conn, text):
        self._send(conn, {"type": "system", "text": text})

    def broadcast_system(self, text, exclude=None):
        with self._lock:
            targets = [c for c in self.clients.values() if c is not exclude]
        for conn in targets:
            self._send_system(conn, text)

    def broadcast_event(self, envelope, exclude=None):
        """Broadcast a structured (non-text) event, e.g. user_joined/user_left."""
        with self._lock:
            targets = [c for c in self.clients.values() if c is not exclude]
        for conn in targets:
            self._send(conn, envelope)

    def _notify_armer(self, armer_name, detail, **extra):
        with self._lock:
            armer_conn = self.clients.get(armer_name)
        if armer_conn is not None:
            self._send(armer_conn, dict({"type": "lab_attack_performed", "detail": detail},
                                        **extra))

    def _apply_lab_tamper_or_drop(self, envelope, sender_name):
        """Chat-envelope lab actions, applied (if armed) before the normal
        relay below. Returns the (possibly altered) envelope, or None if it
        should not be relayed at all (drop_next)."""
        with self._lab_lock:
            self._last_chat_envelope[sender_name] = envelope
            pending = self._lab_pending.get(sender_name)
            action = pending[0] if pending and pending[0] in ("tamper_next", "drop_next") else None
            if action:
                del self._lab_pending[sender_name]
                armer = pending[1]

        if action == "tamper_next":
            raw = bytearray(base64.b64decode(envelope["ciphertext"]))
            raw[0] ^= 0xFF  # flip every bit of the first ciphertext byte
            tampered = dict(envelope, ciphertext=base64.b64encode(bytes(raw)).decode("ascii"))
            detail = f"flipped a byte in {sender_name}'s next chat message's ciphertext"
            print(f"    [LAB] {detail}.")
            log_event("lab_attack_performed", action=action, target=sender_name, armed_by=armer)
            self._notify_armer(armer, detail, action=action)
            return tampered
        if action == "drop_next":
            detail = f"silently dropped {sender_name}'s next chat message"
            print(f"    [LAB] {detail}.")
            log_event("lab_attack_performed", action=action, target=sender_name, armed_by=armer)
            self._notify_armer(armer, detail, action=action)
            return None
        return envelope

    def route(self, envelope, sender_name):
        """Forward a handshake/chat envelope to its named recipient only."""
        etype = envelope.get("type")
        if etype == "chat":
            envelope = self._apply_lab_tamper_or_drop(envelope, sender_name)
            if envelope is None:
                return  # drop_next: never relayed

        super().route(envelope, sender_name)

    def _handle_lab_control(self, conn, addr, name, envelope):
        """Arm (or, for replay_last, immediately perform) a one-shot lab
        attack. See the _LAB_ACTIONS comment above ChatServer for the
        safety restrictions this enforces."""
        action = envelope.get("action")
        target = envelope.get("target") or name

        def reject(reason):
            log_event("lab_control_rejected", requested_by=name, from_addr=addr[0],
                      action=action, reason=reason)
            self._send(conn, {"type": "lab_control_result", "action": action,
                              "target": target, "armed": False, "detail": reason})

        if not self.lab_mode:
            reject("lab mode is not enabled on this server (start it with --lab)")
            return
        if addr[0] != "127.0.0.1":
            reject("lab_control is only accepted from a localhost connection")
            return
        if action not in _LAB_ACTIONS:
            reject(f"unknown lab action '{action}'")
            return

        if action == "replay_last":
            with self._lab_lock:
                last = self._last_chat_envelope.get(target)
            if last is None:
                reject(f"no previous chat message from {target} to replay yet")
                return
            detail = f"resent {target}'s most recent chat message a second time"
            print(f"    [LAB] {detail}.")
            log_event("lab_attack_performed", action=action, target=target, armed_by=name)
            self._send(conn, {"type": "lab_control_result", "action": action, "target": target,
                              "armed": True, "detail": "resent immediately"})
            self._notify_armer(name, detail, action=action)
            self.route(dict(last), target)  # a copy: route() may tag the next pending action
            return

        with self._lab_lock:
            self._lab_pending[target] = (action, name)
        detail = {
            "tamper_next": f"next chat message from {target} will be tampered with",
            "drop_next": f"next chat message from {target} will be silently dropped",
        }[action]
        print(f"    [LAB] armed by {name} from {addr[0]}: {detail}")
        self._send(conn, {"type": "lab_control_result", "action": action, "target": target,
                          "armed": True, "detail": detail})

    def _authenticate(self, conn, stream, addr):
        for line in stream:
            try:
                envelope = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(envelope, dict):
                continue
            name = self.authenticate(conn, addr, envelope)
            if name is not None:
                return name
        return None

    def handle_client(self, conn, addr):
        name = None
        try:
            with conn.makefile("r", encoding="utf-8", newline="\n") as stream:
                name = self._authenticate(conn, stream, addr)
                if name is None:
                    return  # disconnected before authenticating

                for line in stream:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        envelope = json.loads(line)
                    except json.JSONDecodeError:
                        log_event("malformed_envelope", from_user=name, from_addr=addr[0],
                                 length=len(line))
                        continue

                    if not isinstance(envelope, dict):
                        continue
                    if envelope.get("type") == "lab_control":
                        self._handle_lab_control(conn, addr, name, envelope)
                    else:
                        self.handle_authenticated(conn, addr, name, envelope)
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            pass
        finally:
            removed = self.remove_client(conn)
            if removed:
                print(f"[-] {removed} disconnected")
                self.broadcast_system(f"*** {removed} left the chat ***")

    def _handle_raw_connection(self, conn, addr):
        """Perform the TLS handshake for one accepted raw connection, then
        hand off to handle_client. Runs in its own thread (spawned right
        after accept(), before any handshake happens) so one slow or hostile
        TLS handshake -- or a client that never speaks TLS at all -- blocks
        only this thread, never the accept loop or other clients.
        """
        try:
            tls_conn = self.ssl_context.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            print(f"[!] TLS handshake failed with {addr[0]}:{addr[1]} -- {exc}")
            log_event("non_tls_connection", from_addr=addr[0], reason=str(exc))
            try:
                conn.close()
            except OSError:
                pass
            return
        # One handler thread reads this connection while other handler
        # threads route()/broadcast into it -- see transport/locked_tls.py.
        safe_conn = LockedTLSSocket(tls_conn)
        with self._lock:
            self._open_conns.add(safe_conn)
        try:
            self.handle_client(safe_conn, addr)
        finally:
            with self._lock:
                self._open_conns.discard(safe_conn)

    def listen(self):
        """Bind and start listening, then return the real port. Idempotent.

        Pass port=0 to let the OS pick a free port (read it back from the
        return value or self.port): there is no window between "find a free
        port" and "bind it" for another process to steal it, unlike the old
        free_port()-then-bind dance. Because the socket is already listening
        when this returns, a client may connect immediately -- callers need no
        "wait until the port accepts connections" polling (whose raw probe
        connections also just generated spurious TLS-handshake failures)."""
        if self._srv is not None:
            return self.port
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen()
        except OSError:
            srv.close()
            raise
        self.port = srv.getsockname()[1]
        self._srv = srv
        return self.port

    def shutdown(self):
        """Ask serve_forever() to return, and force every open connection
        closed. Safe to call more than once, from any thread."""
        self._stop.set()
        with self._lock:
            conns = list(self._open_conns)
        for conn in conns:
            conn.close()

    def serve_forever(self):
        self.listen()
        srv = self._srv
        srv.settimeout(0.2)  # so shutdown() is noticed promptly
        print(f"[*] Server listening on {self.host}:{self.port} over TLS "
              f"(cert fingerprint: {self.cert_fingerprint}) "
              f"(routes handshake/chat envelopes; never sees plaintext app "
              f"secrets or session keys)")
        if self.lab_mode:
            print("[*] LAB MODE ENABLED -- localhost, authenticated clients may arm "
                  "one-shot relay attacks via lab_control. Never enable this on a "
                  "server reachable from anywhere but localhost.")
        try:
            while not self._stop.is_set():
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break  # listening socket closed
                threading.Thread(
                    target=self._handle_raw_connection, args=(conn, addr), daemon=True
                ).start()
        except KeyboardInterrupt:
            print("\n[*] Shutting down")
        finally:
            self._stop.set()
            srv.close()
            self._srv = None
            self.shutdown()
            with self._lock:
                conns = list(self.clients.values())
            for conn in conns:
                self.remove_client(conn)


def main():
    parser = argparse.ArgumentParser(description="Secure chat relay server")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--certfile", default=None)
    parser.add_argument("--keyfile", default=None)
    parser.add_argument("--web-port", type=int, help="also serve HTTP/WebSocket clients on this port")
    parser.add_argument("--lab", action="store_true",
                         help="enable the opt-in Attack Lab (lab_control envelopes from "
                              "authenticated localhost clients only); OFF by default")
    args = parser.parse_args()
    try:
        server = ChatServer(args.host, args.port, args.certfile, args.keyfile,
                            lab_mode=args.lab)
    except CertsMissingError as exc:
        print(f"[!] {exc}")
        sys.exit(1)
    if args.web_port is not None:
        import uvicorn
        from web.app import create_app
        tcp_thread = threading.Thread(target=server.serve_forever, daemon=True)
        # Bind before starting HTTP so a TCP failure cannot silently split the demo.
        server.listen()
        tcp_thread.start()
        try:
            uvicorn.run(create_app(server), host=args.host, port=args.web_port,
                        ws_max_size=int(os.environ.get("SECURECHAT_WS_MAX_BYTES", "65536")))
        finally:
            server.shutdown()
            tcp_thread.join(timeout=5)
    else:
        server.serve_forever()


if __name__ == "__main__":
    main()
