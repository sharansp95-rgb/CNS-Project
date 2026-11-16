"""Production TLS transport for the shared authenticated envelope relay."""

import argparse
import json
import os
import socket
import ssl
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.user_store import get_public_key, register_user, verify_user, DatabaseUserStore

from certs.generate_certs import cert_fingerprint_from_file  # noqa: E402
# Package imports are identical in script and module mode (server/__init__.py).
from server.lockout import LockoutGuard
from server.security_log import log_event
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
class ChatServer(RelayCore):
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT,
                 certfile=None, keyfile=None,
                 lockout=None, database=None, store=None, logger=None, interceptor=None):
        if database is not None and store is None:
            store = DatabaseUserStore(database)
        super().__init__(lockout=lockout,
            register=store.register_user if store else lambda *a, **kw: register_user(*a, **kw),
            verify=store.verify_user if store else lambda *a, **kw: verify_user(*a, **kw),
            public_key=store.get_public_key if store else lambda *a, **kw: get_public_key(*a, **kw),
            logger=logger or (lambda *a, **kw: log_event(*a, **kw)),
            database=database, interceptor=interceptor)
        self.host = host
        self.port = port
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
        # username -> conn (the TLS-wrapped socket). Guarded by _lock: every
        # client thread mutates it on join/leave and reads it on every
        # route/broadcast.

        # Listening socket + lifecycle (see listen()/shutdown()). `_open_conns`
        # tracks EVERY accepted TLS connection (not just authenticated ones in
        # self.clients) so shutdown() can force them all closed.
        self._srv = None
        self._stop = threading.Event()
        self._open_conns = set()

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
                        self.log_event("malformed_envelope", from_user=name, from_addr=addr[0],
                                 length=len(line))
                        continue

                    if not isinstance(envelope, dict):
                        continue
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
            self.log_event("non_tls_connection", from_addr=addr[0], reason=str(exc))
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
    args = parser.parse_args()
    try:
        server = ChatServer(args.host, args.port, args.certfile, args.keyfile)
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
