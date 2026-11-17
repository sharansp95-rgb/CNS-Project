"""python -m attack_lab.simple [--cert C --key K] [--lan-ip IP --ca-cert CA] [--port 8443]

One process: the real web chat (served by the lab relay, victims open https://<host>:PORT),
Mallory's window (127.0.0.1 only) and, with --lan-ip, the certificate page for the phone.
Everything lives in a throw-away directory, never in the real database.
"""

import argparse
import asyncio
import shutil
import tempfile
from pathlib import Path

import uvicorn

from attack_lab.app import certificates
from attack_lab.netproxy.certpage import create_app as cert_app
from attack_lab.netproxy.lan import check_private
from attack_lab.relay import lab_database
from server.storage import LocalStorage
from web.app import create_app as product_gateway

from .app import create_app as mallory_app
from .core import SimpleRelay


class _LanInfo:
    """What the certificate page needs from a proxy: the LAN address and a contact counter."""

    def __init__(self, ip):
        self.lan_ip = ip
        self.hits = set()

    def note_cert_hit(self, address):
        self.hits.add(address)


def build(args, state: Path):
    database = lab_database("sqlite:///" + str(state / "mallory.db"))
    cert, key = certificates(state / "certs")  # only for the relay's unused TCP adapter
    relay = SimpleRelay(certfile=cert, keyfile=key, database=database, logger=lambda *a, **k: None)
    scheme = "https" if args.cert else "http"
    origins = {f"{scheme}://localhost:{args.port}", f"{scheme}://127.0.0.1:{args.port}"}
    if args.lan_ip:
        origins.add(f"{scheme}://{args.lan_ip}:{args.port}")
    victims = product_gateway(
        relay,
        origins=origins,
        include_vault=False,
        attachment_storage=LocalStorage(state / "attachments"),
    )
    return relay, victims


def server(app, host, port, cert=None, key=None, main=False):
    srv = uvicorn.Server(
        uvicorn.Config(
            app,
            host=host,
            port=port,
            log_level="warning",
            proxy_headers=False,
            ws_max_size=65536,
            ssl_certfile=cert,
            ssl_keyfile=key,
        )
    )
    if not main:
        srv.install_signal_handlers = lambda: None
    return srv


async def run(args):
    if args.lan_ip:
        args.lan_ip = check_private(args.lan_ip)  # never a public address, never 0.0.0.0
        if not (args.cert and args.key and args.ca_cert):
            raise SystemExit("--lan-ip needs --cert, --key and --ca-cert (phones need HTTPS)")
    state = Path(tempfile.mkdtemp(prefix="cns-mallory-"))
    try:
        relay, victims = build(args, state)
        servers = [
            server(mallory_app(relay, args.mallory_port), "127.0.0.1", args.mallory_port, main=True)
        ]
        for host in ["127.0.0.1"] + ([args.lan_ip] if args.lan_ip else []):
            servers.append(server(victims, host, args.port, args.cert, args.key))
        if args.lan_ip:
            info = _LanInfo(args.lan_ip)
            servers.append(
                server(cert_app(info, args.ca_cert, args.port), args.lan_ip, args.cert_port)
            )
        scheme = "https" if args.cert else "http"
        print(f"Chat (victims)   : {scheme}://localhost:{args.port}", flush=True)
        print(f"Mallory's window : http://localhost:{args.mallory_port}", flush=True)
        if args.lan_ip:
            print(f"Phone URL        : https://{args.lan_ip}:{args.port}  (LAN)", flush=True)
            print(f"Certificate page : http://{args.lan_ip}:{args.cert_port}/", flush=True)
        tasks = [asyncio.ensure_future(s.serve()) for s in servers[1:]]
        await servers[0].serve()
        for s in servers[1:]:
            s.should_exit = True
        await asyncio.gather(*tasks)
    finally:
        shutil.rmtree(state, ignore_errors=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port", type=int, default=8443, help="the chat the victims open")
    p.add_argument("--mallory-port", type=int, default=8095)
    p.add_argument(
        "--cert", help="TLS certificate (PEM); without it the chat is plain HTTP on loopback"
    )
    p.add_argument("--key", help="TLS private key (PEM)")
    p.add_argument("--lan-ip", help="also serve the chat on this private LAN address (phone)")
    p.add_argument("--ca-cert", help="public demo CA offered on the certificate page")
    p.add_argument("--cert-port", type=int, default=8081)
    try:
        asyncio.run(run(p.parse_args()))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
