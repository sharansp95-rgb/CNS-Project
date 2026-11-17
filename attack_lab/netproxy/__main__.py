"""python -m attack_lab.netproxy --upstream 127.0.0.1:5000 [--listen-port 5001] [--ui-port 8095]

Phone as a victim: add ``--lan-ip <private address> --ca-cert data/network_attack/ca.crt``. The proxy
then also listens on that LAN address and a plain-HTTP page on it offers the demo CA. Mallory's
control page always stays on 127.0.0.1.
"""

import argparse
import asyncio
import webbrowser

import uvicorn

from .app import create_app
from .certpage import create_app as cert_app
from .core import NetProxy


def hostport(text):
    host, _, port = text.rpartition(":")
    return host or "127.0.0.1", int(port)


async def run(args):
    proxy = NetProxy(
        ("127.0.0.1", args.listen_port),
        hostport(args.upstream),
        identify=args.identify,
        delay_seconds=args.delay,
        lan_ip=args.lan_ip,
    )
    await proxy.start()
    cert_server = cert_task = None
    if args.lan_ip:
        if not args.ca_cert:
            raise SystemExit("--lan-ip needs --ca-cert (the public demo CA for the phone)")
        proxy.cert_url = f"http://{args.lan_ip}:{args.cert_port}/"
        cert_server = uvicorn.Server(
            uvicorn.Config(
                cert_app(proxy, args.ca_cert, proxy.port),
                host=args.lan_ip,  # the LAN address only, never 0.0.0.0
                port=args.cert_port,
                log_level="warning",
                proxy_headers=False,
            )
        )
        cert_server.install_signal_handlers = lambda: None  # Mallory's server owns SIGINT/SIGTERM
        cert_task = asyncio.ensure_future(cert_server.serve())
        print(f"Phone URL        : https://{args.lan_ip}:{proxy.port}  (LAN)")
        print(f"Certificate page : {proxy.cert_url}")
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(proxy, args.ui_port),
            host="127.0.0.1",
            port=args.ui_port,
            log_level="warning",
            proxy_headers=False,
        )
    )
    print(f"Mallory's proxy : 127.0.0.1:{proxy.port}  (victims connect here)")
    print(f"Mallory's window: http://localhost:{args.ui_port}", flush=True)
    if args.open:
        webbrowser.open(f"http://localhost:{args.ui_port}")
    await server.serve()
    if cert_server:
        cert_server.should_exit = True
        await cert_task
    await proxy.stop()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--upstream", default="127.0.0.1:5000", help="the real server (host:port)")
    p.add_argument("--listen-port", type=int, default=5001)
    p.add_argument("--ui-port", type=int, default=8095)
    p.add_argument("--delay", type=float, default=3.0, help="seconds a Delay action holds a record")
    p.add_argument(
        "--identify", action="store_true", help="name victims from CNS_DEMO_LABEL (macOS/Linux)"
    )
    p.add_argument("--lan-ip", help="also listen on this private LAN address (phone as victim)")
    p.add_argument("--ca-cert", help="public demo CA (PEM) offered on the LAN certificate page")
    p.add_argument("--cert-port", type=int, default=8081, help="HTTP port of the certificate page")
    p.add_argument("--open", action="store_true", help="open Mallory's window in the browser")
    try:
        asyncio.run(run(p.parse_args()))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
