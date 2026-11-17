"""python -m attack_lab.netproxy --upstream 127.0.0.1:5000 [--listen-port 5001] [--ui-port 8095]"""

import argparse
import asyncio
import webbrowser

import uvicorn

from .app import create_app
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
    )
    await proxy.start()
    config = uvicorn.Config(
        create_app(proxy, args.ui_port),
        host="127.0.0.1",
        port=args.ui_port,
        log_level="warning",
        proxy_headers=False,
    )
    server = uvicorn.Server(config)
    print(f"Mallory's proxy : 127.0.0.1:{proxy.port}  (victims connect here)")
    print(f"Mallory's window: http://localhost:{args.ui_port}")
    if args.open:
        webbrowser.open(f"http://localhost:{args.ui_port}")
    await server.serve()
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
    p.add_argument("--open", action="store_true", help="open Mallory's window in the browser")
    try:
        asyncio.run(run(p.parse_args()))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
