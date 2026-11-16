"""Separate hostile relay: python -m attack_lab [--tcp-port 5056]."""

import argparse
import os
import uvicorn
from attack_lab.app import create_app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8090")))
    parser.add_argument("--tcp-port", type=int)
    args = parser.parse_args()
    origins = os.environ.get(
        "LAB_ALLOWED_ORIGINS",
        f"http://localhost:{args.port},http://127.0.0.1:{args.port}",
    ).split(",")
    uvicorn.run(
        create_app(origins=origins, tcp_port=args.tcp_port),
        host=args.host,
        port=args.port,
        ws_max_size=65536,
    )


if __name__ == "__main__":
    main()
