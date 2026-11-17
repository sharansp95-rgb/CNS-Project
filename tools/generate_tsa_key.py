#!/usr/bin/env python3
"""Create a separate Ed25519 receipt-signing key, without overwriting an identity."""

import argparse
import base64
import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEFAULT_PATH = Path(__file__).resolve().parents[1] / "data/tsa_signing.key"


def generate(path=None):
    path = Path(path or os.environ.get("TSA_KEY_PATH") or DEFAULT_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        return path
    private = Ed25519PrivateKey.generate()
    data = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd, temporary = tempfile.mkstemp(prefix=".tsa-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)  # publish a complete 0600 key, never overwrite
        except FileExistsError:
            pass
    finally:
        os.unlink(temporary)
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path")
    parser.add_argument(
        "--print-env",
        action="store_true",
        help="Print base64 PEM for Render; no file is written unless --path is supplied",
    )
    args = parser.parse_args()
    if args.print_env:
        if args.path:
            data = generate(args.path).read_bytes()
        else:
            data = Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        print(base64.b64encode(data).decode("ascii"))
    else:
        print(generate(args.path))
