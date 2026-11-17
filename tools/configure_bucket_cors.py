"""Restrict the attachment bucket's browser access to the main site's origin.

Reads S3_ENDPOINT, S3_BUCKET, S3_REGION, S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY
from the environment (never from arguments, never printed). Example, with the
values coming from macOS Keychain inside a subshell:

    S3_ENDPOINT=$(security find-generic-password -s cns-s3-endpoint -a team15 -w) \\
    ... .venv/bin/python tools/configure_bucket_cors.py https://team15-securechat.onrender.com
"""

import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server.storage import S3Storage  # noqa: E402


def main(argv):
    if not argv:
        print("usage: configure_bucket_cors.py ORIGIN [ORIGIN...]", file=sys.stderr)
        return 2
    for origin in argv:
        p = urlsplit(origin)
        if p.scheme != "https" or p.path or "*" in origin:
            print(f"Origin must be an exact https origin: {origin}", file=sys.stderr)
            return 2
    env = os.environ
    storage = S3Storage(env["S3_ENDPOINT"], env["S3_BUCKET"], env["S3_REGION"],
                        env["S3_ACCESS_KEY_ID"], env["S3_SECRET_ACCESS_KEY"])
    storage.put_cors(argv)
    print("CORS set for:", ", ".join(argv))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
