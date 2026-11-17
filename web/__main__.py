"""HTTP/WS-only deployment entry point. No TCP listener or Attack Lab imports."""

import os

import uvicorn

from .app import create_app


def main():
    uvicorn.run(
        create_app(),
        host=os.environ.get("WEB_HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8080")),
        proxy_headers=False,
        workers=1,
        ws_max_size=int(os.environ.get("SECURECHAT_WS_MAX_BYTES", "65536")),
    )


if __name__ == "__main__":
    main()
