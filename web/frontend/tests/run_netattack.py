"""Throwaway browser network-attacker rig: HTTPS/WSS gateway behind Mallory's proxy + his window.

Ports (CNS_NETATTACK_BASE, default 8861): base = victims' URL (proxy), base+1 = gateway,
base+2 = Mallory's window. Everything lives in a temp dir; the real data/ is never touched.
"""

import asyncio
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
with tempfile.TemporaryDirectory(prefix="cns-netattack-e2e-") as root:
    base = int(os.environ.get("CNS_NETATTACK_BASE", "8861"))
    os.environ["TSA_KEY_PATH"] = str(Path(root) / "tsa.key")
    os.environ["DATABASE_URL"] = "sqlite:///" + str(Path(root) / "chat.db")
    os.environ["SECURECHAT_ALLOWED_ORIGINS"] = f"https://localhost:{base}"
    os.environ["CALL_STUN_URLS"] = ""  # host candidates only: offline-safe calls
    os.environ["LOCAL_STORAGE_DIR"] = str(Path(root) / "attachments")
    import uvicorn

    from attack_lab.netproxy.app import create_app as mallory_app
    from attack_lab.netproxy.core import NetProxy, ProxyRunner
    from attack_lab.netproxy.webcert import generate
    from web.app import create_app

    _, cert, key = generate(Path(root) / "tls")
    gateway = uvicorn.Server(
        uvicorn.Config(
            create_app(),
            host="127.0.0.1",
            port=base + 1,
            ssl_certfile=str(cert),
            ssl_keyfile=str(key),
            log_level="warning",
            proxy_headers=False,
        )
    )
    threading.Thread(target=gateway.run, daemon=True).start()
    proxy = NetProxy(
        ("127.0.0.1", base),
        ("127.0.0.1", base + 1),
        stall_seconds=float(os.environ.get("CNS_STALL_SECONDS", "2")),
        identify=False,
    )
    runner = ProxyRunner(proxy)
    runner.start()
    ui = uvicorn.Server(
        uvicorn.Config(
            mallory_app(proxy, base + 2),
            host="127.0.0.1",
            port=base + 2,
            log_level="warning",
        )
    )
    asyncio.run_coroutine_threadsafe(ui.serve(), runner.loop)
    try:
        while True:
            time.sleep(1)
    finally:
        runner.stop()
        gateway.should_exit = True
