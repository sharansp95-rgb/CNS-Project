"""Throwaway sandbox for browser tests, with a separate real-service sentinel."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
with tempfile.TemporaryDirectory(prefix="cns-attack-lab-e2e-") as root:
    root = Path(root)
    os.environ["DATABASE_URL"] = "sqlite:///" + str(root / "real-must-not-exist.db")
    os.environ["LAB_DATABASE_URL"] = "sqlite:///" + str(root / "sandbox.db")
    port = int(os.environ.get("CNS_TEST_LAB_PORT", "8766"))
    os.environ["LAB_ALLOWED_ORIGINS"] = f"http://127.0.0.1:{port}"
    os.environ["LAB_ACCESS_CODE"] = os.environ.get(
        "LAB_ACCESS_CODE", "Local-test-access-code-ONLY-1234"
    )
    os.environ["CALL_STUN_URLS"] = ""  # host candidates only in local lab tests
    import uvicorn

    from attack_lab.app import create_app

    try:
        uvicorn.run(
            create_app(state_dir=root / "state"),
            host="127.0.0.1",
            port=port,
            log_level="warning",
        )
    finally:
        assert not (root / "real-must-not-exist.db").exists(), "Sandbox touched real DB"
