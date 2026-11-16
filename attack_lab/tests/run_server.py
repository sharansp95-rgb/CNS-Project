"""Throwaway sandbox for browser tests, with a separate real-service sentinel."""

import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
with tempfile.TemporaryDirectory(prefix="cns-attack-lab-e2e-") as root:
    root = Path(root)
    os.environ["DATABASE_URL"] = "sqlite:///" + str(root / "real-must-not-exist.db")
    os.environ["LAB_DATABASE_URL"] = "sqlite:///" + str(root / "sandbox.db")
    os.environ["LAB_ALLOWED_ORIGINS"] = "http://127.0.0.1:8766"
    import uvicorn
    from attack_lab.app import create_app

    try:
        uvicorn.run(
            create_app(state_dir=root / "state"),
            host="127.0.0.1",
            port=8766,
            log_level="warning",
        )
    finally:
        assert not (root / "real-must-not-exist.db").exists(), "Sandbox touched real DB"
