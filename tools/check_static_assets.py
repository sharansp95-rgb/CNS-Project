"""Fail a Python-only Render build if a committed frontend entry/bundle is absent."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT / "web/static", ROOT / "attack_lab/static"):
    entry = directory / "index.html"
    if not entry.is_file():
        raise SystemExit(
            "Missing built entry; run both frontend build commands and commit static assets"
        )
    for reference in re.findall(
        r'(?:src|href)="(/(?:assets|console-assets)/[^"?#]+)', entry.read_text()
    ):
        if not (directory / reference.lstrip("/")).is_file():
            raise SystemExit("Missing committed bundle: " + reference)
print("Both committed frontend entries and referenced bundles are present")
