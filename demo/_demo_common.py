"""Compatibility alias for the sandbox demo helpers."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attack_lab.scripts import _demo_common as implementation

sys.modules[__name__] = implementation
