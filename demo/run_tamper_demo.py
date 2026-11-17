"""Compatibility entry point; implementation lives in attack_lab/scripts/."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attack_lab.scripts._demo_common import isolate_demo_state
from attack_lab.scripts.run_tamper_demo import main

if __name__ == "__main__":
    isolate_demo_state()
    main()
