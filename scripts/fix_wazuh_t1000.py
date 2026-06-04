#!/usr/bin/env python3
"""DEPRECATED — use `python -m detection_rules fix wazuh` instead."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from detection_rules.__main__ import main  # noqa: E402
if __name__ == "__main__":
    sys.exit(main(["fix", "wazuh"]))
