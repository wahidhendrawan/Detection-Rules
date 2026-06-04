#!/usr/bin/env python3
"""DEPRECATED — use `python -m detection_rules coverage` instead.

Kept as a thin shim for backward compatibility.
"""
from __future__ import annotations
import sys
from pathlib import Path

# allow `python scripts/generate_coverage.py` from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent))

from detection_rules.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(["coverage"]))
