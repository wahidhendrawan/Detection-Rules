"""
detection_rules.paths
=====================

Centralised path constants and rule-discovery helpers.
"""

from __future__ import annotations

from pathlib import Path

# repo root = grandparent of this file (scripts/detection_rules/paths.py)
ROOT = Path(__file__).resolve().parents[2]

SIGMA_DIR        = ROOT / "sigma"
ELASTIC_DIR      = ROOT / "elastic"
SPLUNK_DIR       = ROOT / "splunk"
SENTINEL_DIR     = ROOT / "microsoft-sentinel"
WAZUH_DIR        = ROOT / "wazuh"
CARBONBLACK_DIR  = ROOT / "carbonblack"

PLATFORM_GLOBS: dict[str, tuple[Path, str]] = {
    "sigma":              (SIGMA_DIR,       "**/*.yml"),
    "elastic":            (ELASTIC_DIR,     "**/*.ndjson"),
    "splunk":             (SPLUNK_DIR,      "**/*.spl"),
    "microsoft-sentinel": (SENTINEL_DIR,    "**/*.kql"),
    "wazuh":              (WAZUH_DIR,       "**/*.xml"),
    "carbonblack":        (CARBONBLACK_DIR, "**/*.json"),
}


def iter_rules(platform: str | None = None) -> dict[str, list[Path]]:
    """Return {platform: [path, ...]} for one or all platforms."""
    items = (
        [(platform, PLATFORM_GLOBS[platform])]
        if platform else list(PLATFORM_GLOBS.items())
    )
    out: dict[str, list[Path]] = {}
    for name, (base, pattern) in items:
        out[name] = sorted(base.glob(pattern))
    return out
