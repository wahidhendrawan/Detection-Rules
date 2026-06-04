"""Scaffold a new detection rule from a platform template."""

from __future__ import annotations

import re
import uuid
from argparse import ArgumentParser, Namespace
from datetime import date
from pathlib import Path

from ..paths import ROOT

TEMPLATES_DIR = ROOT / "templates"

PLATFORM_EXT = {
    "sigma": ".yml",
    "elastic": ".ndjson",
    "splunk": ".spl",
    "sentinel": ".kql",
    "wazuh": ".xml",
    "carbonblack": ".json",
}

OS_PREFIX = {
    "windows": "win",
    "linux": "lnx",
    "network": "net",
    "cloud": "cloud",
}

# Maps platform to its output base directory
PLATFORM_DIR = {
    "sigma": ROOT / "sigma",
    "elastic": ROOT / "elastic" / "endpoint",
    "splunk": ROOT / "splunk",
    "sentinel": ROOT / "microsoft-sentinel",
    "wazuh": ROOT / "wazuh" / "rules",
    "carbonblack": ROOT / "carbonblack" / "rules",
}


def _title_to_snake(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")


def _build_output_path(platform: str, os_name: str, title: str) -> Path:
    ext = PLATFORM_EXT[platform]
    prefix = OS_PREFIX[os_name]
    snake = _title_to_snake(title)
    filename = f"{prefix}_{snake}{ext}"

    base = PLATFORM_DIR[platform]
    # Platforms with OS subfolders
    if platform in ("sigma", "splunk", "elastic"):
        return base / os_name / filename
    # sentinel uses flat directory with a prefix style
    if platform == "sentinel":
        return base / filename
    # wazuh and carbonblack use flat rules/ dir
    return base / filename


def add_arguments(parser: ArgumentParser) -> None:
    parser.add_argument("--platform", required=True,
                        choices=list(PLATFORM_EXT.keys()))
    parser.add_argument("--os", required=True, dest="os_name",
                        choices=["windows", "linux", "network", "cloud"])
    parser.add_argument("--technique", required=True,
                        help="MITRE ATT&CK technique ID (e.g. T1059.001)")
    parser.add_argument("--severity", required=True,
                        choices=["low", "medium", "high", "critical"])
    parser.add_argument("--title", required=True,
                        help="Short descriptive title for the rule")


def run(args: Namespace) -> int:
    template_file = TEMPLATES_DIR / f"{args.platform}{PLATFORM_EXT[args.platform]}"
    if not template_file.exists():
        print(f"Error: template not found: {template_file}")
        return 1

    content = template_file.read_text(encoding="utf-8")

    # Replacements
    rule_id = str(uuid.uuid4())
    today = date.today().strftime("%Y/%m/%d")
    today_dash = date.today().strftime("%Y-%m-%d")

    replacements = {
        "<generate uuid v4 here>": rule_id,
        "<generate-uuid-v4>": rule_id,
        "<Short descriptive title, max 80 chars>": args.title,
        "<Short descriptive title>": args.title,
        "<short_descriptive_name>": _title_to_snake(args.title),
        "<one-line description>": args.title,
        "<one-line description of what is detected>": args.title,
        "<Your Name>": "Detection-Rules",
        "2026/01/01": today,
        "2026-01-01": today_dash,
        "TXXXX.YYY": args.technique,
        "TXXXX": args.technique.split(".")[0],
        "tXXXX.YYY": args.technique.lower(),
        "tXXXX": args.technique.split(".")[0].lower(),
        "level: high": f"level: {args.severity}",
        '"severity": "high"': f'"severity": "{args.severity}"',
        "# Severity: high": f"# Severity: {args.severity}",
        "// Severity: High": f"// Severity: {args.severity.capitalize()}",
    }

    for old, new in replacements.items():
        content = content.replace(old, new)

    output = _build_output_path(args.platform, args.os_name, args.title)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    print(f"Created: {output.relative_to(ROOT)}")
    return 0
