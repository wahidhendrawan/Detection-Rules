"""Emit shields.io endpoint JSONs for live README badges."""

from __future__ import annotations

import json
from argparse import ArgumentParser, Namespace
from datetime import datetime, timezone
from pathlib import Path

from ..parsers import parse
from ..paths import ROOT, iter_rules


def _color_for_score(score: float) -> str:
    if score >= 80: return "brightgreen"
    if score >= 60: return "green"
    if score >= 40: return "yellowgreen"
    if score >= 20: return "yellow"
    return "red"


def _color_for_count(count: int, low: int, high: int) -> str:
    if count >= high: return "brightgreen"
    if count >= low: return "green"
    return "yellow"


def add_arguments(parser: ArgumentParser) -> None:
    parser.add_argument("--out-dir", default=str(ROOT / "public" / "badges"))


def run(args: Namespace) -> int:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rules = iter_rules()
    total_rules = sum(len(v) for v in rules.values())

    techniques: set[str] = set()
    rules_with_attack = 0
    rules_with_severity = 0
    total_quality_score = 0.0

    for platform, files in rules.items():
        for f in files:
            r = parse(platform, f)
            if r["techniques"]:
                rules_with_attack += 1
                techniques.update(r["techniques"])
            if r.get("level"):
                rules_with_severity += 1
            # naive quality contribution: tech mapping + severity
            total_quality_score += (
                50 * (1 if r["techniques"] else 0)
                + 30 * (1 if r.get("level") else 0)
                + 20 * (1 if r.get("title") and r["title"] != f.stem else 0)
            )

    avg_quality = round(total_quality_score / max(total_rules, 1), 1)
    pct_attack = round(100 * rules_with_attack / max(total_rules, 1), 1)

    badges = {
        "rules-total.json": {
            "schemaVersion": 1, "label": "rules", "message": str(total_rules),
            "color": "blue",
        },
        "techniques.json": {
            "schemaVersion": 1, "label": "ATT&CK techniques",
            "message": str(len(techniques)),
            "color": _color_for_count(len(techniques), 50, 100),
        },
        "platforms.json": {
            "schemaVersion": 1, "label": "platforms",
            "message": str(sum(1 for v in rules.values() if v)),
            "color": "informational",
        },
        "attack-coverage.json": {
            "schemaVersion": 1, "label": "ATT&CK mapping",
            "message": f"{pct_attack}%",
            "color": _color_for_score(pct_attack),
        },
        "quality-score.json": {
            "schemaVersion": 1, "label": "quality score",
            "message": f"{avg_quality}/100",
            "color": _color_for_score(avg_quality),
        },
        "last-validated.json": {
            "schemaVersion": 1, "label": "last validated",
            "message": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "color": "blue",
        },
    }

    for name, payload in badges.items():
        (out_dir / name).write_text(json.dumps(payload) + "\n")
        print(f"[+] {out_dir / name}: {payload['message']}")

    return 0
