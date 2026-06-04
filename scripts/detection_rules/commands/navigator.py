"""Emit ATT&CK Navigator layers (overall + per platform)."""

from __future__ import annotations

import json
from argparse import ArgumentParser, Namespace
from collections import defaultdict
from pathlib import Path

from ..parsers import parse
from ..paths import ROOT, iter_rules


PLATFORM_COLORS = {
    "sigma":              "#1f77b4",
    "elastic":            "#ff7f0e",
    "splunk":             "#2ca02c",
    "microsoft-sentinel": "#d62728",
    "wazuh":              "#9467bd",
    "carbonblack":        "#8c564b",
}


def _layer(name: str, description: str, techniques: list[dict],
           color_min: str = "#ffe6e6", color_max: str = "#990000",
           min_value: int = 1, max_value: int = 6) -> dict:
    return {
        "name": name,
        "versions": {"layer": "4.5", "navigator": "5.0", "attack": "16"},
        "domain": "enterprise-attack",
        "description": description,
        "filters": {"platforms": ["Linux", "Windows", "macOS", "Network", "Cloud"]},
        "sorting": 3,
        "layout": {"layout": "side", "showName": True, "showID": False},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": [color_min, color_max],
            "minValue": min_value,
            "maxValue": max_value,
        },
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
    }


def add_arguments(parser: ArgumentParser) -> None:
    parser.add_argument("--out-dir", default=str(ROOT / "navigator-layers"))


def run(args: Namespace) -> int:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rules = iter_rules()
    overall: dict[str, set[str]] = defaultdict(set)         # tech -> platforms
    per_platform: dict[str, set[str]] = defaultdict(set)    # platform -> techs

    for platform, files in rules.items():
        for f in files:
            for t in parse(platform, f)["techniques"]:
                overall[t].add(platform)
                per_platform[platform].add(t)

    # overall layer
    overall_techs = [
        {
            "techniqueID": t,
            "score": len(p),
            "comment": f"Covered by: {', '.join(sorted(p))}",
            "enabled": True,
        }
        for t, p in sorted(overall.items())
    ]
    (out_dir / "coverage-overall.json").write_text(
        json.dumps(_layer(
            "Detection-Rules — Overall Coverage",
            "MITRE ATT&CK techniques covered across all platforms.",
            overall_techs,
            min_value=1, max_value=6,
        ), indent=2) + "\n"
    )

    # per-platform layers
    for platform, techs in per_platform.items():
        techs_payload = [
            {
                "techniqueID": t,
                "score": 1,
                "color": PLATFORM_COLORS.get(platform),
                "enabled": True,
            }
            for t in sorted(techs)
        ]
        (out_dir / f"coverage-{platform}.json").write_text(
            json.dumps(_layer(
                f"Detection-Rules — {platform.title()}",
                f"Techniques detected by {platform} rules in this repository.",
                techs_payload,
                min_value=1, max_value=1,
            ), indent=2) + "\n"
        )

    print(f"[+] Wrote {out_dir}/coverage-overall.json")
    for platform in per_platform:
        print(f"[+] Wrote {out_dir}/coverage-{platform}.json")
    return 0
