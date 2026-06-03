#!/usr/bin/env python3
"""
generate_coverage.py
--------------------
Scan all detection rules in this repository, extract MITRE ATT&CK techniques
referenced in tags / metadata, and emit:

  - COVERAGE.md   : human-readable markdown report
  - coverage.json : ATT&CK Navigator-compatible layer

Source formats handled:
  - sigma/**/*.yml        -> tags: ["attack.tXXXX[.YYY]"]
  - elastic/**/*.ndjson   -> threat[].technique[].id  OR  tags: ["TXXXX"]
  - splunk/**/*.spl       -> "# MITRE ATT&CK: TXXXX, TXXXX.YYY" header
  - microsoft-sentinel/*  -> "// MITRE ATT&CK: ..." or "// MITRE: ..."
  - wazuh/**/*.xml        -> <mitre><id>TXXXX</id></mitre>
  - carbonblack/**/*.json -> tags or mitre field (best-effort)
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None

ROOT = Path(__file__).resolve().parent.parent
TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


def find_techniques_in_text(text: str) -> set[str]:
    return {m.upper() for m in TECHNIQUE_RE.findall(text)}


def parse_sigma(path: Path) -> set[str]:
    if yaml is None:
        return find_techniques_in_text(path.read_text(errors="ignore"))
    try:
        data = yaml.safe_load(path.read_text(errors="ignore"))
    except Exception:
        return set()
    if not isinstance(data, dict):
        return set()
    techs: set[str] = set()
    for tag in data.get("tags") or []:
        if isinstance(tag, str) and tag.lower().startswith("attack.t"):
            techs.update(find_techniques_in_text(tag))
    return techs


def parse_elastic(path: Path) -> set[str]:
    techs: set[str] = set()
    for line in path.read_text(errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Elastic detection-rule object structure
        threat = (
            obj.get("attributes", {}).get("threat")
            or obj.get("threat")
            or []
        )
        for t in threat:
            for tech in t.get("technique", []) or []:
                if "id" in tech:
                    techs.update(find_techniques_in_text(tech["id"]))
                for sub in tech.get("subtechnique", []) or []:
                    if "id" in sub:
                        techs.update(find_techniques_in_text(sub["id"]))
        # Fallback: scan tags
        for field in ("tags", "attributes"):
            blob = obj.get(field)
            if blob is not None:
                techs.update(find_techniques_in_text(json.dumps(blob)))
    return techs


def parse_header_comment(path: Path, prefix: str) -> set[str]:
    techs: set[str] = set()
    for line in path.read_text(errors="ignore").splitlines():
        if not line.startswith(prefix):
            # KQL files may have non-comment content; stop scanning header
            if not line.startswith(prefix.rstrip()):
                continue
        if "MITRE" in line.upper():
            techs.update(find_techniques_in_text(line))
    return techs


def parse_wazuh(path: Path) -> set[str]:
    return find_techniques_in_text(path.read_text(errors="ignore"))


def parse_carbonblack(path: Path) -> set[str]:
    try:
        obj = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return set()
    techs: set[str] = set()
    for field in ("tags", "mitre", "description", "name"):
        val = obj.get(field)
        if val:
            techs.update(find_techniques_in_text(json.dumps(val)))
    return techs


def collect_rules() -> dict[str, list[Path]]:
    return {
        "sigma":             sorted(ROOT.glob("sigma/**/*.yml")),
        "elastic":           sorted(ROOT.glob("elastic/**/*.ndjson")),
        "splunk":            sorted(ROOT.glob("splunk/**/*.spl")),
        "microsoft-sentinel": sorted(ROOT.glob("microsoft-sentinel/**/*.kql")),
        "wazuh":             sorted(ROOT.glob("wazuh/**/*.xml")),
        "carbonblack":       sorted(ROOT.glob("carbonblack/**/*.json")),
    }


def build_coverage() -> tuple[dict[str, set[str]], dict[str, dict[str, set[str]]]]:
    """
    Returns:
      technique_to_platforms : {T1059: {sigma, elastic, ...}}
      platform_to_techniques : {sigma: {T1059: {file paths}}, ...}
    """
    rules = collect_rules()
    technique_to_platforms: dict[str, set[str]] = defaultdict(set)
    platform_to_techniques: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    handlers = {
        "sigma": parse_sigma,
        "elastic": parse_elastic,
        "splunk": lambda p: parse_header_comment(p, "#"),
        "microsoft-sentinel": lambda p: parse_header_comment(p, "//"),
        "wazuh": parse_wazuh,
        "carbonblack": parse_carbonblack,
    }

    for platform, files in rules.items():
        handler = handlers[platform]
        for f in files:
            techs = handler(f)
            for t in techs:
                technique_to_platforms[t].add(platform)
                platform_to_techniques[platform][t].add(str(f.relative_to(ROOT)))
    return technique_to_platforms, platform_to_techniques


def render_markdown(t2p: dict[str, set[str]], p2t: dict[str, dict[str, set[str]]]) -> str:
    rules = collect_rules()
    total_files = sum(len(v) for v in rules.values())
    total_techs = len(t2p)

    out: list[str] = []
    out.append("# MITRE ATT&CK Coverage\n")
    out.append("> Auto-generated by `scripts/generate_coverage.py`. **Do not edit manually.**\n")
    out.append("")
    out.append("## Ringkasan\n")
    out.append(f"- Total file rule         : **{total_files}**")
    out.append(f"- Total teknik unik       : **{total_techs}**")
    out.append("")
    out.append("### Per Platform\n")
    out.append("| Platform | Rule | Teknik unik |")
    out.append("|---|---:|---:|")
    for platform in ("sigma", "elastic", "splunk", "microsoft-sentinel", "wazuh", "carbonblack"):
        out.append(
            f"| {platform} | {len(rules.get(platform, []))} | {len(p2t.get(platform, {}))} |"
        )
    out.append("")
    out.append("## Coverage Matrix\n")
    out.append("Tanda ✅ = ada minimal satu rule pada platform tersebut yang memetakan teknik.\n")
    out.append(
        "| Technique | Sigma | Elastic | Splunk | Sentinel | Wazuh | CarbonBlack |"
    )
    out.append("|---|:---:|:---:|:---:|:---:|:---:|:---:|")

    def mark(p: str, t: str) -> str:
        return "✅" if p in t2p.get(t, set()) else "·"

    for tech in sorted(t2p):
        out.append(
            f"| `{tech}` | {mark('sigma', tech)} | {mark('elastic', tech)} | "
            f"{mark('splunk', tech)} | {mark('microsoft-sentinel', tech)} | "
            f"{mark('wazuh', tech)} | {mark('carbonblack', tech)} |"
        )

    out.append("")
    out.append("## Detail per Platform\n")
    for platform, techmap in p2t.items():
        if not techmap:
            continue
        out.append(f"### {platform}\n")
        out.append("| Technique | Rule files |")
        out.append("|---|---|")
        for tech in sorted(techmap):
            files = sorted(techmap[tech])
            out.append(f"| `{tech}` | {', '.join('`'+f+'`' for f in files[:5])}"
                       f"{' ...' if len(files) > 5 else ''} |")
        out.append("")

    return "\n".join(out) + "\n"


def render_navigator(t2p: dict[str, set[str]]) -> dict:
    techniques = []
    for tech, platforms in sorted(t2p.items()):
        techniques.append({
            "techniqueID": tech,
            "score": len(platforms),
            "comment": f"Covered by: {', '.join(sorted(platforms))}",
            "enabled": True,
        })
    return {
        "name": "Detection-Rules Coverage",
        "versions": {"layer": "4.5", "navigator": "5.0", "attack": "16"},
        "domain": "enterprise-attack",
        "description": "MITRE ATT&CK coverage auto-generated from wahidhendrawan/Detection-Rules",
        "filters": {"platforms": ["Linux", "Windows", "macOS", "Network", "Cloud"]},
        "sorting": 3,
        "layout": {"layout": "side", "showName": True, "showID": False},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe6e6", "#ff6666", "#990000"],
            "minValue": 1,
            "maxValue": 6,
        },
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
    }


def main() -> int:
    t2p, p2t = build_coverage()
    md = render_markdown(t2p, p2t)
    nav = render_navigator(t2p)

    (ROOT / "COVERAGE.md").write_text(md)
    (ROOT / "coverage.json").write_text(json.dumps(nav, indent=2) + "\n")

    print(f"[+] Wrote COVERAGE.md ({len(md.splitlines())} lines)")
    print(f"[+] Wrote coverage.json ({len(nav['techniques'])} techniques)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
