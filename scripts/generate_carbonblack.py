"""Generate Carbon Black JSON rules from tools.yml matrix.

Usage: python scripts/generate_carbonblack.py [--dry-run]
"""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required: pip install pyyaml")

ROOT = Path(__file__).resolve().parents[1]
TOOLS_YML = ROOT / "carbonblack" / "tools.yml"
OUT_DIR = ROOT / "carbonblack" / "rules"

# Query field per event type
EVENT_QUERY_PREFIX = {
    "process_creation": "process_name",
    "childproc_creation": "childproc_name",
    "file_modification": "filemod_name",
    "network_connection": "netconn_domain",
    "registry_modification": "regmod_name",
}


def generate(dry_run: bool = False) -> int:
    config = yaml.safe_load(TOOLS_YML.read_text())
    event_types = config["event_types"]
    tools = config["tools"]
    specials = config.get("special", [])
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    count = 0
    # Matrix: event_type × tool
    for event in event_types:
        prefix = EVENT_QUERY_PREFIX[event]
        for tool in tools:
            name = f"cb_{event}_{tool['name']}"
            filename = f"{name}.json"
            rule = {
                "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, name)),
                "name": name,
                "description": f"Detects {event.replace('_', ' ')} involving {tool['query_field']} ({tool['description']})",
                "mitre": tool["mitre"],
                "query": f"{prefix}:{tool['query_field']}",
                "severity": tool["severity"],
                "enabled": True,
                "category": event,
            }
            path = OUT_DIR / filename
            if dry_run:
                print(f"  [dry-run] {filename}")
            else:
                path.write_text(json.dumps(rule, indent=2) + "\n")
            count += 1

    # Special rules
    for spec in specials:
        rule = {
            "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, spec["name"])),
            "name": spec["name"],
            "description": spec["description"],
            "mitre": spec["mitre"],
            "query": spec["query"],
            "severity": spec["severity"],
            "enabled": True,
            "category": "special",
        }
        path = OUT_DIR / spec["filename"]
        if dry_run:
            print(f"  [dry-run] {spec['filename']}")
        else:
            path.write_text(json.dumps(rule, indent=2) + "\n")
        count += 1

    print(f"[generate-cb] {'Would generate' if dry_run else 'Generated'} {count} rules")
    return 0


if __name__ == "__main__":
    dry_run = "--dry-run" in sys.argv
    sys.exit(generate(dry_run))
