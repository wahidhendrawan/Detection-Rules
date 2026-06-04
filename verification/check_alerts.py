"""Verify that SIEM alerts fired after atomic test execution.

Usage: python verification/check_alerts.py --config verification/config.yml --run-file results/run_*.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required")


def load_config(path: str) -> dict:
    return yaml.safe_load(Path(path).read_text())


def check_elastic(config: dict, techniques: list[str]) -> dict[str, bool]:
    """Query Elastic SIEM for alerts matching techniques. Placeholder."""
    # TODO: implement via elasticsearch-py or requests
    print(f"[elastic] Would check {len(techniques)} techniques against {config.get('url', 'N/A')}")
    return {t: False for t in techniques}


def check_splunk(config: dict, techniques: list[str]) -> dict[str, bool]:
    """Query Splunk for notable events. Placeholder."""
    print(f"[splunk] Would check {len(techniques)} techniques")
    return {t: False for t in techniques}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="verification/config.yml")
    parser.add_argument("--run-file", required=True, help="JSON from run_atomics.ps1")
    args = parser.parse_args()

    config = load_config(args.config)
    run_data = json.loads(Path(args.run_file).read_text())

    techniques = [r["technique"] for r in run_data if r.get("status") == "executed"]
    if not techniques:
        print("[!] No successfully executed techniques in run file.")
        return 1

    results = {}
    backend = config.get("backend", "elastic")
    if backend == "elastic":
        results = check_elastic(config.get("elastic", {}), techniques)
    elif backend == "splunk":
        results = check_splunk(config.get("splunk", {}), techniques)

    # Report
    detected = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"\n[Results] {detected}/{total} techniques triggered alerts")
    for tech, fired in sorted(results.items()):
        status = "PASS" if fired else "MISS"
        print(f"  {status} {tech}")

    return 0 if detected == total else 1


if __name__ == "__main__":
    sys.exit(main())
