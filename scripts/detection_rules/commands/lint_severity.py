"""Lint rules for missing or inconsistent severity levels."""

from __future__ import annotations

import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path

from ..parsers import parse
from ..paths import ROOT, iter_rules

VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}

# One-liner heuristic: rules with very short query and no contextual filters
# should not be high/critical.
SHORT_QUERY_THRESHOLD = 300  # bytes


def _is_one_liner(raw, path: Path) -> bool:
    """Heuristic: rule body is very short / no meaningful filter."""
    if isinstance(raw, str):
        return len(raw.strip()) < SHORT_QUERY_THRESHOLD
    if isinstance(raw, dict):
        body = raw.get("body", "")
        if isinstance(body, str) and len(body.strip()) < SHORT_QUERY_THRESHOLD:
            return True
        # Sigma: check if detection has only a simple selection
        det = raw.get("detection", {})
        if isinstance(det, dict):
            cond = det.get("condition", "")
            if isinstance(cond, str) and cond.strip() == "selection":
                sel = det.get("selection", {})
                if isinstance(sel, dict) and len(sel) <= 2:
                    return True
    return False


def add_arguments(parser: ArgumentParser) -> None:
    parser.add_argument("--platform", default=None,
                        help="Limit to one platform (sigma, elastic, etc.)")
    parser.add_argument("--fail-on-missing", action="store_true",
                        help="Exit non-zero if any rule lacks severity.")
    parser.add_argument("--fail-on-mismatch", action="store_true",
                        help="Exit non-zero if severity seems wrong for rule complexity.")


def run(args: Namespace) -> int:
    rules = iter_rules(args.platform) if args.platform else iter_rules()
    missing: list[str] = []
    invalid: list[str] = []
    mismatch: list[str] = []

    for platform, files in rules.items():
        for f in files:
            try:
                rule = parse(platform, f)
            except Exception:
                continue
            rel = str(f.relative_to(ROOT))
            level = str(rule.get("level") or "").lower().strip()

            if not level:
                missing.append(rel)
                continue

            if level not in VALID_LEVELS:
                invalid.append(f"{rel} (got: {level})")
                continue

            # Mismatch: one-liner labeled high/critical
            if level in ("high", "critical") and _is_one_liner(rule.get("raw"), f):
                mismatch.append(f"{rel} (level={level}, but rule looks trivial)")

    # Report
    print(f"[lint-severity] Scanned {sum(len(v) for v in rules.values())} rules")
    if missing:
        print(f"\n  [WARN] Missing severity: {len(missing)}")
        for r in missing[:20]:
            print(f"    - {r}")
        if len(missing) > 20:
            print(f"    ... and {len(missing) - 20} more")
    if invalid:
        print(f"\n  [ERR] Invalid severity value: {len(invalid)}")
        for r in invalid[:10]:
            print(f"    - {r}")
    if mismatch:
        print(f"\n  [WARN] Severity/complexity mismatch: {len(mismatch)}")
        for r in mismatch[:20]:
            print(f"    - {r}")
        if len(mismatch) > 20:
            print(f"    ... and {len(mismatch) - 20} more")

    if not missing and not invalid and not mismatch:
        print("  [OK] All rules pass severity lint.")

    rc = 0
    if args.fail_on_missing and missing:
        rc = 1
    if args.fail_on_mismatch and mismatch:
        rc = 1
    if invalid:
        rc = 1
    return rc
