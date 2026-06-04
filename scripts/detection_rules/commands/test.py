"""Run rule unit tests against event fixtures."""

from __future__ import annotations

import json
import re
import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path

from ..paths import ROOT

TESTS_DIR = ROOT / "tests" / "fixtures"


def add_arguments(parser: ArgumentParser) -> None:
    parser.add_argument(
        "--fixtures-dir", default=str(TESTS_DIR),
        help="Directory containing rule test fixtures (.test.json).",
    )
    parser.add_argument(
        "--rule", default=None,
        help="Path to a specific rule to test (default: all in fixtures-dir).",
    )


def _load_fixture(path: Path) -> dict:
    return json.loads(path.read_text())


def _evaluate(condition: dict, event: dict) -> bool:
    """
    Evaluate a fixture condition against an event.

    Supported operators (per field):
      - "equals"
      - "contains"
      - "regex"
      - "in" (list membership)
      - "endswith"
      - "startswith"
    """
    for field, expected in condition.items():
        actual = event.get(field, "")
        if isinstance(expected, dict):
            for op, val in expected.items():
                if op == "equals" and str(actual) != str(val):
                    return False
                if op == "contains" and str(val) not in str(actual):
                    return False
                if op == "regex" and not re.search(val, str(actual)):
                    return False
                if op == "in" and actual not in val:
                    return False
                if op == "endswith" and not str(actual).endswith(val):
                    return False
                if op == "startswith" and not str(actual).startswith(val):
                    return False
        else:
            if str(actual) != str(expected):
                return False
    return True


def _run_fixture(path: Path) -> tuple[int, int, list[str]]:
    """Run a single fixture and return (passed, failed, error_messages)."""
    fixture = _load_fixture(path)
    rule_path = ROOT / fixture["rule"]
    if not rule_path.exists():
        return 0, 1, [f"{path.name}: rule file not found: {fixture['rule']}"]

    cases = fixture.get("test_cases", [])
    passed = failed = 0
    errors: list[str] = []
    for case in cases:
        expected = case["expected"]  # "match" or "no_match"
        condition = fixture["match_condition"]
        event = case["event"]
        result = _evaluate(condition, event)
        actual = "match" if result else "no_match"
        if actual == expected:
            passed += 1
        else:
            failed += 1
            errors.append(
                f"{path.name}::{case.get('name', '?')} "
                f"expected={expected} got={actual}"
            )
    return passed, failed, errors


def run(args: Namespace) -> int:
    fixtures_dir = Path(args.fixtures_dir)
    if not fixtures_dir.exists():
        print(f"[!] No fixtures directory: {fixtures_dir}", file=sys.stderr)
        print("    Create test fixtures under tests/fixtures/ — see tests/README.md")
        return 0  # not a failure: tests are opt-in

    fixtures = sorted(fixtures_dir.glob("**/*.test.json"))
    if args.rule:
        fixtures = [f for f in fixtures if str(args.rule) in _load_fixture(f).get("rule", "")]

    if not fixtures:
        print("[i] No fixtures matched.")
        return 0

    total_passed = total_failed = 0
    all_errors: list[str] = []
    for f in fixtures:
        p, fcount, errs = _run_fixture(f)
        total_passed += p
        total_failed += fcount
        all_errors.extend(errs)

    for e in all_errors:
        print(f"[FAIL] {e}", file=sys.stderr)

    print(
        f"\n[result] {total_passed} passed, {total_failed} failed "
        f"across {len(fixtures)} fixture(s)."
    )
    return 1 if total_failed else 0
