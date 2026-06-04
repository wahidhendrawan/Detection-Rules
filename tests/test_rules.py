"""
Pytest entrypoint that runs every fixture under tests/fixtures/.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def _evaluate(condition: dict, event: dict) -> bool:
    """Evaluate a fixture condition against an event payload."""
    for field, expected in condition.items():
        actual = event.get(field, "")
        if isinstance(expected, dict):
            for op, val in expected.items():
                a = str(actual)
                if op == "equals" and a != str(val):
                    return False
                if op == "contains" and str(val) not in a:
                    return False
                if op == "regex" and not re.search(val, a):
                    return False
                if op == "in" and actual not in val:
                    return False
                if op == "endswith" and not a.endswith(val):
                    return False
                if op == "startswith" and not a.startswith(val):
                    return False
        else:
            if str(actual) != str(expected):
                return False
    return True


def _collect() -> list[tuple[Path, dict, dict]]:
    out: list[tuple[Path, dict, dict]] = []
    for fixture_path in sorted(FIXTURES.glob("**/*.test.json")):
        fixture = json.loads(fixture_path.read_text())
        for case in fixture.get("test_cases", []):
            out.append((fixture_path, fixture, case))
    return out


@pytest.mark.parametrize("fixture_path,fixture,case", _collect(),
                         ids=lambda x: x if isinstance(x, str) else "")
def test_rule(fixture_path: Path, fixture: dict, case: dict):
    rule_path = ROOT / fixture["rule"]
    assert rule_path.exists(), (
        f"{fixture_path.name}: rule file not found: {fixture['rule']}"
    )
    expected = case["expected"]
    actual = "match" if _evaluate(fixture["match_condition"], case["event"]) else "no_match"
    assert actual == expected, (
        f"{fixture_path.name}::{case.get('name', '?')}: "
        f"expected {expected}, got {actual}"
    )
