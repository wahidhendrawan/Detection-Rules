"""Regression tests for the offline Sigma linter."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from detection_rules.commands import lint


def write_rule(path: Path, overrides: str = "") -> Path:
    path.write_text(
        """title: Valid test rule
id: 123e4567-e89b-12d3-a456-426614174000
status: experimental
description: Detects a test event.
author: Test Author
date: 2026/08/01
logsource:
  product: windows
detection:
  selection:
    EventID: 1
  condition: selection
level: medium
tags:
  - attack.t1059
""" + overrides,
        encoding="utf-8",
    )
    return path


def test_lint_file_accepts_complete_rule(tmp_path: Path):
    issues, data = lint.lint_file(write_rule(tmp_path / "valid.yml"))

    assert issues == []
    assert data is not None
    assert data["title"] == "Valid test rule"


def test_lint_file_reports_missing_detection_condition(tmp_path: Path):
    path = write_rule(tmp_path / "missing-condition.yml")
    path.write_text(path.read_text(encoding="utf-8").replace("  condition: selection\n", ""), encoding="utf-8")

    issues, _ = lint.lint_file(path)

    assert any(issue.message == "detection.condition must be a non-empty string" for issue in issues)


def test_lint_file_reports_invalid_uuid_and_attack_tag(tmp_path: Path):
    path = write_rule(tmp_path / "invalid-metadata.yml")
    text = path.read_text(encoding="utf-8")
    text = text.replace("123e4567-e89b-12d3-a456-426614174000", "not-a-uuid")
    text = text.replace("  - attack.t1059", "  - attack.execution")
    path.write_text(text, encoding="utf-8")

    issues, _ = lint.lint_file(path)
    messages = {issue.message for issue in issues}

    assert "id must be a canonical UUID" in messages
    assert "tags must include a MITRE ATT&CK technique (attack.tNNNN)" in messages


def test_lint_paths_reports_duplicate_ids(tmp_path: Path):
    write_rule(tmp_path / "one.yml")
    write_rule(tmp_path / "two.yml")

    files, issues = lint.lint_paths([tmp_path])

    assert len(files) == 2
    assert any(issue.message.startswith("duplicate id") for issue in issues)


def test_lint_paths_skips_correlations_unless_requested(tmp_path: Path):
    correlations = tmp_path / "correlations"
    correlations.mkdir()
    correlation = correlations / "count.yml"
    correlation.write_text(
        """title: Valid correlation
id: 223e4567-e89b-12d3-a456-426614174000
status: experimental
type: correlation
rule: base_rule
group-by:
  - User
timespan: 5m
condition:
  gte: 5
author: Test Author
date: 2026/08/01
level: high
tags:
  - attack.t1110
""",
        encoding="utf-8",
    )

    skipped_files, skipped_issues = lint.lint_paths([tmp_path])
    included_files, included_issues = lint.lint_paths([tmp_path], include_correlations=True)

    assert skipped_files == []
    assert skipped_issues == []
    assert included_files == [correlation.resolve()]
    assert included_issues == []


def test_run_rejects_negative_max_errors(capsys):
    result = lint.run(SimpleNamespace(max_errors=-1, paths=[], include_correlations=False, sigma_cli=False, fix=False))

    assert result == 2
    assert "--max-errors must be zero or greater" in capsys.readouterr().out


def test_run_with_sigma_cli_returns_subprocess_failure(tmp_path: Path, monkeypatch):
    write_rule(tmp_path / "valid.yml")
    monkeypatch.setattr(lint, "_run_sigma_cli", lambda _: 7)

    result = lint.run(
        SimpleNamespace(max_errors=50, paths=[tmp_path], include_correlations=False, sigma_cli=True, fix=False)
    )

    assert result == 7

def test_fix_missing_technique_tags_appends_placeholder(tmp_path: Path):
    path = write_rule(tmp_path / "tactic-only.yml")
    text = path.read_text(encoding="utf-8").replace("  - attack.t1059", "  - attack.execution")
    path.write_text(text, encoding="utf-8")

    _, issues = lint.lint_paths([tmp_path])
    fixed = lint.fix_missing_technique_tags(issues)

    updated = path.read_text(encoding="utf-8")
    assert fixed == 1
    assert "- attack.execution" in updated
    assert "- attack.t1059" in updated

    _, post_issues = lint.lint_paths([tmp_path])
    assert post_issues == []

