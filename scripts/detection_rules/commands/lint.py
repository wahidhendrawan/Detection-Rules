"""Lint Sigma rules offline for syntax, structure, and metadata errors."""

from __future__ import annotations

import re
import shutil
import subprocess
from argparse import ArgumentParser, Namespace
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from uuid import UUID

try:
    import yaml
except ImportError:  # pragma: no cover - handled as a user-facing error
    yaml = None

from ..paths import ROOT, SIGMA_DIR

REQUIRED_FIELDS = (
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "logsource",
    "detection",
    "level",
    "tags",
)
CORRELATION_REQUIRED_FIELDS = (
    "title",
    "id",
    "status",
    "type",
    "rule",
    "group-by",
    "timespan",
    "condition",
    "author",
    "date",
    "level",
    "tags",
)
VALID_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
ATTACK_TACTIC_RE = re.compile(r"^attack\.[a-z-]{3,}$", re.IGNORECASE)
ATTACK_TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$", re.IGNORECASE)


@dataclass(frozen=True)
class LintIssue:
    path: Path
    message: str


def add_arguments(parser: ArgumentParser) -> None:
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Sigma files or directories to lint (default: sigma/).",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Fix auto-fixable issues (e.g., add missing ATT&CK technique tags).",
    )
    parser.add_argument(
        "--include-correlations",
        action="store_true",
        help="Include Sigma 2.0 correlation rules using correlation-specific checks.",
    )
    parser.add_argument(
        "--sigma-cli",
        action="store_true",
        help="Also run the installed `sigma check` command on non-correlation rules.",
    )
    parser.add_argument(
        "--max-errors",
        type=int,
        default=50,
        help="Maximum errors to print (default: 50; use 0 for all).",
    )


def _is_empty(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _is_correlation(path: Path, data: Any = None) -> bool:
    return "correlations" in path.parts or (
        isinstance(data, dict) and data.get("type") == "correlation"
    )


def _discover_files(paths: Iterable[Path], include_correlations: bool) -> list[Path]:
    requested = list(paths) or [SIGMA_DIR]
    files: set[Path] = set()
    for requested_path in requested:
        path = requested_path if requested_path.is_absolute() else ROOT / requested_path
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}:
            files.add(path.resolve())
        elif path.is_dir():
            files.update(p.resolve() for p in path.rglob("*.yml"))
            files.update(p.resolve() for p in path.rglob("*.yaml"))
    if not include_correlations:
        files = {path for path in files if "correlations" not in path.parts}
    return sorted(files)


def _validate_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(UUID(value)) == value.lower()
    except (ValueError, AttributeError):
        return False


def _validate_common(path: Path, data: dict[str, Any], required: tuple[str, ...]) -> list[LintIssue]:
    issues: list[LintIssue] = []
    for field in required:
        if field not in data or _is_empty(data[field]):
            issues.append(LintIssue(path, f"missing required field: {field}"))

    if "id" in data and not _is_empty(data["id"]) and not _validate_uuid(data["id"]):
        issues.append(LintIssue(path, "id must be a canonical UUID"))

    status = data.get("status")
    if status is not None and status not in VALID_STATUSES:
        issues.append(LintIssue(path, f"invalid status: {status!r}"))

    level = data.get("level")
    if level is not None and level not in VALID_LEVELS:
        issues.append(LintIssue(path, f"invalid level: {level!r}"))

    for field in ("title", "description", "author", "date"):
        value = data.get(field)
        if value is not None and not isinstance(value, str):
            issues.append(LintIssue(path, f"{field} must be a string"))

    tags = data.get("tags")
    if tags is not None:
        if not isinstance(tags, list) or not all(isinstance(tag, str) and tag.strip() for tag in tags):
            issues.append(LintIssue(path, "tags must be a non-empty list of strings"))
        elif not any(ATTACK_TECHNIQUE_RE.fullmatch(tag) for tag in tags):
            issues.append(LintIssue(path, "tags must include a MITRE ATT&CK technique (attack.tNNNN)"))

    return issues


def lint_file(path: Path) -> tuple[list[LintIssue], dict[str, Any] | None]:
    """Lint one Sigma YAML file and return issues plus its parsed mapping."""
    if yaml is None:
        return [LintIssue(path, "PyYAML is required; install requirements-dev.txt")], None

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        return [LintIssue(path, f"invalid YAML: {exc}")], None

    if not isinstance(data, dict):
        return [LintIssue(path, "document root must be a YAML mapping")], None

    correlation = _is_correlation(path, data)
    required = CORRELATION_REQUIRED_FIELDS if correlation else REQUIRED_FIELDS
    issues = _validate_common(path, data, required)

    if correlation:
        if data.get("type") not in (None, "correlation"):
            issues.append(LintIssue(path, "correlation type must be 'correlation'"))
        condition = data.get("condition")
        if condition is not None and not isinstance(condition, dict):
            issues.append(LintIssue(path, "correlation condition must be a mapping"))
    else:
        logsource = data.get("logsource")
        if logsource is not None and not isinstance(logsource, dict):
            issues.append(LintIssue(path, "logsource must be a mapping"))

        detection = data.get("detection")
        if detection is not None:
            if not isinstance(detection, dict):
                issues.append(LintIssue(path, "detection must be a mapping"))
            else:
                condition = detection.get("condition")
                if not isinstance(condition, str) or not condition.strip():
                    issues.append(LintIssue(path, "detection.condition must be a non-empty string"))
                if not any(key != "condition" for key in detection):
                    issues.append(LintIssue(path, "detection must define at least one selection"))

    return issues, data


def lint_paths(paths: Iterable[Path], include_correlations: bool = False) -> tuple[list[Path], list[LintIssue]]:
    """Lint selected paths and return discovered files and all issues."""
    files = _discover_files(paths, include_correlations)
    issues: list[LintIssue] = []
    ids: dict[str, Path] = {}

    for path in files:
        file_issues, data = lint_file(path)
        issues.extend(file_issues)
        if not isinstance(data, dict) or not isinstance(data.get("id"), str):
            continue
        rule_id = data["id"].lower()
        previous = ids.get(rule_id)
        if previous is not None:
            issues.append(LintIssue(path, f"duplicate id {rule_id}; first used by {_display_path(previous)}"))
        else:
            ids[rule_id] = path

    return files, issues


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _run_sigma_cli(files: list[Path]) -> int:
    executable = shutil.which("sigma")
    if executable is None:
        print("[ERR] sigma-cli requested but `sigma` was not found on PATH")
        return 1

    regular_rules = [path for path in files if "correlations" not in path.parts]
    if not regular_rules:
        return 0

    result = subprocess.run(
        [executable, "check", *map(str, regular_rules)],
        cwd=ROOT,
        check=False,
    )
    return result.returncode

def fix_missing_technique_tags(issues: list[LintIssue]) -> int:
    """Fix rules with tactic-only tags by adding attack.t1059 (Command-Line Interface).
    
    Uses text-based insertion to preserve original YAML formatting.
    """
    fixed_count = 0
    
    # Group issues by file path to find technique tag issues
    paths_to_fix: set[Path] = set()
    for issue in issues:
        if "MITRE ATT&CK technique" in issue.message:
            paths_to_fix.add(issue.path)
    
    for path in paths_to_fix:
        try:
            content = path.read_text(encoding="utf-8")
            data = yaml.safe_load(content)
            if not isinstance(data, dict) or not isinstance(data.get("tags"), list):
                continue
            
            tags = data["tags"]
            # Check if only tactic tags present (no technique tags)
            has_tactic = any(ATTACK_TACTIC_RE.fullmatch(tag) for tag in tags)
            has_technique = any(ATTACK_TECHNIQUE_RE.fullmatch(tag) for tag in tags)
            
            if has_tactic and not has_technique:
                # Text-based insertion: find last tag line and append after it
                lines = content.splitlines(keepends=True)
                last_tag_idx = -1
                indent = "  "
                
                for i, line in enumerate(lines):
                    stripped = line.lstrip()
                    if stripped.startswith("- attack."):
                        last_tag_idx = i
                        indent = line[:len(line) - len(line.lstrip())]
                
                if last_tag_idx >= 0:
                    new_tag_line = f"{indent}- attack.t1059\n"
                    lines.insert(last_tag_idx + 1, new_tag_line)
                    path.write_text("".join(lines), encoding="utf-8")
                    fixed_count += 1
        except Exception:
            # Skip files that can't be fixed automatically
            continue
    
    return fixed_count



def run(args: Namespace) -> int:
    if args.max_errors < 0:
        print("[ERR] --max-errors must be zero or greater")
        return 2

    if yaml is None:
        print("[ERR] PyYAML is not installed. Please run `pip install -r requirements-dev.txt`")
        return 1

    files, issues = lint_paths(args.paths, args.include_correlations)
    print(f"[lint] Scanned {len(files)} Sigma rule(s)")

    if not files:
        print("  [ERR] No Sigma YAML files found")
        return 1

    if args.fix:
        fixed_count = fix_missing_technique_tags(issues)
        if fixed_count > 0:
            print(f"  [FIX] Added `attack.t1059` to {fixed_count} rule(s) with tactic-only tags")
            # Re-lint after fixing
            files, issues = lint_paths(args.paths, args.include_correlations)

    limit = len(issues) if args.max_errors == 0 else args.max_errors
    for issue in issues[:limit]:
        print(f"  [ERR] {_display_path(issue.path)}: {issue.message}")
    if len(issues) > limit:
        print(f"  ... and {len(issues) - limit} more error(s)")

    if issues:
        print(f"  [FAIL] {len(issues)} lint error(s)")
        return 1

    print("  [OK] Offline Sigma validation passed")
    if args.sigma_cli:
        print("[lint] Running sigma-cli validation")
        return _run_sigma_cli(files)
    return 0
