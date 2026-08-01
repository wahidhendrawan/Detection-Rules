# Architecture: Detection Rules Repository

## Purpose

A centralized repository of security detection rules and hunting queries across nine platforms (Sigma, Elastic, Splunk, Sentinel, Wazuh, Carbon Black, CrowdStrike, SentinelOne, Falco). It serves as a starter pack for blue teams and detection engineers, emphasizing quality, CI validation, and MITRE ATT&CK mapping.

## Repository Structure

```
Detection-Rules/
├─ sigma/, elastic/, splunk/, .../  # Platform rule directories
├─ scripts/                         # Python toolchain source
│  └─ detection_rules/
│     ├─ __main__.py                # Main CLI dispatcher
│     └─ commands/                  # Subcommand implementations
├─ tests/
│  ├─ test_rules.py                 # Pytest fixture runner
│  └─ fixtures/                     # Behavioral test cases
├─ templates/                       # Boilerplate rule templates
├─ .github/workflows/               # CI/CD (lint, test, release)
├─ COVERAGE.md                      # ATT&CK coverage report (generated)
├─ rules.index.json                 # Rule index for web UI (generated)
└─ public/                          # GitHub Pages assets
```

## Toolchain & Automation (`scripts/detection_rules/`)

A unified Python CLI (`python -m detection_rules <command>`) orchestrates all repository maintenance, quality control, and reporting tasks.

### Core CLI Commands

| Command | Description | Implemented In |
|---|---|---|
| `lint` | Validates rule syntax (YAML, XML, JSON) and required fields (ID, title, author, MITRE tags). Can use `sigma-cli` for deeper Sigma validation. | `commands/lint.py` |
| `test` | Runs behavioral tests against `tests/fixtures/**/*.test.json`. | `commands/test.py` |
| `coverage` | Generates `COVERAGE.md` and ATT&CK Navigator JSON (`coverage-*.json`) from rule MITRE tags. | `commands/coverage.py` |
| `index` | Creates `rules.index.json` and `rules.index.yaml` for web UI consumption. | `commands/index.py` |
| `badges` | Generates dynamic JSON badges for the README (total rules, coverage, etc.). | `commands/badges.py` |
| `new` | Creates a new rule from a boilerplate template. | `commands/new.py` |
| `fix` | Applies automated fixes to rule files (e.g., MITRE tag correction). | `commands/fix.py` |
| `metrics` | Calculates repository-wide quality and performance metrics. | `commands/metrics.py` |

The entry point (`__main__.py`) uses `argparse` to dispatch to `run(args)` functions in each command module.

### Carbon Black Rule Generation

Carbon Black rules are not handwritten but generated from a matrix in `carbonblack/tools.yml`. This file defines common malicious tool names, query fields, MITRE techniques, and severity. The (now deprecated) `scripts/generate_carbonblack.py` script iterates this matrix to produce JSON query files in `carbonblack/rules/`.

## Quality & Testing

### Linting (`detection_rules lint`)

- **Syntax**: `yamllint`, `pre-commit` hooks for XML/JSON.
- **Schema**: Enforces required fields (`id`, `title`, `author`, `date`, `level`, MITRE `tags`).
- **Sigma**: Optional deep validation via `sigma-cli`.

CI (`.github/workflows/validate.yml`) runs `pre-commit` and `detection_rules lint` on every PR.

### Behavioral Testing (`detection_rules test`)

Fixture-based testing verifies rule logic without a live SIEM.
- **Fixtures**: `tests/fixtures/**/*.test.json`
- **Runner**: `tests/test_rules.py` (plugs into pytest)
- **Logic**: A simple Python DSL in `_evaluate()` mimics SIEM logic (`equals`, `contains`, `regex`, `endswith`, `startswith`).

Each fixture contains:
1. `rule`: Path to the rule file.
2. `match_condition`: Simplified, runner-friendly detection logic.
3. `test_cases`: Array of event payloads with an `expected` outcome (`match` or `no_match`).

```json
{
  "rule": "sigma/windows/win_powershell_suspicious_encoded_command.yml",
  "match_condition": {
    "Image": { "endswith": "\\powershell.exe" },
    "CommandLine": { "regex": "(?i)(-enc(odedcommand)?\\s)" }
  },
  "test_cases": [
    { "name": "matches encoded", "expected": "match", "event": { ... } },
    { "name": "no match plain", "expected": "no_match", "event": { ... } }
  ]
}
```

## Data Flow: CI & Reporting

```
Git Push (PR/main)
  ↓
GitHub Actions (.github/workflows/validate.yml)
  1. `pre-commit run --all-files`
  2. `python -m detection_rules lint`
  3. `python -m detection_rules test`
  ↓
[on main branch merge]
GitHub Actions (.github/workflows/publish.yml)
  1. `python -m detection_rules coverage` → COVERAGE.md
  2. `python -m detection_rules index` → rules.index.json
  3. `python -m detection_rules badges` → public/badges/*.json
  ↓
Commit and push generated artifacts to `main`
  ↓
GitHub Pages deploys `public/` directory
```

A scheduled workflow (`drift-detection.yml`) also runs daily to ensure generated content is up to date.

## Local Development

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run local toolchain
python -m detection_rules --help
python -m detection_rules lint
python -m detection_rules test

# Run all local pre-commit checks
pre-commit run --all-files
```

## Extension Points

1. **Add a rule**: Place file in correct platform directory. Run `detection_rules lint` and `detection_rules new-test` to create a fixture.
2. **Add a platform**: Create new top-level directory. Add parsing logic to `scripts/detection_rules/parsers.py`. Extend `lint` and `coverage` commands.
3. **Add a toolchain command**: Create `scripts/detection_rules/commands/my_command.py` with `add_arguments(parser)` and `run(args)`, then register it in `__main__.py`.
4. **Add a CI check**: Add step to `.github/workflows/validate.yml`.
5. **Add a fixture test**: Run `python -m detection_rules new-test --rule path/to/rule.yml`.
