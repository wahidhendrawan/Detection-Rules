# Detection Rule Tests

This directory contains **unit tests** for detection rules — fixture-based
tests that verify each rule fires (or correctly does not fire) against a
representative set of synthetic events.

## Why fixture tests?

Detection rules are usually validated only at the syntax level. Fixture
tests add a layer of *behavioral* validation:

1. **Regression safety** — refactoring a rule does not silently break it.
2. **False-positive documentation** — every rule ships with an event that
   "looks suspicious but is benign".
3. **Onboarding** — newcomers can read the test fixture to understand
   exactly what the rule is meant to catch.

## Layout

```
tests/
├─ README.md
├─ conftest.py
├─ test_rules.py
└─ fixtures/
   └─ <platform>/
      └─ <rule>.test.json
```

Each fixture is a JSON file describing:

- which rule it tests (`rule`),
- the simplified detection condition the test runner will evaluate
  (`match_condition`), and
- a list of test cases with `event` payloads and the expected outcome
  (`match` or `no_match`).

> **Note:** `match_condition` is intentionally a re-statement of the rule
> in a runner-friendly DSL. This is what makes the test independent of the
> SIEM backend and lets us cover Sigma / Splunk / KQL / Wazuh in one
> framework. Keep it minimal — the rule itself is the source of truth.

## Fixture schema

```json
{
  "rule": "sigma/windows/win_powershell_suspicious_encoded_command.yml",
  "description": "PowerShell -EncodedCommand abuse (T1059.001 / T1027)",
  "match_condition": {
    "Image":       { "endswith": "\\powershell.exe" },
    "CommandLine": { "regex": "(?i)(-enc(odedcommand)?\\s)" }
  },
  "test_cases": [
    {
      "name": "matches encoded command",
      "expected": "match",
      "event": {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -EncodedCommand JABw..."
      }
    },
    {
      "name": "does not match plain powershell",
      "expected": "no_match",
      "event": {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe Get-Process"
      }
    },
    {
      "name": "does not match unrelated process",
      "expected": "no_match",
      "event": {
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c dir"
      }
    }
  ]
}
```

### Supported operators

Inside `match_condition`, each field maps to either a literal value or an
operator object:

| Operator    | Meaning                                |
|-------------|-----------------------------------------|
| `equals`    | exact string match                      |
| `contains`  | substring match (case-sensitive)        |
| `regex`     | Python `re.search` regex                |
| `in`        | value is in the given list              |
| `endswith`  | string suffix                           |
| `startswith`| string prefix                           |

## Running the tests

```bash
# Custom CLI (no extra dependencies):
python -m detection_rules test

# Or via pytest (recommended in CI):
pip install pytest
pytest tests/
```

Both runners walk `tests/fixtures/**/*.test.json`, evaluate every test
case, and exit non-zero if any case fails.

## Adding a fixture

1. Create `tests/fixtures/<platform>/<rule_basename>.test.json` mirroring
   the rule's location.
2. At minimum include **one match case** and **one no-match case**.
3. Include a "false-positive lookalike" case whenever possible — an event
   that resembles the suspicious one but should be allow-listed.
4. Run `python -m detection_rules test` locally before opening a PR.

## What this framework does *not* do

- It does not call the actual SIEM. You still need to deploy the rule and
  validate end-to-end in staging before production.
- It does not exercise complex correlations / aggregations (yet). Such
  rules can still ship a fixture with a representative event; the test
  documents intent even if it cannot fully simulate behavior.
