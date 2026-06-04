# Rule Lifecycle & Deprecation Policy

## Status Values

Every rule has a lifecycle status:

| Status | Meaning |
|---|---|
| `experimental` | New rule, not yet validated in production |
| `test` | Under active testing/tuning |
| `stable` | Production-ready, validated |
| `deprecated` | Superseded or no longer relevant; will be removed in next major release |

## Deprecating a Rule

When a rule is no longer relevant (technique obsolete, replaced by better rule, or generates too many FPs without fix):

1. **Add deprecation metadata** to the rule:

### Sigma
```yaml
status: deprecated
custom:
  deprecated_date: "2026-06-01"
  replaced_by: "win_improved_certutil_detection.yml"
  reason: "Superseded by rule with better FP filtering"
```

### Carbon Black / Elastic (JSON)
```json
{
  "status": "deprecated",
  "deprecated_date": "2026-06-01",
  "replaced_by": "cb_new_rule.json",
  "reason": "Replaced by behavioral detection"
}
```

### Wazuh (XML)
```xml
<!-- status: deprecated -->
<!-- deprecated_date: 2026-06-01 -->
<!-- replaced_by: new_rule.xml -->
<!-- reason: High false positive rate, replaced -->
```

### Sentinel (KQL) / Splunk (SPL)
```
// Status: deprecated
// Deprecated-Date: 2026-06-01
// Replaced-By: kql_101_improved.kql
// Reason: Superseded by enriched detection
```

2. **Move to `deprecated/` subfolder** within the platform directory:
```
sigma/
├─ windows/
├─ deprecated/       ← deprecated Sigma rules
carbonblack/
├─ rules/
├─ deprecated/       ← deprecated CB rules
```

3. **Update CHANGELOG.md** with deprecation notice.

## Tooling Integration

- `detection_rules coverage` — **excludes** deprecated rules from technique count
- `detection_rules metrics` — reports deprecated rules separately
- `detection_rules lint-severity` — skips deprecated rules
- CI validation — still validates syntax (no broken files), but does not require ATT&CK mapping

## Retention

Deprecated rules are kept for **one major version** (e.g., deprecated in v1.x, removed in v2.0). This gives users time to migrate.

## Convention

- Deprecation PR must include `reason` and ideally `replaced_by`
- If no replacement exists, document in the PR why the detection gap is acceptable
