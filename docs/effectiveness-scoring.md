# Rule Effectiveness Scoring

## Overview

Every detection rule receives an **effectiveness score** on a 0–1 scale representing how reliably it produces true-positive alerts in production. A score of `1.0` means every alert was confirmed malicious; `0.0` means every alert was a false positive.

## Fields

Add these fields to each rule's metadata:

| Field | Type | Description |
|-------|------|-------------|
| `effectiveness` | float (0-1) | Current effectiveness score |
| `last_tuned` | date | Last time the rule was tuned based on feedback |
| `fp_rate` | float (0-1) | False-positive rate over scoring window |
| `tp_rate` | float (0-1) | True-positive rate over scoring window |

## SOC Feedback Loop

1. Alert fires in SIEM/SOAR.
2. Analyst triages and labels the alert as **TP** (true positive) or **FP** (false positive).
3. Labels are exported weekly to the detection engineering pipeline.
4. The pipeline recalculates effectiveness per rule and updates metadata.
5. Rules falling below threshold (e.g., < 0.3) are flagged for tuning.

## Scoring Formula

```
effectiveness = tp / (tp + fp) * volume_weight
```

Where:
- `tp` = count of true-positive labels in the scoring window (default 30 days)
- `fp` = count of false-positive labels in the scoring window
- `volume_weight` = min(1.0, alert_count / minimum_sample_size)

The volume weight ensures rules with very few alerts don't get artificially high or low scores. Default `minimum_sample_size` is 20 alerts.

### Interpretation

| Score | Meaning | Action |
|-------|---------|--------|
| 0.8 – 1.0 | Excellent | No action needed |
| 0.5 – 0.8 | Acceptable | Monitor, consider tuning |
| 0.3 – 0.5 | Poor | Schedule tuning |
| 0.0 – 0.3 | Critical | Disable or rewrite |

## Example Sigma Rule Snippet

```yaml
title: Suspicious PowerShell Encoded Command
id: f3a7c8d2-1b4e-4a9f-8c6d-2e5f7a8b9c0d
status: production
effectiveness: 0.72
last_tuned: 2026-05-15
fp_rate: 0.28
tp_rate: 0.72
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '-encodedcommand'
    condition: selection
level: medium
```

## Maintenance

- Scores are recalculated weekly via CI.
- Rules with no alerts in 90 days have their score reset to `null`.
- Tuning PRs should reference the effectiveness data that triggered the change.
