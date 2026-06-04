# Sigma Correlation Rules

## About

Sigma correlations are a **Sigma Specification 2.0** feature that allows defining multi-event detection logic (e.g., "5 failed logins followed by a success within 10 minutes").

**Important:** `sigma-cli` 1.x does not support `type: correlation` rules. These files will fail validation with errors about missing `logsource` and `detection` fields. This is expected.

## Purpose

These YAML files serve as:
- Documentation of the correlation logic in a vendor-neutral format
- Reference specification for implementing correlations in your SIEM
- Future-proofing for when sigma-cli 2.x adds correlation support

## For SIEM Deployment

Use the platform-native implementations instead:

| Platform | Location |
|----------|----------|
| Microsoft Sentinel | [`microsoft-sentinel/kql_correlation_brute_force.kql`](../../microsoft-sentinel/kql_correlation_brute_force.kql) |
| Splunk | [`splunk/windows/win_brute_force_correlation.spl`](../../splunk/windows/win_brute_force_correlation.spl) |

## Base Rules

Correlation rules reference base Sigma rules that detect individual events:

| Correlation | Base Rule |
|-------------|-----------|
| `brute_force_then_success.yml` | [`sigma/windows/win_brute_force_failed_login.yml`](../windows/win_brute_force_failed_login.yml) |

## CI Compatibility

The CI pipeline (`sigma-spec-check.yml`) excludes `sigma/correlations/` from `sigma check` validation since these rules intentionally lack the `logsource`/`detection` fields required by sigma-cli 1.x.
