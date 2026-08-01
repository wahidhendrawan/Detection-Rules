# SentinelOne Deep Visibility Queries

Detection rules written in S1QL (SentinelOne Query Language) for use with Deep Visibility. These queries can be run directly in the SentinelOne console under **Visibility > Deep Visibility**.

## Coverage

This directory includes endpoint detections for process injection, command and scripting interpreter abuse, anomalous valid-account logons, ransomware encryption behavior, scheduled task creation, application-layer C2, remote services, account creation/manipulation, and credential dumping.

Each query includes a title, description, `Security Team` authorship, creation date, severity, ATT&CK technique/tactic mapping, and an ATT&CK reference. Tune process exclusions and logon baselines for the environment before promoting a query to an alert.

## Deployment notes

1. Run each `.s1ql` query in Deep Visibility and confirm supported field names for the deployed SentinelOne version.
2. Scope endpoint queries to the appropriate operating system and site groups.
3. Convert queries into alerts only after validating expected administrative activity and adding approved exclusions.

## References

- [Deep Visibility Documentation](https://support.sentinelone.com)
- [MITRE ATT&CK](https://attack.mitre.org/)
