# CrowdStrike Falcon Queries

Detection rules written in FQL (Falcon Query Language) for use with CrowdStrike Falcon Event Search. These queries can be used in **Investigate > Event Search** within the Falcon console.

## Coverage

The queries cover process injection, command and scripting interpreter abuse, anomalous valid-account logons, mass file encryption, scheduled task creation, application-layer C2, remote services, account creation/manipulation, and credential dumping.

All queries carry `Security Team` metadata, the 2026-08-01 creation date, severity, ATT&CK technique and tactic mappings, and ATT&CK references. Review event field availability in the target Falcon data source before scheduling a query.

## Deployment notes

1. Run a query in Event Search over a representative time range and confirm its event schema.
2. Baseline approved remote administration, identity-management, and EDR activity.
3. Save tuned searches as scheduled detections with owner and escalation context in Falcon.

## References

- [Falcon Query Language Documentation](https://falcon.crowdstrike.com/documentation)
- [MITRE ATT&CK](https://attack.mitre.org/)
