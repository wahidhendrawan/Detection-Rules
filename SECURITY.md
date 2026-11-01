# Security Policy

## Supported versions

Only the latest release of Detection-Rules gets security fixes. Please check that the problem still exists there before reporting.

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on this repository ([direct link](https://github.com/wahidhendrawan/Detection-Rules/security/advisories/new)). Do not open a public issue, discussion or pull request, and do not post exploit details or credentials anywhere public.

Please include:

- the version or commit you tested, and which platform/query language
- the smallest steps or input that reproduce the problem
- what an attacker gains (data exposure, code execution, privilege escalation, denial of service, …)

Remove real credentials, customer data and sensitive logs from any evidence you share.

You should get a first reply within 7 days. Fixed issues are credited in the release notes unless you ask otherwise.

## In scope

- Scripts under `scripts/` (for example token handling in `deploy_rules.py`, the KEV rule generator)
- GitHub Actions workflows: secret exposure, script injection, unsafe triggers
- Rule content that would run code or leak data when imported into a supported platform

## Out of scope

- Missed detections and false positives: open a normal issue so the rule can be tuned
- Vulnerabilities in the SIEM/EDR platforms themselves: report them to the vendor

## Safe harbor

Good-faith research that follows this policy will not be treated as a violation of the license or of this policy. Only test against your own deployment, access no more data than needed to show the issue, and do not degrade services for other people.
