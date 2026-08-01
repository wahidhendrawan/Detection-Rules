# Identity Provider Detection Threat Model

## Scope

Identity rules in `sigma/cloud/identity/` and `microsoft-sentinel/kql_151_*` through `kql_158_*` cover account and token abuse in Okta, Microsoft Entra ID, and Google Workspace.

## Threats and detections

| Threat | ATT&CK | Detection focus |
|---|---|---|
| Session replay/hijacking | T1550.004 | Successful Okta administrative sessions associated with proxy context |
| Illicit OAuth consent | T1528 | High-risk Microsoft Entra consent grants |
| OAuth/API token abuse | T1550.001 | High-risk Google scopes and anomalous token/API usage |
| MFA fatigue | T1621 | Repeated denied challenges followed by a success |
| Conditional Access bypass | T1556.006 | Successful single-factor sign-ins where policy was not applied or failed |
| Service principal persistence | T1098.001 | Application or service-principal credential additions |
| Forged SAML authentication | T1606.002 | Successful SAML logons with anomalous token issuer context |

## Required telemetry

Ingest Okta System Log, Entra ID `SigninLogs`, `AuditLogs`, and service-principal sign-in logs, plus Google Workspace audit events. Retain actor, target, client ID, application, IP address, device/user-agent, result, conditional-access state, OAuth scopes, and correlation/request IDs.

## Assumptions and limitations

Identity alerts are indicators for investigation, not proof of compromise. VPN, secure web gateways, identity automation, and federated applications can alter network, issuer, and policy context. Detection quality depends on complete tenant audit retention and authoritative known-network, service-principal, and application inventories.

## Triage

1. Correlate the event with identity, device, source IP, user agent, application, and nearby administrative events.
2. Verify authorization for consent grants, credential changes, and Conditional Access exceptions.
3. For suspected token or session theft, revoke sessions/tokens, rotate application credentials, and review downstream API activity.
4. For MFA fatigue, contact the user through a trusted channel and investigate the successful authentication path.

## Expected false positives

Approved SaaS onboarding, CI/CD service principals, travel, VPN/proxy services, break-glass accounts, and MFA enrollment can resemble these detections. Suppress only documented workflows and retain a review process for all high-privilege exclusions.
