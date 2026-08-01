# macOS Detection Threat Model

## Scope

The macOS rules in `sigma/macos/`, `elastic/endpoint/macos/`, and `splunk/macos/` cover persistence, defense evasion, execution, and credential access on managed endpoints. They target LaunchAgent and LaunchDaemon plist creation; Gatekeeper and TCC tampering; XPC service operations; AppleScript execution; `defaults` changes; and Keychain access.

## Threats and detections

| Threat | ATT&CK | Detection focus |
|---|---|---|
| User and root persistence | T1543.001, T1543.004 | New LaunchAgent and LaunchDaemon plist files |
| Gatekeeper bypass | T1553.001 | `xattr` quarantine removal and `spctl --master-disable` |
| Privacy/security control impairment | T1562.001 | Direct TCC database modification |
| XPC service abuse | T1543.001 | `launchctl` bootstrap, kickstart, and submit operations involving XPC |
| AppleScript execution | T1059.002 | `osascript` shell and download behavior |
| Preference tampering | T1112 | `defaults` changes to security-related settings |
| Keychain access | T1555.001 | `security` dump and password search commands |

## Required telemetry

Collect process execution including executable path, full command line, user, parent process, code-signing context, and endpoint hostname. Collect file creation/modification events for `/Library/LaunchAgents`, `/Library/LaunchDaemons`, and user LaunchAgents. Elastic integrations and Splunk sourcetypes must normalize these values to the fields referenced by their rules.

## Assumptions and limitations

The rules detect observed endpoint behavior rather than proving malicious intent. TCC changes performed through supported MDM workflows may not produce the same process telemetry. XPC telemetry varies by EDR product, and the XPC rule is therefore a high-signal hunt requiring environment-specific tuning.

## Triage

1. Identify the user, parent process, code signature, and deployment source.
2. For persistence, review the plist `Program`/`ProgramArguments`, ownership, permissions, and creation history.
3. For Gatekeeper/TCC/Keychain activity, validate a documented administration or support workflow.
4. Isolate and collect the affected endpoint if the initiating process is unsigned, downloaded, or unknown.

## Expected false positives

MDM agents, endpoint security products, legitimate software installers, developer tooling, and approved support scripts can perform some of these actions. Maintain approved signer, path, and management-account exclusions only after validating their scope.
