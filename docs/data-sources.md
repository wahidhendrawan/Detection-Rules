# Data Source & Telemetry Requirements

Dokumen ini menjelaskan telemetry prerequisite per platform agar rule di repo ini berfungsi.

## Microsoft Sentinel (KQL)

| Rule Category | Table/Data Source | License Tier | Notes |
|---|---|---|---|
| `proc_exec_*` | `DeviceProcessEvents` | M365 E5 / Defender for Endpoint | Sysmon alternative: `Event` table with EventID 1 |
| `net_conn_*` | `DeviceNetworkEvents` | M365 E5 | Or `CommonSecurityLog` (CEF) |
| `reg_mod_*` | `DeviceRegistryEvents` | M365 E5 | Or Sysmon EventID 13 via `Event` table |
| `file_create_*` | `DeviceFileEvents` | M365 E5 | |
| `acct_mgr_*` | `SecurityEvent` (4720-4740) | Free tier (Security Events) | Or `AuditLogs` for Entra ID |
| `logon_*` | `SecurityEvent` (4624-4634) / `SigninLogs` | Free / Entra ID P1 | |
| `schtask_*` | `SecurityEvent` (4698-4702) | Free tier | Requires "Audit Other Object Access" |
| `service_*` | `SecurityEvent` (7045, 7040) | Free tier | System event log |
| `obj_access_*` | `SecurityEvent` (4663, 4656) | Free tier | Requires object access auditing enabled |
| `misc_cloud_*` | `AuditLogs`, `SigninLogs`, `AzureActivity` | Entra ID P1/P2 | |

**Minimum setup:** Enable Defender for Endpoint connector + Security Events (via AMA) connector.

## Sigma

Sigma rules use abstracted `logsource` definitions. Required telemetry per logsource:

| Logsource | Windows (Sysmon) | Windows (Native) | Linux |
|---|---|---|---|
| `process_creation` | EventID 1 | Security 4688 + command line auditing | auditd `execve` |
| `file_creation` | EventID 11 | — | auditd `create` |
| `registry_event` | EventID 12/13/14 | Security 4657 | N/A |
| `network_connection` | EventID 3 | Security 5156 | auditd `connect` |
| `dns_query` | EventID 22 | — | Zeek/Suricata |
| `image_load` | EventID 7 | — | — |

**Recommended:** Install Sysmon with [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) for Windows endpoints.

## Splunk

| Rule Category | sourcetype | index | Add-on Required |
|---|---|---|---|
| `win_*` | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | `windows` | [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709) |
| `win_*` (alt) | `WinEventLog:Security` | `windows` | Splunk Add-on for Windows |
| `lnx_*` | `syslog` / `linux:audit` | `linux` | Splunk Add-on for Unix |
| `net_*` | `suricata` / `zeek` / `pan:traffic` | `network` | Vendor-specific TA |
| `cloud_*` | `aws:cloudtrail` / `google:gcp:pubsub:message` | `cloud` | Splunk Add-on for AWS/GCP |

**Performance tip:** Use `tstats` with accelerated data models (`Endpoint`, `Network_Traffic`) for faster searches.

## Wazuh

| Rule Category | Required Decoder/Module | Config |
|---|---|---|
| `win_*` (Security) | `windows_eventchannel` | `ossec.conf` → `<localfile>` Security channel |
| `win_*` (Sysmon) | `windows_eventchannel` | Sysmon channel: `Microsoft-Windows-Sysmon/Operational` |
| `lnx_*` | `sshd`, `auditd`, `syslog` | FIM + SCA modules enabled |
| `net_*` | `json` (Suricata/Zeek) | Log ingestion via `<localfile>` |
| `app_*` | Application-specific decoders | Custom decoders in `/var/ossec/etc/decoders/` |
| `cloud_*` | `aws-s3` module | CloudTrail bucket configured |

**Minimum setup:**
```xml
<ossec_config>
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Security</location>
  </localfile>
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Microsoft-Windows-Sysmon/Operational</location>
  </localfile>
</ossec_config>
```

## Carbon Black (EDR)

| Query Field | Sensor Requirement | Notes |
|---|---|---|
| `process_name` | CB EDR sensor | Default telemetry |
| `childproc_name` | CB EDR sensor | Default |
| `filemod_name` | CB EDR sensor | Default |
| `regmod_name` | CB EDR sensor | Default |
| `netconn_domain` | CB EDR sensor | DNS resolution required |
| `modload_name` | CB EDR sensor | Module load events |

**No additional config** needed — CB sensor collects all event types by default.

## Elastic (Security)

| Rule Type | Required Integration | Data Stream |
|---|---|---|
| Endpoint (Windows) | Elastic Defend / Elastic Agent | `logs-endpoint.events.*` |
| Endpoint (Linux) | Elastic Defend | `logs-endpoint.events.process` |
| Network | Elastic Agent + Network integration | `logs-network_traffic.*` |
| Cloud | AWS/Azure/GCP integrations | `logs-aws.cloudtrail` etc. |

**Index patterns:** Rules target `logs-*` by default. Ensure Elastic Agent is deployed with the Defend integration.

## Cross-Platform: Minimum Viable Telemetry

For maximum rule coverage with minimal setup:

1. **Windows:** Sysmon (EventID 1,3,7,11,12,13,22) + Security audit (4624,4625,4688,4720,7045)
2. **Linux:** auditd with `execve` + Wazuh FIM
3. **Network:** DNS logs (passive DNS or Sysmon 22) + firewall/proxy logs
4. **Cloud:** CloudTrail (AWS), Activity Log (Azure), Audit Log (GCP)
