"""
detection_rules._fixers
=======================

Concrete fixer functions consolidated from the legacy scripts/fix_*.py
files. Each function returns the number of files modified (or 0).

Functions:
  - fix_carbonblack    : add a `mitre` array to every CB rule JSON.
  - fix_sentinel       : backfill `// MITRE ATT&CK:` headers in KQL files.
  - fix_wazuh          : replace placeholder T1000 with real techniques.
  - improve_sigma_fp   : replace generic FP entries with specific ones.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .paths import (
    CARBONBLACK_DIR,
    SENTINEL_DIR,
    SIGMA_DIR,
    WAZUH_DIR,
)


# ---------------------------------------------------------------- Carbon Black
_CB_TOOL_MAP: dict[str, list[str]] = {
    "7z": ["T1560.001"], "at": ["T1053.002"], "bitsadmin": ["T1197"],
    "certutil": ["T1140", "T1105"], "cmd": ["T1059.003"],
    "cscript": ["T1059.005"], "wscript": ["T1059.005"],
    "installutil": ["T1218.004"], "mimikatz": ["T1003.001"],
    "msbuild": ["T1127.001"], "mshta": ["T1218.005"],
    "nc": ["T1095"], "ncat": ["T1095"],
    "net": ["T1087", "T1136", "T1098"], "powershell": ["T1059.001"],
    "procdump": ["T1003.001"], "psexec": ["T1021.002"],
    "rclone": ["T1567.002"], "reg": ["T1112"],
    "regsvr32": ["T1218.010"], "rundll32": ["T1218.011"],
    "schtasks": ["T1053.005"], "wmic": ["T1047"],
    "hacker": ["T1059.006"], "suspicious": ["T1059", "T1036"],
    "malware": ["T1574.002"], "evil": ["T1071.001"],
    "malicious-site": ["T1071.001"],
}

_CB_EXACT: dict[str, list[str]] = {
    "cb_filemod_lsass_dump_dmp.json":  ["T1003.001"],
    "cb_netconn_dns_tunnel_like.json": ["T1071.004", "T1572"],
}


def _cb_techniques(filename: str) -> list[str] | None:
    if filename in _CB_EXACT:
        return _CB_EXACT[filename]
    # Strip prefix `cb_<event>_` and trailing `_<ext>.json`.
    m = re.match(r"cb_[a-z]+_(.+?)_(?:exe|dll|py|com|org)\.json$", filename)
    if not m:
        return None
    tool = m.group(1)
    return _CB_TOOL_MAP.get(tool)


def fix_carbonblack(dry_run: bool = False) -> int:
    changed = 0
    for f in sorted((CARBONBLACK_DIR / "rules").glob("*.json")):
        try:
            data = json.loads(f.read_text())
        except json.JSONDecodeError:
            continue
        techs = _cb_techniques(f.name)
        if not techs:
            continue
        if data.get("mitre") == techs:
            continue
        data["mitre"] = techs
        if dry_run:
            print(f"[dry-run] would tag {f.name} -> {techs}")
        else:
            f.write_text(json.dumps(data, indent=2) + "\n")
        changed += 1
    print(f"[fix:carbonblack] {changed} file(s) {'would be' if dry_run else ''} updated")
    return 0


# ---------------------------------------------------------- Microsoft Sentinel
_SENTINEL_MAP: dict[str, list[str]] = {
    "proc_exec_cmd": ["T1059.003"], "proc_exec_powershell": ["T1059.001"],
    "proc_exec_wscript": ["T1059.005"], "proc_exec_cscript": ["T1059.005"],
    "proc_exec_rundll32": ["T1218.011"], "proc_exec_regsvr32": ["T1218.010"],
    "proc_exec_certutil": ["T1140", "T1105"], "proc_exec_bitsadmin": ["T1197"],
    "proc_exec_schtasks": ["T1053.005"], "proc_exec_at": ["T1053.002"],
    "net_conn_suspicious_port": ["T1571"], "net_conn_rdp": ["T1021.001"],
    "net_conn_ssh": ["T1021.004"], "net_conn_ftp": ["T1071.002"],
    "net_conn_telnet": ["T1021"], "net_conn_smb": ["T1021.002"],
    "net_conn_dns_tunnel": ["T1071.004", "T1572"],
    "net_conn_http_malicious": ["T1071.001"],
    "net_conn_tor": ["T1090.003"],
    "net_conn_darkweb": ["T1071.001", "T1090.003"],
    "reg_mod_run_key": ["T1547.001"], "reg_mod_runonce_key": ["T1547.001"],
    "reg_mod_services": ["T1543.003"], "reg_mod_firewall": ["T1562.004"],
    "reg_mod_defender": ["T1562.001"], "reg_mod_uac": ["T1548.002"],
    "reg_mod_proxy": ["T1090"],
    "reg_mod_rdp": ["T1021.001", "T1112"],
    "reg_mod_wdigest": ["T1003.001", "T1112"],
    "reg_mod_lsa": ["T1547.005"],
    "file_create_exe_temp": ["T1105", "T1036"],
    "file_create_dll_temp": ["T1574.002"],
    "file_create_sys": ["T1543.003"], "file_create_ps1": ["T1059.001"],
    "file_create_vbs": ["T1059.005"], "file_create_bat": ["T1059.003"],
    "file_create_js": ["T1059.007"], "file_create_wsf": ["T1059.005"],
    "file_create_scr": ["T1218", "T1036"], "file_create_pif": ["T1036"],
    "acct_mgr_user_created": ["T1136.001"], "acct_mgr_user_enabled": ["T1098"],
    "acct_mgr_user_pwd_reset": ["T1098"], "acct_mgr_user_deleted": ["T1531"],
    "acct_mgr_user_added_to_group": ["T1098.007"],
    "acct_mgr_user_removed_from_group": ["T1531"],
    "acct_mgr_group_created": ["T1136"],
    "acct_mgr_group_deleted": ["T1531"],
    "acct_mgr_pwd_policy_changed": ["T1484"],
    "acct_mgr_acct_locked_out": ["T1110"],
    "logon_failed": ["T1110"], "logon_success": ["T1078"],
    "logon_explicit": ["T1078"], "logon_special": ["T1078.003"],
    "logon_rdp": ["T1021.001"], "logon_network": ["T1021"],
    "logon_batch": ["T1053"], "logon_service": ["T1543"],
    "logon_unlock": ["T1078"], "logon_cleartext": ["T1078"],
    "schtask_created": ["T1053.005"], "schtask_deleted": ["T1053.005"],
    "schtask_enabled": ["T1053.005"], "schtask_disabled": ["T1053.005"],
    "schtask_updated": ["T1053.005"],
    "schtask_suspicious_name": ["T1053.005", "T1036"],
    "schtask_suspicious_action": ["T1053.005"],
    "schtask_hidden": ["T1053.005", "T1564"],
    "schtask_system_context": ["T1053.005"],
    "schtask_network_trigger": ["T1053.005"],
    "service_installed": ["T1543.003"], "service_started": ["T1543.003"],
    "service_stopped": ["T1489"], "service_failed": ["T1543.003"],
    "service_crashed": ["T1499"],
    "service_suspicious_path": ["T1543.003", "T1036"],
    "service_suspicious_name": ["T1543.003", "T1036"],
    "service_changed_config": ["T1543.003"],
    "service_deleted": ["T1543.003"], "service_disabled": ["T1562.001"],
    "obj_access_file": ["T1083"], "obj_access_registry": ["T1012"],
    "obj_access_sam": ["T1003.002"], "obj_access_lsass": ["T1003.001"],
    "obj_access_shadow_copy": ["T1003.003"],
    "obj_access_backup": ["T1490"], "obj_access_ntds": ["T1003.003"],
    "obj_access_audit_policy": ["T1562.002"],
    "obj_access_event_log": ["T1070.001"],
    "obj_access_host_file": ["T1565.001"],
    "misc_cloud_login": ["T1078.004"],
    "misc_cloud_failed_login": ["T1110"],
    "misc_cloud_mfa_disabled": ["T1556.006"],
    "misc_cloud_admin_assigned": ["T1098.003"],
    "misc_cloud_fw_changed": ["T1562.004"],
    "misc_cloud_vm_created": ["T1578.002"],
    "misc_cloud_vm_deleted": ["T1578.003"],
    "misc_cloud_storage_public": ["T1530"],
    "misc_cloud_api_key_created": ["T1098.001"],
    "misc_cloud_suspicious_api": ["T1098"],
}


def _sentinel_techniques(filename: str) -> list[str] | None:
    m = re.match(r"kql_(?:\d{3}_)?(.+)\.kql$", filename)
    if not m:
        return None
    return _SENTINEL_MAP.get(m.group(1))


def fix_sentinel(dry_run: bool = False) -> int:
    changed = 0
    for f in sorted(SENTINEL_DIR.glob("*.kql")):
        techs = _sentinel_techniques(f.name)
        if not techs:
            continue
        body = f.read_text()
        already = re.search(r"^// MITRE ATT&CK:", body, re.MULTILINE)
        line = f"// MITRE ATT&CK: {', '.join(techs)}"
        if already:
            new_body = re.sub(r"^// MITRE ATT&CK:.*$", line, body, flags=re.MULTILINE)
        else:
            new_body = line + "\n" + body
        if new_body == body:
            continue
        if dry_run:
            print(f"[dry-run] would update {f.name} -> {line}")
        else:
            f.write_text(new_body)
        changed += 1
    print(f"[fix:sentinel] {changed} file(s) {'would be' if dry_run else ''} updated")
    return 0


# --------------------------------------------------------------------- Wazuh
_WAZUH_APP_PATTERNS = {
    "_stopped": ["T1489"], "_started": ["T1543"], "_restarted": ["T1543"],
    "_crashed": ["T1499"], "_failed": ["T1499"],
    "_config_changed": ["T1562.001"],
    "_unauthorized_access": ["T1078"],
}

_WAZUH_EXACT: dict[str, list[str]] = {
    "lnx_apt_get_install.xml": ["T1072"], "lnx_yum_install.xml": ["T1072"],
    "lnx_crontab_creation.xml": ["T1053.003"],
    "lnx_failed_su_usage.xml": ["T1110", "T1078"],
    "lnx_suspicious_su_usage.xml": ["T1078.003"],
    "lnx_passwd_file_modified.xml": ["T1098", "T1003.008"],
    "lnx_shadow_file_modified.xml": ["T1098", "T1003.008"],
    "lnx_sshd_config_modified.xml": ["T1556", "T1098.004"],
    "lnx_suspicious_history_deletion.xml": ["T1070.003"],
    "lnx_systemctl_disable_service.xml": ["T1489", "T1562.001"],
    "net_dns_tunneling_suspicion.xml": ["T1071.004", "T1572"],
    "net_firewall_rule_added.xml": ["T1562.004"],
    "net_firewall_rule_deleted.xml": ["T1562.004"],
    "net_ftp_anonymous_login.xml": ["T1078"],
    "net_ssh_failed_root_login.xml": ["T1110.001"],
    "net_ssh_root_login.xml": ["T1078.003"],
    "net_suspicious_port_3389_outbound.xml": ["T1021.001"],
    "net_suspicious_port_4444.xml": ["T1571"],
    "net_suspicious_user_agent_curl.xml": ["T1071.001", "T1105"],
    "net_suspicious_user_agent_wget.xml": ["T1071.001", "T1105"],
    "win_ad_computer_account_created.xml": ["T1136.002"],
    "win_ad_group_policy_modified.xml": ["T1484.001"],
    "win_ad_password_reset.xml": ["T1098"],
    "win_ad_user_added_to_admin_group.xml": ["T1098.007"],
    "win_ad_user_deleted.xml": ["T1531"],
    "win_ad_user_unlocked.xml": ["T1098"],
    "windows_firewall_modified.xml": ["T1562.004"],
    "windows_defender_disabled.xml": ["T1562.001"],
    "win_registry_persistence_run.xml": ["T1547.001"],
    "win_registry_persistence_runonce.xml": ["T1547.001"],
    "win_suspicious_process_cmd_encoded.xml": ["T1059.003", "T1027"],
    "win_suspicious_process_lsass.xml": ["T1003.001"],
    "schtasks_creation.xml": ["T1053.005"],
    "service_creation.xml": ["T1543.003"],
    "rdp_brute_force.xml": ["T1110.001", "T1021.001"],
    "psexec_execution.xml": ["T1021.002"],
    "ssh_brute_force.xml": ["T1110.001"],
    "directory_traversal.xml": ["T1190"],
    "sql_injection_attempt.xml": ["T1190"],
    "xss_attempt.xml": ["T1190"],
    "php_code_injection.xml": ["T1190", "T1505.003"],
    "web_shell_upload.xml": ["T1505.003"],
    "shadow_file_access.xml": ["T1003.008"],
    "mimikatz_usage.xml": ["T1003.001"],
    "powershell_encoded_command.xml": ["T1059.001", "T1027"],
    "netcat_reverse_shell.xml": ["T1059.004", "T1095"],
    "base64_decoding.xml": ["T1140", "T1027"],
    "suspicious_curl_wget.xml": ["T1071.001", "T1105"],
    "kernel_module_loading.xml": ["T1547.006"],
    "cron_job_modification.xml": ["T1053.003"],
    "group_modification.xml": ["T1098.007"],
    "account_creation.xml": ["T1136"],
    "sudo_abuse.xml": ["T1548.003"],
    "nginx_error_log_spike.xml": ["T1499"],
    "apache_error_log_spike.xml": ["T1499"],
    "nmap_scan_detected.xml": ["T1046"],
    "clear_linux_history.xml": ["T1070.003"],
    "aws_iam_user_created.xml": ["T1136"],
    "aws_s3_bucket_public_access.xml": ["T1530"],
    "gcp_iam_role_grant.xml": ["T1098.003"],
}


def _wazuh_techniques(filename: str) -> list[str] | None:
    if filename in _WAZUH_EXACT:
        return _WAZUH_EXACT[filename]
    for suffix, tech in _WAZUH_APP_PATTERNS.items():
        if suffix in filename:
            return tech
    return None


def fix_wazuh(dry_run: bool = False) -> int:
    changed = 0
    for f in sorted((WAZUH_DIR / "rules").glob("*.xml")):
        body = f.read_text()
        if "<id>T1000</id>" not in body:
            continue
        techs = _wazuh_techniques(f.name)
        if not techs:
            continue
        new_block = "\n".join(f"      <id>{t}</id>" for t in techs)
        new_body = re.sub(
            r"\s*<id>T1000</id>",
            "\n" + new_block,
            body,
            count=1,
        )
        if dry_run:
            print(f"[dry-run] would tag {f.name} -> {techs}")
        else:
            f.write_text(new_body)
        changed += 1
    print(f"[fix:wazuh] {changed} file(s) {'would be' if dry_run else ''} updated")
    return 0


# ----------------------------------------------------------------- Sigma FPs
_GENERIC_FP_LINE = "  - Legitimate administrative activity"

_BIN_FP: dict[str, list[str]] = {
    "powershell": [
        "Microsoft scheduled tasks (Get-WindowsUpdate, MicrosoftEdgeUpdate).",
        "RMM/MDM tools (Datto, NinjaOne, Intune) yang dispatch script.",
        "Vendor installer signed yang menjalankan PowerShell helper.",
    ],
    "pwsh": ["Microsoft scheduled tasks atau RMM/MDM tools yang pakai pwsh."],
    "cmd": [
        "Script administrasi rutin (batch script signed).",
        "Software installer yang spawn cmd untuk post-install task.",
    ],
    "wscript": ["Internal VBScript tooling (jarang di environment modern)."],
    "cscript": ["Internal VBScript tooling (jarang di environment modern)."],
    "rundll32": [
        "Microsoft signed components (printer driver, control panel applet).",
        "Software vendor installer signed.",
    ],
    "regsvr32": [
        "Microsoft installer (msiexec) yang meregister DLL legit.",
        "Software vendor installer signed.",
    ],
    "certutil": [
        "Admin sysadmin yang sah download CRL/CTL.",
        "PKI tooling internal (Windows ADCS).",
    ],
    "bitsadmin": [
        "Microsoft Update / SCCM yang menggunakan BITS untuk delivery.",
        "Software install yang download komponen via BITS.",
    ],
    "mshta": ["Internal HTA tooling (sangat jarang di environment modern)."],
    "wmic": [
        "System management tools (SCCM, monitoring) yang pakai WMI/WMIC.",
        "Admin script untuk inventory.",
    ],
    "schtasks": [
        "Software install legit yang membuat scheduled task.",
        "Microsoft Update scheduled task creation.",
    ],
    "vssadmin": [
        "Backup software (Veeam, Commvault, Acronis) yang manage shadow copy.",
        "Admin yang manual menjalankan vssadmin saat troubleshoot.",
    ],
    "procdump": [
        "Authorized IR investigation untuk memory acquisition.",
        "Microsoft Sysinternals troubleshooting yang sah.",
    ],
    "psexec": [
        "Admin yang sah pakai PsExec untuk remote management.",
        "SCCM atau RMM tools yang invoke PsExec.",
    ],
    "net": [
        "Admin yang menjalankan 'net user' / 'net group' untuk audit.",
        "Login script yang map network drive.",
    ],
    "reg": [
        "Software install legit yang modifikasi registry.",
        "Admin troubleshoot registry secara manual.",
    ],
    "sudo": [
        "Admin sysadmin yang menjalankan command sah dengan sudo.",
        "Configuration management (Ansible, Salt) yang pakai sudo.",
    ],
    "ssh": [
        "Admin yang sah login via SSH.",
        "Automation / CI runner yang SSH ke target server.",
    ],
    "curl": [
        "Sysadmin yang download asset dari URL internal.",
        "CI/CD pipeline yang fetch artifact.",
    ],
    "wget": [
        "Sysadmin yang download asset dari URL internal.",
        "Package manager yang fetch dependency.",
    ],
}


def _sigma_target_bin(path: Path) -> str | None:
    """Return a key from _BIN_FP based on filename heuristics."""
    name = path.stem.lower()
    for bin_name in _BIN_FP:
        if bin_name in name:
            return bin_name
    return None


def improve_sigma_fp(dry_run: bool = False) -> int:
    changed = 0
    for f in sorted(SIGMA_DIR.glob("**/*.yml")):
        body = f.read_text()
        if "falsepositives:" not in body:
            continue
        # only touch rules whose entire FP list is the generic single line
        m = re.search(
            r"^falsepositives:\n((?:" + re.escape(_GENERIC_FP_LINE) + r"\n)+)",
            body,
            re.MULTILINE,
        )
        if not m:
            continue
        bin_name = _sigma_target_bin(f)
        if not bin_name:
            continue
        replacement = "falsepositives:\n" + "\n".join(
            f"  - {fp}" for fp in _BIN_FP[bin_name]
        ) + "\n"
        new_body = body[: m.start()] + replacement + body[m.end():]
        if dry_run:
            print(f"[dry-run] would refine FP in {f.relative_to(SIGMA_DIR)} ({bin_name})")
        else:
            f.write_text(new_body)
        changed += 1
    print(f"[fix:sigma-fp] {changed} file(s) {'would be' if dry_run else ''} updated")
    return 0
