#!/usr/bin/env python3
"""
fix_sentinel_mitre.py
---------------------
Backfill `// MITRE ATT&CK: TXXXX` header into every Sentinel `.kql` file.
Mapping is derived from the structured filename (kql_NNN_<category>_<topic>.kql).
"""

from __future__ import annotations
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SENTINEL_DIR = ROOT / "microsoft-sentinel"

# Filename suffix (without leading 'kql_NNN_') -> list of techniques
MAP: dict[str, list[str]] = {
    # Process execution (LOLBins)
    "proc_exec_cmd":             ["T1059.003"],
    "proc_exec_powershell":      ["T1059.001"],
    "proc_exec_wscript":         ["T1059.005"],
    "proc_exec_cscript":         ["T1059.005"],
    "proc_exec_rundll32":        ["T1218.011"],
    "proc_exec_regsvr32":        ["T1218.010"],
    "proc_exec_certutil":        ["T1140", "T1105"],
    "proc_exec_bitsadmin":       ["T1197"],
    "proc_exec_schtasks":        ["T1053.005"],
    "proc_exec_at":              ["T1053.002"],

    # Network connections
    "net_conn_suspicious_port":  ["T1571"],
    "net_conn_rdp":              ["T1021.001"],
    "net_conn_ssh":              ["T1021.004"],
    "net_conn_ftp":              ["T1071.002"],
    "net_conn_telnet":           ["T1021"],
    "net_conn_smb":              ["T1021.002"],
    "net_conn_dns_tunnel":       ["T1071.004", "T1572"],
    "net_conn_http_malicious":   ["T1071.001"],
    "net_conn_tor":              ["T1090.003"],
    "net_conn_darkweb":          ["T1071.001", "T1090.003"],

    # Registry modifications
    "reg_mod_run_key":           ["T1547.001"],
    "reg_mod_runonce_key":       ["T1547.001"],
    "reg_mod_services":          ["T1543.003"],
    "reg_mod_firewall":          ["T1562.004"],
    "reg_mod_defender":          ["T1562.001"],
    "reg_mod_uac":               ["T1548.002"],
    "reg_mod_proxy":             ["T1090"],
    "reg_mod_rdp":               ["T1021.001", "T1112"],
    "reg_mod_wdigest":           ["T1003.001", "T1112"],
    "reg_mod_lsa":               ["T1547.005"],

    # File creation in suspicious paths
    "file_create_exe_temp":      ["T1105", "T1036"],
    "file_create_dll_temp":      ["T1574.002"],
    "file_create_sys":           ["T1543.003"],
    "file_create_ps1":           ["T1059.001"],
    "file_create_vbs":           ["T1059.005"],
    "file_create_bat":           ["T1059.003"],
    "file_create_js":            ["T1059.007"],
    "file_create_wsf":           ["T1059.005"],
    "file_create_scr":           ["T1218", "T1036"],
    "file_create_pif":           ["T1036"],

    # Account management
    "acct_mgr_user_created":           ["T1136.001"],
    "acct_mgr_user_enabled":           ["T1098"],
    "acct_mgr_user_pwd_reset":         ["T1098"],
    "acct_mgr_user_deleted":           ["T1531"],
    "acct_mgr_user_added_to_group":    ["T1098.007"],
    "acct_mgr_user_removed_from_group":["T1531"],
    "acct_mgr_group_created":          ["T1136"],
    "acct_mgr_group_deleted":          ["T1531"],
    "acct_mgr_pwd_policy_changed":     ["T1484"],
    "acct_mgr_acct_locked_out":        ["T1110"],

    # Logon events
    "logon_failed":              ["T1110"],
    "logon_success":             ["T1078"],
    "logon_explicit":            ["T1078"],
    "logon_special":             ["T1078"],
    "logon_rdp":                 ["T1021.001"],
    "logon_network":             ["T1021"],
    "logon_batch":               ["T1078"],
    "logon_service":             ["T1078"],
    "logon_unlock":              ["T1098"],
    "logon_cleartext":           ["T1556"],

    # Scheduled tasks
    "schtask_created":           ["T1053.005"],
    "schtask_deleted":           ["T1053.005"],
    "schtask_enabled":           ["T1053.005"],
    "schtask_disabled":          ["T1053.005"],
    "schtask_updated":           ["T1053.005"],
    "schtask_suspicious_name":   ["T1053.005", "T1036"],
    "schtask_suspicious_action": ["T1053.005"],
    "schtask_hidden":            ["T1053.005", "T1564"],
    "schtask_system_context":    ["T1053.005", "T1078"],
    "schtask_network_trigger":   ["T1053.005"],

    # Services
    "service_installed":         ["T1543.003"],
    "service_started":           ["T1543.003"],
    "service_stopped":           ["T1489"],
    "service_failed":            ["T1499"],
    "service_crashed":           ["T1499"],
    "service_suspicious_path":   ["T1543.003", "T1036"],
    "service_suspicious_name":   ["T1543.003", "T1036"],
    "service_changed_config":    ["T1543.003"],
    "service_deleted":           ["T1543.003"],
    "service_disabled":          ["T1543.003", "T1562.001"],

    # Object access (sensitive resources)
    "obj_access_file":           ["T1005"],
    "obj_access_registry":       ["T1012"],
    "obj_access_sam":            ["T1003.002"],
    "obj_access_lsass":          ["T1003.001"],
    "obj_access_shadow_copy":    ["T1490"],
    "obj_access_backup":         ["T1490"],
    "obj_access_ntds":           ["T1003.003"],
    "obj_access_audit_policy":   ["T1562.002"],
    "obj_access_event_log":      ["T1070.001"],
    "obj_access_host_file":      ["T1565.001"],

    # Cloud
    "misc_cloud_login":              ["T1078.004"],
    "misc_cloud_failed_login":       ["T1110", "T1078.004"],
    "misc_cloud_mfa_disabled":       ["T1556.006"],
    "misc_cloud_admin_assigned":     ["T1098.003"],
    "misc_cloud_fw_changed":         ["T1562.004"],
    "misc_cloud_vm_created":         ["T1578.002"],
    "misc_cloud_vm_deleted":         ["T1578.003"],
    "misc_cloud_storage_public":     ["T1530"],
    "misc_cloud_api_key_created":    ["T1098.001"],
    "misc_cloud_suspicious_api":     ["T1078.004"],
}

# Files that don't follow the kql_NNN_ pattern
EXTRA_MAP: dict[str, list[str]] = {
    "kql_endpoint_win_powershell_suspicious_encoded_command.kql": ["T1059.001", "T1027"],
    "kql_net_dns_suspicious_tunnel.kql":                          ["T1071.004", "T1572"],
}


def techniques_for(filename: str) -> list[str] | None:
    if filename in EXTRA_MAP:
        return EXTRA_MAP[filename]
    m = re.match(r"^kql_\d{3}_(.+)\.kql$", filename)
    if not m:
        return None
    suffix = m.group(1)
    return MAP.get(suffix)


def add_mitre_header(text: str, techs: list[str]) -> str:
    """
    Insert `// MITRE ATT&CK: ...` line into the file's header comment block.
    If header already has 'MITRE', skip. If file has no header at all, prepend.
    """
    lines = text.splitlines()
    mitre_line = f"// MITRE ATT&CK: {', '.join(techs)}"

    # already has MITRE → skip
    if any("MITRE" in ln for ln in lines[:10]):
        return text

    # find last contiguous comment line at the top
    last_comment_idx = -1
    for i, ln in enumerate(lines):
        if ln.startswith("//"):
            last_comment_idx = i
        else:
            break

    if last_comment_idx == -1:
        # no header exists → prepend
        new_lines = [mitre_line] + lines
    else:
        new_lines = lines[: last_comment_idx + 1] + [mitre_line] + lines[last_comment_idx + 1 :]

    out = "\n".join(new_lines)
    if not out.endswith("\n"):
        out += "\n"
    return out


def main() -> int:
    files = sorted(SENTINEL_DIR.glob("*.kql"))
    fixed: list[str] = []
    skipped: list[str] = []
    unmatched: list[str] = []

    for path in files:
        techs = techniques_for(path.name)
        if not techs:
            unmatched.append(path.name)
            continue
        text = path.read_text()
        new = add_mitre_header(text, techs)
        if new != text:
            path.write_text(new)
            fixed.append(f"{path.name}: {','.join(techs)}")
        else:
            skipped.append(path.name)

    print(f"[+] Fixed: {len(fixed)}")
    for f in fixed[:8]:
        print(f"    {f}")
    if len(fixed) > 8:
        print(f"    ... and {len(fixed) - 8} more")
    if unmatched:
        print(f"[!] Unmatched ({len(unmatched)}):")
        for f in unmatched:
            print(f"    {f}")
    if skipped:
        print(f"[?] Already had MITRE header (skipped): {len(skipped)}")
    return 0 if not unmatched else 1


if __name__ == "__main__":
    sys.exit(main())
