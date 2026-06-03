#!/usr/bin/env python3
"""
fix_wazuh_t1000.py
------------------
Replace placeholder MITRE technique 'T1000' (which is NOT a valid ATT&CK
technique - real techniques start at T1001) with appropriate technique(s)
based on filename + rule description.
"""

from __future__ import annotations
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WAZUH_DIR = ROOT / "wazuh" / "rules"

# Map filename -> list of MITRE techniques
# Multiple techniques are emitted as multiple <id>...</id> elements
# inside the existing <mitre> block.
APP_PATTERNS = {
    "_stopped":             ["T1489"],                    # Service Stop
    "_started":             ["T1543"],                    # Create or Modify System Process
    "_restarted":           ["T1543"],                    # Create or Modify System Process
    "_crashed":             ["T1499"],                    # Endpoint DoS
    "_failed":              ["T1499"],                    # Endpoint DoS / failed start
    "_config_changed":      ["T1562.001"],                # Impair Defenses: Disable/Modify Tools
    "_unauthorized_access": ["T1078"],                    # Valid Accounts
}

EXACT_MAP: dict[str, list[str]] = {
    # Linux
    "lnx_apt_get_install.xml":               ["T1072"],              # Software Deployment Tools
    "lnx_yum_install.xml":                   ["T1072"],
    "lnx_crontab_creation.xml":              ["T1053.003"],          # Cron
    "lnx_failed_su_usage.xml":               ["T1110", "T1078"],     # Brute Force + Valid Accounts
    "lnx_suspicious_su_usage.xml":           ["T1078.003"],          # Valid Accounts: Local Accounts
    "lnx_passwd_file_modified.xml":          ["T1098", "T1003.008"], # Account Manipulation + /etc/passwd
    "lnx_shadow_file_modified.xml":          ["T1098", "T1003.008"],
    "lnx_sshd_config_modified.xml":          ["T1556", "T1098.004"], # Modify Auth Process + SSH Authorized Keys
    "lnx_suspicious_history_deletion.xml":   ["T1070.003"],          # Clear Command History
    "lnx_systemctl_disable_service.xml":     ["T1489", "T1562.001"], # Service Stop + Impair Defenses

    # Network
    "net_dns_tunneling_suspicion.xml":       ["T1071.004", "T1572"],  # DNS + Protocol Tunneling
    "net_firewall_rule_added.xml":           ["T1562.004"],            # Impair Defenses: Modify Firewall
    "net_firewall_rule_deleted.xml":         ["T1562.004"],
    "net_ftp_anonymous_login.xml":           ["T1078"],                # Valid Accounts
    "net_ssh_failed_root_login.xml":         ["T1110.001"],            # Brute Force: Password Guessing
    "net_ssh_root_login.xml":                ["T1078.003"],            # Valid Accounts: Local
    "net_suspicious_port_3389_outbound.xml": ["T1021.001"],            # RDP
    "net_suspicious_port_4444.xml":          ["T1571"],                # Non-Standard Port
    "net_suspicious_user_agent_curl.xml":    ["T1071.001", "T1105"],   # Web Protocols + Ingress Tool Transfer
    "net_suspicious_user_agent_wget.xml":    ["T1071.001", "T1105"],

    # Windows / AD
    "win_ad_computer_account_created.xml":   ["T1136.002"],            # Create Account: Domain Account
    "win_ad_group_policy_modified.xml":      ["T1484.001"],            # Group Policy Modification
    "win_ad_password_reset.xml":             ["T1098"],                # Account Manipulation
    "win_ad_user_added_to_admin_group.xml":  ["T1098.007"],            # Add Local/Domain Groups
    "win_ad_user_deleted.xml":               ["T1531"],                # Account Access Removal
    "win_ad_user_unlocked.xml":              ["T1098"],                # Account Manipulation
    "win_registry_persistence_run.xml":      ["T1547.001"],            # Registry Run Keys
    "win_registry_persistence_runonce.xml":  ["T1547.001"],
    "win_suspicious_process_cmd_encoded.xml": ["T1059.003", "T1027"],  # cmd + obfuscation
    "win_suspicious_process_lsass.xml":      ["T1003.001"],            # LSASS Memory
}


def techniques_for(filename: str) -> list[str] | None:
    """Resolve techniques from filename, exact match wins over pattern."""
    if filename in EXACT_MAP:
        return EXACT_MAP[filename]
    if filename.startswith("app_"):
        for suffix, techs in APP_PATTERNS.items():
            if filename.endswith(suffix + ".xml"):
                return techs
    return None


def replace_mitre_block(xml: str, techs: list[str]) -> str:
    """
    Replace the contents of <mitre>...</mitre> with the given technique list.
    Preserves indentation of the original <mitre> block.
    """
    # Find the indentation level by looking at the line with <mitre>
    m = re.search(r"^(\s*)<mitre>", xml, flags=re.MULTILINE)
    indent = m.group(1) if m else "    "
    inner_indent = indent + "  "

    new_ids = "\n".join(f"{inner_indent}<id>{t}</id>" for t in techs)
    new_block = f"{indent}<mitre>\n{new_ids}\n{indent}</mitre>"

    return re.sub(
        r"^\s*<mitre>.*?</mitre>",
        new_block,
        xml,
        count=1,
        flags=re.MULTILINE | re.DOTALL,
    )


def main() -> int:
    files = sorted(WAZUH_DIR.glob("*.xml"))
    fixed: list[str] = []
    skipped: list[str] = []
    unmatched: list[str] = []

    for path in files:
        text = path.read_text()
        if "T1000<" not in text and "T1000 " not in text and ">T1000<" not in text and "T1000\n" not in text:
            # Look for <id>T1000</id> specifically
            if not re.search(r"<id>\s*T1000\s*</id>", text):
                continue

        techs = techniques_for(path.name)
        if not techs:
            unmatched.append(path.name)
            continue

        new_text = replace_mitre_block(text, techs)
        if new_text != text:
            path.write_text(new_text)
            fixed.append(f"{path.name}: T1000 -> {','.join(techs)}")
        else:
            skipped.append(path.name)

    print(f"[+] Fixed: {len(fixed)}")
    for f in fixed[:20]:
        print(f"    {f}")
    if len(fixed) > 20:
        print(f"    ... and {len(fixed) - 20} more")
    if unmatched:
        print(f"[!] Unmatched ({len(unmatched)}):")
        for f in unmatched:
            print(f"    {f}")
    if skipped:
        print(f"[?] Skipped (no change): {len(skipped)}")

    return 0 if not unmatched else 1


if __name__ == "__main__":
    sys.exit(main())
