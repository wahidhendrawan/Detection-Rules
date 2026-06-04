#!/usr/bin/env python3
"""
classify_sentinel.py
--------------------
Add `// Severity:` and `// FalsePositives:` headers to every Sentinel
`.kql` file. Heuristics:

- 1-liner query that only matches a process/event ID without filter
  -> Severity: informational (use as hunting baseline only)
- Query with specific indicators (suspicious port, threshold, AND with
  command-line) -> Severity: low
- Manual override for known noisy patterns elevated to medium with
  proper hardening done in a separate commit.
"""

from __future__ import annotations
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SENT = ROOT / "microsoft-sentinel"

# Files that already have meaningful filtering -> 'low' instead of 'informational'
LOW_FIDELITY: set[str] = {
    "kql_011_net_conn_suspicious_port.kql",      # specific ports 4444, 31337, 1337
    "kql_017_net_conn_dns_tunnel.kql",           # UDP/53 + bytes threshold
    "kql_018_net_conn_http_malicious.kql",
    "kql_019_net_conn_tor.kql",
    "kql_020_net_conn_darkweb.kql",
    "kql_025_reg_mod_defender.kql",              # specific registry mod
    "kql_029_reg_mod_wdigest.kql",               # specific registry value
    "kql_030_reg_mod_lsa.kql",
    "kql_069_schtask_system_context.kql",        # SYSTEM context
    "kql_085_obj_access_shadow_copy.kql",
    "kql_087_obj_access_ntds.kql",
    "kql_089_obj_access_event_log.kql",
    "kql_093_misc_cloud_mfa_disabled.kql",
    "kql_094_misc_cloud_admin_assigned.kql",
    "kql_098_misc_cloud_storage_public.kql",
    "kql_099_misc_cloud_api_key_created.kql",
    "kql_endpoint_win_powershell_suspicious_encoded_command.kql",
    "kql_net_dns_suspicious_tunnel.kql",
}

# Generic FP message per category
FP_BY_PREFIX = {
    "proc_exec_":     "Aktivitas administratif rutin yang menjalankan binary tersebut (admin script, scheduled task, software update).",
    "net_conn_":      "Koneksi keluar yang sah dari aplikasi enterprise (RMM, monitoring agent).",
    "reg_mod_":       "Software install/update yang sah memodifikasi registry.",
    "file_create_":   "Software install/update yang sah membuat file di path tersebut.",
    "acct_mgr_":      "Aktivitas account management oleh admin yang sah.",
    "logon_":         "Logon legit (terutama service account, scheduled task).",
    "schtask_":       "Scheduled task yang dibuat oleh installer software vendor.",
    "service_":       "Operasi service legit (Windows Update, software install).",
    "obj_access_":    "Tools backup/forensic yang sah mengakses resource tersebut.",
    "misc_cloud_":    "Aktivitas cloud admin / automation legit (CI/CD, IaC).",
}


def category_of(filename: str) -> str | None:
    m = re.match(r"^kql_\d{3}_(.+)\.kql$", filename)
    if not m:
        return None
    sfx = m.group(1)
    for k in FP_BY_PREFIX:
        if sfx.startswith(k):
            return k
    return None


def already_classified(text: str) -> bool:
    return any(ln.lower().startswith("// severity:") for ln in text.splitlines()[:8])


def insert_metadata(text: str, severity: str, fp: str | None) -> str:
    if already_classified(text):
        return text
    lines = text.splitlines()
    # find last contiguous comment line
    last_comment = -1
    for i, ln in enumerate(lines):
        if ln.startswith("//"):
            last_comment = i
        else:
            break
    inject: list[str] = [f"// Severity: {severity}"]
    if fp:
        inject.append("// FalsePositives:")
        inject.append(f"//   - {fp}")
    if last_comment == -1:
        new_lines = inject + lines
    else:
        new_lines = lines[: last_comment + 1] + inject + lines[last_comment + 1 :]
    out = "\n".join(new_lines)
    if not out.endswith("\n"):
        out += "\n"
    return out


def main() -> int:
    files = sorted(SENT.glob("*.kql"))
    fixed = 0
    skipped = 0
    for path in files:
        text = path.read_text()
        if already_classified(text):
            skipped += 1
            continue
        severity = "low" if path.name in LOW_FIDELITY else "informational"
        cat = category_of(path.name)
        fp = FP_BY_PREFIX.get(cat) if cat else None
        new = insert_metadata(text, severity, fp)
        if new != text:
            path.write_text(new)
            fixed += 1
    print(f"[+] Classified: {fixed}")
    print(f"[?] Already had severity (skipped): {skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
