#!/usr/bin/env python3
"""
improve_sigma_fp.py
-------------------
Replace generic single-line "Legitimate administrative activity"
falsepositives in Sigma rules with more specific FP entries based on
the rule's primary detection target (extracted from
logsource.category + selection.Image / selection.CommandLine).

Conservative: only modify rules whose FP is exactly
  - Legitimate administrative activity
"""
from __future__ import annotations
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SIGMA = ROOT / "sigma"

GENERIC = "  - Legitimate administrative activity"

# binary basename -> specific FP suggestions
BIN_FP: dict[str, list[str]] = {
    "powershell": [
        "Microsoft scheduled tasks (Get-WindowsUpdate, MicrosoftEdgeUpdate).",
        "RMM/MDM tools (Datto, NinjaOne, Intune) yang dispatch script.",
        "Vendor installer signed yang menjalankan PowerShell helper.",
    ],
    "pwsh": [
        "Microsoft scheduled tasks atau RMM/MDM tools yang pakai pwsh.",
    ],
    "cmd": [
        "Script administrasi rutin (batch script signed).",
        "Software installer yang spawn cmd untuk post-install task.",
    ],
    "wscript": [
        "Internal VBScript tooling (jarang di environment modern).",
    ],
    "cscript": [
        "Internal VBScript tooling (jarang di environment modern).",
    ],
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
    "mshta": [
        "Internal HTA tooling (sangat jarang di environment modern).",
    ],
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
        "CI/CD pipeline yang fetch artifact.",
    ],
    "nc": [
        "Admin debugging network connectivity (jarang di prod).",
    ],
    "ncat": [
        "Admin debugging network connectivity (jarang di prod).",
    ],
}

# Category -> default FP set if no specific binary detected
CATEGORY_FP: dict[str, list[str]] = {
    "process_creation": [
        "Aktivitas administratif rutin yang menjalankan binary tersebut.",
        "Software install / update signed yang spawn proses tersebut.",
    ],
    "file_event": [
        "Software install / update legit yang membuat / memodifikasi file.",
        "User legit yang menyimpan file di path tersebut.",
    ],
    "registry_event": [
        "Software install legit yang menambah entry registry.",
        "Group Policy push setting baru.",
    ],
    "network_connection": [
        "Aplikasi enterprise (RMM, monitoring) yang melakukan koneksi keluar.",
        "User yang akses service eksternal yang sah.",
    ],
    "image_load": [
        "Microsoft signed DLL yang di-load oleh trusted binary.",
        "Software vendor installer yang load DLL legit.",
    ],
    "ps_module": [
        "Admin yang sah menggunakan modul PowerShell tersebut.",
    ],
    "create_remote_thread": [
        "Software EDR/AV yang inject ke proses untuk monitoring.",
        "Debugger yang attach ke proses.",
    ],
    "dns_query": [
        "Aplikasi enterprise yang melakukan DNS lookup.",
        "DNS verification (SPF, DKIM) yang sah.",
    ],
    "webserver": [
        "User legit yang akses URL tersebut.",
        "Vulnerability scanner yang authenticated scan.",
    ],
    "auth": [
        "User legit yang sukses authenticate.",
        "Service account dengan token rotation.",
    ],
}


def parse_target_binary(text: str) -> str | None:
    """Detect primary binary referenced in selection.Image|endswith."""
    # Look for `\binary.exe` patterns
    m = re.findall(r"\\([a-zA-Z0-9_-]+)\.exe", text)
    if m:
        # Most common one wins
        from collections import Counter
        return Counter(m).most_common(1)[0][0].lower()
    return None


def parse_logsource_category(text: str) -> str | None:
    m = re.search(r"^\s*category:\s*(\S+)", text, flags=re.MULTILINE)
    return m.group(1).lower() if m else None


def fp_for_rule(text: str, filename: str) -> list[str]:
    binary = parse_target_binary(text)
    if binary and binary in BIN_FP:
        return BIN_FP[binary][:3]

    cat = parse_logsource_category(text)
    if cat and cat in CATEGORY_FP:
        return CATEGORY_FP[cat][:3]

    # Filename-based heuristics for rules without process_creation category
    name = filename.lower()
    if "ssh" in name or "passwd" in name or "shadow" in name:
        return CATEGORY_FP.get("auth", []) + ["Admin yang sah memodifikasi user."]
    if "dns" in name:
        return CATEGORY_FP.get("dns_query", [])
    if "registry" in name or "_reg_" in name:
        return CATEGORY_FP.get("registry_event", [])
    if "_file_" in name or "_create_" in name:
        return CATEGORY_FP.get("file_event", [])

    # Generic safe fallback
    return [
        "Aktivitas administratif rutin yang sah dengan signature trusted.",
        "Software install / update legit (verifikasi via parent process & signer).",
    ]


def replace_generic_fp(text: str, new_fps: list[str]) -> str:
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        out.append(lines[i])
        if lines[i].rstrip() == "falsepositives:":
            # Check if next non-empty line is exactly the generic
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines) and lines[j].rstrip() == GENERIC:
                # Find end of FP list
                k = j
                while k < len(lines) and (lines[k].startswith("  -") or not lines[k].strip()):
                    k += 1
                # Replace
                for fp in new_fps:
                    out.append(f"  - {fp}")
                i = k
                continue
        i += 1
    result = "\n".join(out)
    if text.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result


def main() -> int:
    files = sorted(SIGMA.rglob("*.yml"))
    fixed = 0
    skipped = 0
    for path in files:
        text = path.read_text()
        if GENERIC not in text:
            skipped += 1
            continue
        new_fps = fp_for_rule(text, path.name)
        new_text = replace_generic_fp(text, new_fps)
        if new_text != text:
            path.write_text(new_text)
            fixed += 1
    print(f"[+] Improved FP: {fixed}")
    print(f"[?] Already specific (skipped): {skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
