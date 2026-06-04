"""Map repository rules to Atomic Red Team test IDs (verification)."""

from __future__ import annotations

import json
from argparse import ArgumentParser, Namespace
from pathlib import Path

from ..parsers import parse
from ..paths import ROOT, iter_rules

# Curated mapping of MITRE technique -> Atomic Red Team test references.
# Each entry is (atomic_id, atomic_name, repo_path).
# Source: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics
ATOMIC_TESTS: dict[str, list[tuple[str, str, str]]] = {
    "T1003.001": [
        ("T1003.001-1", "Dump LSASS.exe Memory using ProcDump",
         "atomics/T1003.001/T1003.001.md"),
        ("T1003.001-2", "Dump LSASS.exe Memory using comsvcs.dll",
         "atomics/T1003.001/T1003.001.md"),
        ("T1003.001-7", "Dump LSASS with Mimikatz",
         "atomics/T1003.001/T1003.001.md"),
    ],
    "T1003.008": [
        ("T1003.008-1", "Access /etc/shadow (Linux)",
         "atomics/T1003.008/T1003.008.md"),
    ],
    "T1027": [
        ("T1027-1", "Decode Base64 Data into Script",
         "atomics/T1027/T1027.md"),
    ],
    "T1053.003": [
        ("T1053.003-1", "Cron — Add script to all cron subfolders",
         "atomics/T1053.003/T1053.003.md"),
    ],
    "T1053.005": [
        ("T1053.005-1", "Scheduled Task Startup Script",
         "atomics/T1053.005/T1053.005.md"),
    ],
    "T1059.001": [
        ("T1059.001-1", "Mimikatz via PowerShell",
         "atomics/T1059.001/T1059.001.md"),
        ("T1059.001-7", "Powershell Invoke Mimikatz Reflection",
         "atomics/T1059.001/T1059.001.md"),
    ],
    "T1059.003": [
        ("T1059.003-1", "Create and Execute Batch Script",
         "atomics/T1059.003/T1059.003.md"),
    ],
    "T1059.004": [
        ("T1059.004-1", "Create and Execute Bash Shell Script",
         "atomics/T1059.004/T1059.004.md"),
    ],
    "T1070.001": [
        ("T1070.001-1", "Clear Logs",
         "atomics/T1070.001/T1070.001.md"),
    ],
    "T1070.003": [
        ("T1070.003-1", "Clear bash history",
         "atomics/T1070.003/T1070.003.md"),
    ],
    "T1071.004": [
        ("T1071.004-1", "DNS Large Query Volume",
         "atomics/T1071.004/T1071.004.md"),
    ],
    "T1078": [
        ("T1078-1", "Create local account with admin privileges",
         "atomics/T1078/T1078.md"),
    ],
    "T1098": [
        ("T1098-1", "Admin Account Manipulate",
         "atomics/T1098/T1098.md"),
    ],
    "T1105": [
        ("T1105-1", "rsync remote file copy (push)",
         "atomics/T1105/T1105.md"),
        ("T1105-13", "Powershell Wget Execute",
         "atomics/T1105/T1105.md"),
    ],
    "T1110.001": [
        ("T1110.001-1", "Brute Force Credentials of single Active Directory domain user",
         "atomics/T1110.001/T1110.001.md"),
    ],
    "T1136.001": [
        ("T1136.001-1", "Create a new user in a command prompt",
         "atomics/T1136.001/T1136.001.md"),
    ],
    "T1140": [
        ("T1140-1", "Deobfuscate/Decode Files Using certutil",
         "atomics/T1140/T1140.md"),
    ],
    "T1190": [
        ("T1190-1", "Exploit a public-facing app (synthetic)",
         "atomics/T1190/T1190.md"),
    ],
    "T1197": [
        ("T1197-1", "Bitsadmin Download (cmd)",
         "atomics/T1197/T1197.md"),
    ],
    "T1218.005": [
        ("T1218.005-1", "Mshta Executes JavaScript Scheme via FileProtocolHandler",
         "atomics/T1218.005/T1218.005.md"),
    ],
    "T1218.010": [
        ("T1218.010-1", "Regsvr32 Local COM Scriptlet Execution",
         "atomics/T1218.010/T1218.010.md"),
    ],
    "T1218.011": [
        ("T1218.011-1", "Rundll32 execute JavaScript Remote Payload",
         "atomics/T1218.011/T1218.011.md"),
    ],
    "T1486": [
        ("T1486-1", "Encrypt files using gpg (Linux)",
         "atomics/T1486/T1486.md"),
    ],
    "T1490": [
        ("T1490-1", "Windows — Delete Volume Shadow Copies via WMI with PowerShell",
         "atomics/T1490/T1490.md"),
    ],
    "T1543.003": [
        ("T1543.003-1", "Modify Fax service to run PowerShell",
         "atomics/T1543.003/T1543.003.md"),
    ],
    "T1547.001": [
        ("T1547.001-1", "Reg Key Run",
         "atomics/T1547.001/T1547.001.md"),
    ],
    "T1548.002": [
        ("T1548.002-1", "Bypass UAC using Event Viewer (cmd)",
         "atomics/T1548.002/T1548.002.md"),
    ],
    "T1548.003": [
        ("T1548.003-1", "Sudo usage",
         "atomics/T1548.003/T1548.003.md"),
    ],
    "T1562.001": [
        ("T1562.001-1", "Disable Microsoft Defender Firewall",
         "atomics/T1562.001/T1562.001.md"),
        ("T1562.001-3", "Disable Windows Defender Realtime Monitoring",
         "atomics/T1562.001/T1562.001.md"),
    ],
    "T1562.004": [
        ("T1562.004-1", "Disable Microsoft Defender Firewall",
         "atomics/T1562.004/T1562.004.md"),
    ],
    "T1567.002": [
        ("T1567.002-1", "Exfiltration to Cloud Storage using Rclone",
         "atomics/T1567.002/T1567.002.md"),
    ],
    "T1571": [
        ("T1571-1", "Testing usage of uncommonly used port",
         "atomics/T1571/T1571.md"),
    ],
    "T1572": [
        ("T1572-1", "DNS over HTTPS (DoH) Tunnel",
         "atomics/T1572/T1572.md"),
    ],
}

ATOMIC_REPO = "https://github.com/redcanaryco/atomic-red-team/blob/master"


def add_arguments(parser: ArgumentParser) -> None:
    parser.add_argument("--out-md", default=str(ROOT / "docs/atomic-red-team.md"))
    parser.add_argument("--out-json", default=str(ROOT / "docs/atomic-red-team.json"))


def run(args: Namespace) -> int:
    rule_to_atomics: dict[str, list[dict]] = {}
    technique_coverage: dict[str, list[str]] = {}

    for platform, files in iter_rules().items():
        for f in files:
            techs = parse(platform, f)["techniques"]
            atomics: list[dict] = []
            for t in sorted(techs):
                for atomic_id, name, path in ATOMIC_TESTS.get(t, []):
                    atomics.append({
                        "technique": t,
                        "atomic_id": atomic_id,
                        "name": name,
                        "url": f"{ATOMIC_REPO}/{path}",
                    })
            if atomics:
                rel = str(f.relative_to(ROOT))
                rule_to_atomics[rel] = atomics
                for a in atomics:
                    technique_coverage.setdefault(a["technique"], []).append(rel)

    payload = {
        "summary": {
            "rules_with_atomic_tests": len(rule_to_atomics),
            "techniques_with_atomic_tests": len(technique_coverage),
            "total_atomic_tests_referenced":
                sum(len(v) for v in rule_to_atomics.values()),
        },
        "by_rule": rule_to_atomics,
        "by_technique": technique_coverage,
    }
    Path(args.out_json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out_json).write_text(json.dumps(payload, indent=2) + "\n")

    lines: list[str] = []
    lines.append("# Atomic Red Team — End-to-End Verification Mapping\n")
    lines.append("> Auto-generated by `python -m detection_rules atomic`. **Do not edit manually.**\n")
    lines.append("")
    lines.append("This document links every rule to one or more")
    lines.append("[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)")
    lines.append("tests that exercise the same MITRE ATT&CK technique.")
    lines.append("Use it to verify rule efficacy in your environment **before**")
    lines.append("promoting the rule from `experimental` / `test` to `stable`.\n")
    lines.append("")
    lines.append("## Verification workflow\n")
    lines.append("1. Pick a rule you want to validate.")
    lines.append("2. Find its row in **Rules → Atomic tests** below.")
    lines.append("3. Run the linked Atomic on a **lab endpoint** with the SIEM connected.")
    lines.append("4. Confirm the rule fires (true positive) and that no neighboring")
    lines.append("   benign event triggers it (false-positive boundary).")
    lines.append("5. Once verified, bump rule status to `stable`.\n")
    lines.append("")
    lines.append("## Summary\n")
    s = payload["summary"]
    lines.append(f"- Rules with Atomic test mapping       : **{s['rules_with_atomic_tests']}**")
    lines.append(f"- Techniques covered by mapping        : **{s['techniques_with_atomic_tests']}**")
    lines.append(f"- Total atomic test references emitted : **{s['total_atomic_tests_referenced']}**")
    lines.append("")
    lines.append("## Rules → Atomic tests\n")
    for rel in sorted(rule_to_atomics):
        atomics = rule_to_atomics[rel]
        lines.append(f"### `{rel}`\n")
        lines.append("| Technique | Atomic | Name |")
        lines.append("|---|---|---|")
        for a in atomics:
            lines.append(f"| `{a['technique']}` | [{a['atomic_id']}]({a['url']}) | {a['name']} |")
        lines.append("")
    Path(args.out_md).write_text("\n".join(lines) + "\n")
    print(f"[+] Wrote {args.out_md}")
    print(f"[+] Wrote {args.out_json}")
    print(
        f"    {s['rules_with_atomic_tests']} rules linked to "
        f"{s['total_atomic_tests_referenced']} Atomic Red Team tests"
    )
    return 0
