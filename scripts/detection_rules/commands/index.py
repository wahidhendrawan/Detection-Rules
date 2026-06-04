"""Generate rules.index.json / rules.index.yaml (cross-platform manifest)."""

from __future__ import annotations

import json
from argparse import ArgumentParser, Namespace
from collections import defaultdict
from pathlib import Path

from ..parsers import find_techniques
from ..paths import ROOT, iter_rules

# ATT&CK technique name + tactic. Subset; unknown techniques flagged.
TECHNIQUE_INFO: dict[str, tuple[str, str]] = {
    "T1003":     ("OS Credential Dumping", "credential-access"),
    "T1003.001": ("LSASS Memory", "credential-access"),
    "T1003.002": ("Security Account Manager", "credential-access"),
    "T1003.003": ("NTDS", "credential-access"),
    "T1003.008": ("/etc/passwd and /etc/shadow", "credential-access"),
    "T1005":     ("Data from Local System", "collection"),
    "T1012":     ("Query Registry", "discovery"),
    "T1016":     ("System Network Configuration Discovery", "discovery"),
    "T1018":     ("Remote System Discovery", "discovery"),
    "T1021":     ("Remote Services", "lateral-movement"),
    "T1021.001": ("Remote Desktop Protocol", "lateral-movement"),
    "T1021.002": ("SMB/Windows Admin Shares", "lateral-movement"),
    "T1021.004": ("SSH", "lateral-movement"),
    "T1027":     ("Obfuscated Files or Information", "defense-evasion"),
    "T1033":     ("System Owner/User Discovery", "discovery"),
    "T1036":     ("Masquerading", "defense-evasion"),
    "T1046":     ("Network Service Discovery", "discovery"),
    "T1047":     ("Windows Management Instrumentation", "execution"),
    "T1053":     ("Scheduled Task/Job", "persistence"),
    "T1053.002": ("At", "persistence"),
    "T1053.003": ("Cron", "persistence"),
    "T1053.005": ("Scheduled Task", "persistence"),
    "T1057":     ("Process Discovery", "discovery"),
    "T1059":     ("Command and Scripting Interpreter", "execution"),
    "T1059.001": ("PowerShell", "execution"),
    "T1059.003": ("Windows Command Shell", "execution"),
    "T1059.004": ("Unix Shell", "execution"),
    "T1059.005": ("Visual Basic", "execution"),
    "T1059.006": ("Python", "execution"),
    "T1059.007": ("JavaScript", "execution"),
    "T1069":     ("Permission Groups Discovery", "discovery"),
    "T1070":     ("Indicator Removal", "defense-evasion"),
    "T1070.001": ("Clear Windows Event Logs", "defense-evasion"),
    "T1070.003": ("Clear Command History", "defense-evasion"),
    "T1071":     ("Application Layer Protocol", "command-and-control"),
    "T1071.001": ("Web Protocols", "command-and-control"),
    "T1071.002": ("File Transfer Protocols", "command-and-control"),
    "T1071.004": ("DNS", "command-and-control"),
    "T1072":     ("Software Deployment Tools", "execution"),
    "T1078":     ("Valid Accounts", "defense-evasion"),
    "T1078.003": ("Local Accounts", "defense-evasion"),
    "T1078.004": ("Cloud Accounts", "defense-evasion"),
    "T1082":     ("System Information Discovery", "discovery"),
    "T1083":     ("File and Directory Discovery", "discovery"),
    "T1087":     ("Account Discovery", "discovery"),
    "T1090":     ("Proxy", "command-and-control"),
    "T1090.003": ("Multi-hop Proxy", "command-and-control"),
    "T1095":     ("Non-Application Layer Protocol", "command-and-control"),
    "T1098":     ("Account Manipulation", "persistence"),
    "T1098.001": ("Additional Cloud Credentials", "persistence"),
    "T1098.003": ("Additional Cloud Roles", "persistence"),
    "T1098.004": ("SSH Authorized Keys", "persistence"),
    "T1098.007": ("Additional Local or Domain Groups", "persistence"),
    "T1105":     ("Ingress Tool Transfer", "command-and-control"),
    "T1110":     ("Brute Force", "credential-access"),
    "T1110.001": ("Password Guessing", "credential-access"),
    "T1112":     ("Modify Registry", "defense-evasion"),
    "T1127":     ("Trusted Developer Utilities Proxy Execution", "defense-evasion"),
    "T1127.001": ("MSBuild", "defense-evasion"),
    "T1133":     ("External Remote Services", "initial-access"),
    "T1136":     ("Create Account", "persistence"),
    "T1136.001": ("Local Account", "persistence"),
    "T1136.002": ("Domain Account", "persistence"),
    "T1140":     ("Deobfuscate/Decode Files or Information", "defense-evasion"),
    "T1190":     ("Exploit Public-Facing Application", "initial-access"),
    "T1197":     ("BITS Jobs", "defense-evasion"),
    "T1218":     ("System Binary Proxy Execution", "defense-evasion"),
    "T1218.004": ("InstallUtil", "defense-evasion"),
    "T1218.005": ("Mshta", "defense-evasion"),
    "T1218.010": ("Regsvr32", "defense-evasion"),
    "T1218.011": ("Rundll32", "defense-evasion"),
    "T1484":     ("Domain Policy Modification", "privilege-escalation"),
    "T1484.001": ("Group Policy Modification", "privilege-escalation"),
    "T1486":     ("Data Encrypted for Impact", "impact"),
    "T1489":     ("Service Stop", "impact"),
    "T1490":     ("Inhibit System Recovery", "impact"),
    "T1499":     ("Endpoint Denial of Service", "impact"),
    "T1505.003": ("Web Shell", "persistence"),
    "T1518":     ("Software Discovery", "discovery"),
    "T1530":     ("Data from Cloud Storage", "collection"),
    "T1531":     ("Account Access Removal", "impact"),
    "T1543":     ("Create or Modify System Process", "persistence"),
    "T1543.003": ("Windows Service", "persistence"),
    "T1547":     ("Boot or Logon Autostart Execution", "persistence"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "persistence"),
    "T1547.005": ("Security Support Provider", "persistence"),
    "T1548":     ("Abuse Elevation Control Mechanism", "privilege-escalation"),
    "T1548.002": ("Bypass User Account Control", "privilege-escalation"),
    "T1548.003": ("Sudo and Sudo Caching", "privilege-escalation"),
    "T1556":     ("Modify Authentication Process", "credential-access"),
    "T1556.006": ("Multi-Factor Authentication", "credential-access"),
    "T1560":     ("Archive Collected Data", "collection"),
    "T1560.001": ("Archive via Utility", "collection"),
    "T1562":     ("Impair Defenses", "defense-evasion"),
    "T1562.001": ("Disable or Modify Tools", "defense-evasion"),
    "T1562.002": ("Disable Windows Event Logging", "defense-evasion"),
    "T1562.004": ("Disable or Modify System Firewall", "defense-evasion"),
    "T1562.008": ("Disable or Modify Cloud Logs", "defense-evasion"),
    "T1564":     ("Hide Artifacts", "defense-evasion"),
    "T1565.001": ("Stored Data Manipulation", "impact"),
    "T1567":     ("Exfiltration Over Web Service", "exfiltration"),
    "T1567.002": ("Exfiltration to Cloud Storage", "exfiltration"),
    "T1570":     ("Lateral Tool Transfer", "lateral-movement"),
    "T1571":     ("Non-Standard Port", "command-and-control"),
    "T1572":     ("Protocol Tunneling", "command-and-control"),
    "T1574":     ("Hijack Execution Flow", "persistence"),
    "T1574.002": ("DLL Side-Loading", "persistence"),
    "T1578":     ("Modify Cloud Compute Infrastructure", "defense-evasion"),
    "T1578.002": ("Create Cloud Instance", "defense-evasion"),
    "T1578.003": ("Delete Cloud Instance", "defense-evasion"),
    "T1611":     ("Escape to Host", "privilege-escalation"),
}

PLATFORMS_ORDER = ["sigma", "elastic", "splunk", "microsoft-sentinel", "wazuh", "carbonblack", "falcon", "sentinelone", "falco"]


def add_arguments(parser: ArgumentParser) -> None:
    parser.add_argument("--out-json", default=str(ROOT / "rules.index.json"))
    parser.add_argument("--out-yaml", default=str(ROOT / "rules.index.yaml"))


def _build() -> dict:
    rules = iter_rules()
    idx: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for platform, files in rules.items():
        for f in files:
            try:
                text = f.read_text(errors="ignore")
            except Exception:
                continue
            for t in find_techniques(text):
                idx[t][platform].append(str(f.relative_to(ROOT)))

    techniques: dict[str, dict] = {}
    for t in sorted(idx):
        info = TECHNIQUE_INFO.get(t, ("Unknown / Custom", "uncategorized"))
        det = {p: sorted(idx[t].get(p, [])) for p in PLATFORMS_ORDER}
        gaps = [p for p in PLATFORMS_ORDER if not det[p]]
        techniques[t] = {
            "name": info[0],
            "tactic": info[1],
            "detections": det,
            "gaps": gaps,
            "coverage_count": sum(1 for v in det.values() if v),
        }

    summary = {
        "total_techniques": len(techniques),
        "total_rules": sum(len(v) for v in rules.values()),
        "rules_per_platform": {p: len(v) for p, v in rules.items()},
        "fully_covered": sum(1 for t in techniques.values() if not t["gaps"]),
        "single_platform_only": sum(1 for t in techniques.values() if t["coverage_count"] == 1),
    }
    return {"summary": summary, "techniques": techniques}


def _to_yaml(data: dict) -> str:
    out: list[str] = []
    out.append("summary:")
    for k, v in data["summary"].items():
        if isinstance(v, dict):
            out.append(f"  {k}:")
            for k2, v2 in v.items():
                out.append(f"    {k2}: {v2}")
        else:
            out.append(f"  {k}: {v}")
    out.append("techniques:")
    for t, info in data["techniques"].items():
        out.append(f"  {t}:")
        out.append(f"    name: {info['name']!r}")
        out.append(f"    tactic: {info['tactic']}")
        out.append(f"    coverage_count: {info['coverage_count']}")
        out.append("    detections:")
        for p, files in info["detections"].items():
            if not files:
                out.append(f"      {p}: []")
            else:
                out.append(f"      {p}:")
                for f in files:
                    out.append(f"        - {f!r}")
        if info["gaps"]:
            out.append("    gaps:")
            for g in info["gaps"]:
                out.append(f"      - {g}")
        else:
            out.append("    gaps: []")
    return "\n".join(out) + "\n"


def run(args: Namespace) -> int:
    data = _build()
    Path(args.out_json).write_text(json.dumps(data, indent=2) + "\n")
    Path(args.out_yaml).write_text(_to_yaml(data))
    s = data["summary"]
    print(f"[+] Wrote {args.out_json} + {args.out_yaml}")
    print(f"    {s['total_techniques']} techniques across {s['total_rules']} rules")
    print(f"    Fully covered: {s['fully_covered']}, single-platform: {s['single_platform_only']}")
    return 0
