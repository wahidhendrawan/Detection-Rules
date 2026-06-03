#!/usr/bin/env python3
"""
fix_carbonblack_mitre.py
------------------------
Add a `mitre` array to every Carbon Black rule JSON. Mapping is based on
the *tool/binary* portion of the filename (which is the dominant
technique signal in CB rules of the form
`cb_<event>_<tool>_<ext>.json`).
"""

from __future__ import annotations
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CB_DIR = ROOT / "carbonblack" / "rules"

# tool/binary -> list of techniques
TOOL_MAP: dict[str, list[str]] = {
    "7z":              ["T1560.001"],   # Archive Collected Data: Utility
    "at":              ["T1053.002"],   # At
    "bitsadmin":       ["T1197"],       # BITS Jobs
    "certutil":        ["T1140", "T1105"],
    "cmd":             ["T1059.003"],
    "cscript":         ["T1059.005"],
    "wscript":         ["T1059.005"],
    "installutil":     ["T1218.004"],
    "mimikatz":        ["T1003.001"],
    "msbuild":         ["T1127.001"],
    "mshta":           ["T1218.005"],
    "nc":              ["T1095"],       # Non-App Layer Protocol
    "ncat":            ["T1095"],
    "net":             ["T1087", "T1136", "T1098"],
    "powershell":      ["T1059.001"],
    "procdump":        ["T1003.001"],
    "psexec":          ["T1021.002"],
    "rclone":          ["T1567.002"],
    "reg":             ["T1112"],
    "regsvr32":        ["T1218.010"],
    "rundll32":        ["T1218.011"],
    "schtasks":        ["T1053.005"],
    "wmic":            ["T1047"],
    "hacker":          ["T1059.006"],   # Python tool
    "suspicious":      ["T1059", "T1036"],  # generic suspicious app
    "malware":         ["T1574.002"],   # malicious DLL
    "evil":            ["T1071.001"],   # com domain
    "malicious-site":  ["T1071.001"],
}

# Files that don't fit the (event)_(tool)_(ext) pattern
EXACT_MAP: dict[str, list[str]] = {
    "cb_filemod_lsass_dump_dmp.json":  ["T1003.001"],
    "cb_netconn_dns_tunnel_like.json": ["T1071.004", "T1572"],
}


def techniques_for(filename: str) -> list[str] | None:
    if filename in EXACT_MAP:
        return EXACT_MAP[filename]

    # cb_<event>_<tool>(_extra)?_<ext>.json
    # remove cb_ prefix and .json, then known event prefixes
    base = filename.removeprefix("cb_").removesuffix(".json")
    for evt in (
        "childproc_creation",
        "file_modification",
        "network_connection",
        "process_creation",
        "registry_modification",
    ):
        if base.startswith(evt + "_"):
            base = base[len(evt) + 1 :]
            break

    # base is now "<tool>_<ext>" or "<tool>_<modifier>_<ext>"
    parts = base.split("_")
    if not parts:
        return None
    tool = parts[0]
    return TOOL_MAP.get(tool)


def main() -> int:
    files = sorted(CB_DIR.glob("*.json"))
    fixed: list[str] = []
    skipped: list[str] = []
    unmatched: list[str] = []

    for path in files:
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            print(f"[!] JSON error in {path.name}: {e}", file=sys.stderr)
            continue

        if isinstance(data.get("mitre"), list) and data["mitre"]:
            skipped.append(path.name)
            continue

        techs = techniques_for(path.name)
        if not techs:
            unmatched.append(path.name)
            continue

        # Insert 'mitre' field. Try to keep insertion order natural
        # (after description/severity).
        new_data: dict = {}
        inserted = False
        for k, v in data.items():
            new_data[k] = v
            if k in ("description", "category", "severity") and not inserted:
                new_data["mitre"] = techs
                inserted = True
        if not inserted:
            new_data["mitre"] = techs

        path.write_text(json.dumps(new_data, indent=2) + "\n")
        fixed.append(f"{path.name}: {','.join(techs)}")

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
        print(f"[?] Already had mitre field (skipped): {len(skipped)}")
    return 0 if not unmatched else 1


if __name__ == "__main__":
    sys.exit(main())
