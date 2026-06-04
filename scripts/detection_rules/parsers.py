"""
detection_rules.parsers
=======================

Per-platform rule parsers. Each parser returns a dict with keys:

    {
      "techniques": set[str],        # MITRE technique IDs (T1059, T1059.001, ...)
      "tags":       set[str],        # raw tag strings (or empty)
      "title":      str,             # rule title (or filename stem)
      "level":      str | None,      # severity if available (low|medium|high|critical)
      "raw":        Any,             # parsed object (dict/text) for downstream use
    }

The parsers are intentionally tolerant: a malformed rule produces an empty
`techniques` set rather than raising, so coverage / metrics keep running.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except ImportError:  # graceful degradation
    yaml = None

TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


def find_techniques(text: str) -> set[str]:
    return {m.upper() for m in TECHNIQUE_RE.findall(text)}


# --------------------------------------------------------------------- Sigma
def parse_sigma(path: Path) -> dict[str, Any]:
    body = path.read_text(errors="ignore")
    data: dict | None = None
    if yaml is not None:
        try:
            data = yaml.safe_load(body)
        except Exception:
            data = None
    techs: set[str] = set()
    tags: set[str] = set()
    title = path.stem
    level = None

    if isinstance(data, dict):
        for tag in data.get("tags") or []:
            if isinstance(tag, str):
                tags.add(tag)
                if tag.lower().startswith("attack.t"):
                    techs.update(find_techniques(tag))
        title = data.get("title") or title
        level = data.get("level")
    else:
        techs = find_techniques(body)

    return {
        "techniques": techs,
        "tags": tags,
        "title": title,
        "level": level,
        "raw": data if isinstance(data, dict) else body,
    }


# ------------------------------------------------------------------- Elastic
def parse_elastic(path: Path) -> dict[str, Any]:
    techs: set[str] = set()
    tags: set[str] = set()
    title = path.stem
    level = None
    objs: list[dict] = []

    for line in path.read_text(errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        objs.append(obj)
        attrs = obj.get("attributes") or {}
        for t in (attrs.get("threat") or obj.get("threat") or []):
            for tech in t.get("technique", []) or []:
                if "id" in tech:
                    techs.update(find_techniques(tech["id"]))
                for sub in tech.get("subtechnique", []) or []:
                    if "id" in sub:
                        techs.update(find_techniques(sub["id"]))
        for tag in attrs.get("tags") or obj.get("tags") or []:
            if isinstance(tag, str):
                tags.add(tag)
                techs.update(find_techniques(tag))
        if attrs.get("name"):
            title = attrs["name"]
        if attrs.get("severity"):
            level = attrs["severity"]

    return {"techniques": techs, "tags": tags, "title": title,
            "level": level, "raw": objs}


# -------------------------------------------------------- Splunk / Sentinel
def _parse_header(path: Path, prefix: str) -> dict[str, Any]:
    techs: set[str] = set()
    title = path.stem
    level = None
    references: list[str] = []
    body = path.read_text(errors="ignore")
    for line in body.splitlines():
        s = line.strip()
        if not s.startswith(prefix):
            # header is over once content starts
            if s and not s.startswith(prefix.rstrip()):
                continue
        upper = s.upper()
        if "MITRE" in upper:
            techs.update(find_techniques(s))
        if upper.startswith(prefix.upper() + " TITLE:") or upper.startswith(prefix.upper() + "TITLE:"):
            title = s.split(":", 1)[1].strip() or title
        if "SEVERITY:" in upper:
            level = s.split(":", 1)[1].strip().lower()
        if "REFERENCES:" in upper or "REFERENCE:" in upper:
            references.append(s.split(":", 1)[1].strip())

    return {"techniques": techs, "tags": set(), "title": title,
            "level": level, "raw": {"body": body, "references": references}}


def parse_splunk(path: Path) -> dict[str, Any]:
    return _parse_header(path, "#")


def parse_sentinel(path: Path) -> dict[str, Any]:
    return _parse_header(path, "//")


# --------------------------------------------------------------------- Wazuh
def parse_wazuh(path: Path) -> dict[str, Any]:
    body = path.read_text(errors="ignore")
    techs = find_techniques(body)
    title = path.stem
    level = None
    m = re.search(r"<description>(.+?)</description>", body, re.DOTALL)
    if m:
        title = m.group(1).strip()
    m = re.search(r'level="(\d+)"', body)
    if m:
        n = int(m.group(1))
        level = (
            "critical" if n >= 12
            else "high" if n >= 9
            else "medium" if n >= 5
            else "low"
        )
    return {"techniques": techs, "tags": set(), "title": title,
            "level": level, "raw": body}


# -------------------------------------------------------------- Carbon Black
def parse_carbonblack(path: Path) -> dict[str, Any]:
    techs: set[str] = set()
    title = path.stem
    level = None
    obj: dict | None = None
    try:
        obj = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return {"techniques": techs, "tags": set(), "title": title,
                "level": level, "raw": None}
    if isinstance(obj, dict):
        title = obj.get("name") or title
        level = obj.get("severity")
        for field in ("tags", "mitre", "description", "name"):
            v = obj.get(field)
            if v:
                techs.update(find_techniques(json.dumps(v)))
    return {"techniques": techs, "tags": set(), "title": title,
            "level": level, "raw": obj}


HANDLERS = {
    "sigma":              parse_sigma,
    "elastic":            parse_elastic,
    "splunk":             parse_splunk,
    "microsoft-sentinel": parse_sentinel,
    "wazuh":              parse_wazuh,
    "carbonblack":        parse_carbonblack,
    "falcon":             parse_sentinel,      # FQL files use // comments like KQL
    "sentinelone":        parse_sentinel,      # S1QL files use // comments like KQL
    "falco":              parse_sigma,          # YAML format, same parser works
}


def parse(platform: str, path: Path) -> dict[str, Any]:
    handler = HANDLERS.get(platform)
    if handler is None:
        raise ValueError(f"Unknown platform: {platform}")
    return handler(path)
