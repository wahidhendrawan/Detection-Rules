"""Tests for scripts/generate_kev_rules.py using a local KEV fixture (no network)."""

from __future__ import annotations

import email.message
import io
import sys
from pathlib import Path
from urllib.response import addinfourl

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import generate_kev_rules as kev  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "kev" / "kev_feed.json"


def _fake_urlopen(body: bytes, content_type: str = "application/json"):
    headers = email.message.Message()
    headers["Content-Type"] = content_type
    return lambda url, timeout: addinfourl(io.BytesIO(body), headers, url)


def test_fetch_kev_returns_vulnerabilities(monkeypatch):
    monkeypatch.setattr(kev, "urlopen", _fake_urlopen(FIXTURE.read_bytes()))
    assert len(kev.fetch_kev()) == 5


@pytest.mark.parametrize(
    "body,content_type",
    [
        (b"<html>maintenance</html>", "text/html"),
        (b'{"vulnerabilities": {}}', "application/json"),
        (b"[]", "application/json"),
    ],
)
def test_fetch_kev_rejects_bad_responses(monkeypatch, body, content_type):
    monkeypatch.setattr(kev, "urlopen", _fake_urlopen(body, content_type))
    with pytest.raises(SystemExit):
        kev.fetch_kev()


def test_fetch_kev_rejects_oversized_feed(monkeypatch):
    monkeypatch.setattr(kev, "MAX_KEV_BYTES", 64)
    monkeypatch.setattr(kev, "urlopen", _fake_urlopen(FIXTURE.read_bytes()))
    with pytest.raises(SystemExit):
        kev.fetch_kev()


def test_main_writes_only_valid_entries(monkeypatch, tmp_path):
    out = tmp_path / "out"
    monkeypatch.setattr(kev, "urlopen", _fake_urlopen(FIXTURE.read_bytes()))
    monkeypatch.setattr(kev, "find_existing_cves", set)
    monkeypatch.setattr(sys, "argv", ["generate_kev_rules.py", "--output", str(out)])

    assert kev.main() == 0

    written = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file())
    assert written == [
        "out/microsoft-sentinel/kev_cve_2099_0001.kql",
        "out/sigma/kev_cve_2099_0001.yml",
    ]
    rule = yaml.safe_load((out / "sigma" / "kev_cve_2099_0001.yml").read_text(encoding="utf-8"))
    assert rule["title"].startswith('CVE-2099-0001: Example: Corp Widget "Pro" - ')
    assert rule["x_kev"]["vendor_project"] == "Example: Corp"
    assert rule["x_kev"]["required_action"] == "Apply mitigations per vendor instructions: patch now."
