"""Regression tests for the heatmap command."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from detection_rules.commands import heatmap


def test_select_platforms_returns_all_when_none_requested():
    result = heatmap._select_platforms(None)
    assert result == heatmap.SUPPORTED_PLATFORMS


def test_select_platforms_preserves_canonical_order():
    # Request platforms in non-canonical order
    result = heatmap._select_platforms(["wazuh", "sigma", "elastic"])
    # Output order should match SUPPORTED_PLATFORMS order
    assert result == ("sigma", "elastic", "wazuh")


def test_select_platforms_rejects_unknown():
    try:
        heatmap._select_platforms(["sigma", "unknown-platform"])
        assert False, "should have raised ValueError"
    except ValueError as exc:
        assert "unknown platform" in str(exc).lower()


def test_select_platforms_rejects_empty():
    try:
        heatmap._select_platforms([])
        assert False, "should have raised ValueError"
    except ValueError as exc:
        assert "at least one platform" in str(exc).lower()


def test_heat_level_boundaries():
    # Zero always gives 0
    assert heatmap._heat_level(0, 10) == 0
    assert heatmap._heat_level(0, 0) == 0
    # Maximum count gives 5
    assert heatmap._heat_level(10, 10) == 5
    # Non-zero count with valid max gives 1-5
    assert 1 <= heatmap._heat_level(1, 10) <= 5
    assert 1 <= heatmap._heat_level(5, 10) <= 5


def test_build_payload_structure():
    # Mock minimal coverage data
    t2p = {"T1059": {"sigma", "elastic"}, "T1003": {"sigma"}}
    p2t = {
        "sigma": {"T1059": {"sigma/win.yml"}, "T1003": {"sigma/cred.yml"}},
        "elastic": {"T1059": {"elastic/exec.ndjson"}},
    }
    rules = {
        "sigma": [Path("sigma/win.yml"), Path("sigma/cred.yml")],
        "elastic": [Path("elastic/exec.ndjson")],
    }

    payload = heatmap._build_payload(t2p, p2t, rules, ["sigma", "elastic"])

    # Structure validation
    assert payload["schema_version"] == 1
    assert "title" in payload
    assert "domain" in payload
    assert len(payload["platforms"]) == 2
    assert payload["platforms"][0]["id"] == "sigma"
    assert payload["platforms"][1]["id"] == "elastic"

    # Summary validation
    summary = payload["summary"]
    assert summary["platform_count"] == 2
    assert summary["technique_count"] == 2
    assert summary["rule_count"] == 3

    # Techniques validation
    techniques = {t["technique_id"]: t for t in payload["techniques"]}
    assert "T1059" in techniques
    assert "T1003" in techniques
    assert techniques["T1059"]["coverage_count"] == 2
    assert techniques["T1003"]["coverage_count"] == 1


def test_build_payload_filters_uncovered_techniques():
    t2p = {"T1059": {"sigma"}, "T1003": {"wazuh"}}
    p2t = {
        "sigma": {"T1059": {"sigma/win.yml"}},
        "wazuh": {"T1003": {"wazuh/cred.xml"}},
    }
    rules = {"sigma": [Path("sigma/win.yml")], "wazuh": [Path("wazuh/cred.xml")]}

    # Request only sigma - T1003 should be excluded
    payload = heatmap._build_payload(t2p, p2t, rules, ["sigma"])

    technique_ids = [t["technique_id"] for t in payload["techniques"]]
    assert "T1059" in technique_ids
    assert "T1003" not in technique_ids


def test_build_payload_deterministic_output():
    t2p = {"T1059": {"elastic", "sigma"}, "T1003": {"sigma"}}
    p2t = {
        "sigma": {"T1059": {"b.yml", "a.yml"}, "T1003": {"c.yml"}},
        "elastic": {"T1059": {"x.ndjson"}},
    }
    rules = {
        "sigma": [Path("b.yml"), Path("a.yml"), Path("c.yml")],
        "elastic": [Path("x.ndjson")],
    }

    payload1 = heatmap._build_payload(t2p, p2t, rules, ["sigma", "elastic"])
    payload2 = heatmap._build_payload(t2p, p2t, rules, ["sigma", "elastic"])

    # JSON serialization should be identical (deterministic)
    json1 = json.dumps(payload1, sort_keys=True)
    json2 = json.dumps(payload2, sort_keys=True)
    assert json1 == json2

    # Rules within each technique should be sorted
    for technique in payload1["techniques"]:
        for platform_id, rule_list in technique["rules"].items():
            assert rule_list == sorted(rule_list)


def test_render_html_contains_accessibility_features():
    payload = {
        "schema_version": 1,
        "title": "Test Heatmap",
        "domain": "enterprise-attack",
        "platforms": [{"id": "sigma", "label": "Sigma"}],
        "summary": {
            "platform_count": 1,
            "rule_count": 1,
            "technique_count": 1,
            "max_rules_per_cell": 1,
        },
        "platform_summary": [
            {"platform": "sigma", "label": "Sigma", "rule_count": 1, "technique_count": 1}
        ],
        "techniques": [
            {
                "technique_id": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactic": "execution",
                "coverage_count": 1,
                "coverage_percent": 100.0,
                "rule_count": 1,
                "platforms": ["sigma"],
                "rules": {"sigma": ["test.yml"]},
            }
        ],
    }

    html_output = heatmap._render_html(payload)

    # Check accessibility features
    assert 'lang="en"' in html_output
    assert "<title>" in html_output
    assert 'role="search"' in html_output
    assert 'role="status"' in html_output
    assert 'aria-live="polite"' in html_output
    assert 'aria-label=' in html_output
    assert 'scope="col"' in html_output
    assert 'scope="row"' in html_output
    assert '<label' in html_output
    assert 'class="skip-link"' in html_output
    assert '<noscript>' in html_output


def test_render_html_escapes_special_characters():
    payload = {
        "schema_version": 1,
        "title": "Test <script>alert('xss')</script>",
        "domain": "enterprise-attack",
        "platforms": [{"id": "sigma", "label": "Sigma & Elastic"}],
        "summary": {
            "platform_count": 1,
            "rule_count": 1,
            "technique_count": 1,
            "max_rules_per_cell": 1,
        },
        "platform_summary": [
            {"platform": "sigma", "label": "Sigma & Elastic", "rule_count": 1, "technique_count": 1}
        ],
        "techniques": [
            {
                "technique_id": "T1059",
                "name": "Command <Interpreter>",
                "tactic": "execution",
                "coverage_count": 1,
                "coverage_percent": 100.0,
                "rule_count": 1,
                "platforms": ["sigma"],
                "rules": {"sigma": ["test.yml"]},
            }
        ],
    }

    html_output = heatmap._render_html(payload)

    # Verify HTML escaping
    assert "<script>alert('xss')</script>" not in html_output
    assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html_output
    assert "Sigma &amp; Elastic" in html_output
    assert "&lt;Interpreter&gt;" in html_output


def test_run_rejects_unknown_platform(tmp_path: Path, capsys):
    args = SimpleNamespace(
        out_html=str(tmp_path / "out.html"),
        out_json=str(tmp_path / "out.json"),
        platform=["unknown-platform"],
    )

    result = heatmap.run(args)

    assert result == 2
    captured = capsys.readouterr()
    assert "unknown platform" in captured.out.lower()
