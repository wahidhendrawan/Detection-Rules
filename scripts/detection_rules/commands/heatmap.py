"""Generate a standalone accessible ATT&CK coverage heatmap and JSON data."""

from __future__ import annotations

import html
import json
import math
from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import Iterable

from ..paths import PLATFORM_GLOBS, ROOT
from . import coverage
from .index import TECHNIQUE_INFO

SCHEMA_VERSION = 1
SUPPORTED_PLATFORMS = tuple(PLATFORM_GLOBS)
PLATFORM_LABELS = {
    "sigma": "Sigma",
    "elastic": "Elastic",
    "splunk": "Splunk",
    "microsoft-sentinel": "Microsoft Sentinel",
    "wazuh": "Wazuh",
    "carbonblack": "Carbon Black",
    "falcon": "CrowdStrike Falcon",
    "sentinelone": "SentinelOne",
    "falco": "Falco",
}


def add_arguments(parser: ArgumentParser) -> None:
    parser.add_argument(
        "--out-html",
        default=str(ROOT / "public" / "heatmap.html"),
        help="standalone HTML output path (default: public/heatmap.html)",
    )
    parser.add_argument(
        "--out-json",
        default=str(ROOT / "public" / "heatmap.json"),
        help="machine-readable JSON output path (default: public/heatmap.json)",
    )
    parser.add_argument(
        "--platform",
        action="append",
        choices=SUPPORTED_PLATFORMS,
        metavar="PLATFORM",
        help="include a platform; repeat to include multiple (default: all)",
    )


def _select_platforms(requested: Iterable[str] | None) -> tuple[str, ...]:
    if requested is None:
        return SUPPORTED_PLATFORMS

    requested_set = set(requested)
    unknown = requested_set.difference(SUPPORTED_PLATFORMS)
    if unknown:
        names = ", ".join(sorted(unknown))
        raise ValueError(f"unknown platform(s): {names}")

    selected = tuple(platform for platform in SUPPORTED_PLATFORMS if platform in requested_set)
    if not selected:
        raise ValueError("at least one platform is required")
    return selected


def _build_payload(
    t2p: dict[str, set[str]],
    p2t: dict[str, dict[str, set[str]]],
    rules: dict[str, list[Path]],
    requested_platforms: Iterable[str] | None = None,
) -> dict:
    platforms = _select_platforms(requested_platforms)
    techniques: list[dict] = []
    max_rule_count = 0

    for technique_id in sorted(t2p):
        covered_platforms = tuple(
            platform for platform in platforms if platform in t2p[technique_id]
        )
        if not covered_platforms:
            continue

        detections = {
            platform: sorted(p2t.get(platform, {}).get(technique_id, set()))
            for platform in platforms
        }
        rule_count = sum(len(paths) for paths in detections.values())
        max_rule_count = max(max_rule_count, *(len(paths) for paths in detections.values()))
        name, tactic = TECHNIQUE_INFO.get(
            technique_id, ("Unknown / Custom", "uncategorized")
        )
        techniques.append(
            {
                "technique_id": technique_id,
                "name": name,
                "tactic": tactic,
                "coverage_count": len(covered_platforms),
                "coverage_percent": round(100 * len(covered_platforms) / len(platforms), 1),
                "rule_count": rule_count,
                "platforms": list(covered_platforms),
                "rules": detections,
            }
        )

    platform_summary = [
        {
            "platform": platform,
            "label": PLATFORM_LABELS.get(platform, platform),
            "rule_count": len(rules.get(platform, [])),
            "technique_count": sum(
                1 for technique in techniques if platform in technique["platforms"]
            ),
        }
        for platform in platforms
    ]

    return {
        "schema_version": SCHEMA_VERSION,
        "title": "Detection-Rules MITRE ATT&CK Coverage Heatmap",
        "domain": "enterprise-attack",
        "platforms": [
            {"id": platform, "label": PLATFORM_LABELS.get(platform, platform)}
            for platform in platforms
        ],
        "summary": {
            "platform_count": len(platforms),
            "rule_count": sum(len(rules.get(platform, [])) for platform in platforms),
            "technique_count": len(techniques),
            "max_rules_per_cell": max_rule_count,
        },
        "platform_summary": platform_summary,
        "techniques": techniques,
    }


def _heat_level(count: int, maximum: int) -> int:
    if count <= 0 or maximum <= 0:
        return 0
    return max(1, min(5, math.ceil(5 * math.log1p(count) / math.log1p(maximum))))


def _render_html(payload: dict) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    platforms = payload["platforms"]
    summary = payload["summary"]
    maximum = summary["max_rules_per_cell"]

    platform_headers = "".join(
        f'<th scope="col"><span class="platform-name">{esc(platform["label"])}</span></th>'
        for platform in platforms
    )
    rows: list[str] = []
    for technique in payload["techniques"]:
        cells: list[str] = []
        for platform in platforms:
            count = len(technique["rules"][platform["id"]])
            level = _heat_level(count, maximum)
            label = f'{count} rule' if count == 1 else f'{count} rules'
            display = str(count) if count else "—"
            cells.append(
                f'<td class="heat heat-{level}" data-label="{esc(platform["label"])}">'
                f'<span aria-label="{esc(label)}">{display}</span></td>'
            )
        search_text = " ".join(
            (
                technique["technique_id"],
                technique["name"],
                technique["tactic"],
                *technique["platforms"],
            )
        ).lower()
        coverage_label = (
            f'{technique["coverage_count"]} of {summary["platform_count"]} platforms '
            f'({technique["coverage_percent"]}%)'
        )
        rows.append(
            f'<tr data-search="{esc(search_text)}" '
            f'data-coverage="{technique["coverage_count"]}">'
            f'<th scope="row"><span class="technique-id">{esc(technique["technique_id"])}</span>'
            f'<span class="technique-name">{esc(technique["name"])}</span></th>'
            f'<td data-label="Tactic">{esc(technique["tactic"].replace("-", " "))}</td>'
            f'{"".join(cells)}'
            f'<td class="coverage" data-label="Coverage">{esc(coverage_label)}</td>'
            f'<td class="total" data-label="Mapped rules">{technique["rule_count"]}</td>'
            '</tr>'
        )

    platform_cards = "".join(
        '<li>'
        f'<strong>{esc(item["label"])}</strong>'
        f'<span>{item["technique_count"]} techniques · {item["rule_count"]} rules</span>'
        '</li>'
        for item in payload["platform_summary"]
    )
    title = esc(payload["title"])
    rows_html = "\n".join(rows)
    no_results_colspan = len(platforms) + 4

    return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{title}</title>
<style>
:root{{--bg:#f8fafc;--panel:#fff;--text:#172033;--muted:#526079;--border:#cbd5e1;--focus:#075985;--h1:#e0f2fe;--h2:#bae6fd;--h3:#7dd3fc;--h4:#38bdf8;--h5:#0369a1;--on-dark:#fff}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0f172a;--panel:#172033;--text:#f8fafc;--muted:#cbd5e1;--border:#526079;--focus:#7dd3fc;--h1:#19354c;--h2:#164e63;--h3:#075985;--h4:#0369a1;--h5:#0c4a6e;--on-dark:#fff}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:1rem/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}}a{{color:inherit}}.skip-link{{position:absolute;left:.5rem;top:-4rem;background:var(--panel);padding:.75rem;z-index:10}}.skip-link:focus{{top:.5rem}}header,main,footer{{width:min(100% - 2rem,100rem);margin:auto}}header{{padding:2.5rem 0 1rem}}h1{{font-size:clamp(1.8rem,5vw,3rem);line-height:1.1;margin:0 0 .75rem}}.lede{{color:var(--muted);max-width:70ch}}.summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(10rem,1fr));gap:.75rem;margin:1.5rem 0}}.summary div,.platforms li{{background:var(--panel);border:1px solid var(--border);border-radius:.5rem;padding:1rem}}.summary strong{{display:block;font-size:1.7rem}}.summary span,.platforms span{{display:block;color:var(--muted);font-size:.875rem}}.platforms{{display:grid;grid-template-columns:repeat(auto-fit,minmax(12rem,1fr));gap:.5rem;list-style:none;padding:0}}.controls{{display:flex;align-items:end;flex-wrap:wrap;gap:1rem;margin:2rem 0 1rem}}.field{{display:grid;gap:.25rem}}label{{font-weight:700}}input,select{{min-height:2.75rem;padding:.55rem .7rem;border:1px solid var(--border);border-radius:.35rem;background:var(--panel);color:var(--text);font:inherit}}input{{width:min(28rem,80vw)}}:focus-visible{{outline:3px solid var(--focus);outline-offset:2px}}#result-count{{color:var(--muted);margin-left:auto}}.table-wrap{{overflow:auto;background:var(--panel);border:1px solid var(--border);border-radius:.5rem}}table{{width:100%;border-collapse:collapse;min-width:64rem}}caption{{text-align:left;padding:1rem;font-weight:700}}th,td{{border-top:1px solid var(--border);padding:.65rem;text-align:center;vertical-align:middle}}thead th{{position:sticky;top:0;background:var(--panel);z-index:1}}tbody th{{text-align:left;min-width:14rem}}.technique-id,.technique-name{{display:block}}.technique-id{{font:700 .9rem ui-monospace,SFMono-Regular,Consolas,monospace}}.technique-name{{font-weight:400;color:var(--muted)}}.heat{{font-weight:700;min-width:5rem}}.heat-0{{color:var(--muted)}}.heat-1{{background:var(--h1)}}.heat-2{{background:var(--h2)}}.heat-3{{background:var(--h3)}}.heat-4{{background:var(--h4)}}.heat-5{{background:var(--h5);color:var(--on-dark)}}.coverage{{min-width:9rem}}.total{{font-weight:700}}[hidden]{{display:none!important}}.empty{{padding:2rem;color:var(--muted)}}footer{{padding:2rem 0;color:var(--muted);font-size:.875rem}}.noscript{{border-left:.3rem solid var(--focus);padding:.75rem;background:var(--panel)}}
@media(max-width:50rem){{.platform-name{{writing-mode:vertical-rl}}#result-count{{width:100%;margin:0}}}}
@media print{{.controls,.skip-link{{display:none}}thead th{{position:static}}.table-wrap{{overflow:visible}}}}
</style>
</head>
<body>
<a class="skip-link" href="#heatmap">Skip to heatmap</a>
<header>
<h1>{title}</h1>
<p class="lede">Rule counts by ATT&amp;CK technique and detection platform. Darker cells indicate more mapped rules; every cell also includes its numeric value.</p>
<div class="summary" aria-label="Coverage summary">
<div><strong>{summary["technique_count"]}</strong><span>covered techniques</span></div>
<div><strong>{summary["rule_count"]}</strong><span>rule files scanned</span></div>
<div><strong>{summary["platform_count"]}</strong><span>platforms included</span></div>
</div>
<ul class="platforms" aria-label="Platform summary">{platform_cards}</ul>
</header>
<main id="main">
<section aria-labelledby="heatmap-heading">
<h2 id="heatmap-heading">Coverage heatmap</h2>
<div class="controls" role="search">
<div class="field"><label for="search">Filter techniques</label><input id="search" type="search" placeholder="ID, name, tactic, or platform" autocomplete="off"></div>
<div class="field"><label for="coverage-filter">Platform coverage</label><select id="coverage-filter"><option value="all">All coverage levels</option><option value="single">One platform only</option><option value="partial">More than one, not all</option><option value="full">All selected platforms</option></select></div>
<p id="result-count" role="status" aria-live="polite">Showing {summary["technique_count"]} of {summary["technique_count"]} techniques</p>
</div>
<noscript><p class="noscript">JavaScript is disabled. The complete heatmap remains available; interactive filters are unavailable.</p></noscript>
<div class="table-wrap" id="heatmap" tabindex="0" aria-label="Scrollable heatmap table">
<table>
<caption>Mapped rule counts. An em dash means no mapped rule.</caption>
<thead><tr><th scope="col">Technique</th><th scope="col">Tactic</th>{platform_headers}<th scope="col">Coverage</th><th scope="col">Mapped rules</th></tr></thead>
<tbody id="heatmap-body">
{rows_html}
<tr id="empty-row" hidden><td class="empty" colspan="{no_results_colspan}">No techniques match the selected filters.</td></tr>
</tbody>
</table>
</div>
</section>
</main>
<footer><p>Generated deterministically from repository coverage data by <code>python -m detection_rules heatmap</code>. No external assets or services are required.</p></footer>
<script>
(() => {{
  "use strict";
  const rows = [...document.querySelectorAll("#heatmap-body tr[data-search]")];
  const search = document.getElementById("search");
  const coverage = document.getElementById("coverage-filter");
  const status = document.getElementById("result-count");
  const empty = document.getElementById("empty-row");
  const platformCount = {summary["platform_count"]};
  function render() {{
    const query = search.value.trim().toLocaleLowerCase();
    let shown = 0;
    for (const row of rows) {{
      const count = Number(row.dataset.coverage);
      const matchesCoverage = coverage.value === "all" ||
        (coverage.value === "single" && count === 1) ||
        (coverage.value === "partial" && count > 1 && count < platformCount) ||
        (coverage.value === "full" && count === platformCount);
      const visible = row.dataset.search.includes(query) && matchesCoverage;
      row.hidden = !visible;
      if (visible) shown += 1;
    }}
    empty.hidden = shown !== 0;
    status.textContent = `Showing ${{shown}} of ${{rows.length}} techniques`;
  }}
  search.addEventListener("input", render);
  coverage.addEventListener("change", render);
}})();
</script>
</body>
</html>
'''


def run(args: Namespace) -> int:
    try:
        payload = _build_payload(*coverage._build(), args.platform)
    except ValueError as exc:
        print(f"[!] {exc}")
        return 2

    out_html = Path(args.out_html)
    out_json = Path(args.out_json)
    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_json.parent.mkdir(parents=True, exist_ok=True)

    out_html.write_text(_render_html(payload), encoding="utf-8", newline="\n")
    out_json.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"[+] Wrote {out_html}")
    print(f"[+] Wrote {out_json} ({payload['summary']['technique_count']} techniques)")
    return 0
