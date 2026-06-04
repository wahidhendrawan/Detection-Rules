# Performance & Cost Benchmarks

## Overview

Detection rules execute continuously against high-volume data streams. Poorly optimized queries increase costs, delay alerts, and can cause missed detections when queries time out or get throttled. Every millisecond saved per query multiplies across thousands of daily executions.

---

## Microsoft Sentinel (KQL)

**Efficiency tips:**
- Apply `| where TimeGenerated > ago(15m)` as the first filter — the engine prunes partitions early
- Avoid leading wildcards (`*admin`) — they bypass indexes and force full scans
- Use `materialized_view()` for pre-aggregated lookups (e.g., rare process baselines)
- Prefer `has` over `contains`; prefer `in~` over chained `or` statements
- Project only needed columns early: `| project TimeGenerated, Account, Computer`

| Query Pattern | Estimated KU Cost (per run) |
|---|---|
| Simple time-filtered, single table | 0.005–0.01 KU |
| Multi-table join with `let` statements | 0.05–0.2 KU |
| Leading wildcard / `contains` on large table | 0.3–1.0+ KU |
| Materialized view lookup | 0.001–0.005 KU |

---

## Splunk

**tstats vs raw search:**

| Method | Relative Speed | Use Case |
|---|---|---|
| `tstats` (accelerated data model) | 10–100x faster | Field-indexed data (CIM-mapped) |
| `stats` on raw search | Baseline | Ad-hoc or non-accelerated data |
| `raw search + regex` | 2–5x slower | Unstructured logs, last resort |

**Recommendations:**
- Accelerate data models used by detection rules (Network Traffic, Endpoint, Authentication)
- Use summary indexing for expensive aggregations that run hourly/daily
- Prefix searches with `index=` and `sourcetype=` to limit bucket scanning
- Avoid `NOT` at the start of searches — it forces broad scans

---

## Elastic

| Query Type | Strength | Weakness |
|---|---|---|
| EQL | Sequence/correlation, stateful detection | Slower on high-cardinality joins |
| KQL | Fast keyword filtering, Kibana-friendly | No sequences or pipes |
| Lucene | Raw index performance, regex support | Complex syntax, no correlation |

**ILM impact:** Rules querying warm/cold tier indices incur 3–10x latency. Pin detection rule target indices to the hot tier or use searchable snapshots selectively.

---

## Wazuh

- **Rule ordering:** Place high-frequency match rules (firewall drops, auth failures) at lower `level` values and earlier `rule_id` ranges to short-circuit evaluation
- **Decoder performance:** Regex decoders with backtracking patterns (`.*.*`) degrade throughput — use anchored patterns with `prematch`
- **Active response overhead:** Each triggered response forks a process; batch responses or rate-limit to avoid agent CPU spikes (keep <5 responses/sec/agent)

---

## Carbon Black

- **Query pagination:** Use `start` and `rows` parameters; queries returning >10K results get throttled. Page in batches of 500–1000
- **Watchlist vs feed:**

| Method | Latency | Resource Cost |
|---|---|---|
| Watchlist (query-based) | Near real-time, sensor-side | Higher sensor CPU |
| Feed (IOC list) | Batch interval (5–15 min) | Lower sensor CPU, server-side matching |

Use watchlists for behavioral queries; feeds for bulk IOC matching.

---

## General Best Practices

1. **Time window scoping** — Never query unbounded time ranges. Match the window to detection logic (e.g., 5 min for brute force, 1 hr for lateral movement)
2. **Field extraction vs full-text** — Structured field queries are 5–50x faster than full-text searches across all platforms
3. **Pre-filtering** — Chain cheap filters (index, source, event type) before expensive operations (regex, joins, stats)
4. **Stagger execution** — Offset rule schedules to avoid query spikes on shared infrastructure
5. **Test with production volume** — A rule fast on 1 GB will behave differently on 1 TB

---

## Cost Estimation (per rule, per day)

Assumes rule runs every 5 minutes (288 executions/day) against moderate log volume (~50 GB/day ingestion).

| Platform | Tier | Estimated Cost/Rule/Day | Notes |
|---|---|---|---|
| Microsoft Sentinel | Pay-as-you-go | $0.05–$0.50 | KU-based; joins increase cost |
| Microsoft Sentinel | Commitment tier | $0.02–$0.20 | 100 GB/day commitment |
| Splunk | Enterprise | Included (license) | Cost is in infrastructure/license |
| Splunk | Cloud | $0.01–$0.10 | SVCs consumed per search |
| Elastic | Self-managed | Infra cost only | CPU-bound; EQL sequences cost more |
| Elastic | Cloud | $0.01–$0.08 | Based on search compute units |
| Wazuh | Self-managed | Infra cost only | CPU-bound; scale manager vertically |
| Carbon Black | Cloud | Included | Watchlists consume sensor resources |

> **Note:** Costs are rough estimates for planning purposes. Actual costs depend on data volume, query complexity, and platform-specific pricing changes.
