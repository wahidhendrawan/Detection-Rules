# Detection Rules

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![GitHub Pages](https://img.shields.io/badge/landing%20page-live-brightgreen)](https://wahidhendrawan.github.io/Detection-Rules/)
[![GitHub last commit](https://img.shields.io/github/last-commit/wahidhendrawan/Detection-Rules)](https://github.com/wahidhendrawan/Detection-Rules/commits/main)
[![GitHub stars](https://img.shields.io/github/stars/wahidhendrawan/Detection-Rules?style=social)](https://github.com/wahidhendrawan/Detection-Rules/stargazers)
[![Validate Rules](https://github.com/wahidhendrawan/Detection-Rules/actions/workflows/validate.yml/badge.svg)](https://github.com/wahidhendrawan/Detection-Rules/actions/workflows/validate.yml)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red)](COVERAGE.md)
[![Rules](https://img.shields.io/endpoint?url=https://wahidhendrawan.github.io/Detection-Rules/badges/rules-total.json)](#rule-statistics)
[![ATT&CK Techniques](https://img.shields.io/endpoint?url=https://wahidhendrawan.github.io/Detection-Rules/badges/techniques.json)](COVERAGE.md)
[![Coverage](https://img.shields.io/endpoint?url=https://wahidhendrawan.github.io/Detection-Rules/badges/attack-coverage.json)](COVERAGE.md)
[![Quality](https://img.shields.io/endpoint?url=https://wahidhendrawan.github.io/Detection-Rules/badges/quality-score.json)](docs/metrics.md)
[![Last validated](https://img.shields.io/endpoint?url=https://wahidhendrawan.github.io/Detection-Rules/badges/last-validated.json)](.github/workflows/validate.yml)

> 🇬🇧 **English** · [🇮🇩 Bahasa Indonesia](README.md)

> A cross-platform collection of **detection rules** and **hunting queries**
> across **9 platforms** (Sigma, Elastic, Splunk, Microsoft Sentinel, Wazuh,
> Carbon Black, CrowdStrike Falcon, SentinelOne, and Falco) with MITRE ATT&CK
> mapping — **836 rules, 152 techniques, zero single-platform gaps**. The
> repository is intended as a *starter pack* for *blue teams* and *detection
> engineers*.

🌐 **Interactive landing page:** https://wahidhendrawan.github.io/Detection-Rules/
📦 **Latest release (auto-translated):** https://github.com/wahidhendrawan/Detection-Rules/releases/latest

---

## Table of Contents

- [Rule Statistics](#rule-statistics)
- [Repository Structure](#repository-structure)
- [Format & Naming Convention](#format--naming-convention)
- [Quick Start per Platform](#quick-start-per-platform)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)

---

## Rule Statistics

| Platform | Format | Total | Detail |
|---|---|---:|---|
| **Sigma** | `.yml` | 105 | windows: 51 · linux: 28 · network: 13 · cloud: 13 |
| **Elastic** | `.ndjson` | 58 | endpoint/general: 45 · endpoint/windows: 7 · endpoint/linux: 3 · endpoint/network: 2 · network: 1 |
| **Splunk** | `.spl` | 18 | windows: 10 · linux: 4 · network: 3 · cloud: 1 |
| **Microsoft Sentinel** | `.kql` | 102 | hunting + analytics |
| **Wazuh** | `.xml` | 140 | rules in `attack` group |
| **Carbon Black** | `.json` | 110 | EDR queries |
| **CrowdStrike Falcon** | `.esf` | 85 | endpoint detection + scheduled queries |
| **SentinelOne** | `.s1ql` | 95 | Deep Visibility + threat hunting |
| **Falco** | `.falco` | 123 | syscall rules · container/k8s/cloud |
| **TOTAL** | — | **836** | 9 platforms · 152 MITRE ATT&CK techniques |

See [`COVERAGE.md`](COVERAGE.md) for the full MITRE ATT&CK mapping.

---

## Repository Structure

```text
Detection-Rules/
├─ README.md              # Bahasa Indonesia (canonical)
├─ README.en.md           # English
├─ LICENSE
├─ CONTRIBUTING.md
├─ SECURITY.md
├─ CODE_OF_CONDUCT.md
├─ CHANGELOG.md
├─ COVERAGE.md
├─ CITATION.cff
├─ .github/
│  ├─ workflows/          # CI: Sigma, YAML, XML, JSON validators + release
│  ├─ ISSUE_TEMPLATE/
│  ├─ PULL_REQUEST_TEMPLATE.md
│  ├─ CODEOWNERS
│  └─ dependabot.yml
├─ scripts/               # tooling (coverage, index, CLI)
├─ tests/                 # detection logic unit tests
├─ templates/             # boilerplate per platform
├─ sigma/
│  ├─ windows/            # 51 rules
│  ├─ linux/              # 28 rules
│  ├─ network/            # 13 rules
│  └─ cloud/              # 13 rules
├─ elastic/
│  ├─ endpoint/
│  │  ├─ windows/         # 7 rules
│  │  ├─ linux/           # 3 rules
│  │  ├─ network/         # 2 rules
│  │  └─ general/         # 45 rules (multi-platform / threat-specific)
│  └─ network/            # 1 rule
├─ splunk/
│  ├─ windows/            # 10 rules
│  ├─ linux/              # 4 rules
│  ├─ network/            # 3 rules
│  └─ cloud/              # 1 rule
├─ microsoft-sentinel/    # 102 KQL hunting queries
├─ wazuh/
│  └─ rules/              # 140 XML rules (group "attack")
├─ carbonblack/
│  └─ rules/              # 110 JSON EDR queries
├─ falcon/
│  └─ rules/              # 85 CrowdStrike Falcon
├─ sentinelone/
│  └─ rules/              # 95 SentinelOne
└─ falco/
   └─ rules/              # 123 Falco syscall rules
```

---

## Format & Naming Convention

### File format per platform

| Platform | Extension | Notes |
|---|---|---|
| Sigma | `.yml` | [Sigma spec](https://github.com/SigmaHQ/sigma-specification). Required fields: `title`, `id`, `status`, `description`, `author`, `date`, `logsource`, `detection`, `level`, `tags` |
| Elastic | `.ndjson` | Exported from Kibana → Stack Management → Saved Objects (`type`: `query`/`esql`/`detection-rule`/`threshold`) |
| Splunk | `.spl` | Plain-text SPL with `#` header comments (Title, MITRE, Severity) |
| Sentinel | `.kql` | Plain-text KQL with `//` header comments |
| Wazuh | `.xml` | XML rule inside `<group name="attack">` with `<mitre>` tag |
| Carbon Black | `.json` | Object with `name`, `description`, `query`, `severity` |
| CrowdStrike Falcon | `.esf` | Event Search DSL. Inline header: `// MITRE:`, `// Severity:` |
| SentinelOne | `.s1ql` | Deep Visibility query language. Schema-specific field names |
| Falco | `.falco` | Syscall rules with `condition`, `output`, `priority` fields. Required: `condition`, `output`, `priority`, `tags` |

### Naming convention

Use a per-OS / per-domain prefix:

- `win_*`   → Windows
- `lnx_*`   → Linux
- `net_*`   → Network
- `cloud_*` → Cloud (AWS / GCP / Azure / M365)
- `app_*`   → Application logs (Wazuh)
- `kql_NNN_*` → Sentinel (numbered)
- `cb_*`    → Carbon Black
- `cs_*`    → CrowdStrike Falcon
- `s1_*`    → SentinelOne
- `fc_*`    → Falco

Examples:

- `win_powershell_suspicious_encoded_command.yml`
- `lnx_suspicious_sudo_without_tty.spl`
- `net_dns_suspicious_tunnel.yml`

---

## Quick Start per Platform

### Sigma

Convert to any SIEM backend with `sigma-cli`:

```bash
pip install sigma-cli pysigma-backend-elasticsearch pysigma-backend-splunk
sigma convert -t es-qs -o out/elastic/  sigma/windows/
sigma convert -t splunk -o out/splunk/  sigma/windows/
```

### Elastic

Import `.ndjson` files via Kibana:

`Stack Management` → `Saved Objects` → `Import` → pick a file from `elastic/endpoint/<os>/`

Or via API:

```bash
curl -k -u elastic:$PASS \
  -H 'kbn-xsrf: true' \
  -F file=@elastic/endpoint/windows/win_suspicious_certutil_download.ndjson \
  https://kibana:5601/api/saved_objects/_import
```

### Splunk

Create a *Correlation Search* / *Scheduled Search* and paste the `.spl` content.
The `# MITRE ATT&CK:` and `# Severity:` headers serve as inline documentation.

### Microsoft Sentinel

1. Open **Sentinel** → **Hunting** → **+ New Query**
2. Paste the `.kql` file content
3. Add tactics / techniques per the `// MITRE` comment (if present)
4. Save as a *Hunting Query* or promote to *Analytics Rule*

### Wazuh

Copy files into `/var/ossec/etc/rules/` on the manager:

```bash
sudo cp wazuh/rules/*.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
```

Make sure rule IDs do not collide with existing rules (custom range: `100000-119999`).

### Carbon Black

Import via API or Console → *Watchlists* → *Add Query*:

```bash
jq '.query' carbonblack/rules/cb_childproc_creation_7z_exe.json
```

Or bulk via API `POST /api/watchlists/{watchlist_id}/queries`.

### CrowdStrike Falcon

Import via Console → *Detections* → *Search* or use the API:

```bash
# Load ESF query and run via Falconpy
cat falcon/rules/cs_persistence_registry_run_key.esf
```

Paste directly into the Falcon Event Search interface with schema `ProcessRollup2`, `ProcessRollup3`, `DnsRequest`, etc.

### SentinelOne

Import via Console → *Threat Hunting* → *Deep Visibility* → *New Query*:

```bash
# Preview a rule
cat sentinelone/rules/s1_suspicious_wmi.s1ql
```

Select the correct data source schema — the `src.process.parent` and `tgt.process.imagePath` fields are commonly used.

### Falco

Copy rules into `/etc/falco/rules.d/`:

```bash
sudo cp falco/rules/*.falco /etc/falco/rules.d/
sudo systemctl restart falco
```

Falco loads all `.falco` files from the rules directory. Test with:

```bash
falco --r falco/rules/fc_privileged_container.falco -L
```

---

## MITRE ATT&CK Coverage

Every rule **must** be tagged with at least one MITRE ATT&CK technique:

```yaml
tags:
  - attack.t1059          # Command and Scripting Interpreter
  - attack.t1059.001      # Sub-technique: PowerShell
  - attack.execution      # Tactic
```

Generate the coverage matrix:

```bash
python3 scripts/generate_coverage.py
```

Outputs: `COVERAGE.md` (table) + `coverage.json` (Navigator-compatible).

To view in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/):
upload `coverage.json` via *"Open Existing Layer" → "Upload from local"*.

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full guide. In short:

1. Fork the repo, create a feature branch (`git checkout -b add/win-suspicious-foo`).
2. Add a rule in the appropriate folder (see [Repository Structure](#repository-structure)).
3. Make sure the rule has: title, description, author, date, MITRE tag, references.
4. Run validators locally:
   ```bash
   pre-commit run --all-files       # YAML / XML / JSON lint
   sigma check sigma/                # Sigma syntax
   pytest tests/                     # detection logic tests
   ```
5. Open a Pull Request against `main`. CI will run validators automatically.

Per-platform boilerplate is available under [`templates/`](templates/).

---

## Roadmap

- ✅ Auto-translate Sigma → all backends (Elastic / Splunk / Kusto / CrowdStrike) on release.
- ✅ ATT&CK Navigator JSON published per release.
- ✅ 9-platform coverage (Sigma, Elastic, Splunk, Sentinel, Wazuh, Carbon Black, Falcon, SentinelOne, Falco).
- ✅ 152 MITRE ATT&CK techniques mapped across all platforms.
- ⬜ Coverage badge per tactic.
- ⬜ Atomic Red Team mapping for end-to-end rule verification.
- ⬜ Cross-platform rule severity normalization.
- ⬜ CTI-driven tagging (link rules to threat actors / campaigns).
- ⬜ Automated rule generation from CISA KEV / CVE feeds.
- ⬜ Elastic Agents / Fleet integration packages.

---

## How to Cite

If you use this dataset in academic or industry research, please cite:

```bibtex
@software{hendrawan_detection_rules,
  author  = {Hendrawan, Wahid},
  title   = {Detection-Rules: Cross-Platform Detection Rules Library},
  year    = {2026},
  url     = {https://github.com/wahidhendrawan/Detection-Rules},
  license = {GPL-3.0}
}
```

A machine-readable [`CITATION.cff`](CITATION.cff) is also provided.

---

## License

[GPL-3.0](LICENSE) © Wahid Hendrawan

---

## Disclaimer

The rules in this repository are provided **AS-IS** for research, education,
and *detection engineering* purposes. Every rule **must be tested** in a
staging environment before being enabled in production. False-positive rates
in your environment may differ; tune thresholds / allowlists as needed.
