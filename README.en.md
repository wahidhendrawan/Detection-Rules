# Detection Rules

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
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
> (Sigma, Elastic, Splunk, Microsoft Sentinel, Wazuh, and Carbon Black) with
> MITRE ATT&CK mapping. The repository is intended as a *starter pack* for
> *blue teams* and *detection engineers*.

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
| **TOTAL** | — | **533** | — |

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
└─ carbonblack/
   └─ rules/              # 110 JSON EDR queries
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

### Naming convention

Use a per-OS / per-domain prefix:

- `win_*`   → Windows
- `lnx_*`   → Linux
- `net_*`   → Network
- `cloud_*` → Cloud (AWS / GCP / Azure / M365)
- `app_*`   → Application logs (Wazuh)
- `kql_NNN_*` → Sentinel (numbered)
- `cb_*`    → Carbon Black

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
- ⬜ Coverage badge per tactic.
- ⬜ Atomic Red Team mapping for end-to-end rule verification.
- ⬜ Cross-platform rule severity normalization.
- ⬜ CTI-driven tagging (link rules to threat actors / campaigns).

---

## How to Cite

If you use this dataset in academic or industry research, please cite:

```bibtex
@software{hendrawan_detection_rules,
  author  = {Hendrawan, Wahid},
  title   = {Detection-Rules: Cross-Platform Detection Rules Library},
  year    = {2026},
  url     = {https://github.com/wahidhendrawan/Detection-Rules},
  license = {MIT}
}
```

A machine-readable [`CITATION.cff`](CITATION.cff) is also provided.

---

## License

[MIT](LICENSE) © Wahid Hendrawan

---

## Disclaimer

The rules in this repository are provided **AS-IS** for research, education,
and *detection engineering* purposes. Every rule **must be tested** in a
staging environment before being enabled in production. False-positive rates
in your environment may differ; tune thresholds / allowlists as needed.
