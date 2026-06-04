# Detection Rules

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub Pages](https://img.shields.io/badge/landing%20page-live-brightgreen)](https://wahidhendrawan.github.io/Detection-Rules/)
[![GitHub last commit](https://img.shields.io/github/last-commit/wahidhendrawan/Detection-Rules)](https://github.com/wahidhendrawan/Detection-Rules/commits/main)
[![GitHub stars](https://img.shields.io/github/stars/wahidhendrawan/Detection-Rules?style=social)](https://github.com/wahidhendrawan/Detection-Rules/stargazers)
[![Validate Rules](https://github.com/wahidhendrawan/Detection-Rules/actions/workflows/validate.yml/badge.svg)](https://github.com/wahidhendrawan/Detection-Rules/actions/workflows/validate.yml)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red)](COVERAGE.md)
[![Rules](https://img.shields.io/endpoint?url=https://wahidhendrawan.github.io/Detection-Rules/badges/rules-total.json)](#statistik-rule)
[![ATT&CK Techniques](https://img.shields.io/endpoint?url=https://wahidhendrawan.github.io/Detection-Rules/badges/techniques.json)](COVERAGE.md)
[![Coverage](https://img.shields.io/endpoint?url=https://wahidhendrawan.github.io/Detection-Rules/badges/attack-coverage.json)](COVERAGE.md)
[![Quality](https://img.shields.io/endpoint?url=https://wahidhendrawan.github.io/Detection-Rules/badges/quality-score.json)](docs/metrics.md)
[![Last validated](https://img.shields.io/endpoint?url=https://wahidhendrawan.github.io/Detection-Rules/badges/last-validated.json)](.github/workflows/validate.yml)

> 🇮🇩 **Bahasa Indonesia** · [🇬🇧 English](README.en.md)

> Kumpulan **detection rules** dan **hunting queries** lintas 9 platform (Sigma,
> Elastic, Splunk, Microsoft Sentinel, Wazuh, Carbon Black, CrowdStrike,
> SentinelOne, dan Falco) dengan mapping MITRE ATT&CK. Repository ini
> dimaksudkan sebagai *starter pack* untuk *blue team* dan *detection engineer*.

🌐 **Landing page interaktif:** https://wahidhendrawan.github.io/Detection-Rules/  
📦 **Latest release (auto-translated):** https://github.com/wahidhendrawan/Detection-Rules/releases/latest

---

## Daftar Isi

- [Statistik Rule](#statistik-rule)
- [Struktur Repository](#struktur-repository)
- [Format & Konvensi Penamaan](#format--konvensi-penamaan)
- [Quick Start per Platform](#quick-start-per-platform)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Kontribusi](#kontribusi)
- [Roadmap](#roadmap)
- [Lisensi](#lisensi)

---

## Statistik Rule

| Platform | Format | Total | Detail |
|---|---|---:|---|
| **Sigma** | `.yml` | 227 | windows: 127 · linux: 36 · network: 22 · cloud: 39 · correlations: 3 |
| **Elastic** | `.ndjson` | 58 | endpoint/general: 45 · endpoint/windows: 7 · endpoint/linux: 3 · endpoint/network: 2 · network: 1 |
| **Splunk** | `.spl` | 66 | windows: 58 · linux: 4 · network: 3 · cloud: 1 |
| **Microsoft Sentinel** | `.kql` | 150 | hunting + analytics |
| **Wazuh** | `.xml` | 187 | rules attack group |
| **Carbon Black** | `.json` | 142 | EDR queries (generated from `tools.yml`) |
| **CrowdStrike Falcon** | `.fql` | 2 | Falcon Query Language |
| **SentinelOne** | `.s1ql` | 2 | Deep Visibility queries |
| **Falco** | `.yaml` | 2 | K8s/container runtime rules |
| **TOTAL** | — | **836** | — |

Lihat [`COVERAGE.md`](COVERAGE.md) untuk pemetaan ke MITRE ATT&CK.

---

## Struktur Repository

```text
Detection-Rules/
├─ README.md
├─ LICENSE
├─ CONTRIBUTING.md
├─ SECURITY.md
├─ CODE_OF_CONDUCT.md
├─ CHANGELOG.md
├─ COVERAGE.md
├─ .github/
│  ├─ workflows/        # CI: validasi sigma, yaml, xml, json
│  ├─ ISSUE_TEMPLATE/
│  ├─ PULL_REQUEST_TEMPLATE.md
│  └─ CODEOWNERS
├─ scripts/             # tooling (mis. generator MITRE coverage)
├─ templates/           # boilerplate per platform
├─ sigma/
│  ├─ windows/          # 127 rule
│  ├─ linux/            # 36 rule
│  ├─ network/          # 22 rule
│  ├─ cloud/            # 39 rule
│  └─ correlations/     # 3 aggregation rule
├─ elastic/
│  ├─ endpoint/
│  │  ├─ windows/       # 7 rule
│  │  ├─ linux/         # 3 rule
│  │  ├─ network/       # 2 rule
│  │  └─ general/       # 45 rule (multi-platform / threat-specific)
│  └─ network/          # 1 rule
├─ splunk/
│  ├─ windows/          # 58 rule
│  ├─ linux/            # 4 rule
│  ├─ network/          # 3 rule
│  └─ cloud/            # 1 rule
├─ microsoft-sentinel/  # 150 KQL hunting queries
├─ wazuh/
│  └─ rules/            # 187 XML rule (group "attack")
├─ carbonblack/
│  ├─ rules/            # 142 JSON EDR query (generated)
│  └─ tools.yml         # codegen matrix definition
├─ sentinelone/         # 2 S1QL Deep Visibility queries
├─ falcon/              # 2 CrowdStrike FQL queries
├─ falco/               # 2 K8s/container runtime rules
└─ verification/        # Atomic Red Team test pipeline
```

---

## Format & Konvensi Penamaan

### Format file per platform

| Platform | Ekstensi | Catatan |
|---|---|---|
| Sigma | `.yml` | Spec [Sigma](https://github.com/SigmaHQ/sigma-specification). Field wajib: `title`, `id`, `status`, `description`, `author`, `date`, `logsource`, `detection`, `level`, `tags` |
| Elastic | `.ndjson` | Hasil ekspor dari Kibana → Stack Management → Saved Objects (`type`: `query`/`esql`/`detection-rule`/`threshold`) |
| Splunk | `.spl` | Search SPL plain-text dengan komentar `#` di header (Title, MITRE, Severity) |
| Sentinel | `.kql` | KQL query plain-text dengan komentar `//` di header |
| Wazuh | `.xml` | Rule XML dalam `<group name="attack">` dengan tag `<mitre>` |
| Carbon Black | `.json` | Object dengan field `name`, `description`, `query`, `severity` |

### Naming convention

Gunakan prefix per kategori OS/domain:

- `win_*`  → Windows
- `lnx_*`  → Linux
- `net_*`  → Network
- `cloud_*` → Cloud (AWS/GCP/Azure/M365)
- `app_*`  → Application (Wazuh)
- `kql_NNN_*` → Sentinel (numbered)

Contoh:

- `win_powershell_suspicious_encoded_command.yml`
- `lnx_suspicious_sudo_without_tty.spl`
- `net_dns_suspicious_tunnel.yml`

---

## Quick Start per Platform

### Sigma

Konversi ke backend SIEM apa pun via `sigma-cli`:

```bash
pip install sigma-cli pysigma-backend-elasticsearch pysigma-backend-splunk
sigma convert -t es-qs -o out/elastic/  sigma/windows/
sigma convert -t splunk -o out/splunk/  sigma/windows/
```

### Elastic

Import file `.ndjson` via Kibana:

`Stack Management` → `Saved Objects` → `Import` → pilih file dari `elastic/endpoint/<os>/`

Atau via API:

```bash
curl -k -u elastic:$PASS \
  -H 'kbn-xsrf: true' \
  -F file=@elastic/endpoint/windows/win_suspicious_certutil_download.ndjson \
  https://kibana:5601/api/saved_objects/_import
```

### Splunk

Buat *Correlation Search* / *Scheduled Search*, lalu paste isi file `.spl`.
Header `# MITRE ATT&CK:` dan `# Severity:` berfungsi sebagai dokumentasi inline.

### Microsoft Sentinel

1. Buka **Sentinel** → **Hunting** → **+ New Query**
2. Paste isi file `.kql`
3. Tambah tactics/techniques sesuai komentar `// MITRE` (jika ada)
4. Save sebagai *Hunting Query* atau promote ke *Analytics Rule*

### Wazuh

Salin file ke `/var/ossec/etc/rules/` di manager:

```bash
sudo cp wazuh/rules/*.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
```

Pastikan `id` rule tidak bentrok dengan rule existing (rentang custom: `100000-119999`).

### Carbon Black

Import via API atau Console → *Watchlists* → *Add Query*:

```bash
jq '.query' carbonblack/rules/cb_childproc_creation_7z_exe.json
```

Atau bulk via API `POST /api/watchlists/{watchlist_id}/queries`.

---

## MITRE ATT&CK Coverage

Setiap rule **wajib** ditag dengan teknik MITRE ATT&CK:

```yaml
tags:
  - attack.t1059          # Command and Scripting Interpreter
  - attack.t1059.001      # Sub-technique: PowerShell
  - attack.execution      # Tactic
```

Generate coverage matrix:

```bash
python3 scripts/generate_coverage.py
```

Outputnya: `COVERAGE.md` (tabel) + `coverage.json` (Navigator-compatible).

---

## Kontribusi

Lihat [`CONTRIBUTING.md`](CONTRIBUTING.md) untuk panduan lengkap. Ringkas:

1. Fork repo, buat branch fitur (`git checkout -b add/win-suspicious-foo`).
2. Tambah rule di folder yang sesuai (lihat [Struktur Repository](#struktur-repository)).
3. Pastikan rule punya: title, description, author, date, MITRE tag, references.
4. Jalankan validator lokal:
   ```bash
   pre-commit run --all-files       # YAML/XML/JSON lint
   sigma check sigma/                # Sigma syntax
   ```
5. Buka Pull Request ke `main`. CI akan menjalankan validator otomatis.

Boilerplate per platform tersedia di [`templates/`](templates/).

---

## Roadmap

- ✅ Tambah workflow auto-translate Sigma → semua backend (Elastic/Splunk/Kusto/CrowdStrike) via release artifact.
- ✅ Generate ATT&CK Navigator JSON ke GitHub Pages.
- ✅ Coverage badge dinamis (per tactic).
- ✅ Atomic Red Team mapping untuk verifikasi rule.
- ✅ Rule severity normalization (cross-platform) — `detection_rules lint-severity`.
- ✅ EDR vendor expansion (SentinelOne, CrowdStrike Falcon, Falco).
- ✅ Cloud/SaaS rules (AWS, Azure, GCP, Okta, GitHub).
- ⬜ Sigma correlation rules end-to-end (pending pySigma correlation support).
- ⬜ CI integration test dengan Elastic docker (end-to-end alert verification).
- ⬜ Deploy workflow ke production SIEM (Elastic/Splunk/Sentinel).
- ⬜ Rule effectiveness scoring dari real SOC feedback.
- ⬜ Community monthly rule sprint program.

---

## Lisensi

[MIT](LICENSE) © Wahid Hendrawan

---

## Disclaimer

Rule di repo ini disediakan **AS-IS** untuk keperluan riset, edukasi, dan
*detection engineering*. Setiap rule **harus diuji** di lingkungan staging
sebelum diaktifkan di produksi. False positive di environment Anda mungkin
berbeda; sesuaikan threshold / whitelist sesuai kebutuhan.
