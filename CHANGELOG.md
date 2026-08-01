# Changelog

Semua perubahan signifikan pada repo ini akan didokumentasikan di sini.

Format mengikuti [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning mengikuti [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [v1.5.0] - 2026-08-01

### Added
- **ATT&CK coverage heatmap generator** — `detection_rules heatmap` command generates standalone HTML and machine-readable JSON showing rule coverage per technique and platform. Features deterministic output, platform filtering, keyboard navigation, and accessibility support.
- **Architecture guide** at `docs/architecture.md` documenting CLI structure, rule validation pipeline, and extension points.
- Offline `detection_rules lint` command for Sigma YAML syntax, required metadata, UUID, detection structure, ATT&CK technique, and duplicate-ID validation, with optional `sigma-cli` checks.

## [v1.4.0] - 2026-07-26

### Added
- CISA Known Exploited Vulnerabilities auto-generator script (`scripts/generate_kev_rules.py`).
- Falcon, SentinelOne, and Falco platform support — 9 total platforms with 836 rules, 152 techniques.
- Mega project README with comprehensive badges for all 10 platforms, new platform quick-start guides.
- CITATION.cff and FUNDING.yml for academic and sponsor attribution.
- GitHub Discussions enabled.

### Changed
- Export stats refreshed: 9 platforms, 836 rules, 152 MITRE ATT&CK techniques.

## [v1.1.0] - 2026-07-26

### Added
- Scripts to fix and backfill MITRE ATT&CK techniques for Wazuh, Sentinel, and Carbon Black rules.
- Governance files (`CONTRIBUTING.md`, `SECURITY.md`, etc.), issue/PR templates, and `CODEOWNERS`.
- GitHub Actions for validation (`validate.yml`) and stale issue cleanup (`stale.yml`).
- Coverage generation script and auto-generated `COVERAGE.md`.
- Pre-commit hooks for local validation.
- Rewritten `README.md` with comprehensive details.

### Fixed
- Replaced placeholder `T1000` MITRE technique in 100 Wazuh rules with valid techniques.
- Corrected invalid Sigma tactic tags (`attack.defense_evasion` → `attack.defense-evasion`).
- Backfilled missing MITRE techniques in 102 Sentinel KQL files and 110 Carbon Black JSON rules, significantly increasing coverage.
- Fixed invalid `status` and `id` fields in several Sigma rules.

### Changed
- **BREAKING**: Renamed `Microsoft Sentinel/` to `microsoft-sentinel/`.
- **BREAKING**: Restructured `splunk/` and `elastic/endpoint/` directories by category.
- Regenerated `COVERAGE.md`, increasing unique cross-platform techniques from 77 to 124.

[Unreleased]: https://github.com/wahidhendrawan/Detection-Rules/compare/v1.1.0...HEAD
[v1.1.0]: https://github.com/wahidhendrawan/Detection-Rules/compare/v1.0.0...v1.1.0

### Added

- Skrip `scripts/fix_wazuh_t1000.py` — replace placeholder `T1000`
  dengan teknik MITRE valid (100 rule Wazuh).
- Skrip `scripts/fix_sentinel_mitre.py` — backfill header
  `// MITRE ATT&CK: TXXXX` ke 102 KQL file Sentinel.
- Skrip `scripts/fix_carbonblack_mitre.py` — backfill field `mitre`
  ke 110 JSON Carbon Black.

### Fixed

- **Wazuh** — 100 rule yang memakai placeholder `T1000` (bukan teknik
  MITRE valid; teknik dimulai dari `T1001`). Setiap rule sekarang
  dipetakan ke teknik yang sesuai berdasarkan filename/description
  (mis. `app_*_stopped` → `T1489`, `net_dns_tunneling` → `T1071.004`
  + `T1572`, `win_suspicious_process_lsass` → `T1003.001`).
- **Sigma** — 27 rule yang memakai underscore di tactic tag
  (`attack.defense_evasion`) diganti ke hyphen (`attack.defense-evasion`)
  sesuai Sigma specification. Tag `attack.ingress_tool_transfer`
  (yang sebenarnya teknik T1105, bukan tactic) diganti ke `attack.t1105`.
- **Microsoft Sentinel** — 102 KQL file yang sebelumnya tidak punya tag
  MITRE eksplisit di header sekarang ada. Coverage Sentinel naik dari
  0 → 61 teknik.
- **Carbon Black** — 110 JSON yang sebelumnya tidak punya field `mitre`
  sekarang ada. Coverage Carbon Black naik dari 0 → 30 teknik.

### Changed

- `COVERAGE.md` & `coverage.json` di-regenerate. Teknik unik lintas
  platform: **77 → 124** (+61%).

### Added

- Struktur governance lengkap: `CONTRIBUTING.md`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, issue templates (bug report, false positive,
  rule request), PR template, `CODEOWNERS`.
- GitHub Actions workflow `validate.yml`: yamllint, sigma-cli, xmllint,
  jq (JSON & NDJSON), KQL smoke check, MITRE coverage artifact upload.
- GitHub Actions workflow `stale.yml`: auto-cleanup issue/PR yang stale.
- Skrip `scripts/generate_coverage.py` untuk generate `COVERAGE.md` dan
  `coverage.json` (ATT&CK Navigator-compatible).
- File `COVERAGE.md` (auto-generated) dengan matrix lintas platform.
- Pre-commit config (`.pre-commit-config.yaml`) untuk validasi lokal.
- Folder `templates/` berisi boilerplate per platform.
- README.md ditulis ulang lengkap dengan badges, tabel statistik,
  quick-start per platform, dan roadmap.
- `.yamllint.yml` config (relax line-length=200, ignore non-Sigma folders).

### Changed

- **BREAKING**: rename folder `Microsoft Sentinel/` → `microsoft-sentinel/`
  (hilangkan spasi). Semua 102 file `.kql` ikut dipindah dengan `git mv`
  sehingga history tetap utuh.
- **BREAKING**: restruktur `splunk/` dari flat list → `splunk/{windows,linux,network,cloud}/`.
- **BREAKING**: restruktur `elastic/endpoint/` dari flat list →
  `elastic/endpoint/{windows,linux,network,general}/`.

### Removed

- Folder placeholder kosong: `sigma/rules/`, `elastic/rules/`, `splunk/query/`.

### Fixed

- 7 rule Sigma yang memakai severity word (`high`/`medium`) sebagai
  `status:` — diganti ke `status: experimental` (field `level:` yang
  sudah ada tidak diubah).
- 6 rule Sigma yang `id:`-nya tidak valid UUID — di-regenerate dengan
  UUID v4.

### Known Issues

- Banyak rule di `wazuh/rules/` memakai placeholder `T1000` (bukan teknik
  MITRE valid; teknik dimulai dari `T1001`). Akan dibersihkan di rilis
  selanjutnya.
- Rule di `microsoft-sentinel/` dan `carbonblack/rules/` belum semuanya
  punya tag MITRE eksplisit. Coverage = 0 untuk dua platform tersebut
  pada generator saat ini.

---

## [1.0.0] - TBA

Rilis awal — kumpulan rule lintas platform dari sebelumnya.

[Unreleased]: https://github.com/wahidhendrawan/Detection-Rules/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/wahidhendrawan/Detection-Rules/releases/tag/v1.0.0
