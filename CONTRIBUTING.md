# Panduan Kontribusi

Terima kasih sudah ingin berkontribusi ke **Detection-Rules**! Dokumen ini
menjelaskan bagaimana cara berkontribusi rule baru, melaporkan bug,
atau mengusulkan perbaikan.

---

## Daftar Isi

- [Code of Conduct](#code-of-conduct)
- [Cara Berkontribusi](#cara-berkontribusi)
- [Standar Rule per Platform](#standar-rule-per-platform)
- [Naming Convention](#naming-convention)
- [MITRE ATT&CK Tagging](#mitre-attck-tagging)
- [Validasi Lokal](#validasi-lokal)
- [Proses Review](#proses-review)
- [Melaporkan Bug / False Positive](#melaporkan-bug--false-positive)

---

## Code of Conduct

Project ini tunduk pada [Code of Conduct](CODE_OF_CONDUCT.md). Dengan
berpartisipasi, Anda diharapkan menjaga lingkungan yang ramah dan inklusif.

---

## Cara Berkontribusi

1. **Fork** repository ini.
2. **Clone** fork Anda:
   ```bash
   git clone https://github.com/<username>/Detection-Rules.git
   cd Detection-Rules
   ```
3. **Buat branch** dari `main`:
   ```bash
   git checkout -b add/<short-description>
   # contoh: add/win-suspicious-rundll32-network
   ```
4. **Tambah / ubah rule** di folder yang sesuai (lihat [README](README.md#struktur-repository)).
5. **Validasi lokal** (lihat [Validasi Lokal](#validasi-lokal)).
6. **Commit** dengan pesan yang jelas. Format yang dianjurkan:
   ```
   feat(sigma/windows): add detection for suspicious certutil download
   fix(wazuh): correct rule ID conflict 100019
   docs(readme): update coverage table
   ```
7. **Push** branch & buka **Pull Request** ke `main`.

---

## Standar Rule per Platform

Boilerplate lengkap tersedia di [`templates/`](templates/). Semua rule **wajib** punya:

- **Title**: deskriptif, ≤ 80 karakter.
- **Description**: jelaskan apa yang dideteksi & kenapa itu mencurigakan.
- **Author**: nama / handle pengirim.
- **Date**: tanggal pembuatan (format `YYYY/MM/DD` untuk Sigma, atau ISO 8601).
- **References** (jika ada): URL ke threat intel, CVE, blog post, atau ATT&CK technique.
- **MITRE ATT&CK tags**: minimal satu `attack.tXXXX` dan satu tactic.
- **Severity / Level**: `low`, `medium`, `high`, atau `critical`.

### Sigma (`.yml`)

```yaml
title: <Deskriptif singkat>
id: <UUID v4>
status: experimental | test | stable | deprecated
description: |
  Penjelasan multi-baris.
author: <Nama>
date: 2026/01/01
references:
  - https://...
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\example.exe'
  condition: selection
fields:
  - Image
  - CommandLine
falsepositives:
  - Penjelasan FP yang diketahui.
level: high
tags:
  - attack.t1059
  - attack.execution
```

### Elastic (`.ndjson`)

Ekspor langsung dari Kibana → Stack Management → Saved Objects → Export.
Pastikan field `references[]` dan `threat[]` (mapping MITRE) terisi.

### Splunk (`.spl`)

```spl
# Title: <Deskriptif>
# Description: <penjelasan>
# Author: <nama>
# Date: 2026-01-01
# MITRE ATT&CK: T1059, T1059.001
# Severity: high
# References: https://...

index=windows ...
| stats ... by ...
| sort - _time
```

### Microsoft Sentinel (`.kql`)

```kql
// Title: <Deskriptif>
// Description: <penjelasan>
// Author: <nama>
// Date: 2026-01-01
// MITRE ATT&CK: T1059
// Severity: high
// References: https://...

ProcessExecutionEvents
| where ProcessName == 'cmd.exe'
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

### Wazuh (`.xml`)

```xml
<group name="attack">
  <rule id="100100" level="8">
    <decoded_as>windows_security</decoded_as>
    <field name="event_id">4720</field>
    <description>Detects user account creation.</description>
    <mitre>
      <id>T1136.001</id>
    </mitre>
  </rule>
</group>
```

> **PENTING**: Rule ID Wazuh harus dalam rentang custom **100000-119999**.
> Cek konflik dengan `grep -r 'rule id="100100"' wazuh/`.

### Carbon Black (`.json`)

```json
{
  "name": "cb_<short_name>",
  "description": "...",
  "query": "process_name:example.exe AND ...",
  "severity": "high"
}
```

---

## Naming Convention

| Prefix | Untuk | Contoh |
|---|---|---|
| `win_` | Windows | `win_suspicious_powershell.yml` |
| `lnx_` | Linux | `lnx_sudo_without_tty.spl` |
| `net_` | Network | `net_dns_tunneling.yml` |
| `cloud_` | Cloud (AWS/GCP/Azure/M365) | `cloud_iam_role_grant.spl` |
| `app_` | Application logs (Wazuh) | `app_apache_unauthorized.xml` |
| `kql_NNN_` | Sentinel (numbered) | `kql_101_proc_exec_certutil.kql` |
| `cb_` | Carbon Black | `cb_childproc_creation_7z.json` |

Aturan tambahan:

- Gunakan `snake_case`, lowercase.
- Tidak boleh ada spasi atau karakter spesial.
- Maksimal 80 karakter.

---

## MITRE ATT&CK Tagging

Setiap rule **WAJIB** punya minimal satu tag teknik dan satu tag tactic.

Format tag:

- `attack.tXXXX` → teknik (contoh: `attack.t1059`)
- `attack.tXXXX.YYY` → sub-technique (contoh: `attack.t1059.001`)
- `attack.<tactic>` → tactic (contoh: `attack.execution`)

Tactic yang valid:

`reconnaissance`, `resource_development`, `initial_access`, `execution`,
`persistence`, `privilege_escalation`, `defense_evasion`, `credential_access`,
`discovery`, `lateral_movement`, `collection`, `command_and_control`,
`exfiltration`, `impact`.

Lihat [https://attack.mitre.org](https://attack.mitre.org) untuk referensi lengkap.

---

## Validasi Lokal

Sebelum push, jalankan validator:

```bash
# 1. Setup pre-commit
pip install pre-commit sigma-cli yamllint
pre-commit install

# 2. Validasi semua file
pre-commit run --all-files

# 3. Validasi Sigma
sigma check sigma/

# 4. Validasi XML Wazuh
xmllint --noout wazuh/rules/*.xml

# 5. Validasi JSON Carbon Black
for f in carbonblack/rules/*.json; do jq empty "$f"; done

# 6. Validasi NDJSON Elastic
for f in $(find elastic -name '*.ndjson'); do
  while IFS= read -r line; do echo "$line" | jq empty || echo "Invalid: $f"; done < "$f"
done
```

Generator coverage:

```bash
python3 scripts/generate_coverage.py
```

CI di GitHub akan menjalankan semua validator otomatis pada PR.

---

## Proses Review

1. PR dibuka → CI (GitHub Actions) berjalan otomatis.
2. Tunggu hingga semua check **hijau**.
3. Maintainer akan review:
   - Kebenaran logika deteksi.
   - Kelengkapan metadata (MITRE tag, references, FP).
   - Konsistensi penamaan & struktur.
4. Setelah approval & CI hijau → maintainer akan **squash merge**.

PR yang stuck > 14 hari tanpa response akan diberi label `stale` dan ditutup
otomatis setelah 7 hari berikutnya (kecuali dilabel `keep-open`).

---

## Melaporkan Bug / False Positive

- **Bug rule** (rule tidak fire / fire salah): buka [Issue → Bug Report](https://github.com/wahidhendrawan/Detection-Rules/issues/new?template=bug_report.yml).
- **False positive**: buka [Issue → False Positive](https://github.com/wahidhendrawan/Detection-Rules/issues/new?template=false_positive.yml). Sertakan:
  - Path file rule.
  - Sample event yang false positive.
  - Lingkungan (OS, EDR/SIEM version).
- **Permintaan rule baru**: buka [Issue → Rule Request](https://github.com/wahidhendrawan/Detection-Rules/issues/new?template=rule_request.yml).
- **Vulnerability di tooling repo**: lihat [SECURITY.md](SECURITY.md).

---

Terima kasih atas kontribusi Anda! 🛡️
