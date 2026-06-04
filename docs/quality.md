# Rule Quality & Fidelity Classification

Tidak semua rule di repo ini cocok dipakai langsung sebagai *alerting rule*
di SIEM produksi. Beberapa rule sengaja dibuat **broad/permisif** untuk
*hunting* atau *baseline*, sementara yang lain sudah cukup **spesifik**
untuk detection aktif.

Dokumen ini menjelaskan sistem klasifikasi fidelitas yang dipakai di
seluruh rule di repo ini.

---

## Tingkat Fidelitas

| Level | Pengguna untuk | Karakteristik | Direkomendasikan jadi… |
|---|---|---|---|
| `informational` | Audit / observability / asset inventory | Match event apa pun yang relevan tanpa filter mencurigakan. False positive **tinggi by design**. | Hunting query atau saved search, **bukan** alert. |
| `low` | Hunting awal / threat hunting | Match pola umum yang **bisa** mencurigakan. Volume sedang. | Daily hunt notebook, log enrichment. |
| `medium` | Detection dengan investigasi manual | Match pola spesifik tapi masih bisa benign. Perlu konteks tambahan untuk yakin. | Alert ke L1 SOC dengan playbook investigasi. |
| `high` | Detection yang dapat ditindaklanjuti | Pola yang dengan tingkat keyakinan tinggi mengarah ke aktivitas malicious. False positive minim. | Direct alert ke L2 SOC / IR. |
| `critical` | Detection yang harus segera ditindaklanjuti | Indikator strong compromise (mis. credential dump, ransomware behavior). | Page on-call SOC / immediate response. |

---

## Cara Klasifikasi

Untuk menentukan level rule, gunakan checklist berikut:

1. **Apakah match-nya hanya pada nama proses / event ID generik?**
   (mis. `process_name == 'cmd.exe'`, `event_id == 4624`)
   → `informational` atau `low`.

2. **Apakah ada filter pendamping?**
   (parent process, command-line args, user context, file path, threshold,
   time window)
   → naik ke `medium`.

3. **Apakah kombinasi filter-nya membuat rule sulit di-trigger oleh
   aktivitas legit?**
   → `high`.

4. **Apakah behavior yang dideteksi merupakan indikator strong post-compromise?**
   (mis. LSASS dump, shadow copy deletion, mass file rename ransomware)
   → `critical`.

---

## Konvensi Penulisan per Platform

### Sigma (`.yml`)

Field standar Sigma `level:` digunakan langsung. Field `falsepositives:` **wajib**
diisi dengan list FP yang diketahui.

```yaml
level: medium
falsepositives:
  - Software vendor signed installer (mis. Microsoft Update).
  - Admin script yang memang menjalankan certutil untuk download internal.
```

### Microsoft Sentinel (`.kql`)

Comment header `// Severity:` di awal file. Tambahkan `// FalsePositives:`
juga jika applicable.

```kql
// Title: PowerShell EncodedCommand
// Severity: high
// FalsePositives:
//   - Microsoft scheduled tasks (Get-WindowsUpdate.ps1, dsregcmd, dll).
//   - Tools manajemen RMM (Datto, NinjaOne) yang pakai EncodedCommand.
```

### Splunk (`.spl`)

Comment header `# Severity:` dan `# False Positives:`.

```spl
# Severity: high
# False Positives:
#   - Microsoft scheduled tasks yang pakai EncodedCommand
#   - RMM tools (Datto, NinjaOne)
```

### Wazuh (`.xml`)

Wazuh punya field `level` numerik (0-15). Mapping:

| Sigma level | Wazuh level |
|---|---|
| `informational` | 3-4 |
| `low` | 5-6 |
| `medium` | 7-9 |
| `high` | 10-12 |
| `critical` | 13-15 |

Comment XML untuk dokumentasi tambahan:

```xml
<!--
  Severity: high
  FalsePositives:
    - Routine apache restart oleh systemd timer
-->
<rule id="100100" level="10">
  ...
</rule>
```

### Elastic (`.ndjson`)

Field `severity` (low/medium/high/critical) dan `risk_score` (0-100).
Field `false_positives[]` di rule body.

### Carbon Black (`.json`)

Field `severity` (1-10 atau "low"/"medium"/"high"/"critical").
Field `false_positives` (array of strings) opsional.

---

## Contoh Klasifikasi

### `informational` — Hunting/Audit

```kql
// kql_001_proc_exec_cmd.kql
// Severity: informational
// Description: Hunts for cmd.exe execution. Sangat umum, hanya untuk
//              baseline/hunting. Jangan dijadikan alert tanpa filter
//              tambahan.
ProcessExecutionEvents | where ProcessName == 'cmd.exe'
```

### `medium` — Detection dengan investigasi

```kql
// kql_002_proc_exec_powershell.kql
// Severity: medium
// Description: PowerShell execution dengan flag mencurigakan.
//              Memerlukan investigasi manual untuk konfirmasi malicious.
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("EncodedCommand", "-enc ", "-w hidden",
                                     "DownloadString", "IEX", "Invoke-Expression")
| where InitiatingProcessFileName !in~ ("explorer.exe", "services.exe")
```

### `high` — Direct alert

```yaml
# win_powershell_suspicious_encoded_command.yml
level: high
falsepositives:
  - Microsoft scheduled tasks (whitelist by parent + user).
  - RMM tools.
```

### `critical` — Page on-call

```yaml
# win_lsass_dump_via_procdump.yml
level: critical
falsepositives:
  - Authorized IR investigation (verify with ticket).
```

---

## Migrasi Rule Existing

Rule lama yang belum diklasifikasi diberi level **default berdasarkan
heuristik**:

| Pola | Level default |
|---|---|
| 1-line query tanpa filter, hanya match nama proses/event ID | `informational` |
| Query dengan filter sederhana (1-2 kondisi) | `low` |
| Query dengan filter berlapis (proses + args + parent) | `medium` |
| Query yang match indicator post-exploit jelas (mimikatz output, ransomware patterns) | `high` |
| Indikator strong compromise (LSASS dump, ransomware mass rename) | `critical` |

Re-klasifikasi rule existing dilakukan secara bertahap (setiap PR yang
menyentuh rule wajib menambahkan/memperbarui field severity).

---

## Referensi

- [Sigma Specification — level field](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#level)
- [MITRE Cyber Analytic Repository — Detection Quality](https://car.mitre.org/)
- [Palantir Alerting and Detection Strategy (ADS) Framework](https://github.com/palantir/alerting-detection-strategy-framework)
