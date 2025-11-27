# SIEM Detection Rules

Repository ini berisi kumpulan **detection rules** untuk berbagai platform SIEM
(Sigma, Elastic / Kibana, Splunk, dan query generic). Struktur dibuat agar mudah
di-maintain dan di-extend.

## Struktur Repository

```text
siem-detection-rules/
├─ README.md
├─ LICENSE
├─ .gitignore
├─ sigma/
│  ├─ windows/
│  ├─ linux/
│  ├─ network/
│  └─ cloud/
├─ elastic/
│  ├─ endpoint/
│  └─ network/
├─ splunk/
└─ queries/
```

## Format Rule

- **Sigma**: file `.yml` mengikuti spesifikasi Sigma (title, id, logsource, detection, fields, tags).
- **Elastic**: file `.ndjson` berisi export KQL/EQL detection rules (1 rule per baris).
- **Splunk**: file `.spl` berisi SPL search beserta komentar `#`.
- **Queries**: file `.kql`, `.eql`, atau `.sql` untuk keperluan lain (hunting / ad-hoc).

## Naming Convention

- Gunakan prefix platform & kategori:
  - `win_`, `lnx_`, `net_`, `cloud_`
- Gunakan kata-kata pendek dan jelas, contoh:
  - `win_powershell_suspicious_encoded_command.yml`
  - `net_dns_suspicious_tunnel.yml`

## MITRE ATT&CK Tagging

Setiap rule dianjurkan menambahkan tag:
- `attack.tXXXX` (mis: `attack.t1059`)
- `attack.txxxx.mXXXX` untuk sub-technique (mis: `attack.t1059.001`)
- `attack.execution`, `attack.discovery`, dll.

## Cara Pakai Cepat

1. **Sigma**
   - Konversi ke backend (Elastic/Splunk/QRadar, dll) menggunakan `sigma-cli`:
     ```bash
     sigma convert -t es-qs -o out/ elastic/sigma/windows/win_powershell_suspicious_encoded_command.yml
     ```

2. **Elastic**
   - Import file `.ndjson` via:
     - *Stack Management* → *Saved Objects* → *Import*

3. **Splunk**
   - Copy query `.spl` ke *Correlation Search* atau *Scheduled Search*.

## Kontribusi

1. Tambah / ubah rule di folder sesuai platform.
2. Pastikan:
   - Ada `title`, `description`, `status`, `author`, `date`, `references` (jika ada).
   - Ada mapping MITRE ATT&CK di `tags`.
3. Lakukan PR ke branch utama.

---

Dibuat untuk menjadi base repository detection rules yang bisa langsung di-push ke GitHub.
