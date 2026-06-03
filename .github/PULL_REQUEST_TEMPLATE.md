<!-- Terima kasih atas kontribusinya! Lengkapi checklist di bawah. -->

## Deskripsi Singkat

<!-- Apa yang berubah & kenapa? Link issue terkait jika ada (Closes #123). -->

## Jenis Perubahan

- [ ] 🆕 Rule baru
- [ ] 🐛 Perbaikan rule existing (bug fix / FP reduction)
- [ ] 📝 Dokumentasi
- [ ] 🔧 Tooling / CI / refactor
- [ ] 💥 Breaking change (rename folder, hapus rule, dst.)

## Platform & Kategori

- [ ] Sigma · `windows` / `linux` / `network` / `cloud`
- [ ] Elastic · `endpoint` / `network`
- [ ] Splunk · `windows` / `linux` / `network` / `cloud`
- [ ] Microsoft Sentinel
- [ ] Wazuh
- [ ] Carbon Black

## Checklist Rule (jika menambah/ubah rule)

- [ ] File ditempatkan di folder yang benar
- [ ] Naming sesuai konvensi (`win_`, `lnx_`, `net_`, `cloud_`, `app_`, `kql_NNN_`, `cb_`)
- [ ] Metadata lengkap: title, description, author, date, references
- [ ] MITRE ATT&CK tag minimal 1 teknik + 1 tactic
- [ ] Severity / level di-set
- [ ] False positive yang diketahui didokumentasikan
- [ ] Sudah diuji di lingkungan staging (jelaskan di bawah)
- [ ] Tidak ada konflik rule ID (Wazuh: range 100000–119999)

## Bukti Pengujian

<!--
Sertakan salah satu:
- Screenshot hasil deteksi di SIEM/EDR.
- Sample event (sanitize PII!) yang men-trigger rule.
- Output `sigma check` jika rule Sigma.
- Atomic Red Team test ID jika ada.
-->

## Referensi

<!-- Threat intel, blog, CVE, ATT&CK, dst. -->

## Catatan untuk Reviewer

<!-- Hal khusus yang perlu diperhatikan reviewer. -->
