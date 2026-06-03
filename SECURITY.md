# Security Policy

Terima kasih sudah meluangkan waktu untuk meningkatkan keamanan project ini.

## Lingkup

Repository ini berisi **detection rules**. Yang dimaksud "vulnerability"
dalam konteks repo ini bisa berupa:

1. **Tooling/CI vulnerability**: bug di skrip `scripts/`, GitHub Actions
   workflow, atau pre-commit config yang bisa dimanipulasi attacker.
2. **Rule yang berbahaya**: rule yang **bocor** PII pada output, bisa
   menyebabkan DoS pada SIEM (regex katastropik), atau secara tidak sengaja
   mengekspos data sensitif.
3. **Supply-chain risk**: dependensi atau action pihak ketiga yang
   ter-typosquat / di-pin tidak aman.

Bug **detection** (false negative / false positive) **bukan** vulnerability,
laporkan via [GitHub Issue → False Positive / Bug Report](https://github.com/wahidhendrawan/Detection-Rules/issues/new/choose).

---

## Versi yang Didukung

Karena repo ini bersifat *rolling*, hanya branch `main` yang aktif disupport.

| Branch | Status |
|---|---|
| `main` | ✅ Supported |
| Tag rilis (`v1.x`) | ✅ Supported (60 hari setelah rilis) |
| Branch lainnya | ❌ Tidak disupport |

---

## Cara Melaporkan

**Jangan** buka GitHub Issue publik untuk vulnerability. Sebagai gantinya:

1. **Preferred**: gunakan [GitHub Private Vulnerability Reporting](https://github.com/wahidhendrawan/Detection-Rules/security/advisories/new).
2. **Alternatif**: kirim email ke maintainer melalui kontak yang tertera di profil GitHub.

Cantumkan:

- Deskripsi vulnerability.
- Komponen / file yang terdampak.
- Steps to reproduce (PoC kalau ada).
- Dampak potensial.
- Versi / commit hash yang Anda uji.
- Saran mitigasi (opsional).

---

## Response SLA

| Tahap | Target |
|---|---|
| Acknowledgement laporan | 72 jam |
| Initial assessment | 7 hari |
| Patch / mitigasi | 30 hari (severity high/critical), 90 hari (low/medium) |
| Public disclosure | Setelah patch tersedia, dengan kredit kepada reporter |

---

## Disclosure Policy

Kami mengikuti **coordinated disclosure**. Reporter diharapkan tidak
mempublikasikan detail vulnerability sampai patch tersedia (atau 90 hari
sejak laporan, mana yang lebih dulu).

Reporter akan disebutkan di [`CHANGELOG.md`](CHANGELOG.md) dan rilis notes
(kecuali memilih anonim).

---

## Out-of-Scope

- Rule false positive / false negative — gunakan Issue biasa.
- Saran improvement umum — buka Discussion atau Issue.
- Vulnerability di SIEM/EDR vendor (Elastic, Splunk, Microsoft, Wazuh,
  Carbon Black) — laporkan ke vendor masing-masing.
- Permintaan support deployment / integrasi.

---

Terima kasih sudah membantu menjaga ekosistem ini tetap aman 🛡️
