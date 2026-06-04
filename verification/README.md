# Atomic Red Team Verification Pipeline

Skeleton untuk automated rule verification menggunakan [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team).

## Arsitektur

```
verification/
├── README.md           ← dokumen ini
├── config.yml          ← environment config (SIEM endpoint, creds path)
├── run_atomics.ps1     ← execute atomic tests pada Windows target
├── check_alerts.py     ← query SIEM dan verify rule fired
└── results/            ← output per-run (gitignored)
```

## Prasyarat

- Windows VM/lab (Vagrant, Hyper-V, atau cloud) dengan Sysmon + agent SIEM
- [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) terinstall
- Python 3.11+ untuk `check_alerts.py`
- Credential ke SIEM API (Elastic, Splunk, Sentinel) di env var / vault

## Alur Kerja

1. **Execute** — `run_atomics.ps1` menjalankan atomic tests per technique ID
2. **Wait** — tunggu telemetry di-ingest (configurable delay, default 120s)
3. **Verify** — `check_alerts.py` query SIEM, cek apakah alert fired
4. **Report** — output `results/YYYY-MM-DD.json` + summary markdown

## Status

> ⚠️ **Skeleton** — belum executable end-to-end. Kontribusi welcome.
