# Sprint #001 — Juni 2026

## Tema: Cloud & Container Detection

Target: 10 rules baru untuk cloud dan container threats.

## Teknik yang Tersedia

| # | Technique | Platform Suggestion | Claimed By |
|---|---|---|---|
| 1 | T1552.005 Cloud Instance Metadata API | Sigma, Sentinel | - |
| 2 | T1610 Deploy Container | Falco | - |
| 3 | T1613 Container and Resource Discovery | Falco, Sigma | - |
| 4 | T1609 Container Administration Command | Falco | - |
| 5 | T1537 Transfer Data to Cloud Account | Sigma, Splunk | - |
| 6 | T1580 Cloud Infrastructure Discovery | Sigma, Sentinel | - |
| 7 | T1578.001 Create Snapshot | Sigma, Sentinel | - |
| 8 | T1525 Implant Internal Image | Falco | - |
| 9 | T1204.003 Malicious Image | Falco | - |
| 10 | T1496 Resource Hijacking (Cryptomining) | Sigma, Wazuh | - |

## Cara Berpartisipasi

1. Comment di issue sprint untuk claim teknik
2. Fork repo, buat rule di platform yang sesuai
3. Submit PR dengan label `community:sprint`
4. Review oleh maintainer dalam 48 jam

## Hadiah

- Nama di CHANGELOG + README contributors
- Badge "Sprint Champion" untuk kontributor terbanyak
