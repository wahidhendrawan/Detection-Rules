# Rule Templates

Boilerplate per platform untuk mempercepat pembuatan rule baru.
Salin file template ke folder yang sesuai, ubah nama, dan isi placeholder.

| File | Untuk | Tujuan folder |
|---|---|---|
| `sigma.yml` | Sigma | `sigma/<os>/` |
| `elastic.ndjson` | Elastic Security | `elastic/endpoint/<os>/` |
| `splunk.spl` | Splunk SPL | `splunk/<os>/` |
| `sentinel.kql` | Microsoft Sentinel | `microsoft-sentinel/` |
| `wazuh.xml` | Wazuh | `wazuh/rules/` |
| `carbonblack.json` | Carbon Black | `carbonblack/rules/` |

Lihat [`CONTRIBUTING.md`](../CONTRIBUTING.md) untuk standar metadata wajib.

## Tips

- Generate UUID v4 untuk Sigma `id` field: `python3 -c 'import uuid;print(uuid.uuid4())'`
- Cek konflik Wazuh rule ID: `grep -r 'rule id="100100"' wazuh/`
- Validasi Sigma sebelum commit: `sigma check sigma/path/to/rule.yml`
