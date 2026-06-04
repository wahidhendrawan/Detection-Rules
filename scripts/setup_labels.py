"""Create GitHub labels for the Detection-Rules repository using gh CLI."""

import subprocess
import json

LABELS = [
    ("good-first-rule", "0e8a16", "Easy rules for newcomers"),
    ("platform:sigma", "1d76db", "Sigma format rule"),
    ("platform:elastic", "f9d0c4", "Elastic/EQL rule"),
    ("platform:splunk", "ff7043", "Splunk SPL rule"),
    ("platform:sentinel", "7057ff", "Microsoft Sentinel KQL rule"),
    ("platform:wazuh", "0d47a1", "Wazuh rule"),
    ("platform:carbonblack", "546e7a", "Carbon Black rule"),
    ("priority:gap-closure", "d93f0b", "Closes ATT&CK gap"),
    ("quality:uplift", "f9a825", "Improves existing rule quality"),
    ("type:correlation", "9c27b0", "Correlation/aggregation rule"),
    ("severity:critical", "b60205", "Critical severity"),
    ("severity:high", "e11d48", "High severity"),
    ("community:sprint", "0075ca", "Part of monthly sprint"),
]


def get_existing_labels():
    result = subprocess.run(
        ["gh", "label", "list", "--json", "name", "--limit", "200"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"Error listing labels: {result.stderr}")
        return set()
    return {label["name"] for label in json.loads(result.stdout)}


def main():
    existing = get_existing_labels()
    for name, color, description in LABELS:
        if name in existing:
            print(f"SKIP (exists): {name}")
            continue
        result = subprocess.run(
            ["gh", "label", "create", name, "--color", color, "--description", description],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"CREATED: {name}")
        else:
            print(f"ERROR: {name} - {result.stderr.strip()}")


if __name__ == "__main__":
    main()
