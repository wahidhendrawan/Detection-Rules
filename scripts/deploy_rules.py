#!/usr/bin/env python3
"""Deploy detection rules to target SIEM platform."""

import argparse
import os
import sys
import uuid
from pathlib import Path

import requests


def deploy_elastic(base_dir: Path) -> bool:
    url = os.environ["ELASTIC_URL"]
    token = os.environ["ELASTIC_TOKEN"]
    rules_dir = base_dir / "elastic"
    files = list(rules_dir.rglob("*.ndjson"))
    if not files:
        print("No .ndjson files found in elastic/")
        return True

    failed = []
    for f in files:
        print(f"Importing: {f.relative_to(base_dir)}")
        resp = requests.post(
            f"{url}/api/saved_objects/_import?overwrite=true",
            headers={"kbn-xsrf": "true", "Authorization": f"ApiKey {token}"},
            files={"file": (f.name, f.open("rb"), "application/x-ndjson")},
        )
        if resp.ok:
            result = resp.json()
            print(f"  ✓ Success ({result.get('successCount', 0)} objects)")
        else:
            print(f"  ✗ Failed ({resp.status_code}): {resp.text[:200]}")
            failed.append(str(f))

    if failed:
        print(f"\n{len(failed)}/{len(files)} rules failed.")
    return len(failed) == 0


def deploy_splunk(base_dir: Path) -> bool:
    url = os.environ["SPLUNK_URL"]
    token = os.environ["SPLUNK_TOKEN"]
    rules_dir = base_dir / "splunk"
    files = list(rules_dir.rglob("*.spl"))
    if not files:
        print("No .spl files found in splunk/")
        return True

    failed = []
    for f in files:
        rule_name = f.stem
        search_content = f.read_text(encoding="utf-8").strip()
        print(f"Creating saved search: {rule_name}")
        resp = requests.post(
            f"{url}/servicesNS/admin/search/saved/searches",
            headers={"Authorization": f"Bearer {token}"},
            data={
                "name": rule_name,
                "search": search_content,
                "is_scheduled": "1",
                "cron_schedule": "*/15 * * * *",
                "dispatch.earliest_time": "-15m",
                "dispatch.latest_time": "now",
                "alert_type": "number of events",
                "alert_comparator": "greater than",
                "alert_threshold": "0",
            },
            verify=False,  # nosec B501 - Splunk lab/dev instances commonly use self-signed certs
        )
        if resp.status_code in (200, 201, 409):
            if resp.status_code == 409:
                # Already exists, update it
                resp = requests.post(
                    f"{url}/servicesNS/admin/search/saved/searches/{rule_name}",
                    headers={"Authorization": f"Bearer {token}"},
                    data={"search": search_content},
                    verify=False,  # nosec B501 - same as above, self-signed cert in lab/dev
                )
            print(f"  ✓ Success ({resp.status_code})")
        else:
            print(f"  ✗ Failed ({resp.status_code}): {resp.text[:200]}")
            failed.append(rule_name)

    if failed:
        print(f"\n{len(failed)}/{len(files)} rules failed.")
    return len(failed) == 0


def deploy_sentinel(base_dir: Path) -> bool:
    tenant_id = os.environ["SENTINEL_TENANT_ID"]
    client_id = os.environ["SENTINEL_CLIENT_ID"]
    client_secret = os.environ["SENTINEL_CLIENT_SECRET"]
    workspace_id = os.environ["SENTINEL_WORKSPACE_ID"]

    # Get access token
    token_resp = requests.post(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://management.azure.com/.default",
        },
    )
    if not token_resp.ok:
        print(f"Authentication failed: {token_resp.text[:200]}")
        return False
    access_token = token_resp.json()["access_token"]

    rules_dir = base_dir / "microsoft-sentinel"
    files = list(rules_dir.rglob("*.kql"))
    if not files:
        print("No .kql files found in microsoft-sentinel/")
        return True

    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    resource_group = os.environ.get("SENTINEL_RESOURCE_GROUP", "")
    api_version = "2024-09-01"
    base_url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}/providers"
        f"/Microsoft.OperationalInsights/workspaces/{workspace_id}"
        f"/providers/Microsoft.SecurityInsights/alertRules"
    )

    failed = []
    for f in files:
        rule_name = f.stem.replace("_", " ")
        query = f.read_text(encoding="utf-8").strip()
        rule_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f.name))
        print(f"Creating analytics rule: {rule_name}")

        resp = requests.put(
            f"{base_url}/{rule_id}?api-version={api_version}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            json={
                "kind": "Scheduled",
                "properties": {
                    "displayName": rule_name,
                    "query": query,
                    "queryFrequency": "PT5H",
                    "queryPeriod": "PT5H",
                    "severity": "Medium",
                    "triggerOperator": "GreaterThan",
                    "triggerThreshold": 0,
                    "enabled": True,
                    "suppressionEnabled": False,
                    "suppressionDuration": "PT5H",
                },
            },
        )
        if resp.ok:
            print(f"  ✓ Success ({resp.status_code})")
        else:
            print(f"  ✗ Failed ({resp.status_code}): {resp.text[:200]}")
            failed.append(rule_name)

    if failed:
        print(f"\n{len(failed)}/{len(files)} rules failed.")
    return len(failed) == 0


def main():
    parser = argparse.ArgumentParser(description="Deploy detection rules to SIEM")
    parser.add_argument("--target", choices=["elastic", "splunk", "sentinel"], required=True)
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent.parent

    deployers = {"elastic": deploy_elastic, "splunk": deploy_splunk, "sentinel": deploy_sentinel}
    success = deployers[args.target](base_dir)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
