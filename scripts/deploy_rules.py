#!/usr/bin/env python3
"""Deploy detection rules to target SIEM platform."""

import argparse
import os
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import requests

DEFAULT_TIMEOUT = 30  # seconds
HTTPS_SCHEME = "https"


def _validate_url(url: str, *, allow_http: bool = False) -> str:
    """Validate a configured service base URL and return it without a trailing slash."""
    if not url or url != url.strip():
        raise ValueError("URL must be non-empty and contain no surrounding whitespace")

    parsed = urlsplit(url)
    allowed_schemes = ("http", HTTPS_SCHEME) if allow_http else (HTTPS_SCHEME,)
    if parsed.scheme not in allowed_schemes:
        expected = " or ".join(allowed_schemes)
        raise ValueError(f"URL must use {expected}")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("URL must include a host and must not include credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("URL must not include a query string or fragment")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc

    return url.rstrip("/")


def _request_error(error: requests.RequestException) -> str:
    """Return an error classification without exposing service response data."""
    return type(error).__name__


def deploy_elastic(base_dir: Path) -> bool:
    """Import Elastic/Kibana saved objects from NDJSON files."""
    allow_http = os.environ.get("ELASTIC_ALLOW_HTTP", "false").lower() == "true"
    url = _validate_url(os.environ["ELASTIC_URL"], allow_http=allow_http)
    token = os.environ["ELASTIC_TOKEN"]
    files = list((base_dir / "elastic").rglob("*.ndjson"))
    if not files:
        print("No .ndjson files found in elastic/")
        return True

    failed = []
    for rule_file in files:
        print(f"Importing: {rule_file.relative_to(base_dir)}")
        try:
            with rule_file.open("rb") as file_handle:
                with requests.post(
                    f"{url}/api/saved_objects/_import?overwrite=true",
                    headers={"kbn-xsrf": "true", "Authorization": f"ApiKey {token}"},
                    files={"file": (rule_file.name, file_handle, "application/x-ndjson")},
                    timeout=DEFAULT_TIMEOUT,
                ) as response:
                    if response.ok:
                        try:
                            success_count = response.json().get("successCount", 0)
                        except ValueError:
                            success_count = "unknown"
                        print(f"  ✓ Success ({success_count} objects)")
                    else:
                        print(f"  ✗ Failed ({response.status_code})")
                        failed.append(str(rule_file))
        except requests.RequestException as error:
            print(f"  ✗ Request error: {_request_error(error)}")
            failed.append(str(rule_file))

    if failed:
        print(f"\n{len(failed)}/{len(files)} rules failed.")
    return not failed


def deploy_splunk(base_dir: Path) -> bool:
    """Create or update Splunk saved searches from SPL files."""
    allow_http = os.environ.get("SPLUNK_ALLOW_HTTP", "false").lower() == "true"
    url = _validate_url(os.environ["SPLUNK_URL"], allow_http=allow_http)
    token = os.environ["SPLUNK_TOKEN"]
    # Verify TLS by default. Only disable for lab/dev with self-signed certs
    # via SPLUNK_VERIFY_TLS=false; production should use trusted certificates.
    ssl_verify = os.environ.get("SPLUNK_VERIFY_TLS", "true").lower() != "false"
    files = list((base_dir / "splunk").rglob("*.spl"))
    if not files:
        print("No .spl files found in splunk/")
        return True

    failed = []
    for rule_file in files:
        rule_name = rule_file.stem
        search_content = rule_file.read_text(encoding="utf-8").strip()
        print(f"Creating saved search: {rule_name}")
        try:
            with requests.post(
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
                verify=ssl_verify,
                timeout=DEFAULT_TIMEOUT,
            ) as response:
                if response.status_code == 409:
                    with requests.post(
                        f"{url}/servicesNS/admin/search/saved/searches/{rule_name}",
                        headers={"Authorization": f"Bearer {token}"},
                        data={"search": search_content},
                        verify=ssl_verify,
                        timeout=DEFAULT_TIMEOUT,
                    ) as update_response:
                        if update_response.ok:
                            print(f"  ✓ Success ({update_response.status_code})")
                        else:
                            print(f"  ✗ Failed ({update_response.status_code})")
                            failed.append(rule_name)
                elif response.ok:
                    print(f"  ✓ Success ({response.status_code})")
                else:
                    print(f"  ✗ Failed ({response.status_code})")
                    failed.append(rule_name)
        except requests.RequestException as error:
            print(f"  ✗ Request error: {_request_error(error)}")
            failed.append(rule_name)

    if failed:
        print(f"\n{len(failed)}/{len(files)} rules failed.")
    return not failed


def deploy_sentinel(base_dir: Path) -> bool:
    """Deploy KQL files as Microsoft Sentinel scheduled analytics rules."""
    tenant_id = os.environ["SENTINEL_TENANT_ID"]
    client_id = os.environ["SENTINEL_CLIENT_ID"]
    client_secret = os.environ["SENTINEL_CLIENT_SECRET"]
    workspace_id = os.environ["SENTINEL_WORKSPACE_ID"]

    try:
        with requests.post(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://management.azure.com/.default",
            },
            timeout=DEFAULT_TIMEOUT,
        ) as response:
            if not response.ok:
                print(f"Authentication failed ({response.status_code})")
                return False
            try:
                access_token = response.json()["access_token"]
            except (ValueError, KeyError):
                print("Authentication failed: invalid token response")
                return False
    except requests.RequestException as error:
        print(f"Authentication request error: {_request_error(error)}")
        return False

    files = list((base_dir / "microsoft-sentinel").rglob("*.kql"))
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
    for rule_file in files:
        rule_name = rule_file.stem.replace("_", " ")
        query = rule_file.read_text(encoding="utf-8").strip()
        rule_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, rule_file.name))
        print(f"Creating analytics rule: {rule_name}")
        try:
            with requests.put(
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
                timeout=DEFAULT_TIMEOUT,
            ) as response:
                if response.ok:
                    print(f"  ✓ Success ({response.status_code})")
                else:
                    print(f"  ✗ Failed ({response.status_code})")
                    failed.append(rule_name)
        except requests.RequestException as error:
            print(f"  ✗ Request error: {_request_error(error)}")
            failed.append(rule_name)

    if failed:
        print(f"\n{len(failed)}/{len(files)} rules failed.")
    return not failed


def main() -> None:
    parser = argparse.ArgumentParser(description="Deploy detection rules to SIEM")
    parser.add_argument("--target", choices=["elastic", "splunk", "sentinel"], required=True)
    args = parser.parse_args()

    deployers = {
        "elastic": deploy_elastic,
        "splunk": deploy_splunk,
        "sentinel": deploy_sentinel,
    }
    try:
        success = deployers[args.target](Path(__file__).resolve().parent.parent)
    except (KeyError, ValueError) as error:
        print(f"Deployment configuration error: {error}")
        success = False
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
