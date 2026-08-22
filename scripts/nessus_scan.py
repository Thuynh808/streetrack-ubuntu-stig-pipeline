#!/usr/bin/env python3

import os
import sys
import argparse
import time
import requests
from dotenv import load_dotenv
from datetime import datetime

# ------------------------------------------------------------
# Load environment variables
# ------------------------------------------------------------

load_dotenv()

NESSUS_URL = os.getenv("NESSUS_URL")
NESSUS_ACCESS_KEY = os.getenv("NESSUS_ACCESS_KEY")
NESSUS_SECRET_KEY = os.getenv("NESSUS_SECRET_KEY")
NESSUS_POLICY_NAME = os.getenv("NESSUS_POLICY_NAME")
NESSUS_SCANNER_NAME = os.getenv("NESSUS_SCANNER_NAME")


# ------------------------------------------------------------
# Validate environment variables
# ------------------------------------------------------------

def validate_environment():
    required_vars = {
        "NESSUS_URL": NESSUS_URL,
        "NESSUS_ACCESS_KEY": NESSUS_ACCESS_KEY,
        "NESSUS_SECRET_KEY": NESSUS_SECRET_KEY,
        "NESSUS_POLICY_NAME": NESSUS_POLICY_NAME,
        "NESSUS_SCANNER_NAME": NESSUS_SCANNER_NAME,
    }

    missing = [
        name
        for name, value in required_vars.items()
        if not value
    ]

    if missing:
        print("[ERROR] Missing required environment variables:")

        for name in missing:
            print(f"  - {name}")

        sys.exit(1)


# ------------------------------------------------------------
# Tenable API headers
# ------------------------------------------------------------

HEADERS = {
    "X-ApiKeys": (
        f"accessKey={NESSUS_ACCESS_KEY};"
        f"secretKey={NESSUS_SECRET_KEY}"
    ),
    "Accept": "application/json",
    "User-Agent": "Streetrack-STIG-Pipeline/1.0",
}


# ------------------------------------------------------------
# API request helper
# ------------------------------------------------------------

def api_get(endpoint):
    url = f"{NESSUS_URL.rstrip('/')}{endpoint}"

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=30,
        )

        response.raise_for_status()
        return response

    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Unable to connect to {NESSUS_URL}")
        sys.exit(1)

    except requests.exceptions.Timeout:
        print("[ERROR] Tenable API request timed out.")
        sys.exit(1)

    except requests.exceptions.HTTPError as error:
        print(f"[ERROR] Tenable API returned: {error}")

        try:
            print(response.json())
        except ValueError:
            print(response.text)

        sys.exit(1)

    except requests.exceptions.RequestException as error:
        print(f"[ERROR] API request failed: {error}")
        sys.exit(1)


# ------------------------------------------------------------
# API POST request helper
# ------------------------------------------------------------

def api_post(endpoint, payload):
    url = f"{NESSUS_URL.rstrip('/')}{endpoint}"

    try:
        response = requests.post(
            url,
            headers=HEADERS,
            json=payload,
            timeout=30,
        )

        response.raise_for_status()
        return response

    except requests.exceptions.RequestException as error:
        print(f"[ERROR] API request failed: {error}")

        if "response" in locals():
            try:
                print(response.json())
            except ValueError:
                print(response.text)

        sys.exit(1)


# ------------------------------------------------------------
# Find policy / scan template
# ------------------------------------------------------------

def get_policy():
    print(f"[INFO] Looking for scan template: {NESSUS_POLICY_NAME}")

    response = api_get("/policies")
    data = response.json()

    policies = data.get("policies", [])

    for policy in policies:
        if policy.get("name") == NESSUS_POLICY_NAME:
            return policy

    print(
        f"[ERROR] Scan template not found: "
        f"{NESSUS_POLICY_NAME}"
    )
    sys.exit(1)

def get_policy_details(policy_id):
    print(f"[INFO] Retrieving policy details for ID: {policy_id}")

    response = api_get(f"/policies/{policy_id}")
    return response.json()


# ------------------------------------------------------------
# Find internal scanner
# ------------------------------------------------------------

def get_scanner():
    print(f"[INFO] Looking for scanner: {NESSUS_SCANNER_NAME}")

    response = api_get("/scanners")
    data = response.json()

    scanners = data.get("scanners", [])

    for scanner in scanners:
        if scanner.get("name") == NESSUS_SCANNER_NAME:
            return scanner

    print(f"[ERROR] Scanner not found: {NESSUS_SCANNER_NAME}")
    sys.exit(1)


# ------------------------------------------------------------
# Create scan from existing policy
# ------------------------------------------------------------

def create_scan(policy, policy_details, scanner, target, mode):
    policy_id = policy["id"]
    policy_uuid = policy_details["uuid"]
    scanner_id = scanner["id"]

    timestamp = datetime.now().strftime("%Y-%m-%d-%H%M")
    scan_name = f"Streetrack-Ubuntu-STIG-{mode}-{timestamp}"

    print(f"[INFO] Creating {mode} scan")
    print(f"[INFO] Scan name: {scan_name}")
    print(f"[INFO] Target: {target}")
    print(f"[INFO] Scanner: {scanner.get('name')}")
    print(f"[INFO] Scanner ID: {scanner_id}")

    payload = {
        "uuid": policy_uuid,
        "settings": {
            "name": scan_name,
            "description": (
                f"Streetrack Ubuntu 24.04 STIG {mode} assessment"
            ),
            "text_targets": target,
            "policy_id": policy_id,
            "scanner_id": scanner_id,
        },
    }

    response = api_post("/scans", payload)

    return response.json(), scan_name


# ------------------------------------------------------------
# Launch scan
# ------------------------------------------------------------

def launch_scan(scan_id):
    print(f"[INFO] Launching scan ID: {scan_id}")

    response = api_post(
        f"/scans/{scan_id}/launch",
        {}
    )

    return response.json()


# ------------------------------------------------------------
# Wait for scan to complete
# ------------------------------------------------------------

def wait_for_scan(
    scan_id,
    poll_interval=30,
    max_poll_errors=5,
):
    print()
    print(f"[INFO] Waiting for scan ID {scan_id} to complete")

    consecutive_errors = 0

    while True:
        try:
            url = f"{NESSUS_URL.rstrip('/')}/scans/{scan_id}"

            response = requests.get(
                url,
                headers=HEADERS,
                timeout=30,
            )

            response.raise_for_status()
            data = response.json()

            status = (
                data.get("info", {})
                .get("status", "unknown")
                .lower()
            )

            consecutive_errors = 0

            print(f"[INFO] Scan status: {status}")

            if status == "completed":
                print("[OK] Scan completed successfully")
                return data

            if status in {
                "canceled",
                "aborted",
                "stopped",
                "failed",
            }:
                print(
                    f"[ERROR] Scan ended unexpectedly "
                    f"with status: {status}"
                )
                sys.exit(1)

        except requests.exceptions.RequestException as error:
            consecutive_errors += 1

            print(
                f"[WARNING] Unable to retrieve scan status "
                f"({consecutive_errors}/{max_poll_errors})"
            )
            print(f"[WARNING] {error}")

            if consecutive_errors >= max_poll_errors:
                print(
                    "[ERROR] Maximum consecutive polling "
                    "errors reached."
                )
                sys.exit(1)

        time.sleep(poll_interval)


# ------------------------------------------------------------
# Request compliance HTML export
# ------------------------------------------------------------

def request_html_export(scan_id):
    print()
    print(
        f"[INFO] Requesting compliance HTML export "
        f"for scan ID {scan_id}"
    )

    response = api_post(
        f"/scans/{scan_id}/export",
        {
            "format": "html",
            "chapters": "compliance_exec;compliance",
        },
    )

    data = response.json()

    file_id = data.get("file")

    if not file_id:
        print("[ERROR] Export request did not return a file ID")
        print(data)
        sys.exit(1)

    print("[OK] Compliance HTML export requested")
    print(f"Export file ID: {file_id}")

    return file_id

# ------------------------------------------------------------
# Wait for HTML export to become ready
# ------------------------------------------------------------

def wait_for_export(
    scan_id,
    file_id,
    poll_interval=5,
):
    print()
    print("[INFO] Waiting for HTML export to become ready")

    while True:
        response = api_get(
            f"/scans/{scan_id}/export/{file_id}/status"
        )

        data = response.json()

        status = data.get(
            "status",
            "unknown",
        ).lower()

        print(f"[INFO] Export status: {status}")

        if status == "ready":
            print("[OK] HTML export is ready")
            return

        if status in {
            "error",
            "failed",
            "canceled",
        }:
            print(
                f"[ERROR] Export ended unexpectedly "
                f"with status: {status}"
            )
            sys.exit(1)

        time.sleep(poll_interval)

# ------------------------------------------------------------
# Download compliance HTML report
# ------------------------------------------------------------

def download_html_export(
    scan_id,
    file_id,
    mode,
    scan_name,
):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)

    output_dir = os.path.join(
        project_root,
        "evidence",
        mode,
    )

    os.makedirs(
        output_dir,
        exist_ok=True,
    )

    filename = f"{scan_name}-report.html"

    output_path = os.path.join(
        output_dir,
        filename,
    )

    url = (
        f"{NESSUS_URL.rstrip('/')}"
        f"/scans/{scan_id}"
        f"/export/{file_id}/download"
    )

    print()
    print("[INFO] Downloading compliance HTML report")

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=60,
        )

        response.raise_for_status()

    except requests.exceptions.RequestException as error:
        print(
            f"[ERROR] Failed to download HTML report: "
            f"{error}"
        )
        sys.exit(1)

    with open(output_path, "wb") as report_file:
        report_file.write(response.content)

    print("[OK] Compliance HTML report downloaded")
    print(f"[OK] Saved to: {output_path}")

    return output_path


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Streetrack Ubuntu 24.04 STIG assessment"
    )

    parser.add_argument(
        "mode",
        choices=["baseline", "verification"],
        help="Assessment stage",
    )

    parser.add_argument(
        "--target",
        required=True,
        help="IP address or hostname of the Ubuntu target",
    )

    args = parser.parse_args()

    validate_environment()

    print("=" * 60)
    print("Streetrack Ubuntu 24.04 STIG Compliance Pipeline")
    print("=" * 60)

    policy = get_policy()

    print()
    print("[OK] Tenable scan template found")
    print(f"Name: {policy.get('name')}")
    print(f"ID:   {policy.get('id')}")

    print()

    policy_details = get_policy_details(policy["id"])

    print("[OK] Policy details retrieved")
    print(f"Policy UUID: {policy_details.get('uuid')}")

    print()
    
    scanner = get_scanner() 

    print()
    print("[OK] Internal scanner found")
    print(f"Name: {scanner.get('name')}")
    print(f"ID:   {scanner.get('id')}")   

    scan, scan_name = create_scan(
        policy,
        policy_details,
        scanner,
        args.target,
        args.mode,
    )

    print()
    print("[OK] Scan configuration created")

    if "scan" not in scan:
        print("[ERROR] Unexpected response while creating scan")
        print(scan)
        sys.exit(1)

    scan_id = scan["scan"].get("id")

    print(f"Scan ID: {scan_id}")

    print()

    launch_result = launch_scan(scan_id)

    print("[OK] Scan launch request accepted")

    if "scan_uuid" in launch_result:
        print(f"Scan UUID: {launch_result.get('scan_uuid')}")
    
    wait_for_scan(scan_id)

    file_id = request_html_export(scan_id)

    wait_for_export(
        scan_id,
        file_id,
    )

    report_file = download_html_export(
        scan_id,
        file_id,
        args.mode,
        scan_name,
    )

    print()
    print("=" * 60)
    print("[OK] Streetrack STIG assessment complete")
    print(f"[OK] Assessment stage: {args.mode}")
    print(f"[OK] Scan ID: {scan_id}")
    print(f"[OK] Report: {report_file}")
    print("=" * 60)

if __name__ == "__main__":
    main()
