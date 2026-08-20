#!/usr/bin/env python3

import os
import sys
import argparse

import requests
from dotenv import load_dotenv


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

    scan_name = f"Streetrack-Ubuntu-STIG-{mode}"

    print(f"[INFO] Creating {mode} scan")
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

    return response.json()


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

    scan = create_scan(
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

if __name__ == "__main__":
    main()
