#!/usr/bin/env python3
"""
Bulk FileVantage change-record remediation for the "long command line / 0 results" UI bug.

Scans CrowdStrike Falcon FileVantage change records for a configurable set of hosts,
matches noisy records by their entity_path, and bulk-suppresses (or purges) them via
the API when the console workflow is non-functional.

Credentials are read from environment variables — nothing sensitive is hardcoded:

    export FALCON_CLIENT_ID=...
    export FALCON_CLIENT_SECRET=...
    export FALCON_BASE_URL=https://api.crowdstrike.com   # adjust for your cloud

Host Agent IDs (AIDs) and the match term are supplied via env vars / constants below.
This is a sanitized reference implementation intended as a portfolio example.
"""

import os
import sys
import time
import warnings

import requests

warnings.filterwarnings("ignore", category=UserWarning, module="urllib3")

# --- Configuration (no secrets in source) ---------------------------------
CLIENT_ID = os.environ.get("FALCON_CLIENT_ID")
CLIENT_SECRET = os.environ.get("FALCON_CLIENT_SECRET")
BASE_URL = os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com")

# The substring to match against each record's entity_path (the file being changed).
# Set to the noisy config/file name you are clearing, e.g. via env var.
MATCH_TERM = os.environ.get("FIM_MATCH_TERM", "example.config").lower()

# Comma-separated list of host Agent IDs (AIDs) to scope the scan.
# e.g. export FIM_AIDS="aaaa...,bbbb...,cccc..."
AIDS = [a.strip() for a in os.environ.get("FIM_AIDS", "").split(",") if a.strip()]

# "suppress" to hide from the console Changes view, or "purge" to delete.
OPERATION = os.environ.get("FIM_OPERATION", "suppress")

QUERY_LIMIT = 500          # records per query page
OFFSET_CAP = 10_000        # FileVantage hard offset cap
BATCH_SIZE = 100           # max IDs per hydrate / action call
RATE_DELAY = 3.0           # seconds between action calls (avoids 409 / resets)


def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def authenticate():
    if not CLIENT_ID or not CLIENT_SECRET:
        die("FALCON_CLIENT_ID and FALCON_CLIENT_SECRET must be set in the environment.")
    res = requests.post(
        f"{BASE_URL}/oauth2/token",
        data={"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    # NOTE: the token endpoint returns HTTP 201 (not 200) on success.
    if res.status_code not in (200, 201):
        die(f"Authentication failed: {res.status_code} {res.text}")
    token = res.json().get("access_token")
    if not token:
        die(f"No access_token in auth response: {res.text}")
    return {"Authorization": f"Bearer {token}"}


def scan_matching_ids(headers):
    """Page through changes for the scoped AIDs and collect IDs whose entity_path matches."""
    if not AIDS:
        die("No host AIDs supplied. Set FIM_AIDS to a comma-separated list of Agent IDs.")

    aid_filter = "aid:[" + ",".join(f"'{aid}'" for aid in AIDS) + "]"
    matched = []
    offset = 0

    print(f"Scanning FileVantage changes for {len(AIDS)} host(s), match term '{MATCH_TERM}'...")
    while offset < OFFSET_CAP:
        q = requests.get(
            f"{BASE_URL}/filevantage/queries/changes/v2",
            headers=headers,
            params={"limit": QUERY_LIMIT, "offset": offset, "filter": aid_filter},
        )
        if q.status_code != 200:
            print(f"  query failed: {q.status_code} {q.text}", file=sys.stderr)
            break

        data = q.json()
        ids = data.get("resources", [])
        if not ids:
            break

        # Hydrate in batches to inspect entity_path (cannot filter on it server-side).
        for i in range(0, len(ids), BATCH_SIZE):
            chunk = ids[i:i + BATCH_SIZE]
            ent = requests.get(
                f"{BASE_URL}/filevantage/entities/changes/v2",
                headers=headers,
                params={"ids": chunk},
            )
            if ent.status_code == 200:
                for change in ent.json().get("resources", []):
                    path = str(change.get("entity_path", "")).lower()
                    if MATCH_TERM in path:
                        matched.append(change.get("id"))

        offset += QUERY_LIMIT
        total = data.get("meta", {}).get("pagination", {}).get("total", offset + 1)
        print(f"  scanned {offset} events (matched {len(matched)} so far)")
        if offset >= total:
            break

    return matched


def apply_action(headers, ids):
    """Suppress or purge the matched records in batches, respecting rate limits."""
    if not ids:
        print("No matching records found. "
              "Verify the records haven't aged out of query retention.")
        return

    print(f"\nApplying '{OPERATION}' to {len(ids)} record(s)...")
    for i in range(0, len(ids), BATCH_SIZE):
        chunk = ids[i:i + BATCH_SIZE]
        # NOTE: the payload key MUST be "change_ids", not "ids".
        # The API silently accepts "ids" (returns 202) but does nothing.
        payload = [{
            "change_ids": chunk,
            "operation": OPERATION,
            "comment": f"Bulk {OPERATION} of FIM noise backlog",
        }]
        res = requests.post(
            f"{BASE_URL}/filevantage/entities/actions/v1",
            headers={**headers, "Content-Type": "application/json"},
            json=payload,
        )
        batch_no = (i // BATCH_SIZE) + 1
        if res.status_code in (200, 201, 202):
            print(f"  batch {batch_no}: {len(chunk)} record(s) ok")
        else:
            print(f"  batch {batch_no} failed: {res.status_code} {res.text}", file=sys.stderr)
        time.sleep(RATE_DELAY)
    print("\nDone.")


def main():
    headers = authenticate()
    ids = scan_matching_ids(headers)
    apply_action(headers, ids)


if __name__ == "__main__":
    main()
