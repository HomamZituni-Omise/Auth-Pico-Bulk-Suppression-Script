# FileVantage Stale Alert Bulk Suppression

Tooling for remediating a CrowdStrike Falcon **FileVantage** (File Integrity
Monitoring) failure mode: grouped **Changes**-view entries with very long
`command_line` strings display alert counts (hundreds to thousands per group)
but return **"0 results"** when clicked — making suppression or deletion through
the console impossible.

Because the console workflow is broken for these records, remediation has to go
through the FileVantage API. This repo holds a resilient script that does that.

## Contents

| File | What it is |
|------|-----------|
| [`CASE-STUDY.md`](CASE-STUDY.md) | Full incident write-up: problem, root-cause analysis, three-layer fix, API constraints, lessons learned. |
| [`suppression-rule-rationale.md`](suppression-rule-rationale.md) | Decision record for the suppression rule — risk assessment and method. |
| [`bulk_suppress_fim.py`](bulk_suppress_fim.py) | Reference Python script: time-window scan, entity_path matching, batched suppress/purge via the API. |

## When this applies

The signature of the bug: a Changes-view group is keyed on a very long
`command_line`, the group shows a non-zero count, but clicking it returns
0 results. A common trigger is a noisy process (a long Java command line, a
build toolchain, etc.) repeatedly writing transient files under a monitored
path, where the noisy term appears only in the `command_line` and not in the
`entity_path` (the file actually being changed).

If a command-line grouped alert set shows a count but opens to 0 results, treat
it as this bug and go straight to the API instead of the console.

## What the script does

- Authenticates to the CrowdStrike API (OAuth).
- Scans records in **12-hour time windows** to work around the 10,000 offset cap.
- Hydrates each record to inspect `entity_path` / `command_line`.
- Matches on a configurable noise term (`MATCH_TERM`).
- Suppresses in batches of 100 using the correct `change_ids` payload.
- Is **idempotent** — already-suppressed records are skipped on re-run.

## Usage

1. Provide CrowdStrike API credentials via environment variables (do **not**
   hardcode them):

   ```bash
   export FALCON_CLIENT_ID=...
   export FALCON_CLIENT_SECRET=...
   export FALCON_BASE_URL=https://api.crowdstrike.com   # adjust for your cloud
   ```

2. Set the match/scope parameters (at the top of the script or via args):

   - `MATCH_TERM` — the noise term to match.
   - Host filter — restrict to the affected hosts.
   - Date window — start/end of the range to scan.

3. Run:

   ```bash
   python bulk_suppress.py
   ```

The script logs each window scanned, records matched, and batches suppressed.
Re-running is safe.

## API Constraints (discovered the hard way)

| Constraint | Detail |
|------------|--------|
| Suppress payload key | Must be `change_ids`, **not** `ids`. Wrong key returns 202 but silently does nothing. |
| Max IDs per suppress call | 100 |
| Offset pagination cap | 10,000 (HTTP 400 beyond this) — use time-window filters. |
| Valid FQL filter fields | `action_timestamp`, `ingestion_timestamp`, `host.name`. **Not** `entity_path`, `command_line`, `is_suppressed`; `severity` errors. |
| Rate limiting | ~3s delay between suppress calls; faster triggers 409 / resets. |
| 409 Conflict | Prior action still processing — wait and retry. |
| OAuth token response | Returns HTTP **201**, not 200 — accept both. |

## Rule fixes (defense in depth)

Suppressing the historical backlog only clears what already exists. To stop new
alerts and catch stragglers:

- **Policy rule (source exclusion):** exclude the specific transient files and
  processes generating the noise, so no new alerts are created. Scope exclusions
  as narrowly as possible.
- **Suppression rule matching:** suppression rules match the Object Name against
  the `entity_path` (the file being changed), **not** the `command_line`. A rule
  written against a command-line string will never fire. Match on the file path,
  or use a broad Object Name as a safety net.

Keep meaningful changes — config files, binaries, keys, permission changes under
monitored paths — in scope so they still alert.

## Notes

Suppression only hides events from the console Changes view; the underlying
telemetry still flows to your SIEM, so audit trails are preserved. EDR detection
operates independently and is unaffected by FIM suppression or rule exclusions.
