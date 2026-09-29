# Case Study: FileVantage Stale Alert Remediation

> Sanitized example based on a real incident. Hostnames, ticket numbers,
> credentials, policy IDs, and organization-specific names have been removed
> or generalized. Written as a portfolio piece.

**Platform:** CrowdStrike Falcon FileVantage (File Integrity Monitoring)

## Problem Statement

The FileVantage **Changes** view was flooded with thousands of file-integrity
change alerts from a set of application/payment servers. Alerts were grouped by
command line in the UI sidebar, showing counts of 900–1,100+ per group across
multiple server instances.

**Critical UI Bug:** clicking into any grouped entry returned "0 results / No
results found" — making it impossible to select, suppress, or delete the records
through the normal console workflow. The standard inline suppression workflow was
completely non-functional for these records.

**Root cause of the UI bug:** the extremely long Java `command_line` string on the
process records (1000+ characters), combined with stale group index entries that
don't resolve against the active filter combination.

## Investigation & Root Cause Analysis

**Step 1 — Confirm the UI bug.** In the Changes view, grouped by Command Line,
the sidebar showed entries with counts of 700–1,100 each, but clicking any of them
displayed "No results found." Bulk actions (Suppress, Delete) were impossible via
the UI.

**Step 2 — Confirm data exists via API.** Key discovery: the `entity_path` (the
file actually being monitored) is a `.jdb` transaction file — not the config file
named in the group. The config-file name only appears in the `command_line` as an
argument to the Java process.

**Step 3 — Understand why the suppression rule failed.** The existing rule matched
`Object Name: Include only <config-file>`. This never matched, because the Object
Name filter applies to the `entity_path` (the `.jdb` file being changed), not the
command line.

**Step 4 — Discover the correct API payload.** The critical breakthrough: the API
accepts a payload keyed on `"ids"` without error (returns 202) but silently ignores
it. The correct key is `"change_ids"`. This single-field difference cost hours of
debugging.

**Step 5 — Verify.** A test call with the correct `change_ids` payload returned
202 Accepted; records confirmed `is_suppressed: True` seconds later.

**Step 6 — Discover pagination limits.** The FileVantage query endpoint has a hard
offset cap of 10,000. With hundreds of thousands of records to scan, offset-based
pagination alone cannot reach all records. Solution: **time-window pagination** —
divide the range into 12-hour windows, each under 10k records, and page within each.

## Solution: Three-Layer Approach

**Layer 1 — API script (clear the backlog).** A resilient Python script authenticates,
scans each time window, hydrates records to inspect `entity_path`/`command_line`,
matches on the noise term, and suppresses in batches of 100 with the `change_ids`
payload. Idempotent — skips already-suppressed records on re-run.

**Layer 2 — Policy rule update (stop new alerts).** Update the monitoring policy to
exclude the transient files (`.jdb`) and the noisy application/Java processes at the
source, so no new alerts are generated. Scope exclusions as narrowly as possible.

**Layer 3 — Suppression rule fix (safety net).** The original rule matched Object
Name against the config-file name, which never fired (Object Name matches the
`entity_path`, a `.jdb` file). Fix: set Object Name to "Include all" under the
monitored path so anything slipping through auto-suppresses.

### Security justification for the `.jdb` exclusion

The `.jdb` files are BerkeleyDB write-ahead transaction journals managed internally
by the application engine. There is no realistic attack scenario targeting these
ephemeral files. An attacker would target config files, application binaries, JARs,
or SSH keys/certs — all still monitored. Raw telemetry for `.jdb` writes still flows
to the SIEM for audit trails.

## API Constraints Discovered

| Constraint | Detail |
|------------|--------|
| Max IDs per suppress call | 100 |
| Offset pagination cap | 10,000 (HTTP 400 beyond this) |
| Rate limiting | ~3-second delay required between action calls |
| 409 Conflict | Returned when a prior action is still processing — wait and retry |
| No `entity_path` FQL filter | Must hydrate each record and inspect locally |
| Auth response code | Returns HTTP 201 (not 200) — accept both |
| Payload key | Must use `change_ids`, not `ids` — wrong key silently accepted but ignored |

## Results (illustrative)

| Metric | Value |
|--------|-------|
| Total records scanned | ~480,000 |
| Noise records identified | ~20,000 |
| Successfully suppressed | ~20,000 |
| Errors | 0 |
| Runtime | ~55 minutes |

## Compliance Notes

- Raw FIM telemetry continues to flow to the SIEM/log backend regardless of
  suppression. Suppression only hides events from the console Changes view; audit
  requirements remain satisfied.
- EDR detection operates independently — suppression and rule exclusions do not
  affect it.
- Meaningful changes (config files, binaries, JARs, keys, permission changes under
  the monitored path) still generate alerts.

## Lessons Learned

1. **FileVantage UI has a bug with long command lines** — grouped entries show
   counts but return 0 results when clicked. The only workaround is API-based
   suppression.
2. **The API payload key is `change_ids`, not `ids`** — the endpoint accepts the
   wrong key silently (202) but does nothing.
3. **Offset pagination caps at 10,000** — use time-window filters to page through
   large datasets.
4. **Suppression rules match on `entity_path` (the file), not `command_line`** —
   knowing which field a rule matches against is critical.
5. **Rate limits require multi-second delays** — faster calls cause 409 conflicts
   or connection resets.
6. **The OAuth token endpoint returns HTTP 201, not 200** — scripts checking for
   exactly 200 will fail authentication.

## Reusable Handling Pattern

The same failure mode recurs whenever a very long command line is grouped in the
Changes UI (e.g., build toolchains like .NET SDK / SonarScanner running in
containers). The signature is identical: the group shows a count but opens to
0 results.

1. If a command-line grouped alert set shows counts but opens to 0 results, treat it
   as the long-command-line UI bug and stop trying to clear it through the console.
2. Use the API (or SIEM) to identify the real `entity_path`; don't rely only on the
   grouped `command_line` label.
3. Exclude the transient file path at the source rule when it is safe to do so.
   Avoid excluding general-purpose runtimes (e.g., `dotnet`, `java`) by process
   alone — that creates a living-off-the-land blind spot.
4. Bulk-suppress the historical backlog with the script, adjusting the match term,
   host filters, and date windows for the affected case.
