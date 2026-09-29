# FileVantage Suppression Rule Rationale (Example)

> Sanitized example based on a real remediation. Hostnames, credentials, policy
> IDs, and organization-specific names have been removed or generalized.

## Rule Details

| Field | Value |
|-------|-------|
| **Rule Name** | Suppress `<app-config>` background changes |
| **Target Path** | `/opt/app/servers/*/config/<app-config>` |
| **Platform** | Linux |
| **Scope** | Global |

## Background

A long-running Java payment/application platform generates continuous FileVantage
(FIM) change events from its processes accessing a configuration file and the
associated transaction journal (`.jdb`) files. These events flood the FileVantage
Changes view with tens of thousands of benign records, making it hard to identify
legitimate security events.

## Problem Statement

- The Falcon FileVantage **inline** suppression workflow fails for these events due
  to a UI bug: the console's automatic query validation returns 0 results (caused by
  a very long command-line string), which grays out the "Create Suppression Rule"
  button.
- No results can be exported from the Changes tab for these entries.
- Workaround: create the suppression rule directly from the **Suppression rules
  tab → Create suppression rule**, bypassing the broken inline validation.

## Affected Hosts

Events were observed across production, cert, staging, dev, and test instances of
the application servers. (Specific hostnames omitted in this example — scope the
rule to your own host set.)

| Host (example) | Environment |
|----------------|-------------|
| `app-server-01` | PROD |
| `app-server-02` | PROD |
| `app-server-03` | CERT |
| `app-server-04` | STAGING |
| `app-server-05` | DEV / TEST |

## Process Details

- **Image:** `/usr/lib/jvm/<jdk>/bin/java`
- **Parent:** `/usr/bin/nohup`
- **Grandparent:** `/usr/bin/bash`
- **User:** dedicated service account (non-root)
- **Command Line:** long wrapper launching the application process with a
  `-config .../config/<app-config>` argument (1000+ characters)

## Event Details

- **Event Name:** `FileIntegrityMonitorRuleMatched` (Linux)
- **Object Access Types:** read/access and write/modify
- **Object Paths:** `/opt/app/servers/*/transactions/*.jdb`

(Policy IDs / rule group IDs omitted — these are environment-specific.)

## Risk Assessment

| Factor | Assessment |
|--------|-----------|
| **Process legitimacy** | Known application process running as a dedicated service account |
| **Activity type** | BerkeleyDB transaction journal writes — expected I/O for the workload |
| **Config file purpose** | Dependency-injection config, loaded once at JVM startup |
| **Threat signal** | None — operational noise from a known application |
| **EDR coverage** | Endpoint detection rules operate independently; suppression does not affect them |

## Data Retention Confirmation

**Verified via SIEM query:** raw `FileIntegrityMonitorRuleMatched` telemetry continues
to flow to the SIEM/log backend regardless of FileVantage UI suppression status.

**Key finding:** FileVantage suppression rules only hide events from the console's
Changes view. The raw sensor data is still ingested, retained, and queryable for
compliance and audit purposes.

## Decision

Create a **global suppression rule** targeting the config path on Linux to remove the
benign change records from the FileVantage unsuppressed view, while maintaining full
telemetry retention in the data backend for audit requirements.

## Method

Because the inline UI suppression is broken (0-results validation bug), create the
rule manually:

1. Navigate to **Endpoint Security → FileVantage → Suppression rules**
2. Click **Create suppression rule**
3. Fill in:
   - Rule Name: `Suppress <app-config> background changes`
   - Target Path: `/opt/app/servers/*/config/<app-config>`
   - Platform: Linux
4. Save
