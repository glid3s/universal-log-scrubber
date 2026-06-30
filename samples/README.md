# Sample Logs

This folder contains small, synthetic log sets for learning and smoke testing Universal Log Scrubber before using it on sensitive data.

The samples are intentionally fictional but varied. They include usernames, emails, hosts, private IPs, SIDs, GUIDs, tenant names, service accounts, API-key-like strings, URLs, JWT-shaped values, cloud IDs, VPN events, web requests, and free-text messages.

## Safety

These files are synthetic. They are safe to commit and safe to use for demos.

Do not replace them with real client logs. If you need a new fixture, fictionalize it first.

v4.15 also supports local enterprise exports and diagnostic reports such as
ServiceNow, Nexthink, SCCM/MECM, Intune CSV/XLSX exports, Intune Diagnostics
`.log`/`.txt`/`.reg`/`.html`/`.xml` reports, and DOCX/PPTX text extraction. Do
not add real examples of those files to this folder; use synthetic fixtures or
keep raw exports in a local ignored work directory.

## Quick sample smoke test

From the repository root:

```powershell
.\scripts\Test-SampleLogs.ps1
```

The script runs dry-run and real scrub passes against the sample files and verifies that each real scrub reports clean output.

## Manual examples

Dry-run an NDJSON app log:

```powershell
$env:SCRUB_SALT = 'sample-only-do-not-use-in-production'
.\scripts\Run-UniversalScrubber.ps1 `
  -Path .\samples\logs\app-auth.ndjson `
  -WorkDir .\samples\out\app-auth-preview `
  -Profile AppJson `
  -SaltFromEnv SCRUB_SALT `
  -SeedFile .\samples\sample-seeds.txt `
  -AllowlistFile .\samples\sample-allowlist.txt `
  -DryRun `
  -ExplainDetections `
  -NonInteractive
```

Build a profile from the gateway sample:

```powershell
.\scripts\Run-UniversalScrubber.ps1 `
  -BuildProfileFromSample `
  -Path .\samples\logs\gateway-kv.log `
  -WorkDir .\samples\generated-profile `
  -ProfileOut .\samples\generated-profile\gateway-profile.json `
  -ProfileReportOut .\samples\generated-profile\gateway-profile-report_DO_NOT_UPLOAD.md `
  -Force `
  -NonInteractive
```

Create a safe upload bundle from a sample run:

```powershell
$env:SCRUB_SALT = 'sample-only-do-not-use-in-production'
.\scripts\Run-UniversalScrubber.ps1 `
  -Path .\samples\logs\web-access.log `
  -WorkDir .\samples\out\web-access `
  -Profile WebAccess `
  -SaltFromEnv SCRUB_SALT `
  -SeedFile .\samples\sample-seeds.txt `
  -AllowlistFile .\samples\sample-allowlist.txt `
  -SafeBundleOut .\samples\out\web-access\safe-upload.zip `
  -Force `
  -NonInteractive
```

## Files

| File | Purpose |
|---|---|
| `logs/app-auth.ndjson` | Application JSON/NDJSON values, auth events, tokens, hosts, users. |
| `logs/cloud-audit.jsonl` | Cloud/audit-style activity with principals, resources, tenant names, regions. |
| `logs/gateway-kv.log` | key=value/logfmt style gateway and API events. |
| `logs/vpn-firewall.log` | VPN/firewall-style text events with identities, IPs, devices, and policy names. |
| `logs/web-access.log` | Web/proxy style logs with URLs, user agents, client IPs, status codes. |
| `logs/windows-event-sample.csv` | Windows event CSV-style rows with providers, SIDs, users, hosts, and messages. |
| `sample-seeds.txt` | Fictional shapeless terms that should be scrubbed. |
| `sample-allowlist.txt` | Public/diagnostic values that should stay readable. |

# v4.15 Sample Coverage

The committed `samples/logs` folder contains only synthetic fixtures. It now includes examples for:

- Application NDJSON and cloud audit JSONL.
- Sentinel-style incident/alert JSONL and EDR/XDR alert JSONL.
- ServiceNow, Nexthink, SCCM/MECM, Intune, and M365/identity CSV exports.
- Firewall/VPN syslog or key=value text and structured Windows Event CSV.
- Intune diagnostic `.reg`, `.html`, and `.xml` reports.

Run the public sample smoke test:

```powershell
.\scripts\Test-SampleLogs.ps1
```

Sample outputs are written under `samples/out/` and are ignored. Treat any token maps, salts, manifests, converted intermediates, and generated reports as local-only artifacts.
