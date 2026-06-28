# Sample Logs

This folder contains small, synthetic log sets for learning and smoke testing Universal Log Scrubber before using it on sensitive data.

The samples are intentionally fictional but varied. They include usernames, emails, hosts, private IPs, SIDs, GUIDs, tenant names, service accounts, API-key-like strings, URLs, JWT-shaped values, cloud IDs, VPN events, web requests, and free-text messages.

## Safety

These files are synthetic. They are safe to commit and safe to use for demos.

Do not replace them with real client logs. If you need a new fixture, fictionalize it first.

External public corpora downloaded through v4.13 tools belong in
`samples/external-corpora/` by default. That folder is ignored by git because
public corpora may be raw, unsanitized, realistic, offensive, or
license-restricted.

## Quick sample smoke test

From the repository root:

```powershell
.\scripts\Test-SampleLogs.ps1
```

The script runs dry-run and real scrub passes against the sample files and verifies that each real scrub reports clean output.

## Optional external corpus catalog

List curated public corpus entries:

```powershell
.\scripts\Get-SampleLogs.ps1
```

Save a small direct-download corpus sample after reviewing source warnings:

```powershell
.\scripts\Get-SampleLogs.ps1 -Name Loghub-Apache -AcceptRisk
```

Run local recommendation and dry-run smoke tests over downloaded corpora:

```powershell
Invoke-ExternalCorpusSmokeTest `
  -CorpusRoot .\samples\external-corpora `
  -Recurse `
  -UseRecommendations `
  -DryRunOnly `
  -Salt "preview-only" `
  -NonInteractive
```

## Manual examples

Dry-run an NDJSON app log:

```powershell
$env:SCRUB_SALT = 'sample-only-do-not-use-in-production'
.\scripts\Run-UniversalScrubber_v4_13.ps1 `
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
.\scripts\Run-UniversalScrubber_v4_13.ps1 `
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
.\scripts\Run-UniversalScrubber_v4_13.ps1 `
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

