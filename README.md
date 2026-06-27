# Universal Log Scrubber

Universal Log Scrubber is a local-first PowerShell tool for preparing logs from
secure environments before they are shared with external analysis tools,
including LLMs. It replaces sensitive values with deterministic HMAC tokens so
events can still be correlated without exposing the original identifiers.

The tool is designed for Windows event logs, CSV exports, IIS/W3C-style logs,
and mixed diagnostic text. Version 4.8 adds safer token-map handling, EVTX
conversion progress, better Windows account detection, and broader offline
secret detection.

## Safety First

Never upload token maps, salts, detailed detection review reports, raw logs, or
generated manifests from sensitive runs. Only upload scrubbed outputs after the
leak check passes and a local reviewer approves the result.

Files named like these are private artifacts:

- `scrub_token_map_DO_NOT_UPLOAD.csv`
- `*_DO_NOT_UPLOAD.csv`
- `scrub_run_manifest.json`
- local salt files
- raw `.evtx`, `.csv`, `.log`, or exported client logs

## Quick Start

Open PowerShell in the repository root:

```powershell
Import-Module .\src\UniversalLogScrubber_v4_8.psm1 -Force
Invoke-ScrubSelfTest

.\scripts\Run-UniversalScrubber_v4_8.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -SaltFromEnv SCRUB_SALT `
  -Profile WindowsEventCsv `
  -NonInteractive
```

For noninteractive use, provide one of `-Salt`, `-SaltFromEnv`, or `-SaltFile`.
Prefer `-SaltFromEnv` or `-SaltFile` so the salt is not left in command history.

## What Gets Scrubbed

- Windows accounts, domains, workstation names, hostnames, IPs, SIDs, GUIDs,
  emails, URLs, DNS names, X.500-style names, and common file/path identifiers.
- Label-aware Windows Event message fields such as `Account Name`,
  `Account Domain`, `User Name`, `Service Name`, `Workstation Name`,
  `Source Network Address`, and `Client Address`.
- Offline secret patterns including bearer/basic auth values, password and key
  fields, connection strings, PEM private keys, and common provider token forms.

Diagnostic/public values such as loopback IPs, all-zero GUIDs, known public
Microsoft domains, and common Windows built-in accounts are preserved where that
is safer and more readable.

## v4.8 Highlights

- `-TokenMapMode Merge|Replace`, with merge as the safer default for discovery.
- Atomic token-map writes with backups and metadata columns.
- Collision-safe output names when two source files share a basename.
- Streaming EVTX-to-CSV conversion with progress updates.
- Optional `-EvtxProgressMode CountFirst` for true percentage progress and
  EventData/UserData extraction.
- Safe counts-only detection summary reports via `-DetectionSummaryReport`.
- Default HMAC token length raised to 24 hex characters for new runs.

## Repository Layout

```text
src/      PowerShell module
scripts/  runnable launcher
docs/     security and operational notes
```

## Validation

```powershell
Import-Module .\src\UniversalLogScrubber_v4_8.psm1 -Force
Invoke-ScrubSelfTest

.\scripts\Run-UniversalScrubber_v4_8.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed-preview `
  -SaltFromEnv SCRUB_SALT `
  -DryRun `
  -ExplainDetections `
  -NonInteractive
```

Use dry runs on synthetic or approved local logs only. Dry runs preview
detections without writing scrubbed output files.

## Documentation

See [USAGE.md](USAGE.md) for detailed workflows, examples, policy modes, token
map handling, EVTX conversion guidance, and safe-upload checklists.
