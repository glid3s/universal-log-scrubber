# Universal Log Scrubber Usage Guide

This guide walks through the normal local workflow for scrubbing logs before
they leave a secure environment.

## Recommended Workflow

1. Put raw logs in a local working folder that will not be uploaded.
2. Set a run salt using an environment variable or protected salt file.
3. Run a dry run with detection explanations for a small representative sample.
4. Run the scrubber against the full log set.
5. Review the leak-check result and any local-only detection report.
6. Upload only the scrubbed output files that passed review.
7. Keep the token map and salt private for local re-identification.

## Salt Handling

The salt controls deterministic token generation. Reuse the same salt only when
you intentionally need tokens to correlate across runs.

```powershell
$env:SCRUB_SALT = 'use-a-long-random-secret-value'

.\scripts\Run-UniversalScrubber_v4_8.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

You can also use `-SaltFile C:\secure\scrub_salt.txt`. Avoid `-Salt` for
repeatable production workflows because command history may retain it.

## Basic CSV Scrub

```powershell
.\scripts\Run-UniversalScrubber_v4_8.ps1 `
  -Path C:\logs\Security.evtx.csv `
  -WorkDir C:\scrubbed `
  -Profile WindowsEventCsv `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

## Recursive Folder Scrub

```powershell
.\scripts\Run-UniversalScrubber_v4_8.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -Include *.csv,*.log,*.evtx `
  -Recurse `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

## EVTX Conversion

EVTX files are converted to CSV before scrubbing. Version 4.8 streams conversion
output and shows progress so large logs do not look hung.

```powershell
.\scripts\Run-UniversalScrubber_v4_8.ps1 `
  -Path C:\logs\Security.evtx `
  -WorkDir C:\scrubbed `
  -SaltFromEnv SCRUB_SALT `
  -EvtxProgressMode Fast `
  -NonInteractive
```

Use `CountFirst` when you want true percentage progress and EventData/UserData
columns:

```powershell
.\scripts\Run-UniversalScrubber_v4_8.ps1 `
  -Path C:\logs\Security.evtx `
  -WorkDir C:\scrubbed `
  -SaltFromEnv SCRUB_SALT `
  -EvtxProgressMode CountFirst `
  -NonInteractive
```

## Token Maps

The token map is the private lookup table that lets local reviewers re-identify
tokens later. It must not be uploaded.

Use merge mode when adding logs to an existing map:

```powershell
.\scripts\Run-UniversalScrubber_v4_8.ps1 `
  -Path C:\more-logs `
  -WorkDir C:\scrubbed `
  -TokenMapCsv C:\scrubbed\scrub_token_map_DO_NOT_UPLOAD.csv `
  -TokenMapMode Merge `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

Use replace mode only when intentionally starting a new map:

```powershell
.\scripts\Run-UniversalScrubber_v4_8.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -TokenMapMode Replace `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

## Policy Modes

- `Balanced` is recommended for most secure-client log sharing.
- `Strict` scrubs more aggressively and may reduce readability.
- `Readable` preserves more known diagnostics and should be paired with local
  review.

```powershell
.\scripts\Run-UniversalScrubber_v4_8.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -ScrubPolicy Strict `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

## Reports

Detailed detection reports can contain original values or context. Treat them as
local-only.

```powershell
.\scripts\Run-UniversalScrubber_v4_8.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -FalsePositiveReport C:\scrubbed\detection_review_DO_NOT_UPLOAD.csv `
  -DetectionSummaryReport C:\scrubbed\detection_summary.csv `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

`DetectionSummaryReport` contains detector counts only and is safer to discuss
externally, but still review it before sharing.

## Seed Terms

Some sensitive terms are shapeless and cannot be inferred reliably, such as
project names, client names, vendor nicknames, or internal host prefixes. Add
them as seed terms.

```powershell
.\scripts\Run-UniversalScrubber_v4_8.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -SensitiveTerms Contoso,ProjectFalcon,legacy-host-prefix `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

## Restore Local Findings

Use restore only inside the secure environment with the private token map.

```powershell
Import-Module .\src\UniversalLogScrubber_v4_8.psm1 -Force

Restore-ScrubbedFile `
  -InputPath C:\analysis\findings_from_llm.csv `
  -TokenMapCsv C:\scrubbed\scrub_token_map_DO_NOT_UPLOAD.csv `
  -OutputPath C:\analysis\findings_reidentified.csv
```

## Safe Upload Checklist

- Leak check passed.
- Output file is scrubbed, not raw or intermediate.
- No `DO_NOT_UPLOAD` files are included.
- No token map, salt, manifest, or detailed detection review is included.
- A local reviewer checked representative rows and edge cases.
- The same salt/map strategy is documented for future correlation needs.

## Validation

Run the built-in self-test:

```powershell
Import-Module .\src\UniversalLogScrubber_v4_8.psm1 -Force
Invoke-ScrubSelfTest
```

Run a dry-run preview through the normal launcher:

```powershell
.\scripts\Run-UniversalScrubber_v4_8.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed-preview `
  -SaltFromEnv SCRUB_SALT `
  -DryRun `
  -ExplainDetections `
  -NonInteractive
```

Use synthetic or approved local logs for dry-run validation. The dry run previews
what would be detected and tokenized without writing scrubbed output files.
