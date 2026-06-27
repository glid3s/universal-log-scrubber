# Universal Log Scrubber

Universal Log Scrubber is a local-first PowerShell tool for preparing logs from
secure environments before they are shared with external analysis tools,
including LLMs. It replaces sensitive values with deterministic HMAC tokens so
events can still be correlated without exposing the original identifiers.

It works offline against Windows Event exports, EVTX files, CSV/TSV/PSV,
JSON/NDJSON, IIS/W3C, web access/proxy logs, key=value/logfmt/CEF-style logs,
syslog, and mixed diagnostic text. Version 4.11 adds local log-format
recommendations, safer first-run guidance, and optional automatic profile
selection for uniform folders.

## Safety First

Never upload token maps, salts, detailed detection review reports, raw logs, or
generated manifests from sensitive runs. Only upload scrubbed outputs after the
leak check passes and a local reviewer approves the result.

Private artifacts include:

- `scrub_token_map_DO_NOT_UPLOAD.csv`
- `*_DO_NOT_UPLOAD.csv`
- `profile_build_report_DO_NOT_UPLOAD.md`
- `scrub_run_manifest.json`
- local salt files
- detailed detection review reports
- raw `.evtx`, `.csv`, `.log`, `.json`, `.xlsx`, or exported client logs

## Quick Start

Open PowerShell in the repository root:

```powershell
Import-Module .\src\UniversalLogScrubber_v4_11.psm1 -Force
Invoke-ScrubSelfTest

.\scripts\Run-UniversalScrubber_v4_11.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed-preview `
  -SaltFromEnv SCRUB_SALT `
  -Profile Generic `
  -DryRun `
  -ExplainDetections `
  -NonInteractive
```

For noninteractive use, provide one of `-Salt`, `-SaltFromEnv`, or `-SaltFile`.
Prefer `-SaltFromEnv` or `-SaltFile` so the salt is not left in command history.

## Local Recommendations

Use recommendations when you are not sure which profile fits a folder. These
modes read only small local samples. They do not require a salt, scrub files,
create token maps, write reports, or build upload bundles.

```powershell
Test-LogFormat -Path .\logs -Recurse

Invoke-UniversalScrubber -Path .\logs -RecommendOnly

Invoke-UniversalScrubber -Path .\logs -SafeFirstRun

Invoke-UniversalScrubber `
  -Path .\some.jsonl `
  -AutoProfile `
  -DryRun `
  -Salt "preview-only" `
  -MapSource Discover `
  -NonInteractive
```

`-AutoProfile` chooses a profile only when every selected file confidently
recommends the same built-in profile. Mixed folders should be split by type or
run with `-Profile` explicitly.

## Build A Profile From A Sample

When the built-in profiles are not specific enough, point the tool at a local
sample. It will create an editable BYOP profile without storing raw sample
values in the profile.

```powershell
.\scripts\Run-UniversalScrubber_v4_11.ps1 `
  -BuildProfileFromSample `
  -Path C:\logs\sample.log `
  -WorkDir C:\profiles `
  -ProfileOut C:\profiles\generated-profile.json `
  -ProfileReportOut C:\profiles\profile_build_report_DO_NOT_UPLOAD.md `
  -NonInteractive
```

Then preview with the generated profile:

```powershell
.\scripts\Run-UniversalScrubber_v4_11.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed-preview `
  -ProfileFile C:\profiles\generated-profile.json `
  -DryRun `
  -ExplainDetections `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

Add `-ProfileWizard` when you want the tool to ask whether to write optional
seed and allowlist files from the sample evidence. Those files may contain raw
values and stay local.

## What Gets Scrubbed

- Principals, accounts, emails, domains, hostnames, servers, machines, IPs,
  SIDs, GUIDs, URLs, URIs, DNS names, X.500-style names, MACs, cloud IDs, and
  common file/path identifiers.
- Universal label/value forms such as `username=`, `host:`, `src_ip=`,
  `tenantId=`, `API Key =`, `client_secret=`, `authorization=`, and similar
  labels in CSV cells, JSON values, key=value logs, and free text.
- Offline secret patterns including bearer/basic auth values, password and key
  fields, connection strings, PEM private keys, and common provider token forms.
- User-provided seed terms for shapeless values such as organization names,
  client names, project names, tenant display names, vendor nicknames, and local
  product names.

Diagnostic/public values such as loopback IPs, all-zero GUIDs, known public
domains, and common built-in Windows accounts are preserved where that is safer
and more readable. You can add your own allowlist values in a profile or
`-AllowlistFile`.

## v4.11 Highlights

- `Test-LogFormat` recommends existing profiles from small local file samples.
- `-RecommendOnly` and `-SafeFirstRun` show recommendations and exit before salt,
  token-map, report, bundle, or scrubbed-output work begins.
- `-AutoProfile` can select one high-confidence built-in profile for uniform
  inputs and refuses mixed folders in noninteractive mode.
- `New-ScrubProfileFromSample` and `-BuildProfileFromSample` generate schema v2
  BYOP profiles from local sample logs.
- Optional `-ProfileWizard` can write sample-derived seed and allowlist files
  only when the user asks for them.
- `Test-ScrubProfile` validates profiles without running a scrub.
- `-SafeBundleOut` creates a zip with only clean scrubbed outputs and a safe
  readme, excluding token maps, salts, manifests, and detailed reports.
- Dry-run summaries now separate high-confidence detections, values to review,
  and values preserved by allowlist/diagnostic rules.
- v4.9 BYOP support remains: `SchemaColumns`, `WholeColumnRules`, `LabelRules`,
  `CustomRegexRules`, `Allowlist`, `AllowlistFile`, `SeedTerms`, and `SeedFiles`.

## Repository Layout

```text
src/            PowerShell module
scripts/        runnable launcher
docs/           security and operational notes
docs/profiles/  BYOP handbook and ready-to-edit profile examples
.github/        CI self-test workflow
```

## Validation

```powershell
Import-Module .\src\UniversalLogScrubber_v4_11.psm1 -Force
Test-LogFormat -Path .\samples\logs -Recurse
Invoke-UniversalScrubber -Path .\samples\logs -Recurse -RecommendOnly -NonInteractive
Invoke-UniversalScrubber -Path .\samples\logs -Recurse -SafeFirstRun -NonInteractive
Invoke-ScrubSelfTest

.\scripts\Run-UniversalScrubber_v4_11.ps1 `
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

See [USAGE.md](USAGE.md) for step-by-step workflows, profile generation,
profile authoring, seed and allowlist file formats, policy modes, token map
handling, EVTX conversion guidance, and safe-upload checklists.
