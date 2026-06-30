# Universal Log Scrubber

Universal Log Scrubber is a local-first PowerShell tool for preparing logs from
secure environments before they are shared with external analysis tools,
including LLMs. It replaces sensitive values with deterministic HMAC tokens so
events can still be correlated without exposing the original identifiers.

It works offline against Windows Event exports, EVTX files, CSV/TSV/PSV,
JSON/NDJSON, IIS/W3C, web access/proxy logs, key=value/logfmt/CEF-style logs,
syslog, enterprise CSV/XLSX exports, Office documents, and mixed diagnostic
text. Version 4.15.0 adds compact progress feedback, native DOCX/PPTX text
extraction, ServiceNow/Nexthink/SCCM/Intune export profiles, an
IntuneDiagnostics text profile, and continued streaming CSV/parallel scrub
performance work.

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
- raw `.evtx`, `.csv`, `.log`, `.json`, `.xlsx`, `.docx`, `.pptx`, `.reg`,
  `.html`, `.xml`, or exported client logs

## Quick Start

Open PowerShell in the repository root:

```powershell
Import-Module .\UniversalLogScrubber\UniversalLogScrubber.psd1 -Force
Invoke-ScrubSelfTest

.\scripts\Run-UniversalScrubber.ps1 `
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

## Enterprise Exports And Office Files

Use local recommendations first when a folder has mixed exports:

```powershell
Test-LogFormat -Path C:\exports -Recurse
```

Built-in v4.15 profiles include:

- `ServiceNow` for incident/change/task/CMDB CSV exports with callers,
  assignees, CIs, URLs, work notes, and comments.
- `Nexthink` for device, user, binary, destination, campaign, and remote-action
  CSV exports.
- `Sccm` for SCCM/MECM inventory, deployment, client, and collection CSV
  exports.
- `Intune` for Intune/Endpoint Manager device, enrollment, app, policy, and
  compliance CSV exports.
- `IntuneDiagnostics` for Intune diagnostic bundle logs and reports such as
  `.log`, `.txt`, `.reg`, `.html`, and `.xml` files.

Examples:

```powershell
.\scripts\Run-UniversalScrubber.ps1 `
  -Path C:\exports\ServiceNowTickets.csv `
  -WorkDir C:\scrubbed\ServiceNow `
  -Profile ServiceNow `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive

.\scripts\Run-UniversalScrubber.ps1 `
  -Path C:\IntuneDiagnostics `
  -WorkDir C:\scrubbed\IntuneDiagnostics `
  -Profile IntuneDiagnostics `
  -Recurse `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

XLSX workbooks are converted locally before scrubbing. v4.15 converts the first
worksheet; export specific sheets or build a BYOP profile for complex workbooks.
DOCX and PPTX files are parsed with native OpenXML zip reading, not Office COM
automation. The module writes local UNSCRUBBED `.txt` intermediates under
`-WorkDir`, scrubs those text files, then deletes unsafe intermediates unless you
ask to keep them.

Legacy `.doc` and `.ppt` files are not parsed natively. Export them to
`.docx`, `.pptx`, or plain text first. ETL traces and CAB archives are
recommendation-only guardrails in v4.15; convert ETL to `.log`/`.txt`/`.csv` or
extract approved CAB contents before scrubbing.

## Build A Profile From A Sample

When the built-in profiles are not specific enough, point the tool at a local
sample. It will create an editable BYOP profile without storing raw sample
values in the profile.

```powershell
.\scripts\Run-UniversalScrubber.ps1 `
  -BuildProfileFromSample `
  -Path C:\logs\sample.log `
  -WorkDir C:\profiles `
  -ProfileOut C:\profiles\generated-profile.json `
  -ProfileReportOut C:\profiles\profile_build_report_DO_NOT_UPLOAD.md `
  -NonInteractive
```

Then preview with the generated profile:

```powershell
.\scripts\Run-UniversalScrubber.ps1 `
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
- Sensitive-looking numeric JSON identifiers such as user, account, session,
  request, trace, and resource IDs, while preserving benign counts, status
  codes, ports, durations, sizes, and versions.
- User-provided seed terms for shapeless values such as organization names,
  client names, project names, tenant display names, vendor nicknames, and local
  product names.

Diagnostic/public values such as loopback IPs, all-zero GUIDs, known public
domains, and common built-in Windows accounts are preserved where that is safer
and more readable. You can add your own allowlist values in a profile or
`-AllowlistFile`.

## v4.15.0 Highlights

- Unified compact progress feedback for discovery, scrub, streaming parallel
  scrub, conversion, leak checks, and smoke tests.
- Native OpenXML text intake for DOCX and PPTX, with local-only UNSCRUBBED text
  intermediates under `-WorkDir`.
- Built-in profile recommendations for ServiceNow, Nexthink, SCCM/MECM, Intune,
  and Intune Diagnostics exports.
- Conservative default detection remains BYOP-first for local/vendor edge cases,
  while known users, hosts, private IPs, URLs, secrets, serial-like device
  identifiers, and comments/work notes are tokenized in the relevant profiles.
- Streaming CSV parallel scrub uses in-process ordered batches, not temporary
  input chunk copies.
- Windows Event CSV handling preserves provider names, event IDs, levels,
  timestamps, provider/template GUIDs, and well-known Windows identities while
  tokenizing real users, machines, private IPs, and secrets.
- XLSX conversion remains local; v4.15 documents first-sheet behavior.
- ETL and CAB files are detected with clear guidance to convert or extract
  approved contents before scrubbing.

## Earlier Highlights

- Stable package layout: `UniversalLogScrubber\UniversalLogScrubber.psd1`
  imports the unversioned `UniversalLogScrubber.psm1`.
- `Invoke-UniversalScrubber -Version` and `Invoke-UniversalLogScrubber -Version`
  report the installed module version and paths without prompting for run input.
- ULS-prefixed aliases are exported for discoverability while existing command
  names remain canonical.
- JSON numeric scrubbing is conservative but safer for sensitive-looking
  identity, session, request, trace, and resource keys.
- URL/connection host detection covers JDBC, database, cache, queue, Kafka, and
  WS/WSS-style schemes.
- v4.11 recommendations remain: `Test-LogFormat`, `-RecommendOnly`,
  `-SafeFirstRun`, and `-AutoProfile`.
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
UniversalLogScrubber/  module manifest and script module
scripts/               launcher and sample tests
docs/                  security and operational notes
docs/profiles/         BYOP handbook and ready-to-edit profile examples
.github/               CI self-test workflow
```

## Validation

```powershell
Test-ModuleManifest .\UniversalLogScrubber\UniversalLogScrubber.psd1
Import-Module .\UniversalLogScrubber\UniversalLogScrubber.psd1 -Force
Invoke-UniversalScrubber -Version
Invoke-UniversalLogScrubber -Version
Test-LogFormat -Path .\samples\logs -Recurse
Invoke-UniversalScrubber -Path .\samples\logs -Recurse -RecommendOnly -NonInteractive
Invoke-UniversalScrubber -Path .\samples\logs -Recurse -SafeFirstRun -NonInteractive
Invoke-ScrubSelfTest
Invoke-ULSScrubSelfTest
.\scripts\Test-SampleLogs.ps1

.\scripts\Run-UniversalScrubber.ps1 `
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

# Universal Log Scrubber v4.15 Quick Notes

Universal Log Scrubber 4.15 keeps the default `Balanced` policy conservative and BYOP-first: built-in detection targets well-known sensitive values, while local/vendor edge cases are best handled with profiles, seed files, allowlists, or the new additive `-ProfileExtensionFile` overlay.

Common v4.15 examples:

```powershell
# Run a normal scrub with the built-in recommendation for a folder of logs.
Invoke-UniversalScrubber -Path .\logs -Recurse -AutoProfile -SaltFile .\salt.txt -NonInteractive

# Add local BYOP rules without copying a whole built-in profile.
Invoke-UniversalScrubber -Path .\tickets.csv -Profile ServiceNow -ProfileExtensionFile .\servicenow-local-extension.json -SaltFile .\salt.txt -NonInteractive

# Build a standalone editable profile from a sample, starting from a built-in profile.
Invoke-UniversalScrubber -BuildProfileFromSample -Path .\sample-firewall.log -BaseProfile Firewall -ProfileOut .\firewall-custom.json -Force -NonInteractive

# ETL conversion is explicit and local. The converted CSV remains unsanitized until the scrub step completes.
Invoke-UniversalScrubber -Path .\trace.etl -ConvertEtl -Profile Generic -SaltFile .\salt.txt -NonInteractive
```

New or improved v4.15 recommendations include Intune diagnostics (`.log`, `.txt`, `.reg`, `.html`, `.xml`), ServiceNow, Nexthink, SCCM/ConfigMgr, Intune CSV exports, M365/identity audit exports, Sentinel/cloud audit JSONL, EDR/XDR JSONL, firewall/VPN text, structured firewall CSV exports, XLSX, DOCX, PPTX, and ETL traces.
