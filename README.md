# Universal Log Scrubber

Universal Log Scrubber is a local-first PowerShell tool for preparing logs from
secure environments before they are shared with external analysis tools,
including LLMs. It replaces sensitive values with deterministic HMAC tokens so
events can still be correlated without exposing the original identifiers.

It works offline against Windows Event exports, EVTX files, CSV/TSV/PSV,
JSON/NDJSON, IIS/W3C, web access/proxy logs, key=value/logfmt/CEF-style logs,
syslog, and mixed diagnostic text. Version 4.9 expands the tool into a stronger
universal scrubber with configurable BYOP profiles, seed files, allowlists,
custom regex rules, and universal label-aware detection.

## Safety First

Never upload token maps, salts, detailed detection review reports, raw logs, or
generated manifests from sensitive runs. Only upload scrubbed outputs after the
leak check passes and a local reviewer approves the result.

Private artifacts include:

- `scrub_token_map_DO_NOT_UPLOAD.csv`
- `*_DO_NOT_UPLOAD.csv`
- `scrub_run_manifest.json`
- local salt files
- detailed detection review reports
- raw `.evtx`, `.csv`, `.log`, `.json`, `.xlsx`, or exported client logs

## Quick Start

Open PowerShell in the repository root:

```powershell
Import-Module .\src\UniversalLogScrubber_v4_9.psm1 -Force
Invoke-ScrubSelfTest

.\scripts\Run-UniversalScrubber_v4_9.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -SaltFromEnv SCRUB_SALT `
  -Profile Generic `
  -DryRun `
  -ExplainDetections `
  -NonInteractive
```

For noninteractive use, provide one of `-Salt`, `-SaltFromEnv`, or `-SaltFile`.
Prefer `-SaltFromEnv` or `-SaltFile` so the salt is not left in command history.

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

## v4.9 Highlights

- BYOP profile schema v2 with `SchemaColumns`, `WholeColumnRules`,
  `LabelRules`, `CustomRegexRules`, `Allowlist`, `AllowlistFile`, `SeedTerms`,
  and `SeedFiles`.
- CLI seed files via `-SeedFile` and alias-friendly `-SensitiveTermsFile`.
- Universal label-aware detection for non-Windows logs.
- Built-in non-Windows presets for web access/proxy, cloud audit, firewall,
  VPN, app JSON, database, container, Kubernetes, and identity-provider logs.
- Custom regex detectors with capture groups, keyword prefilters, entropy
  thresholds, and allowlists.
- Dry-run detector counts and safer profile validation messages.
- v4.8 reliability retained: token-map merge/replace, atomic map writes,
  collision-safe outputs, EVTX progress, EventData/UserData extraction, and
  24-hex-character default HMAC tokens.

## Repository Layout

```text
src/            PowerShell module
scripts/        runnable launcher
docs/           security and operational notes
docs/profiles/  ready-to-edit BYOP profile examples
```

## Validation

```powershell
Import-Module .\src\UniversalLogScrubber_v4_9.psm1 -Force
Invoke-ScrubSelfTest

.\scripts\Run-UniversalScrubber_v4_9.ps1 `
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

See [USAGE.md](USAGE.md) for detailed workflows, profile authoring, seed and
allowlist file formats, policy modes, token map handling, EVTX conversion
guidance, and safe-upload checklists.
