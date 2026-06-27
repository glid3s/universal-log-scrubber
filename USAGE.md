# Universal Log Scrubber Usage Guide

This guide is written for people who need to safely prepare logs for external
analysis, including LLM-assisted analysis, without sending sensitive values out
of a secure environment.

The short version:

1. Use a dry run first.
2. Review what would be tokenized.
3. Tune with a profile, seed file, or allowlist if needed.
4. Scrub only after the preview looks right.
5. Upload only scrubbed outputs, never token maps or local reports.

## First Run

Open PowerShell in the repository root and run the built-in self-test:

```powershell
Import-Module .\src\UniversalLogScrubber_v4_10.psm1 -Force
Invoke-ScrubSelfTest
```

Set a salt. The salt makes the same real value become the same token every time.
Use the same salt when multiple logs need to correlate with each other.

```powershell
$env:SCRUB_SALT = 'use-a-long-random-secret-value'
```

Run a dry-run preview. This writes no scrubbed files and no token map:

```powershell
.\scripts\Run-UniversalScrubber_v4_10.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed-preview `
  -SaltFromEnv SCRUB_SALT `
  -DryRun `
  -ExplainDetections `
  -NonInteractive
```

If the preview looks good, run the real scrub:

```powershell
.\scripts\Run-UniversalScrubber_v4_10.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

## What Files Are Safe To Upload?

Usually safe after review:

- `*_scrubbed.*` files that passed leak check.
- A `-SafeBundleOut` zip created by the tool.
- A counts-only detection summary after local review.

Never upload:

- `scrub_token_map_DO_NOT_UPLOAD.csv`
- `profile_build_report_DO_NOT_UPLOAD.md`
- `detection_review_DO_NOT_UPLOAD.csv`
- `scrub_run_manifest.json`
- raw logs, intermediate converted logs, salts, or seed files

Create a safer upload zip:

```powershell
.\scripts\Run-UniversalScrubber_v4_10.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -SafeBundleOut C:\scrubbed\safe-upload.zip `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

The bundle includes only clean scrubbed outputs and a plain safe readme. It
excludes maps, salts, manifests, raw logs, and detailed local reports.

## How To Read Dry-Run Output

Dry-run output shows what would be tokenized.

- `High confidence tokenizations` are things like IPs, SIDs, secrets, emails,
  GUIDs, MACs, auth headers, and provider tokens.
- `Review for context/readability` means the value is likely sensitive, but a
  human may want to confirm the profile is not over-scrubbing useful diagnostics.
- `Preserved by allowlist/diagnostic rules` means the tool recognized something
  public or diagnostic and left it readable.

If a sensitive value appears in dry-run examples and has a token, good. If a
sensitive value appears in the source but not in dry-run output, add a profile
rule or seed term. If a public value would be tokenized, add an allowlist.

## Choosing A Profile

Use `Generic` when unsure. Use a specific profile when the log type is known:

- `WindowsEventCsv` for Windows event CSV/EVTX conversions.
- `AppJson` for JSON and NDJSON application logs.
- `Logfmt`, `Cef`, or `Kv`-style profiles for `key=value` logs.
- `WebAccess` or `Proxy` for access/proxy logs.
- `CloudAudit`, `Firewall`, `Vpn`, `Database`, `Container`, `Kubernetes`, or
  `IdentityProvider` when those labels match the source.

Example:

```powershell
.\scripts\Run-UniversalScrubber_v4_10.ps1 `
  -Path C:\logs\app.ndjson `
  -WorkDir C:\scrubbed `
  -Profile AppJson `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

## Build A Profile From A Sample

When no built-in profile fits, let the tool inspect a local sample and generate
a BYOP profile.

Analyzer-only mode:

```powershell
.\scripts\Run-UniversalScrubber_v4_10.ps1 `
  -BuildProfileFromSample `
  -Path C:\logs\sample.log `
  -WorkDir C:\profiles `
  -ProfileOut C:\profiles\generated-profile.json `
  -ProfileReportOut C:\profiles\profile_build_report_DO_NOT_UPLOAD.md `
  -MaxSampleRows 500 `
  -NonInteractive
```

What this creates:

- `generated-profile.json`: editable schema v2 profile. It does not store raw
  sample values by default.
- `profile_build_report_DO_NOT_UPLOAD.md`: local-only evidence report with raw
  examples, suggestions, and confidence hints.

Optional wizard mode:

```powershell
.\scripts\Run-UniversalScrubber_v4_10.ps1 `
  -BuildProfileFromSample `
  -Path C:\logs\sample.log `
  -WorkDir C:\profiles `
  -ProfileWizard
```

The wizard can write `generated-seeds.txt` and `generated-allowlist.txt` when
you explicitly choose to create them. Those files may contain raw values and
must stay local.

Preview with the generated profile:

```powershell
.\scripts\Run-UniversalScrubber_v4_10.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed-preview `
  -ProfileFile C:\profiles\generated-profile.json `
  -DryRun `
  -ExplainDetections `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

Validate a profile without scrubbing:

```powershell
Import-Module .\src\UniversalLogScrubber_v4_10.psm1 -Force
Test-ScrubProfile -Path C:\profiles\generated-profile.json
```

## What To Do When Something Looks Wrong

Sensitive value was missed:

- Add it to a seed file if it is a shapeless name, project, tenant, vendor, or
  local product term.
- Add a label rule if it appears after a label like `username=`, `host:`, or
  `API Key =`.
- Add a whole-column rule if an entire column is sensitive.
- Add a custom regex if it follows a local pattern like ticket IDs or internal
  asset IDs.

Useful public value was tokenized:

- Add it to an allowlist file.
- Use `regex:` for repeated public labels like build names.
- Use `domain:` for public domains and subdomains.

Too much was tokenized:

- Check whether `Strict` policy is being used.
- Add `PassThrough` schema rules for analytical columns such as timestamps,
  status codes, methods, levels, durations, counts, and event categories.

Too little was tokenized:

- Use `Strict`.
- Add a BYOP profile.
- Add seed terms for values that cannot be detected by shape.

## Seed Terms

Seed terms are sensitive terms that do not have a reliable pattern. Examples:
client names, internal project names, organization names, vendor nicknames,
tenant display names, and internal product names.

Seed file:

```text
# One term per line. Comments start with #.
ExampleCorp
ProjectFalcon
LegacyVendorName
internal-product-code
```

Use it:

```powershell
.\scripts\Run-UniversalScrubber_v4_10.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -SeedFile C:\profiles\client-seeds.txt `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

`-SensitiveTermsFile` is also accepted as an alias-friendly seed-file input.

## Allowlists

Allowlists preserve public diagnostics or harmless values that would otherwise
look sensitive.

Allowlist file:

```text
127.0.0.1
::1
public.example.com
domain:microsoft.com
regex:^(health|ready|live)$
regex:^build-[0-9]+$
```

Use it:

```powershell
.\scripts\Run-UniversalScrubber_v4_10.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -AllowlistFile C:\profiles\public-allowlist.txt `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

## BYOP Profile Basics

BYOP means bring your own profile. A profile tells the scrubber how to interpret
your log source.

Main schema v2 sections:

- `SchemaColumns`: decide whether columns/JSON keys are scrubbed, scanned, or
  passed through.
- `WholeColumnRules`: tokenize entire values in sensitive columns.
- `LabelRules`: tokenize values after labels in text, JSON strings, or cells.
- `CustomRegexRules`: define local patterns with capture groups, keywords, and
  optional entropy thresholds.
- `SeedTerms` and `SeedFiles`: add shapeless sensitive terms.
- `Allowlist` and `AllowlistFile`: preserve approved public values.

Example:

```json
{
  "SchemaVersion": 2,
  "Name": "CsvSchemaExample",
  "Format": "Csv",
  "DenyByDefault": true,
  "SchemaColumns": [
    { "Exact": "Timestamp", "Action": "PassThrough" },
    { "Wildcard": "*Message*", "Action": "Scan" }
  ],
  "WholeColumnRules": [
    { "Exact": "UserID", "Prefix": "PRINCIPAL" },
    { "Regex": "(?i)^(machine|host|server)$", "Prefix": "DNS" },
    { "Regex": "(?i)^(clientip|src_ip|dst_ip)$", "Prefix": "IP", "SplitOn": "[;,|]" },
    { "Regex": "(?i)(api[_ -]?key|token|secret|password)", "Prefix": "SECRET" }
  ],
  "LabelRules": [
    { "Name": "InlineUsers", "Labels": [ "username", "user", "account" ], "Prefix": "PRINCIPAL" },
    { "Name": "InlineHosts", "Labels": [ "host", "server", "node" ], "Prefix": "DNS" },
    { "Name": "InlineSecrets", "Labels": [ "API Key", "api_key", "client_secret" ], "Prefix": "SECRET" }
  ],
  "SeedFiles": [ "client-seeds.txt" ],
  "AllowlistFile": [ "public-allowlist.txt" ]
}
```

More detailed BYOP guidance and copy/paste examples are in
[docs/profiles/README.md](docs/profiles/README.md).

## EVTX Conversion

EVTX files are converted to CSV before scrubbing. Conversion streams rows and
shows progress so large event logs do not look hung.

```powershell
.\scripts\Run-UniversalScrubber_v4_10.ps1 `
  -Path C:\logs\Security.evtx `
  -WorkDir C:\scrubbed `
  -SaltFromEnv SCRUB_SALT `
  -EvtxProgressMode Fast `
  -NonInteractive
```

Use `CountFirst` when you want true percentage progress. It does a pre-pass to
count events, then writes CSV rows with EventData/UserData columns when present.

## Token Maps

The token map is the private lookup table that lets local reviewers re-identify
tokens later. It must not be uploaded.

Merge into an existing map:

```powershell
.\scripts\Run-UniversalScrubber_v4_10.ps1 `
  -Path C:\more-logs `
  -WorkDir C:\scrubbed `
  -TokenMapCsv C:\scrubbed\scrub_token_map_DO_NOT_UPLOAD.csv `
  -TokenMapMode Merge `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

Use replace mode only when intentionally starting a new map:

```powershell
.\scripts\Run-UniversalScrubber_v4_10.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -TokenMapMode Replace `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

## Policy Modes

- `Balanced` is recommended for most secure-client log sharing.
- `Strict` scrubs more aggressively and may reduce readability.
- `Readable` preserves more known diagnostics and should be paired with review.

```powershell
.\scripts\Run-UniversalScrubber_v4_10.ps1 `
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
.\scripts\Run-UniversalScrubber_v4_10.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -FalsePositiveReport C:\scrubbed\detection_review_DO_NOT_UPLOAD.csv `
  -DetectionSummaryReport C:\scrubbed\detection_summary.csv `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

`DetectionSummaryReport` contains detector counts only and is safer to discuss
externally, but still review it before sharing.

## Restore Local Findings

Use restore only inside the secure environment with the private token map.

```powershell
Import-Module .\src\UniversalLogScrubber_v4_10.psm1 -Force

Restore-ScrubbedFile `
  -InputPath C:\analysis\findings_from_llm.csv `
  -TokenMapCsv C:\scrubbed\scrub_token_map_DO_NOT_UPLOAD.csv `
  -OutputPath C:\analysis\findings_reidentified.csv
```

## Safe Upload Checklist

- Leak check passed.
- Output file is scrubbed, not raw or intermediate.
- No `DO_NOT_UPLOAD` files are included.
- No token map, salt, manifest, profile build report, or detailed detection review is included.
- A local reviewer checked representative rows and edge cases.
- The same salt/map strategy is documented for future correlation needs.

## Validation

```powershell
Import-Module .\src\UniversalLogScrubber_v4_10.psm1 -Force
Invoke-ScrubSelfTest
```

Use synthetic or approved local logs for dry-run validation. The dry run previews
what would be detected and tokenized without writing scrubbed output files.
