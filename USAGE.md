# Universal Log Scrubber Usage Guide

This guide walks through the local workflow for scrubbing logs before they leave
a secure environment. The tool is offline and deterministic: the same original
value becomes the same token when the same salt and HMAC length are used.

## Recommended Workflow

1. Put raw logs in a local working folder that will not be uploaded.
2. Set a run salt using an environment variable or protected salt file.
3. Run a dry run on a representative sample with `-ExplainDetections`.
4. Add a BYOP profile, seed file, or allowlist when the preview needs tuning.
5. Re-run dry-run until sensitive values are tokenized and public diagnostics are preserved.
6. Run the scrubber against the approved log set.
7. Review the leak-check result and any local-only detection report.
8. Upload only the scrubbed output files that passed review.
9. Keep the token map and salt private for local re-identification.

## Salt Handling

The salt controls deterministic token generation. Reuse the same salt only when
you intentionally need tokens to correlate across files or runs.

```powershell
$env:SCRUB_SALT = 'use-a-long-random-secret-value'

.\scripts\Run-UniversalScrubber_v4_9.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

You can also use `-SaltFile C:\secure\scrub_salt.txt`. Avoid `-Salt` for
repeatable production workflows because command history may retain it.

## Basic Scrubs

CSV or Windows Event CSV:

```powershell
.\scripts\Run-UniversalScrubber_v4_9.ps1 `
  -Path C:\logs\Security.evtx.csv `
  -WorkDir C:\scrubbed `
  -Profile WindowsEventCsv `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

Recursive mixed folder:

```powershell
.\scripts\Run-UniversalScrubber_v4_9.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -Include *.csv,*.log,*.json,*.evtx `
  -Recurse `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

JSON or NDJSON:

```powershell
.\scripts\Run-UniversalScrubber_v4_9.ps1 `
  -Path C:\logs\app.ndjson `
  -WorkDir C:\scrubbed `
  -Profile AppJson `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

key=value, logfmt, CEF, or LEEF-style text:

```powershell
.\scripts\Run-UniversalScrubber_v4_9.ps1 `
  -Path C:\logs\gateway.log `
  -WorkDir C:\scrubbed `
  -Profile Logfmt `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

## Built-In Profiles

Use `Generic` when you are unsure. More specific built-ins are available for:

- `WindowsEventCsv`, `CA`, `IIS`, `Syslog`, `Apache`, `Cef`, `Logfmt`
- `WebAccess`, `CloudAudit`, `Firewall`, `Vpn`, `Proxy`
- `AppJson`, `Database`, `Container`, `Kubernetes`, `IdentityProvider`
- `Text`, `Tsv`, `Psv`

Built-ins are intentionally conservative. Use BYOP profiles when a log source
has local schema, custom labels, or organization-specific identifiers.

## EVTX Conversion

EVTX files are converted to CSV before scrubbing. Conversion streams rows and
shows progress so large event logs do not look hung.

```powershell
.\scripts\Run-UniversalScrubber_v4_9.ps1 `
  -Path C:\logs\Security.evtx `
  -WorkDir C:\scrubbed `
  -SaltFromEnv SCRUB_SALT `
  -EvtxProgressMode Fast `
  -NonInteractive
```

Use `CountFirst` when you want true percentage progress. It does a pre-pass to
count events, then writes CSV rows with EventData/UserData columns when present.

```powershell
.\scripts\Run-UniversalScrubber_v4_9.ps1 `
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
.\scripts\Run-UniversalScrubber_v4_9.ps1 `
  -Path C:\more-logs `
  -WorkDir C:\scrubbed `
  -TokenMapCsv C:\scrubbed\scrub_token_map_DO_NOT_UPLOAD.csv `
  -TokenMapMode Merge `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

Use replace mode only when intentionally starting a new map:

```powershell
.\scripts\Run-UniversalScrubber_v4_9.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -TokenMapMode Replace `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

## Seed Terms

Seed terms are for shapeless sensitive values that cannot be inferred reliably:
organization names, client names, project names, vendor nicknames, internal
product names, tenant display names, and host prefixes.

Inline terms still work:

```powershell
.\scripts\Run-UniversalScrubber_v4_9.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -SensitiveTerms ExampleCorp,ProjectFalcon,legacy-host-prefix `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

For real workflows, prefer a seed file:

```powershell
.\scripts\Run-UniversalScrubber_v4_9.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -SeedFile C:\profiles\client-seeds.txt `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

`-SensitiveTermsFile` is an alias-friendly seed-file input. Profiles can also
include `SeedTerms` and `SeedFiles`. The tool trims whitespace, ignores blank
lines and `#` comments, removes duplicates, and reports counts only.

Seed file format:

```text
# One term per line. Comments start with #.
ExampleCorp
ProjectFalcon
LegacyVendorName
internal-product-code
```

## Allowlists

Allowlists preserve public diagnostics or harmless values that would otherwise
look sensitive. Use them for known public domains, health-check words, loopback
values, build labels, status names, and similar non-sensitive values.

```powershell
.\scripts\Run-UniversalScrubber_v4_9.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed `
  -AllowlistFile C:\profiles\public-allowlist.txt `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

Allowlist file format:

```text
# Plain text means exact value.
127.0.0.1
::1
public.example.com

# Preserve a domain and its subdomains.
domain:microsoft.com

# Regex values are supported.
regex:^(health|ready|live)$
regex:^build-[0-9]+$
```

## BYOP Profiles

BYOP means bring your own profile. Use it when the built-ins do not know your
schema, labels, local ID formats, or organization-specific vocabulary.

Practical BYOP workflow:

1. Start with `Generic` dry-run.
2. Identify schema columns that are always sensitive, always public, or need free-text scanning.
3. Identify labels that introduce sensitive values, such as `Account Name =`, `API Key =`, `username=`, `host:`, `src_ip=`, or `tenantId=`.
4. Put organization, client, project, tenant, vendor, and product names in a seed file.
5. Add custom regex rules for local IDs that no generic detector can know.
6. Add allowlists for public diagnostics, status values, known public domains, and health-check labels.
7. Re-run dry-run with `-ExplainDetections`.
8. Scrub only after the preview looks right.

Generate a starter profile:

```powershell
.\scripts\Run-UniversalScrubber_v4_9.ps1 `
  -WorkDir C:\profiles `
  -ProfileTemplate Csv `
  -NonInteractive
```

Run with a profile:

```powershell
.\scripts\Run-UniversalScrubber_v4_9.ps1 `
  -Path C:\logs\export.csv `
  -WorkDir C:\scrubbed-preview `
  -ProfileFile C:\profiles\csv-schema-profile.json `
  -SeedFile C:\profiles\client-seeds.txt `
  -AllowlistFile C:\profiles\public-allowlist.txt `
  -DryRun `
  -ExplainDetections `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

Ready-to-edit examples live in [docs/profiles](docs/profiles):

- `csv-schema-profile.json`
- `json-app-profile.json`
- `kv-log-profile.json`
- `webaccess-profile.json`
- `seed.example.txt`
- `allowlist.example.txt`

### Profile Schema v2 Fields

`SchemaColumns` defines how named columns or JSON keys behave:

- `Action = Scrub` tokenizes the entire value.
- `Action = Scan` scans the value as free text.
- `Action = PassThrough` preserves the value.
- Match columns with `Exact`, `Wildcard`, or `Regex`.
- Optional `Prefix` controls token type.
- Optional `SplitOn` tokenizes list-like values item by item.

`WholeColumnRules` tokenizes entire column/key values, useful for `UserID`,
`Machine`, `Server`, `ClientIP`, `APIKey`, and similar fields.

`LabelRules` tokenizes values after labels in any scanned text:

- `Labels`: label names such as `username`, `host`, `API Key`, `tenantId`.
- `SeparatorRegex`: defaults to `[:=]`.
- `ValueRegex`: optional custom value boundary.
- `Prefix`: token prefix, such as `PRINCIPAL`, `DNS`, `IP`, `SECRET`, `X500`, or `OBJECT`.
- `Preserve` and `PreserveRegex`: rule-local values to keep.

`CustomRegexRules` adds local detectors:

- `Name`: rule name shown in dry-run/detection reports.
- `Regex`: PowerShell/.NET regular expression.
- `CaptureGroup`: group to tokenize. Use `0` for the whole match.
- `Prefix`: token prefix.
- `Keywords`: cheap prefilter words that must appear before the regex runs.
- `Entropy`: optional minimum entropy threshold for secret-like values.
- `Allowlist` and `AllowlistRegex`: rule-local public values to preserve.

`Allowlist`, `AllowlistFile`, `SeedTerms`, and `SeedFiles` behave the same as
the CLI inputs. Relative file paths are resolved relative to the profile file.

### CSV Schema Example

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
  "SeedFiles": [ "client-seeds.txt" ],
  "AllowlistFile": [ "public-allowlist.txt" ]
}
```

### JSON/Application Logs

JSON keys are preserved. String values are scrubbed, and each key acts like a
column name for schema rules.

```json
{
  "SchemaVersion": 2,
  "Name": "JsonAppExample",
  "Format": "Json",
  "DenyByDefault": true,
  "WholeColumnRules": [
    { "Regex": "(?i)^(user|username|actor|principal)$", "Prefix": "PRINCIPAL" },
    { "Regex": "(?i)^(host|server|node|pod|container)$", "Prefix": "DNS" },
    { "Regex": "(?i)^(ip|src_ip|client_ip|remote_addr)$", "Prefix": "IP" },
    { "Regex": "(?i)(api[_-]?key|token|secret|password)", "Prefix": "SECRET" }
  ],
  "LabelRules": [
    { "Name": "TenantLabels", "Labels": [ "tenant", "tenantId", "org" ], "Prefix": "X500" }
  ]
}
```

### key=value, logfmt, and CEF-Style Logs

Use `Format = "Kv"` when the file is mostly `key=value` or extension fields.

```json
{
  "SchemaVersion": 2,
  "Name": "GatewayKvExample",
  "Format": "Kv",
  "DenyByDefault": true,
  "LabelRules": [
    { "Name": "Users", "Labels": [ "user", "username", "suser", "duser" ], "Prefix": "PRINCIPAL" },
    { "Name": "Hosts", "Labels": [ "host", "dhost", "shost" ], "Prefix": "DNS" },
    { "Name": "Addresses", "Labels": [ "src", "dst", "src_ip", "dst_ip" ], "Prefix": "IP" },
    { "Name": "Secrets", "Labels": [ "api_key", "token", "secret", "password" ], "Prefix": "SECRET" }
  ]
}
```

### Web Access and Proxy Logs

For parsed web exports, use column rules. For raw access lines, use `WebAccess`
or a profile with `Format = "Text"`/`Auto`.

```json
{
  "SchemaVersion": 2,
  "Name": "WebProxyExample",
  "Format": "Auto",
  "DenyByDefault": true,
  "SchemaColumns": [
    { "Regex": "(?i)^(date|time|method|status|bytes)$", "Action": "PassThrough" },
    { "Regex": "(?i)^(uri|url|referer|user-agent|message)$", "Action": "Scan" }
  ],
  "WholeColumnRules": [
    { "Regex": "(?i)^(c-ip|clientip|src_ip|remote_addr|x-forwarded-for)$", "Prefix": "IP", "SplitOn": "[,; ]+" },
    { "Regex": "(?i)^(cs-username|username|user)$", "Prefix": "PRINCIPAL" },
    { "Regex": "(?i)^(host|cs-host|server|upstream_host)$", "Prefix": "DNS" }
  ]
}
```

### Custom Regex With Capture Group and Entropy

This keeps the label readable and tokenizes only the second capture group:

```json
{
  "CustomRegexRules": [
    {
      "Name": "CompanySessionToken",
      "Regex": "(?i)\\b(session[_ -]?token\\s*[:=]\\s*)([A-Za-z0-9_-]{24,})",
      "CaptureGroup": 2,
      "Prefix": "SECRET",
      "Keywords": [ "session", "token" ],
      "Entropy": 3.2,
      "Allowlist": [ "not-a-real-token" ]
    }
  ]
}
```

## Policy Modes

- `Balanced` is recommended for most secure-client log sharing.
- `Strict` scrubs more aggressively and may reduce readability.
- `Readable` preserves more known diagnostics and should be paired with local review.

```powershell
.\scripts\Run-UniversalScrubber_v4_9.ps1 `
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
.\scripts\Run-UniversalScrubber_v4_9.ps1 `
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
Import-Module .\src\UniversalLogScrubber_v4_9.psm1 -Force

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
Import-Module .\src\UniversalLogScrubber_v4_9.psm1 -Force
Invoke-ScrubSelfTest
```

Run a dry-run preview through the normal launcher:

```powershell
.\scripts\Run-UniversalScrubber_v4_9.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed-preview `
  -SaltFromEnv SCRUB_SALT `
  -DryRun `
  -ExplainDetections `
  -NonInteractive
```

Use synthetic or approved local logs for dry-run validation. The dry run previews
what would be detected and tokenized without writing scrubbed output files.
