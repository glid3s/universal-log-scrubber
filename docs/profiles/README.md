# BYOP Handbook

BYOP means bring your own profile. A profile is a plain JSON or PSD1 file that
tells Universal Log Scrubber how to treat a specific log source.

Use BYOP when:

- The built-in profiles miss values you know are sensitive.
- A column is always sensitive, such as `UserID`, `Server`, `ClientIP`, or `APIKey`.
- A log has local labels like `tenantId=`, `API Key =`, `device:`, or `operator=`.
- Your environment has shapeless names that patterns cannot infer.
- Public diagnostic values are being scrubbed and should stay readable.

## Built-In Profiles Added In v4.15

The scrubber includes conservative starting profiles for common enterprise
exports:

- `ServiceNow`: incident/change/task/CMDB CSV exports. Preserves ticket numbers,
  states, priorities, timestamps, and common workflow metadata while tokenizing
  callers, assignees, users, CIs, hosts, private IPs, URLs, secrets, work notes,
  comments, and descriptions.
- `Nexthink`: device, user, binary, destination, campaign, and remote-action
  CSV exports. Preserves operational state/version/count fields while tokenizing
  users, devices, hosts, destinations, private IPs, and comment-like text.
- `Sccm`: SCCM/MECM inventory, deployment, client, and collection CSV exports.
  Preserves numeric resource/deployment/collection/site metadata while
  tokenizing users, devices, hostnames, private IPs, MACs, serial-like IDs, and
  server fields.
- `Intune`: Intune/Endpoint Manager device, enrollment, app, policy, and
  compliance CSV exports. Preserves compliance/status/platform/policy metadata
  while tokenizing UPNs, users, devices, serial-like IDs, IMEI/MEID, MACs,
  private IPs, tenant/domain fields, and secrets.
- `IntuneDiagnostics`: text-style Intune diagnostic bundle content, including
  `.log`, `.txt`, `.reg`, `.html`, and `.xml` report files. ETL traces must be
  converted first; CAB archives should be extracted only when approved.

These profiles are intentionally not a substitute for local review. Use
`Test-LogFormat`, dry runs, and BYOP rules for organization-specific fields,
custom vendor labels, local asset IDs, and report/comment edge cases.

## Mental Model

The scrubber works in layers:

1. Schema rules decide what to do with columns or JSON keys.
2. Whole-column rules tokenize the entire value when the column itself is sensitive.
3. Label rules tokenize values after labels in messages, text logs, and cells.
4. Custom regex rules catch local formats such as ticket IDs or asset IDs.
5. Seed files catch shapeless terms such as organization, project, vendor, and tenant names.
6. Allowlists preserve public diagnostics and known harmless values.
7. Leak checks re-scan scrubbed output before anything is considered safe.

The generated token map is private. A BYOP profile is less sensitive than a token
map, but review it before sharing because schema names can still reveal context.

## Start From A Sample

The easiest workflow is to generate a starter profile from a local sample.

```powershell
.\scripts\Run-UniversalScrubber.ps1 `
  -BuildProfileFromSample `
  -Path C:\logs\sample.log `
  -WorkDir C:\profiles `
  -ProfileOut C:\profiles\generated-profile.json `
  -ProfileReportOut C:\profiles\profile_build_report_DO_NOT_UPLOAD.md `
  -MaxSampleRows 500 `
  -NonInteractive
```

The generated profile does not include raw sample values by default. The report
does include raw examples and is marked `DO_NOT_UPLOAD`.

Run a dry run with the generated profile:

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

Use wizard mode when you want the tool to ask whether to write seed and allowlist
files from the sample evidence:

```powershell
.\scripts\Run-UniversalScrubber.ps1 `
  -BuildProfileFromSample `
  -Path C:\logs\sample.log `
  -WorkDir C:\profiles `
  -ProfileWizard
```

## Manual Workflow

1. Start with `Generic` and `-DryRun -ExplainDetections`.
2. Mark obvious timestamp/status/count columns as `PassThrough`.
3. Mark sensitive identity/host/IP/secret columns as `WholeColumnRules`.
4. Add label rules for repeated `label=value` or `Label: value` patterns.
5. Add seed terms for names and terms with no reliable pattern.
6. Add allowlists for public diagnostics.
7. Re-run dry-run and repeat until the preview looks right.

## Decision Tree

Use `SchemaColumns` when:

- A column should be passed through because it is analytical.
- A column should be scanned as free text.
- A JSON key should be handled like a column.

Use `WholeColumnRules` when:

- Every value in the column is sensitive.
- Examples include `UserID`, `UserName`, `Machine`, `Server`, `ClientIP`,
  `APIKey`, `Tenant`, `SessionId`, and `CorrelationId`.

Use `LabelRules` when:

- The sensitive value appears after a label inside text.
- Examples include `username=alice`, `host: app01`, `API Key = abc123`, and
  `tenantId=contoso`.

Use `CustomRegexRules` when:

- The value follows a local pattern that generic detectors cannot know.
- Examples include `CASE-123456`, `ASSET-AB12-CD34`, or local transaction IDs.

Use seed files when:

- The value is just a word or phrase.
- Examples include organization names, project names, vendor nicknames, tenant
  display names, and product names.

Use allowlists when:

- A public value is useful for analysis and safe to preserve.
- Examples include loopback IPs, health-check words, public domains, methods,
  and status names.

## Schema Columns

```json
"SchemaColumns": [
  { "Exact": "Timestamp", "Action": "PassThrough", "Description": "Analytical time." },
  { "Wildcard": "*Message*", "Action": "Scan", "Description": "Free text." },
  { "Regex": "(?i)^(status|method|level)$", "Action": "PassThrough" }
]
```

Actions:

- `PassThrough`: keep the value unchanged.
- `Scan`: scan the value as free text.
- `Scrub`: tokenize the whole value.

Matching:

- `Exact`: one exact column/key name.
- `Wildcard`: shell-style wildcard such as `*Message*`.
- `Regex`: .NET/PowerShell regular expression.

## Whole Column Rules

```json
"WholeColumnRules": [
  { "Regex": "(?i)^(user(id|name)?|account|principal)$", "Prefix": "PRINCIPAL" },
  { "Regex": "(?i)^(host|server|machine|device|node)$", "Prefix": "DNS" },
  { "Regex": "(?i)^(clientip|src_ip|dst_ip|ipaddress)$", "Prefix": "IP", "SplitOn": "[;,|]" },
  { "Regex": "(?i)(api[_ -]?key|token|secret|password)", "Prefix": "SECRET" }
]
```

`SplitOn` is useful when a column contains a list. Each item gets its own token.

## Label Rules

```json
"LabelRules": [
  { "Name": "Users", "Labels": [ "username", "user", "account" ], "Prefix": "PRINCIPAL" },
  { "Name": "Hosts", "Labels": [ "host", "server", "node" ], "Prefix": "DNS" },
  { "Name": "Addresses", "Labels": [ "src_ip", "dst_ip", "client address" ], "Prefix": "IP" },
  { "Name": "Secrets", "Labels": [ "API Key", "api_key", "client_secret" ], "Prefix": "SECRET" }
]
```

Defaults handle `:` and `=` separators. Use `SeparatorRegex` only when the log
uses a different separator. Use `ValueRegex` only when the value boundary is
unusual.

## Custom Regex Rules

This tokenizes only capture group 2, keeping the label readable:

```json
"CustomRegexRules": [
  {
    "Name": "LocalTicketId",
    "Regex": "(?i)\\b(ticket[_ -]?id\\s*[:=]\\s*)(TKT-[0-9]{6})\\b",
    "CaptureGroup": 2,
    "Prefix": "OBJECT",
    "Keywords": [ "ticket", "TKT-" ],
    "Entropy": 0,
    "Allowlist": [ "TKT-000000" ]
  }
]
```

Tips:

- Use `Keywords` to avoid running expensive regexes on every line.
- Use `CaptureGroup` when only part of a match is sensitive.
- Use `Entropy` for secret-like values, not for human-readable IDs.
- Keep custom regexes local and simple; broad patterns can over-scrub.

## Seed Strategy

Seed files are plain text:

```text
# One term per line
ExampleCorp
ProjectFalcon
LegacyVendorName
internal-product-code
```

Good seed terms:

- Client or organization names.
- Project names.
- Tenant display names.
- Vendor nicknames.
- Internal product names.

Avoid seed terms that are too short or too generic, such as `app`, `prod`,
`server`, or `admin`, unless your policy truly requires them.

## Allowlist Strategy

Allowlist files are also plain text:

```text
127.0.0.1
::1
public.example.com
domain:microsoft.com
regex:^(health|ready|live)$
regex:^build-[0-9]+$
```

Use exact values for one known value. Use `domain:` for a public domain and its
subdomains. Use `regex:` for repeated public diagnostics.

Do not allowlist private hosts, client domains, private IPs, usernames, tenant
names, or secrets.

## Copy/Paste Profiles

CSV schema-driven profile:

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
    { "Exact": "Server", "Prefix": "DNS" },
    { "Exact": "ClientIP", "Prefix": "IP" },
    { "Exact": "APIKey", "Prefix": "SECRET" }
  ],
  "SeedFiles": [ "seed.example.txt" ],
  "AllowlistFile": [ "allowlist.example.txt" ]
}
```

JSON/application profile:

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
  ]
}
```

key=value profile:

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

## Troubleshooting

Profile will not load:

- Run `Test-ScrubProfile -Path C:\profiles\profile.json`.
- Check JSON commas and quotes.
- Check `Prefix` values. Valid examples include `PRINCIPAL`, `DNS`, `IP`,
  `SECRET`, `X500`, `URI`, and `OBJECT`.

Dry-run misses a value:

- Add a seed if it is a shapeless word or name.
- Add a label rule if it follows a label.
- Add a whole-column rule if the whole column is sensitive.
- Add a custom regex if it follows a local format.

Dry-run scrubs too much:

- Add pass-through schema columns for harmless analytical fields.
- Add allowlists for public diagnostics.
- Try `Balanced` before `Strict`.

Generated profile is too broad:

- Remove generic `GeneratedShape*` custom regexes that are not useful.
- Tighten column rules from `Wildcard` or `Regex` to `Exact`.
- Keep the profile build report local and use it only as evidence while tuning.

## Example Files

This folder includes ready-to-edit examples:

- `csv-schema-profile.json`
- `json-app-profile.json`
- `kv-log-profile.json`
- `webaccess-profile.json`
- `seed.example.txt`
- `allowlist.example.txt`

# v4.15 Profile Extensions

Use `-ProfileExtensionFile` when a built-in profile is close but your organization has extra fields, labels, ticket templates, or vendor identifiers that should be scrubbed. Extensions are additive overlays; they do not replace the selected profile.

Example:

```powershell
Invoke-UniversalScrubber `
  -Path .\exports\incidents.csv `
  -Profile ServiceNow `
  -ProfileExtensionFile .\docs\profiles\profile-extension-example.json `
  -SaltFile .\salt.txt `
  -NonInteractive
```

Profile builder can also start from a built-in profile and merge extension rules into a standalone editable profile:

```powershell
Invoke-UniversalScrubber `
  -BuildProfileFromSample `
  -Path .\samples\logs\servicenow_incidents.csv `
  -BaseProfile ServiceNow `
  -ProfileExtensionFile .\docs\profiles\profile-extension-example.json `
  -ProfileOut .\servicenow-custom.json `
  -Force `
  -NonInteractive
```

Prefer profile extensions for local edge cases instead of making default detection broader. That keeps `Balanced` mode predictable and reduces false positives for everyone.
