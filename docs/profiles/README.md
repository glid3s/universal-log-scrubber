# Profile Examples

This folder contains ready-to-edit BYOP profile and extension examples.

For the full BYOP walkthrough, tuning workflow, and enterprise starter guidance,
see the [BYOP Profile Authoring wiki page](https://github.com/glid3s/universal-log-scrubber/wiki/BYOP-Profile-Authoring).

## Safety

Profiles are safer than token maps, but they can still reveal local schema names,
vendor fields, tenant labels, and internal workflow shape. Review profiles before
sharing them. Keep token maps, salts, manifests, detailed reports, and profile
build reports local-only.

## Full Profile Examples

- `csv-schema-profile.json`: schema-first CSV profile with pass-through,
  scan, and whole-column rules.
- `json-app-profile.json`: application JSON/JSONL profile starter.
- `kv-log-profile.json`: key=value/logfmt profile starter.
- `webaccess-profile.json`: web access/proxy profile starter.

## Extension Examples

Use `-ProfileExtensionFile` when a built-in profile is close but your
organization has extra fields, labels, ticket templates, or vendor identifiers
that should be scrubbed. Extensions are additive overlays; they do not replace
the selected profile.

- `profile-extension-example.json`: small generic overlay example.
- `servicenow-local-extension.json`: ServiceNow local asset, requester,
  work-note, and vendor ticket fields.
- `endpoint-management-extension.json`: Nexthink, SCCM/MECM, and Intune
  endpoint export overlays.
- `security-audit-extension.json`: identity, Sentinel, cloud audit, EDR, and
  XDR alert overlays.
- `network-edge-extension.json`: firewall, proxy, VPN, gateway, and key=value
  network edge overlays.

Example:

```powershell
Invoke-UniversalScrubber `
  -Path .\exports\incidents.csv `
  -Profile ServiceNow `
  -ProfileExtensionFile .\docs\profiles\servicenow-local-extension.json `
  -SaltFile .\salt.txt `
  -NonInteractive
```

You can layer more than one extension when one file is shared across a team and
another is local to a specific export:

```powershell
Invoke-UniversalScrubber `
  -Path .\exports\security-alerts.jsonl `
  -Profile Edr `
  -ProfileExtensionFile .\docs\profiles\security-audit-extension.json,.\local-queue-extension.json `
  -SaltFile .\salt.txt `
  -NonInteractive
```

## Seeds And Allowlists

- `seed.example.txt`: example private seed terms for shapeless values that
  patterns cannot infer.
- `allowlist.example.txt`: example public diagnostics that can stay readable
  after review.

Keep real seed files private unless they have been reviewed for sharing.

## Validate Examples

Validate full profiles:

```powershell
Import-Module .\UniversalLogScrubber\UniversalLogScrubber.psd1 -Force
Test-ScrubProfile -Path .\docs\profiles\csv-schema-profile.json
```

Validate extension files by importing them:

```powershell
Import-Module .\UniversalLogScrubber\UniversalLogScrubber.psd1 -Force
Import-ScrubProfileExtensionFile -Path .\docs\profiles\servicenow-local-extension.json
```
