# BYOP Profile Examples

These examples are safe synthetic templates. Copy one into a private working
folder, edit the labels/columns/regexes for your log source, then run a dry run
with `-ProfileFile`.

Recommended first pass:

```powershell
.\scripts\Run-UniversalScrubber_v4_9.ps1 `
  -Path C:\logs `
  -WorkDir C:\scrubbed-preview `
  -ProfileFile C:\profiles\csv-schema-profile.json `
  -SeedFile C:\profiles\seed.example.txt `
  -AllowlistFile C:\profiles\allowlist.example.txt `
  -DryRun `
  -ExplainDetections `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

Keep profile-specific seed and allowlist files private if they include client,
organization, project, host, tenant, or vendor names.
