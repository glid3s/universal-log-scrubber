# Changelog

## v4.9

- Added BYOP profile schema v2 with schema-column rules, whole-column rules,
  label rules, custom regex rules, seed terms/files, and allowlists.
- Added `-SeedFile`, alias-friendly `-SensitiveTermsFile`, `-AllowlistFile`,
  and `-ProfileTemplate`.
- Generalized Windows Event label-aware detection into universal label/value
  detection across CSV cells, JSON values, key=value logs, and free text.
- Added built-in non-Windows profile presets for web access/proxy, cloud audit,
  firewall, VPN, app JSON, database, container, Kubernetes, and identity-provider
  logs.
- Added keyword-prefiltered custom regex detectors with capture groups,
  optional entropy thresholds, and rule allowlists.
- Added seed-file merging for discovery, scrubbing, dry-run preview, and leak
  checks.
- Improved dry-run summaries with detector counts and streaming CSV dry-run
  scanning.
- Added synthetic self-test coverage for schema v2 profiles, seed files,
  allowlists, custom regex rules, universal labels, v4.8 profile compatibility,
  and invalid-profile errors.
- Added `docs/profiles/` with ready-to-edit BYOP examples.

## v4.8

- Added safer token-map merge/replace behavior with atomic writes and backups.
- Added token-map metadata for salt fingerprint, HMAC length, source tracking,
  and source path hashes.
- Added collision-safe output names for same-basename inputs.
- Streamed EVTX conversion with progress feedback and optional count-first mode.
- Improved Windows Event label-aware detection for bare account and host values.
- Preserved common diagnostic/public values to reduce false positives.
- Added offline secret detection for auth headers, key fields, connection
  strings, private keys, and common provider token shapes.
- Added counts-only detection summary reports.
- Raised default HMAC token length for new runs to 24 hex characters.
