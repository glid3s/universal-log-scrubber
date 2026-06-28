# Changelog

## v4.13.0

- Retired versioned module and launcher filenames for the stable package layout:
  `UniversalLogScrubber\UniversalLogScrubber.psd1` now imports
  `UniversalLogScrubber.psm1`, and the launcher is
  `scripts\Run-UniversalScrubber.ps1`.
- Added ULS-prefixed aliases for command discovery while keeping existing
  command names canonical.
- Added `Invoke-UniversalScrubber -Version` and
  `Invoke-UniversalLogScrubber -Version`.
- Consolidated duplicate hotfix override functions and moved module exports to
  the true end of the module.
- Added conservative JSON numeric scrubbing for sensitive-looking keys while
  preserving benign counts, ports, status codes, timings, sizes, and versions.
- Expanded connection URI host detection for JDBC, database, cache, queue,
  Kafka, and WS/WSS-style schemes.
- Added progress feedback for external corpus smoke tests, W3C conversion,
  large text/KV discovery, and normal text/KV scrubbing phases.
- Corrected external corpus documentation and refreshed v4.13.0 workflow and
  PR testing references.

## v4.12

- Added a curated external corpus catalog via `Get-LogCorpusCatalog` and
  `Search-LogCorpusCatalog`.
- Added `Save-LogCorpusSample` for explicit-risk, opt-in public sample downloads
  and manual-download instruction manifests.
- Added `Invoke-ExternalCorpusSmokeTest` for optional local recommendation and
  dry-run checks over externally downloaded corpus folders.
- Added `scripts\Get-SampleLogs.ps1` as a friendly catalog/search/save wrapper.
- Ignored `samples/external-corpora/` and `external-corpus-results/` so public
  corpora and smoke-test outputs do not get committed.
- Bumped the versioned module and launcher names to v4.12.

## v4.11

- Added `Test-LogFormat` for local-only log format and profile recommendations.
- Added `-RecommendOnly` and `-SafeFirstRun` to show recommendations before salt,
  token-map, report, bundle, or scrubbed-output work begins.
- Added `-AutoProfile` for uniform, high-confidence inputs, with a clear
  noninteractive stop for mixed or low-confidence folders.
- Added recommendation coverage for CSV, TSV, PSV, JSON, JSONL/NDJSON, W3C/IIS,
  CEF, LEEF, logfmt, Apache/Nginx-like access logs, syslog-like logs, EVTX,
  XLSX, Windows Event CSV, AD CS CSV, and generic text fallback.
- Bumped the versioned module and launcher names to v4.11.

## v4.10

- Added `New-ScrubProfileFromSample` and launcher support via
  `-BuildProfileFromSample` for local sample-log profile generation.
- Added analyzer-only profile generation that writes raw sample evidence only to
  `profile_build_report_DO_NOT_UPLOAD.md`, not to the generated profile.
- Added optional `-ProfileWizard` support for user-selected seed and allowlist
  file generation.
- Added `Test-ScrubProfile` for profile validation without running a scrub.
- Added `-SafeBundleOut` for safe upload zip creation from clean scrubbed
  outputs only.
- Improved dry-run summaries with high-confidence, review-needed, and preserved
  value counts.
- Expanded `USAGE.md` for non-technical workflows and expanded
  `docs/profiles/README.md` into a BYOP handbook.
- Added GitHub Actions self-test workflow.

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

