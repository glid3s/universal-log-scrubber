# Changelog

## v4.15.0

- Added unified compact progress feedback across discovery, streaming scrub,
  streaming parallel scrub, conversion, verification, and smoke-test paths.
- Added native OpenXML text extraction for DOCX and PPTX files. Extracted text
  intermediates are local-only and UNSCRUBBED until the scrub step completes.
- Added profile recommendations and built-in profiles for ServiceNow,
  Nexthink, SCCM/MECM, Intune CSV exports, and Intune Diagnostics text/report
  bundles.
- Added recommendation guardrails for ETL traces and CAB archives so users
  convert or extract approved contents instead of scrubbing binary containers.
- Kept XLSX conversion local and documented first-worksheet behavior.
- Extended offline self-tests for fast CSV parsing, ordered streaming parallel
  CSV output, DOCX/PPTX extraction, enterprise profiles, Intune Diagnostics,
  progress formatting, and v4.14 precision regressions.
- Fixed built-in custom regex profile initialization so built-in and BYOP
  custom regex rules use the same compiled runtime path.
- Tightened enterprise profile precision, including SCCM numeric ID
  pass-through and MAC/serial token prefix handling.
- Removed retired public-log catalog/download helper commands and wrapper script;
  use the committed synthetic samples or approved local logs for additional
  testing.

## v4.14.0

- Made Balanced mode more conservative for default auto-detection, moving broad
  edge-case identifiers toward BYOP or Strict mode.
- Specialized Windows Event CSV scrubbing to preserve operational metadata,
  provider names, event IDs, levels, timestamps, well-known Windows identities,
  and provider/template GUIDs by default.
- Reworked CSV-family `-ParallelScrub` to use in-process ordered streaming
  batches instead of disk chunk copies.
- Added faster streaming CSV parsing with coverage for quoted commas, doubled
  quotes, empty cells, and multiline quoted fields.
- Added `-SkipLeakCheck` support for trusted repeat runs while keeping the
  independent leak check default-on.
- Improved URL/connection host, IPv6 validation, JSON numeric, and
  Windows-event false-positive behavior.

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
- Added progress feedback for W3C conversion, large text/KV discovery, and
  normal text/KV scrubbing phases.

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

# Universal Log Scrubber v4.15.0

## Added

- Added native, opt-in ETL intake through Windows `tracerpt.exe`. `.etl` files are detected and recommended, but conversion only runs when `-ConvertEtl` is supplied.
- Added `-ProfileExtensionFile` for lightweight additive BYOP overlays. Extensions can add column rules, label rules, custom regexes, seed files, and allowlists without copying an entire profile.
- Added `-BaseProfile` support for sample-built BYOP profiles so generated profiles can start from a built-in profile and then become standalone editable JSON.
- Added built-in recommendations/profiles for firewall/VPN text, structured firewall CSV exports, SCCM/ConfigMgr CMTrace-style text, EDR/XDR JSONL, Intune diagnostics, M365/identity audit exports, ServiceNow, Nexthink, and Intune exports.
- Added synthetic samples for Intune registry, HTML, and XML diagnostics.

## Changed

- Kept `Balanced` conservative by default: high-confidence sensitive values are scrubbed, while broad GUID/hash/object/IPv6/dotted-name detections stay behind stronger context, `Strict`, or BYOP.
- Improved Windows Event CSV handling for structured `EventDataJson`, System/PowerShell-style messages, provider metadata preservation, and sensitive machine/user/IP/command/script residue.
- Improved large-file CSV/text paths to favor streaming and in-process batch work instead of full-file materialization or disk chunk duplication.
- Unified progress messages around compact phase/file/rate/row/worker status so long operations stay readable.

## Fixed

- Fixed JSON/JSONL dry-run change accounting so nested Sentinel/EDR/app JSON changes are counted and shown.
- Reduced false positives from broad network column matching, especially fields such as `description` and `subscription`.
- Preserved operational metadata for enterprise exports while still tokenizing users, UPN/email, devices, hosts, private IPs, URLs/connection hosts, serial-like identifiers, secrets, comments, work notes, and diagnostic free text.
