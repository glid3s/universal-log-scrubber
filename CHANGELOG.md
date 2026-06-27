# Changelog

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
