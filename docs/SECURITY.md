# Security Notes

Universal Log Scrubber is designed for local/offline use in secure
environments. It does not perform network validation of secrets.

## Never Upload

- Raw logs.
- Token maps.
- Salts or salt files.
- Detailed detection review reports.
- Any file marked `DO_NOT_UPLOAD`.
- Generated manifests from sensitive runs unless reviewed and approved by the
  owning environment.

## Review Guidance

Use dry runs and local-only detection reports to tune seed terms before sharing
scrubbed logs. For highly sensitive clients, pair the automated leak check with
manual review of representative rows, especially free-text message fields.

## Reporting Issues

When reporting a bug publicly, use synthetic examples. Do not include customer
logs, production hostnames, usernames, domains, tokens, paths, or screenshots
that may contain sensitive data.
