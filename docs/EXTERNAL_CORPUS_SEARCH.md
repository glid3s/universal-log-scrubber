# External Corpus Search and Smoke Testing

Universal Log Scrubber includes external corpus helpers for finding, downloading, and smoke-testing public sample logs against the scrubber.

These helpers are intended for testing detector behavior, validating false-positive handling, and building confidence that new scrubber changes work across real-world log formats.

External corpus support is especially useful when you want to answer questions like:

* Does the scrubber correctly tokenize IP addresses, domains, usernames, paths, emails, URLs, and secrets?
* Are detector explanations understandable?
* Are false positives preserved when they are obviously non-sensitive diagnostic or file-like values?
* Does a profile behave safely across different log families?
* Can a scrubbed output leave the local machine without leaking raw sensitive values?

## Safety warning

Public log corpora may contain real-looking or real operational data. Treat downloaded corpus files as untrusted input.

Do not upload raw external corpus files, token maps, detection review reports, or false-positive reports to third-party systems unless you have reviewed and approved them.

The following files should normally stay local:

* `token_map*.csv`
* `*_DO_NOT_UPLOAD.csv`
* `detection_review_DO_NOT_UPLOAD.csv`
* false-positive review reports
* raw downloaded corpus logs
* raw extracted archives
* local work folders containing unsanitized inputs

Scrubbed outputs are safer, but they should still be reviewed before sharing.

## Static catalog vs online search

The scrubber supports two types of corpus discovery.

### Static catalog

The static catalog contains curated entries built into the module.

Use it when you want known, stable corpus sources:

```powershell
Get-LogCorpusCatalog
```

Search the static catalog:

```powershell
Search-LogCorpusCatalog -Query Apache
Search-LogCorpusCatalog -Query OpenSSH
```

### Online LogHub search

Online search queries the LogHub repository live and returns available datasets and files.

Use it when you want to browse or search available LogHub datasets such as Apache, Android, Linux, OpenSSH, Windows, Zookeeper, and others.

```powershell
Search-LogCorpusCatalog -Online -Query Android |
  Select-Object Name,Dataset,FileName,SuggestedProfile,ApproxSize |
  Format-Table -AutoSize
```

Search a specific dataset:

```powershell
Search-LogCorpusCatalog -Online -Dataset Zookeeper |
  Select-Object Name,Dataset,FileName,SuggestedProfile,ApproxSize |
  Format-Table -AutoSize
```

Refresh online results instead of using cached results:

```powershell
Search-LogCorpusCatalog -Online -Refresh -Dataset Apache |
  Format-Table -AutoSize
```

## Common search examples

Find Apache corpus entries:

```powershell
Search-LogCorpusCatalog -Online -Query Apache |
  Select-Object Name,Dataset,FileName,SuggestedProfile,ApproxSize |
  Format-Table -AutoSize
```

Find Android logs:

```powershell
Search-LogCorpusCatalog -Online -Query Android |
  Select-Object Name,Dataset,FileName,SuggestedProfile,ApproxSize |
  Format-Table -AutoSize
```

List Zookeeper files:

```powershell
Search-LogCorpusCatalog -Online -Dataset Zookeeper |
  Select-Object Name,Dataset,FileName,SuggestedProfile,ApproxSize |
  Format-Table -AutoSize
```

Get the full online catalog:

```powershell
Get-LogCorpusCatalog -Online -Refresh |
  Select-Object Name,Dataset,FileName,SuggestedProfile,ApproxSize |
  Format-Table -AutoSize
```

## Understanding search results

Typical result fields include:

| Field              | Meaning                                                                 |
| ------------------ | ----------------------------------------------------------------------- |
| `Name`             | The scrubber’s corpus entry name.                                       |
| `Dataset`          | The LogHub dataset folder, such as `Apache`, `Android`, or `Zookeeper`. |
| `FileName`         | The source file name in the corpus.                                     |
| `SuggestedProfile` | The scrubber profile that is likely appropriate for the file.           |
| `ApproxSize`       | Approximate file size when available.                                   |
| `SourceUrl`        | The raw download URL or source location.                                |
| `Provider`         | The corpus provider, such as LogHub.                                    |

The suggested profile is a convenience hint. It is not a safety guarantee. You can override the profile during testing.

## Downloading a corpus sample

External downloads require `-AcceptRisk`.

This is intentional. It makes the risk boundary explicit because downloaded public corpus files may contain raw operational data.

Example:

```powershell
$root = "C:\Users\$env:USERNAME\Documents\Universal Log Scrubber\samples\external-corpora"

Save-LogCorpusSample `
  -Name Loghub-Apache `
  -OutputDirectory $root `
  -AcceptRisk
```

For online LogHub entries, first find the exact entry name:

```powershell
Search-LogCorpusCatalog -Online -Dataset Apache |
  Select-Object Name,Dataset,FileName,SuggestedProfile,ApproxSize |
  Format-Table -AutoSize
```

Then save the selected entry:

```powershell
Save-LogCorpusSample `
  -Online `
  -Name "LogHub-Apache-Apache_2k.log" `
  -OutputDirectory "C:\Users\$env:USERNAME\Documents\Universal Log Scrubber\samples\external-corpora" `
  -AcceptRisk
```

The exact `Name` depends on the online result returned by the catalog.

## Archive extraction

Some corpus entries may be archives.

Use `-ExtractArchive` when you want the helper to extract supported archive formats after download:

```powershell
Save-LogCorpusSample `
  -Online `
  -Name "LogHub-SomeDataset-SomeArchive.zip" `
  -OutputDirectory "C:\Users\$env:USERNAME\Documents\Universal Log Scrubber\samples\external-corpora" `
  -AcceptRisk `
  -ExtractArchive
```

Supported extraction behavior may include:

* `.zip`
* single-file `.gz`
* `.tar`
* `.tgz`
* `.tar.gz`, when `tar.exe` is available

After extraction, inspect the output folder before running a broad recursive test.

## Running a smoke test

Use `Invoke-ExternalCorpusSmokeTest` after downloading one or more corpus samples.

Example:

```powershell
$corpusRoot = "C:\Users\$env:USERNAME\Documents\Universal Log Scrubber\samples\external-corpora"
$outRoot = "C:\Users\$env:USERNAME\Documents\Universal Log Scrubber\external-corpus-results"

Invoke-ExternalCorpusSmokeTest `
  -Path $corpusRoot `
  -OutputDirectory $outRoot `
  -Salt "external-corpus-preview-only" `
  -Profile Text `
  -Recurse
```

The smoke test writes local summary files such as:

* `external-corpus-summary.csv`
* `external-corpus-summary.json`
* `external-corpus-summary.md`

These summaries are useful for reviewing what was tested and whether the scrubbed outputs were clean.

## Testing one downloaded file directly

For targeted testing, run `Invoke-UniversalScrubber` directly against a specific log file.

Example with Apache:

```powershell
$apacheLog = "C:\Users\$env:USERNAME\Documents\Universal Log Scrubber\samples\external-corpora\Loghub-Apache\Apache_2k.log"
$work = "C:\Users\$env:USERNAME\Documents\Universal Log Scrubber\external-corpus-results\Loghub-Apache-test"

Invoke-UniversalScrubber `
  -Path $apacheLog `
  -Profile Text `
  -WorkDir $work `
  -Salt "external-corpus-preview-only" `
  -MapSource Discover `
  -DryRun `
  -ExplainDetections `
  -NonInteractive
```

## Detection review report

When `-ExplainDetections` is used and no explicit false-positive report path is supplied, the scrubber writes a local review report automatically:

```text
detection_review_DO_NOT_UPLOAD.csv
```

This report includes both tokenized detections and preserved values.

Example columns include:

| Column     | Meaning                                       |
| ---------- | --------------------------------------------- |
| `Detector` | The detector or shape that matched the value. |
| `Action`   | `Tokenized` or `Preserved`.                   |
| `Value`    | The original detected value.                  |
| `Token`    | The replacement token, when applicable.       |
| `Reason`   | Why the value was tokenized or preserved.     |
| `Column`   | The source column, when available.            |
| `Context`  | Nearby context, when available.               |

Example review rows:

```text
IPv4  Tokenized  208.51.151.210       IP_...  Shape detector
FQDN  Preserved  workerEnv.init        Discovery preserve
FQDN  Preserved  workers2.properties   Discovery preserve
```

The detection review report is deduplicated. Repeated values are counted internally, but the same detector/action/value/token/reason combination is only listed once in the report.

## Reviewing detection explanations

View the detection review report:

```powershell
$work = "C:\Users\$env:USERNAME\Documents\Universal Log Scrubber\external-corpus-results\Loghub-Apache-test"

Import-Csv (Join-Path $work "detection_review_DO_NOT_UPLOAD.csv") |
  Select-Object Detector,Action,Value,Token,Reason |
  Format-Table -AutoSize
```

Check for duplicate review rows:

```powershell
Import-Csv (Join-Path $work "detection_review_DO_NOT_UPLOAD.csv") |
  Group-Object Detector,Action,Value,Token,Reason |
  Where-Object Count -gt 1 |
  Select-Object Count,Name |
  Format-Table -AutoSize
```

Expected result: no rows.

## Recommended workflow

A safe external corpus workflow looks like this:

1. Search for a dataset.
2. Download one corpus sample with `-AcceptRisk`.
3. Inspect the downloaded file locally.
4. Run a dry run with `-ExplainDetections`.
5. Review `detection_review_DO_NOT_UPLOAD.csv`.
6. Confirm false positives are preserved or understood.
7. Run a real scrub only after the dry run looks correct.
8. Review scrubbed output before sharing.
9. Keep token maps and review reports local.

Example:

```powershell
Search-LogCorpusCatalog -Online -Dataset Apache |
  Select-Object Name,Dataset,FileName,SuggestedProfile,ApproxSize |
  Format-Table -AutoSize

Save-LogCorpusSample `
  -Online `
  -Name "LogHub-Apache-Apache_2k.log" `
  -OutputDirectory "C:\Users\$env:USERNAME\Documents\Universal Log Scrubber\samples\external-corpora" `
  -AcceptRisk

$apacheLog = "C:\Users\$env:USERNAME\Documents\Universal Log Scrubber\samples\external-corpora\LogHub-Apache\Apache_2k.log"
$work = "C:\Users\$env:USERNAME\Documents\Universal Log Scrubber\external-corpus-results\LogHub-Apache-review"

Invoke-UniversalScrubber `
  -Path $apacheLog `
  -Profile Text `
  -WorkDir $work `
  -Salt "external-corpus-preview-only" `
  -MapSource Discover `
  -DryRun `
  -ExplainDetections `
  -NonInteractive

Import-Csv (Join-Path $work "detection_review_DO_NOT_UPLOAD.csv") |
  Select-Object Detector,Action,Value,Token,Reason |
  Format-Table -AutoSize
```

## Folder safety and generated artifacts

The scrubber tries to avoid reprocessing generated artifacts such as:

* scrubbed outputs
* token maps
* detection reports
* false-positive reports
* corpus manifests
* external corpus summaries
* local build or generated profile artifacts
* archives such as `.zip`

This prevents folder-based tests from accidentally treating generated reports as new raw input.

Even with this protection, review the target folder before recursive runs.

## Troubleshooting

### Online search returns no results

Try refreshing:

```powershell
Search-LogCorpusCatalog -Online -Refresh -Query Apache
```

Try searching by dataset:

```powershell
Search-LogCorpusCatalog -Online -Refresh -Dataset Apache
```

Check internet access and GitHub availability.

### GitHub API rate limiting

Online catalog search uses unauthenticated GitHub access. If you run repeated searches quickly, GitHub may rate-limit requests.

Wait and retry, or use static catalog entries when possible.

### A downloaded file is not the log I expected

Run the search again and inspect the returned `Name`, `Dataset`, `FileName`, and `SourceUrl`.

```powershell
Search-LogCorpusCatalog -Online -Dataset Apache |
  Select-Object Name,Dataset,FileName,SourceUrl |
  Format-List
```

### Detection report shows preserved values

That is expected. The report is meant to show both positive tokenizations and preservation decisions.

Preservation rows are useful because they explain why values such as local diagnostic names, method-like identifiers, or known file names were not tokenized.

### Detection report has duplicate values

The report should be deduplicated by detector, action, value, token, reason, and column. If duplicates appear, rerun the latest module and confirm self-tests pass:

```powershell
Import-Module .\src\UniversalLogScrubber_v4_12.psm1 -Force
Invoke-ScrubSelfTest
```

### PowerShell blocks the module as unsigned

If the module was downloaded or copied from the internet, Windows may mark it as blocked.

For the current PowerShell session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Unblock-File .\src\UniversalLogScrubber_v4_12.psm1
Import-Module .\src\UniversalLogScrubber_v4_12.psm1 -Force
```

## What good output looks like

For an Apache-style sample, a clean dry-run review might show:

```text
IPv4  Tokenized  208.x.x.x              IP_...  Shape detector
FQDN  Preserved  workerEnv.init         Discovery preserve
FQDN  Preserved  workers2.properties    Discovery preserve
```

A successful smoke test should produce local summary files and should not report obvious raw IPs, emails, URLs, domains, secrets, or private keys remaining in scrubbed output.

Always review the generated summaries and scrubbed files before sharing anything outside your environment.
