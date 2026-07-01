<#
.SYNOPSIS
  Launcher for the Universal Log Scrubber. Just run it.

.DESCRIPTION
  Imports the packaged UniversalLogScrubber module and starts the interactive,
  hand-held scrubbing flow. Any switch you pass is forwarded;
  anything still required is prompted for.

.EXAMPLE
  .\Run-UniversalScrubber.ps1
  # Fully interactive.

.EXAMPLE
  .\Run-UniversalScrubber.ps1 -Path C:\winlogs\Security.evtx
  # Auto-converts the .evtx to CSV, then scrubs it.

.EXAMPLE
  .\Run-UniversalScrubber.ps1 -Path C:\logs -DryRun -ExplainDetections
  # Preview what WOULD be tokenized -- writes nothing.
#>
[CmdletBinding()]
param(
    [switch]$Version,
    [string]$Path,
    [string]$WorkDir,
    [switch]$RecommendOnly,
    [switch]$SafeFirstRun,
    [switch]$AutoProfile,
    [string]$Salt,
    [int]$HmacLength = 24,
    [string]$Profile,
    [string]$ProfileFile,
    [string[]]$ProfileExtensionFile,
    [string]$TokenMapCsv,
    [ValidateSet('Discover','ExistingMap','AD')][string]$MapSource,
    [ValidateSet('Merge','Replace')][string]$TokenMapMode = 'Merge',
    [string[]]$SensitiveTerms,
    [Alias('SeedTermsFile')][string[]]$SensitiveTermsFile,
    [string[]]$SeedFile,
    [string[]]$AllowlistFile,
    [ValidateSet('Generic','Csv','Json','Kv','WebAccess','Cloud','App')][string]$ProfileTemplate,
    [switch]$BuildProfileFromSample,
    [string]$ProfileOut,
    [string]$ProfileReportOut,
    [string]$BaseProfile,
    [switch]$ProfileWizard,
    [int]$MaxSampleRows = 500,
    [ValidateSet('Auto','Csv','Json','Kv','Text')][string]$SampleFormat = 'Auto',
    [switch]$ProtectGeneratedProfile,
    [string]$SafeBundleOut,
    [switch]$Force,
    [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = 'Balanced',
    [ValidateSet('Fast','CountFirst')][string]$EvtxProgressMode = 'Fast',
    [switch]$ExplainDetections,
    [string]$FalsePositiveReport,
    [string]$DetectionSummaryReport,
    [string]$SaltFromEnv,
    [string]$SaltFile,
    [switch]$KeepIntermediate,
    [switch]$ConvertEtl,
    [ValidateSet('Auto','GetWinEvent','Tracerpt')][string]$EtlConverter = 'Auto',
    [string]$TracerptPath,
    [switch]$Recurse,
    [string[]]$Include,
    [string[]]$Exclude,
    [switch]$DryRun,
    [switch]$Stream,
    [switch]$NoCorrelate,
    [switch]$SkipLeakCheck,
    [switch]$PerfReport,
    [switch]$PerfReportDetailed,
    [ValidateSet('PowerShell','Auto','Python')][string]$ProcessingEngine = 'PowerShell',
    [string]$PythonPath,
    [int]$PythonMinSpeedupPercent = 15,
    [switch]$ParallelScrub,
    [switch]$NoParallelScrub,
    [switch]$ParallelDiscovery,
    [switch]$NoParallelDiscovery,
    [switch]$DiscoveryOnly,
    [int]$ThrottleLimit = 4,
    [int]$ChunkSize = 0,
    [int]$LargeFileThresholdMB = 100,
    [string]$WorkerProgressFile,
    [int]$WorkerProgressRowsTotal = 0,
    [int]$WorkerProgressChunk = 0,
    [int]$WorkerProgressIntervalRows = 250,
    [int]$WorkerProgressIntervalSeconds = 1,
    [switch]$NonInteractive
)

$ErrorActionPreference = 'Stop'

# Prefer the packaged repository layout: scripts\ launcher, UniversalLogScrubber\ module.
$repoRoot = Split-Path -Parent $PSScriptRoot
$candidatePaths = @(
    (Join-Path $repoRoot 'UniversalLogScrubber\UniversalLogScrubber.psd1'),
    (Join-Path $repoRoot 'UniversalLogScrubber\UniversalLogScrubber.psm1'),
    (Join-Path $PSScriptRoot 'UniversalLogScrubber.psd1'),
    (Join-Path $PSScriptRoot 'UniversalLogScrubber.psm1')
)

$modulePath = $candidatePaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

if (-not $modulePath) {
    Write-Host "Cannot find UniversalLogScrubber.psd1 or UniversalLogScrubber.psm1." -ForegroundColor Red
    Write-Host "Keep this launcher with the packaged UniversalLogScrubber module folder." -ForegroundColor Yellow
    exit 1
}

Import-Module $modulePath -Force

# Forward only the parameters the user actually supplied.
$forward = @{}
foreach ($k in $PSBoundParameters.Keys) { $forward[$k] = $PSBoundParameters[$k] }
Invoke-UniversalScrubber @forward


