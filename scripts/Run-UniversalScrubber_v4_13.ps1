<#
.SYNOPSIS
  Launcher for the Universal Log Scrubber. Just run it.

.DESCRIPTION
  Imports the matching UniversalLogScrubber_*.psm1 (derived from THIS launcher's
  own filename, so the .ps1 and .psm1 versions can never drift apart) and starts
  the interactive, hand-held scrubbing flow. Any switch you pass is forwarded;
  anything still required is prompted for.

.EXAMPLE
  .\Run-UniversalScrubber_v4_13.ps1
  # Fully interactive.

.EXAMPLE
  .\Run-UniversalScrubber_v4_13.ps1 -Path C:\winlogs\Security.evtx
  # Auto-converts the .evtx to CSV, then scrubs it.

.EXAMPLE
  .\Run-UniversalScrubber_v4_13.ps1 -Path C:\logs -DryRun -ExplainDetections
  # Preview what WOULD be tokenized -- writes nothing.
#>
[CmdletBinding()]
param(
    [string]$Path,
    [string]$WorkDir,
    [switch]$RecommendOnly,
    [switch]$SafeFirstRun,
    [switch]$AutoProfile,
    [string]$Salt,
    [int]$HmacLength = 24,
    [string]$Profile,
    [string]$ProfileFile,
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
    [switch]$ProfileWizard,
    [int]$MaxSampleRows = 500,
    [ValidateSet('Auto','Csv','Json','Kv','Text')][string]$SampleFormat = 'Auto',
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
    [switch]$Recurse,
    [string[]]$Include,
    [string[]]$Exclude,
    [switch]$DryRun,
    [switch]$Stream,
    [switch]$NoCorrelate,
    [switch]$NonInteractive
)

$ErrorActionPreference = 'Stop'

# Derive the module name from THIS launcher's own name:
#   Run-UniversalScrubber_v4_13.ps1  ->  UniversalLogScrubber_v4_13.psm1
$myBase = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
$suffix = ''
if ($myBase -match '^Run-UniversalScrubber(.*)$') { $suffix = $matches[1] }
$moduleName = "UniversalLogScrubber{0}.psm1" -f $suffix
$modulePath = Join-Path $PSScriptRoot $moduleName

# Prefer the packaged repository layout: scripts\ launcher, src\ module.
if (-not (Test-Path $modulePath)) {
    $repoModulePath = Join-Path (Split-Path -Parent $PSScriptRoot) (Join-Path 'src' $moduleName)
    if (Test-Path $repoModulePath) { $modulePath = $repoModulePath }
}

# Fall back to the newest UniversalLogScrubber_*.psm1 next to the launcher or in
# ..\src if the exact match isn't present (e.g. the launcher was renamed).
if (-not (Test-Path $modulePath)) {
    $searchRoots = @($PSScriptRoot, (Join-Path (Split-Path -Parent $PSScriptRoot) 'src')) | Select-Object -Unique
    $alt = Get-ChildItem -Path $searchRoots -Filter 'UniversalLogScrubber*.psm1' -ErrorAction SilentlyContinue |
           Sort-Object Name -Descending | Select-Object -First 1
    if ($alt) { $modulePath = $alt.FullName }
}

if (-not (Test-Path $modulePath)) {
    Write-Host "Cannot find a UniversalLogScrubber_*.psm1 next to this launcher ($PSScriptRoot)." -ForegroundColor Red
    Write-Host "Keep this launcher and its matching .psm1 module in the same folder." -ForegroundColor Yellow
    exit 1
}

Import-Module $modulePath -Force

# Forward only the parameters the user actually supplied.
$forward = @{}
foreach ($k in $PSBoundParameters.Keys) { $forward[$k] = $PSBoundParameters[$k] }
Invoke-UniversalScrubber @forward


