<#
.SYNOPSIS
  Lists or saves curated external public log corpus samples.

.DESCRIPTION
  This helper imports the repository module and exposes the external
  corpus catalog. By default it lists or searches catalog entries. When -Name is
  supplied, it saves that corpus entry under .\samples\external-corpora unless
  -Destination is provided.

  Direct downloads require -AcceptRisk. Manual-download catalog entries write an
  instructions manifest and never attempt to bypass the source workflow.
#>
[CmdletBinding()]
param(
    [string]$Name,
    [string]$Query,
    [string]$Source,
    [string]$Format,
    [string]$Profile,
    [string]$Destination,
    [switch]$Force,
    [switch]$AcceptRisk
)

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$modulePath = Join-Path $repoRoot 'UniversalLogScrubber\UniversalLogScrubber.psd1'
Import-Module $modulePath -Force

if ([string]::IsNullOrWhiteSpace($Destination)) {
    $Destination = Join-Path $repoRoot 'samples\external-corpora'
}

if (-not [string]::IsNullOrWhiteSpace($Name)) {
    Save-LogCorpusSample -Name $Name -Destination $Destination -Force:$Force -AcceptRisk:$AcceptRisk
    return
}

$hasFilter = (-not [string]::IsNullOrWhiteSpace($Query)) -or
             (-not [string]::IsNullOrWhiteSpace($Source)) -or
             (-not [string]::IsNullOrWhiteSpace($Format)) -or
             (-not [string]::IsNullOrWhiteSpace($Profile))

$items = if ($hasFilter) {
    Search-LogCorpusCatalog -Query $Query -Source $Source -Format $Format -Profile $Profile
}
else {
    Get-LogCorpusCatalog
}

$items |
    Select-Object Name,Source,FormatHint,SuggestedProfile,ApproxSize,CanDownloadDirectly,RequiresManualDownload |
    Format-Table -AutoSize

Write-Host ""
Write-Host "To save a direct-download sample:" -ForegroundColor Cyan
Write-Host "  .\scripts\Get-SampleLogs.ps1 -Name Loghub-Apache -AcceptRisk" -ForegroundColor DarkGray
Write-Host "External corpus files default to: $Destination" -ForegroundColor DarkGray
