[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:Failures = New-Object System.Collections.Generic.List[string]

function Add-Failure {
    param([string]$Message)
    [void]$script:Failures.Add($Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Add-Pass {
    param([string]$Message)
    Write-Host "[ OK ] $Message" -ForegroundColor Green
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if ($Condition) { Add-Pass $Message } else { Add-Failure $Message }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $repoRoot 'src\UniversalLogScrubber_v4_13.psm1'
$launcherPath = Join-Path $repoRoot 'scripts\Run-UniversalScrubber_v4_13.ps1'

Assert-True (Test-Path -LiteralPath $modulePath) 'v4.13 module file exists'
Assert-True (Test-Path -LiteralPath $launcherPath) 'v4.13 launcher file exists'

$tokens = $null
$errors = $null
$moduleText = [System.IO.File]::ReadAllText($modulePath)
$ast = [System.Management.Automation.Language.Parser]::ParseInput($moduleText, [ref]$tokens, [ref]$errors)
Assert-True ($errors.Count -eq 0) 'module parses without static errors'

$duplicateFunctions = @(
    $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        Group-Object Name |
        Where-Object { $_.Count -gt 1 }
)
Assert-True ($duplicateFunctions.Count -eq 0) 'module has no duplicate function definitions'

Import-Module $modulePath -Force

$expectedCommands = @(
    'Get-LogCorpusCatalog',
    'Search-LogCorpusCatalog',
    'Save-LogCorpusSample',
    'Invoke-ExternalCorpusSmokeTest',
    'Invoke-ScrubSelfTest',
    'Test-LogFormat'
)
foreach ($name in $expectedCommands) {
    Assert-True ([bool](Get-Command $name -ErrorAction SilentlyContinue)) "exported command exists: $name"
}

$signatureChecks = @(
    @{ Command = 'Search-LogCorpusCatalog'; Params = @('Online','Dataset','Refresh','Query','Source','Format','Profile') },
    @{ Command = 'Save-LogCorpusSample'; Params = @('Online','Dataset','ExtractArchive','AcceptRisk','Destination','Force') },
    @{ Command = 'Invoke-ExternalCorpusSmokeTest'; Params = @('CorpusRoot','WorkDir','DryRunOnly','UseRecommendations','Salt','NonInteractive') }
)
foreach ($check in $signatureChecks) {
    $cmd = Get-Command $check.Command -ErrorAction Stop
    foreach ($paramName in $check.Params) {
        Assert-True ($cmd.Parameters.ContainsKey($paramName)) "$($check.Command) exposes -$paramName"
    }
}

$docsToScan = @(
    'README.md',
    'USAGE.md',
    'samples\README.md',
    'docs\EXTERNAL_CORPUS_SEARCH.md',
    'docs\profiles\README.md',
    '.github\pull_request_template.md',
    '.github\workflows\self-test.yml',
    'scripts\Get-SampleLogs.ps1',
    'scripts\Test-SampleLogs.ps1'
)

foreach ($relative in $docsToScan) {
    $path = Join-Path $repoRoot $relative
    if (-not (Test-Path -LiteralPath $path)) {
        Add-Failure "missing scanned file: $relative"
        continue
    }
    $text = [System.IO.File]::ReadAllText($path)
    Assert-True ($text -notmatch 'UniversalLogScrubber_v4_(10|11|12)|Run-UniversalScrubber_v4_(10|11|12)') "$relative has no stale versioned command file references"
}

$externalCorpusDoc = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'docs\EXTERNAL_CORPUS_SEARCH.md'))
Assert-True ($externalCorpusDoc -notmatch 'Get-LogCorpusCatalog\s+-Online') 'external corpus docs use Search-LogCorpusCatalog for online searches'
Assert-True ($externalCorpusDoc -notmatch 'Invoke-ExternalCorpusSmokeTest[\s\S]{0,240}-(Path|Destination|Profile)\b') 'external corpus smoke-test docs use CorpusRoot/WorkDir examples'

if ($script:Failures.Count -gt 0) {
    throw ("Static checks failed:`n - " + ($script:Failures -join "`n - "))
}

Write-Host "All static checks passed." -ForegroundColor Green
