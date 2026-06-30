<#
.SYNOPSIS
  Runs a sample-log smoke test against synthetic logs in .\samples.

.DESCRIPTION
  This is not a replacement for Invoke-ScrubSelfTest. It gives users and
  maintainers a visible, realistic set of sample logs to dry-run and scrub before
  using the tool with sensitive data.
#>
[CmdletBinding()]
param(
    [string]$Salt = 'sample-only-do-not-use-in-production',
    [string]$WorkDir = (Join-Path $PSScriptRoot '..\samples\out\smoke-test'),
    [switch]$SkipRealScrub
)

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$modulePath = Join-Path $repoRoot 'UniversalLogScrubber\UniversalLogScrubber.psd1'
Import-Module $modulePath -Force

$env:SCRUB_SAMPLE_SALT = $Salt
$sampleRoot = Join-Path $repoRoot 'samples\logs'
$seedFile = Join-Path $repoRoot 'samples\sample-seeds.txt'
$allowFile = Join-Path $repoRoot 'samples\sample-allowlist.txt'
$outRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WorkDir)
New-Item -ItemType Directory -Path $outRoot -Force | Out-Null

$cases = @(
    @{ Name='Application NDJSON'; Path='app-auth.ndjson'; Profile='AppJson' },
    @{ Name='Cloud audit JSONL'; Path='cloud-audit.jsonl'; Profile='CloudAudit' },
    @{ Name='Gateway key/value'; Path='gateway-kv.log'; Profile='Logfmt' },
    @{ Name='VPN/firewall text'; Path='vpn-firewall.log'; Profile='Firewall' },
    #@{ Name='VPN/firewall text'; Path='vpn-firewall.log'; Profile='WebAccess' },
    @{ Name='Web access text'; Path='web-access.log'; Profile='WebAccess' },
    @{ Name='Windows event CSV'; Path='windows-event-sample.csv'; Profile='WindowsEventCsv' }

    # New synthetic product samples
    @{ Name='ServiceNow incidents CSV'; Path='servicenow_incidents.csv'; Profile='ServiceNow' },
    @{ Name='Nexthink devices/executions CSV'; Path='nexthink_devices_executions.csv'; Profile='Nexthink'; RawAbsent=@('VDI-CALL-0902','marco.silva@northstar.example','C:\Users\marco.silva','0899cd856fba9b131050135138cd87c5e5222f0a0657b94730901988d5cabdbb','f06be575-39a5-4198-98a0-ce7b7ae8983e') },
    @{ Name='M365 unified audit CSV'; Path='m365_unified_audit_log.csv'; Profile='IdentityProvider' },
    @{ Name='Sentinel incidents/alerts JSONL'; Path='sentinel_incidents_alerts.jsonl'; Profile='CloudAudit' },
    @{ Name='Firewall/VPN syslog text'; Path='firewall_vpn_syslog.log'; Profile='Firewall' },
    @{ Name='EDR alerts JSONL'; Path='edr_alerts.jsonl'; Profile='Edr' },
    @{ Name='Intune managed devices CSV'; Path='intune_managed_devices.csv'; Profile='Intune' },
    @{ Name='SCCM CMTrace client log'; Path='sccm_cmtrace_client.log'; Profile='SccmText' },
    @{ Name='Intune registry export'; Path='intune_registry_export.reg'; Profile='IntuneDiagnostics' },
    @{ Name='Intune MDM HTML report'; Path='intune_mdm_report.html'; Profile='IntuneDiagnostics' },
    @{ Name='Intune policy XML report'; Path='intune_policy_report.xml'; Profile='IntuneDiagnostics' }
)

$failures = New-Object System.Collections.Generic.List[string]
foreach ($case in $cases) {
    $inputPath = Join-Path $sampleRoot $case.Path
    if (-not (Test-Path -LiteralPath $inputPath)) { throw "Sample missing: $inputPath" }
    $caseOut = Join-Path $outRoot (($case.Name -replace '[^A-Za-z0-9_.-]', '-').ToLowerInvariant())
    New-Item -ItemType Directory -Path $caseOut -Force | Out-Null

    Write-Host ""
    Write-Host "=== $($case.Name) dry run ===" -ForegroundColor Cyan
    $dry = Invoke-UniversalScrubber `
        -Path $inputPath `
        -WorkDir (Join-Path $caseOut 'dryrun') `
        -Profile $case.Profile `
        -SaltFromEnv SCRUB_SAMPLE_SALT `
        -SeedFile $seedFile `
        -AllowlistFile $allowFile `
        -DryRun `
        -ExplainDetections `
        -NonInteractive

    $dryChanges = (@($dry | ForEach-Object { $_.ChangeCount }) | Measure-Object -Sum).Sum
    if ($dryChanges -le 0) { [void]$failures.Add("Dry run found no changes for $($case.Name)") }

    if (-not $SkipRealScrub) {
        Write-Host ""
        Write-Host "=== $($case.Name) real scrub ===" -ForegroundColor Cyan
        $real = Invoke-UniversalScrubber `
            -Path $inputPath `
            -WorkDir (Join-Path $caseOut 'scrubbed') `
            -Profile $case.Profile `
            -SaltFromEnv SCRUB_SAMPLE_SALT `
            -SeedFile $seedFile `
            -AllowlistFile $allowFile `
            -TokenMapMode Replace `
            -SafeBundleOut (Join-Path $caseOut 'scrubbed\safe-upload.zip') `
            -Force `
            -NonInteractive

        foreach ($r in @($real)) {
            if (-not $r.Clean) { [void]$failures.Add("Leak check did not pass for $($case.Name): $($r.Input)") }
            if ($case.RawAbsent -and $r.Output -and (Test-Path -LiteralPath $r.Output)) {
                $scrubbedText = Get-Content -Path $r.Output -Raw
                foreach ($raw in @($case.RawAbsent)) {
                    if ($scrubbedText -match [regex]::Escape([string]$raw)) {
                        [void]$failures.Add("Raw value remained for $($case.Name): $raw")
                    }
                }
            }
        }
    }
}

# Exercise the profile builder on a real-looking synthetic sample.
$builderOut = Join-Path $outRoot 'profile-builder'
New-Item -ItemType Directory -Path $builderOut -Force | Out-Null
$built = Invoke-UniversalScrubber `
    -BuildProfileFromSample `
    -Path (Join-Path $sampleRoot 'gateway-kv.log') `
    -WorkDir $builderOut `
    -BaseProfile Logfmt `
    -ProfileOut (Join-Path $builderOut 'generated-gateway-profile.json') `
    -ProfileReportOut (Join-Path $builderOut 'generated-gateway-profile-report_DO_NOT_UPLOAD.md') `
    -Force `
    -NonInteractive

if (-not (Test-Path -LiteralPath $built.ProfilePath)) { [void]$failures.Add('Profile builder did not write a profile.') }
if (-not (Test-ScrubProfile -Path $built.ProfilePath -Quiet)) { [void]$failures.Add('Generated sample profile did not validate.') }

if ($failures.Count -gt 0) {
    Write-Host ""
    Write-Host "Sample log smoke test failed:" -ForegroundColor Red
    foreach ($f in $failures) { Write-Host " - $f" -ForegroundColor Red }
    exit 1
}

Write-Host ""
Write-Host "Sample log smoke test passed." -ForegroundColor Green
