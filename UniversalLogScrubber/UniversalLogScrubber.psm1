<#
.SYNOPSIS
  Universal, deterministic log scrubber. Builds a token map first, then scrubs
  one or many log files so they can leave a secure environment for analysis.

.DESCRIPTION
  This module generalizes the proven scrubbing engine from the AD CS ESC-audit
  pipeline into a log-type-agnostic tool. The engine is unchanged in spirit:

    * Every sensitive value is replaced by  PREFIX_<hmac>  where the HMAC is
      HMAC-SHA256(salt, normalized-value), truncated to a fixed length. The same
      real value ALWAYS collapses to the same token, in every file and every run
      that shares the salt -- that is what lets you correlate across files while
      never exposing the real value.

    * A private "token map" CSV records  realValue -> token  so YOU can re-identify
      findings later. It is secret and must never leave your environment.

    * After scrubbing, a leak check scans the output for residual identifiers and
      for any explicit sensitive terms you named, and re-hardens automatically.

  WHAT IS NEW vs the CA-only pipeline
  -----------------------------------
    1. The token-map SOURCE is pluggable:
         - Discover  : build the map FROM the log(s) themselves (no AD needed).
         - ExistingMap: reuse a map you already built.
         - AD        : build an authoritative identity map from Active Directory
                       (optional; only when you are domain-joined with rights).
    2. Column / field semantics are driven by a PROFILE, not hard-coded. Ships
       with a generic deny-by-default profile and a CA profile (so your existing
       AD CS exports still scrub for testing).
    3. Works on CSV (field-aware) and on free-form text logs (syslog, JSON lines,
       key=value, plain text) via a whole-file hardening pass.

  v2 ADDS
  -------
    * JSON adapter: .json / .ndjson / .jsonl are parsed and only the VALUES are
      tokenized -- keys are preserved -- so structured logs stay structured.
    * -DryRun: previews what WOULD be tokenized (counts by type + samples) and
      writes nothing (no scrubbed files, no token map).
    * EVTX pre-step: .evtx inputs are auto-converted to CSV (Get-WinEvent) and
      scrubbed with the WindowsEventCsv profile.

  v3 ADDS
  -------
    * More detectors: IPv6, MAC, UNC paths, URLs (userinfo+host), JWTs, AWS ARNs /
      access keys, cloud instance ids, base64 blobs -- plus a public-domain
      ALLOWLIST so well-known domains (microsoft.com, etc.) stay readable.
    * More log types / profiles: TSV, PSV, IIS/W3C (auto-converted), syslog,
      apache/nginx, CEF/LEEF and logfmt (key=value value-only), and XLSX
      (auto-converted, first sheet).
    * Bring-your-own profile: load custom column rules from a .json/.psd1 file.
    * In-log alias correlation: co-occurring aliases of one identity (email/UPN
      and DOMAIN\user) collapse to a single token. Disable with -NoCorrelate.
    * Streaming (-Stream): bounded-memory scrub for very large files; auto-offered
      for inputs over 50 MB.
    * Invoke-ScrubSelfTest: validates a build on synthetic data (no real logs).

  v4 ADDS
  -------
    * Restore-ScrubbedFile: un-scrub -- turn a token back into its real value using
      the private map (re-identify a finding; round-trip a file).
    * New-SyntheticLog: generate a planted test log for any built-in profile.
    * Full self-test: one fixture per profile (Generic, CA, Tsv, Psv, Syslog,
      Apache, Cef, Logfmt, WindowsEventCsv, Text, Json, IIS), a per-detector matrix,
      a streaming-vs-normal equivalence check, and a scrub -> restore round-trip.
    * v3 patch folded in: valid IPv4 is tokenized (was mistaken for an OID), and the
      leak gate no longer skips IPv4. The 'token map written' notice is now [WARN].

  v4.1 FIXES
  ----------
    * EVTX run path: the .evtx -> CSV hand-off now repoints at the converted CSV
      correctly (was scrubbing the raw .evtx and mis-suggesting the Text profile).
    * EVTX conversion is hardened: every event field is string-normalized and each
      record is read in isolation, so one odd event can't abort the whole log.

  v4.2 FIXES
  ----------
    * Fail-closed cell handling: if a single cell can't be fully hardened it is first
      retried with the safe pass set, then (worst case) replaced with one token --
      so a tricky value (e.g. a stack trace in an event Message) can neither crash
      the run nor leak. A one-line summary reports how many cells fell back.
    * Banner cosmetics: the box borders stay cyan; only the subtitle text dims.

  v4.3 / v4.4 FIXES
  -----------------
    * Dry-run preview no longer crashes on real event logs: the per-cell scan is
      isolated and uses string-safe comparison (the comparison in the preview-only
      loop tripped a type mismatch on some Windows event Message values).
    * Leak check no longer false-positives on a backslash between two existing
      tokens (PRINCIPAL_x\PRINCIPAL_y) or on Windows path fragments
      (WINDOWS\system32) -- neither is a credential leak.

  v4.5 FIXES
  ----------
    * The dry-run crash is fixed at the source: the preview SUMMARY now counts by
      token kind manually (not Group-Object/Sort-Object) and can't crash the
      read-only preview. (The scan loop was fine; the summary step was the problem.)
    * The launcher now derives the module name from its OWN filename, so the .ps1
      and .psm1 can never point at mismatched versions again.

  v4.6 FIXES
  ----------
    * Leak check is now path-aware: a 'word\word' that is really a Windows file path
      (C:\Program Files\Microsoft Office\root\Office16\...) is no longer mis-reported
      as a DOMAIN\user credential leak, while a genuine standalone DOMAIN\user is
      still flagged.

  v4.7 FIXES
  ----------
    * Adds a scrub policy knob (Strict / Balanced / Readable). Balanced is the
      default: preserve common Windows / Microsoft diagnostics and path structure
      while still tokenizing identities, hosts, private domains, SIDs, IPs and
      high-confidence secrets.
    * Detection decisions are context-aware and can be explained in dry-run output
      or written to a local false-positive review CSV.
    * Windows path handling now preserves standard OS path segments, WER filenames,
      executables/libraries/log files and Microsoft package names; C:\Users\<name>
      profile segments and UNC hosts are still tokenized.
    * Ambiguous base64, long-hex and GUID detections are reduced in diagnostic
      contexts such as WER crash reports.

  v4.8 ADDS
  ---------
    * Token maps can merge into an existing map, are written with a temp file and
      backup, and include safe metadata for source/hash auditing.
    * Same-basename inputs in one run get collision-safe output names.
    * EVTX conversion streams to CSV with progress and optional EventData/UserData
      columns via -EvtxProgressMode CountFirst.
    * Windows Event label-aware scrubbing catches bare account names inside Message
      fields, and offline secret patterns cover common bearer/key/connection-string
      forms without network validation.
    * A safe counts-only -DetectionSummaryReport complements the local-only detailed
      false-positive report.

  v4.9 ADDS
  ---------
    * Universal label-aware detection now applies beyond Windows Event logs to
      CSV cells, JSON values, key=value/logfmt/CEF-style text and free-form logs.
    * BYOP profile schema v2 adds SchemaColumns, WholeColumnRules, LabelRules,
      CustomRegexRules, Allowlist/AllowlistFile and SeedTerms/SeedFiles.
    * CLI seed files are first-class via -SeedFile and -SensitiveTermsFile, with
      -AllowlistFile for public diagnostic values that should stay readable.
    * Built-in non-Windows presets cover web access/proxy, cloud audit, firewall,
      VPN, app JSON, database, container/Kubernetes and identity-provider logs.
    * Dry-run summaries include detector counts, and profile regexes compile once
      with timeouts plus keyword prefilters for expensive custom rules.

  v4.10 ADDS
  ----------
    * New-ScrubProfileFromSample builds an editable BYOP profile from a local
      sample log without putting raw sample values in the generated profile.
    * -BuildProfileFromSample, -ProfileOut, -ProfileReportOut, -ProfileWizard,
      -MaxSampleRows, -SampleFormat and -Force expose that builder in the normal
      launcher flow.
    * Test-ScrubProfile validates BYOP profiles without running a scrub.
    * -SafeBundleOut creates a zip containing only scrubbed clean outputs plus a
      safe readme, excluding maps, salts, manifests and detailed reports.
    * Dry-run summaries now separate high-confidence detections, values to
      review, and values preserved by allowlist/diagnostic rules.

  v4.11 ADDS
  ----------
    * Test-LogFormat locally samples candidate log files and recommends existing
      scrub profiles before any salt, token map or scrubbed output is needed.
    * -RecommendOnly and -SafeFirstRun show local-only recommendations and exit
      before scrubbing.
    * -AutoProfile can choose one high-confidence profile for uniform inputs and
      refuses mixed/low-confidence folders in noninteractive mode.

  v4.15 ADDS
  ----------
    * Enterprise profile recommendations for ServiceNow, Nexthink, SCCM/ConfigMgr,
      Intune, M365/identity audit, Sentinel/cloud audit, EDR/XDR, and firewall logs.
    * -ProfileExtensionFile adds local BYOP overlays without copying an entire
      built-in profile.
    * .etl intake is explicit with -ConvertEtl and uses Windows tracerpt.exe.

  CONSISTENCY GUARANTEE
  ---------------------
  Map-build, scrub and leak-harden all share ONE salt, ONE HMAC length and ONE
  normalizer for the session. The token map is authoritative: during scrubbing a
  value found in the map always resolves to its mapped token regardless of which
  code path encounters it, so tokens never diverge.

  SECURITY
  --------
    * The *_token_map_DO_NOT_UPLOAD.csv file is SECRET. Never upload it.
    * Upload only the *_scrubbed.* files.
    * Reuse the SAME salt for every run that must correlate.

  QUICK START
  -----------
    Import-Module .\UniversalLogScrubber\UniversalLogScrubber.psd1
    Invoke-UniversalScrubber              # fully interactive, hand-held
    Invoke-UniversalScrubber -Path C:\logs -Profile Generic -MapSource Discover

.NOTES
  PowerShell 5.1+ (Windows PowerShell and PowerShell 7 both fine). The AD map
  source additionally needs a domain-joined session with read rights; every other
  capability works anywhere, fully offline.
#>

# We deliberately do NOT enable Set-StrictMode globally -- the AD/LDAP path was
# written without it and forcing strict mode there could surface spurious errors.
# The helpers below are written to be strict-safe regardless.

# =====================================================================
# REGION: Session state (shared by every stage)
# =====================================================================
$script:ModuleName       = 'UniversalLogScrubber'
$script:ModuleVersion    = '4.15.0'
$script:Salt             = $null
$script:HmacLength       = 24
$script:TokenByNorm      = @{}     # normalized-value -> token (the loaded map)
$script:TokenMapCacheKey = $null   # "<path>|<lastwrite>" of the map in memory
$script:AdditionalBroadLabels = @()
$script:ScrubPolicy = 'Balanced'
$script:ExplainDetections = $false
$script:DetectionTrace = $null
$script:DetectionTraceSeen = @{}
$script:FalsePositiveReport = $null
$script:DetectionCounts = @{}
$script:DetectionSummaryReport = $null
$script:CurrentTokenMapCsv = $null
$script:TokenMapMode = 'Merge'
$script:EvtxProgressMode = 'Fast'
$script:RegexTimeout = [TimeSpan]::FromMilliseconds(250)
$script:CurrentProfile = $null
$script:RuntimeLabelRules = @()
$script:RuntimeCustomRegexRules = @()
$script:RuntimeAllowExact = @{}
$script:RuntimeAllowRegex = @()
$script:KnownTokenPrefixes = @(
    'PRINCIPAL','UNMAPPED_PRINCIPAL','UNMAPPED_UPN','COMPUTER','GROUP',
    'OBJECT','SID','DNS','UPN','EMAIL','CERT','TEMPLATE','CA','X500',
    'GUID','IP','IP6','HOST','URL','URI','MAC','JWT','ARN','AWSKEY',
    'INSTANCE','BLOB','SECRET','APIKEY','CONNSTR','PEM'
)

# =====================================================================
# REGION: Performance patch (v4.14.0 perf-1) -- behavior-preserving
#   1. Per-file (column,value)->scrubbed memoization cache. Populated per file
#      in Invoke-ScrubFile; $null disables it so direct callers/discovery are
#      unaffected. See Scrub-Field.
#   2. Larger static regex cache. The free-text / secret / common / leak
#      hardening passes use static [regex]::Replace/Matches(string, pattern, ...)
#      calls that share the process-wide cache (default size 15). The per-cell
#      battery cycles through more than 15 distinct patterns, so they were being
#      evicted and recompiled on essentially every cell. Raising the cache keeps
#      them compiled. Pure speed; no behavior change.
# =====================================================================
$script:__cellCache = $null
$script:__hmacTokenCache = $null
[System.Text.RegularExpressions.Regex]::CacheSize = 256

# Low-risk perf patch: precompiled Windows user-profile path regexes. These are used
# only behind a cheap substring gate in Invoke-WindowsPathUserHardening. Behavior is
# intended to match the prior dynamic [regex]::Replace calls while avoiding repeated
# regex lookup/compile overhead on hot Windows Event Message/EventDataJson paths.
$script:__rxWinUserPathOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
$script:__rxWinUserPathNormal = [System.Text.RegularExpressions.Regex]::new('((?:\\\?\\)?[A-Za-z]:\\Users\\)([^\\/"'',;:\r\n]+)', $script:__rxWinUserPathOptions, $script:RegexTimeout)
$script:__rxWinUserPathEscaped = [System.Text.RegularExpressions.Regex]::new('([A-Za-z]:\\\\Users\\\\)([^\\/"'',;:\r\n]+)', $script:__rxWinUserPathOptions, $script:RegexTimeout)


# Optional phase timing report (-PerfReport). Behavior-neutral: timings are collected only
# when enabled and are written at the end of Invoke-UniversalScrubber.
$script:PerfReportEnabled = $false
$script:PerfReportDetailedEnabled = $false
$script:PerfReportRows = $null
$script:PerfReportPath = $null
$script:PerfReportTextPath = $null

# Compact, consistent progress rendering. Keep status short because hosts often
# truncate Write-Progress status text before the most useful data.
$script:UlsProgressState = @{}
function Write-UlsProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Activity,
        [string]$Phase,
        [string]$File,
        [long]$RowsDone = -1,
        [long]$RowsTotal = -1,
        [long]$BytesDone = -1,
        [long]$BytesTotal = -1,
        [int]$Workers = -1,
        [int]$Pending = -1,
        [int]$Ready = -1,
        [int]$CompletedBatches = -1,
        [switch]$Completed,
        [switch]$Reset,
        [switch]$Force,
        [int]$MinIntervalMs = 1000
    )

    if ($Reset) {
        [void]$script:UlsProgressState.Remove($Activity)
        return
    }

    if ($Completed) {
        Write-Progress -Activity $Activity -Completed
        [void]$script:UlsProgressState.Remove($Activity)
        return
    }

    $now = [datetime]::UtcNow
    $state = $script:UlsProgressState[$Activity]
    if ($null -eq $state) {
        $state = [pscustomobject]@{ LastUtc = $now.AddMilliseconds(-1 * ($MinIntervalMs + 1)); StartUtc = $now }
        $script:UlsProgressState[$Activity] = $state
    }
    if (-not $Force -and (($now - $state.LastUtc).TotalMilliseconds -lt $MinIntervalMs)) { return }

    $bits = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($Phase)) { [void]$bits.Add($Phase) }
    if ($RowsDone -ge 0) {
        if ($RowsTotal -gt 0) { [void]$bits.Add(("rows {0}/{1}" -f $RowsDone, $RowsTotal)) }
        else { [void]$bits.Add(("rows {0}" -f $RowsDone)) }
    }
    if ($BytesDone -ge 0) {
        $mbDone = [Math]::Round(($BytesDone / 1MB), 1)
        if ($BytesTotal -gt 0) { [void]$bits.Add(("{0}/{1} MB" -f $mbDone, [Math]::Round(($BytesTotal / 1MB), 1))) }
        else { [void]$bits.Add(("{0} MB" -f $mbDone)) }
    }
    if ($Workers -ge 0) { [void]$bits.Add(("active {0}" -f $Workers)) }
    if ($Pending -ge 0) { [void]$bits.Add(("pending {0}" -f $Pending)) }
    if ($Ready -ge 0) { [void]$bits.Add(("ready {0}" -f $Ready)) }
    if ($CompletedBatches -ge 0) { [void]$bits.Add(("batches {0}" -f $CompletedBatches)) }
    $elapsed = [Math]::Max(0.001, ($now - $state.StartUtc).TotalSeconds)
    if ($RowsDone -gt 0) { [void]$bits.Add(("{0}/s" -f [Math]::Round(($RowsDone / $elapsed), 0))) }
    [void]$bits.Add(("elapsed {0}" -f ([TimeSpan]::FromSeconds([Math]::Round($elapsed)).ToString("mm\:ss"))))

    $pct = -1
    if ($BytesTotal -gt 0 -and $BytesDone -ge 0) { $pct = [Math]::Min(100, [Math]::Max(0, [int](($BytesDone / [double]$BytesTotal) * 100))) }
    elseif ($RowsTotal -gt 0 -and $RowsDone -ge 0) { $pct = [Math]::Min(100, [Math]::Max(0, [int](($RowsDone / [double]$RowsTotal) * 100))) }

    $label = if ([string]::IsNullOrWhiteSpace($File)) { $Activity } else { ("{0}: {1}" -f $Activity, $File) }
    Write-Progress -Activity $label -Status (($bits.ToArray()) -join '; ') -PercentComplete $pct
    $state.LastUtc = $now
}

function New-UlsPerfStopwatch {
    if (-not $script:PerfReportEnabled) { return $null }
    return [System.Diagnostics.Stopwatch]::StartNew()
}

function Add-UlsPerfPhase {
    param(
        [Parameter(Mandatory)][string]$Phase,
        [System.Diagnostics.Stopwatch]$Stopwatch,
        [double]$Seconds = -1,
        [string]$File = '',
        [int]$Rows = -1,
        [int]$Cells = -1,
        [string]$Notes = ''
    )
    if (-not $script:PerfReportEnabled) { return }
    if ($null -eq $script:PerfReportRows) { $script:PerfReportRows = New-Object System.Collections.Generic.List[object] }
    if ($Stopwatch) {
        if ($Stopwatch.IsRunning) { $Stopwatch.Stop() }
        $Seconds = $Stopwatch.Elapsed.TotalSeconds
    }
    [void]$script:PerfReportRows.Add([pscustomobject]@{
        Phase   = $Phase
        File    = $File
        Seconds = [Math]::Round([double]$Seconds, 3)
        Rows    = $Rows
        Cells   = $Cells
        Notes   = $Notes
    })
}

function Write-UlsPerfReport {
    param([Parameter(Mandatory)][string]$WorkDir)
    if (-not $script:PerfReportEnabled) { return $null }
    if ($null -eq $script:PerfReportRows) { $script:PerfReportRows = New-Object System.Collections.Generic.List[object] }

    $csvPath = Resolve-OutPath -Path (Join-Path $WorkDir 'scrub_perf_report.csv')
    $txtPath = Resolve-OutPath -Path (Join-Path $WorkDir 'scrub_perf_report.txt')

    # Materialize the generic List[object] as a real object array.  Do not use
    # @($script:PerfReportRows): in some PowerShell/.NET combinations that wraps
    # the List object itself instead of enumerating its rows, which can produce
    # noisy post-run Export-Csv / type conversion errors even after scrubbing has
    # completed successfully.
    $rows = @(
        foreach ($r in $script:PerfReportRows) {
            if ($null -ne $r) { $r }
        }
    )

    if ($rows.Count -gt 0) {
        $rows |
            Select-Object Phase, File, Seconds, Rows, Cells, Notes |
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    }
    else {
        '"Phase","File","Seconds","Rows","Cells","Notes"' | Set-Content -Path $csvPath -Encoding UTF8
    }

    $lines = New-Object System.Collections.Generic.List[string]
    [void]$lines.Add('Universal Log Scrubber performance report')
    [void]$lines.Add(('GeneratedUtc: {0}' -f ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))))
    [void]$lines.Add('')

    $preferred = @('Read CSV','Discover identifiers','Build/correlate map','Scrub fields','Post hardening','Leak check','Write output')
    $grouped = $rows | Group-Object Phase
    $byPhase = @{}
    foreach ($g in $grouped) { $byPhase[[string]$g.Name] = [double](($g.Group | Measure-Object -Property Seconds -Sum).Sum) }

    foreach ($p in $preferred) {
        if ($byPhase.ContainsKey($p)) { [void]$lines.Add(('{0}: {1:N3} sec' -f $p, [double]$byPhase[$p])) }
        else { [void]$lines.Add(('{0}: 0.000 sec' -f $p)) }
    }
    $detailOnlyPhases = @('Scrub column')
    foreach ($k in ($byPhase.Keys | Sort-Object)) {
        if ($preferred -contains $k) { continue }
        if ($detailOnlyPhases -contains $k) { continue }
        [void]$lines.Add(('{0}: {1:N3} sec' -f $k, [double]$byPhase[$k]))
    }

    [void]$lines.Add('')
    [void]$lines.Add('Details:')
    foreach ($r in $rows) {
        $detail = '{0} | {1:N3}s | file={2} | rows={3} | cells={4}' -f $r.Phase, [double]$r.Seconds, $r.File, $r.Rows, $r.Cells
        if ($r.Notes) { $detail += ' | ' + [string]$r.Notes }
        [void]$lines.Add($detail)
    }

    [string[]]$lineArray = $lines.ToArray()
    [System.IO.File]::WriteAllLines($txtPath, $lineArray, [System.Text.Encoding]::UTF8)
    $script:PerfReportPath = $csvPath
    $script:PerfReportTextPath = $txtPath
    Write-Ok "Performance report written: $csvPath"
    Write-Ok "Performance summary written: $txtPath"
    return $csvPath
}

# =====================================================================
# REGION: Pretty console UI
# =====================================================================
$script:UiWidth = 72

# Print one boxed line: the left/right borders stay cyan, only the inner text takes
# $TextColor (so the box frame never changes color with the subtitle).
function Write-BannerLine {
    param([string]$Text, [string]$TextColor = 'Cyan')
    $w = $script:UiWidth
    $side = [string]([char]0x2551)
    $inner = "  " + $Text
    if ($inner.Length -gt ($w - 2)) { $inner = $inner.Substring(0, $w - 2) }
    $inner = $inner.PadRight($w - 2)
    Write-Host $side -ForegroundColor Cyan -NoNewline
    Write-Host $inner -ForegroundColor $TextColor -NoNewline
    Write-Host $side -ForegroundColor Cyan
}

function Write-Banner {
    param([string]$Title, [string]$Subtitle)
    $w = $script:UiWidth
    $top = [string]([char]0x2554) + ([string]([char]0x2550) * ($w - 2)) + [string]([char]0x2557)
    $bot = [string]([char]0x255A) + ([string]([char]0x2550) * ($w - 2)) + [string]([char]0x255D)
    Write-Host ""
    Write-Host $top -ForegroundColor Cyan
    Write-BannerLine -Text $Title -TextColor Cyan
    if ($Subtitle) { Write-BannerLine -Text $Subtitle -TextColor DarkCyan }
    Write-Host $bot -ForegroundColor Cyan
}

function Write-Rule {
    param([string]$Label)
    $w = $script:UiWidth
    if ($Label) {
        $dash = [string]([char]0x2500)
        $left = ($dash * 3) + " " + $Label + " "
        Write-Host ($left + ($dash * [Math]::Max(0, $w - $left.Length))) -ForegroundColor DarkCyan
    }
    else {
        Write-Host ([string]([char]0x2500) * $w) -ForegroundColor DarkCyan
    }
}

function Write-Status {
    param(
        [Parameter(Mandatory)][ValidateSet('OK','WARN','FAIL','STEP','INFO','WORK')][string]$Tag,
        [Parameter(Mandatory)][string]$Message
    )
    switch ($Tag) {
        'OK'   { $label = '[ OK ]'; $c = 'Green' }
        'WARN' { $label = '[WARN]'; $c = 'Yellow' }
        'FAIL' { $label = '[FAIL]'; $c = 'Red' }
        'STEP' { $label = '[STEP]'; $c = 'Cyan' }
        'INFO' { $label = '[INFO]'; $c = 'Gray' }
        'WORK' { $label = '[ .. ]'; $c = 'DarkCyan' }
    }
    Write-Host $label -ForegroundColor $c -NoNewline
    Write-Host (" " + $Message)
}

function Write-Ok    { param([string]$m) Write-Status -Tag OK   -Message $m }
function Write-Warn  { param([string]$m) Write-Status -Tag WARN -Message $m }
function Write-Fail  { param([string]$m) Write-Status -Tag FAIL -Message $m }
function Write-Step  { param([string]$m) Write-Status -Tag STEP -Message $m }
function Write-Info  { param([string]$m) Write-Status -Tag INFO -Message $m }
function Write-Work  { param([string]$m) Write-Status -Tag WORK -Message $m }
function Write-Detail { param([string]$m) Write-Host ("       " + $m) -ForegroundColor DarkGray }

# =====================================================================
# REGION: Interactive prompt helpers
# =====================================================================
function Read-DefaultString {
    param([Parameter(Mandatory)][string]$Prompt, [string]$Default)
    if ($PSBoundParameters.ContainsKey('Default')) {
        $promptText = if ([string]::IsNullOrEmpty($Default)) { $Prompt } else { "$Prompt [$Default]" }
        $answer = Read-Host $promptText
        if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
        return $answer.Trim()
    }
    while ($true) {
        $answer = Read-Host $Prompt
        if (-not [string]::IsNullOrWhiteSpace($answer)) { return $answer.Trim() }
        Write-Warn "A value is required."
    }
}

function Read-DefaultInt {
    param([Parameter(Mandatory)][string]$Prompt, [Parameter(Mandatory)][int]$Default)
    $answer = Read-Host "$Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
    $parsed = 0
    if ([int]::TryParse($answer.Trim(), [ref]$parsed)) { return $parsed }
    Write-Warn "Not a whole number; using $Default."
    return $Default
}

function Read-YesNo {
    param([Parameter(Mandatory)][string]$Prompt, [bool]$Default = $true)
    $suffix = if ($Default) { "[Y/n]" } else { "[y/N]" }
    $answer = Read-Host "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
    return ($answer.Trim() -match '^(y|yes)$')
}

# Numbered chooser. $Options is an array of @{ Key=...; Label=...; Detail=... }.
# Returns the chosen Key.
function Read-Choice {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][array]$Options,
        [int]$DefaultIndex = 1
    )
    for ($i = 0; $i -lt $Options.Count; $i++) {
        $n = $i + 1
        Write-Host ("   {0}) " -f $n) -ForegroundColor Cyan -NoNewline
        Write-Host $Options[$i].Label -ForegroundColor White
        if ($Options[$i].Detail) { Write-Host ("        " + $Options[$i].Detail) -ForegroundColor DarkGray }
    }
    $sel = Read-DefaultString -Prompt $Prompt -Default ([string]$DefaultIndex)
    $idx = 0
    if ([int]::TryParse($sel, [ref]$idx) -and $idx -ge 1 -and $idx -le $Options.Count) {
        return $Options[$idx - 1].Key
    }
    # allow typing the key directly
    foreach ($o in $Options) { if ($o.Key -ieq $sel) { return $o.Key } }
    Write-Warn "Unrecognized choice; using default."
    return $Options[$DefaultIndex - 1].Key
}

# Prompt once for the salt; entry is masked; cached for the whole session.
function Get-SessionSalt {
    if (-not [string]::IsNullOrWhiteSpace($script:Salt)) { return $script:Salt }
    Write-Host ""
    Write-Warn "A salt is required to tokenize values."
    Write-Detail "Use the SAME salt every time you want tokens to line up across files / runs."
    Write-Detail "Treat it like a password: anyone with the salt + a token map can re-identify."
    while ($true) {
        $secure = Read-Host "Enter salt" -AsSecureString
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        if ([string]::IsNullOrWhiteSpace($plain)) { Write-Warn "Salt cannot be empty."; continue }
        $script:Salt = $plain
        return $script:Salt
    }
}

# =====================================================================
# REGION: Paths
# =====================================================================
function Resolve-OutPath {
    param([Parameter(Mandatory)][string]$Path)
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $dir = Split-Path -Parent $full
    if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    return $full
}

function Get-PathFingerprint {
    param([Parameter(Mandatory)][string]$Path, [int]$Length = 12)
    $resolved = try { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path) } catch { [string]$Path }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($resolved.ToLowerInvariant()))
        return (ConvertTo-HexString -Bytes $bytes).Substring(0, [Math]::Min([Math]::Max($Length, 4), 64)).ToUpperInvariant()
    }
    finally { $sha.Dispose() }
}

function Get-SafeDerivedPath {
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutDir,
        [Parameter(Mandatory)][string]$Suffix,
        [switch]$UseHash
    )
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($InputPath) -replace '(?i)_UNSCRUBBED$', ''
    if ($UseHash) { $stem = "{0}_{1}" -f $stem, (Get-PathFingerprint -Path $InputPath -Length 8) }
    return (Join-Path $OutDir ($stem + $Suffix))
}

function Get-TokenCountInText {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return 0 }
    return ([regex]::Matches($Text, '(?:HV_|UNMAPPED_)?[A-Z0-9]+(?:_[A-Z0-9]+)*_[A-F0-9]{4,}|(?:BROAD|ADCS|HV_GROUP|BUILTIN)_[A-Z0-9_]+')).Count
}

function Get-TokenCountInFile {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return 0 }
    try {
        $count = 0
        $rx = [regex]'(?:HV_|UNMAPPED_)?[A-Z0-9]+(?:_[A-Z0-9]+)*_[A-F0-9]{4,}|(?:BROAD|ADCS|HV_GROUP|BUILTIN)_[A-Z0-9_]+'
        foreach ($line in [System.IO.File]::ReadLines((Resolve-Path -LiteralPath $Path).Path)) {
            if ([string]::IsNullOrEmpty($line)) { continue }
            $count += $rx.Matches($line).Count
        }
        return $count
    } catch { return 0 }
}

# =====================================================================
# REGION: Crypto / normalization / token core (schema-agnostic)
# =====================================================================
function Normalize-SANValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim()
    if     ($v -match '(?i)principal name\s*=\s*(.+)$') { $v = $matches[1] }
    elseif ($v -match '(?i)rfc822 name\s*=\s*(.+)$')    { $v = $matches[1] }
    elseif ($v -match '(?i)upn\s*=\s*(.+)$')            { $v = $matches[1] }
    elseif ($v -match '(?i)email\s*=\s*(.+)$')          { $v = $matches[1] }
    $v = $v -replace '(?i)^smtp:', ''
    $v = $v -replace '(?i)^mailto:', ''
    return $v.Trim()
}

function Normalize-TokenKey {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = Normalize-SANValue -Value $Value
    if ([string]::IsNullOrWhiteSpace($v)) { return $null }
    return ($v.Trim() -replace "`r|`n", " ").ToLowerInvariant()
}

function ConvertTo-HexString {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return "" }
    # PowerShell pipeline-per-byte conversion is expensive in hot HMAC fallback paths.
    # BitConverter preserves the same byte-to-hex content; callers already normalize case.
    return ([System.BitConverter]::ToString($Bytes).Replace('-', '').ToLowerInvariant())
}

# Returns "PREFIX_<hex>" or $null if the value cannot be normalized.
function Invoke-HmacToken {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Prefix)
    $normalized = Normalize-TokenKey -Value $Value
    if (-not $normalized) { return $null }
    $salt = Get-SessionSalt
    $len = [Math]::Min([Math]::Max($script:HmacLength, 4), 64)

    # Low/medium-risk perf patch: cache deterministic HMAC fallback tokens during a file scrub.
    # Token-map hits still win before this function is called. The cache key includes salt,
    # output length, prefix, and normalized value so changing any token parameter cannot reuse
    # an incompatible token. $null disables caching for direct/discovery callers.
    $cacheKey = $salt + ([char]0) + ([string]$len) + ([char]0) + $Prefix + ([char]0) + $normalized
    if ($null -ne $script:__hmacTokenCache -and $script:__hmacTokenCache.ContainsKey($cacheKey)) {
        return $script:__hmacTokenCache[$cacheKey]
    }

    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($salt)
    $msgBytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
    try { $hash = $hmac.ComputeHash($msgBytes) } finally { $hmac.Dispose() }
    $hex = (ConvertTo-HexString -Bytes $hash).Substring(0, $len).ToUpperInvariant()
    $token = "$Prefix`_$hex"
    if ($null -ne $script:__hmacTokenCache) { $script:__hmacTokenCache[$cacheKey] = $token }
    return $token
}

function Is-AlreadyToken {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return (
        $Value -match '^(HV_)?(PRINCIPAL|COMPUTER|GROUP|OBJECT|SID|DNS|UPN|EMAIL|CERT|TEMPLATE|CA|X500|GUID|IP|IP6|HOST|URL|URI|MAC|JWT|ARN|AWSKEY|INSTANCE|BLOB|SECRET|APIKEY|CONNSTR|PEM)_[A-F0-9]{4,}$' -or
        $Value -match '^UNMAPPED_(UPN|PRINCIPAL|DNS|OBJECT|IP)_[A-F0-9]{4,}$' -or
        $Value -match '^(BROAD|ADCS|HV_GROUP|BUILTIN)_[A-Z0-9_]+$'
    )
}

# Windows well-known SID / group resolver. Optional but broadly useful for any
# Windows-sourced log -- collapses well-known principals to readable, non-secret
# labels instead of opaque hashes. Returns $null for anything not well-known.
function Get-CanonicalKnownLabelByValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $trimmed = $Value.Trim()
    $simple = $trimmed
    if     ($trimmed -match '^CN=([^,]+),') { $simple = $matches[1] }
    elseif ($trimmed -match '\\')           { $simple = ($trimmed -split '\\')[-1] }
    $simple = $simple.Trim()
    $simpleLower = $simple.ToLowerInvariant()

    switch -Regex ($trimmed) {
        '^S-1-1-0$'      { return "BROAD_EVERYONE" }
        '^S-1-5-11$'     { return "BROAD_AUTHENTICATED_USERS" }
        '^S-1-5-18$'     { return "BUILTIN_SYSTEM" }
        '^S-1-5-32-545$' { return "BROAD_BUILTIN_USERS" }
        '^S-1-5-32-544$' { return "HV_GROUP_BUILTIN_ADMINISTRATORS" }
        '^S-1-5-32-548$' { return "HV_GROUP_ACCOUNT_OPERATORS" }
        '^S-1-5-32-549$' { return "HV_GROUP_SERVER_OPERATORS" }
        '^S-1-5-32-550$' { return "HV_GROUP_PRINT_OPERATORS" }
        '^S-1-5-32-551$' { return "HV_GROUP_BACKUP_OPERATORS" }
        '-512$'          { return "HV_GROUP_DOMAIN_ADMINS" }
        '-513$'          { return "BROAD_DOMAIN_USERS" }
        '-515$'          { return "BROAD_DOMAIN_COMPUTERS" }
        '-516$'          { return "HV_GROUP_DOMAIN_CONTROLLERS" }
        '-517$'          { return "ADCS_GROUP_CERT_PUBLISHERS" }
        '-518$'          { return "HV_GROUP_SCHEMA_ADMINS" }
        '-519$'          { return "HV_GROUP_ENTERPRISE_ADMINS" }
        '-520$'          { return "HV_GROUP_GROUP_POLICY_CREATOR_OWNERS" }
        '-526$'          { return "HV_GROUP_KEY_ADMINS" }
        '-527$'          { return "HV_GROUP_ENTERPRISE_KEY_ADMINS" }
    }
    switch ($simpleLower) {
        "everyone"                      { return "BROAD_EVERYONE" }
        "authenticated users"           { return "BROAD_AUTHENTICATED_USERS" }
        "system"                        { return "BUILTIN_SYSTEM" }
        "local system"                  { return "BUILTIN_SYSTEM" }
        "nt authority\system"           { return "BUILTIN_SYSTEM" }
        "domain users"                  { return "BROAD_DOMAIN_USERS" }
        "domain computers"              { return "BROAD_DOMAIN_COMPUTERS" }
        "users"                         { return "BROAD_BUILTIN_USERS" }
        "builtin\users"                 { return "BROAD_BUILTIN_USERS" }
        "administrators"                { return "HV_GROUP_BUILTIN_ADMINISTRATORS" }
        "builtin\administrators"        { return "HV_GROUP_BUILTIN_ADMINISTRATORS" }
        "domain admins"                 { return "HV_GROUP_DOMAIN_ADMINS" }
        "enterprise admins"             { return "HV_GROUP_ENTERPRISE_ADMINS" }
        "schema admins"                 { return "HV_GROUP_SCHEMA_ADMINS" }
        "account operators"             { return "HV_GROUP_ACCOUNT_OPERATORS" }
        "server operators"              { return "HV_GROUP_SERVER_OPERATORS" }
        "print operators"               { return "HV_GROUP_PRINT_OPERATORS" }
        "backup operators"              { return "HV_GROUP_BACKUP_OPERATORS" }
        "domain controllers"            { return "HV_GROUP_DOMAIN_CONTROLLERS" }
        "enterprise domain controllers" { return "HV_GROUP_ENTERPRISE_DOMAIN_CONTROLLERS" }
        "group policy creator owners"   { return "HV_GROUP_GROUP_POLICY_CREATOR_OWNERS" }
        "key admins"                    { return "HV_GROUP_KEY_ADMINS" }
        "enterprise key admins"         { return "HV_GROUP_ENTERPRISE_KEY_ADMINS" }
        "dnsadmins"                     { return "HV_GROUP_DNSADMINS" }
        "cert publishers"               { return "ADCS_GROUP_CERT_PUBLISHERS" }
    }
    foreach ($label in $script:AdditionalBroadLabels) {
        if (-not [string]::IsNullOrWhiteSpace($label) -and $trimmed -eq $label) { return "BROAD_DOMAIN_USERS" }
    }
    return $null
}

# True when a dotted-decimal string should be LEFT INTACT as an OID / version
# number rather than tokenized -- i.e. it is NOT a valid IPv4 address. A 4-octet
# value with every octet 0-255 is treated as an IP (and tokenized). This is the
# fix for IPv4 addresses being silently preserved -- and skipped by the leak
# check -- because they matched the old "dotted-decimal == OID" guard.
function Test-PreserveDottedDecimal {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim()
    if ($v -notmatch '^([0-9]+\.)+[0-9]+$') { return $false }                                                 # not dotted-decimal at all
    if ($v -match '^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$') { return $false }     # valid IPv4 -> tokenize it
    return $true
}

# Single token resolver. Order:
#   already-a-token -> token map -> canonical safe label -> keep OID -> fresh HMAC.
# The token map is consulted before the HMAC fallback, so a mapped value always
# wins -- guaranteeing identical tokens no matter which path reaches it.
function Get-Token {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Prefix)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $clean = $Value.Trim()
    if (Is-AlreadyToken -Value $clean) { return $clean }
    $norm = Normalize-TokenKey -Value $clean
    if ($norm -and $script:TokenByNorm.ContainsKey($norm)) { return $script:TokenByNorm[$norm] }
    if ($script:ScrubPolicy -ne 'Strict' -and (Test-UlsWellKnownSid -Value $clean)) { return $clean }
    if ($script:ScrubPolicy -ne 'Strict' -and (Test-UlsWellKnownWindowsPrincipal -Value $clean)) { return $clean }
    $known = Get-CanonicalKnownLabelByValue -Value $clean
    if ($known) { return $known }
    if (Test-PreserveDottedDecimal -Value $clean) { return $clean }   # leave OIDs / versions (not IPs) intact
    # ULS perf patch 5 (FP fix): never tokenize loopback / localhost on ANY path. The universal-label
    # path otherwise reached the HMAC fallback without the shape path's loopback guard, so values like
    # ::1 ended up tokenized. Gated -- Strict still tokenizes everything.
    if ($script:ScrubPolicy -ne 'Strict' -and (Test-PreserveIpAddress -Value $clean)) { return $clean }
    if ($script:ScrubPolicy -ne 'Strict' -and $Prefix -eq 'IP6' -and -not (Test-UlsValidIpv6Address -Value $clean)) { return $clean }
    $token = Invoke-HmacToken -Value $clean -Prefix $Prefix
    if ($token) { return $token }
    return $clean
}

# =====================================================================
# REGION: Shape detectors (single source of truth)
#   Used BOTH by discovery (what to put in the map) and by hardening (what to
#   replace). Keeping one list guarantees the two agree.
# =====================================================================
# Each entry: Name, Prefix, Rx (single-quoted regex, no anchors so it can be
# scanned anywhere in a string).
$script:ShapeDetectors = @(
    @{ Name = 'SID';       Prefix = 'SID';  Common = $true; Sentinel = 'S-1-'; Rx = 'S-1-\d+(?:-\d+)+' },
    @{ Name = 'GUID';      Prefix = 'GUID'; Common = $true; Rx = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' },
    @{ Name = 'Email/UPN'; Prefix = 'UNMAPPED_UPN'; Sentinel = '@'; Rx = '[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}' },
    @{ Name = 'IPv4';      Prefix = 'IP';   Rx = '(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)' },
    @{ Name = 'DOMAIN\user'; Prefix = 'PRINCIPAL'; Rx = '(?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]+\\[A-Za-z0-9_.\-$]+' },
    @{ Name = 'FQDN';      Prefix = 'DNS';  Rx = '(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}' },
    @{ Name = 'LongHex';   Prefix = 'CERT'; Rx = '(?<![A-Za-z0-9_])[0-9a-fA-F]{20,}(?![A-Za-z0-9_])' },
    # --- v3 additions (also applied at scrub time by Invoke-CommonDetectors) ---
    @{ Name = 'JWT';       Prefix = 'JWT';  Common = $true; Sentinel = 'eyJ'; Rx = 'eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}' },
    @{ Name = 'AWS_ARN';   Prefix = 'ARN';  Common = $true; Sentinel = 'arn:'; Rx = 'arn:aws[A-Za-z0-9\-]*:[A-Za-z0-9\-]*:[A-Za-z0-9\-]*:[0-9]*:[A-Za-z0-9_/.:\-]+' },
    @{ Name = 'AWS_Key';   Prefix = 'AWSKEY'; Common = $true; Rx = '(?:AKIA|ASIA)[0-9A-Z]{16}' },
    @{ Name = 'CloudInstance'; Prefix = 'INSTANCE'; Common = $true; Sentinel = 'i-'; Rx = '\bi-[0-9a-f]{8,17}\b' },
    @{ Name = 'MAC';       Prefix = 'MAC';  Common = $true; Rx = '(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}' },
    @{ Name = 'IPv6';      Prefix = 'IP6';  Common = $true; Skip = '^\d{1,5}(:\d{1,5}){1,7}$'; Rx = '(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}|::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:' },
    @{ Name = 'Base64Blob'; Prefix = 'BLOB'; Common = $true; Rx = '(?<![A-Za-z0-9+/=_])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])' }
)

# Public / well-known domains we deliberately KEEP unredacted so scrubbed logs stay
# readable (and so the FQDN detector does not over-tokenize them). Extended per-run
# from the chosen profile's AllowedDomains.
$script:AllowedDomainsDefault = @(
    'microsoft.com','windows.com','microsoftonline.com','office.com','office365.com','live.com',
    'azure.com','windowsupdate.com','msftncsi.com','msn.com','bing.com','outlook.com','msedge.net',
    'google.com','googleapis.com','gstatic.com',
    'apple.com','mozilla.org','amazonaws.com','cloudflare.com','digicert.com','verisign.com',
    'collector.cc','localhost','localdomain','example.com','example.org','example.net'
)
$script:AllowedDomains = @($script:AllowedDomainsDefault)

function Test-AllowedDomain {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().ToLowerInvariant()
    if ($v -match '@([^@]+)$') { $v = $matches[1] }   # email -> domain part
    foreach ($d in $script:AllowedDomains) {
        $dd = ([string]$d).Trim().ToLowerInvariant()
        if ($dd -and ($v -eq $dd -or $v.EndsWith('.' + $dd))) { return $true }
    }
    return $false
}

function Get-DetectionContext {
    param([string]$Text, [int]$Index, [int]$Length, [int]$Radius = 48)
    # ULS perf patch 3: this context string is only consumed by Add-DetectionTrace's
    # detailed trace, which is discarded unless -ExplainDetections or -FalsePositiveReport
    # is active (same gate as Add-DetectionTrace). Skip the Substring + regex on the common
    # (non-reporting) path. Test-DiagnosticContext no longer routes through here (it computes
    # its own window), so this gate cannot affect any preserve / scrub decision.
    if (-not $script:ExplainDetections -and [string]::IsNullOrWhiteSpace($script:FalsePositiveReport)) { return "" }
    if ([string]::IsNullOrEmpty($Text) -or $Index -lt 0) { return "" }
    $start = [Math]::Max(0, $Index - $Radius)
    $end = [Math]::Min($Text.Length, $Index + $Length + $Radius)
    return (($Text.Substring($start, $end - $start)) -replace "`r|`n", " ")
}

function Add-DetectionTrace {
    param(
        [string]$Detector,
        [string]$Action,
        [string]$Value,
        [string]$Token,
        [string]$Reason,
        [string]$ColumnName,
        [string]$Context
    )
    $countKey = ("{0}|{1}" -f $Detector, $Action)
    if (-not $script:DetectionCounts) { $script:DetectionCounts = @{} }
    if (-not $script:DetectionCounts.ContainsKey($countKey)) { $script:DetectionCounts[$countKey] = 0 }
    $script:DetectionCounts[$countKey] = [int]$script:DetectionCounts[$countKey] + 1
    if (-not $script:ExplainDetections -and [string]::IsNullOrWhiteSpace($script:FalsePositiveReport)) { return }
    if (-not $script:DetectionTraceSeen) { $script:DetectionTraceSeen = @{} }
    $traceKey = (@($Detector,$Action,$Value,$Token,$Reason,$ColumnName) | ForEach-Object { if ($null -eq $_) { '' } else { [string]$_ } }) -join ([string]([char]31))
    if ($script:DetectionTraceSeen.ContainsKey($traceKey)) { return }
    $script:DetectionTraceSeen[$traceKey] = $true
    if (-not $script:DetectionTrace) { $script:DetectionTrace = New-Object System.Collections.Generic.List[object] }
    [void]$script:DetectionTrace.Add([pscustomobject]@{
        Detector = $Detector
        Action   = $Action
        Value    = $Value
        Token    = $Token
        Reason   = $Reason
        Column   = $ColumnName
        Context  = $Context
    })
}

function Test-KnownFileOrDiagnosticName {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':')
    return (
        $v -match '(?i)\.(exe|dll|sys|log|dat|xml|csv|txt|dmp|tmp|etl|evtx|edb|asar|unpacked|jar|sqm|mui|cat|inf|werinternalmetadata)$' -or
        $v -match '(?i)^WER[.-]' -or
        $v -match '(?i)^DSS\d*\.log$' -or
        $v -match '(?i)^0x[0-9a-f]+$'
    )
}

function Test-WindowsDiagnosticDottedName {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('"', "'", ',', ';', ':')
    return (
        (Test-KnownFileOrDiagnosticName -Value $v) -or
        $v -match '(?i)^(Microsoft|MicrosoftWindows)\.' -or
        $v -match '(?i)^Microsoft[A-Za-z0-9]+\.' -or
        $v -match '(?i)\.(Addin|AddinLoader|FormRegionAddin|Connect|FastConnect)(\.|$)' -or
        $v -match '(?i)^(OneNote|Outlook|Teams|UmOutlook|OscAddin|ShellExperienceHost|StartMenuExperienceHost|MicrosoftOfficeHub)\.' -or
        $v -match '^\d+\.\d+(?:\.\d+)*(?:Z)?$' -or
        $v -match '^\d+\.\d{6,}Z$' -or
        $v -match '^[A-Za-z][A-Za-z0-9_-]*\d+(?:\.\d+){2,}$'
    )
}

function Test-WindowsPathLikeDomainUser {
    param([string]$Value, [string]$Text, [int]$Index = -1, [int]$Length = 0)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }
    $v = $Value.Trim()
    if ($v -notmatch '\\') { return $false }
    $first = ($v -split '\\', 2)[0].Trim()
    $second = ($v -split '\\', 2)[1].Trim()
    if ($first -match '(?i)^(windows|winnt|system32|syswow64|sysnative|systemroot|drivers|users|public|default|programdata|appdata|microsoft|program files( \(x86\))?|inf|temp|tmp|config|fonts|assembly|servicing|winsxs|tasks|spool|wbem|registry|device|harddiskvolume\d*|office\d+|wer|reportqueue|reportarchive|livekernelreports|whea)$') { return $true }
    if ($second -match '(?i)^(windows|wer|temp|system32|syswow64|office\d+)$') { return $true }
    if (Test-KnownFileOrDiagnosticName -Value $second) { return $true }
    if (-not [string]::IsNullOrEmpty($Text) -and $Index -ge 0) {
        $before = if ($Index -gt 0) { [string]$Text[$Index - 1] } else { '' }
        $aft = $Index + [Math]::Max($Length, $v.Length)
        $after = if ($aft -lt $Text.Length) { [string]$Text[$aft] } else { '' }
        if ((@('\', '/', ':', '?') -contains $before) -or (@('\', '/') -contains $after)) { return $true }
        $cs = [Math]::Max(0, $Index - 32)
        $ctx = $Text.Substring($cs, $Index - $cs)
        if (($ctx -match '[A-Za-z]:\\') -or ($ctx -match '\\\\\?\\') -or ($ctx -match '\\[^\\"'',;]*$')) { return $true }
    }
    return $false
}

function Test-LooksLikeBase64Blob {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim()
    if ($v.Length -lt 40) { return $false }
    if ($v -match '[\\:]') { return $false }
    if ($v -match '(?i)[a-z]{3,}/[a-z]{3,}/') { return $false }
    $pad = $v
    while (($pad.Length % 4) -ne 0) { $pad += '=' }
    try {
        $bytes = [Convert]::FromBase64String($pad)
        return ($bytes.Length -ge 24)
    }
    catch { return $false }
}

function Test-DiagnosticContext {
    param([string]$Text, [int]$Index, [int]$Length)
    # Computes its own context window (was Get-DetectionContext -Radius 80) so the perf
    # gate added to Get-DetectionContext cannot change this preserve decision. The window
    # math and the cleanup regex are identical to the previous behavior.
    if ([string]::IsNullOrEmpty($Text) -or $Index -lt 0) { return $false }
    $start = [Math]::Max(0, $Index - 80)
    $end   = [Math]::Min($Text.Length, $Index + $Length + 80)
    $ctx   = (($Text.Substring($start, $end - $start)) -replace "`r|`n", " ")
    return ($ctx -match '(?i)\b(WER|Windows Error Reporting|Fault bucket|Report Id|ReportQueue|ReportArchive|AppHang|LiveKernelEvent|Hashed bucket|Cab Guid|Attached files)\b')
}

function Test-PreserveIpAddress {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim()
    return ($v -match '^(127)(?:\.\d{1,3}){3}$' -or $v -eq '::1' -or $v -ieq 'localhost')
}

function Test-PreserveGuid {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('{','}')
    return ($v -eq '00000000-0000-0000-0000-000000000000')
}

function __ULS_Legacy_Test_PreserveDetectedValue_763 {
    param(
        [string]$Value,
        [string]$Detector,
        [string]$Prefix,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if (Test-ScrubAllowlist -Value $Value) { return $true }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }
    $v = $Value.Trim()
    if (Is-AlreadyToken -Value $v) { return $true }
    if (Test-PreserveDottedDecimal -Value $v) { return $true }
    if (($Prefix -eq 'IP' -or $Prefix -eq 'IP6') -and (Test-PreserveIpAddress -Value $v)) { return $true }
    if ($Prefix -eq 'GUID' -and (Test-PreserveGuid -Value $v)) { return $true }
    if ($Detector -eq 'DOMAIN\user' -or $Prefix -eq 'PRINCIPAL') {
        if (Test-WindowsPathLikeDomainUser -Value $v -Text $Text -Index $Index -Length $Length) { return $true }
    }
    if ($Prefix -eq 'DNS') {
        if (Test-AllowedDomain -Value $v) { return $true }
        if (Test-WindowsDiagnosticDottedName -Value $v) { return $true }
        if ($script:ScrubPolicy -eq 'Readable' -and (Test-KnownFileOrDiagnosticName -Value $v)) { return $true }
    }
    if ($Prefix -eq 'BLOB' -and -not (Test-LooksLikeBase64Blob -Value $v)) { return $true }
    if (($Prefix -eq 'GUID' -or $Prefix -eq 'CERT') -and (Test-DiagnosticContext -Text $Text -Index $Index -Length $Length)) { return $true }
    return $false
}

function New-ScrubRegex {
    param(
        [Parameter(Mandatory)][string]$Pattern,
        [string]$Context = 'regex',
        [System.Text.RegularExpressions.RegexOptions]$Options = ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline)
    )
    try {
        return [regex]::new($Pattern, $Options, $script:RegexTimeout)
    }
    catch {
        throw "Invalid $Context '$Pattern': $($_.Exception.Message)"
    }
}

function Resolve-ProfileTokenPrefix {
    param([Parameter(Mandatory)][string]$Prefix, [string]$Context = 'profile rule')
    $p = $Prefix.Trim().ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($p)) { throw "$Context has an empty Prefix." }
    if (@($script:KnownTokenPrefixes | Where-Object { $_ -ieq $p }).Count -eq 0) {
        throw "$Context has invalid Prefix '$Prefix'. Expected one of: $($script:KnownTokenPrefixes -join ', ')."
    }
    return $p
}

function Get-ShannonEntropy {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return 0.0 }
    $counts = @{}
    foreach ($ch in $Value.ToCharArray()) {
        $k = [string]$ch
        if (-not $counts.ContainsKey($k)) { $counts[$k] = 0 }
        $counts[$k] = [int]$counts[$k] + 1
    }
    $entropy = 0.0
    foreach ($k in $counts.Keys) {
        $p = [double]$counts[$k] / [double]$Value.Length
        if ($p -gt 0) { $entropy -= $p * ([Math]::Log($p, 2)) }
    }
    return $entropy
}

function ConvertTo-ColumnRuleRegex {
    param([string]$Exact, [string]$Wildcard, [string]$Regex, [string]$Context)
    if (-not [string]::IsNullOrWhiteSpace($Regex)) { return (New-ScrubRegex -Pattern $Regex -Context $Context) }
    if (-not [string]::IsNullOrWhiteSpace($Wildcard)) {
        $pat = '^' + ([regex]::Escape($Wildcard) -replace '\\\*', '.*' -replace '\\\?', '.') + '$'
        return (New-ScrubRegex -Pattern $pat -Context $Context)
    }
    if (-not [string]::IsNullOrWhiteSpace($Exact)) {
        return (New-ScrubRegex -Pattern ('^' + [regex]::Escape($Exact) + '$') -Context $Context)
    }
    throw "$Context requires Exact, Wildcard, or Regex."
}

function ConvertTo-ProfileColumnRules {
    param($Rules, [string]$DefaultAction = 'Scan', [string]$DefaultPrefix = 'OBJECT', [string]$Context = 'profile column rule')
    $out = New-Object System.Collections.Generic.List[object]
    $defaultPrefixResolved = Resolve-ProfileTokenPrefix -Prefix $DefaultPrefix -Context $Context
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        if ($r -is [string]) {
            $rx = ConvertTo-ColumnRuleRegex -Exact $r -Context $Context
            [void]$out.Add([pscustomobject]@{ RegexObject=$rx; Action=$DefaultAction; Prefix=$defaultPrefixResolved; SplitOn=$null; Description='' })
            continue
        }
        $actionRaw = if ($r.Action) { [string]$r.Action } else { $DefaultAction }
        $actionMatch = @('Scrub','Scan','PassThrough') | Where-Object { $_ -ieq $actionRaw } | Select-Object -First 1
        if (-not $actionMatch) { throw "$Context has invalid Action '$actionRaw'. Expected Scrub, Scan, or PassThrough." }
        $action = [string]$actionMatch
        $prefixRaw = if ($r.Prefix) { [string]$r.Prefix } else { $defaultPrefixResolved }
        $prefix = Resolve-ProfileTokenPrefix -Prefix $prefixRaw -Context $Context
        $exactValues = @()
        if ($r.Exact) { $exactValues += @($r.Exact) }
        if ($r.Column) { $exactValues += @($r.Column) }
        if ($r.Columns) { $exactValues += @($r.Columns) }
        if ($r.Name) { $exactValues += @($r.Name) }
        $wildcards = @()
        if ($r.Wildcard) { $wildcards += @($r.Wildcard) }
        if ($r.Pattern -and -not $r.Regex) { $wildcards += @($r.Pattern) }
        $regexes = @()
        if ($r.Regex) { $regexes += @($r.Regex) }
        if ($r.Match -eq 'Regex' -and $r.Pattern) { $regexes += @($r.Pattern) }
        foreach ($ex in $exactValues) {
            if ([string]::IsNullOrWhiteSpace([string]$ex)) { continue }
            $rx = ConvertTo-ColumnRuleRegex -Exact ([string]$ex) -Context $Context
            [void]$out.Add([pscustomobject]@{ RegexObject=$rx; Action=$action; Prefix=$prefix; SplitOn=$r.SplitOn; Description=([string]$r.Description) })
        }
        foreach ($wc in $wildcards) {
            if ([string]::IsNullOrWhiteSpace([string]$wc)) { continue }
            $rx = ConvertTo-ColumnRuleRegex -Wildcard ([string]$wc) -Context $Context
            [void]$out.Add([pscustomobject]@{ RegexObject=$rx; Action=$action; Prefix=$prefix; SplitOn=$r.SplitOn; Description=([string]$r.Description) })
        }
        foreach ($re in $regexes) {
            if ([string]::IsNullOrWhiteSpace([string]$re)) { continue }
            $rx = ConvertTo-ColumnRuleRegex -Regex ([string]$re) -Context $Context
            [void]$out.Add([pscustomobject]@{ RegexObject=$rx; Action=$action; Prefix=$prefix; SplitOn=$r.SplitOn; Description=([string]$r.Description) })
        }
    }
    return @($out.ToArray())
}

function Read-ScrubListFile {
    param([Parameter(Mandatory)][string]$Path, [string]$BasePath)
    $p = $Path
    if (-not [System.IO.Path]::IsPathRooted($p) -and $BasePath) { $p = Join-Path $BasePath $p }
    if (-not (Test-Path -LiteralPath $p)) { throw "List file not found: $Path" }
    $items = New-Object System.Collections.Generic.List[string]
    foreach ($line in [System.IO.File]::ReadLines((Resolve-Path -LiteralPath $p).Path)) {
        $t = ([string]$line).Trim()
        if ([string]::IsNullOrWhiteSpace($t) -or $t.StartsWith('#')) { continue }
        [void]$items.Add($t)
    }
    return @($items.ToArray())
}

function Merge-ScrubTerms {
    param([string[]]$Terms = @(), [string[]]$Files = @(), [string]$BasePath)
    $seen = @{}
    foreach ($term in @($Terms)) {
        $t = ([string]$term).Trim()
        if ($t.Length -lt 3) { continue }
        $k = $t.ToLowerInvariant()
        if (-not $seen.ContainsKey($k)) { $seen[$k] = $t }
    }
    foreach ($file in @($Files)) {
        if ([string]::IsNullOrWhiteSpace($file)) { continue }
        foreach ($term in (Read-ScrubListFile -Path $file -BasePath $BasePath)) {
            $t = ([string]$term).Trim()
            if ($t.Length -lt 3) { continue }
            $k = $t.ToLowerInvariant()
            if (-not $seen.ContainsKey($k)) { $seen[$k] = $t }
        }
    }
    return @($seen.Values | Sort-Object)
}

function Add-AllowlistEntry {
    param($Entry, [string]$BasePath)
    if ($null -eq $Entry) { return }
    if ($Entry -is [string]) {
        $t = $Entry.Trim()
        if ([string]::IsNullOrWhiteSpace($t)) { return }
        if ($t -match '(?i)^regex:(.+)$') {
            $script:RuntimeAllowRegex += (New-ScrubRegex -Pattern $matches[1].Trim() -Context 'allowlist regex')
        }
        elseif ($t -match '(?i)^domain:(.+)$') {
            $script:AllowedDomains += @($matches[1].Trim())
        }
        else {
            $script:RuntimeAllowExact[$t.ToLowerInvariant()] = $true
        }
        return
    }
    if ($Entry.Domain) { $script:AllowedDomains += @([string]$Entry.Domain) }
    if ($Entry.Regex) { $script:RuntimeAllowRegex += (New-ScrubRegex -Pattern ([string]$Entry.Regex) -Context 'allowlist regex') }
    if ($Entry.Value) { $script:RuntimeAllowExact[([string]$Entry.Value).Trim().ToLowerInvariant()] = $true }
    if ($Entry.Exact) { foreach ($v in @($Entry.Exact)) { if ($v) { $script:RuntimeAllowExact[([string]$v).Trim().ToLowerInvariant()] = $true } } }
}

function Test-ScrubAllowlist {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':', '}', ']', ')')
    if ($script:RuntimeAllowExact -and $script:RuntimeAllowExact.ContainsKey($v.ToLowerInvariant())) { return $true }
    foreach ($rx in @($script:RuntimeAllowRegex)) {
        if ($rx.IsMatch($v)) { return $true }
    }
    if (Test-AllowedDomain -Value $v) { return $true }
    return $false
}

function Get-DefaultUniversalLabelRules {
    return @(
        [pscustomobject]@{ Name='SecretLabels'; Labels=@('api key','api_key','apikey','access token','access_token','refresh token','refresh_token','client secret','client_secret','secret','password','passwd','pwd','authorization','auth token','bearer token'); Prefix='SECRET'; SeparatorRegex='[:=]'; ValueRegex=$null; PreserveRegex='(?i)^(redacted|masked|null|none|\*+|x+)$' },
        [pscustomobject]@{ Name='PrincipalLabels'; Labels=@('account name','account','user name','username','user','principal','subject','actor','caller','login','identity','client user'); Prefix='PRINCIPAL'; SeparatorRegex='[:=]'; ValueRegex=$null; PreserveRegex=$null },
        [pscustomobject]@{ Name='DomainTenantLabels'; Labels=@('account domain','domain','tenant','tenant id','tenantid','organization','org','realm'); Prefix='X500'; SeparatorRegex='[:=]'; ValueRegex=$null; PreserveRegex=$null },
        [pscustomobject]@{ Name='HostLabels'; Labels=@('host','hostname','server','server name','machine','machine name','computer','computer name','device','workstation','workstation name','client name','target server name','pod','container','node','instance'); Prefix='DNS'; SeparatorRegex='[:=]'; ValueRegex=$null; PreserveRegex=$null },
        [pscustomobject]@{ Name='AddressLabels'; Labels=@('ip','ip address','src_ip','dst_ip','source ip','destination ip','source address','destination address','source network address','client address','remote addr','remote_addr','x-forwarded-for'); Prefix='IP'; SeparatorRegex='[:=]'; ValueRegex=$null; PreserveRegex=$null },
        [pscustomobject]@{ Name='UrlLabels'; Labels=@('url','uri','endpoint','callback','redirect_uri','redirect uri'); Prefix='URI'; SeparatorRegex='[:=]'; ValueRegex=$null; PreserveRegex=$null },
        [pscustomobject]@{ Name='ObjectIdLabels'; Labels=@('session','session id','sessionid','request id','requestid','correlation id','correlationid','trace id','traceid','span id','spanid','transaction id','transactionid'); Prefix='OBJECT'; SeparatorRegex='[:=]'; ValueRegex=$null; PreserveRegex=$null }
    )
}

function ConvertTo-UniversalLabelRule {
    param($Rule, [string]$Context = 'label rule')
    $name = if ($Rule.Name) { [string]$Rule.Name } else { $Context }
    $prefixRaw = if ($Rule.Prefix) { [string]$Rule.Prefix } else { 'OBJECT' }
    $prefix = Resolve-ProfileTokenPrefix -Prefix $prefixRaw -Context "$Context '$name'"
    $sep = if ($Rule.SeparatorRegex) { [string]$Rule.SeparatorRegex } else { '[:=]' }
    $valueRx = if ($Rule.ValueRegex) { [string]$Rule.ValueRegex } else { '(?:"[^"\r\n]{1,512}"|''[^''\r\n]{1,512}''|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|NT AUTHORITY|Window Manager|Font Driver Host|[^,\s;|]{1,512})' }
    $labelRx = $null
    if ($Rule.LabelRegex) { $labelRx = [string]$Rule.LabelRegex }
    else {
        $labels = @()
        if ($Rule.Labels) { $labels += @($Rule.Labels) }
        if ($Rule.Label) { $labels += @($Rule.Label) }
        if ($labels.Count -eq 0) { throw "$Context '$name' requires Labels or LabelRegex." }
        $labelRx = (($labels | ForEach-Object { [regex]::Escape(([string]$_).Trim()) }) -join '|')
    }
    $full = "(?im)((?<![A-Za-z0-9_])(?:$labelRx)(?![A-Za-z0-9_])\s*(?:$sep)\s*)($valueRx)"
    $preserve = if ($Rule.PreserveRegex) { New-ScrubRegex -Pattern ([string]$Rule.PreserveRegex) -Context "$Context preserve regex" } else { $null }
    $allow = @{}
    if ($Rule.Preserve) { foreach ($p in @($Rule.Preserve)) { if ($p) { $allow[([string]$p).Trim().ToLowerInvariant()] = $true } } }
    return [pscustomobject]@{
        Name = $name
        Prefix = $prefix
        RegexObject = (New-ScrubRegex -Pattern $full -Context "$Context '$name'")
        PreserveRegex = $preserve
        PreserveExact = $allow
    }
}

function Get-UniversalLabeledValuePrefix {
    param([string]$Label, [string]$Value, [string]$DefaultPrefix)
    $v = ([string]$Value).Trim().Trim('"', "'")
    if ([string]::IsNullOrWhiteSpace($v)) { return $null }
    if ($DefaultPrefix -match '^(SECRET|APIKEY|CONNSTR|PEM)$') { return $DefaultPrefix }
    if ($Label -match '(?i)(key|secret|token|password|passwd|pwd|auth)') { return 'SECRET' }
    if ($Label -match '(?i)(address|addr|ip|x-forwarded)') {
        if ($v -match '^\d{1,3}(\.\d{1,3}){3}$') { return 'IP' }
        if ($v -match ':') { return 'IP6' }
        return 'DNS'
    }
    if ($Label -match '(?i)(url|uri|endpoint|callback|redirect)') { return 'URI' }
    if ($Label -match '(?i)(host|server|machine|computer|device|workstation|node|pod|container|instance|client name)') { return 'DNS' }
    if ($Label -match '(?i)(domain|tenant|organization|org|realm)') { return 'X500' }
    if ($v -match '\$$') { return 'COMPUTER' }
    if ($DefaultPrefix) { return $DefaultPrefix }
    return 'OBJECT'
}

function Test-PreserveUniversalLabeledValue {
    param($Rule, [string]$Label, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':', '}', ']', ')')
    if ([string]::IsNullOrWhiteSpace($v)) { return $true }
    if (Is-AlreadyToken -Value $v) { return $true }
    if (Test-ScrubAllowlist -Value $v) { return $true }
    if ($Rule.PreserveExact -and $Rule.PreserveExact.ContainsKey($v.ToLowerInvariant())) { return $true }
    if ($Rule.PreserveRegex -and $Rule.PreserveRegex.IsMatch($v)) { return $true }
    if ($v -match '^(?:-|N/A|NULL|\(null\))$') { return $true }
    if ($v -match '(?i)^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|Guest|DefaultAccount|WDAGUtilityAccount|DWM-\d+|UMFD-\d+)$') { return $true }
    if ($v -match '(?i)^(WORKGROUP|NT AUTHORITY|BUILTIN|Window Manager|Font Driver Host)$') { return $true }
    if (($Label -match '(?i)(Address|IP|addr)') -and (Test-PreserveIpAddress -Value $v)) { return $true }
    return $false
}

function __ULS_Legacy_Find_UniversalLabeledIdentifiers_1040 {
    param([Parameter(Mandatory)][string]$Text)
    $found = @{}
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    foreach ($rule in @($script:RuntimeLabelRules)) {
        foreach ($m in $rule.RegexObject.Matches($Text)) {
            $label = ($m.Groups[1].Value -replace '\s*(?:[:=])\s*$', '').Trim()
            $raw = $m.Groups[2].Value.Trim().Trim('"', "'")
            if (Test-PreserveUniversalLabeledValue -Rule $rule -Label $label -Value $raw) { continue }
            $prefix = Get-UniversalLabeledValuePrefix -Label $label -Value $raw -DefaultPrefix $rule.Prefix
            if (-not $prefix) { continue }
            $norm = Normalize-TokenKey -Value $raw
            if ($norm -and -not $found.ContainsKey($norm)) {
                $found[$norm] = [pscustomobject]@{ Raw = $raw; Prefix = $prefix; Rule = $rule.Name }
            }
        }
    }
    return @($found.Values)
}

function Find-UniversalLabeledLeaks {
    param([Parameter(Mandatory)][string]$Text)
    $leaks = @()
    foreach ($id in (Find-UniversalLabeledIdentifiers -Text $Text)) {
        $rawLeakValue = [string]$id.Raw
        if (Is-AlreadyToken -Value $rawLeakValue) { continue }
        if ($rawLeakValue -match '(?i)^[a-z][a-z0-9+.-]*://[^/\s]*(?:HV_)?(?:PRINCIPAL|COMPUTER|GROUP|OBJECT|SID|DNS|UPN|EMAIL|CERT|TEMPLATE|CA|X500|GUID|IP|IP6|HOST|URL|URI|MAC|JWT|ARN|AWSKEY|INSTANCE|BLOB|SECRET|APIKEY|CONNSTR|PEM)_[A-F0-9]{4,}') { continue }
        if ($rawLeakValue -match '(?i)^(?:Bearer|Basic|Digest|Token)?\s*(?:HV_)?(?:PRINCIPAL|COMPUTER|GROUP|OBJECT|SID|DNS|UPN|EMAIL|CERT|TEMPLATE|CA|X500|GUID|IP|IP6|HOST|URL|URI|MAC|JWT|ARN|AWSKEY|INSTANCE|BLOB|SECRET|APIKEY|CONNSTR|PEM)_[A-F0-9]{4,}$') { continue }
        # ULS patch 7 (consistency fix): do NOT flag values the scrubber intentionally preserves, so
        # the leak check agrees with Get-Token. Loopback / localhost (::1, 127.x) are preserved by
        # Get-Token in Balanced/Readable (patch 5); without this the check flagged its own preserve
        # (e.g. "AddressLabels: ::1") and failed a file that holds nothing sensitive.
        if ($script:ScrubPolicy -ne 'Strict' -and (Test-PreserveIpAddress -Value $rawLeakValue)) { continue }
        $leaks += ("{0}: {1}" -f $id.Rule, $rawLeakValue)
    }
    return @($leaks | Select-Object -Unique)
}

function Invoke-UniversalLabelHardening {
    param([Parameter(Mandatory)][string]$Text, [string]$ColumnName)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    $out = $Text
    foreach ($rule in @($script:RuntimeLabelRules)) {
        $out = $rule.RegexObject.Replace($out, {
            param($m)
            $prefixText = $m.Groups[1].Value
            $label = ($prefixText -replace '\s*(?:[:=])\s*$', '').Trim()
            $raw = $m.Groups[2].Value.Trim().Trim('"', "'")
            if (Test-PreserveUniversalLabeledValue -Rule $rule -Label $label -Value $raw) { return $m.Value }
            # ULS patch 9: apply the same high-confidence low-signal filter the discovery and leak-check
            # finders use, so the scrub agrees with them and stops tokenizing junk words after labels.
            if (Test-UlsRound3LowSignalUniversalLabel -Value $raw -Rule $rule.Name) { return $m.Value }
            $prefix = Get-UniversalLabeledValuePrefix -Label $label -Value $raw -DefaultPrefix $rule.Prefix
            if (-not $prefix) { return $m.Value }
            $tok = Get-Token -Value $raw -Prefix $prefix
            Add-DetectionTrace -Detector 'UniversalLabel' -Action 'Tokenized' -Value $raw -Token $tok -Reason $rule.Name -ColumnName $ColumnName -Context (Get-DetectionContext -Text $Text -Index $m.Index -Length $m.Length)
            return $prefixText + $tok
        })
    }
    return $out
}

function Test-RuleAllowlistedSecret {
    param($Rule, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    $v = $Value.Trim().Trim('"', "'")
    if (Test-ScrubAllowlist -Value $v) { return $true }
    if ($Rule.AllowExact -and $Rule.AllowExact.ContainsKey($v.ToLowerInvariant())) { return $true }
    foreach ($rx in @($Rule.AllowRegex)) { if ($rx.IsMatch($v)) { return $true } }
    if ($Rule.Entropy -and ((Get-ShannonEntropy -Value $v) -lt [double]$Rule.Entropy)) { return $true }
    return $false
}

function Find-CustomRegexIdentifiers {
    param([Parameter(Mandatory)][string]$Text)
    $found = @{}
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    foreach ($rule in @($script:RuntimeCustomRegexRules)) {
        if ($rule.Keywords -and $rule.Keywords.Count -gt 0) {
            $hasKeyword = $false
            foreach ($kw in @($rule.Keywords)) { if ($Text.IndexOf([string]$kw, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hasKeyword = $true; break } }
            if (-not $hasKeyword) { continue }
        }
        foreach ($m in $rule.RegexObject.Matches($Text)) {
            $group = [int]$rule.CaptureGroup
            if ($group -ge $m.Groups.Count -or -not $m.Groups[$group].Success) { continue }
            $raw = $m.Groups[$group].Value.Trim().Trim('"', "'")
            if (Test-RuleAllowlistedSecret -Rule $rule -Value $raw) { continue }
            if (Is-AlreadyToken -Value $raw) { continue }
            $norm = Normalize-TokenKey -Value $raw
            if ($norm -and -not $found.ContainsKey($norm)) {
                $found[$norm] = [pscustomobject]@{ Raw = $raw; Prefix = $rule.Prefix; Rule = $rule.Name }
            }
        }
    }
    return @($found.Values)
}

function Invoke-CustomRegexHardening {
    param([Parameter(Mandatory)][string]$Text, [string]$ColumnName)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    $out = $Text
    foreach ($rule in @($script:RuntimeCustomRegexRules)) {
        if ($rule.Keywords -and $rule.Keywords.Count -gt 0) {
            $hasKeyword = $false
            foreach ($kw in @($rule.Keywords)) { if ($out.IndexOf([string]$kw, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hasKeyword = $true; break } }
            if (-not $hasKeyword) { continue }
        }
        $out = $rule.RegexObject.Replace($out, {
            param($m)
            $group = [int]$rule.CaptureGroup
            if ($group -ge $m.Groups.Count -or -not $m.Groups[$group].Success) { return $m.Value }
            $raw = $m.Groups[$group].Value.Trim().Trim('"', "'")
            if (Test-RuleAllowlistedSecret -Rule $rule -Value $raw) { return $m.Value }
            if (Is-AlreadyToken -Value $raw) { return $m.Value }
            $tok = Get-Token -Value $raw -Prefix $rule.Prefix
            Add-DetectionTrace -Detector 'CustomRegex' -Action 'Tokenized' -Value $raw -Token $tok -Reason $rule.Name -ColumnName $ColumnName -Context (Get-DetectionContext -Text $Text -Index $m.Index -Length $m.Length)
            if ($group -eq 0) { return $tok }
            $rel = $m.Groups[$group].Index - $m.Index
            return $m.Value.Substring(0, $rel) + $tok + $m.Value.Substring($rel + $m.Groups[$group].Length)
        })
    }
    return $out
}

function Test-UlsWindowsUserPathHardeningNeeded {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    # One sentinel catches both normal paths (C:\Users\name) and JSON/CSV-escaped
    # paths (C:\\Users\\name), because the escaped form still contains "\Users\"
    # starting at its second slash. Avoids a second full-string IndexOf on hot fields.
    return ($Text.IndexOf('\Users\', [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
}

function Invoke-WindowsPathUserHardening {
    param([Parameter(Mandatory)][string]$Text)
    if (-not (Test-UlsWindowsUserPathHardeningNeeded -Text $Text)) { return $Text }

    $preserveProfileRegex = '^(Public|Default|Default User|All Users)$'
    $replaceProfile = {
        param($m)
        $profile = $m.Groups[2].Value
        if ([string]::IsNullOrWhiteSpace($profile) -or
            $profile -match $preserveProfileRegex -or
            (Is-AlreadyToken -Value $profile)) {
            return $m.Value
        }
        return $m.Groups[1].Value + (Get-Token -Value $profile -Prefix "PRINCIPAL")
    }

    # Normal Windows paths: C:\Users\alice\...
    $out = $script:__rxWinUserPathNormal.Replace($Text, $replaceProfile)

    # JSON/CSV-escaped Windows paths: C:\\Users\\alice\\...
    $out = $script:__rxWinUserPathEscaped.Replace($out, $replaceProfile)
    return $out
}

function Get-WindowsEventLabelRegex {
    return '(?im)(Account Name|Account Domain|User Name|Target User Name|Subject User Name|Service Name|Workstation Name|Source Network Address|Client Address|Client Name|Computer Name|Machine Name|Target Server Name)\s*:\s*(\S+)'
}

function Test-PreserveWindowsLabeledValue {
    param([string]$Label, [string]$Value)
    $rule = [pscustomobject]@{ PreserveExact=@{}; PreserveRegex=$null }
    return (Test-PreserveUniversalLabeledValue -Rule $rule -Label $Label -Value $Value)
}

function Get-WindowsLabeledValuePrefix {
    param([string]$Label, [string]$Value)
    return (Get-UniversalLabeledValuePrefix -Label $Label -Value $Value -DefaultPrefix 'PRINCIPAL')
}

function Find-WindowsLabeledIdentifiers {
    param([Parameter(Mandatory)][string]$Text)
    return Find-UniversalLabeledIdentifiers -Text $Text
}

function Find-WindowsLabeledLeaks {
    param([Parameter(Mandatory)][string]$Text)
    return Find-UniversalLabeledLeaks -Text $Text
}

function Invoke-WindowsEventLabelHardening {
    param([Parameter(Mandatory)][string]$Text, [string]$ColumnName)
    return Invoke-UniversalLabelHardening -Text $Text -ColumnName $ColumnName
}

function Test-PreserveSecretCandidate {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    $v = $Value.Trim().Trim('"', "'")
    if ($v.Length -lt 8) { return $true }
    if (Is-AlreadyToken -Value $v) { return $true }
    if ($v -match '(?i)^(true|false|null|none|redacted|masked|password|\*+|x+)$') { return $true }
    if (Test-KnownFileOrDiagnosticName -Value $v) { return $true }
    return $false
}

function __ULS_Legacy_Find_SecretIdentifiers_1204 {
    param([Parameter(Mandatory)][string]$Text)
    $found = @{}
    if ($Text -notmatch '(?i)(Authorization\s*[:=]|Bearer\s+|Basic\s+|password\s*[:=]|passwd\s*[:=]|pwd\s*[:=]|secret\s*[:=]|client_secret|api[_-]?key\s*[:=]|access[_-]?token\s*[:=]|refresh[_-]?token\s*[:=]|private[_-]?key\s*[:=]|PRIVATE KEY|connectionstring|connstr|Data Source=|Server=[^\r\n]{0,500}(?:Password|Pwd)=|gh[pousr]_|xox[baprs]-|sk_(?:live|test)_|sk-[A-Za-z0-9]|(?:AKIA|ASIA)[0-9A-Z]{16}|\b(?:token|secret|key|password)[A-Za-z0-9_. \-]{0,24}[:=])') { return @() }
    $add = {
        param([string]$Raw, [string]$Prefix)
        if (Test-PreserveSecretCandidate -Value $Raw) { return }
        $norm = Normalize-TokenKey -Value $Raw
        if ($norm -and -not $found.ContainsKey($norm)) {
            $found[$norm] = [pscustomobject]@{ Raw = $Raw.Trim(); Prefix = $Prefix }
        }
    }
    foreach ($m in [regex]::Matches($Text, '(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----')) {
        & $add $m.Value 'PEM'
    }
    foreach ($m in [regex]::Matches($Text, '(?i)\bAuthorization\s*[:=]\s*(?:Bearer|Basic)\s+([A-Za-z0-9+/_=.\-]{12,})')) {
        & $add $m.Groups[1].Value 'SECRET'
    }
    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key)\s*[:=]\s*["'']?([^"''\s;,]{8,})')) {
        & $add $m.Groups[1].Value 'SECRET'
    }
    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:Server|Data Source)=[^;\r\n]+;(?:[^;\r\n]+;){0,8}(?:Password|Pwd)=[^;\r\n]+')) {
        & $add $m.Value 'CONNSTR'
    }
    foreach ($m in [regex]::Matches($Text, '\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9]{20,}|(?:AKIA|ASIA)[0-9A-Z]{16})\b')) {
        & $add $m.Value 'APIKEY'
    }
    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:token|secret|key|password)[A-Za-z0-9_. \-]{0,24}[:=]\s*["'']?([A-Za-z0-9+/_=\-.]{24,})')) {
        & $add $m.Groups[1].Value 'SECRET'
    }
    return @($found.Values)
}

function Invoke-SecretHardening {
    param([Parameter(Mandatory)][string]$Text, [string]$ColumnName)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    if ($Text -notmatch '(?i)(Authorization\s*[:=]|Bearer\s+|Basic\s+|password\s*[:=]|passwd\s*[:=]|pwd\s*[:=]|secret\s*[:=]|client_secret|api[_-]?key\s*[:=]|access[_-]?token\s*[:=]|refresh[_-]?token\s*[:=]|private[_-]?key\s*[:=]|PRIVATE KEY|connectionstring|connstr|Data Source=|Server=[^\r\n]{0,500}(?:Password|Pwd)=|gh[pousr]_|xox[baprs]-|sk_(?:live|test)_|sk-[A-Za-z0-9]|(?:AKIA|ASIA)[0-9A-Z]{16}|\b(?:token|secret|key|password)[A-Za-z0-9_. \-]{0,24}[:=])') { return $Text }
    $out = $Text
    $out = [regex]::Replace($out, '(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', {
        param($m)
        if (Test-PreserveSecretCandidate -Value $m.Value) { return $m.Value }
        $tok = Get-Token -Value $m.Value -Prefix 'PEM'
        Add-DetectionTrace -Detector 'PEM private key' -Action 'Tokenized' -Value '[PEM private key]' -Token $tok -Reason 'Private key block' -ColumnName $ColumnName -Context '[PEM private key]'
        return $tok
    })
    $out = [regex]::Replace($out, '(?i)(\bAuthorization\s*[:=]\s*(?:Bearer|Basic)\s+)([A-Za-z0-9+/_=.\-]{12,})', {
        param($m)
        $secret = $m.Groups[2].Value
        if (Test-PreserveSecretCandidate -Value $secret) { return $m.Value }
        $tok = Get-Token -Value $secret -Prefix 'SECRET'
        Add-DetectionTrace -Detector 'Authorization secret' -Action 'Tokenized' -Value $secret -Token $tok -Reason 'Authorization header' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $m.Groups[1].Value + $tok
    })
    $out = [regex]::Replace($out, '(?i)(\b(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key)\s*[:=]\s*["'']?)([^"''\s;,]{8,})', {
        param($m)
        $secret = $m.Groups[2].Value
        if (Test-PreserveSecretCandidate -Value $secret) { return $m.Value }
        $prefix = if ($m.Groups[1].Value -match '(?i)api[_-]?key') { 'APIKEY' } else { 'SECRET' }
        $tok = Get-Token -Value $secret -Prefix $prefix
        Add-DetectionTrace -Detector 'Key/value secret' -Action 'Tokenized' -Value $secret -Token $tok -Reason 'Secret-like key name' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $m.Groups[1].Value + $tok
    })
    $out = [regex]::Replace($out, '(?i)\b(?:Server|Data Source)=[^;\r\n]+;(?:[^;\r\n]+;){0,8}(?:Password|Pwd)=[^;\r\n]+', {
        param($m)
        if (Test-PreserveSecretCandidate -Value $m.Value) { return $m.Value }
        $tok = Get-Token -Value $m.Value -Prefix 'CONNSTR'
        Add-DetectionTrace -Detector 'Connection string' -Action 'Tokenized' -Value '[connection string]' -Token $tok -Reason 'Password-bearing connection string' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $tok
    })
    $out = [regex]::Replace($out, '\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9]{20,}|(?:AKIA|ASIA)[0-9A-Z]{16})\b', {
        param($m)
        if (Test-PreserveSecretCandidate -Value $m.Value) { return $m.Value }
        $tok = Get-Token -Value $m.Value -Prefix 'APIKEY'
        Add-DetectionTrace -Detector 'API key' -Action 'Tokenized' -Value $m.Value -Token $tok -Reason 'Known secret prefix' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $tok
    })
    $out = [regex]::Replace($out, '(?i)(\b(?:token|secret|key|password)[A-Za-z0-9_. \-]{0,24}[:=]\s*["'']?)([A-Za-z0-9+/_=\-.]{24,})', {
        param($m)
        $secret = $m.Groups[2].Value
        if (Test-PreserveSecretCandidate -Value $secret) { return $m.Value }
        $tok = Get-Token -Value $secret -Prefix 'SECRET'
        Add-DetectionTrace -Detector 'High entropy secret' -Action 'Tokenized' -Value $secret -Token $tok -Reason 'Keyword + high-entropy-looking value' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $m.Groups[1].Value + $tok
    })
    return $out
}

function Write-DetectionReport {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not $script:DetectionTrace -or $script:DetectionTrace.Count -eq 0) { return $null }
    try {
        $out = Resolve-OutPath -Path $Path
        $escape = {
            param($x)
            $s = [string]$x
            $s = $s -replace "`r|`n", " "
            return '"' + ($s -replace '"', '""') + '"'
        }
        $lines = New-Object System.Collections.Generic.List[string]
        [void]$lines.Add('"Detector","Action","Value","Token","Reason","Column","Context"')
        $traceItems = @()
        try { $traceItems = @($script:DetectionTrace.ToArray()) } catch { $traceItems = @($script:DetectionTrace) }
        foreach ($d in $traceItems) {
            $fields = @(
                (& $escape $d.Detector),
                (& $escape $d.Action),
                (& $escape $d.Value),
                (& $escape $d.Token),
                (& $escape $d.Reason),
                (& $escape $d.Column),
                (& $escape $d.Context)
            )
            [void]$lines.Add(($fields -join ','))
        }
        [System.IO.File]::WriteAllText([string]$out, (($lines.ToArray()) -join [Environment]::NewLine), [System.Text.Encoding]::UTF8)
        Write-Warn "Detection review report written: $out"
        Write-Warn "Treat this report like the token map if it contains original values or context."
        return $out
    }
    catch {
        Write-Warn "Could not write detection review report: line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        return $null
    }
}

function Write-DetectionSummaryReport {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not $script:DetectionCounts -or $script:DetectionCounts.Count -eq 0) { return $null }
    try {
        $out = Resolve-OutPath -Path $Path
        $rows = foreach ($k in ($script:DetectionCounts.Keys | Sort-Object)) {
            $parts = $k -split '\|', 2
            [pscustomobject]@{
                Detector = $parts[0]
                Action   = if ($parts.Count -gt 1) { $parts[1] } else { "" }
                Count    = [int]$script:DetectionCounts[$k]
            }
        }
        $rows | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8
        Write-Ok "Safe detection summary written: $out"
        return $out
    }
    catch {
        Write-Warn "Could not write detection summary: $($_.Exception.Message)"
        return $null
    }
}

# v3 detectors that are applied AT SCRUB TIME (in addition to the core passes).
# CSV-safe: every value class stops at quote / comma / whitespace. UNC and URL need
# group handling so they are bespoke; the rest iterate the Common-flagged list above.
function Invoke-CommonDetectors {
    param([Parameter(Mandatory)][string]$Text)
    $out = $Text
    # ULS perf patch 4: cheap literal pre-checks -- skip a pass when the required literal
    # substring is absent from the current text. Hardening replaces identifiers with tokens
    # (which never contain these sentinels) and never ADDS one, so skipping a pass that could
    # not have matched is byte-identical.
    $oic = [System.StringComparison]::OrdinalIgnoreCase
    if ($out.IndexOf('\Users\', $oic) -ge 0) { $out = Invoke-WindowsPathUserHardening -Text $out }

    # UNC path: tokenize the host in \\host\share (before any DOMAIN\user pass).
    if ($out.IndexOf('\\') -ge 0) {
        $out = [regex]::Replace($out, '\\\\([A-Za-z0-9._\-]+)((?:\\[^\s",;]*)?)', {
            param($m)
            $h = $m.Groups[1].Value
            if (Is-AlreadyToken -Value $h) { return $m.Value }
            if (Test-AllowedDomain -Value $h) { return $m.Value }
            if (Test-PreserveDetectedValue -Value $h -Detector 'UNC host' -Prefix 'DNS' -Text $out -Index $m.Groups[1].Index -Length $h.Length) { return $m.Value }
            $tok = Get-Token -Value $h -Prefix "DNS"
            Add-DetectionTrace -Detector 'UNC host' -Action 'Tokenized' -Value $h -Token $tok -Reason 'UNC host' -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
            return '\\' + $tok + $m.Groups[2].Value
        })
    }

    # URL / connection URI: tokenize optional userinfo and the host in scheme://[user@]host[:port]/...
    # Includes common database, cache, queue, Kafka, WebSocket, and JDBC schemes.
    if ($out.IndexOf('://') -ge 0) {
        $out = [regex]::Replace($out, '(?i)\b((?:jdbc:[a-z][a-z0-9+.-]*|https?|ftp|ldap|ldaps|smb|wss?|postgres(?:ql)?|mysql|mssql|sqlserver|redis|mongodb(?:\+srv)?|amqps?|kafka))://([^/\s"'',;]+)', {
            param($m)
            $scheme = $m.Groups[1].Value
            $auth = $m.Groups[2].Value
            $user = ''
            $hostport = $auth
            if ($auth -match '^([^@]+)@(.+)$') { $user = $matches[1]; $hostport = $matches[2] }
            $hp = $hostport; $port = ''
            if ($hostport -match '^(.+):(\d+)$') { $hp = $matches[1]; $port = ':' + $matches[2] }
            $userTok = if ($user) { (Get-Token -Value $user -Prefix "PRINCIPAL") + '@' } else { '' }
            $hostTok = $hp
            if (-not (Is-AlreadyToken -Value $hp) -and -not (Test-AllowedDomain -Value $hp) -and -not (Test-PreserveDetectedValue -Value $hp -Detector 'URL host' -Prefix 'DNS' -Text $out -Index $m.Groups[2].Index -Length $auth.Length)) {
                $hostTok = Get-Token -Value $hp -Prefix "DNS"
                Add-DetectionTrace -Detector 'URL host' -Action 'Tokenized' -Value $hp -Token $hostTok -Reason 'URL authority host' -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
            }
            return $scheme + '://' + $userTok + $hostTok + $port
        })
    }

    # The simple Common-flagged detectors (JWT, ARN, AWS key, instance id, MAC, IPv6, base64).
    foreach ($d in ($script:ShapeDetectors | Where-Object { $_.Common })) {
        if ($d.Sentinel -and ($out.IndexOf([string]$d.Sentinel, $oic) -lt 0)) { continue }
        $skip = $d.Skip
        $prefix = $d.Prefix
        $out = [regex]::Replace($out, $d.Rx, {
            param($m)
            $val = $m.Value
            if (Is-AlreadyToken -Value $val) { return $val }
            if ($skip -and ($val -match $skip)) { return $val }
            if (Test-PreserveDetectedValue -Value $val -Detector $d.Name -Prefix $prefix -Text $out -Index $m.Index -Length $m.Length) {
                Add-DetectionTrace -Detector $d.Name -Action 'Preserved' -Value $val -Token '' -Reason 'Balanced diagnostic preserve' -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
                return $val
            }
            $tok = Get-Token -Value $val -Prefix $prefix
            Add-DetectionTrace -Detector $d.Name -Action 'Tokenized' -Value $val -Token $tok -Reason 'Shape detector' -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
            return $tok
        })
    }
    return $out
}

# Value-only hardening for key=value text (logfmt, CEF/LEEF extensions). Keys are
# preserved; each value is run through the per-field hardener. A whole-text pass
# afterwards (by the caller) catches any identifiers outside key=value form.
function Invoke-KvValueOnlyText {
    param([Parameter(Mandatory)][string]$Text)
    return [regex]::Replace($Text, '([A-Za-z0-9_.\-]+)=("(?:[^"\\]|\\.)*"|[^\s]+)', {
        param($m)
        $key = $m.Groups[1].Value
        $val = $m.Groups[2].Value
        $q = ''
        $inner = $val
        if ($val.Length -ge 2 -and $val[0] -eq '"' -and $val[$val.Length - 1] -eq '"') { $q = '"'; $inner = $val.Substring(1, $val.Length - 2) }
        $scr = Invoke-FreeTextHardening -ColumnName $key -Value $inner
        return $key + '=' + $q + $scr + $q
    })
}

# Decide a token prefix from a value's SHAPE alone (no column context).
function __ULS_Legacy_Get_ValueShapePrefix_1430 {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim()
    if ($v -match '^S-1-\d+-')                                                  { return "SID" }
    if ($v -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') { return "GUID" }
    if ($v -match '^[0-9a-fA-F]{32,}$')                                         { return "CERT" }
    if ($v -match '^[^@\s]+@[^@\s]+\.[^@\s]+$')                                 { return "UNMAPPED_UPN" }
    if ($v -match '^\d{1,3}(\.\d{1,3}){3}$')                                    { return "IP" }
    if ($v -match '^[A-Za-z0-9_.-]+\\[A-Za-z0-9_.\-$]+$')                       { return "PRINCIPAL" }
    if ($v -match '^(CN|OU|DC|O|L|ST|C)=')                                      { return "X500" }
    if ($v -match '^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$')                         { return "DNS" }
    return $null
}

# Return the set of DISTINCT raw identifier strings present in a chunk of text,
# each tagged with a best-effort prefix. Used by the discovery map builder.
function __ULS_Legacy_Find_Identifiers_1447 {
    param([Parameter(Mandatory)][string]$Text)
    $found = @{}   # normalizedKey -> @{ Raw; Prefix }
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    foreach ($id in (Find-UniversalLabeledIdentifiers -Text $Text)) {
        $norm = Normalize-TokenKey -Value $id.Raw
        if ($norm -and -not $found.ContainsKey($norm)) {
            $found[$norm] = [pscustomobject]@{ Raw = $id.Raw; Prefix = $id.Prefix }
        }
    }
    foreach ($id in (Find-CustomRegexIdentifiers -Text $Text)) {
        $norm = Normalize-TokenKey -Value $id.Raw
        if ($norm -and -not $found.ContainsKey($norm)) {
            $found[$norm] = [pscustomobject]@{ Raw = $id.Raw; Prefix = $id.Prefix }
        }
    }
    foreach ($id in (Find-SecretIdentifiers -Text $Text)) {
        $norm = Normalize-TokenKey -Value $id.Raw
        if ($norm -and -not $found.ContainsKey($norm)) {
            $found[$norm] = [pscustomobject]@{ Raw = $id.Raw; Prefix = $id.Prefix }
        }
    }
    foreach ($d in $script:ShapeDetectors) {
        foreach ($m in [regex]::Matches($Text, $d.Rx)) {
            $raw = $m.Value
            if ([string]::IsNullOrWhiteSpace($raw)) { continue }
            if (Is-AlreadyToken -Value $raw) { continue }
            if (Test-PreserveDottedDecimal -Value $raw) { continue }   # OID / version (not an IP)
            if ($d.Skip -and ($raw -match $d.Skip)) { continue }  # e.g. IPv6 detector skips HH:MM:SS
            # Keep well-known public domains readable (don't map them).
            if (($d.Prefix -eq 'DNS' -or $d.Prefix -eq 'UNMAPPED_UPN') -and (Test-AllowedDomain -Value $raw)) { continue }
            if (Test-PreserveDetectedValue -Value $raw -Detector $d.Name -Prefix $d.Prefix -Text $Text -Index $m.Index -Length $m.Length) {
                Add-DetectionTrace -Detector $d.Name -Action 'Preserved' -Value $raw -Token '' -Reason 'Discovery preserve' -Context (Get-DetectionContext -Text $Text -Index $m.Index -Length $m.Length)
                continue
            }
            $norm = Normalize-TokenKey -Value $raw
            if (-not $norm) { continue }
            if (-not $found.ContainsKey($norm)) {
                $found[$norm] = [pscustomobject]@{ Raw = $raw; Prefix = $d.Prefix }
            }
        }
    }
    return @($found.Values)
}

# =====================================================================
# REGION: Token map load / save
# =====================================================================
function Get-MapColumnName {
    param([Parameter(Mandatory)]$Row, [Parameter(Mandatory)][string[]]$Candidates)
    $props = @($Row.PSObject.Properties.Name)
    foreach ($candidate in $Candidates) { if ($props -contains $candidate) { return $candidate } }
    return $null
}

function New-ScrubTokenMapRow {
    param(
        [Parameter(Mandatory)][string]$InputValue,
        [Parameter(Mandatory)][string]$NormalizedValue,
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][string]$TokenType,
        [Parameter(Mandatory)][string]$Source,
        [string]$FirstSeenSource,
        [string]$LastSeenSource,
        [string]$SourcePathHash
    )
    if ([string]::IsNullOrWhiteSpace($FirstSeenSource)) { $FirstSeenSource = $Source }
    if ([string]::IsNullOrWhiteSpace($LastSeenSource)) { $LastSeenSource = $Source }
    [pscustomobject][ordered]@{
        InputValue      = $InputValue
        NormalizedValue = $NormalizedValue
        Token           = $Token
        TokenType       = $TokenType
        Source          = $Source
        SaltFingerprint = (Get-SaltFingerprint)
        HmacLength      = $script:HmacLength
        FirstSeenSource = $FirstSeenSource
        LastSeenSource  = $LastSeenSource
        SourcePathHash  = $SourcePathHash
    }
}

function Test-UlsShouldMapDiscoveredIdentifier {
    param(
        [string]$Raw,
        [string]$Prefix,
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = $script:ScrubPolicy
    )

    if ([string]::IsNullOrWhiteSpace($Raw) -or [string]::IsNullOrWhiteSpace($Prefix)) { return $false }
    if ($ScrubPolicy -ne 'Strict') {
        if (Test-UlsWellKnownSid -Value $Raw) { return $false }
        if (Test-UlsWellKnownWindowsPrincipal -Value $Raw) { return $false }
    }
    return $true
}

function Export-ScrubTokenMapRows {
    param([Parameter(Mandatory)]$Rows, [Parameter(Mandatory)][string]$TokenMapCsv)
    $out = Resolve-OutPath -Path $TokenMapCsv
    $dir = Split-Path -Parent $out
    if (-not $dir) { $dir = (Get-Location).Path }
    $tmp = Join-Path $dir (".{0}.{1}.tmp" -f ([System.IO.Path]::GetFileName($out)), ([guid]::NewGuid().ToString("N")))
    $backup = $out + ".bak"
    $rowsForWrite = @($Rows)
    if ($rowsForWrite.Count -gt 0) {
        $rowsForWrite | Export-Csv -Path $tmp -NoTypeInformation -Encoding UTF8
    }
    else {
        [pscustomobject][ordered]@{
            InputValue=""; NormalizedValue=""; Token=""; TokenType=""; Source="";
            SaltFingerprint=""; HmacLength=""; FirstSeenSource=""; LastSeenSource=""; SourcePathHash=""
        } | Select-Object -First 0 | Export-Csv -Path $tmp -NoTypeInformation -Encoding UTF8
    }
    try {
        if (Test-Path -LiteralPath $out) {
            try { [System.IO.File]::Replace($tmp, $out, $backup, $true) }
            catch {
                Copy-Item -LiteralPath $out -Destination $backup -Force -ErrorAction SilentlyContinue
                Move-Item -LiteralPath $tmp -Destination $out -Force
            }
        }
        else {
            Move-Item -LiteralPath $tmp -Destination $out -Force
        }
    }
    finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    return $out
}

function Import-ScrubTokenMap {
    param([Parameter(Mandatory)][string]$TokenMapCsv)
    if (-not (Test-Path $TokenMapCsv)) { throw "Token map not found: $TokenMapCsv" }
    $resolved = (Resolve-Path -Path $TokenMapCsv).Path
    $cacheKey = "$resolved|$((Get-Item -Path $resolved).LastWriteTimeUtc.Ticks)"
    if ($script:TokenMapCacheKey -eq $cacheKey -and $script:TokenByNorm -and $script:TokenByNorm.Count -gt 0) {
        Write-Info "Reusing token map already in memory ($($script:TokenByNorm.Count) entries)."
        return $script:TokenByNorm
    }
    Write-Work "Loading token map: $([System.IO.Path]::GetFileName($TokenMapCsv))"
    $tokenRows = Import-Csv $TokenMapCsv
    $map = @{}
    foreach ($row in $tokenRows) {
        $inputCol = Get-MapColumnName -Row $row -Candidates @("InputValue", "OriginalValue", "Value", "SourceValue")
        $normCol  = Get-MapColumnName -Row $row -Candidates @("NormalizedValue", "Normalized", "NormalizedKey")
        $tokenCol = Get-MapColumnName -Row $row -Candidates @("Token", "ScrubbedValue", "Replacement")
        if (-not $tokenCol) { continue }
        $token = [string]$row.$tokenCol
        if ([string]::IsNullOrWhiteSpace($token)) { continue }
        $norm = $null
        if ($normCol -and $row.$normCol)       { $norm = Normalize-TokenKey -Value ([string]$row.$normCol) }
        elseif ($inputCol -and $row.$inputCol) { $norm = Normalize-TokenKey -Value ([string]$row.$inputCol) }
        if ($norm -and -not $map.ContainsKey($norm)) { $map[$norm] = $token }
    }
    $script:TokenByNorm = $map
    $script:TokenMapCacheKey = $cacheKey
    $script:CurrentTokenMapCsv = $resolved
    Write-Ok "Loaded $($script:TokenByNorm.Count) token map entries."
    return $map
}

function Test-TokenMapCollisions {
    param([Parameter(Mandatory)]$Rows)
    $byToken = @{}
    $bySource = @{}
    foreach ($r in @($Rows)) {
        $tok = [string]$r.Token
        $norm = [string]$r.NormalizedValue
        if ([string]::IsNullOrWhiteSpace($tok) -or [string]::IsNullOrWhiteSpace($norm)) { continue }
        if (-not $byToken.ContainsKey($tok)) { $byToken[$tok] = New-Object System.Collections.Generic.HashSet[string] }
        if (-not $bySource.ContainsKey($tok)) { $bySource[$tok] = New-Object System.Collections.Generic.List[string] }
        [void]$byToken[$tok].Add($norm)
        [void]$bySource[$tok].Add([string]$r.Source)
    }
    $collisions = @()
    foreach ($tok in $byToken.Keys) {
        if ($byToken[$tok].Count -le 1) { continue }
        $sources = @($bySource[$tok])
        $intentional = ($sources.Count -gt 0 -and @($sources | Where-Object { $_ -notmatch '(\+corr$|^AD:)' }).Count -eq 0)
        if (-not $intentional) { $collisions += $tok }
    }
    if ($collisions.Count -gt 0) {
        Write-Warn "Token collision warning: $($collisions.Count) token(s) map to multiple normalized values."
        Write-Warn "Increase -HmacLength and rebuild the map if these aliases were not intentionally correlated."
        foreach ($tok in ($collisions | Select-Object -First 5)) {
            Write-Detail ("{0}: {1}" -f $tok, ((@($byToken[$tok]) | Select-Object -First 4) -join ', '))
        }
    }
    return $collisions.Count
}

# =====================================================================
# REGION: Map source 1 -- DISCOVERY (build the map from the log itself)
# =====================================================================
function New-ScrubTokenMap {
    <#
      Scan one or more input files, detect identifier-shaped values, and mint a
      stable token for each distinct value. Writes a private token-map CSV and
      loads it into the session. No AD required.
    #>
    param(
        [Parameter(Mandatory)][string[]]$InputPath,
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [string[]]$SeedTerms = @(),
        [switch]$NoCorrelate,
        [ValidateSet('Merge','Replace')][string]$TokenMapMode = 'Merge',
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = $script:ScrubPolicy,
        [string]$ProfileName = '',
        [string]$WorkDir = '',
        [string[]]$AllowlistFile = @(),
        [switch]$ParallelDiscovery,
        [switch]$NoParallelDiscovery,
        [int]$ThrottleLimit = 4,
        [int]$ChunkSize = 0,
        [int]$LargeFileThresholdMB = 100,
        [switch]$KeepIntermediate,
        [string]$WorkerProgressFile,
        [int]$WorkerProgressRowsTotal = 0,
        [int]$WorkerProgressChunk = 0,
        [int]$WorkerProgressIntervalRows = 1000,
        [int]$WorkerProgressIntervalSeconds = 1
    )
    $script:ScrubPolicy = $ScrubPolicy
    [void](Get-SessionSalt)
    Write-Rule "Building token map by discovery"

    $seen = @{}   # normKey -> [pscustomobject] map row
    $fileNo = 0
    $out = Resolve-OutPath -Path $TokenMapCsv
    if ($TokenMapMode -eq 'Merge' -and (Test-Path -LiteralPath $out)) {
        Write-Info "Merging with existing token map: $([System.IO.Path]::GetFileName($out))"
        foreach ($row in (Import-Csv $out)) {
            $inputCol = Get-MapColumnName -Row $row -Candidates @("InputValue", "OriginalValue", "Value", "SourceValue")
            $normCol  = Get-MapColumnName -Row $row -Candidates @("NormalizedValue", "Normalized", "NormalizedKey")
            $tokenCol = Get-MapColumnName -Row $row -Candidates @("Token", "ScrubbedValue", "Replacement")
            if (-not $tokenCol -or [string]::IsNullOrWhiteSpace([string]$row.$tokenCol)) { continue }
            $inputValue = if ($inputCol) { [string]$row.$inputCol } else { "" }
            $norm = if ($normCol -and $row.$normCol) { Normalize-TokenKey -Value ([string]$row.$normCol) } else { Normalize-TokenKey -Value $inputValue }
            if (-not $norm -or $seen.ContainsKey($norm)) { continue }
            $source = if ($row.Source) { [string]$row.Source } else { "ExistingMap" }
            $tokenType = if ($row.TokenType) { [string]$row.TokenType } else { "OBJECT" }
            $firstSeen = if ($row.FirstSeenSource) { [string]$row.FirstSeenSource } else { $source }
            $lastSeen = if ($row.LastSeenSource) { [string]$row.LastSeenSource } else { $source }
            $pathHash = if ($row.SourcePathHash) { [string]$row.SourcePathHash } else { "" }
            $seen[$norm] = New-ScrubTokenMapRow `
                -InputValue $inputValue `
                -NormalizedValue $norm `
                -Token ([string]$row.$tokenCol) `
                -TokenType $tokenType `
                -Source $source `
                -FirstSeenSource $firstSeen `
                -LastSeenSource $lastSeen `
                -SourcePathHash $pathHash
        }
        Write-Ok "Preserved $($seen.Count) existing token map entr$(if ($seen.Count -eq 1) { 'y' } else { 'ies' })."
    }

    # --- In-log alias correlation (union-find over co-occurring principals) ---
    # When a CSV row contains both jdoe@corp.com and CORP\jdoe, they are linked so
    # every alias of that identity collapses to ONE token. Disable with -NoCorrelate.
    $correlate = -not $NoCorrelate
    $parent = @{}
    if ($WorkerProgressIntervalRows -lt 1) { $WorkerProgressIntervalRows = 1000 }
    if ($WorkerProgressIntervalSeconds -lt 1) { $WorkerProgressIntervalSeconds = 1 }
    $ulsDiscoverProgressLastRows = -1
    $ulsDiscoverProgressLastUtc = [DateTime]::UtcNow.AddSeconds(-10)
    $updateDiscoverWorkerProgress = {
        param([int]$RowsDone, [string]$Status, [switch]$Force)
        if ([string]::IsNullOrWhiteSpace($WorkerProgressFile)) { return }
        $now = [DateTime]::UtcNow
        if ($Force -or $RowsDone -eq 0 -or (($RowsDone - $ulsDiscoverProgressLastRows) -ge $WorkerProgressIntervalRows) -or (($now - $ulsDiscoverProgressLastUtc).TotalSeconds -ge $WorkerProgressIntervalSeconds)) {
            Write-UlsWorkerProgressFile -Path $WorkerProgressFile -Chunk $WorkerProgressChunk -RowsDone $RowsDone -RowsTotal $WorkerProgressRowsTotal -Status $Status
            Set-Variable -Name ulsDiscoverProgressLastRows -Scope 1 -Value $RowsDone
            Set-Variable -Name ulsDiscoverProgressLastUtc -Scope 1 -Value $now
        }
    }
    try { & $updateDiscoverWorkerProgress 0 'Starting' -Force } catch { }
    function _CorrFind {
        param($x)
        if (-not $parent.ContainsKey($x)) { $parent[$x] = $x }
        while ($parent[$x] -ne $x) { $parent[$x] = $parent[$parent[$x]]; $x = $parent[$x] }
        return $x
    }
    function _CorrUnion {
        param($a, $b)
        $ra = _CorrFind $a; $rb = _CorrFind $b
        if ($ra -ne $rb) { $parent[$ra] = $rb }
    }
    function _LocalPart {
        param($Raw, $Prefix)
        if ($Prefix -eq 'UNMAPPED_UPN' -and $Raw -match '^([^@]+)@') { return $matches[1].ToLowerInvariant() }
        if ($Prefix -eq 'PRINCIPAL' -and $Raw -match '\\([^\\]+)$') { return ($matches[1].TrimEnd('$')).ToLowerInvariant() }
        return $null
    }
    foreach ($file in $InputPath) {
        $fileNo++
        if (-not (Test-Path $file)) { Write-Warn "Skipping (not found): $file"; continue }
        $name = [System.IO.Path]::GetFileName($file)
        $fileHash = Get-PathFingerprint -Path $file -Length 12
        $source = "Discovery:$name"
        Write-Work "Scanning ($fileNo/$($InputPath.Count)): $name"

        $isCsv = ([System.IO.Path]::GetExtension($file)).ToLowerInvariant() -eq '.csv'
        $hits = 0
        if ($isCsv) {
            $fileLength = 0
            try { $fileLength = (Get-Item -LiteralPath $file).Length } catch { }
            $reader = [System.IO.StreamReader]::new($file)
            $headers = @()
            $discoverScanColumns = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $discoverSkipColumns = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $rn = 0
            $ulsPerfDiscover = New-UlsPerfStopwatch
            $discoverCache = @{}
            $ulsPerfDiscoverCells = 0
            $ulsPerfDiscoverSkippedCells = 0
            try {
                $headerRecord = Read-UlsDelimitedRecord -Reader $reader -Delimiter ','
                if ($null -ne $headerRecord) {
                    $headers = [string[]]$headerRecord
                    if ($headers.Count -gt 0) { $headers[0] = ([string]$headers[0]).TrimStart([char]0xFEFF) }
                    foreach ($h in $headers) {
                        if (Test-UlsDiscoveryShouldScanColumn -Profile $script:CurrentProfile -ColumnName $h) { [void]$discoverScanColumns.Add($h) }
                        else { [void]$discoverSkipColumns.Add($h) }
                    }
                    if ($discoverSkipColumns.Count -gt 0) {
                        Write-Detail ("Discovery skipped pass-through column(s): {0}" -f (($discoverSkipColumns | Sort-Object) -join ', '))
                    }
                }

                while ($true) {
                    $record = Read-UlsDelimitedRecord -Reader $reader -Delimiter ','
                    if ($null -eq $record) { break }
                    $rn++
                    try { & $updateDiscoverWorkerProgress $rn 'Running' } catch { }
                    if ($rn % 250 -eq 0) {
                        $pct = -1
                        try {
                            if ($fileLength -gt 0) { $pct = [Math]::Min(99, [Math]::Max(0, [int](([int64]$reader.BaseStream.Position * 100.0) / [double]$fileLength))) }
                        } catch { }
                        Write-UlsProgress -Activity "Discover" -Phase ("unique {0}" -f $seen.Count) -File $name -RowsDone $rn -BytesDone ([int64]$reader.BaseStream.Position) -BytesTotal $fileLength
                    }
                    $rowPrincipals = @{}   # localpart -> list of norms seen in THIS row
                    for ($ci = 0; $ci -lt $headers.Count; $ci++) {
                        $propName = [string]$headers[$ci]
                        if (-not $discoverScanColumns.Contains($propName)) { $ulsPerfDiscoverSkippedCells++; continue }
                        $ulsPerfDiscoverCells++
                        $cell = if ($ci -lt $record.Count) { [string]$record[$ci] } else { '' }
                        if ([string]::IsNullOrWhiteSpace($cell)) { continue }
                        if ($discoverCache.ContainsKey($cell)) { $cellIds = $discoverCache[$cell] }
                        else { $cellIds = @(Find-Identifiers -Text $cell); $discoverCache[$cell] = $cellIds }
                        foreach ($id in $cellIds) {
                            if (-not (Test-UlsShouldMapDiscoveredIdentifier -Raw ([string]$id.Raw) -Prefix ([string]$id.Prefix) -ScrubPolicy $ScrubPolicy)) { continue }
                            $norm = Normalize-TokenKey -Value $id.Raw
                            if (-not $norm) { continue }
                            if (-not $seen.ContainsKey($norm)) {
                                $tok = Get-Token -Value $id.Raw -Prefix $id.Prefix
                                $seen[$norm] = New-ScrubTokenMapRow -InputValue $id.Raw -NormalizedValue $norm -Token $tok -TokenType $id.Prefix -Source $source -SourcePathHash $fileHash
                                $hits++
                            }
                            else {
                                $seen[$norm].LastSeenSource = $source
                                if (-not $seen[$norm].SourcePathHash) { $seen[$norm].SourcePathHash = $fileHash }
                            }
                            if ($correlate) {
                                $lp = _LocalPart -Raw $id.Raw -Prefix $id.Prefix
                                if ($lp -and $lp.Length -ge 3) {
                                    if (-not $rowPrincipals.ContainsKey($lp)) { $rowPrincipals[$lp] = New-Object System.Collections.Generic.List[string] }
                                    if (-not $rowPrincipals[$lp].Contains($norm)) { $rowPrincipals[$lp].Add($norm) }
                                }
                            }
                        }
                    }
                    if ($correlate) {
                        foreach ($lp in $rowPrincipals.Keys) {
                            $members = @($rowPrincipals[$lp])
                            for ($mi = 1; $mi -lt $members.Count; $mi++) { _CorrUnion $members[0] $members[$mi] }
                        }
                    }
                }
            }
            finally {
                try { $reader.Close() } catch { }
                Write-UlsProgress -Activity "Discover" -File $name -Completed
            }
            $ulsPerfDiscoverNotes = 'CSV cell identifier scan'
            if ($discoverSkipColumns.Count -gt 0) {
                $ulsPerfDiscoverNotes = ('CSV cell identifier scan; scanned={0}; skipped={1}; skippedColumns={2}' -f $ulsPerfDiscoverCells, $ulsPerfDiscoverSkippedCells, (($discoverSkipColumns | Sort-Object) -join ','))
            }
            Add-UlsPerfPhase -Phase 'Read CSV' -Seconds 0 -File $name -Rows $rn -Notes 'CSV streaming read interleaved with discovery'
            Add-UlsPerfPhase -Phase 'Discover identifiers' -Stopwatch $ulsPerfDiscover -File $name -Rows $rn -Cells $ulsPerfDiscoverCells -Notes $ulsPerfDiscoverNotes
        }
        else {
            # Large text/KV/web logs must not be loaded with ReadAllText. A multi-GB access.log
            # can exceed available string/object memory before discovery even starts. Stream one
            # line at a time, preserve the same token-map semantics, and keep only the discovered
            # unique identifiers in memory.
            $fileLength = 0
            try { $fileLength = (Get-Item -LiteralPath $file).Length } catch { }
            $thresholdBytes = [long]([Math]::Max($LargeFileThresholdMB, 1) * 1MB)
            $autoParallelDiscoveryCandidate = (-not $NoParallelDiscovery -and -not [string]::IsNullOrWhiteSpace($WorkDir) -and -not [string]::IsNullOrWhiteSpace($ProfileName) -and ($fileLength -ge $thresholdBytes -and $ThrottleLimit -gt 1))
            # Large line-oriented discovery can now use true streaming parallel batches: no physical input chunks.
            $useParallelDiscovery = (-not $NoParallelDiscovery -and -not [string]::IsNullOrWhiteSpace($WorkDir) -and -not [string]::IsNullOrWhiteSpace($ProfileName) -and ($ParallelDiscovery -or $autoParallelDiscoveryCandidate))
            if ($autoParallelDiscoveryCandidate -and -not $ParallelDiscovery) {
                Write-Info ("Auto streaming-parallel discovery ({0} MB; throttle={1}; batchSize={2}; no input chunk files). Use -NoParallelDiscovery to disable." -f [Math]::Round(($fileLength / 1MB),1), $ThrottleLimit, $(if ($ChunkSize -gt 0) { $ChunkSize } else { 20000 }))
            }
            if ($useParallelDiscovery) {
                $workerRows = @(Invoke-DiscoverFileParallelText -InputPath $file -TokenMapCsv $out -WorkDir $WorkDir -ProfileName $ProfileName -SensitiveTerms $SeedTerms -AllowlistFile $AllowlistFile -ScrubPolicy $ScrubPolicy -ThrottleLimit $ThrottleLimit -ChunkSize $ChunkSize -NoCorrelate:$NoCorrelate -KeepIntermediate:$KeepIntermediate)
                foreach ($wr in $workerRows) {
                    $inputCol = Get-MapColumnName -Row $wr -Candidates @("InputValue", "OriginalValue", "Value", "SourceValue")
                    $normCol  = Get-MapColumnName -Row $wr -Candidates @("NormalizedValue", "Normalized", "NormalizedKey")
                    $tokenCol = Get-MapColumnName -Row $wr -Candidates @("Token", "ScrubbedValue", "Replacement")
                    if (-not $tokenCol -or [string]::IsNullOrWhiteSpace([string]$wr.$tokenCol)) { continue }
                    $inputValue = if ($inputCol) { [string]$wr.$inputCol } else { "" }
                    $norm = if ($normCol -and $wr.$normCol) { Normalize-TokenKey -Value ([string]$wr.$normCol) } else { Normalize-TokenKey -Value $inputValue }
                    if (-not $norm) { continue }
                    if (-not $seen.ContainsKey($norm)) {
                        $tokenType = if ($wr.TokenType) { [string]$wr.TokenType } else { "OBJECT" }
                        if (-not (Test-UlsShouldMapDiscoveredIdentifier -Raw $inputValue -Prefix $tokenType -ScrubPolicy $ScrubPolicy)) { continue }
                        $tok = [string]$wr.$tokenCol
                        $seen[$norm] = New-ScrubTokenMapRow -InputValue $inputValue -NormalizedValue $norm -Token $tok -TokenType $tokenType -Source $source -SourcePathHash $fileHash
                        $hits++
                    }
                    else {
                        $seen[$norm].LastSeenSource = $source
                        if (-not $seen[$norm].SourcePathHash) { $seen[$norm].SourcePathHash = $fileHash }
                    }
                }
                Write-Detail ("Parallel discovery merged {0} worker map row(s)." -f $workerRows.Count)
            }
            else {
            $ulsPerfReadText = New-UlsPerfStopwatch
            $ulsPerfDiscoverText = New-UlsPerfStopwatch
            $lineNo = 0
            $candidateNo = 0
            $lastProgress = [DateTime]::UtcNow.AddSeconds(-10)
            $activity = "Discovering identifiers in $name"
            Write-UlsProgress -Activity "Discover" -Phase "start" -File $name -BytesDone 0 -BytesTotal $fileLength -Force
            $reader = [System.IO.StreamReader]::new($file)
            try {
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    if ($null -eq $line) { break }
                    $lineNo++
                    try { & $updateDiscoverWorkerProgress $lineNo 'Running' } catch { }
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }

                    $now = [DateTime]::UtcNow
                    if (($lineNo % 10000 -eq 0) -or (($now - $lastProgress).TotalSeconds -ge 2)) {
                        $pct = -1
                        try {
                            if ($fileLength -gt 0) { $pct = [Math]::Min(99, [int](($reader.BaseStream.Position / [double]$fileLength) * 100)) }
                        } catch { $pct = -1 }
                        $status = "Line $lineNo; $($seen.Count) unique so far"
                        if ($fileLength -gt 0) { $status = "$status; $([Math]::Round(($reader.BaseStream.Position / 1MB),1)) MB / $([Math]::Round(($fileLength / 1MB),1)) MB" }
                        Write-UlsProgress -Activity "Discover" -Phase ("unique {0}" -f $seen.Count) -File $name -RowsDone $lineNo -BytesDone ([int64]$reader.BaseStream.Position) -BytesTotal $fileLength
                        $lastProgress = $now
                    }

                    foreach ($id in (Find-Identifiers -Text $line)) {
                        $candidateNo++
                        if (-not (Test-UlsShouldMapDiscoveredIdentifier -Raw ([string]$id.Raw) -Prefix ([string]$id.Prefix) -ScrubPolicy $ScrubPolicy)) { continue }
                        $norm = Normalize-TokenKey -Value $id.Raw
                        if ($norm -and -not $seen.ContainsKey($norm)) {
                            $tok = Get-Token -Value $id.Raw -Prefix $id.Prefix
                            $seen[$norm] = New-ScrubTokenMapRow -InputValue $id.Raw -NormalizedValue $norm -Token $tok -TokenType $id.Prefix -Source $source -SourcePathHash $fileHash
                            $hits++
                        }
                        elseif ($norm) {
                            $seen[$norm].LastSeenSource = $source
                            if (-not $seen[$norm].SourcePathHash) { $seen[$norm].SourcePathHash = $fileHash }
                        }
                    }
                }
            }
            finally {
                try { $reader.Close() } catch { }
                Write-UlsProgress -Activity "Discover" -File $name -Completed
            }
            if ($ulsPerfReadText) { $ulsPerfReadText.Stop() }
            if ($ulsPerfDiscoverText) { $ulsPerfDiscoverText.Stop() }
            # For streaming text discovery, reading and scanning are interleaved. Keep summary labels
            # stable: report zero/near-zero Read CSV and put the work in Discover identifiers.
            Add-UlsPerfPhase -Phase 'Read CSV' -Seconds 0 -File $name -Rows $lineNo -Notes 'Text/KV streaming read interleaved with discovery'
            Add-UlsPerfPhase -Phase 'Discover identifiers' -Seconds $ulsPerfDiscoverText.Elapsed.TotalSeconds -File $name -Rows $lineNo -Notes ("Text/KV streaming identifier scan; candidates={0}; bytes={1}" -f $candidateNo, $fileLength)
            }
        }
        Write-Detail "$hits new identifier(s) from $name"
    }
    try { & $updateDiscoverWorkerProgress $WorkerProgressRowsTotal 'Completed' -Force } catch { }

    $ulsPerfBuildMap = New-UlsPerfStopwatch

    # Seed terms: shapeless secrets (org / host prefixes / project codenames) the
    # detectors cannot recognise. Mapped here so they tokenize consistently.
    foreach ($term in $SeedTerms) {
        $t = ([string]$term).Trim()
        if ($t.Length -lt 3) { continue }
        $norm = Normalize-TokenKey -Value $t
        if ($norm -and -not $seen.ContainsKey($norm)) {
            $prefix = if ($t -match '^(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$') { "DNS" } else { "X500" }
            $tok = Get-Token -Value $t -Prefix $prefix
            $seen[$norm] = New-ScrubTokenMapRow -InputValue $t -NormalizedValue $norm -Token $tok -TokenType $prefix -Source "SeedTerm" -SourcePathHash ""
        }
    }

    # Apply correlation: every alias in a connected group gets ONE deterministic token.
    if ($correlate -and $parent.Count -gt 0) {
        $groups = @{}
        foreach ($k in @($parent.Keys)) {
            $root = _CorrFind $k
            if (-not $groups.ContainsKey($root)) { $groups[$root] = New-Object System.Collections.Generic.List[string] }
            $groups[$root].Add($k)
        }
        $mergedGroups = 0
        foreach ($root in @($groups.Keys)) {
            $members = @($groups[$root] | Where-Object { $seen.ContainsKey($_) })
            if ($members.Count -lt 2) { continue }
            $raws = @($members | ForEach-Object { $seen[$_].InputValue })
            $emailRaws = @($raws | Where-Object { $_ -match '@' } | Sort-Object)
            $canonical = if ($emailRaws.Count -gt 0) { $emailRaws[0] } else { @($raws | Sort-Object)[0] }
            $shared = Invoke-HmacToken -Value $canonical -Prefix "PRINCIPAL"
            if (-not $shared) { continue }
            foreach ($m in $members) {
                $seen[$m].Token = $shared
                if ([string]$seen[$m].Source -notmatch '\+corr$') { $seen[$m].Source = [string]$seen[$m].Source + "+corr" }
            }
            $mergedGroups++
        }
        if ($mergedGroups -gt 0) { Write-Ok "Correlated $mergedGroups identity group(s) so aliases share one token." }
    }

    if ($seen.Count -gt 0) {
        $rowsOut = @($seen.Values) | Sort-Object Token, InputValue -Unique
        [void](Test-TokenMapCollisions -Rows $rowsOut)
        $out = Export-ScrubTokenMapRows -Rows $rowsOut -TokenMapCsv $out
    }
    else {
        $out = Export-ScrubTokenMapRows -Rows @() -TokenMapCsv $out
        Write-Warn "No identifiers were discovered. Output map is empty (check the input)."
    }
    Write-Ok "Token map written: $out  ($($seen.Count) entries)"
    Write-Warn "DO NOT upload this token map -- it re-identifies everything."
    [void](Import-ScrubTokenMap -TokenMapCsv $out)
    Add-UlsPerfPhase -Phase 'Build/correlate map' -Stopwatch $ulsPerfBuildMap -File ([System.IO.Path]::GetFileName($out)) -Rows $seen.Count -Notes ('NoCorrelate={0}; Mode={1}' -f [bool]$NoCorrelate, $TokenMapMode)
    return $out
}

# =====================================================================
# REGION: Map source 2 -- ACTIVE DIRECTORY (optional, authoritative)
#   Collapses every representation of one identity (SID, DOMAIN\sam, UPN, mail,
#   SPN, dNSHostName) onto a SINGLE token. Degrades gracefully off-domain.
# =====================================================================
function New-ScrubTokenMapFromAD {
    param(
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [switch]$SkipComputers,
        [string[]]$SeedTerms = @()
    )
    [void](Get-SessionSalt)
    Write-Rule "Building token map from Active Directory"
    try { Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop } catch { }

    function Convert-ObjectSidToString {
        param([Parameter(Mandatory)]$ObjectSid)
        [byte[]]$bytes = @($ObjectSid | ForEach-Object { [byte]$_ })
        return ([System.Security.Principal.SecurityIdentifier]::new($bytes, 0)).Value
    }
    function Get-One { param($R,$N) if ($R.Properties.Contains($N) -and $R.Properties[$N].Count -gt 0) { return $R.Properties[$N][0] } return $null }
    function Get-Many { param($R,$N) if ($R.Properties.Contains($N) -and $R.Properties[$N].Count -gt 0) { return @($R.Properties[$N]) } return @() }

    $defaultNC = $null
    try {
        $rootDse = [ADSI]"LDAP://RootDSE"
        $defaultNC = [string]$rootDse.defaultNamingContext
    } catch { $defaultNC = $null }
    if ([string]::IsNullOrWhiteSpace($defaultNC)) {
        Write-Fail "Could not reach Active Directory (not domain-joined, or no rights)."
        return $null
    }
    $dnsName = (($defaultNC -split "," | Where-Object { $_ -like "DC=*" } | ForEach-Object { $_.Substring(3) }) -join ".")
    $netbios = ($dnsName -split "\.")[0].ToUpperInvariant()
    Write-Info "Domain: $dnsName  (NetBIOS $netbios)"

    $rows = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $count = 0
    try {
    $entry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$defaultNC")
    $searcher = [System.DirectoryServices.DirectorySearcher]::new($entry)
    $parts = @("(&(objectCategory=person)(objectClass=user))", "(objectCategory=group)")
    if (-not $SkipComputers) { $parts += "(objectCategory=computer)" }
    $searcher.Filter = "(|$($parts -join ''))"
    $searcher.PageSize = 1000
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    foreach ($p in @("distinguishedName","objectSid","objectClass","sAMAccountName","cn","name","userPrincipalName","mail","proxyAddresses","dNSHostName","servicePrincipalName")) {
        [void]$searcher.PropertiesToLoad.Add($p)
    }

    Write-Work "Enumerating AD users, groups and computers..."
    foreach ($r in $searcher.FindAll()) {
        $count++
        if ($count % 500 -eq 0) { Write-UlsProgress -Activity "Read AD" -Phase ("aliases {0}" -f $seen.Count) -RowsDone $count }
        $sidBytes = Get-One $r "objectSid"
        if (-not $sidBytes) { continue }
        $sid = Convert-ObjectSidToString -ObjectSid $sidBytes
        $classes = @(Get-Many $r "objectClass" | ForEach-Object { "$_".ToLowerInvariant() })
        $type = if ($classes -contains "group") { "Group" } elseif ($classes -contains "computer") { "Computer" } elseif ($classes -contains "user") { "User" } else { "Object" }

        $sam = [string](Get-One $r "sAMAccountName")
        $cn  = [string](Get-One $r "cn")
        $name= [string](Get-One $r "name")
        $upn = [string](Get-One $r "userPrincipalName")
        $mail= [string](Get-One $r "mail")
        $dns = [string](Get-One $r "dNSHostName")
        $dn  = [string](Get-One $r "distinguishedName")

        $known = Get-CanonicalKnownLabelByValue -Value $sam
        if (-not $known) { $known = Get-CanonicalKnownLabelByValue -Value $cn }
        if ($known) {
            $token = $known
        }
        else {
            $prefix = switch ($type) { "Group" {"GROUP"} "Computer" {"COMPUTER"} "User" {"PRINCIPAL"} default {"OBJECT"} }
            $token = Invoke-HmacToken -Value $sid -Prefix $prefix
        }
        if (-not $token) { continue }

        $aliases = New-Object System.Collections.Generic.List[string]
        foreach ($v in @($sid,$dn,$sam,$cn,$name,$upn,$mail,$dns)) {
            if (-not [string]::IsNullOrWhiteSpace($v) -and -not $aliases.Contains($v)) { $aliases.Add($v) }
        }
        if ($sam) {
            foreach ($v in @("$netbios\$sam")) { if (-not $aliases.Contains($v)) { $aliases.Add($v) } }
            if ($type -eq "User" -or $type -eq "Computer") { $imp = "$sam@$dnsName"; if (-not $aliases.Contains($imp)) { $aliases.Add($imp) } }
            if ($sam.EndsWith("$")) {
                $nd = $sam.TrimEnd("$")
                foreach ($v in @($nd, "$netbios\$nd")) { if (-not $aliases.Contains($v)) { $aliases.Add($v) } }
                if ($type -eq "Computer") { $cu = "$nd@$dnsName"; if (-not $aliases.Contains($cu)) { $aliases.Add($cu) } }
            }
        }
        foreach ($pa in (Get-Many $r "proxyAddresses")) { if ("$pa" -match '^(?i)smtp:(.+)$') { $a = $matches[1]; if ($a -and -not $aliases.Contains($a)) { $aliases.Add($a) } } }
        foreach ($spn in (Get-Many $r "servicePrincipalName")) { if ($spn -and -not $aliases.Contains([string]$spn)) { $aliases.Add([string]$spn) } }
        foreach ($addr in @($upn,$mail)) {
            if (-not [string]::IsNullOrWhiteSpace($addr)) {
                foreach ($variant in @($addr, "Principal Name=$addr", "RFC822 Name=$addr", "UPN=$addr", "Email=$addr", "smtp:$addr", "mailto:$addr")) {
                    if (-not $aliases.Contains($variant)) { $aliases.Add($variant) }
                }
            }
        }
        if ($dns) { foreach ($v in @($dns, "DNS Name=$dns", "dNSHostName=$dns")) { if (-not $aliases.Contains($v)) { $aliases.Add($v) } } }

        foreach ($alias in $aliases) {
            $norm = Normalize-TokenKey -Value $alias
            if ($norm -and -not $seen.ContainsKey($norm)) {
                $seen[$norm] = $true
                $rowType = switch ($type) { "Group" {"GROUP"} "Computer" {"COMPUTER"} "User" {"PRINCIPAL"} default {"OBJECT"} }
                $rows.Add((New-ScrubTokenMapRow -InputValue $alias -NormalizedValue $norm -Token $token -TokenType $rowType -Source "AD" -SourcePathHash "AD"))
            }
        }
    }
    Write-UlsProgress -Activity "Read AD" -Completed
    }
    catch {
        Write-Warn "AD enumeration interrupted: $($_.Exception.Message)"
        if ($rows.Count -eq 0) { return $null }
    }

    foreach ($term in $SeedTerms) {
        $t = ([string]$term).Trim()
        if ($t.Length -lt 3) { continue }
        $norm = Normalize-TokenKey -Value $t
        if ($norm -and -not $seen.ContainsKey($norm)) {
            $seen[$norm] = $true
            $prefix = if ($t -match '^(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$') { "DNS" } else { "X500" }
            $rows.Add((New-ScrubTokenMapRow -InputValue $t -NormalizedValue $norm -Token (Get-Token -Value $t -Prefix $prefix) -TokenType $prefix -Source "SeedTerm" -SourcePathHash ""))
        }
    }

    $out = Resolve-OutPath -Path $TokenMapCsv
    $rowsOut = $rows | Sort-Object Token, InputValue -Unique
    [void](Test-TokenMapCollisions -Rows $rowsOut)
    $out = Export-ScrubTokenMapRows -Rows $rowsOut -TokenMapCsv $out
    Write-Ok "AD token map written: $out  ($($rows.Count) aliases)"
    Write-Warn "DO NOT upload this token map."
    [void](Import-ScrubTokenMap -TokenMapCsv $out)
    return $out
}

# =====================================================================
# REGION: Profiles (column / field semantics, per log type)
# =====================================================================
function Get-ScrubProfile {
    param([string]$Name)

    # Generic, deny-by-default: no column allow-list. Every cell is scanned for
    # identifier shapes; pure numbers / booleans / dates / OIDs / existing tokens
    # pass untouched. Shapeless secrets need SeedTerms.
    $generic = [pscustomobject]@{
        Name = 'Generic'
        Description = 'Any log. Deny-by-default: scans every field for identifier shapes.'
        Format = 'Auto'                 # Csv if .csv, else Text
        PassThroughRegex = $null
        ColumnPrefix = @()              # no column hints; rely on value shape
        FreeTextRegex = '.*'            # harden every column
        DenyByDefault = $true
    }

    # CA / AD CS exports -- mirrors the original pipeline's column rules so your
    # existing *_UNSCRUBBED.csv files scrub identically.
    $ca = [pscustomobject]@{
        Name = 'CA'
        Description = 'AD CS ESC-audit exports (issued certs, templates, CA/PKI security).'
        Format = 'Csv'
        PassThroughRegex = '^(RequestID|SubmittedWhen|ResolvedWhen|NotBefore|NotAfter|Disposition|ParseStatus|Published|SubjectSuppliedByRequester|SANSuppliedByRequester|SubjectOrSANSuppliedByRequester|ManagerApprovalRequired|AuthorizedSignaturesRequired|RequiredSignatureCount|NoSecurityExtension|NoEKU|AuthCapableOrAnyPurpose|ESC1Candidate_AnyEnroll|ESC1Candidate_BroadEnroll|ESC4Candidate|ESC5Candidate|ESC7Candidate|ESC11Candidate|ESC6_CAConfigFlag|EditF_AttributeSubjectAltName2|EditFlagsHex|InterfaceFlagsHex|IF_EnforceEncryptICertRequest|SecuritySource|IsDangerous|IsDefaultPrincipal|AccessType|PkiObjectType|Rights|SidMismatchLikelyBenign|StrongCertificateBindingEnforcement|EnforcementLevel|FullEnforcement|ReadStatus|ReadMethod|EndpointKind|Scheme|IsHttp|AuthFromMetadata|Probed|Reachable|HttpStatus|AuthSchemesOffered|NtlmOffered|EpaTokenChecking|EpaSource|Esc8RiskFromMetadata|ESC8Confirmed|ESC8NeedsEpaCheck|ESC8Mitigated|ESC8Candidate|HasSidSecurityExtension|RequestAttributesHasSAN|IsEnrollmentAgentCert|HasAnyPurposeOrNoEKU|OnBehalfOfCallerMismatch|NameFlag.*|EnrollmentFlag.*|EKU.*|OID.*|AuthEKUsMatched)$'
        ColumnPrefix = @(
            @{ Pattern = '^ca_|publishingca|certissuer'; Prefix = 'CA' },
            @{ Pattern = 'template'; Prefix = 'TEMPLATE'; NotOid = $true },
            @{ Pattern = 'hash|thumbprint|serial|certificatehash|rawcertificate'; Prefix = 'CERT' },
            @{ Pattern = 'dns|hostname|fqdn'; Prefix = 'DNS' },
            @{ Pattern = 'san_upn|subjectaltnameupn|upn|email'; Prefix = 'UNMAPPED_UPN' },
            @{ Pattern = 'requester|caller'; Prefix = 'UNMAPPED_PRINCIPAL'; DollarComputer = $true },
            @{ Pattern = 'principal|owner|user|account|enroll|permission|acl|allow|dangerouscontrol|group'; Prefix = 'PRINCIPAL'; DollarComputer = $true },
            @{ Pattern = 'issuer|subject|distinguished|x500|dn'; Prefix = 'X500' }
        )
        FreeTextRegex = 'Subject|Issuer|Distinguished|RequestAttributes|SAN|Principal|Enroll|Permission|ACL|Allow|Dangerous|Owner|Group|Name|Dns|DNS|Email|URI|Url|URL|Host'
        DenyByDefault = $false
    }

    # Generic Windows event log exported to CSV (Get-WinEvent | Export-Csv etc.).
    $win = [pscustomobject]@{
        Name = 'WindowsEventCsv'
        Description = 'Windows event logs exported to CSV.'
        Format = 'Csv'
        PassThroughRegex = '^(Id|EventID|Level|LevelDisplayName|TimeCreated|RecordId|LogName|ProviderName|ProviderId|ProviderGuid|Version|Qualifiers|Task|TaskDisplayName|Opcode|OpcodeDisplayName|Keywords|KeywordsDisplayNames|ProcessId|ThreadId|ActivityId|RelatedActivityId)$'
        ColumnPrefix = @(
            @{ Pattern = 'sid'; Prefix = 'SID' },
            @{ Pattern = 'address|ip'; Prefix = 'IP' },
            @{ Pattern = 'computer|host|workstation|machine'; Prefix = 'DNS' },
            @{ Pattern = 'account|user|subject|target|caller'; Prefix = 'PRINCIPAL'; DollarComputer = $true },
            @{ Pattern = 'domain'; Prefix = 'X500' }
        )
        FreeTextRegex = '^(Message|EventDataJson)$'
        DenyByDefault = $false
        SchemaColumns = ConvertTo-ProfileColumnRules -Rules @(
            [pscustomobject]@{ Regex = '^(Message|EventDataJson)$'; Action = 'Scan'; Prefix = 'OBJECT' },
            [pscustomobject]@{ Regex = '^(Id|EventID|Level|LevelDisplayName|TimeCreated|RecordId|LogName|ProviderName|ProviderId|ProviderGuid|Version|Qualifiers|Task|TaskDisplayName|Opcode|OpcodeDisplayName|Keywords|KeywordsDisplayNames|ProcessId|ThreadId|ActivityId|RelatedActivityId)$'; Action = 'PassThrough'; Prefix = 'OBJECT' }
        ) -DefaultAction 'Scan' -DefaultPrefix 'OBJECT' -Context 'WindowsEventCsv SchemaColumns'
        WholeColumnRules = ConvertTo-ProfileColumnRules -Rules @(
            [pscustomobject]@{ Regex = '^(MachineName|ComputerName)$'; Action = 'Scrub'; Prefix = 'COMPUTER' }
        ) -DefaultAction 'Scrub' -DefaultPrefix 'COMPUTER' -Context 'WindowsEventCsv WholeColumnRules'
    }

    # Free-form text logs (syslog, application logs, JSON lines, key=value).
    $text = [pscustomobject]@{
        Name = 'Text'
        Description = 'Free-form text logs (syslog, app logs, JSON lines, key=value).'
        Format = 'Text'
        PassThroughRegex = $null
        ColumnPrefix = @()
        FreeTextRegex = '.*'
        DenyByDefault = $true
    }

    # Tab- and pipe-delimited tables (treated like CSV with a different delimiter).
    $tsv = [pscustomobject]@{
        Name='Tsv'; Description='Tab-separated tables (.tsv).'; Format='Tsv'; Delimiter="`t"
        PassThroughRegex=$null; ColumnPrefix=@(); FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $psv = [pscustomobject]@{
        Name='Psv'; Description='Pipe-separated tables (col1|col2|...).'; Format='Psv'; Delimiter='|'
        PassThroughRegex=$null; ColumnPrefix=@(); FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }

    # IIS / W3C access logs (after the #Fields header is converted to CSV columns).
    $iis = [pscustomobject]@{
        Name='IIS'; Description='IIS / W3C access logs (.log with a #Fields header).'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(date|time|time-taken|sc-status|sc-substatus|sc-win32-status|sc-bytes|cs-bytes|s-port|cs-method|cs-version)$'
        ColumnPrefix=@(
            @{ Pattern='(^|[_\-. ])(?:c-ip|s-ip|x-forwarded|x-forwarded-for|ip|ipaddr|ipaddress)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='username|cs-username|user'; Prefix='PRINCIPAL'; DollarComputer=$true },
            @{ Pattern='host|computername|s-computername|cs-host'; Prefix='DNS' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }

    # Free-form text variants (detectors do the work).
    $syslog = [pscustomobject]@{
        Name='Syslog'; Description='Syslog (RFC 3164/5424) and similar line logs.'; Format='Text'; Delimiter=','
        PassThroughRegex=$null; ColumnPrefix=@(); FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $apache = [pscustomobject]@{
        Name='Apache'; Description='Apache / Nginx access logs (combined/common format).'; Format='Text'; Delimiter=','
        PassThroughRegex=$null; ColumnPrefix=@(); FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }

    # key=value text: tokenize VALUES, preserve keys.
    $cef = [pscustomobject]@{
        Name='Cef'; Description='CEF / LEEF SIEM events (key=value extensions).'; Format='Kv'; Delimiter=','
        PassThroughRegex=$null; ColumnPrefix=@(); FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $logfmt = [pscustomobject]@{
        Name='Logfmt'; Description='logfmt key=value application logs.'; Format='Kv'; Delimiter=','
        PassThroughRegex=$null; ColumnPrefix=@(); FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }

    $webAccess = [pscustomobject]@{
        Name='WebAccess'; Description='Web access logs from reverse proxies, Nginx, Apache, CDNs, and load balancers.'; Format='Text'; Delimiter=','
        PassThroughRegex=$null; ColumnPrefix=@(); FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $cloudAudit = [pscustomobject]@{
        Name='CloudAudit'; Description='Cloud audit/activity logs with principals, tenants, resources, source IPs, and request IDs.'; Format='Json'; Delimiter=','
        PassThroughRegex='^(eventTime|eventType|eventName|eventSource|awsRegion|status|result|severity|level|operation|category)$'
        ColumnPrefix=@(
            @{ Pattern='user|principal|actor|caller|identity|assumedrole|arn'; Prefix='PRINCIPAL'; DollarComputer=$true },
            @{ Pattern='tenant|account|subscription|project|organization|org'; Prefix='X500' },
            @{ Pattern='(^|[_\-. ])(?:source|client|remote|ip|ipaddr|ipaddress|address|addr)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='host|resource|instance|node|cluster'; Prefix='DNS' },
            @{ Pattern='request|correlation|trace|session|eventid'; Prefix='OBJECT' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $firewallText = [pscustomobject]@{
        Name='Firewall'; Description='Firewall/VPN syslog and key=value text logs with source/destination addresses, users, devices, and rules.'; Format='Kv'; Delimiter=','
        PassThroughRegex=$null
        ColumnPrefix=@(
            @{ Pattern='(^|[_\-. ])(?:src|dst|source|destination|client|remote|ip|ipaddr|ipaddress|addr|address)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='user|account|principal|identity|login'; Prefix='PRINCIPAL'; DollarComputer=$true },
            @{ Pattern='host|device|gateway|server|clientname|fqdn|domain'; Prefix='DNS' },
            @{ Pattern='url|uri|endpoint'; Prefix='URI' },
            @{ Pattern='session|correlation|request|rule|policy'; Prefix='OBJECT' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $firewallTextAlias = [pscustomobject]@{
        Name='FirewallText'; Description='Alias-style profile for firewall/VPN syslog and key=value text logs.'; Format='Kv'; Delimiter=','
        PassThroughRegex=$firewallText.PassThroughRegex; ColumnPrefix=$firewallText.ColumnPrefix; FreeTextRegex=$firewallText.FreeTextRegex; DenyByDefault=$firewallText.DenyByDefault; AllowedDomains=$firewallText.AllowedDomains
    }
    $firewallCsv = [pscustomobject]@{
        Name='FirewallCsv'; Description='Structured firewall/network security CSV exports with source/destination addresses, users, devices, and rules.'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(action|allow|deny|protocol|proto|port|src_port|dst_port|bytes|packets|rule|policy|severity|time|date|timestamp)$'
        ColumnPrefix=@(
            @{ Pattern='(^|[_\-. ])(?:src|dst|source|destination|client|remote|ip|ipaddr|ipaddress|addr|address)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='user|account|principal|identity'; Prefix='PRINCIPAL'; DollarComputer=$true },
            @{ Pattern='host|device|gateway|server|clientname'; Prefix='DNS' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $vpn = [pscustomobject]@{
        Name='Vpn'; Description='VPN, remote access, and authentication gateway logs.'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(action|status|result|duration|bytes|port|protocol|time|date|timestamp|reason)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|account|principal|identity|login'; Prefix='PRINCIPAL' },
            @{ Pattern='(^|[_\-. ])(?:client|remote|assigned|source|ip|ipaddr|ipaddress|address|addr)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='host|gateway|server|device'; Prefix='DNS' },
            @{ Pattern='session|correlation|request'; Prefix='OBJECT' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $proxy = [pscustomobject]@{
        Name='Proxy'; Description='Proxy, SWG, and web filtering logs.'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(action|status|category|method|http_method|response_code|bytes|time|date|timestamp|mime|user_agent)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|account|principal'; Prefix='PRINCIPAL' },
            @{ Pattern='(^|[_\-. ])(?:client|source|remote|ip|ipaddr|ipaddress|address|addr)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='url|uri|referer|referrer|request'; Prefix='URI' },
            @{ Pattern='host|domain|fqdn|server'; Prefix='DNS' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $appJson = [pscustomobject]@{
        Name='AppJson'; Description='Application JSON/NDJSON logs with user, host, tenant, request, trace, and secret fields.'; Format='Json'; Delimiter=','
        PassThroughRegex='^(timestamp|time|level|severity|messageTemplate|event|eventId|status|duration|elapsed|count)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|account|principal|actor|subject'; Prefix='PRINCIPAL' },
            @{ Pattern='host|server|machine|node|pod|container|service'; Prefix='DNS' },
            @{ Pattern='(^|[_\-. ])(?:ip|ipaddr|ipaddress|address|addr|client|remote|source)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='tenant|org|organization|domain'; Prefix='X500' },
            @{ Pattern='request|correlation|trace|span|session|transaction'; Prefix='OBJECT' },
            @{ Pattern='token|secret|password|key|authorization'; Prefix='SECRET' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $database = [pscustomobject]@{
        Name='Database'; Description='Database audit/query logs with users, clients, hosts, SQL text, and connection strings.'; Format='Text'; Delimiter=','
        PassThroughRegex=$null
        ColumnPrefix=@(
            @{ Pattern='user|login|principal|account|owner|schema'; Prefix='PRINCIPAL' },
            @{ Pattern='host|server|database|db|instance|client'; Prefix='DNS' },
            @{ Pattern='(^|[_\-. ])(?:ip|ipaddr|ipaddress|address|addr|client)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='password|secret|connection|string|conn'; Prefix='SECRET' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $container = [pscustomobject]@{
        Name='Container'; Description='Container runtime, Docker, and orchestrator logs.'; Format='Json'; Delimiter=','
        PassThroughRegex='^(time|timestamp|level|severity|stream|exitCode|restartCount|status)$'
        ColumnPrefix=@(
            @{ Pattern='container|pod|node|host|image|service|namespace|cluster'; Prefix='DNS' },
            @{ Pattern='user|account|principal|serviceaccount'; Prefix='PRINCIPAL' },
            @{ Pattern='(^|[_\-. ])(?:ip|ipaddr|ipaddress|address|addr)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='secret|token|key|password'; Prefix='SECRET' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $kubernetes = [pscustomobject]@{
        Name='Kubernetes'; Description='Kubernetes audit and workload logs.'; Format='Json'; Delimiter=','
        PassThroughRegex='^(kind|apiVersion|verb|stage|level|timestamp|code|reason|namespace)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|groups|serviceaccount|impersonated'; Prefix='PRINCIPAL' },
            @{ Pattern='pod|node|container|host|cluster|object|resource|namespace'; Prefix='DNS' },
            @{ Pattern='(^|[_\-. ])(?:source|ip|ipaddr|ipaddress|address|addr)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='token|secret|authorization'; Prefix='SECRET' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $identityProvider = [pscustomobject]@{
        Name='IdentityProvider'; Description='Identity provider, SSO, MFA, and directory sign-in logs.'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(time|date|timestamp|result|status|success|failure|risk|mfa|method|app|application|event|eventid)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|upn|email|account|principal|actor|target'; Prefix='UNMAPPED_UPN' },
            @{ Pattern='tenant|domain|realm|org|organization|directory'; Prefix='X500' },
            @{ Pattern='(^|[_\-. ])(?:ip|ipaddr|ipaddress|address|addr|client|source|remote)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='device|host|machine|computer'; Prefix='DNS' },
            @{ Pattern='session|correlation|request|token|jti'; Prefix='OBJECT' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $serviceNow = [pscustomobject]@{
        Name='ServiceNow'; Description='ServiceNow incident/change/task/CMDB exports with callers, assignees, CIs, notes, and URLs.'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(number|sys_id|opened|opened_at|closed|closed_at|resolved|resolved_at|updated|sys_updated_on|created|sys_created_on|state|status|priority|impact|urgency|severity|category|subcategory|assignment_group|business_service|short_description|approval|active|made_sla|reassignment_count|calendar_duration|business_duration)$'
        ColumnPrefix=@(
            @{ Pattern='caller|opened_by|resolved_by|closed_by|assigned_to|requested_for|requested_by|watch_list|user|email|upn'; Prefix='PRINCIPAL'; DollarComputer=$true },
            @{ Pattern='cmdb_ci|configuration_item|computer|host|device|server|node|endpoint|asset'; Prefix='COMPUTER' },
            @{ Pattern='(^|[_\-. ])(?:ip|ipaddr|ipaddress|address|addr|source|destination)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='company|department|domain|tenant|account'; Prefix='X500' },
            @{ Pattern='url|uri|link|endpoint'; Prefix='URI' },
            @{ Pattern='work_notes|comments|description|close_notes|additional_comments'; Prefix='OBJECT' },
            @{ Pattern='token|secret|password|credential|key'; Prefix='SECRET' }
        )
        FreeTextRegex='work_notes|comments|description|notes|url|uri|link'
        DenyByDefault=$false; AllowedDomains=@('service-now.com','servicenow.com')
    }
    $intuneDiagnostics = [pscustomobject]@{
        Name='IntuneDiagnostics'; Description='Intune diagnostics bundle logs, MDM diagnostic reports, registry exports, XML/HTML reports, and command-output text.'; Format='Text'; Delimiter=','
        PassThroughRegex='^(timestamp|time|date|status|state|result|level|severity|eventid|event_id|errorcode|error_code|hresult|policy|policyname|provider|operation|phase|step|count)$'
        ColumnPrefix=@()
        FreeTextRegex='(?i)(intune|mdm|omadm|deviceenroller|deviceenrollment|enrollment|autopilot|windows update|windowsupdate|policy|compliance|tenant|upn|user|device|serial|imei|wifi|ethernet|regedit|registry|html|xml)'
        DenyByDefault=$false; AllowedDomains=@('microsoft.com','windows.net')
        LabelRules=@(
            @{ Name='IntuneUser'; Labels=@('UPN','User Principal Name','User','User Name','UserId','Primary User','Enrolled By'); Prefix='UNMAPPED_UPN' },
            @{ Name='IntuneDevice'; Labels=@('Device Name','Managed Device Name','Computer Name','Hostname','Serial Number','IMEI','MEID','Azure AD Device ID','AAD Device ID'); Prefix='COMPUTER' },
            @{ Name='IntuneNetwork'; Labels=@('IP Address','IPv4 Address','WiFi MAC Address','Ethernet MAC Address','MAC Address'); Prefix='OBJECT' },
            @{ Name='IntuneTenant'; Labels=@('Tenant ID','Tenant Name','Domain Name','Enrollment UPN'); Prefix='X500' },
            @{ Name='IntuneSecrets'; Labels=@('Token','Refresh Token','Access Token','Authorization','Bearer','Password','Client Secret'); Prefix='SECRET' }
        )
        CustomRegexRules=@(
            @{
                Name='RegistryUserSid'
                Regex='(?i)(\\(?:Users|ProfileList)\\)(S-1-5-21-[0-9-]{10,})'
                CaptureGroup=2
                Prefix='SID'
                Keywords=@('ProfileList','Users','S-1-5-21')
                Entropy=0
            },
            @{
                Name='HtmlAttributeSensitiveValue'
                Regex='(?i)\b(?:data-user|data-upn|data-device|data-tenant)\s*=\s*["'']([^"'']{3,200})["'']'
                CaptureGroup=1
                Prefix='OBJECT'
                Keywords=@('data-user','data-upn','data-device','data-tenant')
                Entropy=0
            },
            @{
                Name='IntuneDiagnosticSerialNumber'
                Regex='(?i)\b(Serial\s+Number\s*[:=]\s*)([A-Z0-9][A-Z0-9._-]{5,})\b'
                CaptureGroup=2
                Prefix='COMPUTER'
                Keywords=@('Serial Number')
                Entropy=0
            }
        )
    }
    $nexthink = [pscustomobject]@{
        Name='Nexthink'; Description='Nexthink device, user, binary, destination, campaign, and experience exports.'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(timestamp|time|date|event_time|collector|score|status|state|severity|platform|os|os_version|version|binary_version|package_version|count|duration|latency|size|bytes|cpu|memory|disk|battery|wifi|execution_status)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|upn|email|account|employee|principal'; Prefix='PRINCIPAL'; DollarComputer=$true },
            @{ Pattern='device|host|hostname|machine|computer|endpoint|collector|serial|asset'; Prefix='COMPUTER' },
            @{ Pattern='(^|[_\-. ])(?:ip|ipaddr|ipaddress|address|addr|remote|destination|source)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='domain|tenant|organization|department|entity'; Prefix='X500' },
            @{ Pattern='url|uri|web|destination|dns|fqdn'; Prefix='DNS' },
            @{ Pattern='campaign|survey|question|answer|comment|description'; Prefix='OBJECT' },
            @{ Pattern='token|secret|password|credential|key'; Prefix='SECRET' }
        )
        FreeTextRegex='comment|description|campaign|question|answer|url|uri|destination|execution\.output|output|message|details|path|file'
        CustomRegexRules=@(
            @{
                Name='NexthinkActionDevice'
                Regex='(?i)(\bAction\s+run\s+by\s+\S+\s+on\s+)([A-Za-z][A-Za-z0-9_-]{2,})'
                CaptureGroup=2
                Prefix='COMPUTER'
                Keywords=@('Action run by')
                Entropy=0
            }
        )
        DenyByDefault=$false; AllowedDomains=@('nexthink.com')
    }
    $sccm = [pscustomobject]@{
        Name='Sccm'; Description='SCCM/MECM inventory, deployment, client, and collection exports.'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(timestamp|time|date|site|site_code|status|state|result|compliance|deployment_status|client_status|active|obsolete|version|build|os|os_version|collection|collection_id|deployment_id|assignment_id|article_id|ci_id|resourceid|resource_id|model|manufacturer|count)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|last_logon|primary_user|upn|email|account'; Prefix='PRINCIPAL'; DollarComputer=$true },
            @{ Pattern='device|resource|computer|machine|hostname|netbios|client|endpoint|serial|smbios|bios|asset'; Prefix='COMPUTER' },
            @{ Pattern='(^|[_\-. ])(?:ip|ipaddr|ipaddress|address|addr|subnet|boundary)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='(^|_)(mac|macaddress|mac_address|mac_addresses0)($|_)'; Prefix='MAC' },
            @{ Pattern='domain|forest|tenant|department|org|organization'; Prefix='X500' },
            @{ Pattern='package|application|app|program|software|publisher|product'; Prefix='OBJECT' },
            @{ Pattern='url|uri|management_point|distribution_point|server'; Prefix='DNS' },
            @{ Pattern='token|secret|password|credential|key'; Prefix='SECRET' }
        )
        FreeTextRegex='description|error|message|comment|url|uri|server|management|distribution'
        DenyByDefault=$false; AllowedDomains=@()
    }
    $sccmText = [pscustomobject]@{
        Name='SccmText'; Description='SCCM/MECM/ConfigMgr client, CMTrace, deployment, and management-point text logs.'
        Format='Text'; Delimiter=','
        PassThroughRegex=$null
        ColumnPrefix=@()
        FreeTextRegex='.*'
        DenyByDefault=$true
        AllowedDomains=@('microsoft.com','windows.net')
        LabelRules=@(
            @{ Name='ConfigMgrUser'; Labels=@('user','username','account','context','caller','primary user'); Prefix='PRINCIPAL'; Preserve=@('SYSTEM','LOCAL SYSTEM','NT AUTHORITY\SYSTEM') },
            @{ Name='ConfigMgrDevice'; Labels=@('device','machine','computer','hostname','client','management point','distribution point','server'); Prefix='COMPUTER' },
            @{ Name='ConfigMgrAddress'; Labels=@('ip','ip address','client ip','remote address','source address'); Prefix='IP' },
            @{ Name='ConfigMgrUrl'; Labels=@('url','uri','mp','dp','endpoint'); Prefix='URI' }
        )
        CustomRegexRules=@(
            @{
                Name='CMTraceContext'
                Regex='(?i)\bcontext="([^"]{3,180})"'
                CaptureGroup=1
                Prefix='PRINCIPAL'
                Keywords=@('context=')
                Entropy=0
                Allowlist=@('SYSTEM','LOCAL SYSTEM','NT AUTHORITY\SYSTEM')
            }
        )
    }
    $intune = [pscustomobject]@{
        Name='Intune'; Description='Microsoft Intune / Endpoint Manager device, app, policy, enrollment, and compliance exports.'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(timestamp|time|date|last_sync|enrolled_date|enrollment_date|compliance_state|compliant|managed|ownership|management_agent|platform|os|os_version|model|manufacturer|policy|policy_name|profile|assignment|state|status|result|risk|count|version)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|upn|email|primary_user|enrolled_by|owner|principal|account'; Prefix='UNMAPPED_UPN'; DollarComputer=$true },
            @{ Pattern='device|device_name|managed_device|computer|host|machine|serial|imei|meid|azure_ad_device|aad_device|entra|endpoint'; Prefix='COMPUTER' },
            @{ Pattern='(^|[_\-. ])(?:ip|ipaddr|ipaddress|address|addr)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='(^|_)(mac|macaddress|mac_address|wifi|wi_?fi|ethernet)($|_)'; Prefix='MAC' },
            @{ Pattern='tenant|domain|organization|department|group'; Prefix='X500' },
            @{ Pattern='app|application|bundle|package|publisher|certificate|thumbprint'; Prefix='OBJECT' },
            @{ Pattern='url|uri|server|endpoint'; Prefix='DNS' },
            @{ Pattern='token|secret|password|credential|key'; Prefix='SECRET' }
        )
        FreeTextRegex='description|error|message|remediation|notes|url|uri'
        DenyByDefault=$false; AllowedDomains=@('microsoft.com','windows.net')
    }
    $edr = [pscustomobject]@{
        Name='Edr'; Description='EDR/XDR alert JSON or JSONL exports with devices, users, network destinations, commands, and evidence.'
        Format='Json'; Delimiter=','
        PassThroughRegex='^(timestamp|time|date|vendor|product|severity|level|status|state|action|verdict|process_name|parent_process|parent_process_name|file_name|sha1|sha256|md5|alert_id|event_id|rule|rule_name|tactic|technique)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|user_email|upn|account|principal|identity'; Prefix='PRINCIPAL'; DollarComputer=$true },
            @{ Pattern='device|device_name|device_id|host|hostname|machine|computer|endpoint|asset|sensor'; Prefix='COMPUTER' },
            @{ Pattern='(^|[_\-. ])(?:ip|ipaddr|ipaddress|address|addr|remote_ip|local_ip|source|destination)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='domain|remote_domain|dns|fqdn|url|uri|endpoint'; Prefix='DNS' },
            @{ Pattern='command|command_line|process_path|image_path|file_path|registry|evidence|description|message'; Prefix='OBJECT' },
            @{ Pattern='token|secret|password|credential|key|authorization'; Prefix='SECRET' }
        )
        FreeTextRegex='command|command_line|process_path|image_path|file_path|registry|evidence|description|message|url|uri|domain'
        DenyByDefault=$false; AllowedDomains=@('microsoft.com','windows.net')
    }

    $all = [ordered]@{ Generic=$generic; CA=$ca; WindowsEventCsv=$win; Text=$text;
                       Tsv=$tsv; Psv=$psv; IIS=$iis; Syslog=$syslog; Apache=$apache; Cef=$cef; Logfmt=$logfmt;
                       WebAccess=$webAccess; CloudAudit=$cloudAudit; Firewall=$firewallText; FirewallText=$firewallTextAlias; FirewallCsv=$firewallCsv; Vpn=$vpn; Proxy=$proxy;
                       AppJson=$appJson; Database=$database; Container=$container; Kubernetes=$kubernetes; IdentityProvider=$identityProvider;
                       ServiceNow=$serviceNow; IntuneDiagnostics=$intuneDiagnostics; Nexthink=$nexthink; Sccm=$sccm; SccmText=$sccmText; Intune=$intune; Edr=$edr }
    if ($Name) {
        foreach ($k in $all.Keys) { if ($k -ieq $Name) { return $all[$k] } }
        return $null
    }
    return @($all.Values)
}

# =====================================================================
# REGION: Local log format recommendations (no salt, no scrubbing)
# =====================================================================
function __ULS_Legacy_Test_GeneratedScrubArtifactName_2196 {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -match '(?i)(_scrubbed|\.scrubbed\.|token_map|DO_NOT_UPLOAD|false_positive|detection_report|scrub_run_manifest)') { return $true }
    if ([System.IO.Path]::GetExtension($Name) -ieq '.zip') { return $true }
    return $false
}

function __ULS_Legacy_Resolve_LogRecommendationTargets_2204 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Recurse,
        [string[]]$Include,
        [string[]]$Exclude
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { throw "Path is required." }
    $targets = @()
    if (Test-Path -LiteralPath $Path -PathType Container) {
        $targets = @(Get-ChildItem -LiteralPath $Path -File -Recurse:$Recurse -ErrorAction SilentlyContinue)
    }
    elseif (Test-Path -LiteralPath $Path -PathType Leaf) {
        $targets = @(Get-Item -LiteralPath $Path)
    }
    else { throw "Path not found: $Path" }

    $targets = @($targets | Where-Object { -not (Test-GeneratedScrubArtifactName -Name $_.Name) })
    if ($Include -and $Include.Count -gt 0) {
        $targets = @($targets | Where-Object {
            $ok = $false
            foreach ($pat in $Include) { if ($_.Name -like $pat) { $ok = $true; break } }
            $ok
        })
    }
    if ($Exclude -and $Exclude.Count -gt 0) {
        $targets = @($targets | Where-Object {
            $skip = $false
            foreach ($pat in $Exclude) { if ($_.Name -like $pat) { $skip = $true; break } }
            -not $skip
        })
    }
    return @($targets | Sort-Object FullName)
}

function Get-ReadableFileSample {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$File,
        [int]$SampleLines = 50
    )

    if ($SampleLines -lt 1) { $SampleLines = 1 }
    $warnings = @()
    $ext = ([string]$File.Extension).ToLowerInvariant()
    if ($ext -in @('.evtx','.xlsx','.docx','.pptx','.doc','.ppt','.cab','.etl','.zip')) {
        $warnings += "File type is not sampled as plain text."
        return [pscustomobject]@{ Lines = @(); Text = ''; Warnings = $warnings }
    }

    $lines = @()
    try {
        $lines = @(Get-Content -LiteralPath $File.FullName -TotalCount $SampleLines -ErrorAction Stop)
    }
    catch {
        $warnings += "Could not read sample: $($_.Exception.Message)"
    }

    $text = if ($lines.Count -gt 0) { [string]::Join("`n", @($lines | ForEach-Object { [string]$_ })) } else { '' }
    if ($text -match "`0") { $warnings += "Sample contains NUL bytes and may be binary." }
    return [pscustomobject]@{ Lines = $lines; Text = $text; Warnings = $warnings }
}

function Get-LogHeaderColumns {
    param([string]$Header, [string]$Delimiter)
    if ([string]::IsNullOrWhiteSpace($Header)) { return @() }
    $parts = @($Header -split [regex]::Escape($Delimiter))
    return @($parts | ForEach-Object {
        $c = ([string]$_).Trim()
        $c = $c.Trim([char]34).Trim([char]39)
        $c.Trim()
    } | Where-Object { $_ })
}

function Get-LogColumnHitCount {
    param([string[]]$Columns, [string[]]$Patterns)
    $hits = 0
    foreach ($pat in $Patterns) {
        foreach ($col in @($Columns)) {
            if ($col -match $pat) { $hits++; break }
        }
    }
    return $hits
}

function Test-JsonText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    try {
        [void]($Text | ConvertFrom-Json -ErrorAction Stop)
        return $true
    }
    catch { return $false }
}

function Test-JsonLines {
    param([string[]]$Lines)
    $checked = 0
    $ok = 0
    foreach ($line in @($Lines)) {
        $t = ([string]$line).Trim()
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        $checked++
        try {
            [void]($t | ConvertFrom-Json -ErrorAction Stop)
            $ok++
        }
        catch { }
        if ($checked -ge 10) { break }
    }
    if ($checked -le 1) { return $false }
    return ($ok -ge [Math]::Ceiling($checked * 0.8))
}

function Get-UlsEnterpriseProfileHint {
    param(
        [string[]]$Columns = @(),
        [string]$Text = ''
    )

    $columnsSafe = @($Columns | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $textSafe = [string]$Text

    $hints = @(
        [pscustomobject]@{
            Profile='ServiceNow'; Format='ServiceNow export'; Confidence=92
            Patterns=@('(?i)^sys_id$','(?i)^number$','(?i)^short_description$','(?i)^work_notes$','(?i)^additional_comments$','(?i)^caller_id$','(?i)^opened_by$','(?i)^assigned_to$','(?i)^cmdb_ci$','(?i)^assignment_group$','(?i)^sys_created_on$','(?i)^sys_updated_on$')
            TextPattern='(?i)\b(service[- ]?now|sys_id|work_notes|cmdb_ci|assignment_group|additional_comments)\b'
            Reason='Header/sample contains ServiceNow task, CMDB, caller, assignee, or work-note fields.'
            MinHits=3
        }
        [pscustomobject]@{
            Profile='Nexthink'; Format='Nexthink export'; Confidence=90
            Patterns=@('(?i)^device_uid$','(?i)^device_name$','(?i)^device\.name$','(?i)^device\.collector\.uid$','(?i)^user_name$','(?i)^user\.name$','(?i)^user\.email$','(?i)^user_sid$','(?i)^binary_name$','(?i)^binary\.name$','(?i)^remote_action$','(?i)^remote_action\.name$','(?i)^campaign$','(?i)^campaign\.name$','(?i)^execution_status$','(?i)^execution\.status$','(?i)^collector$','(?i)^experience_score$','(?i)^destination$','(?i)^destination\.name$','(?i)^destination\.ip$')
            TextPattern='(?i)\b(nexthink|device_uid|remote_action|experience_score|execution_status|binary_name)\b'
            Reason='Header/sample contains Nexthink device, user, binary, campaign, or remote-action fields.'
            MinHits=3
        }
        [pscustomobject]@{
            Profile='Sccm'; Format='SCCM/MECM export'; Confidence=91
            Patterns=@('(?i)^ResourceID$','(?i)^SMSUniqueIdentifier$','(?i)^Name0$','(?i)^User_Name0$','(?i)^CollectionID$','(?i)^DeploymentID$','(?i)^SiteCode$','(?i)^PackageID$','(?i)^ApplicationName$','(?i)^ClientVersion$','(?i)^LastLogonUserName$','(?i)^MAC_Addresses0$','(?i)^SerialNumber0$')
            TextPattern='(?i)\b(SMSUniqueIdentifier|ResourceID|CollectionID|DeploymentID|SiteCode|ClientVersion|MECM|SCCM)\b'
            Reason='Header/sample contains SCCM/MECM inventory, client, collection, or deployment fields.'
            MinHits=3
        }
        [pscustomobject]@{
            Profile='Intune'; Format='Intune export'; Confidence=91
            Patterns=@('(?i)^managedDeviceName$','(?i)^managed device id$','(?i)^deviceName$','(?i)^device name$','(?i)^userPrincipalName$','(?i)^user principal name$','(?i)^primary user$','(?i)^email address$','(?i)^azureADDeviceId$','(?i)^azure ad device id$','(?i)^complianceState$','(?i)^compliance$','(?i)^managementAgent$','(?i)^enrolledDateTime$','(?i)^deviceEnrollmentType$','(?i)^serialNumber$','(?i)^serial number$','(?i)^imei$','(?i)^wiFiMacAddress$','(?i)^wi-fi mac$','(?i)^ethernetMacAddress$','(?i)^ownerType$','(?i)^operatingSystem$','(?i)^os$','(?i)^osVersion$','(?i)^os version$','(?i)^last check-in$')
            TextPattern='(?i)\b(Intune|Endpoint Manager|managedDeviceName|azureADDeviceId|complianceState|managementAgent|deviceEnrollmentType)\b'
            Reason='Header/sample contains Intune device, enrollment, compliance, or management-agent fields.'
            MinHits=3
        }
        [pscustomobject]@{
            Profile='IdentityProvider'; Format='M365/identity audit export'; Confidence=89
            Patterns=@('(?i)^CreationDate$','(?i)^UserIds?$','(?i)^Operations?$','(?i)^AuditData$','(?i)^Workload$','(?i)^RecordType$','(?i)^ResultStatus$','(?i)^ClientIP$','(?i)^UserId$','(?i)^ObjectId$','(?i)^Actor$','(?i)^Target$')
            TextPattern='(?i)\b(OfficeActivity|AzureActiveDirectory|Exchange|SharePoint|Unified Audit|AuditData|ResultStatus|ClientIP)\b'
            Reason='Header/sample contains Microsoft 365, Entra ID, or unified audit export fields.'
            MinHits=3
        }
        [pscustomobject]@{
            Profile='FirewallCsv'; Format='Firewall CSV export'; Confidence=88
            Patterns=@('(?i)^(src|src_ip|srcip|source|source_ip|sourceip|source_address|sourceaddress)$','(?i)^(dst|dst_ip|dstip|destination|destination_ip|destinationip|destination_address|destinationaddress)$','(?i)^(action|rule|policy|protocol|proto)$','(?i)^(src_port|srcport|dst_port|dstport|bytes|packets)$','(?i)^(user|username|identity|src_user|srcuser|source_user|sourceuser|destination_user|destinationuser)$','(?i)^(src_host|srchost|source_host|sourcehost|dst_host|dsthost|destination_host|destinationhost)$')
            TextPattern='(?i)\b(src_ip|dst_ip|source_ip|destination_ip|firewall|vpn|policy|rule|deny|allow)\b'
            Reason='Header/sample contains firewall/VPN source, destination, action, rule, or user fields.'
            MinHits=3
        }
    )

    foreach ($hint in $hints) {
        $hits = Get-LogColumnHitCount -Columns $columnsSafe -Patterns $hint.Patterns
        if ($hits -ge [int]$hint.MinHits) {
            return [pscustomobject]@{ Profile=$hint.Profile; Format=$hint.Format; Confidence=$hint.Confidence; Reason=$hint.Reason }
        }
        if ($hits -ge 2 -and -not [string]::IsNullOrWhiteSpace($textSafe) -and $textSafe -match $hint.TextPattern) {
            return [pscustomobject]@{ Profile=$hint.Profile; Format=$hint.Format; Confidence=$hint.Confidence; Reason=$hint.Reason }
        }
    }
    return $null
}

function Test-UlsIntuneDiagnosticsText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $patterns = @(
        '(?i)\b(Intune|IntuneManagementExtension|Endpoint Manager)\b',
        '(?i)\b(MDM|OMADM|OMA-DM|DeviceManagement-Enterprise-Diagnostics-Provider)\b',
        '(?i)\b(DeviceEnroller|DeviceEnrollment|EnterpriseMgmt|EnrollmentStatusTracking|Autopilot)\b',
        '(?i)\b(Windows Update|WindowsUpdate|UsoSvc|UpdateSessionOrchestration)\b',
        '(?i)\b(PolicyManager|./Vendor/MSFT|Diagnostic Report|MDMDiagReport)\b',
        '(?i)\\(SOFTWARE\\Microsoft\\Enrollments|SOFTWARE\\Microsoft\\Provisioning|ProfileList\\S-1-5-21-)'
    )
    $hits = 0
    foreach ($pat in $patterns) {
        if ($Text -match $pat) { $hits++ }
    }
    return ($hits -ge 2)
}

function Test-UlsFirewallVpnText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $hasNetworkPair = ($Text -match '(?i)\b(src_ip|source_ip|src=|saddr=)\b' -and $Text -match '(?i)\b(dst_ip|destination_ip|dst=|daddr=)\b')
    $hasFirewallMarker = ($Text -match '(?i)\b(firewall|fw-|vpn|globalprotect|anyconnect|ipsec|wireguard|tunnel|policy=|rule=|proto=|protocol=|deny|allow|blocked|permitted)\b')
    if (-not ($hasNetworkPair -and $hasFirewallMarker)) { return $false }
    $hits = 0
    foreach ($pat in @(
        '(?i)\b(src_ip|source_ip|dst_ip|destination_ip|src=|dst=|saddr=|daddr=)\b',
        '(?i)\b(firewall|fw-|vpn|globalprotect|anyconnect|ipsec|wireguard|tunnel)\b',
        '(?i)\b(action|policy|rule|deny|allow|blocked|permitted|protocol|proto|src_port|dst_port)\s*=',
        '(?i)\b(user|username|account|identity)\s*='
    )) {
        if ($Text -match $pat) { $hits++ }
    }
    return ($hits -ge 2)
}

function New-RecommendedScrubCommand {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Profile,
        [switch]$UseAutoProfile,
        [string]$ExtraSwitches = ''
    )
    $quotedPath = "'" + ($Path -replace "'", "''") + "'"
    $profilePart = if ($UseAutoProfile) { "-AutoProfile" } else { "-Profile $Profile" }
    $extraPart = if ([string]::IsNullOrWhiteSpace($ExtraSwitches)) { '' } else { ' ' + $ExtraSwitches.Trim() }
    return "Invoke-UniversalScrubber -Path $quotedPath $profilePart$extraPart -DryRun -Salt `"preview-only`" -MapSource Discover -NonInteractive"
}

function New-LogFormatRecommendationObject {
    param(
        [Parameter(Mandatory)]$File,
        [Parameter(Mandatory)][string]$DetectedFormat,
        [Parameter(Mandatory)][string]$SuggestedProfile,
        [Parameter(Mandatory)][int]$Confidence,
        [string[]]$Reasons,
        [string[]]$Warnings,
        [string]$ExtraSwitches = ''
    )

    if (-not (Get-ScrubProfile -Name $SuggestedProfile)) {
        $Warnings += "Profile '$SuggestedProfile' is not built in; using Generic."
        $SuggestedProfile = 'Generic'
    }
    if ($Confidence -lt 0) { $Confidence = 0 }
    if ($Confidence -gt 100) { $Confidence = 100 }
    return [pscustomobject]@{
        Path               = $File.FullName
        Name               = $File.Name
        Extension          = $File.Extension
        DetectedFormat     = $DetectedFormat
        SuggestedProfile   = $SuggestedProfile
        Confidence         = $Confidence
        Reasons            = @($Reasons)
        Warnings           = @($Warnings)
        RecommendedCommand = (New-RecommendedScrubCommand -Path $File.FullName -Profile $SuggestedProfile -ExtraSwitches $ExtraSwitches)
    }
}

function Get-LogFormatRecommendation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$File,
        [int]$SampleLines = 50
    )

    $sample = Get-ReadableFileSample -File $File -SampleLines $SampleLines
    $warnings = @($sample.Warnings)
    $lines = @($sample.Lines)
    $text = [string]$sample.Text
    $ext = ([string]$File.Extension).ToLowerInvariant()
    $first = @($lines | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ } | Select-Object -First 1)
    $firstLine = if ($first.Count -gt 0) { [string]$first[0] } else { '' }

    if ($ext -eq '.evtx') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'EVTX' -SuggestedProfile 'WindowsEventCsv' -Confidence 95 `
            -Reasons @('The .evtx extension identifies a Windows Event Log file.') `
            -Warnings @('EVTX is binary; the scrubber converts it to CSV before scrubbing.')
    }
    if ($ext -eq '.etl') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'ETL trace' -SuggestedProfile 'Generic' -Confidence 45 `
            -Reasons @('The .etl extension identifies a Windows Event Trace Log.') `
            -Warnings @('ETL conversion is opt-in. Use -ConvertEtl to run Windows tracerpt.exe locally, or convert ETL to CSV/XML/text with your diagnostic workflow before scrubbing.') `
            -ExtraSwitches '-ConvertEtl'
    }
    if ($ext -eq '.cab') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'CAB archive' -SuggestedProfile 'Text' -Confidence 20 `
            -Reasons @('The .cab extension identifies a cabinet archive, commonly used inside Intune diagnostic bundles.') `
            -Warnings @('CAB archives are not expanded by the scrubber in v4.15. Extract approved contents first, or remove archives that are not needed for review.')
    }
    if ($ext -eq '.xlsx') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'XLSX' -SuggestedProfile 'Generic' -Confidence 90 `
            -Reasons @('The .xlsx extension identifies an Excel workbook.') `
            -Warnings @('Workbook conversion happens locally before scrubbing. In v4.15, the first worksheet is converted; export specific sheets or use BYOP for complex workbooks.')
    }
    if ($ext -eq '.docx') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'DOCX' -SuggestedProfile 'Text' -Confidence 90 `
            -Reasons @('The .docx extension identifies an OpenXML Word document.') `
            -Warnings @('DOCX text extraction happens locally under the work directory before scrubbing. The intermediate text is UNSCRUBBED until the scrub step completes.')
    }
    if ($ext -eq '.pptx') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'PPTX' -SuggestedProfile 'Text' -Confidence 90 `
            -Reasons @('The .pptx extension identifies an OpenXML PowerPoint deck.') `
            -Warnings @('PPTX text extraction happens locally under the work directory before scrubbing. The intermediate text is UNSCRUBBED until the scrub step completes.')
    }
    if ($ext -in @('.doc','.ppt')) {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'Legacy Office document' -SuggestedProfile 'Text' -Confidence 25 `
            -Reasons @('The extension identifies a legacy binary Office format.') `
            -Warnings @('Legacy .doc/.ppt files are not parsed natively. Export to .docx/.pptx or plain text, then scrub the exported file.')
    }

    if (@($lines | Where-Object { ([string]$_) -match '^#Fields:' }).Count -gt 0) {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'W3C/IIS' -SuggestedProfile 'IIS' -Confidence 98 `
            -Reasons @('A #Fields: header was found.') -Warnings $warnings
    }
    if ($ext -in @('.log','.txt','.reg','.html','.htm','.xml') -and (Test-UlsIntuneDiagnosticsText -Text $text)) {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'Intune Diagnostics text/report' -SuggestedProfile 'IntuneDiagnostics' -Confidence 88 `
            -Reasons @('The sample contains Intune, MDM, enrollment, policy, Windows Update, or registry diagnostics markers.') `
            -Warnings $warnings
    }
    if ($text -match '(?m)^\s*CEF:\d+\|') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'CEF' -SuggestedProfile 'Cef' -Confidence 96 `
            -Reasons @('A CEF prefix was found.') -Warnings $warnings
    }
    if ($text -match '(?m)^\s*LEEF:\d+(?:\.\d+)?\|') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'LEEF' -SuggestedProfile 'Cef' -Confidence 94 `
            -Reasons @('A LEEF prefix was found; the built-in CEF profile handles key=value SIEM extensions.') -Warnings $warnings
    }
    if ($text -match '(?is)<!\[LOG\[.*?\]LOG\]!><time=' -or $text -match '(?i)\b(CCMExec|ConfigMgr|Configuration Manager|Software Center|Management Point|Distribution Point)\b') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'SCCM/ConfigMgr client text' -SuggestedProfile 'SccmText' -Confidence 88 `
            -Reasons @('The sample contains CMTrace or SCCM/ConfigMgr client-log markers.') -Warnings $warnings
    }

    $jsonLinesOk = Test-JsonLines -Lines $lines
    $jsonLineExtensionOk = $jsonLinesOk
    if (-not $jsonLineExtensionOk -and $ext -in @('.jsonl','.ndjson') -and -not [string]::IsNullOrWhiteSpace($firstLine)) {
        $jsonLineExtensionOk = Test-JsonText -Text $firstLine
    }
    if ($jsonLinesOk -or $jsonLineExtensionOk) {
        $profile = 'Generic'
        $enterpriseHint = Get-UlsEnterpriseProfileHint -Text $text
        if ($enterpriseHint) { $profile = [string]$enterpriseHint.Profile }
        elseif ($text -match '(?i)"(IncidentNumber|IncidentName|AlertIds|Tactics|Entities|TimeGenerated|ProviderName)"|Microsoft Sentinel|Sentinel') { $profile = 'CloudAudit' }
        elseif ((($text -match '(?i)"(alert_id|process_path|command_line|remote_domain|sha256)"') -and ($text -match '(?i)"(device_name|user_email|remote_ip|process_name)"')) -or ($text -match '(?i)\b(EDR|XDR|Defender for Endpoint)\b')) { $profile = 'Edr' }
        elseif ($text -match '(?i)"(eventSource|eventName|awsRegion|userIdentity|tenantId|operationName|operation|principal|resource|sourceIPAddress)"') { $profile = 'CloudAudit' }
        elseif ($text -match '(?i)"(message|level|trace|span|api_key|client_secret|username|host)"') { $profile = 'AppJson' }
        $reason = if ($enterpriseHint) { @('Multiple sampled lines parse as standalone JSON objects.', [string]$enterpriseHint.Reason) } else { @('Multiple sampled lines parse as standalone JSON objects.') }
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'JSON Lines / NDJSON' -SuggestedProfile $profile -Confidence 92 `
            -Reasons $reason -Warnings $warnings
    }
    if ((Test-JsonText -Text $text) -or ($ext -eq '.json' -and (Test-JsonText -Text $text))) {
        $profile = 'Generic'
        $enterpriseHint = Get-UlsEnterpriseProfileHint -Text $text
        if ($enterpriseHint) { $profile = [string]$enterpriseHint.Profile }
        elseif ($text -match '(?i)"(IncidentNumber|IncidentName|AlertIds|Tactics|Entities|TimeGenerated|ProviderName)"|Microsoft Sentinel|Sentinel') { $profile = 'CloudAudit' }
        elseif ((($text -match '(?i)"(alert_id|process_path|command_line|remote_domain|sha256)"') -and ($text -match '(?i)"(device_name|user_email|remote_ip|process_name)"')) -or ($text -match '(?i)\b(EDR|XDR|Defender for Endpoint)\b')) { $profile = 'Edr' }
        elseif ($text -match '(?i)"(eventSource|eventName|awsRegion|userIdentity|tenantId|operationName|operation|principal|resource|sourceIPAddress)"') { $profile = 'CloudAudit' }
        elseif ($text -match '(?i)"(message|level|trace|span|api_key|client_secret|username|host)"') { $profile = 'AppJson' }
        $reason = if ($enterpriseHint) { @('The sampled content parses as JSON.', [string]$enterpriseHint.Reason) } else { @('The sampled content parses as JSON.') }
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'JSON' -SuggestedProfile $profile -Confidence 90 `
            -Reasons $reason -Warnings $warnings
    }

    $jsonish = ($firstLine -match '^\s*[\{\[]')
    if (-not $jsonish -and ($ext -eq '.tsv' -or ($firstLine -match "`t" -and @($firstLine.ToCharArray() | Where-Object { $_ -eq "`t" }).Count -ge 1))) {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'TSV' -SuggestedProfile 'Tsv' -Confidence 88 `
            -Reasons @('The sample appears tab-delimited.') -Warnings $warnings
    }
    if (-not $jsonish -and ($ext -eq '.psv' -or (($firstLine -split '\|').Count -ge 3 -and $firstLine -notmatch '^\s*(CEF|LEEF):'))) {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'PSV' -SuggestedProfile 'Psv' -Confidence 86 `
            -Reasons @('The sample appears pipe-delimited.') -Warnings $warnings
    }

    if (-not $jsonish -and ($ext -eq '.csv' -or (($firstLine -split ',').Count -ge 3))) {
        $columns = Get-LogHeaderColumns -Header $firstLine -Delimiter ','
        $adHits = Get-LogColumnHitCount -Columns $columns -Patterns @('(?i)^RequestID$','(?i)^CertificateTemplate$','(?i)^CertSubject$','(?i)^CertIssuer$','(?i)^ESC\d*','(?i)^PkiObjectType$')
        $eventHits = Get-LogColumnHitCount -Columns $columns -Patterns @('(?i)^ProviderName$','(?i)^LevelDisplayName$','(?i)^RecordId$','(?i)^MachineName$','(?i)^TimeCreated$','(?i)^Message$')
        if ($adHits -ge 2) {
            return New-LogFormatRecommendationObject -File $File -DetectedFormat 'CSV' -SuggestedProfile 'CA' -Confidence 96 `
                -Reasons @('CSV header contains AD CS certificate/audit columns.') -Warnings $warnings
        }
        if ($eventHits -ge 3) {
            return New-LogFormatRecommendationObject -File $File -DetectedFormat 'Windows Event CSV' -SuggestedProfile 'WindowsEventCsv' -Confidence 96 `
                -Reasons @('CSV header contains Windows Event export columns.') -Warnings $warnings
        }
        $enterpriseHint = Get-UlsEnterpriseProfileHint -Columns $columns -Text $text
        if ($enterpriseHint) {
            return New-LogFormatRecommendationObject -File $File -DetectedFormat ([string]$enterpriseHint.Format) -SuggestedProfile ([string]$enterpriseHint.Profile) -Confidence ([int]$enterpriseHint.Confidence) `
                -Reasons @([string]$enterpriseHint.Reason) -Warnings $warnings
        }
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'CSV' -SuggestedProfile 'Generic' -Confidence 82 `
            -Reasons @('The sample appears comma-delimited.') -Warnings $warnings
    }

    if ($text -match '(?m)^\S+\s+\S+\s+\S+\s+\[[^\]]+\]\s+"[A-Z]+ [^"]+ HTTP/[0-9.]+"\s+\d{3}\s+') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'Apache/Nginx access log' -SuggestedProfile 'Apache' -Confidence 86 `
            -Reasons @('The sample matches common/combined web access log shape.') -Warnings $warnings
    }
    if (Test-UlsFirewallVpnText -Text $text) {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'Firewall/VPN text' -SuggestedProfile 'Firewall' -Confidence 88 `
            -Reasons @('The sample contains firewall/VPN source, destination, user, action, policy, or rule fields.') -Warnings $warnings
    }
    $kvMatches = [regex]::Matches($text, '(?<!\S)[A-Za-z_][A-Za-z0-9_.-]*=("[^"]*"|''[^'']*''|\S+)')
    if ($kvMatches.Count -ge 2) {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'logfmt / key=value' -SuggestedProfile 'Logfmt' -Confidence 88 `
            -Reasons @('Multiple key=value pairs were found in the sample.') -Warnings $warnings
    }
    if ($text -match '(?m)^(?:<\d+>)?(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+\S+\s+') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'Syslog-like text' -SuggestedProfile 'Syslog' -Confidence 82 `
            -Reasons @('The sample starts with a syslog-like timestamp and host prefix.') -Warnings $warnings
    }

    return New-LogFormatRecommendationObject -File $File -DetectedFormat 'Generic text' -SuggestedProfile 'Text' -Confidence 50 `
        -Reasons @('No stronger structured format was detected from the local sample.') -Warnings $warnings
}

function Write-LogFormatRecommendationSummary {
    [CmdletBinding()]
    param(
        [object[]]$Recommendations,
        [switch]$SafeFirstRun,
        [string]$Title = 'Log format recommendations'
    )

    $items = @($Recommendations)
    Write-Rule $Title
    Write-Info "Local-only sample analysis. No salt, token map, report, bundle or scrubbed output is created."
    if ($items.Count -eq 0) {
        Write-Warn "No candidate log files were found."
        return
    }
    foreach ($rec in $items) {
        Write-Ok ("{0}: {1} -> {2} ({3}% confidence)" -f $rec.Name, $rec.DetectedFormat, $rec.SuggestedProfile, $rec.Confidence)
        foreach ($reason in @($rec.Reasons | Select-Object -First 3)) { Write-Detail $reason }
        foreach ($warn in @($rec.Warnings)) { Write-Warn ("{0}: {1}" -f $rec.Name, $warn) }
        Write-Detail ("Suggested: {0}" -f $rec.RecommendedCommand)
    }
    if ($SafeFirstRun) {
        Write-Host ""
        Write-Step "Suggested dry-run command(s)"
        foreach ($cmd in @($items | ForEach-Object { $_.RecommendedCommand } | Select-Object -Unique)) { Write-Detail $cmd }
    }
}

function Test-LogFormat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Recurse,
        [string[]]$Include,
        [string[]]$Exclude,
        [int]$SampleLines = 50,
        [switch]$Quiet
    )

    $targets = Resolve-LogRecommendationTargets -Path $Path -Recurse:$Recurse -Include $Include -Exclude $Exclude
    if ($targets.Count -eq 0) { throw "No candidate log files found: $Path" }
    $recs = @()
    foreach ($t in $targets) { $recs += Get-LogFormatRecommendation -File $t -SampleLines $SampleLines }
    if (-not $Quiet) { Write-LogFormatRecommendationSummary -Recommendations $recs }
    return $recs
}

# =====================================================================
# REGION: Field scrubbing (profile-aware)
# =====================================================================
function Get-FallbackPrefix {
    param([string]$ColumnName, [string]$Value, $Profile)
    $col = if ($ColumnName) { $ColumnName.ToLowerInvariant() } else { "" }
    # Defer multi-valued cells to the caller's list branch.
    if ($Value -match ';|\|') { return $null }
    # Universal pass-through shapes (never tokenize these).
    if ($col -notmatch 'serial|certificate|cert|hash|thumbprint' -and $col -match 'requestid|date|time|when|disposition|validity|count|number|status|flag|enabled|required|approval|candidate') { return $null }
    if ($col -match 'eku|oid|authcapable|published') { return $null }

    if ($Value -match '^S-1-\d+(?:-\d+)+$') { return 'SID' }

    foreach ($rule in $Profile.ColumnPrefix) {
        if ($col -match $rule.Pattern) {
            if ($rule.NotOid -and ($Value -match '^([0-9]+\.)+[0-9]+$')) { continue }
            if ($rule.DollarComputer -and ($Value -match '\$$')) { return "COMPUTER" }
            return $rule.Prefix
        }
    }
    # Fall back to value shape.
    return Get-ValueShapePrefix -Value $Value
}

function Get-TokenForAtomicValue {
    param([string]$ColumnName, [string]$Value, $Profile)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $clean = if ($ColumnName -match 'SAN|UPN|Email') { Normalize-SANValue -Value $Value } else { $Value.Trim() }
    if ([string]::IsNullOrWhiteSpace($clean)) { return $Value }
    if (Is-AlreadyToken -Value $clean) { return $clean }
    if (Test-ScrubAllowlist -Value $clean) { return $clean }
    $norm = Normalize-TokenKey -Value $clean
    if ($norm -and $script:TokenByNorm.ContainsKey($norm)) { return $script:TokenByNorm[$norm] }
    if ($script:ScrubPolicy -ne 'Strict' -and (Test-UlsWellKnownSid -Value $clean)) { return $clean }
    if ($script:ScrubPolicy -ne 'Strict' -and (Test-UlsWellKnownWindowsPrincipal -Value $clean)) { return $clean }
    $known = Get-CanonicalKnownLabelByValue -Value $clean
    if ($known) { return $known }
    if (Test-PreserveDottedDecimal -Value $clean) { return $clean }   # OID / version (not an IP)
    if ($script:ScrubPolicy -ne 'Strict' -and (Test-WindowsDiagnosticDottedName -Value $clean)) { return $clean }
    if ($clean -match '^(true|false)$') { return $clean }        # boolean
    $date = [datetime]::MinValue
    if (($ColumnName -match 'date|time|when|notbefore|notafter') -and [datetime]::TryParse($clean, [ref]$date)) { return $clean }
    $prefix = Get-FallbackPrefix -ColumnName $ColumnName -Value $clean -Profile $Profile
    if ($prefix) {
        $atomicContext = ("{0}: {1}" -f $ColumnName, $clean)
        $atomicIndex = [Math]::Max(0, $atomicContext.Length - $clean.Length)
        if (Test-PreserveDetectedValue -Value $clean -Detector 'AtomicValue' -Prefix $prefix -Text $atomicContext -Index $atomicIndex -Length $clean.Length) { return $clean }
        $token = Invoke-HmacToken -Value $clean -Prefix $prefix
        if ($token) { return $token }
    }
    return $clean
}

function Get-MatchingProfileColumnRule {
    param($Profile, [string]$ColumnName, [string]$RuleSet)
    if (-not $Profile -or [string]::IsNullOrWhiteSpace($ColumnName)) { return $null }
    $rules = @()
    try { if ($Profile.$RuleSet) { $rules = @($Profile.$RuleSet) } } catch { }
    foreach ($rule in $rules) {
        if ($null -eq $rule -or $null -eq $rule.RegexObject) { continue }
        if ($rule.RegexObject.IsMatch($ColumnName)) { return $rule }
    }
    return $null
}

function Test-UlsDiscoveryShouldScanColumn {
    param($Profile, [string]$ColumnName)
    if (-not $Profile -or [string]::IsNullOrWhiteSpace($ColumnName)) { return $true }

    # Discovery should not spend regex time on columns that the active profile already
    # treats as analytical/pass-through metadata. This is deliberately profile-aware and
    # mirrors Scrub-FieldCore's pass-through logic for non-Strict policy. It does NOT skip
    # whole-column scrub rules such as MachineName/ComputerName, and it does NOT skip
    # Message/EventDataJson scan columns.
    try {
        $schemaRule = Get-MatchingProfileColumnRule -Profile $Profile -ColumnName $ColumnName -RuleSet 'SchemaColumns'
        if ($schemaRule -and $schemaRule.Action -eq 'PassThrough' -and $script:ScrubPolicy -ne 'Strict') { return $false }
    } catch { }

    try {
        if ($Profile.PassThroughRegex -and ($ColumnName -match $Profile.PassThroughRegex) -and $script:ScrubPolicy -ne 'Strict') { return $false }
    } catch { }

    return $true
}

function Invoke-TokenizeWholeValue {
    param([string]$ColumnName, [string]$Value, [string]$Prefix = 'OBJECT', [string]$SplitOn)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $text = [string]$Value
    if (-not [string]::IsNullOrWhiteSpace($SplitOn) -and $text -match $SplitOn) {
        $parts = [regex]::Split($text, "($SplitOn)")
        $rebuilt = foreach ($part in $parts) {
            if ($part -match "^($SplitOn)$") { $part }
            else {
                $p = $part.Trim()
                if ([string]::IsNullOrWhiteSpace($p)) { $part }
                elseif (Is-AlreadyToken -Value $p) { $p }
                elseif (Test-ScrubAllowlist -Value $p) { $p }
                else { Get-Token -Value $p -Prefix $Prefix }
            }
        }
        return [string]::Concat($rebuilt)
    }
    $clean = $text.Trim()
    if (Is-AlreadyToken -Value $clean) { return $clean }
    if (Test-ScrubAllowlist -Value $clean) { return $clean }
    return (Get-Token -Value $clean -Prefix $Prefix)
}

function Test-UlsWindowsEventCsvProfile {
    param($Profile)
    try { return ($Profile -and ([string]$Profile.Name -ieq 'WindowsEventCsv')) } catch { return $false }
}

function Test-UlsValidIpv6Address {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $trimChars = [char[]]@('[',']','(',')','{','}','"',[char]39,',',';')
    $v = ([string]$Value).Trim().Trim($trimChars)
    if ($v -notmatch ':') { return $false }
    $addr = [System.Net.IPAddress]::None
    if (-not [System.Net.IPAddress]::TryParse($v, [ref]$addr)) { return $false }
    return ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6)
}

function Test-UlsWellKnownSid {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = ([string]$Value).Trim()
    return (
        $v -match '^S-1-0-0$' -or
        $v -match '^S-1-1-0$' -or
        $v -match '^S-1-[23]-' -or
        $v -match '^S-1-5-(18|19|20|113|114)$' -or
        $v -match '^S-1-5-(32|80|90|96)-' -or
        $v -match '^S-1-15-' -or
        $v -match '^S-1-16-'
    )
}

function Test-UlsWellKnownWindowsPrincipal {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = ([string]$Value).Trim().Trim('"', "'", '.', ',', ';', ':', '}', ']', ')')
    return (
        $v -match '(?i)^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|Guest|DefaultAccount|WDAGUtilityAccount|DWM-\d+|UMFD-\d+)$' -or
        $v -match '(?i)^(NT AUTHORITY|BUILTIN|WORKGROUP|Window Manager|Font Driver Host)$' -or
        $v -match '(?i)^(NT AUTHORITY|BUILTIN|Window Manager|Font Driver Host)\\'
    )
}

function Get-UlsDetectorContext {
    param([string]$Text, [int]$Index = -1, [int]$Length = 0, [int]$Radius = 80)
    if ([string]::IsNullOrEmpty($Text) -or $Index -lt 0) { return '' }
    $start = [Math]::Max(0, $Index - $Radius)
    $end = [Math]::Min($Text.Length, $Index + [Math]::Max($Length, 1) + $Radius)
    return (($Text.Substring($start, $end - $start)) -replace "`r|`n", " ")
}

function Test-UlsGuidHasSensitiveContext {
    param([string]$Text, [int]$Index = -1, [int]$Length = 0)
    $ctx = Get-UlsDetectorContext -Text $Text -Index $Index -Length $Length
    return ($ctx -match '(?i)\b(logon\s*guid|logonguid|client\s*request\s*id|clientrequestid|request\s*id|requestid|correlation\s*id|correlationid|trace\s*id|traceid|session\s*id|sessionid|transaction\s*id|transactionid|operation\s*id|operationid|object\s*id|objectid|tenant\s*id|tenantid|application\s*id|applicationid)\b')
}

function Test-UlsLongHexHasSensitiveContext {
    param([string]$Text, [int]$Index = -1, [int]$Length = 0)
    $ctx = Get-UlsDetectorContext -Text $Text -Index $Index -Length $Length
    return ($ctx -match '(?i)\b(thumbprint|hash|sha1|sha256|certificate|cert|serial|serialnumber|serial\s*number|signature|token|secret|key|password|credential)\b')
}

function Get-UlsConnectionHostPrefix {
    param([string]$HostValue)
    if ([string]::IsNullOrWhiteSpace($HostValue)) { return $null }
    $h = ([string]$HostValue).Trim().Trim('[',']')
    if ($h -match '(?i)^(yes|no|true|false|null|none|unknown|default|failed|success|succeeded|error|warning|info|localhost)$') { return $null }
    if ($h -match '^\d{1,3}(\.\d{1,3}){3}$') { return 'IP' }
    if ($h -match ':' -and (Test-UlsValidIpv6Address -Value $h)) { return 'IP6' }
    if ($h.Length -lt 3) { return $null }
    if ($h -match '^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$') { return 'DNS' }
    return $null
}

function Invoke-UlsConnectionHostHardening {
    param([Parameter(Mandatory)][string]$Text, [string]$ColumnName)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    if ($Text.IndexOf('://') -lt 0 -and $Text -notmatch '(?i)\b(server|host|address|bootstrap\.servers|broker\.list|data source)\s*=') { return $Text }

    $out = [regex]::Replace($Text, '(?i)(?<prefix>\b(?:jdbc:[a-z0-9+.-]+:)?(?:postgres(?:ql)?|mysql|mariadb|sqlserver|oracle|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|kafka|zookeeper|ws|wss|http|https)://(?:[^@\s/;,?]+@)?)(?<host>\[[^\]\s]+\]|[A-Za-z0-9][A-Za-z0-9_.-]{0,252}|\d{1,3}(?:\.\d{1,3}){3})(?<suffix>(?::\d{1,5})?)', {
        param($m)
        $rawHost = $m.Groups['host'].Value
        $host = $rawHost.Trim('[',']')
        if ((Is-AlreadyToken -Value $host) -or (Test-ScrubAllowlist -Value $host) -or (Test-AllowedDomain -Value $host)) { return $m.Value }
        $prefix = Get-UlsConnectionHostPrefix -HostValue $host
        if (-not $prefix) { return $m.Value }
        $tok = Get-Token -Value $host -Prefix $prefix
        if ($rawHost.StartsWith('[') -and $rawHost.EndsWith(']')) { $tok = "[$tok]" }
        Add-DetectionTrace -Detector 'ConnectionHost' -Action 'Tokenized' -Value $host -Token $tok -Reason 'URL/connection string host' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $Text -Index $m.Index -Length $m.Length)
        return $m.Groups['prefix'].Value + $tok + $m.Groups['suffix'].Value
    })

    $out = [regex]::Replace($out, '(?i)(?<prefix>\b(?:server|host|address|bootstrap\.servers|broker\.list|data source)\s*=\s*)(?<host>[A-Za-z0-9][A-Za-z0-9_.-]{1,252}|\d{1,3}(?:\.\d{1,3}){3})(?<suffix>(?::\d{1,5})?)', {
        param($m)
        $host = $m.Groups['host'].Value
        if ((Is-AlreadyToken -Value $host) -or (Test-ScrubAllowlist -Value $host) -or (Test-AllowedDomain -Value $host)) { return $m.Value }
        $prefix = Get-UlsConnectionHostPrefix -HostValue $host
        if (-not $prefix) { return $m.Value }
        $tok = Get-Token -Value $host -Prefix $prefix
        Add-DetectionTrace -Detector 'ConnectionHost' -Action 'Tokenized' -Value $host -Token $tok -Reason 'Connection string host key' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $m.Groups['prefix'].Value + $tok + $m.Groups['suffix'].Value
    })

    return $out
}

function Get-UlsWindowsEventKeyPrefix {
    param([string]$KeyName, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($KeyName) -or [string]::IsNullOrWhiteSpace($Value)) { return $null }
    $k = ([string]$KeyName).Trim()
    $v = ([string]$Value).Trim().Trim('"', "'", '.', ',', ';', ':', '}', ']', ')')
    if ([string]::IsNullOrWhiteSpace($v)) { return $null }
    if (Test-UlsWellKnownSid -Value $v) { return $null }
    if (Test-UlsWellKnownWindowsPrincipal -Value $v) { return $null }
    if ($v -match '^(?:-|N/A|NULL|\(null\)|0x[0-9a-fA-F]+|\d+)$') { return $null }
    if ($k -match '(?i)(process\s*id|processid|thread\s*id|threadid|logon\s*id|logonid|record\s*id|recordid|event\s*id|eventid|provider\s*guid|providerguid|activity\s*id|activityid|opcode|keywords|level|time|date)') { return $null }
    if ($k -match '(?i)(path|process\s*name|processname|image|filename|file\s*name|commandline|command\s*line)$') { return $null }
    if ($k -match '(?i)(sid|security\s*id)$' -or $v -match '^S-1-\d+(?:-\d+)+$') { return 'SID' }
    if ($k -match '(?i)(ip|address|network\s*address|client\s*address|source\s*address|destination\s*address)') {
        if ($v -match ':' -and (Test-UlsValidIpv6Address -Value $v)) { return 'IP6' }
        return 'IP'
    }
    # line 3258 — allow the trailing " Name" / "Name" suffix that Windows event keys use
    if ($k -match '(?i)(computer|machine|workstation|hostname|host|server)(\s*name)?$') { return 'COMPUTER' }
    # if ($k -match '(?i)(computer|machine|workstation|hostname|host\s*name|host)$') { return 'COMPUTER' }
    if ($k -match '(?i)(domain|realm)$') { return 'COMPUTER' }
    if ($k -match '(?i)(user|account|subject|target|caller|member|identity|principal|service)') {
        if ($v -match '\$$') { return 'COMPUTER' }
        return 'PRINCIPAL'
    }
    if ($k -match '(?i)(logon\s*guid|logonguid|correlation\s*id|correlationid|request\s*id|requestid|trace\s*id|traceid|session\s*id|sessionid)$' -and $v -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') { return 'GUID' }
    return $null
}

function Invoke-UlsWindowsEventKeyValueToken {
    param(
        [string]$KeyName,
        [string]$Value,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $raw = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) { return $Value }
    if ((Is-AlreadyToken -Value $raw) -or (Test-ScrubAllowlist -Value $raw)) { return $Value }
    $prefix = Get-UlsWindowsEventKeyPrefix -KeyName $KeyName -Value $raw
    if (-not $prefix) { return $Value }
    if (Test-PreserveDetectedValue -Value $raw -Detector 'WindowsEventKey' -Prefix $prefix -Text $Text -Index $Index -Length $Length) { return $Value }
    return (Get-Token -Value $raw -Prefix $prefix)
}

function Invoke-UlsWindowsEventLabeledHardening {
    param([Parameter(Mandatory)][string]$Text, [string]$ColumnName)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    $labelPattern = '(?i)(?<prefix>\b(?:Security ID|Account Name|Account Domain|Caller Workstation|Workstation Name|Source Network Address|Client Address|IP Address|Computer Name|Server Name|Target User Name|Target Domain Name|Subject User Name|Subject Domain Name|TargetSid|SubjectUserSid|TargetUserName|SubjectUserName|TargetDomainName|SubjectDomainName|WorkstationName|IpAddress)\s*:\s*)(?<value>[^\s,;]+)'
    return [regex]::Replace($Text, $labelPattern, {
        param($m)
        $labelText = $m.Groups['prefix'].Value
        $key = ($labelText -replace '[:\s]+$', '').Trim()
        $value = $m.Groups['value'].Value
        $tok = Invoke-UlsWindowsEventKeyValueToken -KeyName $key -Value $value -Text $Text -Index $m.Groups['value'].Index -Length $m.Groups['value'].Length
        if ($tok -eq $value) { return $m.Value }
        Add-DetectionTrace -Detector 'WindowsEventKey' -Action 'Tokenized' -Value $value -Token $tok -Reason $key -ColumnName $ColumnName -Context (Get-DetectionContext -Text $Text -Index $m.Index -Length $m.Length)
        return $labelText + $tok
    })
}

function Invoke-UlsWindowsEventFlatJsonScrub {
    param([Parameter(Mandatory)][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    if ($Text -notmatch '^\s*[\{\[]') { return $Text }
    $pattern = '(?<prefix>"(?<key>[^"\\]+)"\s*:\s*")(?<value>[^"\\]*(?:\\.[^"\\]*)*)(?<suffix>")'
    return [regex]::Replace($Text, $pattern, {
        param($m)
        $key = $m.Groups['key'].Value
        $value = $m.Groups['value'].Value
        $tok = Invoke-UlsWindowsEventKeyValueToken -KeyName $key -Value $value -Text $Text -Index $m.Groups['value'].Index -Length $m.Groups['value'].Length
        if ($tok -eq $value -and $key -match '(?i)(message|description|command\s*line|commandline|script\s*block|scriptblock|script|xml|payload|details|data|value)') {
            $tok = Invoke-UlsWindowsEventMessageHardening -Text $value -ColumnName ("EventDataJson." + $key)
        }
        if ($tok -eq $value) { return $m.Value }
        Add-DetectionTrace -Detector 'WindowsEventJsonKey' -Action 'Tokenized' -Value $value -Token $tok -Reason $key -ColumnName 'EventDataJson' -Context (Get-DetectionContext -Text $Text -Index $m.Index -Length $m.Length)
        return $m.Groups['prefix'].Value + $tok + $m.Groups['suffix'].Value
    })
}

function Invoke-UlsWindowsEventMessageHardening {
    param([Parameter(Mandatory)][string]$Text, [string]$ColumnName)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }

    $out = $Text
    $out = Invoke-SecretHardening -Text $out -ColumnName $ColumnName
    $out = Invoke-CustomRegexHardening -Text $out -ColumnName $ColumnName
    $out = Invoke-UlsConnectionHostHardening -Text $out -ColumnName $ColumnName
    $out = Invoke-UlsWindowsEventLabeledHardening -Text $out -ColumnName $ColumnName
    $out = Invoke-WindowsPathUserHardening -Text $out

    if ($out.IndexOf('S-1-', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $out = [regex]::Replace($out, 'S-1-\d+(?:-\d+)+', {
            param($m)
            if (Test-PreserveDetectedValue -Value $m.Value -Detector 'SID' -Prefix 'SID' -Text $out -Index $m.Index -Length $m.Length) { return $m.Value }
            return (Get-Token -Value $m.Value -Prefix 'SID')
        })
    }
    if ($out.IndexOf('\') -ge 0) {
        $out = [regex]::Replace($out, '(?<![A-Za-z0-9_.\-:\\/?])[A-Za-z0-9_.-]+\\[A-Za-z0-9_.\-$]+', {
            param($m)
            if (Test-PreserveDetectedValue -Value $m.Value -Detector 'DOMAIN\user' -Prefix 'PRINCIPAL' -Text $out -Index $m.Index -Length $m.Length) { return $m.Value }
            return (Get-Token -Value $m.Value -Prefix 'PRINCIPAL')
        })
    }
    if ($out.IndexOf('@') -ge 0) {
        $out = [regex]::Replace($out, '\b[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', {
            param($m)
            if ((Is-AlreadyToken -Value $m.Value) -or (Test-AllowedDomain -Value $m.Value)) { return $m.Value }
            return (Get-Token -Value $m.Value -Prefix 'UNMAPPED_UPN')
        })
    }
    $out = [regex]::Replace($out, '(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)', {
        param($m)
        if (Test-PreserveDetectedValue -Value $m.Value -Detector 'IPv4' -Prefix 'IP' -Text $out -Index $m.Index -Length $m.Length) { return $m.Value }
        return (Get-Token -Value $m.Value -Prefix 'IP')
    })
    if ($out.IndexOf(':') -ge 0) {
        $out = [regex]::Replace($out, '(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}|::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:', {
            param($m)
            if (-not (Test-UlsValidIpv6Address -Value $m.Value)) { return $m.Value }
            if (Test-PreserveDetectedValue -Value $m.Value -Detector 'IPv6' -Prefix 'IP6' -Text $out -Index $m.Index -Length $m.Length) { return $m.Value }
            return (Get-Token -Value $m.Value -Prefix 'IP6')
        })
    }
    if ($out.IndexOf('.') -ge 0) {
        $out = [regex]::Replace($out, '\b(?=[A-Za-z0-9.-]*[A-Za-z])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b', {
            param($m)
            $value = $m.Value
            if ((Is-AlreadyToken -Value $value) -or (Test-AllowedDomain -Value $value) -or (Test-PreserveDetectedValue -Value $value -Detector 'FQDN' -Prefix 'DNS' -Text $out -Index $m.Index -Length $m.Length)) { return $value }
            return (Get-Token -Value $value -Prefix 'DNS')
        })
    }

    if ($script:ScrubPolicy -eq 'Strict') {
        $out = Invoke-CommonDetectors -Text $out
    }
    else {
        $out = [regex]::Replace($out, '(?i)\b(?:(?:logon\s*guid|client\s*request\s*id|correlation\s*id|trace\s*id|session\s*id|transaction\s*id|operation\s*id)\s*[:=]\s*)\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?', {
            param($m)
            $guid = [regex]::Match($m.Value, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}').Value
            if ([string]::IsNullOrWhiteSpace($guid)) { return $m.Value }
            return ($m.Value -replace [regex]::Escape($guid), (Get-Token -Value $guid -Prefix 'GUID'))
        })
    }
    return $out
}

function Invoke-UlsWindowsEventDataJsonScrub {
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)]$Profile)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    $trim = ([string]$Text).Trim().TrimStart([char]0xFEFF)
    if ($trim -match '^[\{\[]') {
        $fast = Invoke-UlsWindowsEventFlatJsonScrub -Text $Text
        $fast = Invoke-WindowsPathUserHardening -Text $fast
        if ($fast -ne $Text) { return $fast }
        if ([regex]::IsMatch($Text, '"[^"\\]+"\s*:\s*"')) { return $fast }
        try {
            $obj = $trim | ConvertFrom-Json -ErrorAction Stop
            $scrubbed = Invoke-JsonNodeScrub -Node $obj -Profile $Profile -KeyName '' -Changes $null -MaxDepth 40 -Seen @{}
            $jsonOut = $scrubbed | ConvertTo-Json -Depth 40 -Compress
            $jsonOut = Invoke-JsonSerializedKeyValueHardening -Text $jsonOut -Profile $Profile -Changes $null
            return (Invoke-WindowsPathUserHardening -Text $jsonOut)
        }
        catch { }
    }
    # Invoke-UlsWindowsEventMessageHardening already runs Invoke-WindowsPathUserHardening.
    # Avoid a duplicate scan on fallback EventDataJson values.
    return (Invoke-UlsWindowsEventMessageHardening -Text $Text -ColumnName 'EventDataJson')
}

# Per-field free-text hardening (the fuller set; safe because it runs on ONE cell,
# not across the whole CSV). Every match routes through Get-Token.
function __ULS_Legacy_Invoke_FreeTextHardening_3040 {
    param([string]$ColumnName, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $out = $Value
    $out = Invoke-SecretHardening -Text $out -ColumnName $ColumnName
    $out = Invoke-CustomRegexHardening -Text $out -ColumnName $ColumnName
    $out = Invoke-CommonDetectors -Text $out
    $out = Invoke-UniversalLabelHardening -Text $out -ColumnName $ColumnName
    # ULS perf patch 4: skip an inline pass when its regex's required literal substring is absent
    # from the current text. Byte-identical -- hardening replaces identifiers with tokens (which
    # contain none of these sentinels) and never adds one, so a skipped pass could not have matched.
    $oic = [System.StringComparison]::OrdinalIgnoreCase
    if ($out.IndexOf('S-1-', $oic) -ge 0) {
        $out = [regex]::Replace($out, 'S-1-\d+(?:-\d+)+', { param($m) Get-Token -Value $m.Value -Prefix "SID" })
    }
    if ($out.IndexOf('CertificateTemplate', $oic) -ge 0) {
        $out = [regex]::Replace($out, '(?im)(\bCertificateTemplate\s*:\s*)([A-Za-z0-9_.\-]+)', {
            param($m) if (Is-AlreadyToken -Value $m.Groups[2].Value) { return $m.Value } else { return $m.Groups[1].Value + (Get-Token -Value $m.Groups[2].Value -Prefix "TEMPLATE") } })
    }
    $out = [regex]::Replace($out, '(?im)(\b(?:cdc|rmd|ccm)\s*:\s*)([A-Za-z0-9_.\-]+)', {
        param($m) if (Is-AlreadyToken -Value $m.Groups[2].Value) { return $m.Value } else { return $m.Groups[1].Value + (Get-Token -Value $m.Groups[2].Value -Prefix "DNS") } })
    if ($out.IndexOf('=') -ge 0) {
        $out = [regex]::Replace($out, '(?im)(\b(?:DNS Name|Principal Name|RFC822 Name|URL|URI|IP Address)\s*=\s*)([^,;\r\n]+)', {
            param($m)
            $label = $m.Groups[1].Value
            $rawVal = $m.Groups[2].Value.Trim()
            if (Is-AlreadyToken -Value $rawVal) { return $label + $rawVal }
            if ($label -match '(?i)IP Address') { return $label + (Get-Token -Value $rawVal -Prefix "IP") }
            if ($label -match '(?i)Principal Name|RFC822 Name') { return $label + (Get-Token -Value $rawVal -Prefix "UNMAPPED_UPN") }
            if ($label -match '(?i)URL|URI') { return $label + (Get-Token -Value $rawVal -Prefix "URI") }
            return $label + (Get-Token -Value $rawVal -Prefix "DNS") })
    }
    if ($out.IndexOf('\') -ge 0) {
        $out = [regex]::Replace($out, '(?<![A-Za-z0-9_.\-:\\/?])[A-Za-z0-9_.-]+\\[A-Za-z0-9_.\-$]+', {
            param($m)
            if (Test-PreserveDetectedValue -Value $m.Value -Detector 'DOMAIN\user' -Prefix 'PRINCIPAL' -Text $out -Index $m.Index -Length $m.Length) {
                Add-DetectionTrace -Detector 'DOMAIN\user' -Action 'Preserved' -Value $m.Value -Token '' -Reason 'Windows path segment' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
                return $m.Value
            }
            $tok = Get-Token -Value $m.Value -Prefix "PRINCIPAL"
            Add-DetectionTrace -Detector 'DOMAIN\user' -Action 'Tokenized' -Value $m.Value -Token $tok -Reason 'Standalone DOMAIN\user' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
            return $tok
        })
    }
    if ($out.IndexOf('@') -ge 0) {
        $out = [regex]::Replace($out, '\b[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', {
            param($m) if ((Is-AlreadyToken -Value $m.Value) -or (Test-AllowedDomain -Value $m.Value)) { return $m.Value } else { return Get-Token -Value $m.Value -Prefix "UNMAPPED_UPN" } })
    }
    $out = [regex]::Replace($out, '(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)', {
        param($m) if (Test-PreserveDetectedValue -Value $m.Value -Detector 'IPv4' -Prefix 'IP' -Text $out -Index $m.Index -Length $m.Length) { return $m.Value } else { return Get-Token -Value $m.Value -Prefix "IP" }
    })
    $out = [regex]::Replace($out, '\b(?=[A-Za-z0-9.-]*[A-Za-z])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b', {
        param($m)
        $value = $m.Value
        if (Is-AlreadyToken -Value $value) { return $value }
        if ($value -match '^([0-9]+\.)+[0-9]+$') { return $value }
        if ($value -match '^\d+(?:\.\d+)+$') { return $value }
        if (Test-AllowedDomain -Value $value) { return $value }
        if (Test-PreserveDetectedValue -Value $value -Detector 'FQDN' -Prefix 'DNS' -Text $out -Index $m.Index -Length $m.Length) {
            Add-DetectionTrace -Detector 'FQDN' -Action 'Preserved' -Value $value -Token '' -Reason 'Diagnostic dotted name' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
            return $value
        }
        $tok = Get-Token -Value $value -Prefix "DNS"
        Add-DetectionTrace -Detector 'FQDN' -Action 'Tokenized' -Value $value -Token $tok -Reason 'Private or unknown dotted host' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $tok })
    if ($out.IndexOf('=') -ge 0) {
        $out = [regex]::Replace($out, '(?i)\b(?:CN|OU|DC|O|L|ST|C)=[^;,\r\n]+', { param($m) Get-Token -Value $m.Value -Prefix "X500" })
    }
    $out = [regex]::Replace($out, '(?<![A-Za-z0-9_])[0-9a-fA-F]{20,}(?![A-Za-z0-9_])', {
        param($m)
        if (Test-PreserveDetectedValue -Value $m.Value -Detector 'LongHex' -Prefix 'CERT' -Text $out -Index $m.Index -Length $m.Length) {
            Add-DetectionTrace -Detector 'LongHex' -Action 'Preserved' -Value $m.Value -Token '' -Reason 'Diagnostic hash context' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
            return $m.Value
        }
        $tok = Get-Token -Value $m.Value -Prefix "CERT"
        Add-DetectionTrace -Detector 'LongHex' -Action 'Tokenized' -Value $m.Value -Token $tok -Reason 'Long hex value' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $tok
    })
    return $out
}

function Scrub-Field {
    # ULS perf patch 1: per-file memoization wrapper. Within a single file scrub the salt,
    # the loaded token map, the scrub policy, the profile, and the allowlist are all fixed,
    # and Get-Token never mutates the loaded map -- so an identical (column, value) cell
    # always scrubs to the same string. Caching that result is byte-identical to recomputing
    # it and removes the dominant cost on repetitive logs (e.g. Windows Security messages).
    # The cache is created fresh per file in Invoke-ScrubFile; when $script:__cellCache is
    # $null (direct callers, discovery) this wrapper simply forwards to Scrub-FieldCore.
    #
    # Disclosure: because duplicates are not recomputed, -DetectionSummaryReport counts and
    # the fail-closed fallback tally become per-DISTINCT-value rather than per-occurrence.
    # The scrubbed output file, the token map, and the leak-check verdict are UNCHANGED.
    param([string]$ColumnName, $Value, $Profile)
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $text }
    if ($null -eq $script:__cellCache) {
        return (Scrub-FieldCore -ColumnName $ColumnName -Value $Value -Profile $Profile)
    }
    $cacheKey = ([string]$ColumnName) + ([char]0) + $text
    if ($script:__cellCache.ContainsKey($cacheKey)) { return $script:__cellCache[$cacheKey] }
    $result = Scrub-FieldCore -ColumnName $ColumnName -Value $Value -Profile $Profile
    $script:__cellCache[$cacheKey] = $result
    return $result
}

function Scrub-FieldCore {
    param([string]$ColumnName, $Value, $Profile)
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $text }

    try {
        $wholeRule = Get-MatchingProfileColumnRule -Profile $Profile -ColumnName $ColumnName -RuleSet 'WholeColumnRules'
        if ($wholeRule) {
            return [string](Invoke-TokenizeWholeValue -ColumnName $ColumnName -Value $text -Prefix $wholeRule.Prefix -SplitOn $wholeRule.SplitOn)
        }

        $schemaRule = Get-MatchingProfileColumnRule -Profile $Profile -ColumnName $ColumnName -RuleSet 'SchemaColumns'
        if ($schemaRule -and $schemaRule.Action -eq 'Scrub') {
            return [string](Invoke-TokenizeWholeValue -ColumnName $ColumnName -Value $text -Prefix $schemaRule.Prefix -SplitOn $schemaRule.SplitOn)
        }
        if ($schemaRule -and $schemaRule.Action -eq 'PassThrough') { return $text }

        # Profile pass-through columns (analytical / non-identifying). In Balanced/Readable these are
        # truly pass-through: provider names, event ids, timestamps, record ids, and similar metadata
        # are not identifiers by default. Strict keeps the older fail-closed hardening behavior.
        if ($Profile.PassThroughRegex -and ($ColumnName -match $Profile.PassThroughRegex)) {
            if ($script:ScrubPolicy -ne 'Strict') { return $text }
            if (($text -match '^[0-9]+$') -or ($text -match '^\d{4}-\d{2}-\d{2}[T ]')) { return $text }
            return [string](Invoke-LeakHardeningText -Text $text)
        }

        if (Test-UlsWindowsEventCsvProfile -Profile $Profile) {
            if ($ColumnName -ieq 'EventDataJson') { return [string](Invoke-UlsWindowsEventDataJsonScrub -Text $text -Profile $Profile) }
            if ($ColumnName -ieq 'Message') { return [string](Invoke-UlsWindowsEventMessageHardening -Text $text -ColumnName $ColumnName) }
        }

        # Multi-valued cells: split on ; or | and tokenize EACH element on its own, so
        # a principal list never collapses to a single token.
        $multiSplit = if ($schemaRule -and $schemaRule.SplitOn) { [string]$schemaRule.SplitOn } else { ';|\|' }
        if ($text -match $multiSplit) {
            $delimiter = if ($text -match ';') { ';' } elseif ($text -match '\|') { '|' } else { $matches[0] }
            $parts = $text -split [regex]::Escape($delimiter)
            $scrubbedParts = foreach ($part in $parts) {
                $p = $part.Trim()
                if ($p) { Invoke-FreeTextHardening -ColumnName $ColumnName -Value (Get-TokenForAtomicValue -ColumnName $ColumnName -Value $p -Profile $Profile) } else { $p }
            }
            return [string]($scrubbedParts -join $delimiter)
        }

        # Exact whole-value first.
        $exact = Get-TokenForAtomicValue -ColumnName $ColumnName -Value $text -Profile $Profile
        if ($exact -ne $text -or (Is-AlreadyToken -Value $exact)) { return [string]$exact }

        # Free-text fallback: deny-by-default profiles harden every column; others use
        # the profile's free-text column regex.
        if (($schemaRule -and $schemaRule.Action -eq 'Scan') -or $Profile.DenyByDefault -or ($Profile.FreeTextRegex -and $ColumnName -match $Profile.FreeTextRegex)) {
            return [string](Invoke-FreeTextHardening -ColumnName $ColumnName -Value $text)
        }
        return $text
    }
    catch {
        # FAIL CLOSED -- a cell we cannot fully process must never leak. First retry
        # with the whole-file-safe pass set (no broad per-field SID/DOMAIN\user/DN
        # passes); if even that fails, replace the entire cell with one token.
        $script:__scrubFallback = [int]$script:__scrubFallback + 1
        if (-not $script:__scrubFallbackCol) { $script:__scrubFallbackCol = $ColumnName }
        try { return [string](Invoke-LeakHardeningText -Text $text) }
        catch {
            $t = Invoke-HmacToken -Value $text -Prefix "OBJECT"
            if ($t) { return $t }
            return "OBJECT_REDACTED"
        }
    }
}

# =====================================================================
# REGION: Whole-file hardening + leak check + sensitive-term redaction
# =====================================================================
# CSV-safe whole-file passes (value classes stop at quote/comma/space so they
# never swallow a neighbouring column). Routes every match through Get-Token.
function __ULS_Legacy_Invoke_LeakHardeningText_3170 {
    param([Parameter(Mandatory)][string]$Text)
    $out = $Text
    $out = Invoke-SecretHardening -Text $out
    $out = Invoke-CustomRegexHardening -Text $out
    $out = Invoke-CommonDetectors -Text $out
    $out = Invoke-UniversalLabelHardening -Text $out
    # ULS perf patch 4: skip an inline pass when its required literal substring is absent from
    # the current text. Byte-identical -- hardening never introduces these sentinels.
    $oic = [System.StringComparison]::OrdinalIgnoreCase
    if ($out.IndexOf('CertificateTemplate', $oic) -ge 0) {
        $out = [regex]::Replace($out, '(?im)(\bCertificateTemplate\s*:\s*)([A-Za-z0-9_.\-]+)', {
            param($m) if (Is-AlreadyToken -Value $m.Groups[2].Value) { return $m.Value } else { return $m.Groups[1].Value + (Get-Token -Value $m.Groups[2].Value -Prefix "TEMPLATE") } })
    }
    $out = [regex]::Replace($out, '(?im)(\b(?:cdc|rmd|ccm)\s*:\s*)([A-Za-z0-9_.\-]+)', {
        param($m) if (Is-AlreadyToken -Value $m.Groups[2].Value) { return $m.Value } else { return $m.Groups[1].Value + (Get-Token -Value $m.Groups[2].Value -Prefix "DNS") } })
    if ($out.IndexOf('=') -ge 0) {
        $out = [regex]::Replace($out, '(?im)(\b(?:DNS Name|Principal Name|RFC822 Name|URL|URI|IP Address)\s*=\s*)([A-Za-z0-9_.@:\-/]+)', {
            param($m)
            $label = $m.Groups[1].Value
            $value = $m.Groups[2].Value
            if (Is-AlreadyToken -Value $value) { return $m.Value }
            if ($label -match '(?i)IP Address') { return $label + (Get-Token -Value $value -Prefix "IP") }
            if ($label -match '(?i)Principal Name|RFC822 Name') { return $label + (Get-Token -Value $value -Prefix "UNMAPPED_UPN") }
            if ($value -match '@') { return $label + (Get-Token -Value $value -Prefix "UNMAPPED_UPN") }
            return $label + (Get-Token -Value $value -Prefix "DNS") })
    }
    if ($out.IndexOf('@') -ge 0) {
        $out = [regex]::Replace($out, '\b[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', {
            param($m) if ((Is-AlreadyToken -Value $m.Value) -or (Test-AllowedDomain -Value $m.Value)) { return $m.Value } else { return Get-Token -Value $m.Value -Prefix "UNMAPPED_UPN" } })
    }
    $out = [regex]::Replace($out, '(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)', {
        param($m) if ((Is-AlreadyToken -Value $m.Value) -or (Test-PreserveDetectedValue -Value $m.Value -Detector 'IPv4' -Prefix 'IP' -Text $out -Index $m.Index -Length $m.Length)) { return $m.Value } else { return Get-Token -Value $m.Value -Prefix "IP" } })
    $out = [regex]::Replace($out, '\b(?=[A-Za-z0-9.-]*[A-Za-z])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b', {
        param($m)
        $value = $m.Value
        if (Is-AlreadyToken -Value $value) { return $value }
        if ($value -match '^([0-9]+\.)+[0-9]+$') { return $value }
        if ($value -match '^\d+(?:\.\d+)+$') { return $value }
        if (Test-AllowedDomain -Value $value) { return $value }
        if (Test-PreserveDetectedValue -Value $value -Detector 'FQDN' -Prefix 'DNS' -Text $out -Index $m.Index -Length $m.Length) {
            Add-DetectionTrace -Detector 'FQDN' -Action 'Preserved' -Value $value -Token '' -Reason 'Diagnostic dotted name' -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
            return $value
        }
        $tok = Get-Token -Value $value -Prefix "DNS"
        Add-DetectionTrace -Detector 'FQDN' -Action 'Tokenized' -Value $value -Token $tok -Reason 'Private or unknown dotted host' -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $tok })
    $out = [regex]::Replace($out, '(?<![A-Za-z0-9_])[0-9a-fA-F]{20,}(?![A-Za-z0-9_])', {
        param($m)
        if (Is-AlreadyToken -Value $m.Value) { return $m.Value }
        if (Test-PreserveDetectedValue -Value $m.Value -Detector 'LongHex' -Prefix 'CERT' -Text $out -Index $m.Index -Length $m.Length) {
            Add-DetectionTrace -Detector 'LongHex' -Action 'Preserved' -Value $m.Value -Token '' -Reason 'Diagnostic hash context' -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
            return $m.Value
        }
        $tok = Get-Token -Value $m.Value -Prefix "CERT"
        Add-DetectionTrace -Detector 'LongHex' -Action 'Tokenized' -Value $m.Value -Token $tok -Reason 'Long hex value' -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $tok })
    return $out
}

# Redact explicit shapeless secrets (org / vendor / NetBIOS / codenames). Each is
# a literal resolved ONCE via the shared tokenizer so it collapses consistently.
function Protect-SensitiveTerms {
    param([Parameter(Mandatory)][string]$Text, [string[]]$SensitiveTerms = @())
    if (-not $SensitiveTerms -or @($SensitiveTerms).Count -eq 0) { return $Text }
    $out = $Text
    foreach ($term in $SensitiveTerms) {
        $t = ([string]$term).Trim()
        if ($t.Length -lt 3) { continue }   # 1-2 char terms are too collision-prone
        $prefix = if ($t -match '^(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$') { "DNS" } else { "X500" }
        $tok = Get-Token -Value $t -Prefix $prefix
        $out = [regex]::Replace($out, [regex]::Escape($t), $tok.Replace('$', '$$'), 'IgnoreCase')
    }
    return $out
}

function Invoke-UlsLineWiseFileHardening {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$SensitiveTerms = @(),
        [switch]$SkipFirstLine
    )
    $resolved = (Resolve-Path -Path $Path).Path
    $dir = Split-Path -Parent $resolved
    if ([string]::IsNullOrWhiteSpace($dir)) { $dir = (Get-Location).Path }
    $tmp = Join-Path $dir ('.{0}.reharden.{1}.tmp' -f ([System.IO.Path]::GetFileName($resolved)), ([guid]::NewGuid().ToString('N')))
    $reader = $null
    $writer = $null
    $completed = $false
    try {
        $reader = [System.IO.StreamReader]::new($resolved)
        $writer = [System.IO.StreamWriter]::new($tmp, $false, [System.Text.Encoding]::UTF8)
        $lineNo = 0
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            $lineNo++
            if ($SkipFirstLine -and $lineNo -eq 1) {
                $writer.WriteLine($line)
                continue
            }
            $line = Invoke-LeakHardeningText -Text $line
            $line = Protect-SensitiveTerms -Text $line -SensitiveTerms $SensitiveTerms
            $writer.WriteLine($line)
        }
        $completed = $true
    }
    finally {
        if ($writer) { $writer.Close() }
        if ($reader) { $reader.Close() }
        if (-not $completed -and (Test-Path -LiteralPath $tmp)) {
            try { Remove-Item -LiteralPath $tmp -Force } catch { }
        }
    }
    Move-Item -LiteralPath $tmp -Destination $resolved -Force
}

function Test-ScrubbedForLeaks {
    param(
        [Parameter(Mandatory)][string]$CsvPath,
        [string[]]$SensitiveTerms = @(),
        [switch]$SkipFirstLine,
        [switch]$ProbeOnly
    )
    Write-Work "Leak check: $([System.IO.Path]::GetFileName($CsvPath))"
    $findings = New-Object System.Collections.Generic.List[object]

    $termCounts = @{}
    foreach ($term in $SensitiveTerms) {
        if ([string]::IsNullOrWhiteSpace($term)) { continue }
        $t = $term.Trim()
        if ($t.Length -lt 3) { continue }
        $termCounts[$t] = 0
    }
    # ULS perf patch 3 / 3b: run BOTH the finders AND the shape-pattern battery PER PHYSICAL
    # LINE, memoized by line. No identifier, label value, or shape pattern spans a newline, so
    # per-line detection finds the same values -- and it avoids two failure modes on a ~19 MB
    # single string: (a) the timeout-compiled label/custom finders throwing RegexMatchTimeout,
    # and (b) the FQDN/Email shape patterns catastrophically backtracking. A static [regex]::Matches
    # has no timeout, so (b) does not crash -- it just grinds for minutes (the non-stream "hang").
    # The streaming path already detects per line; this brings the non-stream check in line with it.
    $labeledSet = [ordered]@{}; $customSet = [ordered]@{}; $secretSet = [ordered]@{}; $seenLeakLine = @{}
    $patterns = @(
        [pscustomobject]@{ Type = "Email/UPN";   Sentinel = '@';    Rx = '\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b' },
        [pscustomobject]@{ Type = "IPv4";        Rx = '(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)' },
        [pscustomobject]@{ Type = "IPv6";        Skip = '^\d{1,5}(:\d{1,5}){1,7}$'; Rx = '(?:[A-Fa-f0-9]{1,4}:){3,7}[A-Fa-f0-9]{1,4}|::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}' },
        [pscustomobject]@{ Type = "MAC";         Rx = '\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b' },
        [pscustomobject]@{ Type = "SID";         Sentinel = 'S-1-'; Rx = 'S-1-\d+(?:-\d+)+' },
        [pscustomobject]@{ Type = "Windows user profile path"; Sentinel = '\Users\'; Rx = '(?i)(?:\\\?\\)?[A-Za-z]:\\Users\\([^\\/"'',;:\r\n]+)'; Group = 1 },
        [pscustomobject]@{ Type = "Windows user profile path (escaped)"; Sentinel = '\\Users\\'; Rx = '(?i)(?:\\\\\\\?\\\\)?[A-Za-z]:\\\\Users\\\\([^\\/"'',;:\r\n]+)'; Group = 1 },
        [pscustomobject]@{ Type = "DOMAIN\user"; Sentinel = '\';    Rx = '(?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]+\\[A-Za-z0-9_.\-$]+' },
        [pscustomobject]@{ Type = "Bare FQDN";   Rx = '\b(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b' }
    )
    $patternSets = [ordered]@{}
    foreach ($p in $patterns) { $patternSets[$p.Type] = [ordered]@{} }
    # ULS patch 7: progress + literal short-circuits. The leak check is a full verification scan of the
    # output -- give it a progress bar (it was silent), and skip a shape pattern when its required
    # literal is absent from the line (byte-identical verdict: it could not have matched anyway).
    $lcName = [System.IO.Path]::GetFileName($CsvPath)
    $lcN = 0
    $resolvedLeakPath = (Resolve-Path -Path $CsvPath).Path
    foreach ($line in [System.IO.File]::ReadLines($resolvedLeakPath)) {
        $lcN++
        if ($lcN % 2000 -eq 0) { Write-UlsProgress -Activity "Leak check" -File $lcName -RowsDone $lcN }
        if ($SkipFirstLine -and $lcN -eq 1) { continue }
        foreach ($termKey in @($termCounts.Keys)) {
            $termCounts[$termKey] = [int]$termCounts[$termKey] + ([regex]::Matches($line, [regex]::Escape($termKey), 'IgnoreCase')).Count
        }
        if ([string]::IsNullOrEmpty($line) -or $seenLeakLine.ContainsKey($line)) { continue }
        $seenLeakLine[$line] = $true
        foreach ($v in (Find-UniversalLabeledLeaks -Text $line)) { if (-not $labeledSet.Contains($v)) { $labeledSet[$v] = $true } }
        foreach ($v in (Find-CustomRegexIdentifiers -Text $line | ForEach-Object { $_.Raw })) { if (-not $customSet.Contains($v)) { $customSet[$v] = $true } }
        foreach ($v in (Find-SecretIdentifiers -Text $line | ForEach-Object { $_.Raw })) { if (-not $secretSet.Contains($v)) { $secretSet[$v] = $true } }
        foreach ($p in $patterns) {
            if ($p.Sentinel -and ($line.IndexOf([string]$p.Sentinel, [System.StringComparison]::OrdinalIgnoreCase) -lt 0)) { continue }
            $bucket = $patternSets[$p.Type]
            foreach ($m in [regex]::Matches($line, $p.Rx)) {
                $v = $m.Value
                if ($p.PSObject.Properties['Group']) {
                    $groupNum = [int]$p.Group
                    if ($groupNum -gt 0 -and $groupNum -lt $m.Groups.Count -and $m.Groups[$groupNum].Success) {
                        $profileLeak = $m.Groups[$groupNum].Value
                        if ([string]::IsNullOrWhiteSpace($profileLeak)) { continue }
                        if ($profileLeak -match '(?i)^(Public|Default|Default User|All Users)$') { continue }
                        if (Is-AlreadyToken -Value $profileLeak) { continue }
                        $v = $profileLeak
                    }
                }
                if (Is-AlreadyToken -Value $v) { continue }
                if (Test-PreserveDottedDecimal -Value $v) { continue }   # OID / version (not an IP)
                if ($p.Skip -and ($v -match $p.Skip)) { continue }
                if (($p.Type -eq 'Bare FQDN' -or $p.Type -eq 'Email/UPN') -and (Test-AllowedDomain -Value $v)) { continue }
                $prefixForLeak = switch ($p.Type) {
                    'Bare FQDN' { 'DNS' }
                    'DOMAIN\user' { 'PRINCIPAL' }
                    'Email/UPN' { 'UNMAPPED_UPN' }
                    'IPv4' { 'IP' }
                    'IPv6' { 'IP6' }
                    'MAC' { 'MAC' }
                    'SID' { 'SID' }
                    'Windows user profile path' { 'PRINCIPAL' }
                    'Windows user profile path (escaped)' { 'PRINCIPAL' }
                    default { '' }
                }
                if (Test-PreserveDetectedValue -Value $v -Detector $p.Type -Prefix $prefixForLeak -Text $line -Index $m.Index -Length $m.Length) { continue }
                if ($p.Type -eq 'DOMAIN\user') {
                    # A 'word\word' is NOT a credential leak when it is really a file path.
                    $skipDU = $false
                    #  (a) a backslash between two already-scrubbed tokens (PRINCIPAL_x\PRINCIPAL_y)
                    foreach ($seg in ($v -split '\\')) { if (Is-AlreadyToken -Value $seg) { $skipDU = $true; break } }
                    if (-not $skipDU) {
                        #  (b) bordered by a path separator -> it's inside a path
                        $before = if ($m.Index -gt 0) { [string]$line[$m.Index - 1] } else { '' }
                        $aft = $m.Index + $m.Length
                        $after = if ($aft -lt $line.Length) { [string]$line[$aft] } else { '' }
                        if ((@('\', '/', ':') -contains $before) -or (@('\', '/') -contains $after)) { $skipDU = $true }
                        #  (c) a drive root (C:\) or another path segment sits just before it
                        elseif ($m.Index -gt 0) {
                            $cs = [Math]::Max(0, $m.Index - 24)
                            $ctx = $line.Substring($cs, $m.Index - $cs)
                            if (($ctx -match '[A-Za-z]:\\') -or ($ctx -match '\\[^\\"'',;]*$')) { $skipDU = $true }
                        }
                        #  (d) well-known Windows path roots
                        if (-not $skipDU -and ($v -match '(?i)^(windows|winnt|system32|syswow64|sysnative|systemroot|drivers|users|public|default|programdata|appdata|microsoft|program files( \(x86\))?|inf|temp|tmp|config|fonts|assembly|servicing|winsxs|tasks|spool|wbem|registry|device|harddiskvolume\d*)\\')) { $skipDU = $true }
                    }
                    if ($skipDU) { continue }
                }
                if (-not $bucket.Contains($v)) { $bucket[$v] = $true }
            }
        }
    }
    Write-UlsProgress -Activity "Leak check" -File $lcName -Completed
    foreach ($termKey in @($termCounts.Keys)) {
        $count = [int]$termCounts[$termKey]
        if ($count -gt 0) { $findings.Add([pscustomobject]@{ Type = "SensitiveTerm '$termKey'"; Count = $count; Samples = "" }) }
    }
    $labeledLeaks = @($labeledSet.Keys)
    if ($labeledLeaks.Count -gt 0) {
        $findings.Add([pscustomobject]@{ Type = "Universal labeled value"; Count = $labeledLeaks.Count; Samples = (($labeledLeaks | Select-Object -First 5) -join ", ") })
    }
    $customLeaks = @($customSet.Keys)
    if ($customLeaks.Count -gt 0) {
        $findings.Add([pscustomobject]@{ Type = "Custom regex value"; Count = $customLeaks.Count; Samples = (($customLeaks | Select-Object -First 5) -join ", ") })
    }
    $secretLeaks = @($secretSet.Keys)
    if ($secretLeaks.Count -gt 0) {
        $findings.Add([pscustomobject]@{ Type = "Secret-like value"; Count = $secretLeaks.Count; Samples = (($secretLeaks | Select-Object -First 5) -join ", ") })
    }
    foreach ($p in $patterns) {
        $leaks = @($patternSets[$p.Type].Keys)
        if ($leaks.Count -gt 0) {
            $findings.Add([pscustomobject]@{ Type = $p.Type; Count = $leaks.Count; Samples = (($leaks | Select-Object -First 5) -join ", ") })
        }
    }

    if ($findings.Count -eq 0) { Write-Ok "Leak check PASSED: no residual identifiers or sensitive terms."; return $true }
    if ($ProbeOnly) {
        Write-Warn "Leak check found potential residue before final hardening:"
    }
    else {
        Write-Fail "Leak check found POTENTIAL leaks -- review before uploading:"
    }
    foreach ($f in $findings) {
        $msg = "{0}: {1} occurrence(s)" -f $f.Type, $f.Count
        if ($f.Samples) { $msg += "  e.g. $($f.Samples)" }
        Write-Detail $msg
    }
    return $false
}

# =====================================================================
# REGION: JSON adapter (values only -- keys are preserved)
#   Walks a parsed JSON tree and tokenizes leaf STRING values through the same
#   Scrub-Field path as CSV cells (so the JSON key acts as the column hint).
#   Sensitive-key numeric values are tokenized conservatively; booleans / nulls
#   and all keys pass through unchanged.
# =====================================================================
function Get-JsonNodeIdentity {
    param($Node)
    if ($null -eq $Node) { return $null }
    if ($Node -is [string] -or $Node -is [bool] -or $Node -is [int] -or $Node -is [long] -or $Node -is [double] -or $Node -is [decimal] -or $Node -is [datetime] -or $Node -is [guid]) { return $null }
    try { return [string][System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($Node) } catch { return $null }
}

function Get-UniversalLogScrubberVersionInfo {
    $modulePath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($modulePath)) {
        try { if ($MyInvocation.MyCommand.Module -and $MyInvocation.MyCommand.Module.Path) { $modulePath = $MyInvocation.MyCommand.Module.Path } } catch { }
    }

    $manifestPath = Join-Path $PSScriptRoot 'UniversalLogScrubber.psd1'
    if (-not (Test-Path -LiteralPath $manifestPath)) { $manifestPath = $null }

    return [pscustomobject]@{
        Name              = $script:ModuleName
        Version           = $script:ModuleVersion
        ModulePath        = $modulePath
        ManifestPath      = $manifestPath
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        PSEdition         = $PSVersionTable.PSEdition
    }
}

function Test-JsonNumericNode {
    param($Node)
    return (
        $Node -is [byte] -or $Node -is [sbyte] -or
        $Node -is [System.Int16] -or $Node -is [System.UInt16] -or
        $Node -is [int] -or $Node -is [uint32] -or
        $Node -is [long] -or $Node -is [uint64] -or
        $Node -is [single] -or $Node -is [double] -or $Node -is [decimal]
    )
}

function Get-JsonSensitiveNumericPrefix {
    param([string]$KeyName)
    if ([string]::IsNullOrWhiteSpace($KeyName)) { return $null }

    $key = $KeyName.Trim()
    if ($key -match '(?i)(?:time|timestamp|date|duration|elapsed|latency|count|size|bytes|statuscode|httpstatus|eventid|port|pid|processid|threadid|row|line|version|ttl|retry|retries|attempt|attempts|year|month|day|hour|minute|second|milliseconds|seconds|ms)$') {
        return $null
    }
    if ($key -match '(?i)(^|[_\-.])(?:time|timestamp|date|duration|elapsed|latency|count|size|bytes|status|code|level|severity|eventid|event_id|port|pid|processid|threadid|row|line|version|httpstatus|http_status|ttl|retry|retries|attempt|attempts|year|month|day|hour|minute|second|ms|milliseconds|seconds)(?:$|[_\-.])') {
        return $null
    }
    if ($key -match '(?i)(secret|password|passwd|pwd|token|api[_-]?key|key[_-]?id|credential)') { return 'SECRET' }
    if ($key -match '(?i)(^|[_\-.])(?:ip|ipaddr|ipaddress|srcip|dstip|src_ip|dst_ip|source_ip|destination_ip|client_ip|remote_ip)(?:$|[_\-.])') { return 'IP' }
    if ($key -match '(?i)(host|hostname|server|machine|device|asset|node|instance|ip|address)') { return 'DNS' }
    if ($key -match '(?i)(user|account|principal|subject|actor|tenant|client|customer|owner|member|identity|person|employee)') { return 'PRINCIPAL' }
    if ($key -match '(?i)(session|object|request|correlation|trace|span|transaction|resource|target)') { return 'OBJECT' }
    return $null
}

function Invoke-JsonStringValueScrub {
    param(
        [string]$KeyName,
        [string]$Value,
        $Profile
    )

    $wholeRule = Get-MatchingProfileColumnRule -Profile $Profile -ColumnName $KeyName -RuleSet 'WholeColumnRules'
    if ($wholeRule) {
        return [string](Invoke-TokenizeWholeValue -ColumnName $KeyName -Value $Value -Prefix $wholeRule.Prefix -SplitOn $wholeRule.SplitOn)
    }

    $schemaRule = Get-MatchingProfileColumnRule -Profile $Profile -ColumnName $KeyName -RuleSet 'SchemaColumns'
    if ($schemaRule -and $schemaRule.Action -eq 'Scrub') {
        return [string](Invoke-TokenizeWholeValue -ColumnName $KeyName -Value $Value -Prefix $schemaRule.Prefix -SplitOn $schemaRule.SplitOn)
    }

    $scrubbed = [string](Scrub-Field -ColumnName $KeyName -Value $Value -Profile $Profile)
    if ($scrubbed -ne $Value -or (Is-AlreadyToken -Value $scrubbed)) { return $scrubbed }

    $fallbackPrefix = Get-JsonSensitiveNumericPrefix -KeyName $KeyName
    if ($fallbackPrefix -and -not (Test-ScrubAllowlist -Value $Value)) {
        return [string](Get-Token -Value $Value -Prefix $fallbackPrefix)
    }

    return $scrubbed
}

function Invoke-JsonSerializedKeyValueHardening {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)]$Profile,
        $Changes
    )

    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    $stringPattern = '(?<prefix>"(?<key>[A-Za-z0-9_.-]+)"\s*:\s*)"(?<value>[^"\\]*(?:\\.[^"\\]*)*)"'
    $stringMatches = [System.Text.RegularExpressions.Regex]::Matches($Text, $stringPattern)
    if ($stringMatches.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        $lastIndex = 0
        foreach ($Match in $stringMatches) {
            if ($Match.Index -gt $lastIndex) { [void]$sb.Append($Text.Substring($lastIndex, $Match.Index - $lastIndex)) }
            $replacement = $Match.Value
            $key = $Match.Groups['key'].Value
            $value = $Match.Groups['value'].Value
            if (-not ([string]::IsNullOrWhiteSpace($key) -or [string]::IsNullOrWhiteSpace($value) -or (Is-AlreadyToken -Value $value))) {
                $scrubbed = Invoke-JsonStringValueScrub -KeyName $key -Value $value -Profile $Profile
                if ($scrubbed -ne $value) {
                    if ($null -ne $Changes) { [void]$Changes.Add([pscustomobject]@{ Field = $key; Original = $value; Token = $scrubbed }) }
                    $replacement = $Match.Groups['prefix'].Value + '"' + $scrubbed + '"'
                }
            }
            [void]$sb.Append($replacement)
            $lastIndex = $Match.Index + $Match.Length
        }
        if ($lastIndex -lt $Text.Length) { [void]$sb.Append($Text.Substring($lastIndex)) }
        $hardened = $sb.ToString()
    }
    else {
        $hardened = $Text
    }

    $numberPattern = '(?<prefix>"(?<key>[A-Za-z0-9_.-]+)"\s*:\s*)(?<value>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)'
    $numberMatches = [System.Text.RegularExpressions.Regex]::Matches($hardened, $numberPattern)
    if ($numberMatches.Count -eq 0) { return $hardened }

    $sb = New-Object System.Text.StringBuilder
    $lastIndex = 0
    foreach ($Match in $numberMatches) {
        if ($Match.Index -gt $lastIndex) { [void]$sb.Append($hardened.Substring($lastIndex, $Match.Index - $lastIndex)) }
        $replacement = $Match.Value
        $key = $Match.Groups['key'].Value
        $value = $Match.Groups['value'].Value
        if (-not ([string]::IsNullOrWhiteSpace($key) -or [string]::IsNullOrWhiteSpace($value) -or (Is-AlreadyToken -Value $value))) {
            $prefix = Get-JsonSensitiveNumericPrefix -KeyName $key
            if ($prefix) {
                $token = Get-Token -Value $value -Prefix $prefix
                if ($token -ne $value) {
                    if ($null -ne $Changes) { [void]$Changes.Add([pscustomobject]@{ Field = $key; Original = $value; Token = $token }) }
                    $replacement = $Match.Groups['prefix'].Value + '"' + $token + '"'
                }
            }
        }
        [void]$sb.Append($replacement)
        $lastIndex = $Match.Index + $Match.Length
    }
    if ($lastIndex -lt $hardened.Length) { [void]$sb.Append($hardened.Substring($lastIndex)) }

    return $sb.ToString()
}

function Invoke-JsonNodeScrub {
    param(
        $Node,
        $Profile,
        [string]$KeyName = '',
        $Changes,
        [int]$Depth = 0,
        [int]$MaxDepth = 80,
        $Seen
    )
    if ($null -eq $Seen) { $Seen = @{} }
    if ($Depth -ge $MaxDepth) {
        $marker = '[SCRUB_JSON_MAX_DEPTH_EXCEEDED]'
        if ($null -ne $Changes) { [void]$Changes.Add([pscustomobject]@{ Field = $KeyName; Original = '(json depth limit)'; Token = $marker }) }
        return $marker
    }
    if ($null -eq $Node) { return $null }
    if ($Node -is [string]) {
        $s = Invoke-JsonStringValueScrub -KeyName $KeyName -Value $Node -Profile $Profile
        if (($null -ne $Changes) -and ($s -ne $Node)) { [void]$Changes.Add([pscustomobject]@{ Field = $KeyName; Original = $Node; Token = $s }) }
        return $s
    }
    if (Test-JsonNumericNode -Node $Node) {
        $numericPrefix = Get-JsonSensitiveNumericPrefix -KeyName $KeyName
        if ($numericPrefix) {
            $rawNumber = [System.Convert]::ToString($Node, [System.Globalization.CultureInfo]::InvariantCulture)
            $token = Get-Token -Value $rawNumber -Prefix $numericPrefix
            if (($null -ne $Changes) -and ($token -ne $rawNumber)) { [void]$Changes.Add([pscustomobject]@{ Field = $KeyName; Original = $rawNumber; Token = $token }) }
            return $token
        }
        return $Node
    }
    if ($Node -is [bool] -or $Node -is [datetime] -or $Node -is [guid]) { return $Node }

    $id = Get-JsonNodeIdentity -Node $Node
    if ($id -and $Seen.ContainsKey($id)) {
        $marker = '[SCRUB_JSON_CYCLIC_REFERENCE]'
        if ($null -ne $Changes) { [void]$Changes.Add([pscustomobject]@{ Field = $KeyName; Original = '(json cycle)'; Token = $marker }) }
        return $marker
    }
    if ($id) { $Seen[$id] = $true }

    try {
        if ($Node -is [System.Collections.IDictionary]) {
            $newMap = [ordered]@{}
            foreach ($k in @($Node.Keys)) {
                $childKey = [string]$k
                $newMap[$childKey] = Invoke-JsonNodeScrub -Node $Node[$k] -Profile $Profile -KeyName $childKey -Changes $Changes -Depth ($Depth + 1) -MaxDepth $MaxDepth -Seen $Seen
            }
            return [pscustomobject]$newMap
        }

        $props = @()
        if ($Node.PSObject) { $props = @($Node.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' }) }
        if ($props.Count -gt 0) {
            $new = [ordered]@{}
            foreach ($p in $props) {
                $new[$p.Name] = Invoke-JsonNodeScrub -Node $p.Value -Profile $Profile -KeyName $p.Name -Changes $Changes -Depth ($Depth + 1) -MaxDepth $MaxDepth -Seen $Seen
            }
            return [pscustomobject]$new
        }

        if (($Node -is [System.Collections.IEnumerable]) -and -not ($Node -is [string])) {
            $arr = New-Object System.Collections.Generic.List[object]
            foreach ($item in $Node) {
                [void]$arr.Add((Invoke-JsonNodeScrub -Node $item -Profile $Profile -KeyName $KeyName -Changes $Changes -Depth ($Depth + 1) -MaxDepth $MaxDepth -Seen $Seen))
            }
            return ,@($arr.ToArray())
        }
        return $Node
    }
    finally {
        if ($id) { [void]$Seen.Remove($id) }
    }
}

function Invoke-ScrubJsonText {
    param(
        [Parameter(Mandatory)][string]$Text,
        [switch]$IsNdjson,
        [Parameter(Mandatory)]$Profile,
        $Changes,
        [int]$MaxDepth = 80
    )
    if ($null -eq $Changes) { $Changes = New-Object System.Collections.Generic.List[object] }
    $jsonDepth = [Math]::Min([Math]::Max($MaxDepth, 2), 100)
    if ($IsNdjson) {
        # One JSON object per line (NDJSON / JSON Lines).
        $sb = New-Object System.Text.StringBuilder
        foreach ($line in ($Text -split '\r?\n')) {
            $trim = $line.Trim().TrimStart([char]0xFEFF)
            if ($trim -eq '') { continue }
            try {
                $obj = $trim | ConvertFrom-Json -ErrorAction Stop
                $scrubbed = Invoke-JsonNodeScrub -Node $obj -Profile $Profile -KeyName '' -Changes $Changes -MaxDepth $MaxDepth -Seen @{}
                $lineOut = $scrubbed | ConvertTo-Json -Depth $jsonDepth -Compress
                $lineOut = Invoke-JsonSerializedKeyValueHardening -Text $lineOut -Profile $Profile -Changes $Changes
                [void]$sb.AppendLine($lineOut)
            }
            catch { [void]$sb.AppendLine((Invoke-LeakHardeningText -Text $line)) }
        }
        return $sb.ToString()
    }
    try {
        $jsonText = ([string]$Text).TrimStart([char]0xFEFF)
        $obj = $jsonText | ConvertFrom-Json -ErrorAction Stop
        $scrubbed = Invoke-JsonNodeScrub -Node $obj -Profile $Profile -KeyName '' -Changes $Changes -MaxDepth $MaxDepth -Seen @{}
        $jsonOut = $scrubbed | ConvertTo-Json -Depth $jsonDepth
        return (Invoke-JsonSerializedKeyValueHardening -Text $jsonOut -Profile $Profile -Changes $Changes)
    }
    catch {
        Write-Warn "Not valid JSON or JSON scrub failed; falling back to whole-text hardening. $($_.Exception.Message)"
        return (Invoke-LeakHardeningText -Text $Text)
    }
}

# =====================================================================
# REGION: Dry-run preview (report-only, writes nothing)
# =====================================================================
function Get-TokenKind {
    param([string]$Token)
    # Long values are whole scrubbed free-text cells (a message with embedded
    # tokens), not a single token -- group them together and skip the regex
    # (which would backtrack badly on a long string).
    if ([string]::IsNullOrEmpty($Token)) { return '(blank)' }
    if ($Token.Length -gt 80) { return '(free-text)' }
    if ($Token -match '^(.*)_[A-F0-9]{4,}$') { return $matches[1] }
    return $Token
}

function Write-DryRunSummary {
    param([Parameter(Mandatory)][string]$Name, $Changes)
    # Wrapped so a summary hiccup can never crash the (read-only) preview.
    try {
        $items = New-Object System.Collections.Generic.List[object]
        if ($Changes) {
            foreach ($change in $Changes) {
                if ($null -ne $change) { [void]$items.Add($change) }
            }
        }
        $list = @($items.ToArray())
        Write-Host ""
        Write-Status -Tag INFO -Message "DRY RUN -- $Name : $($list.Count) distinct value(s) would be tokenized."
        if ($list.Count -eq 0) { return }
        # Count by token kind manually (avoids Group-Object/Sort-Object edge cases).
        $counts = @{}
        foreach ($c in $list) {
            $kind = [string](Get-TokenKind ([string]$c.Token))
            if ($counts.ContainsKey($kind)) { $counts[$kind] = [int]$counts[$kind] + 1 } else { $counts[$kind] = 1 }
        }
        Write-Detail "By token type:"
        foreach ($kind in (@($counts.Keys) | Sort-Object { $counts[$_] } -Descending)) {
            Write-Detail ("  {0,-22} {1}" -f $kind, $counts[$kind])
        }
        $sample = @($list | Select-Object -First 12)
        Write-Detail "Examples (original -> token):"
        foreach ($c in $sample) {
            $orig = [string]$c.Original
            if ($orig.Length -gt 40) { $orig = $orig.Substring(0, 37) + "..." }
            $tok = [string]$c.Token
            if ($tok.Length -gt 60) { $tok = $tok.Substring(0, 57) + "..." }
            Write-Detail ("  {0,-42} -> {1}" -f $orig, $tok)
        }
        if ($list.Count -gt $sample.Count) { Write-Detail ("  ... and {0} more" -f ($list.Count - $sample.Count)) }
        $traceItems = New-Object System.Collections.Generic.List[object]
        if ($script:DetectionTrace) {
            foreach ($trace in $script:DetectionTrace) {
                if ($null -ne $trace) { [void]$traceItems.Add($trace) }
            }
        }
        $highKinds = @('SECRET','APIKEY','CONNSTR','PEM','JWT','AWSKEY','ARN','IP','IP6','SID','GUID','MAC','UNMAPPED_UPN','EMAIL')
        $high = 0; $review = 0
        foreach ($c in $list) {
            $kind = [string](Get-TokenKind ([string]$c.Token))
            if ($highKinds -contains $kind) { $high++ } else { $review++ }
        }
        $preserved = @($traceItems.ToArray() | Where-Object { $_.Action -eq 'Preserved' }).Count
        Write-Detail "Review guide:"
        Write-Detail ("  High confidence tokenizations: {0}" -f $high)
        Write-Detail ("  Review for context/readability: {0}" -f $review)
        Write-Detail ("  Preserved by allowlist/diagnostic rules: {0}" -f $preserved)
        if ($script:ExplainDetections -and $traceItems.Count -gt 0) {
            Write-Detail "Detection decisions:"
            foreach ($d in (@($traceItems.ToArray()) | Select-Object -First 20)) {
                $val = [string]$d.Value
                if ($val.Length -gt 34) { $val = $val.Substring(0, 31) + "..." }
                Write-Detail ("  {0,-12} {1,-10} {2,-14} {3}" -f $d.Action, $d.Detector, $d.Reason, $val)
            }
            if ($traceItems.Count -gt 20) { Write-Detail ("  ... and {0} more detection decisions" -f ($traceItems.Count - 20)) }
        }
        if ($script:DetectionCounts -and $script:DetectionCounts.Count -gt 0) {
            Write-Detail "Detector counts:"
            foreach ($k in ($script:DetectionCounts.Keys | Sort-Object)) {
                Write-Detail ("  {0,-42} {1}" -f $k, $script:DetectionCounts[$k])
            }
        }
    }
    catch {
        Write-Detail "(preview summary detail unavailable: $($_.Exception.Message))"
    }
}

# =====================================================================
# REGION: EVTX -> CSV pre-step (Windows event logs)
#   Reads a saved .evtx with Get-WinEvent and flattens the analytically useful
#   fields (incl. Message, MachineName, UserId SID) to a CSV the scrubber can
#   consume directly. Windows + Windows PowerShell only.
# =====================================================================
function ConvertTo-ScrubCsvField {
    param($Value)
    if ($null -eq $Value) { return '""' }
    $s = [string]$Value
    return '"' + ($s -replace '"', '""') + '"'
}

function Write-ScrubCsvRow {
    param([Parameter(Mandatory)]$Writer, [Parameter(Mandatory)][string[]]$Columns, [Parameter(Mandatory)]$Row)
    $fields = foreach ($c in $Columns) { ConvertTo-ScrubCsvField $Row[$c] }
    $Writer.WriteLine(($fields -join ','))
}

function ConvertTo-SafeEventDataColumn {
    param([string]$Name, [int]$Index)
    $n = if ([string]::IsNullOrWhiteSpace($Name)) { "Data$Index" } else { $Name.Trim() }
    $n = ($n -replace '[^A-Za-z0-9_]', '_').Trim('_')
    if ([string]::IsNullOrWhiteSpace($n)) { $n = "Data$Index" }
    return "EventData_$n"
}

function Get-EvtxEventDataMap {
    param($Event)
    $map = [ordered]@{}
    try {
        [xml]$xml = $Event.ToXml()
        $idx = 0
        foreach ($node in @($xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']"))) {
            $idx++
            $name = $node.GetAttribute("Name")
            $col = ConvertTo-SafeEventDataColumn -Name $name -Index $idx
            if ($map.Contains($col)) { $col = "{0}_{1}" -f $col, $idx }
            $map[$col] = [string]$node.InnerText
        }
        foreach ($node in @($xml.SelectNodes("//*[local-name()='UserData']//*[not(*)]"))) {
            if ([string]::IsNullOrWhiteSpace([string]$node.InnerText)) { continue }
            $idx++
            $col = ConvertTo-SafeEventDataColumn -Name $node.LocalName -Index $idx
            if ($map.Contains($col)) { $col = "{0}_{1}" -f $col, $idx }
            $map[$col] = [string]$node.InnerText
        }
    }
    catch { }
    return $map
}

function ConvertFrom-EvtxToCsv {
    param(
        [Parameter(Mandatory)][string]$EvtxPath,
        [Parameter(Mandatory)][string]$OutCsv,
        [ValidateSet('Fast','CountFirst')][string]$EvtxProgressMode = $script:EvtxProgressMode
    )
    if (-not (Test-Path $EvtxPath)) { throw "EVTX not found: $EvtxPath" }
    if (-not (Get-Command Get-WinEvent -ErrorAction SilentlyContinue)) {
        throw "Get-WinEvent is unavailable. Reading .evtx needs Windows PowerShell on Windows."
    }
    $out = Resolve-OutPath -Path $OutCsv
    $name = [System.IO.Path]::GetFileName($EvtxPath)
    Write-Work "Converting EVTX -> CSV: $name"

    $eventDataColumns = New-Object System.Collections.Generic.List[string]
    $eventDataSeen = @{}
    $total = $null
    if ($EvtxProgressMode -eq 'CountFirst') {
        $total = 0
        foreach ($e in (Get-WinEvent -Path $EvtxPath -ErrorAction Stop)) {
            $total++
            foreach ($k in (Get-EvtxEventDataMap -Event $e).Keys) {
                if (-not $eventDataSeen.ContainsKey($k)) {
                    $eventDataSeen[$k] = $true
                    [void]$eventDataColumns.Add($k)
                }
            }
            if ($total % 500 -eq 0) {
                Write-UlsProgress -Activity "Index EVTX" -Phase ("cols {0}" -f $eventDataColumns.Count) -File $name -RowsDone $total
            }
        }
        Write-UlsProgress -Activity "Index EVTX" -File $name -Completed
    }

    $columns = @('RecordId','TimeCreated','Id','LevelDisplayName','ProviderName','LogName','MachineName','UserId') + @($eventDataColumns) + @('EventDataJson','Message')
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $writer = New-Object System.IO.StreamWriter($out, $false, $encoding)
    $count = 0
    try {
        $writer.WriteLine((($columns | ForEach-Object { ConvertTo-ScrubCsvField $_ }) -join ','))
        foreach ($e in (Get-WinEvent -Path $EvtxPath -ErrorAction Stop)) {
            try {
                $count++
                $tc = ""
                try { if ($e.TimeCreated) { $tc = $e.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ssK") } } catch { }
                $msg = ""
                try { $msg = [string]$e.Message } catch { $msg = "" }
                $data = Get-EvtxEventDataMap -Event $e
                $eventDataJson = ""
                if ($data.Count -gt 0) {
                    try { $eventDataJson = ([pscustomobject]$data | ConvertTo-Json -Compress -Depth 4) } catch { $eventDataJson = "" }
                }
                $row = [ordered]@{
                    RecordId         = [string]$e.RecordId
                    TimeCreated      = $tc
                    Id               = [string]$e.Id
                    LevelDisplayName = [string]$e.LevelDisplayName
                    ProviderName     = [string]$e.ProviderName
                    LogName          = [string]$e.LogName
                    MachineName      = [string]$e.MachineName
                    UserId           = [string]$e.UserId
                }
                foreach ($c in $eventDataColumns) { $row[$c] = if ($data.Contains($c)) { [string]$data[$c] } else { "" } }
                $row['EventDataJson'] = $eventDataJson
                $row['Message'] = ($msg -replace "`r`n", " " -replace "`n", " " -replace "`r", " ")
                Write-ScrubCsvRow -Writer $writer -Columns $columns -Row $row
                if ($count % 100 -eq 0) {
                    $pct = if ($total -and $total -gt 0) { [int](($count / [Math]::Max($total, 1)) * 100) } else { -1 }
                    Write-UlsProgress -Activity "Convert EVTX" -Phase ("RecordId {0}" -f $e.RecordId) -File $name -RowsDone $count -RowsTotal $total
                }
            }
            catch { }
        }
    }
    finally {
        $writer.Close()
        Write-UlsProgress -Activity "Convert EVTX" -File $name -Completed
    }
    if ($count -eq 0) {
        [pscustomobject]@{ Note = 'No events could be read from this log.' } | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8
    }
    Write-Ok "EVTX converted: $out  ($count events)"
    Write-Detail "Note: this .evtx.csv is UNSCRUBBED -- it gets scrubbed next; delete it after."
    return $out
}

# =====================================================================
# REGION: Bring-your-own profile (JSON / PSD1)
# =====================================================================
function ConvertTo-CustomRegexRules {
    param($Rules)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        $name = if ($r.Name) { [string]$r.Name } elseif ($r.Id) { [string]$r.Id } else { 'CustomRegex' }
        $pat = if ($r.Regex) { [string]$r.Regex } elseif ($r.Pattern) { [string]$r.Pattern } else { $null }
        if ([string]::IsNullOrWhiteSpace($pat)) { throw "CustomRegexRules '$name' requires Regex." }
        $prefixRaw = if ($r.Prefix) { [string]$r.Prefix } else { 'SECRET' }
        $prefix = Resolve-ProfileTokenPrefix -Prefix $prefixRaw -Context "CustomRegexRules '$name'"
        $group = 0
        if ($r.CaptureGroup) { $group = [int]$r.CaptureGroup }
        elseif ($r.SecretGroup) { $group = [int]$r.SecretGroup }
        $allowExact = @{}
        if ($r.Allowlist) { foreach ($a in @($r.Allowlist)) { if ($a) { $allowExact[([string]$a).Trim().ToLowerInvariant()] = $true } } }
        if ($r.Stopwords) { foreach ($a in @($r.Stopwords)) { if ($a) { $allowExact[([string]$a).Trim().ToLowerInvariant()] = $true } } }
        $allowRegex = @()
        if ($r.AllowlistRegex) { foreach ($a in @($r.AllowlistRegex)) { if ($a) { $allowRegex += (New-ScrubRegex -Pattern ([string]$a) -Context "custom regex allowlist '$name'") } } }
        [void]$out.Add([pscustomobject]@{
            Name = $name
            Prefix = $prefix
            Regex = $pat
            RegexObject = (New-ScrubRegex -Pattern $pat -Context "custom regex rule '$name'")
            CaptureGroup = $group
            Keywords = if ($r.Keywords) { @($r.Keywords) } else { @() }
            Entropy = if ($r.Entropy) { [double]$r.Entropy } else { $null }
            AllowExact = $allowExact
            AllowRegex = @($allowRegex)
            Description = if ($r.Description) { [string]$r.Description } else { '' }
        })
    }
    return @($out.ToArray())
}

function Initialize-ScrubProfileRuntime {
    param($Profile, [string[]]$AllowlistFiles = @())
    if (-not $Profile) { return }
    $script:CurrentProfile = $Profile
    $extraAllowed = @()
    try { if ($Profile.AllowedDomains) { $extraAllowed = @($Profile.AllowedDomains) } } catch { }
    $script:AllowedDomains = @($script:AllowedDomainsDefault + $extraAllowed)
    $script:RuntimeAllowExact = @{}
    $script:RuntimeAllowRegex = @()
    foreach ($entry in @($Profile.Allowlist)) { Add-AllowlistEntry -Entry $entry -BasePath $Profile.ProfileRoot }
    $profileAllowFiles = @()
    try { if ($Profile.AllowlistFile) { $profileAllowFiles += @($Profile.AllowlistFile) } } catch { }
    try { if ($Profile.AllowlistFiles) { $profileAllowFiles += @($Profile.AllowlistFiles) } } catch { }
    foreach ($file in @($profileAllowFiles + $AllowlistFiles)) {
        if ([string]::IsNullOrWhiteSpace($file)) { continue }
        foreach ($entry in (Read-ScrubListFile -Path $file -BasePath $Profile.ProfileRoot)) { Add-AllowlistEntry -Entry $entry -BasePath $Profile.ProfileRoot }
    }
    $labelRules = New-Object System.Collections.Generic.List[object]
    foreach ($rule in (Get-DefaultUniversalLabelRules)) { [void]$labelRules.Add((ConvertTo-UniversalLabelRule -Rule $rule -Context 'default label rule')) }
    foreach ($rule in @($Profile.LabelRules)) {
        if ($null -eq $rule) { continue }
        [void]$labelRules.Add((ConvertTo-UniversalLabelRule -Rule $rule -Context 'profile LabelRules'))
    }
    foreach ($label in @($script:AdditionalBroadLabels)) {
        if ([string]::IsNullOrWhiteSpace($label)) { continue }
        [void]$labelRules.Add((ConvertTo-UniversalLabelRule -Rule ([pscustomobject]@{ Name="Additional:$label"; Labels=@($label); Prefix='OBJECT' }) -Context 'additional label'))
    }
    $script:RuntimeLabelRules = @($labelRules.ToArray())
    $script:RuntimeCustomRegexRules = if ($Profile.CustomRegexRules) { @(ConvertTo-CustomRegexRules -Rules $Profile.CustomRegexRules) } else { @() }
}

function Import-ScrubProfileFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { throw "Profile file not found: $Path" }
    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    $raw = if ($ext -eq '.psd1') { Import-PowerShellDataFile -Path $Path } else { (Get-Content -Path $Path -Raw) | ConvertFrom-Json }
    if (-not $raw) { throw "Profile file is empty or invalid: $Path" }
    $name = if ($raw.Name) { [string]$raw.Name } else { [System.IO.Path]::GetFileNameWithoutExtension($Path) }
    $validFormats = @('Auto','Csv','Tsv','Psv','Text','Json','Kv')
    $fmt = if ($raw.Format) { [string]$raw.Format } else { 'Auto' }
    if (@($validFormats | Where-Object { $_ -ieq $fmt }).Count -eq 0) { throw "Invalid profile Format '$fmt'. Expected one of: $($validFormats -join ', ')." }
    $cp = @()
    if ($raw.ColumnPrefix) {
        foreach ($r in @($raw.ColumnPrefix)) {
            $pat = [string]$r.Pattern
            $pre = [string]$r.Prefix
            if ([string]::IsNullOrWhiteSpace($pat)) { throw "Invalid profile ColumnPrefix entry: Pattern is required." }
            try { [void][regex]::new($pat) } catch { throw "Invalid profile ColumnPrefix regex '$pat': $($_.Exception.Message)" }
            $pre = Resolve-ProfileTokenPrefix -Prefix $pre -Context 'ColumnPrefix'
            $cp += @{ Pattern = $pat; Prefix = $pre; NotOid = [bool]$r.NotOid; DollarComputer = [bool]$r.DollarComputer }
        }
    }
    if ($raw.PassThroughRegex) { [void](New-ScrubRegex -Pattern ([string]$raw.PassThroughRegex) -Context 'PassThroughRegex') }
    if ($raw.FreeTextRegex) { [void](New-ScrubRegex -Pattern ([string]$raw.FreeTextRegex) -Context 'FreeTextRegex') }
    $schemaColumns = ConvertTo-ProfileColumnRules -Rules $raw.SchemaColumns -DefaultAction 'Scan' -DefaultPrefix 'OBJECT' -Context 'SchemaColumns'
    $wholeColumnRules = ConvertTo-ProfileColumnRules -Rules $raw.WholeColumnRules -DefaultAction 'Scrub' -DefaultPrefix 'OBJECT' -Context 'WholeColumnRules'
    $customRegexRules = ConvertTo-CustomRegexRules -Rules $raw.CustomRegexRules
    $prof = [pscustomobject]@{
        Name             = $name
        Description      = if ($raw.Description) { [string]$raw.Description } else { "Custom profile ($name)" }
        SchemaVersion    = if ($raw.SchemaVersion) { [int]$raw.SchemaVersion } else { 1 }
        Format           = $fmt
        Delimiter        = if ($raw.Delimiter) { [string]$raw.Delimiter } else { ',' }
        PassThroughRegex = if ($raw.PassThroughRegex) { [string]$raw.PassThroughRegex } else { $null }
        ColumnPrefix     = $cp
        FreeTextRegex    = if ($raw.FreeTextRegex) { [string]$raw.FreeTextRegex } else { '.*' }
        DenyByDefault    = if ($null -ne $raw.DenyByDefault) { [bool]$raw.DenyByDefault } else { $true }
        AllowedDomains   = if ($raw.AllowedDomains) { @($raw.AllowedDomains) } else { @() }
        SchemaColumns    = @($schemaColumns)
        WholeColumnRules = @($wholeColumnRules)
        LabelRules       = if ($raw.LabelRules) { @($raw.LabelRules) } else { @() }
        CustomRegexRules = @($customRegexRules)
        Allowlist        = if ($raw.Allowlist) { @($raw.Allowlist) } else { @() }
        AllowlistFile    = if ($raw.AllowlistFile) { @($raw.AllowlistFile) } else { @() }
        AllowlistFiles   = if ($raw.AllowlistFiles) { @($raw.AllowlistFiles) } else { @() }
        SeedTerms        = if ($raw.SeedTerms) { @($raw.SeedTerms) } else { @() }
        SeedFiles        = if ($raw.SeedFiles) { @($raw.SeedFiles) } else { @() }
        ProfileRoot      = Split-Path -Parent (Resolve-Path -LiteralPath $Path).Path
    }
    Write-Ok "Loaded custom profile '$($prof.Name)' from $([System.IO.Path]::GetFileName($Path))"
    return $prof
}

function Get-UlsObjectPropertyArray {
    param($Object, [string]$Name)
    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Name)) { return @() }
    try {
        if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name) -and $null -ne $Object[$Name]) {
            return @($Object[$Name])
        }
    } catch { }
    try {
        $prop = $Object.PSObject.Properties[$Name]
        if ($prop -and $null -ne $prop.Value) { return @($prop.Value) }
    } catch { }
    return @()
}

function Get-UlsObjectPropertyValue {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Name)) { return $Default }
    try {
        if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name) -and $null -ne $Object[$Name]) {
            return $Object[$Name]
        }
    } catch { }
    try {
        $prop = $Object.PSObject.Properties[$Name]
        if ($prop -and $null -ne $prop.Value) { return $prop.Value }
    } catch { }
    return $Default
}

function Resolve-UlsProfileRelativePath {
    param([string]$Path, [string]$BasePath)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    if ([System.IO.Path]::IsPathRooted($Path) -or [string]::IsNullOrWhiteSpace($BasePath)) { return $Path }
    return (Join-Path $BasePath $Path)
}

function ConvertTo-UlsProfilePathList {
    param($Values, [string]$BasePath)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($v in @($Values)) {
        $s = ([string]$v).Trim()
        if ($s) { [void]$out.Add((Resolve-UlsProfileRelativePath -Path $s -BasePath $BasePath)) }
    }
    return @($out.ToArray())
}

function ConvertTo-UlsColumnPrefixRules {
    param($Rules, [string]$Context = 'profile extension ColumnPrefix')
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        $pat = [string](Get-UlsObjectPropertyValue -Object $r -Name 'Pattern')
        $pre = [string](Get-UlsObjectPropertyValue -Object $r -Name 'Prefix')
        if ([string]::IsNullOrWhiteSpace($pat)) { throw "$Context entry requires Pattern." }
        try { [void][regex]::new($pat) } catch { throw "Invalid $Context regex '$pat': $($_.Exception.Message)" }
        $prefix = Resolve-ProfileTokenPrefix -Prefix $pre -Context $Context
        [void]$out.Add(@{
            Pattern = $pat
            Prefix = $prefix
            NotOid = [bool](Get-UlsObjectPropertyValue -Object $r -Name 'NotOid' -Default $false)
            DollarComputer = [bool](Get-UlsObjectPropertyValue -Object $r -Name 'DollarComputer' -Default $false)
        })
    }
    return @($out.ToArray())
}

function Import-ScrubProfileExtensionFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Profile extension file not found: $Path" }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $root = Split-Path -Parent $resolved
    $ext = [System.IO.Path]::GetExtension($resolved).ToLowerInvariant()
    $raw = if ($ext -eq '.psd1') { Import-PowerShellDataFile -Path $resolved } else { (Get-Content -LiteralPath $resolved -Raw) | ConvertFrom-Json }
    if (-not $raw) { throw "Profile extension file is empty or invalid: $Path" }

    $name = [string](Get-UlsObjectPropertyValue -Object $raw -Name 'Name' -Default ([System.IO.Path]::GetFileNameWithoutExtension($resolved)))
    $schemaColumns = ConvertTo-ProfileColumnRules -Rules (Get-UlsObjectPropertyArray -Object $raw -Name 'SchemaColumns') -DefaultAction 'Scan' -DefaultPrefix 'OBJECT' -Context "profile extension '$name' SchemaColumns"
    $wholeColumnRules = ConvertTo-ProfileColumnRules -Rules (Get-UlsObjectPropertyArray -Object $raw -Name 'WholeColumnRules') -DefaultAction 'Scrub' -DefaultPrefix 'OBJECT' -Context "profile extension '$name' WholeColumnRules"
    $customRegexRules = ConvertTo-CustomRegexRules -Rules (Get-UlsObjectPropertyArray -Object $raw -Name 'CustomRegexRules')
    $allowlistFiles = @()
    $allowlistFiles += ConvertTo-UlsProfilePathList -Values (Get-UlsObjectPropertyArray -Object $raw -Name 'AllowlistFile') -BasePath $root
    $allowlistFiles += ConvertTo-UlsProfilePathList -Values (Get-UlsObjectPropertyArray -Object $raw -Name 'AllowlistFiles') -BasePath $root
    $seedFiles = ConvertTo-UlsProfilePathList -Values (Get-UlsObjectPropertyArray -Object $raw -Name 'SeedFiles') -BasePath $root

    return [pscustomobject]@{
        Name             = $name
        Description      = [string](Get-UlsObjectPropertyValue -Object $raw -Name 'Description' -Default '')
        Path             = $resolved
        ProfileRoot      = $root
        ColumnPrefix     = @(ConvertTo-UlsColumnPrefixRules -Rules (Get-UlsObjectPropertyArray -Object $raw -Name 'ColumnPrefix') -Context "profile extension '$name' ColumnPrefix")
        SchemaColumns    = @($schemaColumns)
        WholeColumnRules = @($wholeColumnRules)
        LabelRules       = @(Get-UlsObjectPropertyArray -Object $raw -Name 'LabelRules')
        CustomRegexRules = @($customRegexRules)
        AllowedDomains   = @(Get-UlsObjectPropertyArray -Object $raw -Name 'AllowedDomains')
        Allowlist        = @(Get-UlsObjectPropertyArray -Object $raw -Name 'Allowlist')
        AllowlistFile    = @($allowlistFiles)
        AllowlistFiles   = @()
        SeedTerms        = @(Get-UlsObjectPropertyArray -Object $raw -Name 'SeedTerms')
        SeedFiles        = @($seedFiles)
    }
}

function Merge-ScrubProfileExtension {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Profile,
        [string[]]$Path = @()
    )
    $paths = @($Path | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($paths.Count -eq 0) { return $Profile }

    $merged = $Profile
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($p in $paths) {
        $extension = Import-ScrubProfileExtensionFile -Path $p
        [void]$names.Add($extension.Name)
        $description = [string](Get-UlsObjectPropertyValue -Object $merged -Name 'Description' -Default '')
        if ($description -notmatch [regex]::Escape($extension.Name)) { $description = ($description + " + extension $($extension.Name)").Trim() }
        $merged = [pscustomobject]@{
            Name             = [string](Get-UlsObjectPropertyValue -Object $merged -Name 'Name' -Default 'ExtendedProfile')
            Description      = $description
            SchemaVersion    = [int](Get-UlsObjectPropertyValue -Object $merged -Name 'SchemaVersion' -Default 2)
            Format           = [string](Get-UlsObjectPropertyValue -Object $merged -Name 'Format' -Default 'Auto')
            Delimiter        = [string](Get-UlsObjectPropertyValue -Object $merged -Name 'Delimiter' -Default ',')
            PassThroughRegex = Get-UlsObjectPropertyValue -Object $merged -Name 'PassThroughRegex' -Default $null
            ColumnPrefix     = @($extension.ColumnPrefix + (Get-UlsObjectPropertyArray -Object $merged -Name 'ColumnPrefix'))
            FreeTextRegex    = [string](Get-UlsObjectPropertyValue -Object $merged -Name 'FreeTextRegex' -Default '.*')
            DenyByDefault    = [bool](Get-UlsObjectPropertyValue -Object $merged -Name 'DenyByDefault' -Default $true)
            AllowedDomains   = @((Get-UlsObjectPropertyArray -Object $merged -Name 'AllowedDomains') + $extension.AllowedDomains)
            SchemaColumns    = @($extension.SchemaColumns + (Get-UlsObjectPropertyArray -Object $merged -Name 'SchemaColumns'))
            WholeColumnRules = @($extension.WholeColumnRules + (Get-UlsObjectPropertyArray -Object $merged -Name 'WholeColumnRules'))
            LabelRules       = @((Get-UlsObjectPropertyArray -Object $merged -Name 'LabelRules') + $extension.LabelRules)
            CustomRegexRules = @((Get-UlsObjectPropertyArray -Object $merged -Name 'CustomRegexRules') + $extension.CustomRegexRules)
            Allowlist        = @((Get-UlsObjectPropertyArray -Object $merged -Name 'Allowlist') + $extension.Allowlist)
            AllowlistFile    = @((Get-UlsObjectPropertyArray -Object $merged -Name 'AllowlistFile') + $extension.AllowlistFile)
            AllowlistFiles   = @((Get-UlsObjectPropertyArray -Object $merged -Name 'AllowlistFiles') + $extension.AllowlistFiles)
            SeedTerms        = @((Get-UlsObjectPropertyArray -Object $merged -Name 'SeedTerms') + $extension.SeedTerms)
            SeedFiles        = @((Get-UlsObjectPropertyArray -Object $merged -Name 'SeedFiles') + $extension.SeedFiles)
            ProfileRoot      = Get-UlsObjectPropertyValue -Object $merged -Name 'ProfileRoot' -Default $null
            ProfileExtensions = @((Get-UlsObjectPropertyArray -Object $merged -Name 'ProfileExtensions') + $extension.Path)
        }
    }
    Write-Ok ("Applied profile extension(s): {0}" -f (($names.ToArray()) -join ', '))
    return $merged
}

function New-ScrubProfileTemplate {
    param(
        [Parameter(Mandatory)][ValidateSet('Generic','Csv','Json','Kv','WebAccess','Cloud','App')][string]$Template,
        [Parameter(Mandatory)][string]$OutputPath
    )
    $format = switch ($Template) {
        'Csv' { 'Csv' }
        'Json' { 'Json' }
        'Kv' { 'Kv' }
        'Cloud' { 'Json' }
        'App' { 'Json' }
        default { 'Auto' }
    }
    $body = @"
{
  "SchemaVersion": 2,
  "Name": "$Template-Custom",
  "Description": "Custom $Template profile for Universal Log Scrubber.",
  "Format": "$format",
  "Delimiter": ",",
  "DenyByDefault": true,
  "AllowedDomains": [
    "example.com"
  ],
  "SchemaColumns": [
    { "Exact": "timestamp", "Action": "PassThrough", "Description": "Analytical timestamp" },
    { "Wildcard": "*message*", "Action": "Scan", "Description": "Free-text message field" }
  ],
  "WholeColumnRules": [
    { "Regex": "(?i)^(user(id|name)?|account|principal)$", "Prefix": "PRINCIPAL", "SplitOn": "[;,|]" },
    { "Regex": "(?i)^(host|server|machine|device)$", "Prefix": "DNS", "SplitOn": "[;,|]" },
    { "Regex": "(?i)^(ip|clientip|src_ip|dst_ip|address)$", "Prefix": "IP", "SplitOn": "[;,|]" },
    { "Regex": "(?i)(api[_ -]?key|token|secret|password)", "Prefix": "SECRET" }
  ],
  "LabelRules": [
    { "Name": "LocalApiKey", "Labels": [ "API Key", "api_key", "client_secret" ], "Prefix": "SECRET" },
    { "Name": "LocalHostLabels", "Labels": [ "host", "server", "node" ], "Prefix": "DNS" }
  ],
  "CustomRegexRules": [
    {
      "Name": "CompanyProjectId",
      "Regex": "(?i)\\b(project[_ -]?id\\s*[:=]\\s*)(PROJ-[0-9]{4}-[A-Z]{3})\\b",
      "CaptureGroup": 2,
      "Prefix": "OBJECT",
      "Keywords": [ "project", "PROJ-" ],
      "Entropy": 0
    }
  ],
  "SeedFiles": [ "seeds.txt" ],
  "AllowlistFile": [ "allowlist.txt" ]
}
"@
    $out = Resolve-OutPath -Path $OutputPath
    $dir = Split-Path -Parent $out
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    [System.IO.File]::WriteAllText($out, $body, [System.Text.Encoding]::UTF8)
    Write-Ok "Profile template written: $out"
    return $out
}

# =====================================================================
# REGION: Profile validation, sample analysis, and safe upload bundles
# =====================================================================
function Test-ScrubProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Quiet
    )
    try {
        $prof = Import-ScrubProfileFile -Path $Path
        Initialize-ScrubProfileRuntime -Profile $prof
        if (-not $Quiet) { Write-Ok "Profile is valid: $Path" }
        return $true
    }
    catch {
        if ($Quiet) { return $false }
        Write-Fail "Profile validation failed: $($_.Exception.Message)"
        throw
    }
}

function Get-ProfileBuilderPrefixForName {
    param([string]$Name)
    $n = ([string]$Name).ToLowerInvariant()
    if ($n -match '(api[_ -]?key|secret|password|passwd|pwd|token|credential|authorization|auth|private[_ -]?key|client[_ -]?secret)') { return 'SECRET' }
    if ($n -match '(user|username|user_id|userid|account|principal|actor|caller|subject|identity|login|suser|duser|cs-username)') { return 'PRINCIPAL' }
    if ($n -match '(src_ip|dst_ip|clientip|client_ip|remote_addr|ipaddress|ip_address|source.*address|destination.*address|\bc-ip\b|\bs-ip\b|\bip\b|x-forwarded-for)') { return 'IP' }
    if ($n -match '(host|hostname|server|machine|device|node|pod|container|workstation|computer|dhost|shost|cs-host|upstream_host)') { return 'DNS' }
    if ($n -match '(tenant|tenantid|tenant_id|org|organization|domain|realm|subscription|accountid|account_id|project)') { return 'X500' }
    if ($n -match '(url|uri|endpoint|referer|referrer|callback|redirect)') { return 'URI' }
    if ($n -match '(session|requestid|request_id|correlation|trace|span|transaction|ticket|case|incident)') { return 'OBJECT' }
    return $null
}

function Get-ProfileBuilderSchemaAction {
    param([string]$Name)
    $n = ([string]$Name).ToLowerInvariant()
    if ($n -match '^(date|time|timestamp|eventtime|created|updated|level|severity|status|result|method|action|operation|category|count|bytes|duration|elapsed|latency|version|protocol|port|http_method|http_status|sc-status|sc-bytes|cs-bytes|time-taken)$') { return 'PassThrough' }
    if ($n -match '(message|msg|detail|details|description|error|exception|stack|payload|raw|body|query|command|line|text)') { return 'Scan' }
    return $null
}

function Get-ProfileBuilderFormat {
    param([string]$Path, [ValidateSet('Auto','Csv','Json','Kv','Text')][string]$Requested = 'Auto')
    if ($Requested -ne 'Auto') { return $Requested }
    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($ext -in @('.csv','.tsv','.psv')) { return 'Csv' }
    if ($ext -in @('.json','.jsonl','.ndjson')) { return 'Json' }
    $first = ''
    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) { $first = $line.Trim(); break }
    }
    if ($first -match '^[\{\[]') { return 'Json' }
    if (($first | Select-String -Pattern '\b[A-Za-z][A-Za-z0-9_.-]{1,40}=' -AllMatches).Matches.Count -ge 2) { return 'Kv' }
    return 'Text'
}

function Get-ProfileBuilderDelimiter {
    param([string]$Path)
    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($ext -eq '.tsv') { return "`t" }
    if ($ext -eq '.psv') { return '|' }
    $header = ''
    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) { $header = $line; break }
    }
    $commas = ($header.ToCharArray() | Where-Object { $_ -eq ',' }).Count
    $tabs = ($header.ToCharArray() | Where-Object { $_ -eq "`t" }).Count
    $pipes = ($header.ToCharArray() | Where-Object { $_ -eq '|' }).Count
    if ($tabs -gt $commas -and $tabs -ge $pipes) { return "`t" }
    if ($pipes -gt $commas -and $pipes -gt $tabs) { return '|' }
    return ','
}

function New-ProfileBuilderStats {
    return @{
        Columns = @{}
        Labels = @{}
        Shapes = @{}
        SeedCandidates = @{}
        AllowCandidates = @{}
        Lines = 0
        Rows = 0
    }
}

function Add-ProfileBuilderExample {
    param($Bucket, [string]$Value, [int]$Limit = 5)
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $v = $Value.Trim()
    if ($Bucket.Examples.Count -lt $Limit -and -not $Bucket.Examples.Contains($v)) { [void]$Bucket.Examples.Add($v) }
}

function Add-ProfileBuilderColumnValue {
    param($Stats, [string]$Name, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Name)) { return }
    $key = $Name.Trim().ToLowerInvariant()
    if (-not $Stats.Columns.ContainsKey($key)) {
        $Stats.Columns[$key] = [pscustomobject]@{
            Name = $Name.Trim()
            Count = 0
            NonBlank = 0
            Examples = (New-Object System.Collections.Generic.List[string])
        }
    }
    $c = $Stats.Columns[$key]
    $c.Count = [int]$c.Count + 1
    if (-not [string]::IsNullOrWhiteSpace($Value)) {
        $c.NonBlank = [int]$c.NonBlank + 1
        Add-ProfileBuilderExample -Bucket $c -Value $Value
    }
}

function Add-ProfileBuilderAllowCandidate {
    param($Stats, [string]$Value, [string]$Reason)
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $v = $Value.Trim().Trim('"', "'")
    if ($v.Length -lt 2 -or $v.Length -gt 120) { return }
    $isAllow = $false
    if ($v -match '^(127\.0\.0\.1|::1|0\.0\.0\.0|localhost)$') { $isAllow = $true }
    elseif ($v -match '^00000000-0000-0000-0000-000000000000$') { $isAllow = $true }
    elseif ($v -match '^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)$') { $isAllow = $true }
    elseif ($v -match '^(health|ready|live|ok|true|false|null|none|success|failed|warning|info|error)$') { $isAllow = $true }
    elseif (Test-AllowedDomain -Value $v) { $isAllow = $true }
    if (-not $isAllow) { return }
    $k = $v.ToLowerInvariant()
    if (-not $Stats.AllowCandidates.ContainsKey($k)) {
        $Stats.AllowCandidates[$k] = [pscustomobject]@{ Value=$v; Reason=$Reason }
    }
}

function Add-ProfileBuilderSeedCandidate {
    param($Stats, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':')
    if ($v.Length -lt 5 -or $v.Length -gt 60) { return }
    if ($v -match '^\d+$|^(true|false|null|none|error|warning|info|debug|trace|status|message|request|response|success|failed)$') { return }
    if ($v -match '@|\\|/|:|=') { return }
    if ($v -match '^\d{4}-\d{2}-\d{2}') { return }
    if ($v -match '^(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$') { return }
    if ($v -notmatch '[A-Za-z]') { return }
    $k = $v.ToLowerInvariant()
    if (-not $Stats.SeedCandidates.ContainsKey($k)) {
        $Stats.SeedCandidates[$k] = [pscustomobject]@{ Value=$v; Count=0 }
    }
    $Stats.SeedCandidates[$k].Count = [int]$Stats.SeedCandidates[$k].Count + 1
}

function Get-ProfileBuilderShapeRegex {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim().Trim('"', "'")
    if ($v.Length -lt 8 -or $v.Length -gt 80) { return $null }
    if ($v -notmatch '[A-Za-z]' -or $v -notmatch '\d') { return $null }
    if ($v -match '@|\\|/|://') { return $null }
    if ($v -match '^\d{1,3}(\.\d{1,3}){3}$') { return $null }
    if ($v -match '^(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$') { return $null }
    $parts = New-Object System.Collections.Generic.List[string]
    $i = 0
    while ($i -lt $v.Length) {
        $ch = $v[$i]
        $start = $i
        if ($ch -match '[A-Z]') { while ($i -lt $v.Length -and ([string]$v[$i]) -match '[A-Z]') { $i++ }; $n = $i - $start; [void]$parts.Add(("[A-Z]{{{0}}}" -f $n)); continue }
        if ($ch -match '[a-z]') { while ($i -lt $v.Length -and ([string]$v[$i]) -match '[a-z]') { $i++ }; $n = $i - $start; [void]$parts.Add(("[a-z]{{{0}}}" -f $n)); continue }
        if ($ch -match '[0-9]') { while ($i -lt $v.Length -and ([string]$v[$i]) -match '[0-9]') { $i++ }; $n = $i - $start; [void]$parts.Add(("[0-9]{{{0}}}" -f $n)); continue }
        if ($ch -match '[-_.]') { [void]$parts.Add([regex]::Escape([string]$ch)); $i++; continue }
        return $null
    }
    return ($parts -join '')
}

function Add-ProfileBuilderTextFacts {
    param($Stats, [string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return }
    foreach ($m in [regex]::Matches($Text, '(?im)(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_. -]{1,40})\s*[:=]\s*("[^"\r\n]{1,160}"|''[^''\r\n]{1,160}''|[^,\s;|]{1,160})')) {
        $label = $m.Groups[1].Value.Trim()
        $value = $m.Groups[2].Value.Trim().Trim('"', "'")
        if ($label -match '^\d+$' -or $label.Length -lt 2) { continue }
        $prefix = Get-UniversalLabeledValuePrefix -Label $label -Value $value -DefaultPrefix (Get-ProfileBuilderPrefixForName -Name $label)
        if (-not $prefix) { $prefix = 'OBJECT' }
        $key = ($prefix + '|' + $label.ToLowerInvariant())
        if (-not $Stats.Labels.ContainsKey($key)) {
            $Stats.Labels[$key] = [pscustomobject]@{ Label=$label; Prefix=$prefix; Count=0; Examples=(New-Object System.Collections.Generic.List[string]) }
        }
        $Stats.Labels[$key].Count = [int]$Stats.Labels[$key].Count + 1
        Add-ProfileBuilderExample -Bucket $Stats.Labels[$key] -Value $value
        Add-ProfileBuilderAllowCandidate -Stats $Stats -Value $value -Reason "Observed after label '$label'"
        Add-ProfileBuilderSeedCandidate -Stats $Stats -Value $value
        $shape = Get-ProfileBuilderShapeRegex -Value $value
        if ($shape) {
            if (-not $Stats.Shapes.ContainsKey($shape)) {
                $Stats.Shapes[$shape] = [pscustomobject]@{ Regex=$shape; Count=0; Prefix='OBJECT'; Examples=(New-Object System.Collections.Generic.List[string]) }
            }
            $Stats.Shapes[$shape].Count = [int]$Stats.Shapes[$shape].Count + 1
            Add-ProfileBuilderExample -Bucket $Stats.Shapes[$shape] -Value $value
        }
    }
    foreach ($m in [regex]::Matches($Text, '\b[A-Za-z][A-Za-z0-9_.-]{4,80}\b')) {
        $v = $m.Value
        Add-ProfileBuilderAllowCandidate -Stats $Stats -Value $v -Reason 'Public diagnostic candidate'
        Add-ProfileBuilderSeedCandidate -Stats $Stats -Value $v
        $shape = Get-ProfileBuilderShapeRegex -Value $v
        if ($shape) {
            if (-not $Stats.Shapes.ContainsKey($shape)) {
                $Stats.Shapes[$shape] = [pscustomobject]@{ Regex=$shape; Count=0; Prefix='OBJECT'; Examples=(New-Object System.Collections.Generic.List[string]) }
            }
            $Stats.Shapes[$shape].Count = [int]$Stats.Shapes[$shape].Count + 1
            Add-ProfileBuilderExample -Bucket $Stats.Shapes[$shape] -Value $v
        }
    }
}

function Add-JsonSamplePairs {
    param($Stats, $Node, [string]$KeyName = '')
    if ($null -eq $Node) { return }
    if ($Node -is [string]) {
        Add-ProfileBuilderColumnValue -Stats $Stats -Name $KeyName -Value $Node
        Add-ProfileBuilderTextFacts -Stats $Stats -Text $Node
        return
    }
    if ($Node -is [bool] -or
        $Node -is [int] -or
        $Node -is [long] -or
        $Node -is [double] -or
        $Node -is [decimal] -or
        $Node -is [datetime] -or
        $Node -is [guid]) {
        if ($KeyName) { Add-ProfileBuilderColumnValue -Stats $Stats -Name $KeyName -Value ([string]$Node) }
        return
    }
    if (($Node -is [System.Collections.IEnumerable]) -and -not ($Node -is [string])) {
        foreach ($item in $Node) { Add-JsonSamplePairs -Stats $Stats -Node $item -KeyName $KeyName }
        return
    }
    if ($Node.PSObject -and @($Node.PSObject.Properties).Count -gt 0) {
        foreach ($p in $Node.PSObject.Properties) { Add-JsonSamplePairs -Stats $Stats -Node $p.Value -KeyName $p.Name }
    }
}

function Invoke-SampleProfileAnalysis {
    param(
        [Parameter(Mandatory)][string[]]$Files,
        [ValidateSet('Auto','Csv','Json','Kv','Text')][string]$SampleFormat = 'Auto',
        [int]$MaxSampleRows = 500
    )
    $stats = New-ProfileBuilderStats
    $format = $null
    $delimiter = ','
    foreach ($file in $Files) {
        $fmt = Get-ProfileBuilderFormat -Path $file -Requested $SampleFormat
        if (-not $format) { $format = $fmt }
        if ($fmt -eq 'Csv') {
            $delimiter = Get-ProfileBuilderDelimiter -Path $file
            $rn = 0
            Import-Csv -Path $file -Delimiter $delimiter | ForEach-Object {
                if ($stats.Rows -ge $MaxSampleRows) { return }
                $stats.Rows = [int]$stats.Rows + 1
                $rn++
                foreach ($prop in $_.PSObject.Properties) {
                    $val = [string]$prop.Value
                    Add-ProfileBuilderColumnValue -Stats $stats -Name $prop.Name -Value $val
                    Add-ProfileBuilderTextFacts -Stats $stats -Text $val
                }
            }
        }
        elseif ($fmt -eq 'Json') {
            $ext = [System.IO.Path]::GetExtension($file).ToLowerInvariant()
            if ($ext -in @('.jsonl','.ndjson')) {
                foreach ($line in [System.IO.File]::ReadLines($file)) {
                    if ($stats.Rows -ge $MaxSampleRows) { break }
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    try {
                        $obj = $line | ConvertFrom-Json -ErrorAction Stop
                        $stats.Rows = [int]$stats.Rows + 1
                        Add-JsonSamplePairs -Stats $stats -Node $obj
                    } catch { Add-ProfileBuilderTextFacts -Stats $stats -Text $line }
                }
            }
            else {
                $raw = [System.IO.File]::ReadAllText($file)
                try {
                    $obj = $raw | ConvertFrom-Json -ErrorAction Stop
                    $stats.Rows = [Math]::Max(1, [int]$stats.Rows)
                    Add-JsonSamplePairs -Stats $stats -Node $obj
                } catch { Add-ProfileBuilderTextFacts -Stats $stats -Text $raw }
            }
        }
        else {
            foreach ($line in [System.IO.File]::ReadLines($file)) {
                if ($stats.Rows -ge $MaxSampleRows) { break }
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                $stats.Rows = [int]$stats.Rows + 1
                $stats.Lines = [int]$stats.Lines + 1
                Add-ProfileBuilderTextFacts -Stats $stats -Text $line
                if ($fmt -eq 'Kv') {
                    foreach ($m in [regex]::Matches($line, '(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_.-]{1,40})=("[^"\r\n]{0,200}"|[^,\s;|]{0,200})')) {
                        Add-ProfileBuilderColumnValue -Stats $stats -Name $m.Groups[1].Value -Value $m.Groups[2].Value.Trim().Trim('"')
                    }
                }
            }
        }
    }
    if (-not $format) { $format = 'Text' }
    return [pscustomobject]@{ Format=$format; Delimiter=$delimiter; Stats=$stats; Files=$Files; MaxSampleRows=$MaxSampleRows }
}

function ConvertTo-GeneratedProfile {
    param($Analysis, [string]$Name, [switch]$IncludeSeeds, [switch]$IncludeAllowlist, [switch]$IncludeCustomRegex = $true)
    $schema = New-Object System.Collections.Generic.List[object]
    $whole = New-Object System.Collections.Generic.List[object]
    foreach ($c in (@($Analysis.Stats.Columns.Values) | Sort-Object Name)) {
        $action = Get-ProfileBuilderSchemaAction -Name $c.Name
        $prefix = Get-ProfileBuilderPrefixForName -Name $c.Name
        if ($action) {
            [void]$schema.Add([ordered]@{ Exact=$c.Name; Action=$action; Description='Generated from sample schema.' })
        }
        if ($prefix) {
            [void]$whole.Add([ordered]@{ Exact=$c.Name; Prefix=$prefix; SplitOn='[;,|]'; Description='Generated from sample schema.' })
        }
    }
    foreach ($default in @(
        @{ Wildcard='*message*'; Action='Scan'; Description='Message-like free text.' },
        @{ Wildcard='*detail*'; Action='Scan'; Description='Detail-like free text.' },
        @{ Wildcard='*description*'; Action='Scan'; Description='Description-like free text.' }
    )) {
        if (@($schema | Where-Object { $_.Wildcard -eq $default.Wildcard }).Count -eq 0) {
            [void]$schema.Add([ordered]@{ Wildcard=$default.Wildcard; Action=$default.Action; Description=$default.Description })
        }
    }

    $labelsByPrefix = @{}
    foreach ($l in @($Analysis.Stats.Labels.Values)) {
        if ($l.Count -lt 1) { continue }
        if (-not $labelsByPrefix.ContainsKey($l.Prefix)) { $labelsByPrefix[$l.Prefix] = New-Object System.Collections.Generic.List[string] }
        if (-not $labelsByPrefix[$l.Prefix].Contains($l.Label)) { [void]$labelsByPrefix[$l.Prefix].Add($l.Label) }
    }
    $labelRules = New-Object System.Collections.Generic.List[object]
    foreach ($prefix in (@($labelsByPrefix.Keys) | Sort-Object)) {
        $labels = @($labelsByPrefix[$prefix].ToArray() | Sort-Object | Select-Object -First 24)
        if ($labels.Count -gt 0) {
            [void]$labelRules.Add([ordered]@{ Name=("Generated{0}Labels" -f $prefix); Labels=$labels; Prefix=$prefix })
        }
    }

    $custom = New-Object System.Collections.Generic.List[object]
    if ($IncludeCustomRegex) {
        $i = 0
        foreach ($shape in (@($Analysis.Stats.Shapes.Values) | Where-Object { $_.Count -ge 2 } | Sort-Object Count -Descending | Select-Object -First 8)) {
            $i++
            [void]$custom.Add([ordered]@{
                Name = ("GeneratedShape{0}" -f $i)
                Regex = ("\b({0})\b" -f $shape.Regex)
                CaptureGroup = 1
                Prefix = $shape.Prefix
                Keywords = @()
                Entropy = 0
                Description = 'Generated from repeated sample value shape; review before production.'
            })
        }
    }

    $profile = [ordered]@{
        SchemaVersion = 2
        Name = $Name
        Description = 'Generated from a local sample. Review before production use.'
        Format = $Analysis.Format
        Delimiter = $Analysis.Delimiter
        DenyByDefault = $true
        SchemaColumns = @($schema.ToArray())
        WholeColumnRules = @($whole.ToArray())
        LabelRules = @($labelRules.ToArray())
        CustomRegexRules = @($custom.ToArray())
    }
    if ($IncludeSeeds) { $profile.SeedFiles = @('generated-seeds.txt') }
    if ($IncludeAllowlist) { $profile.AllowlistFile = @('generated-allowlist.txt') }
    return $profile
}

function ConvertTo-UlsSerializableColumnPrefixRules {
    param($Rules)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        $pat = [string](Get-UlsObjectPropertyValue -Object $r -Name 'Pattern')
        $pre = [string](Get-UlsObjectPropertyValue -Object $r -Name 'Prefix')
        if ([string]::IsNullOrWhiteSpace($pat) -or [string]::IsNullOrWhiteSpace($pre)) { continue }
        $entry = [ordered]@{ Pattern=$pat; Prefix=$pre }
        if ([bool](Get-UlsObjectPropertyValue -Object $r -Name 'NotOid' -Default $false)) { $entry.NotOid = $true }
        if ([bool](Get-UlsObjectPropertyValue -Object $r -Name 'DollarComputer' -Default $false)) { $entry.DollarComputer = $true }
        [void]$out.Add($entry)
    }
    return @($out.ToArray())
}

function ConvertTo-UlsSerializableCustomRegexRules {
    param($Rules)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        $rx = [string](Get-UlsObjectPropertyValue -Object $r -Name 'Regex')
        if ([string]::IsNullOrWhiteSpace($rx)) { continue }
        $entry = [ordered]@{
            Name = [string](Get-UlsObjectPropertyValue -Object $r -Name 'Name' -Default 'CustomRegex')
            Regex = $rx
            CaptureGroup = [int](Get-UlsObjectPropertyValue -Object $r -Name 'CaptureGroup' -Default 0)
            Prefix = [string](Get-UlsObjectPropertyValue -Object $r -Name 'Prefix' -Default 'OBJECT')
            Keywords = @(Get-UlsObjectPropertyArray -Object $r -Name 'Keywords')
            Entropy = Get-UlsObjectPropertyValue -Object $r -Name 'Entropy' -Default 0
        }
        $desc = [string](Get-UlsObjectPropertyValue -Object $r -Name 'Description' -Default '')
        if (-not [string]::IsNullOrWhiteSpace($desc)) { $entry.Description = $desc }
        [void]$out.Add($entry)
    }
    return @($out.ToArray())
}

function Import-UlsRawProfileLikeFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Profile extension file not found: $Path" }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $ext = [System.IO.Path]::GetExtension($resolved).ToLowerInvariant()
    if ($ext -eq '.psd1') { return Import-PowerShellDataFile -Path $resolved }
    return ((Get-Content -LiteralPath $resolved -Raw) | ConvertFrom-Json)
}

function Merge-UlsGeneratedProfileWithBase {
    param(
        [Parameter(Mandatory)]$GeneratedProfile,
        [string]$BaseProfile,
        [string[]]$ProfileExtensionFile = @()
    )

    $merged = $GeneratedProfile
    if (-not [string]::IsNullOrWhiteSpace($BaseProfile)) {
        $base = Get-ScrubProfile -Name $BaseProfile
        if (-not $base) { throw "Unknown base profile for sample profile builder: $BaseProfile" }
        $merged = [ordered]@{
            SchemaVersion = 2
            Name = [string](Get-UlsObjectPropertyValue -Object $GeneratedProfile -Name 'Name' -Default 'GeneratedSampleProfile')
            Description = "Generated from a local sample and based on built-in profile '$($base.Name)'. Review before production use."
            BaseProfile = $base.Name
            Format = [string](Get-UlsObjectPropertyValue -Object $base -Name 'Format' -Default (Get-UlsObjectPropertyValue -Object $GeneratedProfile -Name 'Format' -Default 'Auto'))
            Delimiter = [string](Get-UlsObjectPropertyValue -Object $base -Name 'Delimiter' -Default (Get-UlsObjectPropertyValue -Object $GeneratedProfile -Name 'Delimiter' -Default ','))
            DenyByDefault = [bool](Get-UlsObjectPropertyValue -Object $base -Name 'DenyByDefault' -Default $true)
        }
        $pass = Get-UlsObjectPropertyValue -Object $base -Name 'PassThroughRegex' -Default $null
        if ($pass) { $merged.PassThroughRegex = [string]$pass }
        $free = Get-UlsObjectPropertyValue -Object $base -Name 'FreeTextRegex' -Default $null
        if ($free) { $merged.FreeTextRegex = [string]$free }
        $allowed = @(Get-UlsObjectPropertyArray -Object $base -Name 'AllowedDomains')
        if ($allowed.Count -gt 0) { $merged.AllowedDomains = @($allowed) }
        $baseColumns = @(ConvertTo-UlsSerializableColumnPrefixRules -Rules (Get-UlsObjectPropertyArray -Object $base -Name 'ColumnPrefix'))
        if ($baseColumns.Count -gt 0) { $merged.ColumnPrefix = @($baseColumns) }
        $merged.SchemaColumns = @(Get-UlsObjectPropertyArray -Object $GeneratedProfile -Name 'SchemaColumns')
        $merged.WholeColumnRules = @(Get-UlsObjectPropertyArray -Object $GeneratedProfile -Name 'WholeColumnRules')
        $merged.LabelRules = @((Get-UlsObjectPropertyArray -Object $base -Name 'LabelRules') + (Get-UlsObjectPropertyArray -Object $GeneratedProfile -Name 'LabelRules'))
        $merged.CustomRegexRules = @((ConvertTo-UlsSerializableCustomRegexRules -Rules (Get-UlsObjectPropertyArray -Object $base -Name 'CustomRegexRules')) + (Get-UlsObjectPropertyArray -Object $GeneratedProfile -Name 'CustomRegexRules'))
        foreach ($propName in @('SeedFiles','AllowlistFile')) {
            $vals = @(Get-UlsObjectPropertyArray -Object $GeneratedProfile -Name $propName)
            if ($vals.Count -gt 0) { $merged[$propName] = @($vals) }
        }
    }

    foreach ($extensionPath in @($ProfileExtensionFile)) {
        if ([string]::IsNullOrWhiteSpace([string]$extensionPath)) { continue }
        $raw = Import-UlsRawProfileLikeFile -Path $extensionPath
        if (-not $raw) { continue }
        $extensionName = [string](Get-UlsObjectPropertyValue -Object $raw -Name 'Name' -Default ([System.IO.Path]::GetFileNameWithoutExtension($extensionPath)))
        $existingExtensions = @(Get-UlsObjectPropertyArray -Object $merged -Name 'ProfileExtensions')
        $merged.ProfileExtensions = @($existingExtensions + $extensionName)
        foreach ($propName in @('SchemaColumns','WholeColumnRules','ColumnPrefix')) {
            $vals = @(Get-UlsObjectPropertyArray -Object $raw -Name $propName)
            if ($vals.Count -gt 0) {
                $existing = @(Get-UlsObjectPropertyArray -Object $merged -Name $propName)
                $merged[$propName] = @($vals + $existing)
            }
        }
        foreach ($propName in @('LabelRules','CustomRegexRules','AllowedDomains','Allowlist','AllowlistFile','AllowlistFiles','SeedTerms','SeedFiles')) {
            $vals = @(Get-UlsObjectPropertyArray -Object $raw -Name $propName)
            if ($vals.Count -gt 0) {
                $existing = @(Get-UlsObjectPropertyArray -Object $merged -Name $propName)
                $merged[$propName] = @($existing + $vals)
            }
        }
    }

    return $merged
}

function Write-ProfileBuilderReport {
    param($Analysis, [string]$Path, [string]$ProfilePath)
    $lines = New-Object System.Collections.Generic.List[string]
    [void]$lines.Add('# Profile Build Report - DO_NOT_UPLOAD')
    [void]$lines.Add('')
    [void]$lines.Add('This report may contain raw sample values. Keep it local.')
    [void]$lines.Add('')
    [void]$lines.Add(('Generated profile: {0}' -f $ProfilePath))
    [void]$lines.Add(('Detected format: {0}' -f $Analysis.Format))
    [void]$lines.Add(("Rows/lines inspected: {0}" -f $Analysis.Stats.Rows))
    [void]$lines.Add('')
    [void]$lines.Add('## Files')
    foreach ($f in $Analysis.Files) { [void]$lines.Add(("- {0}" -f $f)) }
    [void]$lines.Add('')
    [void]$lines.Add('## Column/Key Suggestions')
    foreach ($c in (@($Analysis.Stats.Columns.Values) | Sort-Object Name)) {
        $prefix = Get-ProfileBuilderPrefixForName -Name $c.Name
        $action = Get-ProfileBuilderSchemaAction -Name $c.Name
        $examples = (@($c.Examples.ToArray()) | Select-Object -First 3) -join ', '
        [void]$lines.Add(("- {0}: prefix={1} action={2} examples={3}" -f $c.Name, $prefix, $action, $examples))
    }
    [void]$lines.Add('')
    [void]$lines.Add('## Label Suggestions')
    foreach ($l in (@($Analysis.Stats.Labels.Values) | Sort-Object Prefix,Label)) {
        $examples = (@($l.Examples.ToArray()) | Select-Object -First 3) -join ', '
        [void]$lines.Add(("- {0} -> {1} ({2} hit(s)); examples={3}" -f $l.Label, $l.Prefix, $l.Count, $examples))
    }
    [void]$lines.Add('')
    [void]$lines.Add('## Repeated Shape Suggestions')
    foreach ($s in (@($Analysis.Stats.Shapes.Values) | Sort-Object Count -Descending | Select-Object -First 20)) {
        $examples = (@($s.Examples.ToArray()) | Select-Object -First 3) -join ', '
        [void]$lines.Add(("- {0} ({1} hit(s)); examples={2}" -f $s.Regex, $s.Count, $examples))
    }
    [void]$lines.Add('')
    [void]$lines.Add('## Seed Candidates')
    foreach ($s in (@($Analysis.Stats.SeedCandidates.Values) | Sort-Object Count -Descending | Select-Object -First 40)) {
        [void]$lines.Add(("- {0} ({1} hit(s))" -f $s.Value, $s.Count))
    }
    [void]$lines.Add('')
    [void]$lines.Add('## Allowlist Candidates')
    foreach ($a in (@($Analysis.Stats.AllowCandidates.Values) | Sort-Object Value | Select-Object -First 40)) {
        [void]$lines.Add(("- {0} - {1}" -f $a.Value, $a.Reason))
    }
    $out = Resolve-OutPath -Path $Path
    [System.IO.File]::WriteAllText($out, ($lines -join "`r`n"), [System.Text.Encoding]::UTF8)
    return $out
}

function Write-ProfileBuilderOptionalFiles {
    param($Analysis, [string]$Directory, [switch]$ProfileWizard, [switch]$NonInteractive)
    $writeSeeds = $false
    $writeAllow = $false
    if ($ProfileWizard -and -not $NonInteractive) {
        Write-Host ''
        Write-Step 'Profile builder wizard'
        Write-Info 'The generated profile never stores raw sample values. Seed and allowlist files may, so they are optional.'
        if ($Analysis.Stats.SeedCandidates.Count -gt 0) {
            Write-Detail ("Seed candidates: {0}" -f $Analysis.Stats.SeedCandidates.Count)
            $writeSeeds = Read-YesNo -Prompt 'Write generated-seeds.txt from sample candidates' -Default $false
        }
        if ($Analysis.Stats.AllowCandidates.Count -gt 0) {
            Write-Detail ("Allowlist candidates: {0}" -f $Analysis.Stats.AllowCandidates.Count)
            $writeAllow = Read-YesNo -Prompt 'Write generated-allowlist.txt from public diagnostic candidates' -Default $false
        }
    }
    $seedPath = $null
    $allowPath = $null
    if ($writeSeeds) {
        $seedPath = Join-Path $Directory 'generated-seeds.txt'
        $items = @($Analysis.Stats.SeedCandidates.Values | Sort-Object Count -Descending | Select-Object -First 100 | ForEach-Object { $_.Value })
        [System.IO.File]::WriteAllText($seedPath, (("# Generated seed terms. Review before use.`r`n" + ($items -join "`r`n") + "`r`n")), [System.Text.Encoding]::UTF8)
    }
    if ($writeAllow) {
        $allowPath = Join-Path $Directory 'generated-allowlist.txt'
        $items = @($Analysis.Stats.AllowCandidates.Values | Sort-Object Value | ForEach-Object { $_.Value })
        [System.IO.File]::WriteAllText($allowPath, (("# Generated allowlist. Review before use.`r`n" + ($items -join "`r`n") + "`r`n")), [System.Text.Encoding]::UTF8)
    }
    return [pscustomobject]@{ SeedPath=$seedPath; AllowlistPath=$allowPath; IncludeSeeds=[bool]$writeSeeds; IncludeAllowlist=[bool]$writeAllow }
}

function New-ScrubProfileFromSample {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$ProfileOut,
        [string]$ProfileReportOut,
        [string]$BaseProfile,
        [string[]]$ProfileExtensionFile,
        [switch]$ProfileWizard,
        [int]$MaxSampleRows = 500,
        [ValidateSet('Auto','Csv','Json','Kv','Text')][string]$SampleFormat = 'Auto',
        [switch]$Force,
        [switch]$NonInteractive
    )
    if (-not (Test-Path -LiteralPath $Path)) { throw "Sample path not found: $Path" }
    $files = @()
    if (Test-Path -LiteralPath $Path -PathType Container) {
        $files = @(Get-ChildItem -LiteralPath $Path -File -ErrorAction Stop |
            Where-Object { $_.Name -notmatch '(?i)(_scrubbed|\.scrubbed\.|token_map|DO_NOT_UPLOAD|false_positive|detection_report)' } |
            Sort-Object FullName | Select-Object -First 20 | ForEach-Object { $_.FullName })
    }
    else { $files = @((Resolve-Path -LiteralPath $Path).Path) }
    if ($files.Count -eq 0) { throw "No sample files found: $Path" }
    if ($MaxSampleRows -lt 1) { throw "MaxSampleRows must be at least 1." }

    $outPath = if ($ProfileOut) { $ProfileOut } else { Join-Path (Get-Location).Path 'generated-profile.json' }
    $outPath = Resolve-OutPath -Path $outPath
    $outDir = Split-Path -Parent $outPath
    if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    if ((Test-Path -LiteralPath $outPath) -and -not $Force) { throw "Profile output already exists: $outPath. Use -Force to overwrite." }
    $reportPath = if ($ProfileReportOut) { $ProfileReportOut } else { Join-Path $outDir 'profile_build_report_DO_NOT_UPLOAD.md' }
    $reportPath = Resolve-OutPath -Path $reportPath
    if ((Test-Path -LiteralPath $reportPath) -and -not $Force) { throw "Profile report already exists: $reportPath. Use -Force to overwrite." }

    Write-Work "Analyzing sample log(s) locally"
    $analysis = Invoke-SampleProfileAnalysis -Files $files -SampleFormat $SampleFormat -MaxSampleRows $MaxSampleRows
    if ($analysis.Stats.Rows -eq 0 -and $analysis.Stats.Columns.Count -eq 0 -and $analysis.Stats.Labels.Count -eq 0) {
        throw "Sample appears empty or unsupported: $Path"
    }
    $optional = Write-ProfileBuilderOptionalFiles -Analysis $analysis -Directory $outDir -ProfileWizard:$ProfileWizard -NonInteractive:$NonInteractive
    $name = 'GeneratedSampleProfile'
    try { $name = ('Generated-' + [System.IO.Path]::GetFileNameWithoutExtension($files[0])) -replace '[^A-Za-z0-9_.-]', '-' } catch { }
    $profile = ConvertTo-GeneratedProfile -Analysis $analysis -Name $name -IncludeSeeds:($optional.IncludeSeeds) -IncludeAllowlist:($optional.IncludeAllowlist)
    $profile = Merge-UlsGeneratedProfileWithBase -GeneratedProfile $profile -BaseProfile $BaseProfile -ProfileExtensionFile $ProfileExtensionFile
    $profile | ConvertTo-Json -Depth 8 | Set-Content -Path $outPath -Encoding UTF8
    [void](Test-ScrubProfile -Path $outPath -Quiet)
    $report = Write-ProfileBuilderReport -Analysis $analysis -Path $reportPath -ProfilePath $outPath
    Write-Ok "Generated profile: $outPath"
    Write-Warn "Profile build report is local-only: $report"
    if ($optional.SeedPath) { Write-Warn "Generated seeds are local-only: $($optional.SeedPath)" }
    if ($optional.AllowlistPath) { Write-Info "Generated allowlist: $($optional.AllowlistPath)" }
    return [pscustomobject]@{
        ProfilePath = $outPath
        ReportPath = $report
        Format = $analysis.Format
        FilesAnalyzed = $files.Count
        RowsAnalyzed = $analysis.Stats.Rows
        SeedPath = $optional.SeedPath
        AllowlistPath = $optional.AllowlistPath
    }
}

function New-SafeScrubBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Results,
        [Parameter(Mandatory)][string]$OutputPath,
        [switch]$Force
    )
    $clean = @($Results | Where-Object { $_.Clean -and $_.Output -and (Test-Path -LiteralPath $_.Output) })
    if ($clean.Count -eq 0) { throw "No clean scrubbed outputs are available for bundling." }
    $unverified = @($clean | Where-Object { $_.LeakCheckSkipped })
    if ($unverified.Count -gt 0) { throw "Safe bundle requires leak-verified outputs; $($unverified.Count) clean output(s) skipped leak check." }
    $out = Resolve-OutPath -Path $OutputPath
    if ((Test-Path -LiteralPath $out) -and -not $Force) { throw "Safe bundle already exists: $out. Use -Force to overwrite." }
    if ((Test-Path -LiteralPath $out) -and $Force) { Remove-Item -LiteralPath $out -Force }
    $stage = Join-Path ([System.IO.Path]::GetTempPath()) ("scrub_safe_bundle_" + ([System.IO.Path]::GetRandomFileName().Replace('.', '')))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    try {
        foreach ($r in $clean) {
            $dest = Join-Path $stage ([System.IO.Path]::GetFileName($r.Output))
            Copy-Item -LiteralPath $r.Output -Destination $dest -Force
        }
        $summary = @(
            'Universal Log Scrubber safe bundle',
            '',
            ('GeneratedUtc: {0}' -f ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))),
            ('ScrubPolicy: {0}' -f $script:ScrubPolicy),
            ('CleanFiles: {0}' -f $clean.Count),
            '',
            'This bundle intentionally excludes token maps, salts, manifests, raw logs, and detailed detection reports.'
        ) -join "`r`n"
        [System.IO.File]::WriteAllText((Join-Path $stage 'SAFE_UPLOAD_README.txt'), $summary, [System.Text.Encoding]::UTF8)
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $out -Force
    }
    finally {
        try { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    }
    Write-Ok "Safe upload bundle written: $out"
    return $out
}

# =====================================================================
# REGION: Pre-converters -- W3C/IIS logs and XLSX workbooks -> CSV
# =====================================================================
function ConvertFrom-W3CToCsv {
    param([Parameter(Mandatory)][string]$LogPath, [Parameter(Mandatory)][string]$OutCsv)
    Write-Work "Converting W3C/IIS -> CSV: $([System.IO.Path]::GetFileName($LogPath))"
    $fields = $null
    $rows = New-Object System.Collections.Generic.List[object]
    $reader = [System.IO.StreamReader]::new($LogPath)
    $lineNo = 0
    $dataRows = 0
    try {
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            $lineNo++
            if ($null -eq $line) { break }
            if ($line.StartsWith('#')) {
                if ($line -match '^#Fields:\s*(.+)$') { $fields = @($matches[1].Trim() -split '\s+') }
                continue
            }
            if (-not $fields -or [string]::IsNullOrWhiteSpace($line)) { continue }
            $dataRows++
            if ($dataRows % 1000 -eq 0) {
                Write-UlsProgress -Activity "Convert W3C" -Phase ("lines {0}" -f $lineNo) -File ([System.IO.Path]::GetFileName($LogPath)) -RowsDone $dataRows
            }
            $vals = @($line -split '\s+')
            $obj = [ordered]@{}
            for ($i = 0; $i -lt $fields.Count; $i++) { $obj[$fields[$i]] = if ($i -lt $vals.Count) { $vals[$i] } else { '' } }
            $rows.Add([pscustomobject]$obj)
        }
    }
    finally {
        $reader.Close()
        Write-UlsProgress -Activity "Convert W3C" -File ([System.IO.Path]::GetFileName($LogPath)) -Completed
    }
    $out = Resolve-OutPath -Path $OutCsv
    if ($rows.Count -gt 0) { $rows | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8 }
    else { [pscustomobject]@{ Note = 'No data rows / no #Fields header found.' } | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8 }
    Write-Ok "W3C/IIS converted: $out  ($($rows.Count) rows)"
    Write-Detail "Note: this CSV is UNSCRUBBED -- it gets scrubbed next."
    return $out
}

function Resolve-UlsTracerptPath {
    [CmdletBinding()]
    param([string]$TracerptPath)

    $tried = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($TracerptPath)) {
        [void]$tried.Add($TracerptPath)
        if (Test-Path -LiteralPath $TracerptPath -PathType Leaf) {
            return [pscustomobject]@{ Path = (Resolve-Path -LiteralPath $TracerptPath).Path; Tried = @($tried.ToArray()) }
        }
        return [pscustomobject]@{ Path = $null; Tried = @($tried.ToArray()) }
    }

    $cmd = Get-Command tracerpt.exe -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) {
        [void]$tried.Add($cmd.Source)
        if (Test-Path -LiteralPath $cmd.Source -PathType Leaf) {
            return [pscustomobject]@{ Path = $cmd.Source; Tried = @($tried.ToArray()) }
        }
    }

    $windowsRoot = $env:windir
    if ([string]::IsNullOrWhiteSpace($windowsRoot)) { $windowsRoot = $env:SystemRoot }
    foreach ($candidate in @(
        (Join-Path $windowsRoot 'System32\tracerpt.exe'),
        (Join-Path $windowsRoot 'Sysnative\tracerpt.exe')
    )) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        [void]$tried.Add($candidate)
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return [pscustomobject]@{ Path = (Resolve-Path -LiteralPath $candidate).Path; Tried = @($tried.ToArray()) }
        }
    }

    return [pscustomobject]@{ Path = $null; Tried = @($tried.ToArray()) }
}

function ConvertFrom-EtlToCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EtlPath,
        [Parameter(Mandatory)][string]$OutCsv,
        [string]$TracerptPath
    )
    if (-not (Test-Path -LiteralPath $EtlPath)) { throw "ETL not found: $EtlPath" }
    $resolvedEtl = (Resolve-Path -LiteralPath $EtlPath).Path
    $out = Resolve-OutPath -Path $OutCsv
    $outDir = Split-Path -Parent $out
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

    $tracerptInfo = Resolve-UlsTracerptPath -TracerptPath $TracerptPath
    $tracerpt = [string]$tracerptInfo.Path
    if ([string]::IsNullOrWhiteSpace($tracerpt)) {
        $triedText = if ($tracerptInfo.Tried.Count -gt 0) { " Tried: $($tracerptInfo.Tried -join '; ')" } else { '' }
        throw "tracerpt.exe was not found. ETL conversion is Windows-native but optional; run on Windows with tracerpt.exe available, pass -TracerptPath, or convert the ETL to CSV/XML/text before scrubbing.$triedText"
    }

    Write-Work "Converting ETL -> CSV with tracerpt.exe: $([System.IO.Path]::GetFileName($EtlPath))"
    Write-Warn "ETL conversion output is UNSCRUBBED until the scrub step completes: $out"
    $args = @($resolvedEtl, '-of', 'CSV', '-o', $out, '-y')
    $proc = Start-Process -FilePath $tracerpt -ArgumentList $args -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -ne 0) { throw "tracerpt.exe failed with exit code $($proc.ExitCode)." }
    if (-not (Test-Path -LiteralPath $out)) { throw "tracerpt.exe completed but did not create expected CSV: $out" }
    Write-Ok "ETL converted: $out"
    return $out
}

# Best-effort native XLSX reader (first worksheet). Prefers the ImportExcel module
# when present. EXPERIMENTAL -- validate output before trusting it.
function ConvertFrom-XlsxToCsv {
    param([Parameter(Mandatory)][string]$XlsxPath, [Parameter(Mandatory)][string]$OutCsv)
    if (-not (Test-Path $XlsxPath)) { throw "XLSX not found: $XlsxPath" }
    Write-Work "Converting XLSX -> CSV: $([System.IO.Path]::GetFileName($XlsxPath))"
    if (Get-Command Import-Excel -ErrorAction SilentlyContinue) {
        $data = Import-Excel -Path $XlsxPath
        $out = Resolve-OutPath -Path $OutCsv
        $data | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8
        Write-Ok "XLSX converted via ImportExcel: $out"
        return $out
    }
    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path $XlsxPath).Path)
    try {
        $readEntry = {
            param($z, $rx)
            $e = $z.Entries | Where-Object { $_.FullName -match $rx } | Select-Object -First 1
            if (-not $e) { return $null }
            $sr = New-Object System.IO.StreamReader($e.Open())
            try { return $sr.ReadToEnd() } finally { $sr.Close() }
        }
        $shared = @()
        $ssXml = & $readEntry $zip '^xl/sharedStrings\.xml$'
        if ($ssXml) {
            [xml]$sx = $ssXml
            foreach ($si in $sx.sst.si) {
                if ($si.r) { $shared += (($si.r | ForEach-Object { [string]$_.t }) -join '') }
                elseif ($si.t -is [string]) { $shared += [string]$si.t }
                elseif ($si.t.'#text') { $shared += [string]$si.t.'#text' }
                else { $shared += '' }
            }
        }
        $sheetXml = & $readEntry $zip '^xl/worksheets/sheet1\.xml$'
        if (-not $sheetXml) { $sheetXml = & $readEntry $zip '^xl/worksheets/.*\.xml$' }
        if (-not $sheetXml) { throw "No worksheet found in workbook." }
        [xml]$sh = $sheetXml
        $colToIndex = {
            param($ref)
            $letters = ($ref -replace '\d', '')
            $idx = 0
            foreach ($ch in $letters.ToCharArray()) { $idx = $idx * 26 + ([int][char]([string]$ch).ToUpper()) - 64 }
            return $idx - 1
        }
        $parsed = @()
        $maxCol = 0
        foreach ($row in $sh.worksheet.sheetData.row) {
            $cells = @{}
            foreach ($c in @($row.c)) {
                $ci = if ($c.r) { & $colToIndex ([string]$c.r) } else { 0 }
                $val = ''
                if ($c.t -eq 's') { $ii = [int]$c.v; if ($ii -ge 0 -and $ii -lt $shared.Count) { $val = $shared[$ii] } }
                elseif ($c.t -eq 'inlineStr') { $val = [string]$c.is.t }
                else { $val = [string]$c.v }
                $cells[$ci] = $val
                if ($ci -gt $maxCol) { $maxCol = $ci }
            }
            $parsed += , $cells
        }
        if ($parsed.Count -eq 0) { throw "Worksheet has no rows." }
        $hc = $parsed[0]
        $headers = @()
        for ($i = 0; $i -le $maxCol; $i++) {
            $h = if ($hc.ContainsKey($i)) { [string]$hc[$i] } else { '' }
            if ([string]::IsNullOrWhiteSpace($h)) { $h = "Column$($i + 1)" }
            $headers += $h
        }
        $rowsOut = New-Object System.Collections.Generic.List[object]
        for ($r = 1; $r -lt $parsed.Count; $r++) {
            $obj = [ordered]@{}
            for ($i = 0; $i -le $maxCol; $i++) { $obj[$headers[$i]] = if ($parsed[$r].ContainsKey($i)) { [string]$parsed[$r][$i] } else { '' } }
            $rowsOut.Add([pscustomobject]$obj)
        }
        $out = Resolve-OutPath -Path $OutCsv
        if ($rowsOut.Count -gt 0) { $rowsOut | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8 }
        else { [pscustomobject]@{ Note = 'No data rows.' } | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8 }
        Write-Ok "XLSX converted (first sheet): $out  ($($rowsOut.Count) rows)"
        Write-Detail "Native reader = first sheet only; for multi-sheet books export each sheet to CSV."
        return $out
    }
    finally { $zip.Dispose() }
}

function Get-UlsOpenXmlEntryText {
    param(
        [Parameter(Mandatory)][System.IO.Compression.ZipArchive]$Zip,
        [Parameter(Mandatory)][string]$EntryName
    )

    $entry = $Zip.GetEntry($EntryName)
    if (-not $entry) { return '' }
    $sr = New-Object System.IO.StreamReader($entry.Open())
    try { $xmlText = $sr.ReadToEnd() } finally { $sr.Close() }
    if ([string]::IsNullOrWhiteSpace($xmlText)) { return '' }

    try { [xml]$xml = $xmlText } catch { return '' }
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($node in $xml.GetElementsByTagName('*')) {
        if ($node.LocalName -eq 't' -and $null -ne $node.InnerText) {
            $s = [string]$node.InnerText
            if (-not [string]::IsNullOrWhiteSpace($s)) { [void]$parts.Add($s) }
        }
        elseif ($node.LocalName -match '^(br|cr|p)$') {
            if ($parts.Count -gt 0 -and $parts[$parts.Count - 1] -ne '') { [void]$parts.Add('') }
        }
    }
    $text = (($parts.ToArray()) -join "`r`n")
    return ($text -replace "(`r`n){3,}", "`r`n`r`n").Trim()
}

function ConvertFrom-OpenXmlToText {
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutText,
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string[]]$PartPatterns
    )

    if (-not (Test-Path -LiteralPath $InputPath)) { throw "$Kind not found: $InputPath" }
    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }
    $name = [System.IO.Path]::GetFileName($InputPath)
    Write-Work "Converting $Kind -> text: $name"
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $InputPath).Path)
    $out = Resolve-OutPath -Path $OutText
    try {
        $entries = @($zip.Entries | Where-Object {
            $entryName = $_.FullName
            foreach ($pat in $PartPatterns) { if ($entryName -match $pat) { return $true } }
            return $false
        } | Sort-Object FullName)
        if ($entries.Count -eq 0) { throw "No readable OpenXML text parts were found." }

        $lines = New-Object System.Collections.Generic.List[string]
        $i = 0
        foreach ($entry in $entries) {
            $i++
            Write-UlsProgress -Activity "Convert $Kind" -File $name -RowsDone $i -RowsTotal $entries.Count
            $text = Get-UlsOpenXmlEntryText -Zip $zip -EntryName $entry.FullName
            if ([string]::IsNullOrWhiteSpace($text)) { continue }
            [void]$lines.Add(("## {0}" -f $entry.FullName))
            foreach ($line in ($text -split "`r?`n")) { [void]$lines.Add($line) }
            [void]$lines.Add('')
        }
        Write-UlsProgress -Activity "Convert $Kind" -File $name -Completed
        if ($lines.Count -eq 0) { throw "OpenXML package contained no extractable text." }
        [System.IO.File]::WriteAllLines($out, [string[]]$lines.ToArray(), [System.Text.Encoding]::UTF8)
        Write-Ok "$Kind converted to local text: $out"
        Write-Detail "Note: this text is UNSCRUBBED -- it gets scrubbed next."
        return $out
    }
    finally {
        try { $zip.Dispose() } catch { }
        Write-UlsProgress -Activity "Convert $Kind" -File $name -Completed
    }
}

function ConvertFrom-DocxToText {
    param([Parameter(Mandatory)][string]$DocxPath, [Parameter(Mandatory)][string]$OutText)
    return ConvertFrom-OpenXmlToText -InputPath $DocxPath -OutText $OutText -Kind 'DOCX' -PartPatterns @(
        '^word/document\.xml$',
        '^word/header\d*\.xml$',
        '^word/footer\d*\.xml$',
        '^word/footnotes\.xml$',
        '^word/endnotes\.xml$',
        '^word/comments.*\.xml$'
    )
}

function ConvertFrom-PptxToText {
    param([Parameter(Mandatory)][string]$PptxPath, [Parameter(Mandatory)][string]$OutText)
    return ConvertFrom-OpenXmlToText -InputPath $PptxPath -OutText $OutText -Kind 'PPTX' -PartPatterns @(
        '^ppt/slides/slide\d+\.xml$',
        '^ppt/notesSlides/notesSlide\d+\.xml$',
        '^ppt/comments/comment\d+\.xml$',
        '^ppt/commentAuthors\.xml$'
    )
}

# =====================================================================
# REGION: Streaming scrub (bounded memory, opt-in for very large files)
# =====================================================================
function ConvertTo-UlsDelimitedField {
    param($Value)
    if ($null -eq $Value) { return '""' }
    $s = [string]$Value
    return '"' + ($s -replace '"', '""') + '"'
}

function ConvertTo-UlsDelimitedLine {
    param([object[]]$Values, [string]$Delimiter = ',')
    $fields = foreach ($v in @($Values)) { ConvertTo-UlsDelimitedField -Value $v }
    return ($fields -join $Delimiter)
}

function Read-UlsDelimitedRecord {
    param(
        [Parameter(Mandatory)][System.IO.StreamReader]$Reader,
        [string]$Delimiter = ','
    )

    $fastDelim = if ([string]::IsNullOrEmpty($Delimiter)) { [char]',' } else { [char]$Delimiter[0] }
    $fastQuote = [char]'"'
    $fastText = $Reader.ReadLine()
    if ($null -eq $fastText) { return $null }

    $fastHasOpenQuote = {
        param([string]$Value)
        $inside = $false
        for ($i = 0; $i -lt $Value.Length; $i++) {
            if ($Value[$i] -eq $fastQuote) {
                if ($inside -and ($i + 1) -lt $Value.Length -and $Value[$i + 1] -eq $fastQuote) {
                    $i++
                }
                else {
                    $inside = -not $inside
                }
            }
        }
        return $inside
    }

    while ((& $fastHasOpenQuote $fastText) -and -not $Reader.EndOfStream) {
        $nextLine = $Reader.ReadLine()
        if ($null -eq $nextLine) { break }
        $fastText += "`r`n" + $nextLine
    }

    $fastFields = New-Object System.Collections.Generic.List[string]
    $fastSb = New-Object System.Text.StringBuilder
    $fastInQuotes = $false
    $fastAtStart = $true
    for ($i = 0; $i -lt $fastText.Length; $i++) {
        $ch = $fastText[$i]
        if ($fastInQuotes) {
            if ($ch -eq $fastQuote) {
                if (($i + 1) -lt $fastText.Length -and $fastText[$i + 1] -eq $fastQuote) {
                    [void]$fastSb.Append($fastQuote)
                    $i++
                }
                else {
                    $fastInQuotes = $false
                }
            }
            else {
                [void]$fastSb.Append($ch)
            }
            continue
        }

        if ($fastAtStart -and $ch -eq $fastQuote) {
            $fastInQuotes = $true
            $fastAtStart = $false
            continue
        }
        if ($ch -eq $fastDelim) {
            [void]$fastFields.Add($fastSb.ToString())
            $null = $fastSb.Clear()
            $fastAtStart = $true
            continue
        }
        [void]$fastSb.Append($ch)
        $fastAtStart = $false
    }
    [void]$fastFields.Add($fastSb.ToString())
    return [string[]]$fastFields.ToArray()

    $delim = if ([string]::IsNullOrEmpty($Delimiter)) { [char]',' } else { [char]$Delimiter[0] }
    $quote = [char]'"'
    $cr = [char]"`r"
    $lf = [char]"`n"
    $fields = New-Object System.Collections.Generic.List[string]
    $sb = New-Object System.Text.StringBuilder
    $inQuotes = $false
    $atStartOfField = $true
    $sawAny = $false

    while ($true) {
        $next = $Reader.Read()
        if ($next -lt 0) {
            if (-not $sawAny -and $fields.Count -eq 0 -and $sb.Length -eq 0) { return $null }
            [void]$fields.Add($sb.ToString())
            return [string[]]$fields.ToArray()
        }

        $sawAny = $true
        $ch = [char]$next

        if ($inQuotes) {
            if ($ch -eq $quote) {
                if ($Reader.Peek() -eq [int]$quote) {
                    [void]$Reader.Read()
                    [void]$sb.Append($quote)
                }
                else {
                    $inQuotes = $false
                }
            }
            else {
                [void]$sb.Append($ch)
            }
            continue
        }

        if ($ch -eq $quote -and $atStartOfField) {
            $inQuotes = $true
            $atStartOfField = $false
            continue
        }

        if ($ch -eq $delim) {
            [void]$fields.Add($sb.ToString())
            [void]$sb.Clear()
            $atStartOfField = $true
            continue
        }

        if ($ch -eq $cr -or $ch -eq $lf) {
            if ($ch -eq $cr -and $Reader.Peek() -eq [int]$lf) { [void]$Reader.Read() }
            [void]$fields.Add($sb.ToString())
            return [string[]]$fields.ToArray()
        }

        [void]$sb.Append($ch)
        $atStartOfField = $false
    }
}

function ConvertFrom-UlsDelimitedRecord {
    param(
        [Parameter(Mandatory)][string[]]$Headers,
        [Parameter(Mandatory)][string[]]$Values
    )
    $row = [ordered]@{}
    for ($i = 0; $i -lt $Headers.Count; $i++) {
        $row[$Headers[$i]] = if ($i -lt $Values.Count) { [string]$Values[$i] } else { '' }
    }
    return [pscustomobject]$row
}


function Write-UlsWorkerProgressFile {
    param(
        [AllowNull()][string]$Path,
        [int]$Chunk = 0,
        [int]$RowsDone = 0,
        [int]$RowsTotal = 0,
        [string]$Status = 'Running'
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    try {
        $dir = Split-Path -Parent $Path
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $obj = [pscustomobject]@{
            Chunk      = $Chunk
            RowsDone   = [int]$RowsDone
            RowsTotal  = [int]$RowsTotal
            Status     = [string]$Status
            UpdatedUtc = ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))
        }
        $json = $obj | ConvertTo-Json -Compress
        $tmp = "$Path.tmp"
        [System.IO.File]::WriteAllText($tmp, $json, [System.Text.Encoding]::UTF8)
        if (Test-Path -LiteralPath $Path) { Move-Item -LiteralPath $tmp -Destination $Path -Force }
        else { Move-Item -LiteralPath $tmp -Destination $Path -Force }
    } catch {
        # Progress reporting must never fail a scrub worker.
    }
}

function Invoke-ScrubFileStreaming {
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)]$Profile,
        [string[]]$SensitiveTerms = @(),
        [Parameter(Mandatory)][string]$Format,
        [string]$Delimiter = ',',
        [switch]$SkipLeakCheck,
        [string]$WorkerProgressFile,
        [int]$WorkerProgressRowsTotal = 0,
        [int]$WorkerProgressChunk = 0,
        [int]$WorkerProgressIntervalRows = 250,
        [int]$WorkerProgressIntervalSeconds = 1
    )
    $name = [System.IO.Path]::GetFileName($InputPath)
    $outFull = Resolve-OutPath -Path $OutputPath
    Write-Work "Streaming scrub ($Format): $name"
    $leakCounts = @{}
    $leakSamples = @{}
    $rx = @(
        @{ T = 'Email/UPN';   S = '@';    R = '\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b' },
        @{ T = 'IPv4';        R = '(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)' },
        @{ T = 'IPv6';        S = ':';    R = '(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}|::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:' },
        @{ T = 'SID';         S = 'S-1-'; R = 'S-1-\d+(?:-\d+)+' },
        @{ T = 'DOMAIN\user'; S = '\';    R = '(?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]+\\[A-Za-z0-9_.\-$]+' },
        @{ T = 'Bare FQDN';   R = '\b(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b' }
    )
    $updateLeaks = {
        param([string]$line)
        foreach ($v in (Find-UniversalLabeledLeaks -Text $line)) {
            $leakCounts['Universal labeled value'] = ([int]$leakCounts['Universal labeled value']) + 1
            if (-not $leakSamples.ContainsKey('Universal labeled value')) { $leakSamples['Universal labeled value'] = New-Object System.Collections.Generic.List[string] }
            if ($leakSamples['Universal labeled value'].Count -lt 5 -and -not $leakSamples['Universal labeled value'].Contains($v)) { [void]$leakSamples['Universal labeled value'].Add($v) }
        }
        foreach ($v in (Find-CustomRegexIdentifiers -Text $line | ForEach-Object { $_.Raw })) {
            $leakCounts['Custom regex value'] = ([int]$leakCounts['Custom regex value']) + 1
            if (-not $leakSamples.ContainsKey('Custom regex value')) { $leakSamples['Custom regex value'] = New-Object System.Collections.Generic.List[string] }
            if ($leakSamples['Custom regex value'].Count -lt 5 -and -not $leakSamples['Custom regex value'].Contains($v)) { [void]$leakSamples['Custom regex value'].Add($v) }
        }
        foreach ($v in (Find-SecretIdentifiers -Text $line | ForEach-Object { $_.Raw })) {
            $leakCounts['Secret-like value'] = ([int]$leakCounts['Secret-like value']) + 1
            if (-not $leakSamples.ContainsKey('Secret-like value')) { $leakSamples['Secret-like value'] = New-Object System.Collections.Generic.List[string] }
            if ($leakSamples['Secret-like value'].Count -lt 5 -and -not $leakSamples['Secret-like value'].Contains($v)) { [void]$leakSamples['Secret-like value'].Add($v) }
        }
        foreach ($p in $rx) {
            if ($p.S -and ($line.IndexOf([string]$p.S, [System.StringComparison]::OrdinalIgnoreCase) -lt 0)) { continue }
            foreach ($m in [regex]::Matches($line, $p.R)) {
                $v = $m.Value
                if (Is-AlreadyToken -Value $v) { continue }
                if (Test-PreserveDottedDecimal -Value $v) { continue }
                if (($p.T -eq 'Bare FQDN' -or $p.T -eq 'Email/UPN') -and (Test-AllowedDomain -Value $v)) { continue }
                $prefixForLeak = switch ($p.T) {
                    'Bare FQDN' { 'DNS' }
                    'DOMAIN\user' { 'PRINCIPAL' }
                    'Email/UPN' { 'UNMAPPED_UPN' }
                    'IPv4' { 'IP' }
                    'IPv6' { 'IP6' }
                    'SID' { 'SID' }
                    default { '' }
                }
                if (Test-PreserveDetectedValue -Value $v -Detector $p.T -Prefix $prefixForLeak -Text $line -Index $m.Index -Length $m.Length) { continue }
                $leakCounts[$p.T] = ([int]$leakCounts[$p.T]) + 1
                if (-not $leakSamples.ContainsKey($p.T)) { $leakSamples[$p.T] = New-Object System.Collections.Generic.List[string] }
                if ($leakSamples[$p.T].Count -lt 5 -and -not $leakSamples[$p.T].Contains($v)) { [void]$leakSamples[$p.T].Add($v) }
            }
        }
    }
    # ULS perf patch 3: memoize the per-row secondary harden + leak detection by line text.
    # Repetitive logs (e.g. Windows Security) have few distinct rows, so this collapses the
    # ~25-pass hardening battery + leak scan from per-row to per-distinct-row. The written
    # output is byte-identical to the unmemoized path; only -DetectionSummaryReport counts
    # shift to per-distinct-value.
    $lineHardenCache = @{}
    $lineLeakSeen = @{}
    $writer = [System.IO.StreamWriter]::new($outFull, $false, [System.Text.Encoding]::UTF8)
    $n = 0
    $ulsPerfStreamTotal = New-UlsPerfStopwatch
    $ulsPerfScrubTicks = [long]0
    $ulsPerfPostTicks = [long]0
    $ulsPerfWriteTicks = [long]0
    $ulsPerfLeakTicks = [long]0
    $ulsPerfScrubColumnTicks = @{}
    $ulsPerfScrubColumnCounts = @{}
    if ($WorkerProgressIntervalRows -lt 1) { $WorkerProgressIntervalRows = 250 }
    if ($WorkerProgressIntervalSeconds -lt 1) { $WorkerProgressIntervalSeconds = 1 }
    $ulsWorkerProgressLastRows = -1
    $ulsWorkerProgressLastUtc = [DateTime]::UtcNow.AddSeconds(-10)
    $updateWorkerProgress = {
        param([string]$Status, [switch]$Force)
        if ([string]::IsNullOrWhiteSpace($WorkerProgressFile)) { return }
        $now = [DateTime]::UtcNow
        if ($Force -or $n -eq 0 -or (($n - $ulsWorkerProgressLastRows) -ge $WorkerProgressIntervalRows) -or (($now - $ulsWorkerProgressLastUtc).TotalSeconds -ge $WorkerProgressIntervalSeconds)) {
            Write-UlsWorkerProgressFile -Path $WorkerProgressFile -Chunk $WorkerProgressChunk -RowsDone $n -RowsTotal $WorkerProgressRowsTotal -Status $Status
            $script:__ulsWorkerProgressNoop = $null
            Set-Variable -Name ulsWorkerProgressLastRows -Scope 1 -Value $n
            Set-Variable -Name ulsWorkerProgressLastUtc -Scope 1 -Value $now
        }
    }
    & $updateWorkerProgress 'Starting' -Force
    try {
        if ($Format -eq 'Csv' -or $Format -eq 'Tsv' -or $Format -eq 'Psv') {
            $headers = $null
            Import-Csv -Path $InputPath -Delimiter $Delimiter | ForEach-Object {
                $row = $_; $n++
                & $updateWorkerProgress 'Running'
                if ($n % 1000 -eq 0) { Write-UlsProgress -Activity "Stream scrub" -Phase $Format -File $name -RowsDone $n -RowsTotal $WorkerProgressRowsTotal }
                if ($null -eq $headers) {
                    $headers = @($row.PSObject.Properties | ForEach-Object { [string]$_.Name })
                    if ($script:PerfReportEnabled) { $ulsPerfBlock = [System.Diagnostics.Stopwatch]::StartNew() }
                    $headerLine = Protect-SensitiveTerms -Text (ConvertTo-UlsDelimitedLine -Values $headers -Delimiter $Delimiter) -SensitiveTerms $SensitiveTerms
                    if ($script:PerfReportEnabled) { $ulsPerfBlock.Stop(); $ulsPerfPostTicks += $ulsPerfBlock.ElapsedTicks }
                    if ($script:PerfReportEnabled) { $ulsPerfBlock = [System.Diagnostics.Stopwatch]::StartNew() }
                    $writer.WriteLine($headerLine)
                    if ($script:PerfReportEnabled) { $ulsPerfBlock.Stop(); $ulsPerfWriteTicks += $ulsPerfBlock.ElapsedTicks }
                }
                $values = New-Object System.Collections.Generic.List[object]
                if ($script:PerfReportEnabled) { $ulsPerfBlock = [System.Diagnostics.Stopwatch]::StartNew() }
                foreach ($h in $headers) {
                    $prop = $row.PSObject.Properties[$h]
                    $rawValue = if ($null -ne $prop) { $prop.Value } else { $null }
                    if ($script:PerfReportDetailedEnabled) {
                        $ulsPerfColBlock = [System.Diagnostics.Stopwatch]::StartNew()
                        $scrubbedValue = Scrub-Field -ColumnName $h -Value $rawValue -Profile $Profile
                        $ulsPerfColBlock.Stop()
                        if (-not $ulsPerfScrubColumnTicks.ContainsKey($h)) { $ulsPerfScrubColumnTicks[$h] = [long]0; $ulsPerfScrubColumnCounts[$h] = 0 }
                        $ulsPerfScrubColumnTicks[$h] = [long]$ulsPerfScrubColumnTicks[$h] + [long]$ulsPerfColBlock.ElapsedTicks
                        $ulsPerfScrubColumnCounts[$h] = [int]$ulsPerfScrubColumnCounts[$h] + 1
                        [void]$values.Add($scrubbedValue)
                    }
                    else {
                        [void]$values.Add((Scrub-Field -ColumnName $h -Value $rawValue -Profile $Profile))
                    }
                }
                if ($script:PerfReportEnabled) { $ulsPerfBlock.Stop(); $ulsPerfScrubTicks += $ulsPerfBlock.ElapsedTicks }
                if ($script:PerfReportEnabled) { $ulsPerfBlock = [System.Diagnostics.Stopwatch]::StartNew() }
                $dataLine = ConvertTo-UlsDelimitedLine -Values $values.ToArray() -Delimiter $Delimiter
                $dataLine = Protect-SensitiveTerms -Text $dataLine -SensitiveTerms $SensitiveTerms
                if ($script:PerfReportEnabled) { $ulsPerfBlock.Stop(); $ulsPerfPostTicks += $ulsPerfBlock.ElapsedTicks }
                if ($script:PerfReportEnabled) { $ulsPerfBlock = [System.Diagnostics.Stopwatch]::StartNew() }
                $writer.WriteLine($dataLine)
                if ($script:PerfReportEnabled) { $ulsPerfBlock.Stop(); $ulsPerfWriteTicks += $ulsPerfBlock.ElapsedTicks }
                if (-not $SkipLeakCheck -and -not $lineLeakSeen.ContainsKey($dataLine)) {
                    if ($script:PerfReportEnabled) { $ulsPerfBlock = [System.Diagnostics.Stopwatch]::StartNew() }
                    $lineLeakSeen[$dataLine] = $true; & $updateLeaks $dataLine
                    if ($script:PerfReportEnabled) { $ulsPerfBlock.Stop(); $ulsPerfLeakTicks += $ulsPerfBlock.ElapsedTicks }
                }
            }
        }
        elseif ($Format -eq 'Json') {
            $reader = [System.IO.StreamReader]::new($InputPath)
            try {
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine(); if ($null -eq $line) { break }
                    $t = $line.Trim(); if ($t -eq '') { continue }
                    $n++; try { & $updateWorkerProgress 'Running' } catch { }; if ($n % 1000 -eq 0) { Write-UlsProgress -Activity "Stream scrub" -Phase $Format -File $name -RowsDone $n -RowsTotal $WorkerProgressRowsTotal }
                    $scr = Invoke-ScrubJsonText -Text $t -IsNdjson -Profile $Profile
                    $scr = Protect-SensitiveTerms -Text $scr -SensitiveTerms $SensitiveTerms
                    $writer.WriteLine($scr)
                    if (-not $SkipLeakCheck) { & $updateLeaks $scr }
                }
            }
            finally { $reader.Close() }
        }
        else {
            $reader = [System.IO.StreamReader]::new($InputPath)
            try {
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine(); if ($null -eq $line) { break }
                    $n++; try { & $updateWorkerProgress 'Running' } catch { }; if ($n % 1000 -eq 0) { Write-UlsProgress -Activity "Stream scrub" -Phase $Format -File $name -RowsDone $n -RowsTotal $WorkerProgressRowsTotal }
                    $h = if ($Format -eq 'Kv') { Invoke-KvValueOnlyText -Text $line } else { $line }
                    $h = Invoke-LeakHardeningText -Text $h
                    $h = Protect-SensitiveTerms -Text $h -SensitiveTerms $SensitiveTerms
                    $writer.WriteLine($h)
                    if (-not $SkipLeakCheck) { & $updateLeaks $h }
                }
            }
            finally { $reader.Close() }
        }
    }
    finally {
        try { & $updateWorkerProgress 'Completed' -Force } catch { }
        $writer.Close(); Write-UlsProgress -Activity "Stream scrub" -File $name -Completed
    }
    if ($ulsPerfStreamTotal) { $ulsPerfStreamTotal.Stop() }
    if ($script:PerfReportEnabled) {
        $freq = [double][System.Diagnostics.Stopwatch]::Frequency
        $scrubSec = [double]$ulsPerfScrubTicks / $freq
        $postSec = [double]$ulsPerfPostTicks / $freq
        $writeSec = [double]$ulsPerfWriteTicks / $freq
        $leakSec = [double]$ulsPerfLeakTicks / $freq
        $residual = [Math]::Max(0, $ulsPerfStreamTotal.Elapsed.TotalSeconds - $scrubSec - $postSec - $writeSec - $leakSec)
        Add-UlsPerfPhase -Phase 'Read CSV' -Seconds $residual -File $name -Rows $n -Notes 'Streaming Import-Csv/parser/pipeline residual'
        Add-UlsPerfPhase -Phase 'Scrub fields' -Seconds $scrubSec -File $name -Rows $n -Notes 'Streaming row/cell scrub'
        if ($script:PerfReportDetailedEnabled) {
            foreach ($col in ($ulsPerfScrubColumnTicks.Keys | Sort-Object)) {
                Add-UlsPerfPhase -Phase 'Scrub column' -Seconds ([double]$ulsPerfScrubColumnTicks[$col] / $freq) -File $name -Rows $n -Cells ([int]$ulsPerfScrubColumnCounts[$col]) -Notes ("Column=$col")
            }
        }
        Add-UlsPerfPhase -Phase 'Post hardening' -Seconds $postSec -File $name -Rows $n -Notes 'Streaming row render + sensitive terms'
        Add-UlsPerfPhase -Phase 'Write output' -Seconds $writeSec -File $name -Rows $n -Notes 'Streaming writer'
        Add-UlsPerfPhase -Phase 'Leak check' -Seconds $leakSec -File $name -Rows $n -Notes 'Streaming per-distinct-line leak scan'
    }
    $clean = $true
    if ($SkipLeakCheck) { Write-Warn "Leak check SKIPPED (-SkipLeakCheck) -- output was NOT independently verified." }
    else {
        $clean = ($leakCounts.Keys.Count -eq 0)
        if (-not $clean -and ($Format -eq 'Csv' -or $Format -eq 'Tsv' -or $Format -eq 'Psv')) {
            Write-Warn "Residue detected -- attempting one in-place re-harden..."
            try {
                Invoke-UlsLineWiseFileHardening -Path $outFull -SensitiveTerms $SensitiveTerms -SkipFirstLine
                $clean = Test-ScrubbedForLeaks -CsvPath $outFull -SensitiveTerms $SensitiveTerms -SkipFirstLine
                if ($clean) { $leakCounts = @{}; $leakSamples = @{} }
            }
            catch {
                Write-Warn "In-place re-harden could not complete ($($_.Exception.GetType().Name)); leaving output and flagging for review."
                $clean = $false
            }
        }
    }
    if ($clean -and -not $SkipLeakCheck) { Write-Ok "Leak check PASSED (streaming): $name" }
    else {
        if (-not $SkipLeakCheck) {
            Write-Fail "Leak check found residue (streaming) -- review:"
            foreach ($k in $leakCounts.Keys) { Write-Detail ("{0}: {1}  e.g. {2}" -f $k, $leakCounts[$k], (($leakSamples[$k]) -join ', ')) }
        }
    }
    Write-Detail "Output: $([System.IO.Path]::GetFileName($outFull))"
    return [pscustomobject]@{ Input = $InputPath; Output = $outFull; Clean = $clean; Rows = $n; Streamed = $true; LeakCheckSkipped = [bool]$SkipLeakCheck }
}


function ConvertTo-UlsPowerShellSingleQuotedLiteral {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return '$null' }
    return "'" + ([string]$Value -replace "'", "''") + "'"
}

function ConvertTo-UlsPowerShellStringArrayLiteral {
    param([string[]]$Values)
    $items = @($Values | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($items.Count -eq 0) { return '@()' }
    return '@(' + (($items | ForEach-Object { ConvertTo-UlsPowerShellSingleQuotedLiteral -Value ([string]$_) }) -join ',') + ')'
}

function Get-UlsCurrentModulePath {
    $modulePath = $null
    if ($PSCommandPath -and ([System.IO.Path]::GetExtension($PSCommandPath) -ieq '.psm1')) { $modulePath = $PSCommandPath }
    try {
        if (-not $modulePath -and $MyInvocation.MyCommand.Module -and $MyInvocation.MyCommand.Module.Path) {
            $candidate = $MyInvocation.MyCommand.Module.Path
            if ([System.IO.Path]::GetExtension($candidate) -ieq '.psm1') { $modulePath = $candidate }
            elseif ([System.IO.Path]::GetExtension($candidate) -ieq '.psd1') {
                $candidateModule = Join-Path (Split-Path -Parent $candidate) 'UniversalLogScrubber.psm1'
                if (Test-Path -LiteralPath $candidateModule) { $modulePath = $candidateModule }
            }
        }
    } catch { }
    if (-not $modulePath) { $modulePath = Join-Path $PSScriptRoot 'UniversalLogScrubber.psm1' }
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($modulePath)
}


function Invoke-UlsDiscoverTextBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$BatchIndex,
        [Parameter(Mandatory)][string[]]$Lines,
        [Parameter(Mandatory)][string]$ProfileName,
        [Parameter(Mandatory)][string]$Salt,
        [int]$HmacLength = 24,
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = 'Balanced',
        [string[]]$AllowlistFile = @(),
        [string]$Source = 'StreamingParallelDiscovery',
        [string]$SourcePathHash = ''
    )
    $script:Salt = $Salt
    $script:HmacLength = $HmacLength
    $script:ScrubPolicy = $ScrubPolicy
    $prof = Get-ScrubProfile -Name $ProfileName
    Initialize-ScrubProfileRuntime -Profile $prof -AllowlistFiles $AllowlistFile
    $seen = @{}
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($line in @($Lines)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        foreach ($id in (Find-Identifiers -Text ([string]$line))) {
            if (-not (Test-UlsShouldMapDiscoveredIdentifier -Raw ([string]$id.Raw) -Prefix ([string]$id.Prefix) -ScrubPolicy $ScrubPolicy)) { continue }
            $norm = Normalize-TokenKey -Value ([string]$id.Raw)
            if (-not $norm -or $seen.ContainsKey($norm)) { continue }
            $seen[$norm] = $true
            $tok = Get-Token -Value ([string]$id.Raw) -Prefix ([string]$id.Prefix)
            [void]$rows.Add((New-ScrubTokenMapRow -InputValue ([string]$id.Raw) -NormalizedValue $norm -Token $tok -TokenType ([string]$id.Prefix) -Source $Source -SourcePathHash $SourcePathHash))
        }
    }
    return [pscustomobject]@{ BatchIndex = $BatchIndex; Rows = @($rows.ToArray()); LineCount = @($Lines).Count }
}

function Invoke-UlsScrubTextBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$BatchIndex,
        [Parameter(Mandatory)][string[]]$Lines,
        [Parameter(Mandatory)][ValidateSet('Text','Kv','Json')][string]$Format,
        [Parameter(Mandatory)][string]$ProfileName,
        [Parameter(Mandatory)][string]$Salt,
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [int]$HmacLength = 24,
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = 'Balanced',
        [string[]]$SensitiveTerms = @(),
        [string[]]$AllowlistFile = @()
    )
    $script:Salt = $Salt
    $script:HmacLength = $HmacLength
    $script:ScrubPolicy = $ScrubPolicy
    $prof = Get-ScrubProfile -Name $ProfileName
    Initialize-ScrubProfileRuntime -Profile $prof -AllowlistFiles $AllowlistFile
    if (-not [string]::IsNullOrWhiteSpace($TokenMapCsv)) { [void](Import-ScrubTokenMap -TokenMapCsv $TokenMapCsv) }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($lineObj in @($Lines)) {
        $line = [string]$lineObj
        if ($Format -eq 'Json') {
            $t = $line.Trim()
            if ($t -eq '') { continue }
            $h = Invoke-ScrubJsonText -Text $t -IsNdjson -Profile $prof
        }
        elseif ($Format -eq 'Kv') {
            $h = Invoke-KvValueOnlyText -Text $line
            $h = Invoke-LeakHardeningText -Text $h
        }
        else {
            $h = Invoke-LeakHardeningText -Text $line
        }
        $h = Protect-SensitiveTerms -Text $h -SensitiveTerms $SensitiveTerms
        [void]$out.Add([string]$h)
    }
    return [pscustomobject]@{ BatchIndex = $BatchIndex; Lines = [string[]]$out.ToArray(); Rows = $out.Count }
}

function Invoke-UlsScrubCsvBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$BatchIndex,
        [Parameter(Mandatory)][object[]]$Rows,
        [Parameter(Mandatory)][string[]]$Headers,
        [string]$Delimiter = ',',
        [Parameter(Mandatory)][string]$ProfileName,
        [Parameter(Mandatory)][string]$Salt,
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [int]$HmacLength = 24,
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = 'Balanced',
        [string[]]$SensitiveTerms = @(),
        [string[]]$AllowlistFile = @()
    )
    $script:Salt = $Salt
    $script:HmacLength = $HmacLength
    $script:ScrubPolicy = $ScrubPolicy
    $script:__scrubFallback = 0
    $script:__scrubFallbackCol = ''
    $script:__cellCache = @{}
    $script:__hmacTokenCache = @{}
    $prof = Get-ScrubProfile -Name $ProfileName
    if (-not $prof) { throw "Unknown profile for CSV batch worker: $ProfileName" }
    Initialize-ScrubProfileRuntime -Profile $prof -AllowlistFiles $AllowlistFile
    if (-not [string]::IsNullOrWhiteSpace($TokenMapCsv)) { [void](Import-ScrubTokenMap -TokenMapCsv $TokenMapCsv) }

    $out = New-Object System.Collections.Generic.List[string]
    foreach ($rowObj in @($Rows)) {
        $values = New-Object System.Collections.Generic.List[object]
        $rowValues = if ($rowObj -and ($rowObj.PSObject.Properties.Name -contains 'Values')) { [string[]]$rowObj.Values } else { [string[]]$rowObj }
        for ($hi = 0; $hi -lt $Headers.Count; $hi++) {
            $rawValue = if ($hi -lt $rowValues.Count) { $rowValues[$hi] } else { '' }
            [void]$values.Add((Scrub-Field -ColumnName $Headers[$hi] -Value $rawValue -Profile $prof))
        }
        $line = ConvertTo-UlsDelimitedLine -Values $values.ToArray() -Delimiter $Delimiter
        $line = Protect-SensitiveTerms -Text $line -SensitiveTerms $SensitiveTerms
        [void]$out.Add([string]$line)
    }

    return [pscustomobject]@{
        BatchIndex        = $BatchIndex
        Lines             = [string[]]$out.ToArray()
        Rows              = $out.Count
        FallbackCount     = [int]$script:__scrubFallback
        FallbackFirstHint = [string]$script:__scrubFallbackCol
    }
}

function Invoke-UlsRunspaceBatchPool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$WorkerScript,
        [Parameter(Mandatory)][scriptblock]$ReadBatch,
        [Parameter(Mandatory)][scriptblock]$HandleResult,
        [int]$ThrottleLimit = 4,
        [string]$Activity = 'Streaming parallel work',
        [long]$TotalBytes = 0
    )
    if ($ThrottleLimit -lt 1) { $ThrottleLimit = 1 }
    Write-UlsProgress -Activity $Activity -Reset

    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit)
    $pool.ApartmentState = 'MTA'
    $pool.Open()
    $progressCompleted = $false

    # Mutable state is stored in hashtable keys and updated through the indexer.
    # Avoid $state.Completed++ / $state.CompletedRows += ... here: under nested
    # scriptblocks and hashtable dot-notation, progress counters can appear to
    # reset or stop moving even though runspaces are doing work.
    $state = @{
        Running = (New-Object System.Collections.Generic.List[object])
        Submitted = [int64]0
        Completed = [int64]0
        SubmittedRows = [int64]0
        CompletedRows = [int64]0
        SubmittedBytes = [int64]0
        CompletedBytes = [int64]0
        LastProgressUpdate = [datetime]::UtcNow.AddSeconds(-10)
    }

    $writeProgress = {
        param([switch]$Force)
        $nowProgress = [datetime]::UtcNow
        $last = [datetime]$state['LastProgressUpdate']
        if (-not $Force -and (($nowProgress - $last).TotalMilliseconds -lt 500)) { return }

        $runningCount = 0
        try { $runningCount = $state['Running'].Count } catch { $runningCount = 0 }
        $progressBytes = [Math]::Max([int64]$state['CompletedBytes'], [int64]0)
        if ($TotalBytes -gt 0) { $progressBytes = [Math]::Min([int64]$TotalBytes, [int64]$progressBytes) }
        Write-UlsProgress -Activity $Activity -Phase ("batches {0}/{1}" -f ([int64]$state['Completed']), ([int64]$state['Submitted'])) -RowsDone ([int64]$state['CompletedRows']) -RowsTotal ([int64]$state['SubmittedRows']) -BytesDone ([int64]$progressBytes) -BytesTotal $TotalBytes -Workers $runningCount -Force:$Force -MinIntervalMs 500
        $state['LastProgressUpdate'] = $nowProgress
    }

    $drainOne = {
        param([switch]$Wait)
        while ($true) {
            $running = $state['Running']
            $readyIndex = -1
            for ($i = 0; $i -lt $running.Count; $i++) {
                if ($running[$i].Async.IsCompleted) { $readyIndex = $i; break }
            }
            if ($readyIndex -lt 0) {
                if ($Wait -and $running.Count -gt 0) {
                    & $writeProgress
                    Start-Sleep -Milliseconds 50
                    continue
                }
                return $false
            }

            $item = $running[$readyIndex]
            $running.RemoveAt($readyIndex)
            try {
                try {
                    $resultCollection = $item.PowerShell.EndInvoke($item.Async)
                }
                catch {
                    throw ("Streaming parallel batch {0} failed: {1}" -f $item.BatchIndex, $_.Exception.Message)
                }
                foreach ($r in @($resultCollection)) { & $HandleResult $r }

                $state['Completed'] = [int64]$state['Completed'] + 1
                $state['CompletedRows'] = [int64]$state['CompletedRows'] + [int64]$item.Rows
                $state['CompletedBytes'] = [int64]$state['CompletedBytes'] + [int64]$item.Bytes
                & $writeProgress -Force
            }
            finally {
                try { $item.PowerShell.Dispose() } catch { }
            }
            return $true
        }
    }

    try {
        while ($true) {
            while ($state['Running'].Count -lt $ThrottleLimit) {
                $batch = & $ReadBatch
                if ($null -eq $batch) { break }

                $ps = [powershell]::Create()
                $ps.RunspacePool = $pool
                [void]$ps.AddScript($WorkerScript.ToString())
                foreach ($arg in ([object[]]$batch.Args)) { [void]$ps.AddArgument($arg) }
                $async = $ps.BeginInvoke()

                $batchRows = 0L; try { $batchRows = [int64]$batch.Rows } catch { }
                $batchBytes = 0L; try { $batchBytes = [int64]$batch.Bytes } catch { }
                [void]$state['Running'].Add([pscustomobject]@{ PowerShell = $ps; Async = $async; BatchIndex = $batch.Index; Rows = $batchRows; Bytes = $batchBytes })
                $state['Submitted'] = [int64]$state['Submitted'] + 1
                $state['SubmittedRows'] = [int64]$state['SubmittedRows'] + $batchRows
                $state['SubmittedBytes'] = [int64]$state['SubmittedBytes'] + $batchBytes
                & $writeProgress
            }

            if ($state['Running'].Count -eq 0) { break }
            [void](& $drainOne -Wait)
        }
        # Force a final 100% completion state before clearing the progress record.
        if ($TotalBytes -gt 0) { $state['CompletedBytes'] = [Math]::Max([int64]$state['CompletedBytes'], [int64]$TotalBytes) }
        & $writeProgress -Force
        Write-UlsProgress -Activity $Activity -Completed
        $progressCompleted = $true
    }
    finally {
        if (-not $progressCompleted) {
            try { Write-UlsProgress -Activity $Activity -Completed } catch { }
        }
        try {
            foreach ($item in @($state['Running'])) {
                try { $item.PowerShell.Stop() } catch { }
                try { $item.PowerShell.Dispose() } catch { }
            }
        } catch { }
        try { $pool.Close() } catch { }
        try { $pool.Dispose() } catch { }
    }
}

function Invoke-DiscoverFileStreamingParallelText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [Parameter(Mandatory)][string]$WorkDir,
        [Parameter(Mandatory)][string]$ProfileName,
        [string[]]$SensitiveTerms = @(),
        [string[]]$AllowlistFile = @(),
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = $script:ScrubPolicy,
        [int]$HmacLength = $script:HmacLength,
        [int]$ThrottleLimit = 4,
        [int]$ChunkSize = 0,
        [switch]$NoCorrelate,
        [switch]$KeepIntermediate
    )
    if ($ThrottleLimit -lt 1) { $ThrottleLimit = 1 }
    $batchSize = if ($ChunkSize -gt 0) { $ChunkSize } else { 20000 }
    $name = [System.IO.Path]::GetFileName($InputPath)
    $modulePath = Get-UlsCurrentModulePath
    $saltValue = Get-SessionSalt
    $fileHash = Get-PathFingerprint -Path $InputPath -Length 12
    $source = "Discovery:$name"
    Write-Work ("Streaming parallel discovery (Text): {0}  throttle={1} batchSize={2}" -f $name, $ThrottleLimit, $batchSize)
    $reader = [System.IO.StreamReader]::new($InputPath)
    $allRows = New-Object System.Collections.Generic.List[object]
    $batchIndex = 0
    $totalLines = 0
    $worker = {
        param($ModulePath,$BatchIndex,$Lines,$ProfileName,$Salt,$HmacLength,$ScrubPolicy,$AllowlistFile,$Source,$FileHash)
        if (-not (Get-Module -Name UniversalLogScrubber)) { Import-Module $ModulePath -Force }
        Invoke-UlsDiscoverTextBatch -BatchIndex $BatchIndex -Lines ([string[]]$Lines) -ProfileName $ProfileName -Salt $Salt -HmacLength $HmacLength -ScrubPolicy $ScrubPolicy -AllowlistFile ([string[]]$AllowlistFile) -Source $Source -SourcePathHash $FileHash
    }
    $readBatch = {
        if ($reader.EndOfStream) { return $null }
        $bytesBefore = 0L; try { $bytesBefore = [int64]$reader.BaseStream.Position } catch { }
        $lines = New-Object System.Collections.Generic.List[string]
        while ($lines.Count -lt $batchSize -and -not $reader.EndOfStream) {
            $l = $reader.ReadLine()
            if ($null -eq $l) { break }
            [void]$lines.Add($l)
        }
        if ($lines.Count -eq 0) { return $null }
        $idx = $batchIndex; Set-Variable -Name batchIndex -Scope 1 -Value ($batchIndex + 1)
        Set-Variable -Name totalLines -Scope 1 -Value ($totalLines + $lines.Count)
        $argsList = New-Object System.Collections.Generic.List[object]
        [void]$argsList.Add($modulePath)
        [void]$argsList.Add($idx)
        [void]$argsList.Add([string[]]$lines.ToArray())
        [void]$argsList.Add($ProfileName)
        [void]$argsList.Add($saltValue)
        [void]$argsList.Add($HmacLength)
        [void]$argsList.Add($ScrubPolicy)
        [void]$argsList.Add([string[]]$AllowlistFile)
        [void]$argsList.Add($source)
        [void]$argsList.Add($fileHash)
        $bytesAfter = $bytesBefore; try { $bytesAfter = [int64]$reader.BaseStream.Position } catch { }
        $batchBytes = [Math]::Max(0L, ($bytesAfter - $bytesBefore))
        return [pscustomobject]@{ Index=$idx; Args=[object[]]$argsList.ToArray(); Rows=$lines.Count; Bytes=$batchBytes }
    }
    $handle = {
        param($Result)
        if ($null -eq $Result) { return }
        foreach ($r in @($Result.Rows)) { [void]$allRows.Add($r) }
    }
    $sw = New-UlsPerfStopwatch
    $totalBytes = 0L; try { $totalBytes = [int64](Get-Item -LiteralPath $InputPath).Length } catch { }
    try { Invoke-UlsRunspaceBatchPool -WorkerScript $worker -ReadBatch $readBatch -HandleResult $handle -ThrottleLimit $ThrottleLimit -Activity ("Streaming parallel discovery $name") -TotalBytes $totalBytes }
    finally { try { $reader.Close() } catch { } }
    Add-UlsPerfPhase -Phase 'Discover identifiers' -Stopwatch $sw -File $name -Rows $totalLines -Notes ("Streaming parallel discovery batches={0}; throttle={1}; batchSize={2}; no input chunk files" -f $batchIndex,$ThrottleLimit,$batchSize)
    return @($allRows.ToArray())
}

function Invoke-ScrubFileStreamingParallelText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)]$Profile,
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [Parameter(Mandatory)][string]$WorkDir,
        [string[]]$SensitiveTerms = @(),
        [string[]]$AllowlistFile = @(),
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = $script:ScrubPolicy,
        [int]$HmacLength = $script:HmacLength,
        [int]$ThrottleLimit = 4,
        [int]$ChunkSize = 0,
        [switch]$SkipLeakCheck,
        [switch]$KeepIntermediate
    )
    if ($ThrottleLimit -lt 1) { $ThrottleLimit = 1 }
    if (-not (Test-Path -LiteralPath $TokenMapCsv)) { throw "ParallelScrub requires an existing token map after map setup. Not found: $TokenMapCsv" }
    $batchSize = if ($ChunkSize -gt 0) { $ChunkSize } else { 5000 }
    $name = [System.IO.Path]::GetFileName($InputPath); $outFull = Resolve-OutPath -Path $OutputPath
    $profileName = $null; try { $profileName = [string]$Profile.Name } catch { }
    if ([string]::IsNullOrWhiteSpace($profileName)) { throw "Streaming ParallelScrub currently requires a named/built-in profile." }
    $format = $Profile.Format
    if ($format -eq 'Auto') { $format = 'Text' }
    if ($format -ne 'Text' -and $format -ne 'Kv' -and $format -ne 'Json') { throw "Streaming ParallelScrub text path supports Text/Kv/Json formats only; got $format." }
    $modulePath = Get-UlsCurrentModulePath
    $saltValue = Get-SessionSalt
    $tokenMapFull = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TokenMapCsv)
    Write-Work ("Streaming parallel scrub (Text): {0}  throttle={1} batchSize={2}" -f $name, $ThrottleLimit, $batchSize)
    $reader = [System.IO.StreamReader]::new($InputPath)
    $writer = [System.IO.StreamWriter]::new($outFull, $false, [System.Text.Encoding]::UTF8)
    $batchIndex = 0; $totalLines = 0; $writtenLines = 0; $nextWrite = 0
    $ready = @{}
    $worker = {
        param($ModulePath,$BatchIndex,$Lines,$Format,$ProfileName,$Salt,$TokenMapCsv,$HmacLength,$ScrubPolicy,$SensitiveTerms,$AllowlistFile)
        if (-not (Get-Module -Name UniversalLogScrubber)) { Import-Module $ModulePath -Force }
        Invoke-UlsScrubTextBatch -BatchIndex $BatchIndex -Lines ([string[]]$Lines) -Format $Format -ProfileName $ProfileName -Salt $Salt -TokenMapCsv $TokenMapCsv -HmacLength $HmacLength -ScrubPolicy $ScrubPolicy -SensitiveTerms ([string[]]$SensitiveTerms) -AllowlistFile ([string[]]$AllowlistFile)
    }
    $readBatch = {
        if ($reader.EndOfStream) { return $null }
        $bytesBefore = 0L; try { $bytesBefore = [int64]$reader.BaseStream.Position } catch { }
        $lines = New-Object System.Collections.Generic.List[string]
        while ($lines.Count -lt $batchSize -and -not $reader.EndOfStream) {
            $l = $reader.ReadLine()
            if ($null -eq $l) { break }
            [void]$lines.Add($l)
        }
        if ($lines.Count -eq 0) { return $null }
        $idx = $batchIndex; Set-Variable -Name batchIndex -Scope 1 -Value ($batchIndex + 1)
        Set-Variable -Name totalLines -Scope 1 -Value ($totalLines + $lines.Count)
        $argsList = New-Object System.Collections.Generic.List[object]
        [void]$argsList.Add($modulePath)
        [void]$argsList.Add($idx)
        [void]$argsList.Add([string[]]$lines.ToArray())
        [void]$argsList.Add($format)
        [void]$argsList.Add($profileName)
        [void]$argsList.Add($saltValue)
        [void]$argsList.Add($tokenMapFull)
        [void]$argsList.Add($HmacLength)
        [void]$argsList.Add($ScrubPolicy)
        [void]$argsList.Add([string[]]$SensitiveTerms)
        [void]$argsList.Add([string[]]$AllowlistFile)
        $bytesAfter = $bytesBefore; try { $bytesAfter = [int64]$reader.BaseStream.Position } catch { }
        $batchBytes = [Math]::Max(0L, ($bytesAfter - $bytesBefore))
        return [pscustomobject]@{ Index=$idx; Args=[object[]]$argsList.ToArray(); Rows=$lines.Count; Bytes=$batchBytes }
    }
    $handle = {
        param($Result)
        if ($null -eq $Result) { return }
        $ready[[int]$Result.BatchIndex] = $Result
        while ($ready.ContainsKey($nextWrite)) {
            $r = $ready[$nextWrite]
            foreach ($line in @($r.Lines)) { $writer.WriteLine([string]$line); $writtenLines++ }
            $ready.Remove($nextWrite)
            Set-Variable -Name nextWrite -Scope 1 -Value ($nextWrite + 1)
            Write-UlsProgress -Activity "Parallel scrub" -Phase "text" -File $name -RowsDone $writtenLines -RowsTotal $totalLines -CompletedBatches $nextWrite -Ready $ready.Count
        }
    }
    $sw = New-UlsPerfStopwatch
    $totalBytes = 0L; try { $totalBytes = [int64](Get-Item -LiteralPath $InputPath).Length } catch { }
    try { Invoke-UlsRunspaceBatchPool -WorkerScript $worker -ReadBatch $readBatch -HandleResult $handle -ThrottleLimit $ThrottleLimit -Activity ("Streaming parallel scrub $name") -TotalBytes $totalBytes }
    finally { try { $writer.Close() } catch { }; try { $reader.Close() } catch { } }
    Add-UlsPerfPhase -Phase 'Scrub fields' -Stopwatch $sw -File $name -Rows $writtenLines -Notes ("Streaming parallel in-memory batches; throttle={0}; batchSize={1}; no input chunk files" -f $ThrottleLimit,$batchSize)
    $ulsPerfLeak = New-UlsPerfStopwatch
    if ($SkipLeakCheck) { Write-Warn "Leak check SKIPPED (-SkipLeakCheck) -- output was NOT independently verified."; $clean = $true }
    else { $clean = Test-ScrubbedForLeaks -CsvPath $outFull -SensitiveTerms $SensitiveTerms }
    Add-UlsPerfPhase -Phase 'Leak check' -Stopwatch $ulsPerfLeak -File $name -Rows $writtenLines -Notes ('Streaming parallel final leak check; SkipLeakCheck={0}' -f [bool]$SkipLeakCheck)
    Write-Detail "Output: $([System.IO.Path]::GetFileName($outFull))"
    return [pscustomobject]@{ Input=$InputPath; Output=$outFull; Clean=$clean; Rows=$writtenLines; Parallel=$true; Streamed=$true; StreamingParallel=$true; LeakCheckSkipped=[bool]$SkipLeakCheck }
}

function Invoke-ScrubFileStreamingParallelCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)]$Profile,
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [Parameter(Mandatory)][string]$WorkDir,
        [string[]]$SensitiveTerms = @(),
        [string[]]$AllowlistFile = @(),
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = $script:ScrubPolicy,
        [int]$HmacLength = $script:HmacLength,
        [int]$ThrottleLimit = 4,
        [int]$ChunkSize = 0,
        [switch]$SkipLeakCheck,
        [switch]$KeepIntermediate,
        [string]$Delimiter = ','
    )
    if ($ThrottleLimit -lt 1) { $ThrottleLimit = 1 }
    if (-not (Test-Path -LiteralPath $TokenMapCsv)) { throw "ParallelScrub requires an existing token map after map setup. Not found: $TokenMapCsv" }
    $batchSize = if ($ChunkSize -gt 0) { $ChunkSize } else { 2000 }
    if ($batchSize -lt 1) { $batchSize = 1 }

    $name = [System.IO.Path]::GetFileName($InputPath)
    $outFull = Resolve-OutPath -Path $OutputPath
    $profileName = $null
    try { $profileName = [string]$Profile.Name } catch { }
    if ([string]::IsNullOrWhiteSpace($profileName)) { throw "Streaming ParallelScrub currently requires a named/built-in profile." }

    $modulePath = Get-UlsCurrentModulePath
    $saltValue = Get-SessionSalt
    $tokenMapFull = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TokenMapCsv)
    Write-Work ("Streaming parallel scrub (CSV): {0}  throttle={1} batchSize={2}" -f $name, $ThrottleLimit, $batchSize)

    $reader = [System.IO.StreamReader]::new($InputPath)
    $writer = [System.IO.StreamWriter]::new($outFull, $false, [System.Text.Encoding]::UTF8)
    $csvParallelState = @{
        BatchIndex        = 0
        TotalRows         = 0
        WrittenRows       = 0
        NextWrite         = 0
        FallbackCount     = 0
        FallbackFirstHint = ''
    }
    $ready = @{}
    $headers = $null

    $worker = {
        param($Context)
        if (-not (Get-Module -Name UniversalLogScrubber)) { Import-Module ([string]$Context.ModulePath) -Force }
        Invoke-UlsScrubCsvBatch `
            -BatchIndex ([int]$Context.BatchIndex) `
            -Rows ([object[]]$Context.Rows) `
            -Headers ([string[]]$Context.Headers) `
            -Delimiter ([string]$Context.Delimiter) `
            -ProfileName ([string]$Context.ProfileName) `
            -Salt ([string]$Context.Salt) `
            -TokenMapCsv ([string]$Context.TokenMapCsv) `
            -HmacLength ([int]$Context.HmacLength) `
            -ScrubPolicy ([string]$Context.ScrubPolicy) `
            -SensitiveTerms ([string[]]$Context.SensitiveTerms) `
            -AllowlistFile ([string[]]$Context.AllowlistFile)
    }

    $readBatch = {
        if ($null -eq $headers) {
            $headerRecord = Read-UlsDelimitedRecord -Reader $reader -Delimiter $Delimiter
            if ($null -eq $headerRecord) { return $null }
            Set-Variable -Name headers -Scope 1 -Value ([string[]]$headerRecord)
            $headerLine = Protect-SensitiveTerms -Text (ConvertTo-UlsDelimitedLine -Values ([object[]]$headerRecord) -Delimiter $Delimiter) -SensitiveTerms $SensitiveTerms
            $writer.WriteLine($headerLine)
        }

        $bytesBefore = 0L; try { $bytesBefore = [int64]$reader.BaseStream.Position } catch { }
        $rows = New-Object System.Collections.Generic.List[object]
        while ($rows.Count -lt $batchSize) {
            $record = Read-UlsDelimitedRecord -Reader $reader -Delimiter $Delimiter
            if ($null -eq $record) { break }
            [void]$rows.Add([string[]]$record)
        }
        if ($rows.Count -eq 0) { return $null }

        $idx = [int]$csvParallelState['BatchIndex']
        $csvParallelState['BatchIndex'] = $idx + 1
        $csvParallelState['TotalRows'] = [int]$csvParallelState['TotalRows'] + [int]$rows.Count

        $context = [pscustomobject]@{
            ModulePath     = $modulePath
            BatchIndex     = $idx
            Rows           = [object[]]$rows.ToArray()
            Headers        = [string[]]$headers
            Delimiter      = $Delimiter
            ProfileName    = $profileName
            Salt           = $saltValue
            TokenMapCsv    = $tokenMapFull
            HmacLength     = $HmacLength
            ScrubPolicy    = $ScrubPolicy
            SensitiveTerms = [string[]]$SensitiveTerms
            AllowlistFile  = [string[]]$AllowlistFile
        }

        $bytesAfter = $bytesBefore; try { $bytesAfter = [int64]$reader.BaseStream.Position } catch { }
        $batchBytes = [Math]::Max(0L, ($bytesAfter - $bytesBefore))
        return [pscustomobject]@{ Index=$idx; Args=[object[]]@($context); Rows=$rows.Count; Bytes=$batchBytes }
    }

    $handle = {
        param($Result)
        if ($null -eq $Result) { return }
        $ready[[int]$Result.BatchIndex] = $Result
        while ($ready.ContainsKey([int]$csvParallelState['NextWrite'])) {
            $nextWrite = [int]$csvParallelState['NextWrite']
            $r = $ready[$nextWrite]
            foreach ($line in @($r.Lines)) {
                $writer.WriteLine([string]$line)
                $csvParallelState['WrittenRows'] = [int]$csvParallelState['WrittenRows'] + 1
            }
            if ($r.FallbackCount) {
                $csvParallelState['FallbackCount'] = [int]$csvParallelState['FallbackCount'] + [int]$r.FallbackCount
                if ([string]::IsNullOrWhiteSpace([string]$csvParallelState['FallbackFirstHint']) -and -not [string]::IsNullOrWhiteSpace([string]$r.FallbackFirstHint)) {
                    $csvParallelState['FallbackFirstHint'] = [string]$r.FallbackFirstHint
                }
            }
            $ready.Remove($nextWrite)
            $csvParallelState['NextWrite'] = $nextWrite + 1
            Write-UlsProgress -Activity "Parallel scrub" -Phase "csv" -File $name -RowsDone ([int]$csvParallelState['WrittenRows']) -RowsTotal ([int]$csvParallelState['TotalRows']) -CompletedBatches ([int]$csvParallelState['NextWrite']) -Ready $ready.Count
        }
    }

    $sw = New-UlsPerfStopwatch
    $totalBytes = 0L; try { $totalBytes = [int64](Get-Item -LiteralPath $InputPath).Length } catch { }
    try {
        Invoke-UlsRunspaceBatchPool -WorkerScript $worker -ReadBatch $readBatch -HandleResult $handle -ThrottleLimit $ThrottleLimit -Activity ("Streaming parallel CSV scrub $name") -TotalBytes $totalBytes
    }
    finally {
        try { $writer.Close() } catch { }
        try { $reader.Close() } catch { }
    }
    if ($ready.Count -gt 0) { throw "Streaming parallel CSV scrub completed with unwritten out-of-order batch(es): $($ready.Count)" }
    $writtenRows = [int]$csvParallelState['WrittenRows']
    Add-UlsPerfPhase -Phase 'Scrub fields' -Stopwatch $sw -File $name -Rows $writtenRows -Notes ("Streaming parallel CSV in-memory batches; throttle={0}; batchSize={1}; no input chunk files" -f $ThrottleLimit,$batchSize)

    $ulsPerfLeak = New-UlsPerfStopwatch
    if ($SkipLeakCheck) {
        Write-Warn "Leak check SKIPPED (-SkipLeakCheck) -- output was NOT independently verified."
        $clean = $true
    }
    else {
        Write-UlsProgress -Activity "Verify" -Phase "leak check" -File $name -Force
        $clean = Test-ScrubbedForLeaks -CsvPath $outFull -SensitiveTerms $SensitiveTerms -SkipFirstLine -ProbeOnly
        if (-not $clean) {
            Write-Warn "Residue detected -- attempting one in-place re-harden..."
            try {
                Invoke-UlsLineWiseFileHardening -Path $outFull -SensitiveTerms $SensitiveTerms -SkipFirstLine
                $clean = Test-ScrubbedForLeaks -CsvPath $outFull -SensitiveTerms $SensitiveTerms -SkipFirstLine
            }
            catch {
                Write-Warn "In-place re-harden could not complete ($($_.Exception.GetType().Name)); leaving output and flagging for review."
                $clean = $false
            }
        }
        Write-UlsProgress -Activity "Verify" -File $name -Completed
    }
    Add-UlsPerfPhase -Phase 'Leak check' -Stopwatch $ulsPerfLeak -File $name -Rows $writtenRows -Notes ('Streaming parallel CSV final leak check; SkipLeakCheck={0}' -f [bool]$SkipLeakCheck)
    if ([int]$csvParallelState['FallbackCount'] -gt 0) {
        Write-Warn "$($csvParallelState['FallbackCount']) cell(s) required fail-closed fallback inside CSV workers. First column: '$($csvParallelState['FallbackFirstHint'])'."
    }
    Write-Detail "Output: $([System.IO.Path]::GetFileName($outFull))"
    return [pscustomobject]@{ Input=$InputPath; Output=$outFull; Clean=$clean; Rows=$writtenRows; Parallel=$true; Streamed=$true; StreamingParallel=$true; LeakCheckSkipped=[bool]$SkipLeakCheck }
}


function Remove-UlsParallelWorkingFolder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$Retries = 5,
        [int]$DelayMilliseconds = 250
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
    if (-not (Test-Path -LiteralPath $Path)) { return $true }
    for ($attempt = 1; $attempt -le [Math]::Max($Retries, 1); $attempt++) {
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            return $true
        } catch {
            if ($attempt -ge [Math]::Max($Retries, 1)) {
                Write-Warn "Could not remove parallel working folder '$Path': $($_.Exception.Message)"
                return $false
            }
            Start-Sleep -Milliseconds ([Math]::Max($DelayMilliseconds, 50) * $attempt)
        }
    }
    return $false
}

function Remove-UlsStaleParallelWorkingFolders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkDir,
        [Parameter(Mandatory)][string]$InputPath,
        [int]$OlderThanHours = 24
    )
    try {
        if (-not (Test-Path -LiteralPath $WorkDir)) { return }
        $base = [System.IO.Path]::GetFileNameWithoutExtension($InputPath)
        if ([string]::IsNullOrWhiteSpace($base)) { return }
        $cutoff = (Get-Date).AddHours(-[Math]::Max($OlderThanHours, 1))
        Get-ChildItem -LiteralPath $WorkDir -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like ("_parallel_{0}_*" -f $base) -and $_.LastWriteTime -lt $cutoff } |
            ForEach-Object { [void](Remove-UlsParallelWorkingFolder -Path $_.FullName -Retries 2 -DelayMilliseconds 100) }
    } catch {
        # Stale cleanup is best-effort only; never fail the scrub because cleanup failed.
    }
}


function New-UlsLineChunks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$ChunkRoot,
        [int]$ThrottleLimit = 4,
        [int]$ChunkSize = 0,
        [string]$Extension = '.log'
    )
    if ($ThrottleLimit -lt 1) { $ThrottleLimit = 1 }
    if ($ChunkSize -lt 0) { throw "-ChunkSize must be 0 for auto/equal chunks, or a positive integer." }
    if ([string]::IsNullOrWhiteSpace($Extension)) { $Extension = '.log' }
    if (-not $Extension.StartsWith('.')) { $Extension = '.' + $Extension }
    New-Item -ItemType Directory -Path $ChunkRoot -Force | Out-Null

    $fileInfo = Get-Item -LiteralPath $InputPath
    $fileLength = [long]$fileInfo.Length
    $autoChunkSize = ($ChunkSize -le 0)
    $targetBytes = if ($autoChunkSize) { [long][Math]::Ceiling($fileLength / [double]$ThrottleLimit) } else { [long]0 }
    if ($targetBytes -lt 1) { $targetBytes = 1 }

    $chunks = New-Object System.Collections.Generic.List[object]
    $reader = [System.IO.StreamReader]::new($InputPath)
    $writer = $null
    $chunkIndex = 0
    $chunkRows = 0
    $totalRows = 0
    $nextBoundary = $targetBytes
    try {
        while (-not $reader.EndOfStream) {
            if ($null -eq $writer) {
                $chunkIndex++
                $chunkRows = 0
                $chunkFile = Join-Path $ChunkRoot ("chunk_{0:D6}{1}" -f $chunkIndex, $Extension)
                $writer = [System.IO.StreamWriter]::new($chunkFile, $false, [System.Text.Encoding]::UTF8)
            }
            $line = $reader.ReadLine()
            if ($null -eq $line) { break }
            $writer.WriteLine($line)
            $chunkRows++
            $totalRows++

            $shouldRoll = $false
            if ($autoChunkSize) {
                try { if ($reader.BaseStream.Position -ge $nextBoundary -and $chunkIndex -lt $ThrottleLimit) { $shouldRoll = $true } } catch { }
            }
            elseif ($chunkRows -ge $ChunkSize) { $shouldRoll = $true }

            if ($shouldRoll) {
                $writer.Close(); $writer = $null
                [void]$chunks.Add([pscustomobject]@{ Index=$chunkIndex; Input=$chunkFile; Rows=$chunkRows; Bytes=0; WorkDir=$null; Script=$null; StdOut=$null; StdErr=$null; Progress=$null; Process=$null; Output=$null; TokenMap=$null })
                if ($autoChunkSize) { $nextBoundary += $targetBytes }
            }
        }
    }
    finally {
        if ($writer) {
            $writer.Close()
            [void]$chunks.Add([pscustomobject]@{ Index=$chunkIndex; Input=$chunkFile; Rows=$chunkRows; Bytes=0; WorkDir=$null; Script=$null; StdOut=$null; StdErr=$null; Progress=$null; Process=$null; Output=$null; TokenMap=$null })
        }
        try { $reader.Close() } catch { }
    }
    foreach ($c in $chunks) { try { $c.Bytes = (Get-Item -LiteralPath $c.Input).Length } catch { } }
    return [pscustomobject]@{ Chunks=$chunks; Rows=$totalRows; Bytes=$fileLength; Auto=$autoChunkSize; TargetBytes=$targetBytes }
}

function Invoke-UlsChunkWorkerPool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Chunks,
        [Parameter(Mandatory)][string]$PwshPath,
        [Parameter(Mandatory)][string]$Activity,
        [int]$ThrottleLimit = 4,
        [switch]$KeepIntermediate
    )
    if ($ThrottleLimit -lt 1) { $ThrottleLimit = 1 }
    $pending = New-Object System.Collections.Queue
    foreach ($c in $Chunks) { $pending.Enqueue($c) }
    $running = New-Object System.Collections.Generic.List[object]
    $completed = New-Object System.Collections.Generic.List[object]
    $totalRows = 0
    foreach ($c in $Chunks) { $totalRows += [int]$c.Rows }
    if ($totalRows -lt 1) { $totalRows = 1 }
    $progressState = [pscustomobject]@{ LastPercent = -1; LastCompleted = -1; LastRowsDone = -1; LastUpdateUtc = [DateTime]::UtcNow.AddSeconds(-2) }
    $readWorkerProgress = {
        param($Chunk)
        $done = 0; $total = [int]$Chunk.Rows; $status = 'Pending'
        try {
            if ($Chunk.Progress -and (Test-Path -LiteralPath $Chunk.Progress)) {
                $raw = [System.IO.File]::ReadAllText($Chunk.Progress)
                if (-not [string]::IsNullOrWhiteSpace($raw)) {
                    $j = $raw | ConvertFrom-Json -ErrorAction Stop
                    if ($null -ne $j.RowsDone) { $done = [int]$j.RowsDone }
                    if ($null -ne $j.RowsTotal -and [int]$j.RowsTotal -gt 0) { $total = [int]$j.RowsTotal }
                    if ($null -ne $j.Status) { $status = [string]$j.Status }
                }
            }
        } catch { }
        if ($done -lt 0) { $done = 0 }
        if ($total -lt 1) { $total = [int]$Chunk.Rows }
        if ($done -gt $total) { $done = $total }
        return [pscustomobject]@{ RowsDone=$done; RowsTotal=$total; Status=$status }
    }
    $updateProgress = {
        param([switch]$Force)
        $doneChunks = $completed.Count
        $rowsDone = 0
        foreach ($cc in $completed) { $rowsDone += [int]$cc.Rows }
        foreach ($rc in $running) { $rp = & $readWorkerProgress $rc; $rowsDone += [int]$rp.RowsDone }
        if ($rowsDone -gt $totalRows) { $rowsDone = $totalRows }
        $pct = [Math]::Min(100, [Math]::Max(0, [int](($rowsDone / [double]$totalRows) * 100)))
        $now = [DateTime]::UtcNow
        if ($Force -or $pct -ne $progressState.LastPercent -or $doneChunks -ne $progressState.LastCompleted -or $rowsDone -ne $progressState.LastRowsDone -or (($now - $progressState.LastUpdateUtc).TotalSeconds -ge 1.0)) {
            $runningBits = @()
            foreach ($rc in ($running | Sort-Object Index)) { $rp = & $readWorkerProgress $rc; $runningBits += ("{0}:{1}/{2}" -f $rc.Index, [int]$rp.RowsDone, [int]$rp.RowsTotal) }
            $status = "Rows $rowsDone/$totalRows; chunks $doneChunks/$($Chunks.Count); running=$($running.Count); pending=$($pending.Count)"
            if ($runningBits.Count -gt 0) { $status += "; active=" + (($runningBits | Select-Object -First 6) -join ',') }
            Write-Progress -Activity $Activity -Status $status -PercentComplete $pct
            $progressState.LastPercent = $pct; $progressState.LastCompleted = $doneChunks; $progressState.LastRowsDone = $rowsDone; $progressState.LastUpdateUtc = $now
        }
    }
    & $updateProgress -Force
    while ($pending.Count -gt 0 -or $running.Count -gt 0) {
        while ($pending.Count -gt 0 -and $running.Count -lt $ThrottleLimit) {
            $c = $pending.Dequeue()
            Write-Detail ("Starting parallel chunk {0}/{1} ({2} rows)" -f $c.Index, $Chunks.Count, $c.Rows)
            $scriptArg = '"' + ([string]$c.Script -replace '"','\"') + '"'
            $argLine = ('-NoProfile -ExecutionPolicy Bypass -File {0}' -f $scriptArg)
            $startParams = @{ FilePath=$PwshPath; ArgumentList=$argLine; RedirectStandardOutput=$c.StdOut; RedirectStandardError=$c.StdErr; PassThru=$true }
            if ($IsWindows -or $env:OS -eq 'Windows_NT') { $startParams['WindowStyle'] = 'Hidden' }
            try { $proc = Start-Process @startParams }
            catch {
                if ($startParams.ContainsKey('WindowStyle')) { [void]$startParams.Remove('WindowStyle') }
                if ($IsWindows -or $env:OS -eq 'Windows_NT') { $startParams['NoNewWindow'] = $true }
                try { $proc = Start-Process @startParams }
                catch { if ($startParams.ContainsKey('NoNewWindow')) { [void]$startParams.Remove('NoNewWindow') }; $proc = Start-Process @startParams }
            }
            $c.Process = $proc; [void]$running.Add($c)
        }
        Start-Sleep -Milliseconds 200
        for ($idx = $running.Count - 1; $idx -ge 0; $idx--) {
            $c = $running[$idx]
            if ($c.Process.HasExited) {
                if ($c.Process.ExitCode -ne 0) {
                    $errText = ''; try { if (Test-Path -LiteralPath $c.StdErr) { $errText = [System.IO.File]::ReadAllText($c.StdErr) } } catch { }
                    throw ("Parallel worker chunk {0} failed with exit code {1}. {2}" -f $c.Index, $c.Process.ExitCode, $errText)
                }
                try { if ($c.Process) { $c.Process.Dispose() } } catch { }
                if (-not $KeepIntermediate) { try { if ($c.Progress -and (Test-Path -LiteralPath $c.Progress)) { Remove-Item -LiteralPath $c.Progress -Force -ErrorAction SilentlyContinue } } catch { } }
                [void]$completed.Add($c); $running.RemoveAt($idx)
                Write-Detail ("Completed parallel chunk {0}/{1} ({2} rows)" -f $c.Index, $Chunks.Count, $c.Rows)
                & $updateProgress -Force
            }
        }
        & $updateProgress
    }
    Write-Progress -Activity $Activity -Completed
    return @($completed | Sort-Object Index)
}

function Invoke-DiscoverFileParallelText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [Parameter(Mandatory)][string]$WorkDir,
        [Parameter(Mandatory)][string]$ProfileName,
        [string[]]$SensitiveTerms = @(),
        [string[]]$AllowlistFile = @(),
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = $script:ScrubPolicy,
        [int]$HmacLength = $script:HmacLength,
        [int]$ThrottleLimit = 4,
        [int]$ChunkSize = 0,
        [switch]$NoCorrelate,
        [switch]$KeepIntermediate
    )
    return Invoke-DiscoverFileStreamingParallelText -InputPath $InputPath -TokenMapCsv $TokenMapCsv -WorkDir $WorkDir -ProfileName $ProfileName -SensitiveTerms $SensitiveTerms -AllowlistFile $AllowlistFile -ScrubPolicy $ScrubPolicy -HmacLength $HmacLength -ThrottleLimit $ThrottleLimit -ChunkSize $ChunkSize -NoCorrelate:$NoCorrelate -KeepIntermediate:$KeepIntermediate
}

function Invoke-ScrubFileParallelText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)]$Profile,
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [Parameter(Mandatory)][string]$WorkDir,
        [string[]]$SensitiveTerms = @(),
        [string[]]$AllowlistFile = @(),
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = $script:ScrubPolicy,
        [int]$HmacLength = $script:HmacLength,
        [int]$ThrottleLimit = 4,
        [int]$ChunkSize = 0,
        [switch]$SkipLeakCheck,
        [switch]$KeepIntermediate
    )
    return Invoke-ScrubFileStreamingParallelText -InputPath $InputPath -OutputPath $OutputPath -Profile $Profile -SensitiveTerms $SensitiveTerms -AllowlistFile $AllowlistFile -TokenMapCsv $TokenMapCsv -WorkDir $WorkDir -ScrubPolicy $ScrubPolicy -HmacLength $HmacLength -ThrottleLimit $ThrottleLimit -ChunkSize $ChunkSize -SkipLeakCheck:$SkipLeakCheck -KeepIntermediate:$KeepIntermediate
}

function Invoke-ScrubFileParallelCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)]$Profile,
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [Parameter(Mandatory)][string]$WorkDir,
        [string[]]$SensitiveTerms = @(),
        [string[]]$AllowlistFile = @(),
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = $script:ScrubPolicy,
        [int]$HmacLength = $script:HmacLength,
        [int]$ThrottleLimit = 4,
        [int]$ChunkSize = 0,
        [switch]$SkipLeakCheck,
        [switch]$KeepIntermediate,
        [string]$Delimiter = ','
    )

    # v4.14 keeps this legacy private entrypoint as a compatibility shim only.
    # The implementation must stay streaming/runspace-based so -ParallelScrub never
    # creates physical CSV input chunks or per-chunk scrubbed output files.
    return Invoke-ScrubFileStreamingParallelCsv -InputPath $InputPath -OutputPath $OutputPath -Profile $Profile -TokenMapCsv $TokenMapCsv -WorkDir $WorkDir -SensitiveTerms $SensitiveTerms -AllowlistFile $AllowlistFile -ScrubPolicy $ScrubPolicy -HmacLength $HmacLength -ThrottleLimit $ThrottleLimit -ChunkSize $ChunkSize -SkipLeakCheck:$SkipLeakCheck -KeepIntermediate:$KeepIntermediate -Delimiter $Delimiter

    if ($ThrottleLimit -lt 1) { $ThrottleLimit = 1 }
    $autoChunkSize = ($ChunkSize -le 0)
    if ($ChunkSize -lt 0) { throw "-ChunkSize must be 0 for auto/equal chunks, or a positive integer." }
    if ($ChunkSize -gt 0 -and $ChunkSize -lt 100) { $ChunkSize = 100 }
    if (-not (Test-Path -LiteralPath $TokenMapCsv)) { throw "ParallelScrub requires an existing token map after map setup. Not found: $TokenMapCsv" }

    $name = [System.IO.Path]::GetFileName($InputPath)
    $outFull = Resolve-OutPath -Path $OutputPath
    $profileName = $null
    try { $profileName = [string]$Profile.Name } catch { }
    if ([string]::IsNullOrWhiteSpace($profileName)) { throw "ParallelScrub currently requires a named/built-in profile. Use the normal scrub path for anonymous profile objects." }

    $modulePath = Get-UlsCurrentModulePath
    if (-not (Test-Path -LiteralPath $modulePath)) { throw "Could not resolve module path for ParallelScrub workers: $modulePath" }

    $pwshPath = $null
    try { $pwshPath = (Get-Process -Id $PID).Path } catch { }
    if (-not $pwshPath -or -not (Test-Path -LiteralPath $pwshPath)) {
        $cmd = Get-Command pwsh -ErrorAction SilentlyContinue
        if ($cmd) { $pwshPath = $cmd.Source }
    }
    if (-not $pwshPath -or -not (Test-Path -LiteralPath $pwshPath)) { throw "ParallelScrub requires pwsh/PowerShell executable discovery, but none was found." }

    if (-not $KeepIntermediate) { Remove-UlsStaleParallelWorkingFolders -WorkDir $WorkDir -InputPath $InputPath -OlderThanHours 24 }

    $parallelRoot = Join-Path $WorkDir ("_parallel_{0}_{1}" -f ([System.IO.Path]::GetFileNameWithoutExtension($InputPath)), ([System.IO.Path]::GetRandomFileName().Replace('.', '')))
    $chunkInRoot = Join-Path $parallelRoot 'chunks'
    $chunkOutRoot = Join-Path $parallelRoot 'workers'
    New-Item -ItemType Directory -Path $chunkInRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $chunkOutRoot -Force | Out-Null

    $chunkSizeLabel = if ($autoChunkSize) { 'auto/equal' } else { [string]$ChunkSize }
    Write-Work ("Parallel scrub (Csv): {0}  throttle={1} chunkSize={2}" -f $name, $ThrottleLimit, $chunkSizeLabel)

    $saltWorkerFile = Join-Path $parallelRoot 'worker_salt_DO_NOT_UPLOAD.txt'
    [System.IO.File]::WriteAllText($saltWorkerFile, (Get-SessionSalt), [System.Text.Encoding]::UTF8)

    $sensitiveTermsFileForWorkers = $null
    if (@($SensitiveTerms).Count -gt 0) {
        $sensitiveTermsFileForWorkers = Join-Path $parallelRoot 'worker_sensitive_terms.txt'
        [System.IO.File]::WriteAllLines($sensitiveTermsFileForWorkers, [string[]]@($SensitiveTerms), [System.Text.Encoding]::UTF8)
    }

    $readSw = New-UlsPerfStopwatch
    $rows = @(Import-Csv -Path $InputPath -Delimiter $Delimiter)
    Add-UlsPerfPhase -Phase 'Read CSV' -Stopwatch $readSw -File $name -Rows $rows.Count -Notes 'Parallel chunk prep Import-Csv'
    $totalRows = $rows.Count
    if ($totalRows -eq 0) { throw "ParallelScrub found no CSV rows in: $InputPath" }
    if ($autoChunkSize) {
        $ChunkSize = [int][Math]::Ceiling($totalRows / [double]$ThrottleLimit)
        if ($ChunkSize -lt 1) { $ChunkSize = 1 }
        Write-Detail ("Auto chunk size resolved: {0} rows/chunk ({1} rows / throttle {2})" -f $ChunkSize, $totalRows, $ThrottleLimit)
    }

    $chunkPrepSw = New-UlsPerfStopwatch
    $chunks = New-Object System.Collections.Generic.List[object]
    $chunkIndex = 0
    for ($start = 0; $start -lt $totalRows; $start += $ChunkSize) {
        $chunkIndex++
        $endExclusive = [Math]::Min($start + $ChunkSize, $totalRows)
        $chunkRows = New-Object System.Collections.Generic.List[object]
        for ($ri = $start; $ri -lt $endExclusive; $ri++) { [void]$chunkRows.Add($rows[$ri]) }
        $chunkFile = Join-Path $chunkInRoot ("chunk_{0:D6}.csv" -f $chunkIndex)
        $chunkRows | Export-Csv -Path $chunkFile -NoTypeInformation -Encoding UTF8 -Delimiter $Delimiter
        $workerDir = Join-Path $chunkOutRoot ("chunk_{0:D6}" -f $chunkIndex)
        New-Item -ItemType Directory -Path $workerDir -Force | Out-Null
        [void]$chunks.Add([pscustomobject]@{ Index = $chunkIndex; Input = $chunkFile; WorkDir = $workerDir; Rows = $chunkRows.Count; Script = $null; StdOut = $null; StdErr = $null; Progress = $null; Process = $null; Output = $null })
    }
    Add-UlsPerfPhase -Phase 'Parallel chunk prep' -Stopwatch $chunkPrepSw -File $name -Rows $totalRows -Cells $chunks.Count -Notes ("chunkSize={0}; auto={1}; throttle={2}" -f $ChunkSize, $autoChunkSize, $ThrottleLimit)

    $tokenMapResolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TokenMapCsv)
    $moduleLiteral = ConvertTo-UlsPowerShellSingleQuotedLiteral -Value $modulePath
    $profileLiteral = ConvertTo-UlsPowerShellSingleQuotedLiteral -Value $profileName
    $saltFileLiteral = ConvertTo-UlsPowerShellSingleQuotedLiteral -Value $saltWorkerFile
    $tokenMapLiteral = ConvertTo-UlsPowerShellSingleQuotedLiteral -Value $tokenMapResolved
    $policyLiteral = ConvertTo-UlsPowerShellSingleQuotedLiteral -Value $ScrubPolicy
    $allowlistArg = ''
    if (@($AllowlistFile).Count -gt 0) { $allowlistArg = ' -AllowlistFile ' + (ConvertTo-UlsPowerShellStringArrayLiteral -Values $AllowlistFile) }
    $seedFileArg = ''
    if ($sensitiveTermsFileForWorkers) { $seedFileArg = ' -SensitiveTermsFile ' + (ConvertTo-UlsPowerShellStringArrayLiteral -Values @($sensitiveTermsFileForWorkers)) }

    foreach ($c in $chunks) {
        $scriptPath = Join-Path $c.WorkDir 'worker.ps1'
        $stdoutPath = Join-Path $c.WorkDir 'worker.out.txt'
        $stderrPath = Join-Path $c.WorkDir 'worker.err.txt'
        $progressPath = Join-Path $c.WorkDir 'worker.progress.json'
        $pathLiteral = ConvertTo-UlsPowerShellSingleQuotedLiteral -Value $c.Input
        $workLiteral = ConvertTo-UlsPowerShellSingleQuotedLiteral -Value $c.WorkDir
        $progressLiteral = ConvertTo-UlsPowerShellSingleQuotedLiteral -Value $progressPath
        $scriptText = @"
`$ErrorActionPreference = 'Stop'
Import-Module $moduleLiteral -Force
Invoke-UniversalScrubber -Path $pathLiteral -WorkDir $workLiteral -Profile $profileLiteral -SaltFile $saltFileLiteral -HmacLength $HmacLength -MapSource ExistingMap -TokenMapCsv $tokenMapLiteral -TokenMapMode Merge -ScrubPolicy $policyLiteral$seedFileArg$allowlistArg -NonInteractive -Stream -SkipLeakCheck -NoParallelScrub -WorkerProgressFile $progressLiteral -WorkerProgressRowsTotal $($c.Rows) -WorkerProgressChunk $($c.Index) -WorkerProgressIntervalRows 250 -WorkerProgressIntervalSeconds 1 | Out-Null
"@
        [System.IO.File]::WriteAllText($scriptPath, $scriptText, [System.Text.Encoding]::UTF8)
        $c.Script = $scriptPath; $c.StdOut = $stdoutPath; $c.StdErr = $stderrPath; $c.Progress = $progressPath
    }

    $workerSw = New-UlsPerfStopwatch
    $pending = New-Object System.Collections.Queue
    foreach ($c in $chunks) { $pending.Enqueue($c) }
    $running = New-Object System.Collections.Generic.List[object]
    $completed = New-Object System.Collections.Generic.List[object]

    $progressActivity = "Parallel scrub $name"
    $progressState = [pscustomobject]@{ LastPercent = -1; LastCompleted = -1; LastRowsDone = -1; LastUpdateUtc = [DateTime]::UtcNow.AddSeconds(-2) }
    $readWorkerProgress = {
        param($Chunk)
        $done = 0
        $total = [int]$Chunk.Rows
        $status = 'Pending'
        try {
            if ($Chunk.Progress -and (Test-Path -LiteralPath $Chunk.Progress)) {
                $raw = [System.IO.File]::ReadAllText($Chunk.Progress)
                if (-not [string]::IsNullOrWhiteSpace($raw)) {
                    $j = $raw | ConvertFrom-Json -ErrorAction Stop
                    if ($null -ne $j.RowsDone) { $done = [int]$j.RowsDone }
                    if ($null -ne $j.RowsTotal -and [int]$j.RowsTotal -gt 0) { $total = [int]$j.RowsTotal }
                    if ($null -ne $j.Status) { $status = [string]$j.Status }
                }
            }
        } catch {
            # Ignore partial JSON writes or transient file locks.
        }
        if ($done -lt 0) { $done = 0 }
        if ($total -lt 1) { $total = [int]$Chunk.Rows }
        if ($done -gt $total) { $done = $total }
        return [pscustomobject]@{ RowsDone = $done; RowsTotal = $total; Status = $status }
    }
    $updateParallelProgress = {
        param([switch]$Force)
        $doneChunks = $completed.Count
        $totalChunks = [Math]::Max($chunks.Count, 1)
        $rowsDone = 0
        $rowsTotal = [Math]::Max($totalRows, 1)
        foreach ($cc in $completed) { $rowsDone += [int]$cc.Rows }
        foreach ($rc in $running) {
            $rp = & $readWorkerProgress $rc
            $rowsDone += [int]$rp.RowsDone
        }
        if ($rowsDone -gt $rowsTotal) { $rowsDone = $rowsTotal }
        $pct = [Math]::Min(100, [Math]::Max(0, [int](($rowsDone / [double]$rowsTotal) * 100)))
        $now = [DateTime]::UtcNow
        if ($Force -or $pct -ne $progressState.LastPercent -or $doneChunks -ne $progressState.LastCompleted -or $rowsDone -ne $progressState.LastRowsDone -or (($now - $progressState.LastUpdateUtc).TotalSeconds -ge 1.0)) {
            $runningBits = @()
            foreach ($rc in ($running | Sort-Object Index)) {
                $rp = & $readWorkerProgress $rc
                $runningBits += ("{0}:{1}/{2}" -f $rc.Index, [int]$rp.RowsDone, [int]$rp.RowsTotal)
            }
            $status = "Rows $rowsDone/$rowsTotal; chunks $doneChunks/$($chunks.Count); running=$($running.Count); pending=$($pending.Count)"
            if ($runningBits.Count -gt 0) { $status += "; active=" + (($runningBits | Select-Object -First 6) -join ',') }
            Write-Progress -Activity $progressActivity -Status $status -PercentComplete $pct
            $progressState.LastPercent = $pct
            $progressState.LastCompleted = $doneChunks
            $progressState.LastRowsDone = $rowsDone
            $progressState.LastUpdateUtc = $now
        }
    }
    & $updateParallelProgress -Force

    while ($pending.Count -gt 0 -or $running.Count -gt 0) {
        while ($pending.Count -gt 0 -and $running.Count -lt $ThrottleLimit) {
            $c = $pending.Dequeue()
            Write-Detail ("Starting parallel chunk {0}/{1} ({2} rows)" -f $c.Index, $chunks.Count, $c.Rows)
            # Start-Process joins string[] arguments with spaces and may not quote paths with spaces reliably.
            # Use one explicitly quoted argument string so worker.ps1 under paths such as
            # "C:\Users\...\Universal Log Scrubber\..." is passed as one -File argument.
            $scriptArg = '"' + ([string]$c.Script -replace '"','\"') + '"'
            $argLine = ('-NoProfile -ExecutionPolicy Bypass -File {0}' -f $scriptArg)
            $startParams = @{
                FilePath = $pwshPath
                ArgumentList = $argLine
                RedirectStandardOutput = $c.StdOut
                RedirectStandardError = $c.StdErr
                PassThru = $true
            }
            if ($IsWindows -or $env:OS -eq 'Windows_NT') {
                # Keep parallel worker pwsh.exe consoles from flashing/popping up on Windows.
                # This is cosmetic only; stdout/stderr still go to per-worker log files.
                $startParams['WindowStyle'] = 'Hidden'
            }
            try {
                $proc = Start-Process @startParams
            } catch {
                # Some hosts/PowerShell builds reject WindowStyle when output is redirected.
                # Fall back to NoNewWindow first, then to the basic launch so the scrub can still run.
                $hiddenStartError = $_
                if ($startParams.ContainsKey('WindowStyle')) { [void]$startParams.Remove('WindowStyle') }
                if ($IsWindows -or $env:OS -eq 'Windows_NT') { $startParams['NoNewWindow'] = $true }
                try {
                    $proc = Start-Process @startParams
                } catch {
                    if ($startParams.ContainsKey('NoNewWindow')) { [void]$startParams.Remove('NoNewWindow') }
                    $proc = Start-Process @startParams
                }
            }
            $c.Process = $proc
            [void]$running.Add($c)
        }
        Start-Sleep -Milliseconds 200
        for ($idx = $running.Count - 1; $idx -ge 0; $idx--) {
            $c = $running[$idx]
            if ($c.Process.HasExited) {
                if ($c.Process.ExitCode -ne 0) {
                    $errText = ''
                    try { if (Test-Path -LiteralPath $c.StdErr) { $errText = [System.IO.File]::ReadAllText($c.StdErr) } } catch { }
                    throw ("ParallelScrub worker chunk {0} failed with exit code {1}. {2}" -f $c.Index, $c.Process.ExitCode, $errText)
                }
                $childOut = @(Get-ChildItem -Path $c.WorkDir -Filter '*_scrubbed.csv' -File -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -First 1)
                if ($childOut.Count -eq 0) { throw ("ParallelScrub worker chunk {0} did not produce a *_scrubbed.csv output." -f $c.Index) }
                $c.Output = $childOut[0].FullName
                try { if ($c.Process) { $c.Process.Dispose() } } catch { }
                if (-not $KeepIntermediate) {
                    try { if ($c.Progress -and (Test-Path -LiteralPath $c.Progress)) { Remove-Item -LiteralPath $c.Progress -Force -ErrorAction SilentlyContinue } } catch { }
                }
                [void]$completed.Add($c)
                $running.RemoveAt($idx)
                Write-Detail ("Completed parallel chunk {0}/{1} ({2} rows)" -f $c.Index, $chunks.Count, $c.Rows)
                & $updateParallelProgress -Force
            }
        }
        & $updateParallelProgress
    }
    Write-Progress -Activity $progressActivity -Completed
    Add-UlsPerfPhase -Phase 'Scrub fields' -Stopwatch $workerSw -File $name -Rows $totalRows -Notes ("Parallel child pwsh workers; chunks={0}; throttle={1}" -f $chunks.Count, $ThrottleLimit)

    $mergeSw = New-UlsPerfStopwatch
    $first = $true
    $mergedRows = 0
    foreach ($c in ($completed | Sort-Object Index)) {
        $chunkRowsOut = @(Import-Csv -Path $c.Output -Delimiter $Delimiter)
        if ($first) {
            $chunkRowsOut | Export-Csv -Path $outFull -NoTypeInformation -Encoding UTF8 -Delimiter $Delimiter
            $first = $false
        }
        else {
            $chunkRowsOut | Export-Csv -Path $outFull -NoTypeInformation -Encoding UTF8 -Delimiter $Delimiter -Append
        }
        $mergedRows += $chunkRowsOut.Count
    }
    Add-UlsPerfPhase -Phase 'Write output' -Stopwatch $mergeSw -File $name -Rows $mergedRows -Notes 'Parallel chunk output merge'

    $ulsPerfLeak = New-UlsPerfStopwatch
    if ($SkipLeakCheck) {
        Write-Warn "Leak check SKIPPED (-SkipLeakCheck) -- output was NOT independently verified."
        $clean = $true
    }
    else {
        $clean = Test-ScrubbedForLeaks -CsvPath $outFull -SensitiveTerms $SensitiveTerms -SkipFirstLine -ProbeOnly
        if (-not $clean) {
            Write-Warn "Residue detected -- attempting one in-place re-harden..."
            try {
                Invoke-UlsLineWiseFileHardening -Path $outFull -SensitiveTerms $SensitiveTerms -SkipFirstLine
                $clean = Test-ScrubbedForLeaks -CsvPath $outFull -SensitiveTerms $SensitiveTerms -SkipFirstLine
            }
            catch {
                Write-Warn "In-place re-harden could not complete ($($_.Exception.GetType().Name)); leaving output and flagging for review."
                $clean = $false
            }
        }
    }
    Add-UlsPerfPhase -Phase 'Leak check' -Stopwatch $ulsPerfLeak -File $name -Rows $mergedRows -Notes ('Parallel final leak check; SkipLeakCheck={0}' -f [bool]$SkipLeakCheck)

    Write-Detail "Output: $([System.IO.Path]::GetFileName($outFull))"
    if (-not $KeepIntermediate -and $clean) {
        [void](Remove-UlsParallelWorkingFolder -Path $parallelRoot -Retries 8 -DelayMilliseconds 250)
    }
    else {
        Write-Info "Parallel working folder kept: $parallelRoot"
    }

    return [pscustomobject]@{ Input = $InputPath; Output = $outFull; Clean = $clean; Rows = $mergedRows; Parallel = $true; Chunks = $chunks.Count; LeakCheckSkipped = [bool]$SkipLeakCheck }
}

# =====================================================================
# REGION: Self-test (synthetic data only -- validates a build with no real logs)
# =====================================================================
function Restore-ScrubbedFile {
    <#
      Un-scrub: replace tokens with their original values using your private token
      map, so a finding referenced by token can be turned back into the real value.
      Correlated aliases collapse to one token, so a token restores to its canonical
      original (an email is preferred when several aliases share a token).
    #>
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [Parameter(Mandatory)][string]$OutputPath
    )
    if (-not (Test-Path $InputPath)) { throw "Input not found: $InputPath" }
    if (-not (Test-Path $TokenMapCsv)) { throw "Token map not found: $TokenMapCsv" }
    $byToken = @{}
    foreach ($r in (Import-Csv $TokenMapCsv)) {
        $tok = [string]$r.Token; $orig = [string]$r.InputValue
        if ([string]::IsNullOrWhiteSpace($tok) -or [string]::IsNullOrWhiteSpace($orig)) { continue }
        if (-not $byToken.ContainsKey($tok)) { $byToken[$tok] = $orig }
        elseif (($orig -match '@') -and ($byToken[$tok] -notmatch '@')) { $byToken[$tok] = $orig }   # prefer an email alias
    }
    $text = [System.IO.File]::ReadAllText($InputPath)
    $rxTok = '(?:HV_|UNMAPPED_)?[A-Z0-9]+(?:_[A-Z0-9]+)*_[A-F0-9]{4,}|(?:BROAD|ADCS|HV_GROUP|BUILTIN)_[A-Z0-9_]+'
    $restored = [regex]::Replace($text, $rxTok, {
        param($m) if ($byToken.ContainsKey($m.Value)) { return $byToken[$m.Value] } else { return $m.Value }
    })
    $out = Resolve-OutPath -Path $OutputPath
    [System.IO.File]::WriteAllText($out, $restored, [System.Text.Encoding]::UTF8)
    Write-Ok "Restored: $out"
    return $out
}

# Generate a synthetic log for a given profile, with planted identifiers that MUST
# be removed and (optionally) values that MUST be preserved. Used by the self-test
# and handy for ad-hoc testing. Returns Path/ScrubProfile/Planted/Preserve/PreConvert.
function New-SyntheticLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Profile,
        [Parameter(Mandatory)][string]$Dir,
        [string]$Name
    )
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
    $tab = "`t"
    $stem = if ($Name) { $Name } else { "syn_$Profile" }
    $scrubProfile = $Profile; $preConvert = $null; $ext = 'csv'
    $planted = @(); $preserve = @(); $lines = @()
    switch ($Profile) {
        'Generic' {
            $lines = @('User,Email,IP,Host,Note',
                       'CORP\jdoe,jdoe@corp.local,10.1.2.3,dc01.corp.local,ok',
                       'CORP\asmith,asmith@corp.local,10.1.2.4,web01.corp.local,visit https://portal.corp.local/x')
            $planted = @('CORP\jdoe','jdoe@corp.local','10.1.2.3','dc01.corp.local','portal.corp.local')
        }
        'CA' {
            $scrubProfile = 'CA'
            $lines = @('RequestID,RequesterName,SAN_UPN,CertSubject,EKU_OIDs,SerialNumber,Published',
                       '1001,CORP\svcweb$,svcweb@corp.local,"CN=web01.corp.local, O=Contoso",1.3.6.1.5.5.7.3.2; 1.3.6.1.4.1.311.20.2.2,1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d,True')
            $planted = @('CORP\svcweb$','svcweb@corp.local','web01.corp.local','1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d')
            $preserve = @('1.3.6.1.5.5.7.3.2')
        }
        'Tsv' {
            $ext = 'tsv'; $scrubProfile = 'Tsv'
            $lines = @("User${tab}Email${tab}IP", "CORP\bmiller${tab}bmiller@corp.local${tab}10.2.2.2")
            $planted = @('CORP\bmiller','bmiller@corp.local','10.2.2.2')
        }
        'Psv' {
            $ext = 'psv'; $scrubProfile = 'Psv'
            $lines = @('User|Email|IP', 'CORP\cwright|cwright@corp.local|10.3.3.3')
            $planted = @('CORP\cwright','cwright@corp.local','10.3.3.3')
        }
        'Syslog' {
            $ext = 'log'; $scrubProfile = 'Syslog'
            $lines = @('Jan  1 12:00:00 host01 sshd[111]: Accepted password for user1 from 10.4.4.4 port 22',
                       'Jan  1 12:00:01 host01 app: admin@corp.local connected to db.corp.local')
            $planted = @('10.4.4.4','admin@corp.local','db.corp.local')
        }
        'Apache' {
            $ext = 'log'; $scrubProfile = 'Apache'
            $lines = @('203.0.113.5 - bob [01/Jan/2025:00:00:00 +0000] "GET /index HTTP/1.1" 200 123 "https://ref.corp.local/" "Mozilla/5.0"')
            $planted = @('203.0.113.5','ref.corp.local')
        }
        'Cef' {
            $ext = 'log'; $scrubProfile = 'Cef'
            $lines = @('CEF:0|Vendor|Product|1.0|100|Login|5|src=10.5.5.5 suser=dwilson@corp.local dhost=app.corp.local')
            $planted = @('10.5.5.5','dwilson@corp.local','app.corp.local')
            $preserve = @('src=')
        }
        'Logfmt' {
            $ext = 'log'; $scrubProfile = 'Logfmt'
            $lines = @('level=info user=egarcia@corp.local ip=10.6.6.6 host=svc.corp.local msg="ok"')
            $planted = @('egarcia@corp.local','10.6.6.6','svc.corp.local')
            $preserve = @('level=info')
        }
        'WindowsEventCsv' {
            $scrubProfile = 'WindowsEventCsv'
            $lines = @('RecordId,TimeCreated,ProviderName,MachineName,UserId,Message',
                       '1,2025-01-01T00:00:00Z,Microsoft-Windows-Security-Auditing,WINDC01,S-1-5-21-111-222-333-1104,"Logon by CORP\fadmin from 10.7.7.7"')
            $planted = @('S-1-5-21-111-222-333-1104','CORP\fadmin','10.7.7.7')
            $preserve = @('2025-01-01T00:00:00Z')
        }
        'Text' {
            $ext = 'txt'; $scrubProfile = 'Text'
            $lines = @('Contact gharris@corp.local at 10.8.8.8 or visit files.corp.local')
            $planted = @('gharris@corp.local','10.8.8.8','files.corp.local')
        }
        'Json' {
            $ext = 'json'; $scrubProfile = 'Generic'
            $lines = @('{"user":"CORP\\hlee","ip":"10.9.0.1","host":"node.corp.local","ok":true,"count":5}')
            $planted = @('hlee','10.9.0.1','node.corp.local')
            $preserve = @('"count"')
        }
        'IIS' {
            $ext = 'log'; $scrubProfile = 'IIS'; $preConvert = 'W3C'
            $lines = @('#Software: Microsoft Internet Information Services 10.0',
                       '#Fields: date time c-ip cs-username cs-host cs-uri-stem sc-status',
                       '2025-01-01 00:00:00 10.10.0.1 CORP\iuser intranet.corp.local /home 200')
            $planted = @('10.10.0.1','CORP\iuser','intranet.corp.local')
            $preserve = @('2025-01-01')
        }
        default {
            $ext = 'txt'; $scrubProfile = 'Text'
            $lines = @('user test@corp.local ip 10.0.0.9 host generic.corp.local')
            $planted = @('test@corp.local','10.0.0.9','generic.corp.local')
        }
    }
    $path = Join-Path $Dir ("$stem.$ext")
    ($lines -join "`r`n") | Set-Content -Path $path -Encoding UTF8
    return [pscustomobject]@{ Path = $path; ScrubProfile = $scrubProfile; Planted = $planted; Preserve = $preserve; PreConvert = $preConvert }
}

function Invoke-ScrubSelfTest {
    [CmdletBinding()]
    param([switch]$KeepFiles)
    Write-Banner ">_ ULS  v$script:ModuleVersion" "   self-test  ::  synthetic data only  ::  no real logs touched"
    $prevSalt = $script:Salt; $prevLen = $script:HmacLength; $prevAllowed = $script:AllowedDomains; $prevPolicy = $script:ScrubPolicy
    $script:Salt = 'selftest-fixed-salt'; $script:HmacLength = 16; $script:AllowedDomains = @($script:AllowedDomainsDefault)
    $script:__stPass = 0; $script:__stFail = 0
    $assert = {
        param($cond, $msg)
        if ($cond) { Write-Ok $msg; $script:__stPass++ } else { Write-Fail $msg; $script:__stFail++ }
    }
    $reset = { $script:TokenByNorm = @{}; $script:TokenMapCacheKey = $null }
    function New-UlsSelfTestZip {
        param(
            [Parameter(Mandatory)][string]$Path,
            [Parameter(Mandatory)][hashtable]$Entries
        )
        try { Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop } catch { }
        try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }
        if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue }
        $zip = [System.IO.Compression.ZipFile]::Open($Path, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($entryName in @($Entries.Keys)) {
                $entry = $zip.CreateEntry([string]$entryName)
                $stream = $entry.Open()
                $writer = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::UTF8)
                try { $writer.Write([string]$Entries[$entryName]) }
                finally { $writer.Dispose(); $stream.Dispose() }
            }
        }
        finally { $zip.Dispose() }
        return $Path
    }
    function Test-UlsSelfTestDelimitedFilesEqual {
        param(
            [Parameter(Mandatory)][string]$Left,
            [Parameter(Mandatory)][string]$Right,
            [string]$Delimiter = ','
        )
        $leftReader = New-Object System.IO.StreamReader($Left, [System.Text.Encoding]::UTF8, $true)
        $rightReader = New-Object System.IO.StreamReader($Right, [System.Text.Encoding]::UTF8, $true)
        try {
            while ($true) {
                $leftRow = Read-UlsDelimitedRecord -Reader $leftReader -Delimiter $Delimiter
                $rightRow = Read-UlsDelimitedRecord -Reader $rightReader -Delimiter $Delimiter
                if ($null -eq $leftRow -and $null -eq $rightRow) { return $true }
                if ($null -eq $leftRow -or $null -eq $rightRow) { return $false }
                if ($leftRow.Count -ne $rightRow.Count) { return $false }
                for ($i = 0; $i -lt $leftRow.Count; $i++) {
                    if (-not [string]::Equals([string]$leftRow[$i], [string]$rightRow[$i], [System.StringComparison]::Ordinal)) { return $false }
                }
            }
        }
        finally {
            try { $leftReader.Close() } catch { }
            try { $rightReader.Close() } catch { }
        }
    }
    $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("scrubtest_" + ([System.IO.Path]::GetRandomFileName().Replace('.', '')))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    try {
        # ---- 0) Static module guardrails ----
        Write-Rule "Module guardrails"
        $modulePath = $null
        if ($PSCommandPath -and ([System.IO.Path]::GetExtension($PSCommandPath) -ieq '.psm1')) { $modulePath = $PSCommandPath }
        try {
            if (-not $modulePath -and $MyInvocation.MyCommand.Module -and $MyInvocation.MyCommand.Module.Path) {
                $candidate = $MyInvocation.MyCommand.Module.Path
                if ([System.IO.Path]::GetExtension($candidate) -ieq '.psm1') { $modulePath = $candidate }
                elseif ([System.IO.Path]::GetExtension($candidate) -ieq '.psd1') {
                    $candidateModule = Join-Path (Split-Path -Parent $candidate) 'UniversalLogScrubber.psm1'
                    if (Test-Path -LiteralPath $candidateModule) { $modulePath = $candidateModule }
                }
            }
        } catch { }
        if (-not $modulePath) { $modulePath = Join-Path $PSScriptRoot 'UniversalLogScrubber.psm1' }
        & $assert ((Split-Path -Leaf $modulePath) -eq 'UniversalLogScrubber.psm1') "self-test is running against the release module file"
        $moduleText = if ($modulePath -and (Test-Path -LiteralPath $modulePath)) { [System.IO.File]::ReadAllText($modulePath) } else { '' }
        $guardTokens = $null; $guardErrors = $null
        $guardAst = [System.Management.Automation.Language.Parser]::ParseInput($moduleText, [ref]$guardTokens, [ref]$guardErrors)
        & $assert ($guardErrors.Count -eq 0) "module parses without static errors"
        $duplicateFunctions = @($guardAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | Group-Object Name | Where-Object { $_.Count -gt 1 })
        & $assert ($duplicateFunctions.Count -eq 0) "module has no duplicate function definitions"
        & $assert (("  >_ ULS  v$script:ModuleVersion").Length -le ($script:UiWidth - 2)) "compact banner title fits configured width"
        & $assert (("     map first  ::  scrub second  ::  verify before upload").Length -le ($script:UiWidth - 2)) "compact banner subtitle fits configured width"
        & $assert (("     self-test  ::  synthetic data only  ::  no real logs touched").Length -le ($script:UiWidth - 2)) "compact self-test banner subtitle fits configured width"
        try {
            Write-UlsProgress -Activity 'Self-test progress' -Phase 'compact' -File 'sample.csv' -RowsDone 1 -RowsTotal 2 -Workers 2 -Pending 1 -Ready 0 -Force
            Write-UlsProgress -Activity 'Self-test progress stale' -Phase 'old' -RowsDone 1 -Force
            & $assert ($script:UlsProgressState.ContainsKey('Self-test progress stale')) "compact progress helper records active state"
            Write-UlsProgress -Activity 'Self-test progress stale' -Reset
            & $assert (-not $script:UlsProgressState.ContainsKey('Self-test progress stale')) "compact progress helper reset clears stale state"
            Write-UlsProgress -Activity 'Self-test progress' -Completed
            & $assert $true "compact progress helper accepts short status inputs"
        }
        catch { & $assert $false "compact progress helper accepts short status inputs" }

        # ---- 1) Local recommendation mode (no salt required) ----
        Write-Rule "Log format recommendations"
        $recDir = Join-Path $dir 'recommendations'
        New-Item -ItemType Directory -Path $recDir -Force | Out-Null
        $recSpecs = @(
            [pscustomobject]@{ Name='adcs'; Ext='csv'; ExpectedFormat='CSV'; ExpectedProfile='CA'; Lines=@('RequestID,CertificateTemplate,CertSubject,CertIssuer,ESC1Candidate','1,UserTemplate,"CN=Alice","CN=Corp-CA",true') },
            [pscustomobject]@{ Name='windows-event'; Ext='csv'; ExpectedFormat='Windows Event CSV'; ExpectedProfile='WindowsEventCsv'; Lines=@('ProviderName,LevelDisplayName,RecordId,MachineName,TimeCreated,Message','Microsoft-Windows-Security-Auditing,Information,1001,host01,2026-01-01T00:00:00Z,user alice logged on') },
            [pscustomobject]@{ Name='table'; Ext='tsv'; ExpectedFormat='TSV'; ExpectedProfile='Tsv'; Lines=@("time`tuser`thost","2026-01-01`talice`tapp01") },
            [pscustomobject]@{ Name='pipe'; Ext='psv'; ExpectedFormat='PSV'; ExpectedProfile='Psv'; Lines=@('time|user|host','2026-01-01|alice|app01') },
            [pscustomobject]@{ Name='object'; Ext='json'; ExpectedFormat='JSON'; ExpectedProfile='Generic'; Lines=@('{"ok":true,"count":1}') },
            [pscustomobject]@{ Name='stream'; Ext='jsonl'; ExpectedFormat='JSON Lines / NDJSON'; ExpectedProfile='Generic'; Lines=@('{"ok":true,"count":1}','{"ok":false,"count":2}') },
            [pscustomobject]@{ Name='iis'; Ext='log'; ExpectedFormat='W3C/IIS'; ExpectedProfile='IIS'; Lines=@('#Software: Microsoft Internet Information Services 10.0','#Fields: date time c-ip cs-username cs-host cs-uri-stem sc-status','2026-01-01 00:00:00 10.0.0.1 CORP\alice intranet.corp.local /home 200') },
            [pscustomobject]@{ Name='cef'; Ext='log'; ExpectedFormat='CEF'; ExpectedProfile='Cef'; Lines=@('CEF:0|Vendor|Product|1.0|100|Login|5|src=10.0.0.1 suser=alice shost=app01') },
            [pscustomobject]@{ Name='kv'; Ext='log'; ExpectedFormat='logfmt / key=value'; ExpectedProfile='Logfmt'; Lines=@('time=2026-01-01T00:00:00Z level=info user=alice host=app01') },
            [pscustomobject]@{ Name='firewall-text'; Ext='log'; ExpectedFormat='Firewall/VPN text'; ExpectedProfile='Firewall'; Lines=@('2026-01-01T00:00:00Z firewall policy=Allow-VPN action=allow src_ip=10.40.1.10 dst_ip=10.40.2.20 src_user=CORP\alice dst_host=vpn-gw01.corp.local proto=tcp') },
            [pscustomobject]@{ Name='firewall-csv'; Ext='csv'; ExpectedFormat='Firewall CSV export'; ExpectedProfile='FirewallCsv'; Lines=@('Time,Action,Rule,SourceIP,DestinationIP,SourceUser,DestinationHost,Protocol','2026-01-01T00:00:00Z,allow,VPN-Users,10.40.1.10,10.40.2.20,CORP\alice,vpn-gw01.corp.local,tcp') },
            [pscustomobject]@{ Name='apache'; Ext='log'; ExpectedFormat='Apache/Nginx access log'; ExpectedProfile='Apache'; Lines=@('10.0.0.1 - alice [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "curl/8.0"') },
            [pscustomobject]@{ Name='servicenow'; Ext='csv'; ExpectedFormat='ServiceNow export'; ExpectedProfile='ServiceNow'; Lines=@('sys_id,number,short_description,work_notes,caller_id,assigned_to,cmdb_ci,sys_created_on','abc123,INC001,VPN issue,"caller alice from 10.1.1.1",alice@corp.local,CORP\bob,host01.corp.local,2026-01-01T00:00:00Z') },
            [pscustomobject]@{ Name='nexthink'; Ext='csv'; ExpectedFormat='Nexthink export'; ExpectedProfile='Nexthink'; Lines=@('device_uid,device_name,user_name,binary_name,remote_action,execution_status,collector','dev-001,laptop01,alice,notepad.exe,cleanup,success,collector01') },
            [pscustomobject]@{ Name='sccm'; Ext='csv'; ExpectedFormat='SCCM/MECM export'; ExpectedProfile='Sccm'; Lines=@('ResourceID,SMSUniqueIdentifier,Name0,User_Name0,CollectionID,DeploymentID,SiteCode','1001,SMS-abc,WIN10-001,alice,COL00001,DEP00001,P01') },
            [pscustomobject]@{ Name='sccm-text'; Ext='log'; ExpectedFormat='SCCM/ConfigMgr client text'; ExpectedProfile='SccmText'; Lines=@('<![LOG[Successfully processed deployment for user alice@corp.local on client SCCM-LAPTOP-01 IP 10.41.1.10]LOG]!><time="12:00:00.000+000" date="01-01-2026" component="ExecMgr" context="" type="1" thread="1001" file="execmgr.cpp:123">') },
            [pscustomobject]@{ Name='intune'; Ext='csv'; ExpectedFormat='Intune export'; ExpectedProfile='Intune'; Lines=@('managedDeviceName,userPrincipalName,azureADDeviceId,complianceState,managementAgent,enrolledDateTime,deviceEnrollmentType','LAPTOP-01,alice@corp.local,11112222-3333-4444-5555-666677778888,compliant,mdm,2026-01-01T00:00:00Z,windowsAzureADJoin') },
            [pscustomobject]@{ Name='intune-diagnostics'; Ext='reg'; ExpectedFormat='Intune Diagnostics text/report'; ExpectedProfile='IntuneDiagnostics'; Lines=@('Windows Registry Editor Version 5.00','[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\{11112222-3333-4444-5555-666677778888}]','"UPN"="diag.user@corp.local"','"Provider"="DeviceManagement-Enterprise-Diagnostics-Provider"','"PolicyManager"="MDM policy source"') },
            [pscustomobject]@{ Name='m365-audit'; Ext='csv'; ExpectedFormat='M365/identity audit export'; ExpectedProfile='IdentityProvider'; Lines=@('CreationTime,UserId,Operation,Workload,ClientIP,ActorIpAddress,DeviceName','2026-01-01T00:00:00Z,alice@corp.local,UserLoggedIn,AzureActiveDirectory,10.42.1.10,10.42.1.10,AAD-LAPTOP-01') },
            [pscustomobject]@{ Name='sentinel-jsonl'; Ext='jsonl'; ExpectedFormat='JSON Lines / NDJSON'; ExpectedProfile='CloudAudit'; Lines=@('{"incidentNumber":"1234","incidentUrl":"https://portal.azure.com/incidents/1234","owner":{"assignedTo":"analyst@corp.local"},"alerts":[{"entities":[{"hostName":"sentinel-host01.corp.local","address":"10.43.1.10"}]}]}') },
            [pscustomobject]@{ Name='edr-jsonl'; Ext='jsonl'; ExpectedFormat='JSON Lines / NDJSON'; ExpectedProfile='Edr'; Lines=@('{"alert_id":"edr-1234","device_name":"edr-host01.corp.local","user_email":"alice@corp.local","process_path":"C:\\Users\\alice\\malware.exe","remote_ip":"10.44.1.10","remote_domain":"c2.corp.local","sha256":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}') },
            [pscustomobject]@{ Name='etl'; Ext='etl'; ExpectedFormat='ETL trace'; ExpectedProfile='Generic'; Lines=@('Synthetic ETL placeholder used only for detection; conversion is opt-in.') },
            [pscustomobject]@{ Name='plain'; Ext='txt'; ExpectedFormat='Generic text'; ExpectedProfile='Text'; Lines=@('plain diagnostic text with no structured delimiter') }
        )
        $recSalt = $script:Salt
        $script:Salt = $null
        try {
            foreach ($spec in $recSpecs) {
                $recPath = Join-Path $recDir ("{0}.{1}" -f $spec.Name, $spec.Ext)
                $spec.Lines | Set-Content -Path $recPath -Encoding UTF8
                $rec = @(Test-LogFormat -Path $recPath -Quiet | Select-Object -First 1)
                & $assert ($rec.Count -eq 1) "Test-LogFormat [$($spec.Name)] returns one object"
                if ($rec.Count -eq 1) {
                    & $assert ($rec[0].DetectedFormat -eq $spec.ExpectedFormat) "Test-LogFormat [$($spec.Name)] detects $($spec.ExpectedFormat)"
                    & $assert ($rec[0].SuggestedProfile -eq $spec.ExpectedProfile) "Test-LogFormat [$($spec.Name)] suggests $($spec.ExpectedProfile)"
                    & $assert (-not [string]::IsNullOrWhiteSpace($rec[0].RecommendedCommand)) "Test-LogFormat [$($spec.Name)] includes command"
                    if ($spec.Name -eq 'etl') {
                        & $assert ($rec[0].RecommendedCommand -match '-ConvertEtl') "Test-LogFormat [etl] recommends explicit conversion switch"
                        & $assert (($rec[0].Warnings -join ' ') -match 'opt-in') "Test-LogFormat [etl] warns conversion is opt-in"
                    }
                }
            }
            $officeDir = Join-Path $dir 'office'
            New-Item -ItemType Directory -Path $officeDir -Force | Out-Null
            $docxPath = Join-Path $officeDir 'office-sample.docx'
            [void](New-UlsSelfTestZip -Path $docxPath -Entries @{
                '[Content_Types].xml' = '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>'
                'word/document.xml' = '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>docx.user@corp.local</w:t></w:r></w:p><w:p><w:r><w:t>docx-host.corp.local</w:t></w:r></w:p></w:body></w:document>'
                'word/comments.xml' = '<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:comment><w:p><w:r><w:t>comment secret docx-token-123</w:t></w:r></w:p></w:comment></w:comments>'
            })
            $pptxPath = Join-Path $officeDir 'office-sample.pptx'
            [void](New-UlsSelfTestZip -Path $pptxPath -Entries @{
                '[Content_Types].xml' = '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>'
                'ppt/slides/slide1.xml' = '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>pptx.user@corp.local</a:t></a:r></a:p><a:p><a:r><a:t>pptx-host.corp.local</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>'
                'ppt/notesSlides/notesSlide1.xml' = '<p:notes xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>speaker note private-token</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:notes>'
            })
            foreach ($officeSpec in @(
                [pscustomobject]@{ Path=$docxPath; Format='DOCX'; Profile='Text'; Converter='Docx'; Needle='docx.user@corp.local' },
                [pscustomobject]@{ Path=$pptxPath; Format='PPTX'; Profile='Text'; Converter='Pptx'; Needle='pptx.user@corp.local' }
            )) {
                $officeRec = @(Test-LogFormat -Path $officeSpec.Path -Quiet | Select-Object -First 1)
                & $assert ($officeRec.Count -eq 1 -and $officeRec[0].DetectedFormat -eq $officeSpec.Format -and $officeRec[0].SuggestedProfile -eq $officeSpec.Profile) "Test-LogFormat [$($officeSpec.Format)] recommends Text"
                $officeTextPath = Join-Path $officeDir ("converted-{0}.txt" -f $officeSpec.Converter.ToLowerInvariant())
                if ($officeSpec.Converter -eq 'Docx') { [void](ConvertFrom-DocxToText -DocxPath $officeSpec.Path -OutText $officeTextPath) }
                else { [void](ConvertFrom-PptxToText -PptxPath $officeSpec.Path -OutText $officeTextPath) }
                $officeText = Get-Content -Path $officeTextPath -Raw
                & $assert ($officeText -match [regex]::Escape($officeSpec.Needle)) "$($officeSpec.Format) converter extracts body/slide text"
                $officeRun = Invoke-UniversalScrubber -Path $officeSpec.Path -WorkDir (Join-Path $officeDir ("office-run-" + $officeSpec.Converter.ToLowerInvariant())) -Profile Text -Salt 'selftest-fixed-salt' -MapSource Discover -TokenMapMode Replace -SkipLeakCheck -NonInteractive
                $officeOutText = Get-Content -Path $officeRun[0].Output -Raw
                & $assert (-not ($officeOutText -match [regex]::Escape($officeSpec.Needle))) "$($officeSpec.Format) intake scrubs converted text"
            }
            'Generated artifact placeholder' | Set-Content -Path (Join-Path $recDir 'old_scrubbed.log') -Encoding UTF8
            'Generated artifact placeholder' | Set-Content -Path (Join-Path $recDir 'scrub_token_map_DO_NOT_UPLOAD.csv') -Encoding UTF8
            'Generated artifact placeholder' | Set-Content -Path (Join-Path $recDir 'safe-upload.zip') -Encoding UTF8
            $allRecs = @(Test-LogFormat -Path $recDir -Recurse -Quiet)
            & $assert ($allRecs.Count -eq $recSpecs.Count) "Test-LogFormat folder scan works without salt and skips generated artifacts"
            $recommend = @(Invoke-UniversalScrubber -Path $recDir -Recurse -RecommendOnly -NonInteractive)
            & $assert ($recommend.Count -eq $recSpecs.Count) "RecommendOnly exits before salt is required"
            $safeFirst = @(Invoke-UniversalScrubber -Path $recDir -Recurse -SafeFirstRun -NonInteractive)
            & $assert ($safeFirst.Count -eq $recSpecs.Count) "SafeFirstRun exits before salt is required"
            $etlRunRefused = $false
            try {
                [void](Invoke-UniversalScrubber -Path (Join-Path $recDir 'etl.etl') -WorkDir (Join-Path $recDir 'etl-out') -Salt 'selftest-fixed-salt' -NonInteractive)
            }
            catch { $etlRunRefused = ($_.Exception.Message -match 'requires -ConvertEtl') }
            & $assert $etlRunRefused "ETL input refuses conversion unless -ConvertEtl is supplied"
            $etlMissingTracerpt = $false
            try {
                [void](ConvertFrom-EtlToCsv -EtlPath (Join-Path $recDir 'etl.etl') -OutCsv (Join-Path $recDir 'etl.csv') -TracerptPath (Join-Path $recDir 'missing-tracerpt.exe'))
            }
            catch { $etlMissingTracerpt = ($_.Exception.Message -match 'tracerpt\.exe was not found') }
            & $assert $etlMissingTracerpt "ETL converter reports missing tracerpt.exe clearly"
        }
        finally { $script:Salt = $recSalt }

        # ---- 3) Enterprise export profiles ----
        Write-Rule "Enterprise export profiles"
        $enterpriseDir = Join-Path $dir 'enterprise'
        New-Item -ItemType Directory -Path $enterpriseDir -Force | Out-Null
        $enterpriseSpecs = @(
            [pscustomobject]@{
                Profile='ServiceNow'; Lines=@(
                    'number,sys_id,state,priority,caller_id,assigned_to,cmdb_ci,work_notes,sys_created_on',
                    '"INC0010001","abc123def456","Closed","2","alice@corp.local","CORP\bob","app01.corp.local","caller alice from 10.31.1.10 visited https://snow-private.corp.local/task","2026-01-01T00:00:00Z"'
                )
                Preserve=@('INC0010001','Closed','2','2026-01-01T00:00:00Z')
                Remove=@('alice@corp.local','CORP\bob','app01.corp.local','10.31.1.10','snow-private.corp.local')
            },
            [pscustomobject]@{
                Profile='Nexthink'; Lines=@(
                    'timestamp,device_uid,device_name,user_name,destination,binary_name,execution_status,comment',
                    '"2026-01-01T00:00:00Z","dev-001","laptop01.corp.local","alice@corp.local","cache01.corp.local","agent.exe","success","remote action from 10.31.2.10"'
                )
                Preserve=@('2026-01-01T00:00:00Z','success','agent.exe')
                Remove=@('dev-001','laptop01.corp.local','alice@corp.local','cache01.corp.local','10.31.2.10')
            },
            [pscustomobject]@{
                Profile='Sccm'; Lines=@(
                    'ResourceID,SMSUniqueIdentifier,Name0,User_Name0,CollectionID,DeploymentID,SiteCode,IPAddress0,MAC_Addresses0,SerialNumber0',
                    '"1001","SMS-abc","WIN10-001.corp.local","CORP\charlie","COL00001","DEP00001","P01","10.31.3.10","00:11:22:33:44:55","ABC123SERIAL"'
                )
                Preserve=@('1001','COL00001','DEP00001','P01')
                Remove=@('WIN10-001.corp.local','CORP\charlie','10.31.3.10','00:11:22:33:44:55','ABC123SERIAL')
            },
            [pscustomobject]@{
                Profile='Intune'; Lines=@(
                    'managedDeviceName,userPrincipalName,azureADDeviceId,complianceState,managementAgent,enrolledDateTime,serialNumber,wiFiMacAddress,ipAddress',
                    '"LAPTOP-02.corp.local","delta@corp.local","11112222-3333-4444-5555-666677778888","compliant","mdm","2026-01-01T00:00:00Z","SERIAL98765","66:55:44:33:22:11","10.31.4.10"'
                )
                Preserve=@('compliant','mdm','2026-01-01T00:00:00Z')
                Remove=@('LAPTOP-02.corp.local','delta@corp.local','11112222-3333-4444-5555-666677778888','SERIAL98765','66:55:44:33:22:11','10.31.4.10')
            }
        )
        foreach ($es in $enterpriseSpecs) {
            & $reset
            $enterprisePath = Join-Path $enterpriseDir ("{0}.csv" -f $es.Profile)
            $es.Lines | Set-Content -Path $enterprisePath -Encoding UTF8
            $enterpriseOutDir = Join-Path $enterpriseDir ("out-" + $es.Profile)
            $enterpriseRun = Invoke-UniversalScrubber -Path $enterprisePath -WorkDir $enterpriseOutDir -Profile $es.Profile -Salt 'selftest-fixed-salt' -MapSource Discover -TokenMapMode Replace -ScrubPolicy Balanced -SkipLeakCheck -NonInteractive
            $enterpriseText = Get-Content -Path $enterpriseRun[0].Output -Raw
            foreach ($keep in @($es.Preserve)) { & $assert ($enterpriseText -match [regex]::Escape($keep)) "[$($es.Profile)] preserved metadata: $keep" }
            foreach ($gone in @($es.Remove)) { & $assert (-not ($enterpriseText -match [regex]::Escape($gone))) "[$($es.Profile)] removed sensitive value: $gone" }
        }
        & $reset
        $diagPath = Join-Path $enterpriseDir 'IntuneDiagnostics.log'
        @(
            'IntuneManagementExtension PolicyManager MDM DeviceEnrollment diagnostic report',
            'UPN: diag.user@corp.local',
            'Device Name: diag-laptop.corp.local',
            'Serial Number: DIAGSERIAL12345',
            'Profile path HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-111-222-333-1001',
            'Client IP Address: 10.31.5.10',
            'Status: Completed Result: 0x0'
        ) | Set-Content -Path $diagPath -Encoding UTF8
        $diagRun = Invoke-UniversalScrubber -Path $diagPath -WorkDir (Join-Path $enterpriseDir 'out-IntuneDiagnostics') -Profile IntuneDiagnostics -Salt 'selftest-fixed-salt' -MapSource Discover -TokenMapMode Replace -ScrubPolicy Balanced -SkipLeakCheck -NonInteractive
        $diagText = Get-Content -Path $diagRun[0].Output -Raw
        foreach ($keep in @('IntuneManagementExtension','PolicyManager','MDM','Completed','0x0')) { & $assert ($diagText -match [regex]::Escape($keep)) "[IntuneDiagnostics] preserved diagnostic context: $keep" }
        foreach ($gone in @('diag.user@corp.local','diag-laptop.corp.local','DIAGSERIAL12345','S-1-5-21-111-222-333-1001','10.31.5.10')) { & $assert (-not ($diagText -match [regex]::Escape($gone))) "[IntuneDiagnostics] removed sensitive value: $gone" }

        # ---- 3) One planted fixture per profile ----
        Write-Rule "Per-profile fixtures"
        foreach ($pol in @('Balanced','Strict')) {
            $script:ScrubPolicy = $pol
            foreach ($pn in @('Generic','CA','Tsv','Psv','Syslog','Apache','Cef','Logfmt','WindowsEventCsv','Text','Json','IIS')) {
                try {
                    & $reset
                    $fx = New-SyntheticLog -Profile $pn -Dir $dir -Name ("{0}_{1}" -f $pol, $pn)
                    $scrubPath = $fx.Path
                    if ($fx.PreConvert -eq 'W3C') {
                        $scrubPath = ConvertFrom-W3CToCsv -LogPath $fx.Path -OutCsv (Join-Path $dir ("${pol}_${pn}.w3c.csv"))
                    }
                    $map = Join-Path $dir ("map_${pol}_${pn}_DO_NOT_UPLOAD.csv")
                    [void](New-ScrubTokenMap -InputPath @($scrubPath) -TokenMapCsv $map -ScrubPolicy $pol)
                    $out = Join-Path $dir ("${pol}_${pn}_scrubbed" + [System.IO.Path]::GetExtension($scrubPath))
                    $res = Invoke-ScrubFile -InputPath $scrubPath -OutputPath $out -Profile (Get-ScrubProfile -Name $fx.ScrubProfile) -ScrubPolicy $pol
                    $txt = Get-Content -Path $res.Output -Raw
                    & $assert ($res.Clean) "[$pol/$pn] leak check clean"
                    foreach ($p in $fx.Planted) { & $assert (-not ($txt -match [regex]::Escape($p))) "[$pol/$pn] removed: $p" }
                    foreach ($k in $fx.Preserve) { & $assert ($txt -match [regex]::Escape($k)) "[$pol/$pn] preserved: $k" }
                }
                catch { Write-Fail "[$pol/$pn] fixture error: $($_.Exception.Message)"; $script:__stFail++ }
            }
        }

        # ---- 2) Detector matrix (one of each, hardened directly) ----
        Write-Rule "Detector matrix"
        & $reset
        $det = @(
            'ipv4=10.20.30.40',
            'ipv6=2001:0db8:0000:0000:0000:ff00:0042:8329',
            'mac=00:11:22:33:44:55',
            'email=tuser@corp.local',
            'dom=CORP\tdom',
            'fqdn=host.corp.local',
            'sid=S-1-5-21-9-8-7-1234',
            'correlation id: 11112222-3333-4444-5555-666677778888',
            'jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N',
            'arn=arn:aws:iam::123456789012:user/testuser',
            'awskey=AKIAIOSFODNN7EXAMPLE',
            'instance=i-0abcdef1234567890',
            'unc=\\fileserver01\share\report',
            'url=https://admin@intranet.corp.local:8443/secure',
            'b64=U2VsZlRlc3RCYXNlNjRCbG9iVmFsdWUwMTIzNDU2Nzg5QUJDREVGYWJjZGVm',
            'keep=download.microsoft.com',
            'oid=1.3.6.1.4.1.311.20.2.2'
        ) -join "`n"
        $dh = Invoke-FreeTextHardening -ColumnName 'detector' -Value $det
        $mustGo = [ordered]@{
            'IPv4' = '10.20.30.40'; 'IPv6' = 'ff00:0042:8329'; 'MAC' = '00:11:22:33:44:55'
            'Email' = 'tuser@corp.local'; 'DOMAIN\user' = 'CORP\tdom'; 'FQDN' = 'host.corp.local'
            'SID' = 'S-1-5-21-9-8-7-1234'; 'GUID' = '11112222-3333'; 'JWT' = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
            'ARN' = '123456789012'; 'AWSKey' = 'AKIAIOSFODNN7EXAMPLE'; 'InstanceId' = 'i-0abcdef1234567890'
            'UNC host' = 'fileserver01'; 'URL host' = 'intranet.corp.local'; 'Base64' = 'U2VsZlRlc3RCYXNlNjQ'
        }
        foreach ($k in $mustGo.Keys) { & $assert (-not ($dh -match [regex]::Escape($mustGo[$k]))) "detector removed: $k" }
        & $assert ($dh -match 'download\.microsoft\.com') "detector kept allowlisted domain"
        & $assert ($dh -match '1\.3\.6\.1\.4\.1\.311\.20\.2\.2') "detector kept OID"

        # ---- 3) v4.13 JSON numeric and connection URI regression ----
        Write-Rule "v4.13 JSON numeric and connection URI detection"
        & $reset
        $jsonNumeric = '{"userId":123456,"traceId":987654,"count":5,"statusCode":200,"serverPort":443,"ok":true}'
        $jsonNumericOut = Invoke-ScrubJsonText -Text $jsonNumeric -Profile (Get-ScrubProfile -Name Generic)
        $jsonNumericObj = $jsonNumericOut | ConvertFrom-Json
        & $assert ([string]$jsonNumericObj.userId -match '^PRINCIPAL_[A-F0-9]+$') "JSON sensitive numeric userId is scrubbed"
        & $assert ([string]$jsonNumericObj.traceId -match '^OBJECT_[A-F0-9]+$') "JSON sensitive numeric traceId is scrubbed"
        & $assert ([int]$jsonNumericObj.count -eq 5) "JSON benign count number is preserved"
        & $assert ([int]$jsonNumericObj.statusCode -eq 200) "JSON benign statusCode number is preserved"
        & $assert ([int]$jsonNumericObj.serverPort -eq 443) "JSON benign serverPort number is preserved"

        $conn = 'jdbc:postgresql://appuser@db01.corp.local:5432/app redis://cache01.corp.local:6379/0 wss://gateway.corp.local/socket kafka://broker01.corp.local:9092'
        $connOut = Invoke-FreeTextHardening -ColumnName 'connectionString' -Value $conn
        foreach ($gone in @('db01.corp.local','cache01.corp.local','gateway.corp.local','broker01.corp.local')) {
            & $assert (-not ($connOut -match [regex]::Escape($gone))) "connection URI host removed: $gone"
        }
        foreach ($scheme in @('jdbc:postgresql://','redis://','wss://','kafka://')) {
            & $assert ($connOut -match [regex]::Escape($scheme)) "connection URI scheme preserved: $scheme"
        }

        # ---- 4) Windows Event false-positive regression ----
        Write-Rule "Windows Event balanced readability"
        $script:ScrubPolicy = 'Balanced'
        & $reset
        $wer = 'Attached files: \\?\C:\WINDOWS\LiveKernelReports\WHEA\WHEA-20260626-2110.dmp \\?\C:\ProgramData\Microsoft\Windows\WER\Temp\WER.682fc5f3-023d-4e3b-b8de-cbf1960a500b.tmp.WERInternalMetadata.xml app=svchost.exe pkg=Microsoft.Windows.ShellExperienceHost ts=39.043137100Z path=C:\Users\Alice\AppData\Local host=host.corp.local user=CORP\jdoe sid=S-1-5-21-1-2-3-1001 ip=10.44.55.66 unc=\\fileserver01\share url=https://admin@portal.corp.local/path'
        $wh = Invoke-FreeTextHardening -ColumnName 'Message' -Value $wer
        foreach ($keep in @('C:\WINDOWS\LiveKernelReports','C:\ProgramData\Microsoft\Windows\WER\Temp','WHEA-20260626-2110.dmp','WER.682fc5f3-023d-4e3b-b8de-cbf1960a500b.tmp.WERInternalMetadata.xml','svchost.exe','Microsoft.Windows.ShellExperienceHost','39.043137100Z')) {
            & $assert ($wh -match [regex]::Escape($keep)) "WindowsEvent preserved: $keep"
        }
        foreach ($gone in @('Alice','host.corp.local','CORP\jdoe','S-1-5-21-1-2-3-1001','10.44.55.66','fileserver01','portal.corp.local')) {
            & $assert (-not ($wh -match [regex]::Escape($gone))) "WindowsEvent removed: $gone"
        }
        & $assert ($wh -match '\\\?\\C:\\WINDOWS\\LiveKernelReports\\WHEA\\') "WindowsEvent path separators preserved"

        $wePath = Join-Path $dir 'windows-event-v414.csv'
        @(
            'RecordId,TimeCreated,ProviderName,MachineName,UserId,EventDataJson,Message',
            '101,2026-01-01T00:00:00Z,Microsoft-Windows-Security-Auditing,WINHOST01,S-1-5-18,"{""SubjectUserSid"":""S-1-5-18"",""TargetUserName"":""realuser"",""IpAddress"":""10.12.13.14"",""ProviderGuid"":""{11112222-3333-4444-5555-666677778888}""}","Account Name: realuser Account Domain: CORP SubjectUserSid: S-1-5-18 TargetSid: S-1-5-21-1-2-3-1001 Address: 10.12.13.14 Provider {11112222-3333-4444-5555-666677778888} pos 01FF:0038:0268"'
        ) | Set-Content -Path $wePath -Encoding UTF8
        $weOut = Join-Path $dir 'windows-event-v414-scrubbed.csv'
        $weRes = Invoke-ScrubFile -InputPath $wePath -OutputPath $weOut -Profile (Get-ScrubProfile -Name WindowsEventCsv) -ScrubPolicy Balanced -Stream
        $weText = Get-Content -Path $weRes.Output -Raw
        & $assert ($weRes.Clean -and $weRes.Streamed) "WindowsEventCsv streams and verifies clean"
        foreach ($keep in @('Microsoft-Windows-Security-Auditing','101','2026-01-01T00:00:00Z','S-1-5-18','11112222-3333-4444-5555-666677778888','01FF:0038:0268')) {
            & $assert ($weText -match [regex]::Escape($keep)) "WindowsEventCsv preserved default-readable value: $keep"
        }
        foreach ($gone in @('WINHOST01','realuser','10.12.13.14','S-1-5-21-1-2-3-1001')) {
            & $assert (-not ($weText -match [regex]::Escape($gone))) "WindowsEventCsv removed sensitive value: $gone"
        }
        & $assert ($weText -match 'COMPUTER_[A-F0-9]+') "WindowsEventCsv MachineName uses COMPUTER token"

        $edgeGuid = 'generic guid 99992222-3333-4444-5555-666677778888 and short colon 01FF:0038:0268'
        $script:ScrubPolicy = 'Balanced'
        $edgeBalanced = Invoke-FreeTextHardening -ColumnName 'Message' -Value $edgeGuid
        $script:ScrubPolicy = 'Strict'
        $edgeStrict = Invoke-FreeTextHardening -ColumnName 'Message' -Value $edgeGuid
        $script:ScrubPolicy = 'Balanced'
        & $assert ($edgeBalanced -match '99992222-3333-4444-5555-666677778888' -and $edgeBalanced -match '01FF:0038:0268') "Balanced preserves generic GUID and invalid IPv6-like fragment"
        & $assert (-not ($edgeStrict -match '99992222-3333-4444-5555-666677778888')) "Strict tokenizes generic GUID"

        # ---- 5) BYOP schema v2 and universal detection ----
        Write-Rule "BYOP schema v2 and universal detection"
        $script:ScrubPolicy = 'Balanced'
        & $reset
        $byop = Join-Path $dir 'byop'
        $byopOut = Join-Path $byop 'out'
        New-Item -ItemType Directory -Path $byop -Force | Out-Null
        $seedPath = Join-Path $byop 'seeds.txt'
        $allowPath = Join-Path $byop 'allowlist.txt'
        [System.IO.File]::WriteAllText($seedPath, "# synthetic seed terms`r`nOrchidLabs`r`nORCHIDLABS`r`n", [System.Text.Encoding]::UTF8)
        [System.IO.File]::WriteAllText($allowPath, "# public diagnostic values`r`npublic.example.com`r`nregex:^build-[0-9]+$`r`n", [System.Text.Encoding]::UTF8)
        $profilePath = Join-Path $byop 'profile.json'
        $profileJson = @'
{
  "SchemaVersion": 2,
  "Name": "SelfTestBYOP",
  "Format": "Csv",
  "DenyByDefault": true,
  "SeedFiles": [ "seeds.txt" ],
  "AllowlistFile": [ "allowlist.txt" ],
  "SchemaColumns": [
    { "Exact": "Timestamp", "Action": "PassThrough" },
    { "Exact": "Message", "Action": "Scan" }
  ],
  "WholeColumnRules": [
    { "Exact": "UserID", "Prefix": "PRINCIPAL" },
    { "Exact": "Server", "Prefix": "DNS" },
    { "Exact": "ClientIP", "Prefix": "IP" },
    { "Exact": "APIKey", "Prefix": "SECRET" }
  ],
  "LabelRules": [
    { "Name": "SelfTestLabels", "Labels": [ "username", "host", "API Key", "tenantId", "src_ip" ], "Prefix": "OBJECT" }
  ],
  "CustomRegexRules": [
    {
      "Name": "ProjectId",
      "Regex": "(?i)\\b(project[_ -]?id\\s*[:=]\\s*)(PROJ-[0-9]{4}-[A-Z]{3})\\b",
      "CaptureGroup": 2,
      "Prefix": "OBJECT",
      "Keywords": [ "project", "PROJ-" ],
      "Entropy": 0
    }
  ]
}
'@
        [System.IO.File]::WriteAllText($profilePath, $profileJson, [System.Text.Encoding]::UTF8)
        $byopCsv = Join-Path $byop 'byop.csv'
        @(
            'Timestamp,UserID,Server,ClientIP,APIKey,Message,PublicHost',
            '"2026-01-01T00:00:00Z","alice","app01.internal.test","10.91.1.2","sk-test-synthetic000000000000000000000000","username=bob host: db01.internal.test API Key = local-secret-value tenantId=TenantBlue src_ip=10.91.1.3 project id: PROJ-1234-ABC org OrchidLabs public.example.com build-123","public.example.com"'
        ) | Set-Content -Path $byopCsv -Encoding UTF8
        $byopResults = Invoke-UniversalScrubber -Path $byopCsv -WorkDir $byopOut -ProfileFile $profilePath -Salt 'selftest-fixed-salt' -MapSource Discover -TokenMapMode Replace -NonInteractive
        $byopText = Get-Content -Path $byopResults[0].Output -Raw
        foreach ($gone in @('alice','app01.internal.test','10.91.1.2','sk-test-synthetic','bob','db01.internal.test','local-secret-value','TenantBlue','10.91.1.3','PROJ-1234-ABC','OrchidLabs')) {
            & $assert (-not ($byopText -match [regex]::Escape($gone))) "BYOP removed: $gone"
        }
        foreach ($keep in @('public.example.com','build-123','2026-01-01T00:00:00Z')) {
            & $assert ($byopText -match [regex]::Escape($keep)) "BYOP preserved: $keep"
        }
        $dry = Invoke-UniversalScrubber -Path $byopCsv -WorkDir (Join-Path $byop 'dryrun') -ProfileFile $profilePath -SeedFile $seedPath -AllowlistFile $allowPath -Salt 'selftest-fixed-salt' -MapSource Discover -TokenMapMode Replace -DryRun -NonInteractive
        & $assert ((@($dry) | Select-Object -First 1).DryRun -and ((@($dry) | Select-Object -First 1).ChangeCount -gt 0)) "BYOP dry-run uses profile and seed files"
        $extensionPath = Join-Path $byop 'profile-extension.json'
        $extensionJson = @'
{
  "Name": "SelfTestExtension",
  "Description": "Additive overlay for self-test.",
  "Allowlist": [ "public-extension.example.com" ],
  "SchemaColumns": [
    { "Exact": "ExtStatus", "Action": "PassThrough" }
  ],
  "WholeColumnRules": [
    { "Exact": "CustomAsset", "Prefix": "COMPUTER" }
  ],
  "LabelRules": [
    { "Name": "ExtensionLabels", "Labels": [ "asset owner" ], "Prefix": "PRINCIPAL" }
  ],
  "CustomRegexRules": [
    {
      "Name": "ExtensionCaseId",
      "Regex": "(?i)\\b(case id\\s*[:=]\\s*)(CASE-[0-9]+)\\b",
      "CaptureGroup": 2,
      "Prefix": "OBJECT",
      "Keywords": [ "case id", "CASE-" ],
      "Entropy": 0
    }
  ]
}
'@
        [System.IO.File]::WriteAllText($extensionPath, $extensionJson, [System.Text.Encoding]::UTF8)
        $extension = Import-ScrubProfileExtensionFile -Path $extensionPath
        & $assert ($extension.Name -eq 'SelfTestExtension' -and $extension.WholeColumnRules.Count -eq 1 -and $extension.CustomRegexRules.Count -eq 1) "profile extension imports additive rules"
        $extensionCsv = Join-Path $byop 'extension.csv'
        @(
            'Timestamp,ExtStatus,CustomAsset,Message',
            '"2026-01-01T00:00:00Z","Complete","EXT-LAPTOP-77","asset owner: ext.owner case id: CASE-778899 public-extension.example.com"'
        ) | Set-Content -Path $extensionCsv -Encoding UTF8
        & $reset
        $extensionRun = Invoke-UniversalScrubber -Path $extensionCsv -WorkDir (Join-Path $byop 'extension-out') -Profile Generic -ProfileExtensionFile $extensionPath -Salt 'selftest-fixed-salt' -MapSource Discover -TokenMapMode Replace -NonInteractive
        $extensionText = Get-Content -Path $extensionRun[0].Output -Raw
        foreach ($gone in @('EXT-LAPTOP-77','ext.owner','CASE-778899')) {
            & $assert (-not ($extensionText -match [regex]::Escape($gone))) "profile extension removed: $gone"
        }
        foreach ($keep in @('Complete','public-extension.example.com','2026-01-01T00:00:00Z')) {
            & $assert ($extensionText -match [regex]::Escape($keep)) "profile extension preserved: $keep"
        }
        $oldProfilePath = Join-Path $byop 'profile-v48.json'
        [System.IO.File]::WriteAllText($oldProfilePath, '{"Name":"Compat48","Format":"Csv","ColumnPrefix":[{"Pattern":"(?i)^User$","Prefix":"PRINCIPAL"}],"FreeTextRegex":".*"}', [System.Text.Encoding]::UTF8)
        $oldProfile = Import-ScrubProfileFile -Path $oldProfilePath
        & $assert ($oldProfile.Name -eq 'Compat48' -and $oldProfile.SchemaVersion -eq 1) "BYOP imports v4.8-style profiles"
        $badProfilePath = Join-Path $byop 'profile-bad.json'
        [System.IO.File]::WriteAllText($badProfilePath, '{"Name":"BadProfile","Format":"Csv","CustomRegexRules":[{"Name":"Broken","Regex":"(","Prefix":"OBJECT"}]}', [System.Text.Encoding]::UTF8)
        $badFailed = $false
        try { [void](Import-ScrubProfileFile -Path $badProfilePath) } catch { $badFailed = ($_.Exception.Message -match 'custom regex rule') }
        & $assert $badFailed "BYOP invalid regex reports rule context"

        # ---- 5b) Nexthink CSV header and execution-output regression ----
        Write-Rule "Nexthink CSV header and execution output hardening"
        $script:ScrubPolicy = 'Balanced'
        & $reset
        $nexDir = Join-Path $dir 'nexthink'
        New-Item -ItemType Directory -Path $nexDir -Force | Out-Null
        $nexCsv = Join-Path $nexDir 'nexthink.csv'
        @(
            'device.name,user.email,binary.path,binary.sha256,execution.status,execution.output',
            '"VDI-CALL-0902","marco.silva@northstar.example","C:\Users\marco.silva\AppData\Local\Google\Chrome\Application\chrome.exe","0899cd856fba9b131050135138cd87c5e5222f0a0657b94730901988d5cabdbb","success","Action run by marco.silva@northstar.example on VDI-CALL-0902; traceId=f06be575-39a5-4198-98a0-ce7b7ae8983e"'
        ) | Set-Content -Path $nexCsv -Encoding UTF8
        $nexPathCell = Scrub-Field -ColumnName 'binary.path' -Value 'C:\Users\marco.silva\AppData\Local\Google\Chrome\Application\chrome.exe' -Profile (Get-ScrubProfile -Name Nexthink)
        & $assert (-not ([string]$nexPathCell -match [regex]::Escape('C:\Users\marco.silva'))) "Nexthink binary.path first-pass removes user path segment"
        $nexRun = Invoke-UniversalScrubber -Path $nexCsv -WorkDir (Join-Path $nexDir 'out') -Profile Nexthink -Salt 'selftest-fixed-salt' -MapSource Discover -TokenMapMode Replace -NonInteractive
        $nexResult = @($nexRun)[0]
        $nexText = Get-Content -Path $nexResult.Output -Raw
        $nexHeader = Get-Content -Path $nexResult.Output -TotalCount 1
        & $assert ([bool]$nexResult.Clean) "Nexthink CSV verifies clean without default rehardening"
        & $assert ($nexHeader -match 'device\.name' -and $nexHeader -match 'execution\.output') "Nexthink CSV header names are preserved"
        & $assert (-not ($nexHeader -match '(?:COMPUTER|DNS|PRINCIPAL|OBJECT)_[A-F0-9]+')) "Nexthink CSV header is not tokenized"
        foreach ($gone in @('VDI-CALL-0902','marco.silva@northstar.example','C:\Users\marco.silva','0899cd856fba9b131050135138cd87c5e5222f0a0657b94730901988d5cabdbb','f06be575-39a5-4198-98a0-ce7b7ae8983e')) {
            & $assert (-not ($nexText -match [regex]::Escape($gone))) "Nexthink CSV removed raw value: $gone"
        }
        $nexRow = @(Import-Csv -Path $nexResult.Output)[0]
        & $assert ([string]$nexRow.'device.name' -match '^COMPUTER_[A-F0-9]+$') "Nexthink device column uses COMPUTER token"
        & $assert ([string]$nexRow.'execution.output' -match [regex]::Escape([string]$nexRow.'device.name')) "Nexthink output reuses device token"

        # ---- 5) Sample profile builder ----
        Write-Rule "Sample profile builder"
        $builder = Join-Path $dir 'builder'
        New-Item -ItemType Directory -Path $builder -Force | Out-Null
        $builderSpecs = @(
            [pscustomobject]@{
                Name='csv'; Ext='csv'
                Lines=@(
                    'Timestamp,UserID,Server,ClientIP,APIKey,Message',
                    '"2026-01-01T00:00:00Z","alphauser","csv01.internal.test","10.61.1.2","sk-test-csv000000000000000000000","username=bravo host: csv02.internal.test ticket id: TKT-111222"'
                )
                Raw=@('alphauser','csv01.internal.test','10.61.1.2','sk-test-csv','bravo','csv02.internal.test','TKT-111222')
            },
            [pscustomobject]@{
                Name='json'; Ext='jsonl'
                Lines=@('{"timestamp":"2026-01-01T00:00:00Z","username":"jsonuser","host":"json01.internal.test","src_ip":"10.62.1.2","api_key":"sk-test-json000000000000000000000","message":"tenantId=TenantBlue request id: REQ-222333"}')
                Raw=@('jsonuser','json01.internal.test','10.62.1.2','sk-test-json','TenantBlue','REQ-222333')
            },
            [pscustomobject]@{
                Name='kv'; Ext='log'
                Lines=@('time=2026-01-01T00:00:00Z username=kvuser host=kv01.internal.test src_ip=10.63.1.2 api_key=sk-test-kv000000000000000000000 trace_id=TRC-333444')
                Raw=@('kvuser','kv01.internal.test','10.63.1.2','sk-test-kv','TRC-333444')
            },
            [pscustomobject]@{
                Name='text'; Ext='txt'
                Lines=@('username=textuser host: text01.internal.test src_ip=10.64.1.2 API Key = local-secret-text request id: REQ-444555')
                Raw=@('textuser','text01.internal.test','10.64.1.2','local-secret-text','REQ-444555')
            }
        )
        foreach ($spec in $builderSpecs) {
            $samplePath = Join-Path $builder ("sample_{0}.{1}" -f $spec.Name, $spec.Ext)
            $spec.Lines | Set-Content -Path $samplePath -Encoding UTF8
            $profileOut = Join-Path $builder ("generated_{0}.json" -f $spec.Name)
            $reportOut = Join-Path $builder ("report_{0}_DO_NOT_UPLOAD.md" -f $spec.Name)
            $built = New-ScrubProfileFromSample -Path $samplePath -ProfileOut $profileOut -ProfileReportOut $reportOut -MaxSampleRows 50 -Force -NonInteractive
            & $assert ((Test-Path -LiteralPath $built.ProfilePath) -and (Test-Path -LiteralPath $built.ReportPath)) "profile builder [$($spec.Name)] writes profile and report"
            & $assert (Test-ScrubProfile -Path $built.ProfilePath -Quiet) "profile builder [$($spec.Name)] generated profile imports"
            $profileText = Get-Content -Path $built.ProfilePath -Raw
            foreach ($raw in $spec.Raw) { & $assert (-not ($profileText -match [regex]::Escape($raw))) "profile builder [$($spec.Name)] profile omits raw value: $raw" }
            & $assert (-not (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $built.ProfilePath) 'generated-seeds.txt'))) "profile builder [$($spec.Name)] analyzer-only skips seed file"
            & $assert (-not (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $built.ProfilePath) 'generated-allowlist.txt'))) "profile builder [$($spec.Name)] analyzer-only skips allowlist file"
            $runOut = Join-Path $builder ("out_{0}" -f $spec.Name)
            $bundleOut = Join-Path $builder ("safe_{0}.zip" -f $spec.Name)
            $scrub = Invoke-UniversalScrubber -Path $samplePath -WorkDir $runOut -ProfileFile $built.ProfilePath -Salt 'selftest-fixed-salt' -MapSource Discover -TokenMapMode Replace -SafeBundleOut $bundleOut -Force -NonInteractive
            $scrubText = Get-Content -Path $scrub[0].Output -Raw
            foreach ($raw in $spec.Raw) { & $assert (-not ($scrubText -match [regex]::Escape($raw))) "profile builder [$($spec.Name)] scrub removes: $raw" }
            & $assert ((Test-Path -LiteralPath $bundleOut) -and ((Get-Item -LiteralPath $bundleOut).Length -gt 0)) "safe bundle [$($spec.Name)] created"
        }
        $skipBundleOut = Join-Path $builder 'safe_skip_leak.zip'
        $skipOut = Join-Path $builder 'out_skip_leak'
        $skipRun = Invoke-UniversalScrubber -Path (Join-Path $builder 'sample_csv.csv') -WorkDir $skipOut -ProfileFile (Join-Path $builder 'generated_csv.json') -Salt 'selftest-fixed-salt' -MapSource Discover -TokenMapMode Replace -SkipLeakCheck -SafeBundleOut $skipBundleOut -Force -NonInteractive
        & $assert ([bool](@($skipRun)[0].LeakCheckSkipped)) "safe bundle guard records skipped leak check"
        & $assert (-not (Test-Path -LiteralPath $skipBundleOut)) "safe bundle refuses skipped leak-check output"
        $skipManifest = Get-Content -Path (Join-Path $skipOut 'scrub_run_manifest.json') -Raw | ConvertFrom-Json
        & $assert ([bool](@($skipManifest.scrubbedFiles)[0].leakCheckSkipped)) "manifest records skipped leak check"
        $missingFailed = $false
        try { [void](New-ScrubProfileFromSample -Path (Join-Path $builder 'missing.log') -ProfileOut (Join-Path $builder 'missing.json') -NonInteractive) } catch { $missingFailed = ($_.Exception.Message -match 'Sample path not found') }
        & $assert $missingFailed "profile builder invalid path reports clearly"
        $overwriteFailed = $false
        try { [void](New-ScrubProfileFromSample -Path (Join-Path $builder 'sample_csv.csv') -ProfileOut (Join-Path $builder 'generated_csv.json') -ProfileReportOut (Join-Path $builder 'report_csv_DO_NOT_UPLOAD.md') -NonInteractive) } catch { $overwriteFailed = ($_.Exception.Message -match 'already exists') }
        & $assert $overwriteFailed "profile builder refuses overwrite without -Force"
        $baseProfileOut = Join-Path $builder 'generated_kv_base_extension.json'
        $baseReportOut = Join-Path $builder 'report_kv_base_extension_DO_NOT_UPLOAD.md'
        $builtBase = New-ScrubProfileFromSample -Path (Join-Path $builder 'sample_kv.log') -ProfileOut $baseProfileOut -ProfileReportOut $baseReportOut -BaseProfile Logfmt -ProfileExtensionFile $extensionPath -MaxSampleRows 50 -Force -NonInteractive
        $builtBaseText = Get-Content -Path $builtBase.ProfilePath -Raw
        & $assert (Test-ScrubProfile -Path $builtBase.ProfilePath -Quiet) "profile builder base+extension profile imports"
        & $assert ($builtBaseText -match '"BaseProfile"\s*:\s*"Logfmt"') "profile builder records base profile"
        & $assert ($builtBaseText -match 'SelfTestExtension') "profile builder records extension source"
        & $assert ($builtBaseText -match 'ExtensionCaseId') "profile builder merges extension rules into standalone profile"

        # ---- 6) Streaming vs normal equivalence ----
        Write-Rule "Streaming equivalence"
        $script:ScrubPolicy = 'Balanced'
        $parserPath = Join-Path $dir 'parser-edge-cases.csv'
        $parserLines = @(
            (ConvertTo-UlsDelimitedLine -Values @('A','B','C') -Delimiter ','),
            (ConvertTo-UlsDelimitedLine -Values @('one','comma, here','say "hi"') -Delimiter ','),
            (ConvertTo-UlsDelimitedLine -Values @('two','',"line1`r`nline2") -Delimiter ',')
        )
        [System.IO.File]::WriteAllText($parserPath, (($parserLines -join "`r`n") + "`r`n"), [System.Text.Encoding]::UTF8)
        $parserReader = New-Object System.IO.StreamReader($parserPath, [System.Text.Encoding]::UTF8, $true)
        try {
            $parserHeader = Read-UlsDelimitedRecord -Reader $parserReader -Delimiter ','
            $parserRow1 = Read-UlsDelimitedRecord -Reader $parserReader -Delimiter ','
            $parserRow2 = Read-UlsDelimitedRecord -Reader $parserReader -Delimiter ','
            $parserEnd = Read-UlsDelimitedRecord -Reader $parserReader -Delimiter ','
        }
        finally { $parserReader.Close() }
        & $assert ($parserHeader.Count -eq 3 -and $parserHeader[0] -eq 'A' -and $parserHeader[2] -eq 'C') "fast CSV parser reads header"
        & $assert ($parserRow1[1] -eq 'comma, here' -and $parserRow1[2] -eq 'say "hi"') "fast CSV parser preserves quoted commas and doubled quotes"
        & $assert ($parserRow2[1] -eq '' -and $parserRow2[2] -eq "line1`r`nline2") "fast CSV parser preserves empty and multiline quoted fields"
        & $assert ($null -eq $parserEnd) "fast CSV parser reaches EOF cleanly"
        & $reset
        $sfx = New-SyntheticLog -Profile 'Generic' -Dir $dir -Name 'streamcase'
        $smap = Join-Path $dir 'map_stream_DO_NOT_UPLOAD.csv'
        [void](New-ScrubTokenMap -InputPath @($sfx.Path) -TokenMapCsv $smap)
        $hostTok = (Import-Csv $smap | Where-Object { $_.InputValue -eq 'dc01.corp.local' } | Select-Object -First 1).Token
        $r1 = Invoke-ScrubFile -InputPath $sfx.Path -OutputPath (Join-Path $dir 'stream_normal.csv') -Profile (Get-ScrubProfile -Name 'Generic')
        $r2 = Invoke-ScrubFile -InputPath $sfx.Path -OutputPath (Join-Path $dir 'stream_streamed.csv') -Profile (Get-ScrubProfile -Name 'Generic') -Stream
        $t1 = Get-Content -Path $r1.Output -Raw; $t2 = Get-Content -Path $r2.Output -Raw
        & $assert ($r1.Clean -and $r2.Clean) "stream: both modes leak-clean"
        & $assert ($hostTok -and ($t1 -match [regex]::Escape($hostTok)) -and ($t2 -match [regex]::Escape($hostTok))) "stream: identical token in both modes"

        $pcsv = Join-Path $dir 'parallel-windows-event.csv'
        $pHeaders = @('Message','RecordId','ProviderName','EventDataJson','MachineName','TimeCreated','LevelDisplayName','UserId')
        $pRows = @(
            @(
                "Account Name: parallel.user, note ""quoted""`nSource Network Address: 10.21.22.23",
                '201',
                'Microsoft-Windows-Security-Auditing',
                '{"TargetUserName":"parallel.user","IpAddress":"10.21.22.23","ProviderGuid":"{11112222-3333-4444-5555-666677778888}"}',
                'PARHOST01',
                '2026-01-01T00:00:00Z',
                'Information',
                'S-1-5-18'
            ),
            @(
                'Account Name: second.user Account Domain: CORP Source Network Address: 10.21.22.24 url=https://db01.corp.local/app',
                '202',
                'Microsoft-Windows-Security-Auditing',
                '{"TargetUserName":"second.user","IpAddress":"10.21.22.24"}',
                'PARHOST02',
                '2026-01-01T00:00:01Z',
                'Information',
                'S-1-5-19'
            ),
            @(
                'Provider {11112222-3333-4444-5555-666677778888} pos 01FF:0038:0268',
                '203',
                'Microsoft-Windows-Kernel-General',
                '{"ProviderGuid":"{11112222-3333-4444-5555-666677778888}","SubjectUserSid":"S-1-5-20"}',
                'PARHOST03',
                '2026-01-01T00:00:02Z',
                'Information',
                'S-1-5-20'
            )
        )
        $pcsvLines = New-Object System.Collections.Generic.List[string]
        [void]$pcsvLines.Add((ConvertTo-UlsDelimitedLine -Values $pHeaders -Delimiter ','))
        foreach ($pr in $pRows) { [void]$pcsvLines.Add((ConvertTo-UlsDelimitedLine -Values $pr -Delimiter ',')) }
        [System.IO.File]::WriteAllText($pcsv, (($pcsvLines.ToArray() -join "`r`n") + "`r`n"), [System.Text.Encoding]::UTF8)
        $pProfile = Get-ScrubProfile -Name WindowsEventCsv
        Initialize-ScrubProfileRuntime -Profile $pProfile -AllowlistFiles @()
        $pmap = Join-Path $dir 'map_parallel_windows_event_DO_NOT_UPLOAD.csv'
        [void](New-ScrubTokenMap -InputPath @($pcsv) -TokenMapCsv $pmap -ScrubPolicy Balanced)
        $pNormal = Invoke-ScrubFile -InputPath $pcsv -OutputPath (Join-Path $dir 'parallel-normal.csv') -Profile $pProfile -ScrubPolicy Balanced -Stream
        $parallelFolderCountBefore = @(Get-ChildItem -LiteralPath $dir -Directory -Filter '_parallel_*' -ErrorAction SilentlyContinue).Count
        $pParallel = Invoke-ScrubFileStreamingParallelCsv -InputPath $pcsv -OutputPath (Join-Path $dir 'parallel-streaming.csv') -Profile $pProfile -TokenMapCsv $pmap -WorkDir $dir -ScrubPolicy Balanced -ThrottleLimit 3 -ChunkSize 1
        $parallelFolderCountAfter = @(Get-ChildItem -LiteralPath $dir -Directory -Filter '_parallel_*' -ErrorAction SilentlyContinue).Count
        $pNormalText = Get-Content -Path $pNormal.Output -Raw
        $pParallelText = Get-Content -Path $pParallel.Output -Raw
        & $assert ($pNormal.Clean -and $pParallel.Clean -and $pParallel.StreamingParallel) "parallel CSV: normal and streaming-parallel modes leak-clean"
        & $assert (Test-UlsSelfTestDelimitedFilesEqual -Left $pNormal.Output -Right $pParallel.Output -Delimiter ',') "parallel CSV: output matches normal streaming rows and cells"
        & $assert ($parallelFolderCountAfter -eq $parallelFolderCountBefore) "parallel CSV: no _parallel chunk folders are created"
        foreach ($gone in @('parallel.user','second.user','10.21.22.23','10.21.22.24','PARHOST01','PARHOST02','db01.corp.local')) {
            & $assert (-not ($pParallelText -match [regex]::Escape($gone))) "parallel CSV removed: $gone"
        }
        foreach ($keep in @('Microsoft-Windows-Security-Auditing','Microsoft-Windows-Kernel-General','11112222-3333-4444-5555-666677778888','01FF:0038:0268','S-1-5-18','S-1-5-19','S-1-5-20')) {
            & $assert ($pParallelText -match [regex]::Escape($keep)) "parallel CSV preserved: $keep"
        }

        # ---- 7) Round-trip: scrub -> restore ----
        Write-Rule "Round-trip (scrub -> restore)"
        $rtPath = Join-Path $dir 'roundtrip_restored.csv'
        [void](Restore-ScrubbedFile -InputPath $r1.Output -TokenMapCsv $smap -OutputPath $rtPath)
        $rtxt = Get-Content -Path $rtPath -Raw
        & $assert ($rtxt -match 'dc01\.corp\.local') "round-trip: FQDN restored to original"
        & $assert ($rtxt -match '10\.1\.2\.3') "round-trip: IPv4 restored to original"
    }
    catch { Write-Fail "Self-test error: $($_.Exception.Message)"; $script:__stFail++ }
    finally {
        if ($KeepFiles) { Write-Info "Kept synthetic files in: $dir" }
        else { try { Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue } catch { } }
        $script:Salt = $prevSalt; $script:HmacLength = $prevLen; $script:AllowedDomains = $prevAllowed; $script:ScrubPolicy = $prevPolicy
        $script:TokenByNorm = @{}; $script:TokenMapCacheKey = $null
    }
    Write-Host ""
    if ($script:__stFail -eq 0) { Write-Ok "SELF-TEST PASSED ($script:__stPass checks)." }
    else { Write-Fail "SELF-TEST: $script:__stPass passed, $script:__stFail FAILED." }
    return ($script:__stFail -eq 0)
}

# =====================================================================
# REGION: Scrub one file (CSV field-aware, JSON values-only, or whole-text)
# =====================================================================
function Get-ScrubbedOutPath {
    param([Parameter(Mandatory)][string]$InputPath, [Parameter(Mandatory)][string]$OutDir, [switch]$UseHash)
    $ext = [System.IO.Path]::GetExtension($InputPath)
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($InputPath) -replace '(?i)_UNSCRUBBED$', ''
    if ($UseHash) { $stem = "{0}_{1}" -f $stem, (Get-PathFingerprint -Path $InputPath -Length 8) }
    if ($ext.ToLowerInvariant() -eq '.csv') { return (Join-Path $OutDir ("{0}_scrubbed.csv" -f $stem)) }
    return (Join-Path $OutDir ("{0}.scrubbed{1}" -f $stem, $ext))
}

function Invoke-ScrubFile {
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)]$Profile,
        [string[]]$SensitiveTerms = @(),
        [string[]]$AdditionalBroadLabels = @(),
        [string[]]$AllowlistFile = @(),
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = $script:ScrubPolicy,
        [switch]$ExplainDetections,
        [string]$FalsePositiveReport,
        [switch]$DryRun,
        [switch]$Stream,
        [switch]$SkipLeakCheck,
        [string]$WorkerProgressFile,
        [int]$WorkerProgressRowsTotal = 0,
        [int]$WorkerProgressChunk = 0,
        [int]$WorkerProgressIntervalRows = 250,
        [int]$WorkerProgressIntervalSeconds = 1
    )
    if (-not (Test-Path $InputPath)) { throw "Input not found: $InputPath" }
    $script:AdditionalBroadLabels = $AdditionalBroadLabels
    $script:ScrubPolicy = $ScrubPolicy
    if ($ExplainDetections) { $script:ExplainDetections = $true }
    if ($FalsePositiveReport) { $script:FalsePositiveReport = $FalsePositiveReport }
    Initialize-ScrubProfileRuntime -Profile $Profile -AllowlistFiles $AllowlistFile
    [void](Get-SessionSalt)
    $script:__scrubFallback = 0; $script:__scrubFallbackCol = ''
    $script:__cellCache = @{}   # ULS perf patch 1: fresh per-file (column,value)->scrubbed cache
    $script:__hmacTokenCache = @{}   # low-risk perf patch: fresh per-file fallback HMAC token cache

    $name = [System.IO.Path]::GetFileName($InputPath)
    $ext = [System.IO.Path]::GetExtension($InputPath).ToLowerInvariant()
    $format = $Profile.Format
    if ($format -eq 'Auto') {
        if ($ext -eq '.csv') { $format = 'Csv' }
        elseif ($ext -eq '.tsv') { $format = 'Tsv' }
        elseif ($ext -eq '.psv') { $format = 'Psv' }
        elseif ($ext -in @('.json','.ndjson','.jsonl')) { $format = 'Json' }
        else { $format = 'Text' }
    }
    # Delimiter for the CSV-family formats.
    $delim = ','
    try { if ($Profile.Delimiter) { $delim = [string]$Profile.Delimiter } } catch { }
    if ($format -eq 'Tsv') { $delim = "`t" }
    elseif ($format -eq 'Psv') { $delim = '|' }

    $outFull = Resolve-OutPath -Path $OutputPath

    # Streaming path (bounded memory) -- opt-in, skips the in-memory render.
    if ($Stream -and -not $DryRun) {
        return Invoke-ScrubFileStreaming -InputPath $InputPath -OutputPath $outFull -Profile $Profile -SensitiveTerms $SensitiveTerms -Format $format -Delimiter $delim -SkipLeakCheck:$SkipLeakCheck -WorkerProgressFile $WorkerProgressFile -WorkerProgressRowsTotal $WorkerProgressRowsTotal -WorkerProgressChunk $WorkerProgressChunk -WorkerProgressIntervalRows $WorkerProgressIntervalRows -WorkerProgressIntervalSeconds $WorkerProgressIntervalSeconds
    }

    # --- Dry run: report what WOULD change, write nothing. ---
    if ($DryRun) {
        $changes = New-Object System.Collections.Generic.List[object]
        if ($format -eq 'Csv' -or $format -eq 'Tsv' -or $format -eq 'Psv') {
            $rn = 0; $seenPairs = @{}
            Import-Csv -Path $InputPath -Delimiter $delim | ForEach-Object {
                $row = $_
                $rn++
                if ($rn % 250 -eq 0) { Write-UlsProgress -Activity "Dry run" -Phase $format -File $name -RowsDone $rn }
                foreach ($prop in $row.PSObject.Properties) {
                    $cell = [string]$prop.Value
                    if ([string]::IsNullOrWhiteSpace($cell)) { continue }
                    try {
                        $s = [string](Scrub-Field -ColumnName $prop.Name -Value $cell -Profile $Profile)
                        $s = [string](Protect-SensitiveTerms -Text $s -SensitiveTerms $SensitiveTerms)
                        if (-not [string]::Equals($s, $cell)) {
                            $k = ([string]$prop.Name) + '|' + $cell
                            if (-not $seenPairs.ContainsKey($k)) { $seenPairs[$k] = $true; [void]$changes.Add([pscustomobject]@{ Field = [string]$prop.Name; Original = $cell; Token = $s }) }
                        }
                    }
                    catch {
                        $script:__scrubFallback = [int]$script:__scrubFallback + 1
                        if (-not $script:__scrubFallbackCol) { $script:__scrubFallbackCol = "col '$($prop.Name)' [$($_.Exception.GetType().Name)] $($_.Exception.Message)" }
                    }
                }
            }
            Write-UlsProgress -Activity "Dry run" -File $name -Completed
        }
        elseif ($format -eq 'Json') {
            $raw = [System.IO.File]::ReadAllText($InputPath)
            $jsonPreview = Invoke-ScrubJsonText -Text $raw -IsNdjson:($ext -ne '.json') -Profile $Profile -Changes $changes
            $jsonPreview = Protect-SensitiveTerms -Text $jsonPreview -SensitiveTerms $SensitiveTerms
            foreach ($term in $SensitiveTerms) {
                $t = ([string]$term).Trim()
                if ($t.Length -ge 3 -and $raw.IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $seedPrefix = if ($t -match '^(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$') { 'DNS' } else { 'X500' }
                    [void]$changes.Add([pscustomobject]@{ Field='(seed)'; Original=$t; Token=(Get-Token -Value $t -Prefix $seedPrefix) })
                }
            }
        }
        else {
            $text = [System.IO.File]::ReadAllText($InputPath)
            $seenPairs = @{}
            foreach ($id in (Find-Identifiers -Text $text)) {
                if (-not $seenPairs.ContainsKey($id.Raw)) { $seenPairs[$id.Raw] = $true; [void]$changes.Add([pscustomobject]@{ Field = '(text)'; Original = $id.Raw; Token = (Get-Token -Value $id.Raw -Prefix $id.Prefix) }) }
            }
            foreach ($term in $SensitiveTerms) {
                $t = ([string]$term).Trim()
                if ($t.Length -ge 3 -and $text.IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and -not $seenPairs.ContainsKey($t)) {
                    $seedPrefix = if ($t -match '^(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$') { 'DNS' } else { 'X500' }
                    [void]$changes.Add([pscustomobject]@{ Field = '(seed)'; Original = $t; Token = (Get-Token -Value $t -Prefix $seedPrefix) })
                }
            }
        }
        Write-DryRunSummary -Name $name -Changes $changes
        if ($script:__scrubFallback -gt 0) { Write-Warn "$($script:__scrubFallback) cell(s) couldn't be fully hardened and were handled safely (fail-closed). First column: '$($script:__scrubFallbackCol)'." }
        if ($FalsePositiveReport) { [void](Write-DetectionReport -Path $FalsePositiveReport) }
        return [pscustomobject]@{ Input = $InputPath; Output = $null; Clean = $true; DryRun = $true; ChangeCount = $changes.Count; LeakCheckSkipped = $false }
    }

    if ($format -eq 'Csv' -or $format -eq 'Tsv' -or $format -eq 'Psv') {
        Write-Work "Scrubbing ($format, profile '$($Profile.Name)'): $name"
        $ulsPerfRead = New-UlsPerfStopwatch
        $raw = @(Import-Csv $InputPath -Delimiter $delim)
        Add-UlsPerfPhase -Phase 'Read CSV' -Stopwatch $ulsPerfRead -File $name -Rows $raw.Count -Notes 'Scrub Import-Csv'
        $total = $raw.Count
        $rn = 0
        $ulsPerfScrub = New-UlsPerfStopwatch
        $ulsPerfScrubColumnTicks = @{}
        $ulsPerfScrubColumnCounts = @{}
        $scrubbed = foreach ($row in $raw) {
            $rn++
            if ($rn % 250 -eq 0) {
                Write-UlsProgress -Activity "Scrub" -Phase $format -File $name -RowsDone $rn -RowsTotal $total
            }
            $new = [ordered]@{}
            foreach ($prop in $row.PSObject.Properties) {
                if ($script:PerfReportDetailedEnabled) {
                    $ulsPerfColBlock = [System.Diagnostics.Stopwatch]::StartNew()
                    $scrubbedValue = Scrub-Field -ColumnName $prop.Name -Value $prop.Value -Profile $Profile
                    $ulsPerfColBlock.Stop()
                    $colName = [string]$prop.Name
                    if (-not $ulsPerfScrubColumnTicks.ContainsKey($colName)) { $ulsPerfScrubColumnTicks[$colName] = [long]0; $ulsPerfScrubColumnCounts[$colName] = 0 }
                    $ulsPerfScrubColumnTicks[$colName] = [long]$ulsPerfScrubColumnTicks[$colName] + [long]$ulsPerfColBlock.ElapsedTicks
                    $ulsPerfScrubColumnCounts[$colName] = [int]$ulsPerfScrubColumnCounts[$colName] + 1
                    $new[$prop.Name] = $scrubbedValue
                }
                else {
                    $new[$prop.Name] = Scrub-Field -ColumnName $prop.Name -Value $prop.Value -Profile $Profile
                }
            }
            [pscustomobject]$new
        }
        Write-UlsProgress -Activity "Scrub" -File $name -Completed
        $ulsPerfCells = if ($total -gt 0) { $total * (@($raw[0].PSObject.Properties).Count) } else { 0 }
        Add-UlsPerfPhase -Phase 'Scrub fields' -Stopwatch $ulsPerfScrub -File $name -Rows $total -Cells $ulsPerfCells -Notes 'In-memory row/cell scrub'
        if ($script:PerfReportDetailedEnabled) {
            $freq = [double][System.Diagnostics.Stopwatch]::Frequency
            foreach ($col in ($ulsPerfScrubColumnTicks.Keys | Sort-Object)) {
                Add-UlsPerfPhase -Phase 'Scrub column' -Seconds ([double]$ulsPerfScrubColumnTicks[$col] / $freq) -File $name -Rows $total -Cells ([int]$ulsPerfScrubColumnCounts[$col]) -Notes ("Column=$col")
            }
        }

        # ULS perf patch 5: per-cell hardening now covers EVERY column (pass-through metadata columns
        # are hardened in Scrub-Field), so the redundant whole-row Invoke-LeakHardeningText pass is
        # dropped. Render once, redact seed terms, write. The leak check below remains the guarantee.
        $ulsPerfPost = New-UlsPerfStopwatch
        $csvText = (($scrubbed | ConvertTo-Csv -NoTypeInformation -Delimiter $delim) -join "`r`n") + "`r`n"
        $csvText = Protect-SensitiveTerms -Text $csvText -SensitiveTerms $SensitiveTerms
        Add-UlsPerfPhase -Phase 'Post hardening' -Stopwatch $ulsPerfPost -File $name -Rows $total -Cells $ulsPerfCells -Notes 'ConvertTo-Csv + sensitive terms'
        $ulsPerfWrite = New-UlsPerfStopwatch
        [System.IO.File]::WriteAllText($outFull, $csvText, [System.Text.Encoding]::UTF8)
        Add-UlsPerfPhase -Phase 'Write output' -Stopwatch $ulsPerfWrite -File $name -Rows $total -Notes 'WriteAllText'
        Write-Detail "Rows: $total  ->  $([System.IO.Path]::GetFileName($outFull))"
    }
    elseif ($format -eq 'Json') {
        $isNd = ($ext -ne '.json')
        Write-Work "Scrubbing (JSON$(if ($isNd) { ' lines' }), profile '$($Profile.Name)'): $name"
        $raw = [System.IO.File]::ReadAllText($InputPath)
        $jsonOut = Invoke-ScrubJsonText -Text $raw -IsNdjson:$isNd -Profile $Profile
        $jsonOut = Protect-SensitiveTerms -Text $jsonOut -SensitiveTerms $SensitiveTerms
        [System.IO.File]::WriteAllText($outFull, $jsonOut, [System.Text.Encoding]::UTF8)
        Write-Detail "Output: $([System.IO.Path]::GetFileName($outFull))"
    }
    elseif ($format -eq 'Kv') {
        Write-Work "Scrubbing (key=value, profile '$($Profile.Name)'): $name"
        Write-UlsProgress -Activity "Scrub" -Phase "read kv" -File $name -Force
        $text = [System.IO.File]::ReadAllText($InputPath)
        Write-UlsProgress -Activity "Scrub" -Phase "kv values" -File $name -Force
        $text = Invoke-KvValueOnlyText -Text $text
        Write-UlsProgress -Activity "Scrub" -Phase "harden" -File $name -Force
        $text = Invoke-LeakHardeningText -Text $text
        Write-UlsProgress -Activity "Scrub" -Phase "seed terms" -File $name -Force
        $text = Protect-SensitiveTerms -Text $text -SensitiveTerms $SensitiveTerms
        [System.IO.File]::WriteAllText($outFull, $text, [System.Text.Encoding]::UTF8)
        Write-UlsProgress -Activity "Scrub" -File $name -Completed
        Write-Detail "Output: $([System.IO.Path]::GetFileName($outFull))"
    }
    else {
        Write-Work "Scrubbing (text, profile '$($Profile.Name)'): $name"
        Write-UlsProgress -Activity "Scrub" -Phase "read text" -File $name -Force
        $text = [System.IO.File]::ReadAllText($InputPath)
        Write-Detail "Input size: $($text.Length) characters"
        Write-UlsProgress -Activity "Scrub" -Phase "harden" -File $name -Force
        $text = Invoke-LeakHardeningText -Text $text
        Write-UlsProgress -Activity "Scrub" -Phase "seed terms" -File $name -Force
        $text = Protect-SensitiveTerms -Text $text -SensitiveTerms $SensitiveTerms
        [System.IO.File]::WriteAllText($outFull, $text, [System.Text.Encoding]::UTF8)
        Write-UlsProgress -Activity "Scrub" -File $name -Completed
        Write-Detail "Output: $([System.IO.Path]::GetFileName($outFull))"
    }

    # Verify, and auto re-harden once if anything slipped through.
    # ULS perf patch 8: -SkipLeakCheck skips this independent verification pass. Deliberate trade --
    # the per-cell scrub still ran in full; only the separate re-scan is skipped. Use when you trust
    # the scrub config for the data set (e.g. bulk re-runs of vetted log types).
    $ulsPerfLeak = New-UlsPerfStopwatch
    $skipLeakHeader = ($format -eq 'Csv' -or $format -eq 'Tsv' -or $format -eq 'Psv')
    if ($SkipLeakCheck) {
        Write-Warn "Leak check SKIPPED (-SkipLeakCheck) -- output was NOT independently verified."
        $clean = $true
    }
    else {
        $clean = Test-ScrubbedForLeaks -CsvPath $outFull -SensitiveTerms $SensitiveTerms -SkipFirstLine:$skipLeakHeader -ProbeOnly
        if (-not $clean) {
            Write-Warn "Residue detected -- attempting one in-place re-harden..."
            try {
                Invoke-UlsLineWiseFileHardening -Path $outFull -SensitiveTerms $SensitiveTerms -SkipFirstLine:$skipLeakHeader
                $clean = Test-ScrubbedForLeaks -CsvPath $outFull -SensitiveTerms $SensitiveTerms -SkipFirstLine:$skipLeakHeader
            }
            catch {
                # On a large file, even line-wise re-hardening can hit a regex timeout.
                # Do not abort the run -- leave the per-cell-scrubbed output in place and report it as
                # needing review (fail-loud; the per-cell pass already scrubbed every non-pass-through
                # column, and the leak check above flagged exactly what remains).
                Write-Warn "In-place re-harden could not complete ($($_.Exception.GetType().Name)); leaving output and flagging for review."
                $clean = $false
            }
        }
    }
    Add-UlsPerfPhase -Phase 'Leak check' -Stopwatch $ulsPerfLeak -File $name -Notes ('SkipLeakCheck={0}' -f [bool]$SkipLeakCheck)
    if ($script:__scrubFallback -gt 0) { Write-Warn "$($script:__scrubFallback) cell(s) couldn't be fully hardened and were replaced with a safe token (fail-closed, no leak). First column: '$($script:__scrubFallbackCol)'." }
    if ($FalsePositiveReport) { [void](Write-DetectionReport -Path $FalsePositiveReport) }
    return [pscustomobject]@{ Input = $InputPath; Output = $outFull; Clean = $clean; LeakCheckSkipped = [bool]$SkipLeakCheck }
}

# =====================================================================
# REGION: Run manifest
# =====================================================================
function Get-SaltFingerprint {
    $salt = Get-SessionSalt
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($salt)) } finally { $sha.Dispose() }
    return (ConvertTo-HexString -Bytes $bytes).Substring(0, 12).ToUpperInvariant()
}

function Write-RunManifest {
    param(
        [Parameter(Mandatory)][string]$WorkDir,
        [Parameter(Mandatory)][array]$Results,
        [string]$TokenMapCsv,
        [string]$TokenMapMode = $script:TokenMapMode
    )
    $entries = @()
    foreach ($r in $Results) {
        if (-not $r) { continue }
        $bytes = -1; $rows = -1; $tokenCount = 0
        $fileName = if ($r.Output) { [System.IO.Path]::GetFileName($r.Output) } else { [System.IO.Path]::GetFileName($r.Input) }
        if ($r.Output) { try { $bytes = (Get-Item -Path $r.Output).Length } catch { } }
        try {
            if ($null -ne $r.Rows -and [int]$r.Rows -ge 0) { $rows = [int]$r.Rows }
            elseif (($r.Output -as [string]) -match '\.csv$') {
                $lineCount = 0
                foreach ($nullLine in [System.IO.File]::ReadLines((Resolve-Path -Path $r.Output).Path)) { $lineCount++ }
                $rows = [Math]::Max(0, $lineCount - 1)
            }
        } catch { $rows = -1 }
        if ($r.Output) { $tokenCount = Get-TokenCountInFile -Path $r.Output }
        $entries += [pscustomobject]@{
            file           = $fileName
            inputPathHash  = if ($r.Input) { Get-PathFingerprint -Path $r.Input -Length 12 } else { "" }
            scrubbedPath   = if ($r.Output) { [string]$r.Output } else { "" }
            rows           = $rows
            bytes          = $bytes
            tokenCount     = $tokenCount
            leakCheckClean = [bool]$r.Clean
            leakCheckSkipped = [bool]$r.LeakCheckSkipped
            error          = [string]$r.Error
        }
    }
    $manifest = [pscustomobject]@{
        tool            = "UniversalLogScrubber.psm1"
        toolVersion     = $script:ModuleVersion
        schemaVersion   = "4.12"
        generatedUtc    = ((Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))
        saltFingerprint = (Get-SaltFingerprint)
        hmacLength      = $script:HmacLength
        scrubPolicy     = $script:ScrubPolicy
        tokenMapCsv     = $TokenMapCsv
        tokenMapMode    = $TokenMapMode
        scrubbedFiles   = $entries
    }
    $out = Resolve-OutPath -Path (Join-Path $WorkDir "scrub_run_manifest.json")
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $out -Encoding UTF8
    Write-Ok "Run manifest written: $out"
    return $out
}

# =====================================================================
# REGION: Interactive driver
# =====================================================================
function Invoke-UniversalScrubber {
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
        [switch]$Recurse,
        [string[]]$Include,
        [string[]]$Exclude,
        [switch]$DryRun,
        [switch]$Stream,
        [switch]$NoCorrelate,
        [switch]$SkipLeakCheck,
        [switch]$PerfReport,
        [switch]$PerfReportDetailed,
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

    if ($Version) { return Get-UniversalLogScrubberVersionInfo }

    if ($ParallelScrub -and $NoParallelScrub) { throw "Use either -ParallelScrub or -NoParallelScrub, not both." }
    if ($ParallelDiscovery -and $NoParallelDiscovery) { throw "Use either -ParallelDiscovery or -NoParallelDiscovery, not both." }
    if ($LargeFileThresholdMB -lt 1) { $LargeFileThresholdMB = 100 }
    if ($ThrottleLimit -lt 1) { $ThrottleLimit = 1 }
    if ($ChunkSize -lt 0) { throw "-ChunkSize must be 0 for auto/equal chunks, or a positive integer." }
    if ($ChunkSize -gt 0 -and $ChunkSize -lt 100) { $ChunkSize = 100 }
    $chunkSizeLabel = if ($ChunkSize -le 0) { 'auto/equal' } else { [string]$ChunkSize }

    $script:HmacLength = $HmacLength
    $script:ScrubPolicy = $ScrubPolicy
    $script:TokenMapMode = $TokenMapMode
    $script:EvtxProgressMode = $EvtxProgressMode
    $script:ExplainDetections = [bool]$ExplainDetections
    $script:FalsePositiveReport = $FalsePositiveReport
    $script:DetectionSummaryReport = $DetectionSummaryReport
    $script:DetectionTrace = New-Object System.Collections.Generic.List[object]
    $script:DetectionTraceSeen = @{}
    $script:DetectionCounts = @{}
    $script:PerfReportEnabled = [bool]($PerfReport -or $PerfReportDetailed)
    $script:PerfReportDetailedEnabled = [bool]$PerfReportDetailed
    $script:PerfReportRows = New-Object System.Collections.Generic.List[object]
    $script:PerfReportPath = $null
    $script:PerfReportTextPath = $null

    Write-Banner ">_ ULS  v$script:ModuleVersion" "   map first  ::  scrub second  ::  verify before upload"
    if ($RecommendOnly) { Write-Info "RECOMMEND ONLY mode -- local sample analysis only." }
    if ($SafeFirstRun) { Write-Info "SAFE FIRST RUN mode -- local sample analysis only." }
    if ($AutoProfile) { Write-Info "AUTO PROFILE mode -- use one high-confidence recommendation when possible." }
    if ($DryRun) { Write-Info "DRY RUN mode -- nothing will be written." }
    if ($Stream) { Write-Info "STREAM mode -- bounded memory for very large files." }
    if ($PerfReport -or $PerfReportDetailed) { Write-Info "PERF REPORT mode -- phase timings will be written locally." }
    if ($PerfReportDetailed) { Write-Info "PERF REPORT DETAILED mode -- per-column timings add overhead and should not be used for baseline timings." }
    if ($NoParallelScrub) { Write-Info "PARALLEL SCRUB disabled by -NoParallelScrub." }
    elseif ($ParallelScrub) { Write-Info ("PARALLEL SCRUB mode -- streaming runspace batches; throttle={0}; batchSize={1}." -f $ThrottleLimit, $chunkSizeLabel) }
    if ($NoParallelDiscovery) { Write-Info "PARALLEL DISCOVERY disabled by -NoParallelDiscovery." }
    elseif ($ParallelDiscovery) { Write-Info ("PARALLEL DISCOVERY mode -- streaming runspace batches; throttle={0}; batchSize={1}." -f $ThrottleLimit, $chunkSizeLabel) }
    Write-Info ("Large-file auto threshold: {0} MB." -f $LargeFileThresholdMB)
    Write-Info "Scrub policy: $script:ScrubPolicy"

    if ($RecommendOnly -or $SafeFirstRun) {
        if ([string]::IsNullOrWhiteSpace($Path)) {
            if ($NonInteractive) { throw "Path is required in -NonInteractive recommendation mode." }
            Write-Host ""
            Write-Step "What log file or folder should be analyzed?"
            $Path = Read-DefaultString -Prompt "Path to a log file OR a folder of logs"
        }
        $recs = Test-LogFormat -Path $Path -Recurse:$Recurse -Include $Include -Exclude $Exclude -Quiet
        Write-LogFormatRecommendationSummary -Recommendations $recs -SafeFirstRun:$SafeFirstRun -Title 'Recommendation summary'
        return $recs
    }

    if ($SaltFile) {
        if (-not (Test-Path $SaltFile)) { throw "Salt file not found: $SaltFile" }
        $Salt = ([System.IO.File]::ReadAllText((Resolve-Path -Path $SaltFile).Path)).Trim()
    }
    elseif ($SaltFromEnv) {
        $Salt = [Environment]::GetEnvironmentVariable($SaltFromEnv)
        if ([string]::IsNullOrWhiteSpace($Salt)) { throw "Environment variable '$SaltFromEnv' is empty or not set." }
    }
    if ($Salt) { $script:Salt = $Salt }

    # --- Working directory ---
    if ([string]::IsNullOrWhiteSpace($WorkDir)) {
        if ($NonInteractive) { $WorkDir = (Get-Location).Path }
        else { $WorkDir = Read-DefaultString -Prompt "Working folder for outputs" -Default (Get-Location).Path }
    }
    $WorkDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WorkDir)
    if (-not (Test-Path $WorkDir)) { New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null }
    if ($ExplainDetections -and [string]::IsNullOrWhiteSpace($FalsePositiveReport)) {
        $FalsePositiveReport = Join-Path $WorkDir 'detection_review_DO_NOT_UPLOAD.csv'
        $script:FalsePositiveReport = $FalsePositiveReport
        Write-Warn "Detection review report will be written locally: $FalsePositiveReport"
    }
    elseif (-not [string]::IsNullOrWhiteSpace($FalsePositiveReport)) {
        $script:FalsePositiveReport = $FalsePositiveReport
    }
    Write-Info "Working folder: $WorkDir"

    if ($ProfileTemplate) {
        $templatePath = Join-Path $WorkDir ("profile-template-{0}.json" -f $ProfileTemplate.ToLowerInvariant())
        $written = New-ScrubProfileTemplate -Template $ProfileTemplate -OutputPath $templatePath
        Write-Info "Edit this template, then run with -ProfileFile $written."
        return [pscustomobject]@{ ProfileTemplate = $ProfileTemplate; OutputPath = $written }
    }

    if ($BuildProfileFromSample) {
        if ([string]::IsNullOrWhiteSpace($Path)) {
            if ($NonInteractive) { throw "Path is required with -BuildProfileFromSample in -NonInteractive mode." }
            Write-Host ""
            Write-Step "What sample should be analyzed?"
            $Path = Read-DefaultString -Prompt "Path to a sample log file OR folder"
        }
        if ([string]::IsNullOrWhiteSpace($ProfileOut)) { $ProfileOut = Join-Path $WorkDir 'generated-profile.json' }
        if ([string]::IsNullOrWhiteSpace($ProfileReportOut)) { $ProfileReportOut = Join-Path $WorkDir 'profile_build_report_DO_NOT_UPLOAD.md' }
        return New-ScrubProfileFromSample -Path $Path -ProfileOut $ProfileOut -ProfileReportOut $ProfileReportOut -BaseProfile $BaseProfile -ProfileExtensionFile $ProfileExtensionFile -ProfileWizard:$ProfileWizard -MaxSampleRows $MaxSampleRows -SampleFormat $SampleFormat -Force:$Force -NonInteractive:$NonInteractive
    }

    # --- Input file(s) ---
    if ([string]::IsNullOrWhiteSpace($Path)) {
        if ($NonInteractive) { throw "Path is required in -NonInteractive mode." }
        Write-Host ""
        Write-Step "What do you want to scrub?"
        $Path = Read-DefaultString -Prompt "Path to a log file OR a folder of logs"
    }
    $targets = @()
    if (Test-Path $Path -PathType Container) {
        $targets = @(Get-ChildItem -Path $Path -File -Recurse:$Recurse -ErrorAction SilentlyContinue |
            Where-Object { -not (Test-GeneratedScrubArtifactName -Name $_.Name) })
        if ($Include -and $Include.Count -gt 0) {
            $targets = @($targets | Where-Object {
                $n = $_.Name; $ok = $false
                foreach ($pat in $Include) { if ($n -like $pat) { $ok = $true; break } }
                $ok
            })
        }
        if ($Exclude -and $Exclude.Count -gt 0) {
            $targets = @($targets | Where-Object {
                $n = $_.Name; $skip = $false
                foreach ($pat in $Exclude) { if ($n -like $pat) { $skip = $true; break } }
                -not $skip
            })
        }
        $targets = @($targets | Sort-Object FullName)
        if ($targets.Count -eq 0) { throw "No files found in folder: $Path" }
        Write-Ok "Found $($targets.Count) file(s) to scrub:"
        foreach ($t in $targets) { Write-Detail $t.Name }
    }
    elseif (Test-Path $Path -PathType Leaf) {
        $targets = @(Get-Item $Path)
        Write-Ok "Target: $($targets[0].Name)"
    }
    else { throw "Path not found: $Path" }

    if ($AutoProfile -and -not $Profile -and -not $ProfileFile) {
        $autoRecs = @()
        foreach ($t in $targets) { $autoRecs += Get-LogFormatRecommendation -File $t -SampleLines 50 }
        $confident = @($autoRecs | Where-Object { $_.Confidence -ge 80 -and (Get-ScrubProfile -Name $_.SuggestedProfile) })
        $profiles = @($confident | Select-Object -ExpandProperty SuggestedProfile -Unique)
        if ($autoRecs.Count -gt 0 -and $confident.Count -eq $autoRecs.Count -and $profiles.Count -eq 1) {
            $Profile = [string]$profiles[0]
            Write-Ok "AutoProfile selected: $Profile"
        }
        else {
            Write-LogFormatRecommendationSummary -Recommendations $autoRecs -Title 'AutoProfile recommendations'
            if ($NonInteractive) {
                throw "AutoProfile could not choose one high-confidence profile for all selected files. Pass -Profile explicitly or split files by type."
            }
            Write-Warn "AutoProfile could not choose one profile; falling back to the interactive profile picker."
        }
    }

    # --- Pre-convert special inputs (EVTX / XLSX / Office / W3C-IIS) locally before scrubbing ---
    $evtxConverted = $false
    $iisConverted = $false
    $intermediateTargets = @()
    if (@($targets | Where-Object { $_.Extension -imatch '^\.(evtx|etl|xlsx|docx|pptx|doc|ppt|log)$' }).Count -gt 0) {
        Write-Host ""
        Write-Step "Preparing special inputs (event logs / ETL / workbooks / Office / IIS logs)"
        $conversionNameCounts = @{}
        foreach ($ct in $targets) {
            $cext = ([string]$ct.Extension).ToLowerInvariant()
            $suffix = if ($cext -eq '.evtx') { '.evtx.csv' } elseif ($cext -eq '.etl') { '.etl.csv' } elseif ($cext -eq '.xlsx') { '.xlsx.csv' } elseif ($cext -eq '.docx') { '.docx.txt' } elseif ($cext -eq '.pptx') { '.pptx.txt' } elseif ($cext -eq '.log') { '.w3c.csv' } else { $null }
            if (-not $suffix) { continue }
            $key = ([System.IO.Path]::GetFileNameWithoutExtension($ct.FullName) + $suffix).ToLowerInvariant()
            if (-not $conversionNameCounts.ContainsKey($key)) { $conversionNameCounts[$key] = 0 }
            $conversionNameCounts[$key] = [int]$conversionNameCounts[$key] + 1
        }
        $newTargets = @()
        foreach ($t in $targets) {
            $ext2 = ([string]$t.Extension).ToLowerInvariant()
            $converted = $null
            try {
                if ($ext2 -eq '.evtx') {
                    $key = ($t.BaseName + '.evtx.csv').ToLowerInvariant()
                    $outCsv = Get-SafeDerivedPath -InputPath $t.FullName -OutDir $WorkDir -Suffix '.evtx.csv' -UseHash:($conversionNameCounts[$key] -gt 1)
                    [void](ConvertFrom-EvtxToCsv -EvtxPath $t.FullName -OutCsv $outCsv -EvtxProgressMode $EvtxProgressMode)
                    if (Test-Path -LiteralPath $outCsv) { $converted = Get-Item -LiteralPath $outCsv; $evtxConverted = $true }
                }
                elseif ($ext2 -eq '.etl') {
                    if (-not $ConvertEtl) {
                        throw "ETL file '$($t.Name)' requires -ConvertEtl to run tracerpt.exe locally. Or convert the ETL to CSV/XML/text yourself and scrub the converted output."
                    }
                    $key = ($t.BaseName + '.etl.csv').ToLowerInvariant()
                    $outCsv = Get-SafeDerivedPath -InputPath $t.FullName -OutDir $WorkDir -Suffix '.etl.csv' -UseHash:($conversionNameCounts[$key] -gt 1)
                    [void](ConvertFrom-EtlToCsv -EtlPath $t.FullName -OutCsv $outCsv)
                    if (Test-Path -LiteralPath $outCsv) { $converted = Get-Item -LiteralPath $outCsv }
                }
                elseif ($ext2 -eq '.xlsx') {
                    $key = ($t.BaseName + '.xlsx.csv').ToLowerInvariant()
                    $outCsv = Get-SafeDerivedPath -InputPath $t.FullName -OutDir $WorkDir -Suffix '.xlsx.csv' -UseHash:($conversionNameCounts[$key] -gt 1)
                    [void](ConvertFrom-XlsxToCsv -XlsxPath $t.FullName -OutCsv $outCsv)
                    if (Test-Path -LiteralPath $outCsv) { $converted = Get-Item -LiteralPath $outCsv }
                }
                elseif ($ext2 -eq '.docx') {
                    $key = ($t.BaseName + '.docx.txt').ToLowerInvariant()
                    $outTxt = Get-SafeDerivedPath -InputPath $t.FullName -OutDir $WorkDir -Suffix '.docx.txt' -UseHash:($conversionNameCounts[$key] -gt 1)
                    [void](ConvertFrom-DocxToText -DocxPath $t.FullName -OutText $outTxt)
                    if (Test-Path -LiteralPath $outTxt) { $converted = Get-Item -LiteralPath $outTxt }
                }
                elseif ($ext2 -eq '.pptx') {
                    $key = ($t.BaseName + '.pptx.txt').ToLowerInvariant()
                    $outTxt = Get-SafeDerivedPath -InputPath $t.FullName -OutDir $WorkDir -Suffix '.pptx.txt' -UseHash:($conversionNameCounts[$key] -gt 1)
                    [void](ConvertFrom-PptxToText -PptxPath $t.FullName -OutText $outTxt)
                    if (Test-Path -LiteralPath $outTxt) { $converted = Get-Item -LiteralPath $outTxt }
                }
                elseif ($ext2 -in @('.doc','.ppt')) {
                    throw "Legacy Office file '$($t.Name)' is not parsed natively. Export it to .docx/.pptx or plain text, then scrub the exported file."
                }
                elseif ($ext2 -eq '.log') {
                    $head = @(Get-Content -LiteralPath $t.FullName -TotalCount 20 -ErrorAction SilentlyContinue)
                    if ($head -match '^#Fields:') {
                        $key = ($t.BaseName + '.w3c.csv').ToLowerInvariant()
                        $outCsv = Get-SafeDerivedPath -InputPath $t.FullName -OutDir $WorkDir -Suffix '.w3c.csv' -UseHash:($conversionNameCounts[$key] -gt 1)
                        [void](ConvertFrom-W3CToCsv -LogPath $t.FullName -OutCsv $outCsv)
                        if (Test-Path -LiteralPath $outCsv) { $converted = Get-Item -LiteralPath $outCsv; $iisConverted = $true }
                    }
                }
            }
            catch {
                Write-Fail "Conversion failed for $($t.Name): $($_.Exception.Message)"
                if ($ext2 -in @('.doc','.ppt','.etl')) { throw }
            }
            if ($converted) { $newTargets += $converted; $intermediateTargets += $converted } else { $newTargets += $t }
        }
        $targets = @($newTargets)
        if ($targets.Count -eq 0) { throw "No inputs left to scrub after conversion." }
    }

    # --- Salt (prompt securely if still unknown) ---
    Write-Host ""
    Write-Step "Salt"
    if ($NonInteractive -and [string]::IsNullOrWhiteSpace($script:Salt)) {
        throw "Salt is required in -NonInteractive mode. Pass -Salt, -SaltFromEnv, or -SaltFile."
    }
    [void](Get-SessionSalt)
    Write-Ok "Salt set (fingerprint $(Get-SaltFingerprint))."

    # --- Profile ---
    Write-Host ""
    Write-Step "Choose a profile (how fields are interpreted)"
    $prof = $null
    if ($ProfileFile) {
        $prof = Import-ScrubProfileFile -Path $ProfileFile
    }
    elseif ($Profile -and (Test-Path $Profile -PathType Leaf) -and ($Profile -match '\.(json|psd1)$')) {
        $prof = Import-ScrubProfileFile -Path $Profile
    }
    elseif ($Profile) {
        $prof = Get-ScrubProfile -Name $Profile
        if (-not $prof) { throw "Unknown profile: $Profile" }
    }
    else {
        $suggest = 'Generic'
        $firstCsv = $targets | Where-Object { $_.Extension -ieq '.csv' } | Select-Object -First 1
        $anyJson  = @($targets | Where-Object { $_.Extension -imatch '^\.(json|ndjson|jsonl)$' }).Count -gt 0
        $anyTsv   = @($targets | Where-Object { $_.Extension -ieq '.tsv' }).Count -gt 0
        if ($iisConverted) { $suggest = 'IIS' }
        elseif ($firstCsv) {
            try {
                $hdr = (Get-Content -Path $firstCsv.FullName -TotalCount 1 -ErrorAction SilentlyContinue)
                if ($hdr -match 'RequestID|CertificateTemplate|ESC\d|PkiObjectType|StrongCertificateBindingEnforcement') { $suggest = 'CA' }
                elseif ($evtxConverted -or ($hdr -match 'ProviderName|LevelDisplayName|RecordId')) { $suggest = 'WindowsEventCsv' }
            } catch { }
        }
        elseif ($anyJson) { $suggest = 'Generic' }
        elseif ($anyTsv) { $suggest = 'Tsv' }
        else { $suggest = 'Text' }

        if ($NonInteractive) { $prof = Get-ScrubProfile -Name $suggest }
        else {
            $opts = @()
            foreach ($p in (Get-ScrubProfile)) {
                $label = $p.Name; if ($p.Name -eq $suggest) { $label += "   (suggested)" }
                $opts += @{ Key = $p.Name; Label = $label; Detail = $p.Description }
            }
            $opts += @{ Key = '__file'; Label = 'Custom -- load from a profile file (.json/.psd1)'; Detail = 'Bring your own column rules.' }
            $defIdx = 1
            for ($i = 0; $i -lt $opts.Count; $i++) { if ($opts[$i].Key -eq $suggest) { $defIdx = $i + 1 } }
            $choice = Read-Choice -Prompt "Profile number" -Options $opts -DefaultIndex $defIdx
            if ($choice -eq '__file') {
                $pf = Read-DefaultString -Prompt "Path to a profile file (.json or .psd1)"
                $prof = Import-ScrubProfileFile -Path $pf
            }
            else { $prof = Get-ScrubProfile -Name $choice }
        }
    }
    if (-not $prof) { throw "No profile resolved." }
    if ($ProfileExtensionFile -and $ProfileExtensionFile.Count -gt 0) {
        $prof = Merge-ScrubProfileExtension -Profile $prof -Path $ProfileExtensionFile
    }
    Write-Ok "Profile: $($prof.Name) -- $($prof.Description)"

    # --- Sensitive seed terms ---
    if (-not $PSBoundParameters.ContainsKey('SensitiveTerms')) {
        if ($NonInteractive) { $SensitiveTerms = @() }
        else {
            Write-Host ""
            Write-Step "Sensitive terms (optional)"
            Write-Detail "Shapeless secrets the detectors can't recognise on their own:"
            Write-Detail "your org name, internal host prefixes, project codenames, vendor names."
            $raw = Read-DefaultString -Prompt "Comma-separated terms (blank for none)" -Default ""
            $SensitiveTerms = @()
            if (-not [string]::IsNullOrWhiteSpace($raw)) { $SensitiveTerms = @($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
        }
    }
    $profileSeedTerms = @()
    try { if ($prof.SeedTerms) { $profileSeedTerms += @($prof.SeedTerms) } } catch { }
    $seedFilesCombined = @()
    if ($SensitiveTermsFile) { $seedFilesCombined += @($SensitiveTermsFile) }
    if ($SeedFile) { $seedFilesCombined += @($SeedFile) }
    try { if ($prof.SeedFiles) { $seedFilesCombined += @($prof.SeedFiles) } } catch { }
    $SensitiveTerms = Merge-ScrubTerms -Terms (@($SensitiveTerms) + $profileSeedTerms) -Files $seedFilesCombined -BasePath $prof.ProfileRoot
    if ($SensitiveTerms.Count -gt 0) { Write-Ok "$($SensitiveTerms.Count) sensitive term(s) will be redacted." }
    Initialize-ScrubProfileRuntime -Profile $prof -AllowlistFiles $AllowlistFile

    # --- Map source ---
    Write-Host ""
    Write-Step "Where should the token map come from?"
    if (-not $MapSource) {
        if ($NonInteractive) { $MapSource = if ($TokenMapCsv) { 'ExistingMap' } else { 'Discover' } }
        else {
            $opts = @(
                @{ Key='Discover';    Label='Build it from these log(s)  (no AD needed)'; Detail='Scans the files, tokenizes every identifier it finds. The universal default.' },
                @{ Key='ExistingMap'; Label='Use an existing token map';                  Detail='Reuse a map you built earlier (keeps tokens consistent across runs).' },
                @{ Key='AD';          Label='Build from Active Directory  (optional)';     Detail='Authoritative: collapses every alias of one identity to one token. Needs domain rights.' }
            )
            $MapSource = Read-Choice -Prompt "Map source number" -Options $opts -DefaultIndex 1
        }
    }
    Write-Info "Map source: $MapSource"

    if (-not $TokenMapCsv) { $TokenMapCsv = Join-Path $WorkDir "scrub_token_map_DO_NOT_UPLOAD.csv" }

    if ($DryRun) {
        # Dry run writes nothing -- no map is built. Load an existing map read-only
        # if one was chosen; otherwise the preview uses on-the-fly (deterministic) tokens.
        Write-Info "[DRY RUN] No token map will be built or written."
        if ($MapSource -eq 'ExistingMap') {
            if (-not (Test-Path $TokenMapCsv) -and -not $NonInteractive) { $TokenMapCsv = Read-DefaultString -Prompt "Path to the existing token map CSV" }
            if (Test-Path $TokenMapCsv) { [void](Import-ScrubTokenMap -TokenMapCsv $TokenMapCsv) }
        }
        else { Write-Detail "Preview uses on-the-fly tokens (deterministic for your salt)." }
    }
    else {
        switch ($MapSource) {
            'Discover' {
                [void](New-ScrubTokenMap -InputPath @($targets | ForEach-Object { $_.FullName }) -TokenMapCsv $TokenMapCsv -SeedTerms $SensitiveTerms -NoCorrelate:$NoCorrelate -TokenMapMode $TokenMapMode -ScrubPolicy $script:ScrubPolicy -ProfileName $prof.Name -WorkDir $WorkDir -AllowlistFile $AllowlistFile -ParallelDiscovery:$ParallelDiscovery -NoParallelDiscovery:$NoParallelDiscovery -ThrottleLimit $ThrottleLimit -ChunkSize $ChunkSize -LargeFileThresholdMB $LargeFileThresholdMB -KeepIntermediate:$KeepIntermediate -WorkerProgressFile $WorkerProgressFile -WorkerProgressRowsTotal $WorkerProgressRowsTotal -WorkerProgressChunk $WorkerProgressChunk -WorkerProgressIntervalRows $WorkerProgressIntervalRows -WorkerProgressIntervalSeconds $WorkerProgressIntervalSeconds)
            }
            'AD' {
                $ulsPerfAd = New-UlsPerfStopwatch
                $res = New-ScrubTokenMapFromAD -TokenMapCsv $TokenMapCsv -SeedTerms $SensitiveTerms
                Add-UlsPerfPhase -Phase 'Build/correlate map' -Stopwatch $ulsPerfAd -File ([System.IO.Path]::GetFileName($TokenMapCsv)) -Notes 'AD map build'
                if (-not $res) {
                    Write-Warn "Falling back to discovery (AD was unavailable)."
                    [void](New-ScrubTokenMap -InputPath @($targets | ForEach-Object { $_.FullName }) -TokenMapCsv $TokenMapCsv -SeedTerms $SensitiveTerms -NoCorrelate:$NoCorrelate -TokenMapMode $TokenMapMode -ScrubPolicy $script:ScrubPolicy -ProfileName $prof.Name -WorkDir $WorkDir -AllowlistFile $AllowlistFile -ParallelDiscovery:$ParallelDiscovery -NoParallelDiscovery:$NoParallelDiscovery -ThrottleLimit $ThrottleLimit -ChunkSize $ChunkSize -LargeFileThresholdMB $LargeFileThresholdMB -KeepIntermediate:$KeepIntermediate -WorkerProgressFile $WorkerProgressFile -WorkerProgressRowsTotal $WorkerProgressRowsTotal -WorkerProgressChunk $WorkerProgressChunk -WorkerProgressIntervalRows $WorkerProgressIntervalRows -WorkerProgressIntervalSeconds $WorkerProgressIntervalSeconds)
                }
            }
            'ExistingMap' {
                if (-not (Test-Path $TokenMapCsv)) {
                    if ($NonInteractive) { throw "Token map not found: $TokenMapCsv" }
                    $TokenMapCsv = Read-DefaultString -Prompt "Path to the existing token map CSV"
                }
                $ulsPerfImportMap = New-UlsPerfStopwatch
                [void](Import-ScrubTokenMap -TokenMapCsv $TokenMapCsv)
                Add-UlsPerfPhase -Phase 'Build/correlate map' -Stopwatch $ulsPerfImportMap -File ([System.IO.Path]::GetFileName($TokenMapCsv)) -Notes 'ExistingMap import'
            }
        }
    }

    if ($DiscoveryOnly) {
        Write-Ok "Discovery-only complete. Token map written: $TokenMapCsv"
        return [pscustomobject]@{ DiscoveryOnly = $true; TokenMapCsv = $TokenMapCsv }
    }

    # --- Scrub every target ---
    Write-Host ""
    Write-Rule "Scrubbing"
    $scrubNameCounts = @{}
    foreach ($st in $targets) {
        $candidate = [System.IO.Path]::GetFileName((Get-ScrubbedOutPath -InputPath $st.FullName -OutDir $WorkDir))
        $key = $candidate.ToLowerInvariant()
        if (-not $scrubNameCounts.ContainsKey($key)) { $scrubNameCounts[$key] = 0 }
        $scrubNameCounts[$key] = [int]$scrubNameCounts[$key] + 1
    }
    $results = @()
    $i = 0
    foreach ($t in $targets) {
        $i++
        Write-Host ""
        Write-Step "File $i of $($targets.Count): $($t.Name)"
        $candidateName = [System.IO.Path]::GetFileName((Get-ScrubbedOutPath -InputPath $t.FullName -OutDir $WorkDir))
        $outPath = Get-ScrubbedOutPath -InputPath $t.FullName -OutDir $WorkDir -UseHash:($scrubNameCounts[$candidateName.ToLowerInvariant()] -gt 1)
        $useStream = $Stream
        $streamThreshold = 5MB
        $profileName = ''
        try { $profileName = [string]$prof.Name } catch { }
        $shouldAutoStream = (-not $DryRun -and (($t.Length -ge $streamThreshold) -or ($profileName -ieq 'WindowsEventCsv')))
        if (-not $useStream -and $shouldAutoStream) {
            $useStream = $true
            $why = if ($profileName -ieq 'WindowsEventCsv') { 'Windows Event CSV profile' } else { "$([Math]::Round(($t.Length / 1MB), 1)) MB input" }
            Write-Info "Auto-streaming ($why) for faster bounded-memory scrubbing."
        }
        try {
            $parallelFormat = $prof.Format
            if ($parallelFormat -eq 'Auto') {
                $parallelExt = [System.IO.Path]::GetExtension($t.FullName).ToLowerInvariant()
                if ($parallelExt -eq '.csv') { $parallelFormat = 'Csv' }
                elseif ($parallelExt -eq '.tsv') { $parallelFormat = 'Tsv' }
                elseif ($parallelExt -eq '.psv') { $parallelFormat = 'Psv' }
            }
            $parallelDelim = ','
            try { if ($prof.Delimiter) { $parallelDelim = [string]$prof.Delimiter } } catch { }
            if ($parallelFormat -eq 'Tsv') { $parallelDelim = "`t" }
            elseif ($parallelFormat -eq 'Psv') { $parallelDelim = '|' }
            # Treat worker-progress parameters as an internal worker-mode signal so helper
            # paths can never recursively parallelize.
            $parallelWorkerMode = ((-not [string]::IsNullOrWhiteSpace($WorkerProgressFile)) -or ($WorkerProgressRowsTotal -gt 0) -or ($WorkerProgressChunk -gt 0) -or $DiscoveryOnly)
            $largeFileBytes = [long]([Math]::Max($LargeFileThresholdMB, 1) * 1MB)
            $isLargeForWorkers = ($t.Length -ge $largeFileBytes)
            $csvParallelEligible = ($parallelFormat -eq 'Csv' -or $parallelFormat -eq 'Tsv' -or $parallelFormat -eq 'Psv')
            $textParallelEligible = ($parallelFormat -eq 'Text' -or $parallelFormat -eq 'Kv')
            # Default behavior is streaming-first. ParallelScrub uses in-process runspace batches,
            # not physical input chunks, for both line-oriented and CSV-family formats.
            $autoParallelScrub = ((-not $parallelWorkerMode) -and (-not $NoParallelScrub) -and (-not $ParallelScrub) -and $isLargeForWorkers -and $textParallelEligible -and ($ThrottleLimit -gt 1))
            if ($autoParallelScrub) {
                Write-Info ("Auto streaming-parallel scrub ({0} MB; format={1}; throttle={2}; batchSize={3}; no input chunk files). Use -NoParallelScrub to disable." -f [Math]::Round(($t.Length / 1MB),1), $parallelFormat, $ThrottleLimit, $(if ($ChunkSize -gt 0) { $ChunkSize } else { 5000 }))
            }
            elseif ((-not $parallelWorkerMode) -and (-not $NoParallelScrub) -and (-not $ParallelScrub) -and $isLargeForWorkers -and $csvParallelEligible) {
                Write-Info ("Large CSV-family input will stream without temp input chunks ({0} MB; format={1}; profile={2}). Use -ParallelScrub to opt into streaming runspace batches." -f [Math]::Round(($t.Length / 1MB),1), $parallelFormat, $profileName)
            }
            $useParallelScrub = (-not $parallelWorkerMode -and -not $NoParallelScrub -and -not $DryRun -and ($csvParallelEligible -or $textParallelEligible) -and ($ParallelScrub -or $autoParallelScrub))
            if ($useParallelScrub -and $csvParallelEligible) {
                if ($autoParallelScrub -and -not $ParallelScrub) { Write-Info ("Auto-parallel scrub ({0} MB input; format={1}); throttle={2}; chunkSize={3}. Use -NoParallelScrub to disable; use -ChunkSize to customize." -f [Math]::Round(($t.Length / 1MB),1), $parallelFormat, $ThrottleLimit, $chunkSizeLabel) }
                $results += Invoke-ScrubFileStreamingParallelCsv -InputPath $t.FullName -OutputPath $outPath -Profile $prof -SensitiveTerms $SensitiveTerms -AllowlistFile $AllowlistFile -TokenMapCsv $TokenMapCsv -WorkDir $WorkDir -ScrubPolicy $script:ScrubPolicy -HmacLength $HmacLength -ThrottleLimit $ThrottleLimit -ChunkSize $ChunkSize -SkipLeakCheck:$SkipLeakCheck -KeepIntermediate:$KeepIntermediate -Delimiter $parallelDelim
            }
            elseif ($useParallelScrub -and $textParallelEligible) {
                if ($autoParallelScrub -and -not $ParallelScrub) { Write-Info ("Auto-parallel scrub ({0} MB input; format={1}); throttle={2}; chunkSize={3}. Use -NoParallelScrub to disable; use -ChunkSize to customize." -f [Math]::Round(($t.Length / 1MB),1), $parallelFormat, $ThrottleLimit, $chunkSizeLabel) }
                $results += Invoke-ScrubFileParallelText -InputPath $t.FullName -OutputPath $outPath -Profile $prof -SensitiveTerms $SensitiveTerms -AllowlistFile $AllowlistFile -TokenMapCsv $TokenMapCsv -WorkDir $WorkDir -ScrubPolicy $script:ScrubPolicy -HmacLength $HmacLength -ThrottleLimit $ThrottleLimit -ChunkSize $ChunkSize -SkipLeakCheck:$SkipLeakCheck -KeepIntermediate:$KeepIntermediate
            }
            else {
                if ($ParallelScrub -and -not $DryRun -and -not $NoParallelScrub) { Write-Warn "ParallelScrub applies only to CSV/TSV/PSV and line-oriented Text/Kv scrub paths; using normal scrub for $($t.Name)." }
                $results += Invoke-ScrubFile -InputPath $t.FullName -OutputPath $outPath -Profile $prof -SensitiveTerms $SensitiveTerms -AllowlistFile $AllowlistFile -ScrubPolicy $script:ScrubPolicy -ExplainDetections:$ExplainDetections -DryRun:$DryRun -Stream:$useStream -SkipLeakCheck:$SkipLeakCheck -WorkerProgressFile $WorkerProgressFile -WorkerProgressRowsTotal $WorkerProgressRowsTotal -WorkerProgressChunk $WorkerProgressChunk -WorkerProgressIntervalRows $WorkerProgressIntervalRows -WorkerProgressIntervalSeconds $WorkerProgressIntervalSeconds
            }
        }
        catch {
            Write-Fail "Failed on $($t.Name): $($_.Exception.Message)"
            Write-Detail "type: $($_.Exception.GetType().FullName)"
            foreach ($frame in (@($_.ScriptStackTrace -split "`r?`n") | Select-Object -First 5)) { if ($frame -and $frame.Trim()) { Write-Detail $frame.Trim() } }
            $results += [pscustomobject]@{ Input = $t.FullName; Output = $null; Clean = $false; LeakCheckSkipped = $false; Error = $_.Exception.Message }
        }
    }

    # --- Manifest + summary ---
    Write-Host ""
    Write-Rule "Summary"
    if ($DryRun) {
        $tot = (@($results | ForEach-Object { $_.ChangeCount }) | Measure-Object -Sum).Sum
        if ($script:FalsePositiveReport) { [void](Write-DetectionReport -Path $script:FalsePositiveReport) }
        if ($script:DetectionSummaryReport) { [void](Write-DetectionSummaryReport -Path $script:DetectionSummaryReport) }
        Write-Ok "[DRY RUN] Complete. $tot value(s) across $($results.Count) file(s) would be tokenized."
        Write-Info "Nothing was written. Re-run without -DryRun to produce scrubbed files."
        if ($script:PerfReportEnabled) { [void](Write-UlsPerfReport -WorkDir $WorkDir) }
        Write-Host ""
        return $results
    }
    [void](Write-RunManifest -WorkDir $WorkDir -Results $results -TokenMapCsv $TokenMapCsv -TokenMapMode $TokenMapMode)
    if ($script:FalsePositiveReport) { [void](Write-DetectionReport -Path $script:FalsePositiveReport) }
    if ($script:DetectionSummaryReport) { [void](Write-DetectionSummaryReport -Path $script:DetectionSummaryReport) }
    if (-not $KeepIntermediate -and $intermediateTargets.Count -gt 0) {
        foreach ($mid in $intermediateTargets) {
            $used = @($results | Where-Object { $_.Input -eq $mid.FullName -and $_.Clean }).Count -gt 0
            if ($used) {
                try { Remove-Item -LiteralPath $mid.FullName -Force -ErrorAction Stop; Write-Info "Deleted unsafe intermediate: $($mid.Name)" }
                catch { Write-Warn "Could not delete intermediate '$($mid.FullName)': $($_.Exception.Message)" }
            }
        }
    }
    $okCount = @($results | Where-Object { $_.Clean }).Count
    $badCount = @($results | Where-Object { -not $_.Clean }).Count
    foreach ($r in $results) {
        $rn = if ($r.Output) { [System.IO.Path]::GetFileName($r.Output) } else { [System.IO.Path]::GetFileName($r.Input) }
        if ($r.Clean) { Write-Ok $rn }
        else { Write-Fail ($rn + "  (leak check did NOT pass or file failed -- review!)") }
    }
    Write-Host ""
    if ($badCount -eq 0) { Write-Ok "$okCount file(s) scrubbed and verified clean." }
    else { Write-Warn "$okCount clean, $badCount need review before upload." }
    if ($SafeBundleOut) {
        try { [void](New-SafeScrubBundle -Results $results -OutputPath $SafeBundleOut -Force:$Force) }
        catch { Write-Warn "Safe bundle was not created: $($_.Exception.Message)" }
    }
    Write-Host ""
    Write-Warn "NEVER upload: $TokenMapCsv"
    Write-Ok  "Safe to upload: the *_scrubbed.* files in $WorkDir"
    if ($script:PerfReportEnabled) { [void](Write-UlsPerfReport -WorkDir $WorkDir) }
    Write-Host ""
    return $results
}

# BEGIN ULS v4.13 current-version bugfixes: detection review and artifact filtering

# Override: broader generated/local artifact exclusion used by recommendations and folder scrubs.
function Test-GeneratedScrubArtifactName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -match '(?i)(_scrubbed|\.scrubbed\.|token_map|DO_NOT_UPLOAD|false_positive|detection_report|detection_review|scrub_run_manifest|manifest\.json|profile_build_report|generated-profile|profile-template)') { return $true }
    if ([System.IO.Path]::GetExtension($Name) -ieq '.zip') { return $true }
    return $false
}

function __ULS_Legacy_Test_PreserveNonSensitiveDottedArtifactName_5798 {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }

    $v = $Value.Trim()

    # Only preserve bare dotted artifacts here. Anything with stronger network,
    # credential, URL, email, or path signals should remain eligible for normal
    # tokenization. Strict mode intentionally does not use this readability rule.
    if ($script:ScrubPolicy -eq 'Strict') { return $false }
    if ($v -match '@|://|[\\/]|^\d') { return $false }
    if ($v -notmatch '\.') { return $false }
    if ($v.Length -gt 160) { return $false }

    # Preserve local/config filenames that the generic FQDN detector often sees
    # in logs. This is extension-shape based, not an exact-value allowlist.
    if ($v -match '(?i)^[A-Za-z0-9_.-]+\.(properties|conf|cfg|ini|yaml|yml|toml|xml|json|log|txt|pid|lock|policy|rules|template|templates|jar|war|ear|class)$') {
        return $true
    }

    $parts = @($v -split '\.')
    if ($parts.Count -lt 2) { return $false }

    # Avoid preserving ordinary public-domain-shaped two-part names like
    # example.com, example.net, etc. This keeps the heuristic conservative.
    $publicTlds = @{
        'com'=$true; 'net'=$true; 'org'=$true; 'edu'=$true; 'gov'=$true; 'mil'=$true; 'int'=$true;
        'io'=$true; 'co'=$true; 'us'=$true; 'uk'=$true; 'ca'=$true; 'de'=$true; 'fr'=$true; 'au'=$true;
        'br'=$true; 'mx'=$true; 'cn'=$true; 'jp'=$true; 'in'=$true; 'ru'=$true; 'eu'=$true; 'biz'=$true;
        'info'=$true; 'dev'=$true; 'app'=$true; 'cloud'=$true; 'local'=$true; 'lan'=$true
    }
    $lastLower = $parts[-1].ToLowerInvariant()
    if ($parts.Count -eq 2 -and $publicTlds.ContainsKey($lastLower)) { return $false }

    # Preserve Java/property-style keys and ZooKeeper/log-framework labels.
    # This is family/shape based, not exact-value allowlisting.
    $safePropertyPrefixes = @{
        'java'=$true; 'javax'=$true; 'jdk'=$true; 'sun'=$true; 'os'=$true; 'user'=$true;
        'file'=$true; 'path'=$true; 'line'=$true; 'host'=$true; 'zookeeper'=$true;
        'autopurge'=$true; 'snap'=$true; 'data'=$true; 'client'=$true; 'server'=$true;
        'quorum'=$true; 'sync'=$true; 'tick'=$true; 'init'=$true; 'leader'=$true;
        'election'=$true; 'log4j'=$true; 'slf4j'=$true; 'netty'=$true; 'jline'=$true;
        'xerces'=$true; 'xml'=$true; 'xmlParserAPIs'=$true
    }
    $first = $parts[0]
    $firstLower = $first.ToLowerInvariant()
    if ($safePropertyPrefixes.ContainsKey($firstLower)) {
        return $true
    }

    # Preserve compact metric/state labels like n.sid, n.zxid, n.peerEpoch, etc.
    if ($parts.Count -eq 2 -and $first.Length -le 3 -and $parts[1] -match '^[A-Za-z][A-Za-z0-9_-]{1,48}$') {
        return $true
    }

    # Preserve method/context identifiers such as workerEnv.init.
    if ($parts.Count -eq 2) {
        $left = $parts[0]
        $right = $parts[1]
        if (($left -match '[a-z][A-Z]') -and ($right -match '^[A-Za-z_][A-Za-z0-9_-]{1,48}$')) {
            return $true
        }
    }

    # Preserve Java fully-qualified class/package symbols when they have a Java-ish
    # package root and at least one class-like segment. Real DNS labels are normally
    # lowercase; class symbols commonly include PascalCase/camelCase segments.
    if ($parts.Count -ge 3 -and $firstLower -in @('org','com','net','io','edu','gov')) {
        $hasClassLikeSegment = $false
        foreach ($p in $parts) {
            if ($p -match '[A-Z]' -and $p -match '^[A-Za-z_][A-Za-z0-9_$-]*$') {
                $hasClassLikeSegment = $true
                break
            }
        }
        if ($hasClassLikeSegment) { return $true }
    }

    return $false
}

# Override: DNS/FQDN preservation now keeps obvious local dotted artifacts in Balanced/Readable.
function __ULS_Legacy_Test_PreserveDetectedValue_5880 {
    param(
        [string]$Value,
        [string]$Detector,
        [string]$Prefix,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if (Test-ScrubAllowlist -Value $Value) { return $true }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }
    $v = $Value.Trim()
    if (Is-AlreadyToken -Value $v) { return $true }
    if (Test-PreserveDottedDecimal -Value $v) { return $true }
    if (($Prefix -eq 'IP' -or $Prefix -eq 'IP6') -and (Test-PreserveIpAddress -Value $v)) { return $true }
    if ($Prefix -eq 'GUID' -and (Test-PreserveGuid -Value $v)) { return $true }
    if ($Detector -eq 'DOMAIN\user' -or $Prefix -eq 'PRINCIPAL') {
        if (Test-WindowsPathLikeDomainUser -Value $v -Text $Text -Index $Index -Length $Length) { return $true }
    }
    if ($Prefix -eq 'DNS') {
        if (Test-AllowedDomain -Value $v) { return $true }
        if (Test-WindowsDiagnosticDottedName -Value $v) { return $true }
        if (Test-PreserveNonSensitiveDottedArtifactName -Value $v -Text $Text -Index $Index -Length $Length) { return $true }
        if ($script:ScrubPolicy -eq 'Readable' -and (Test-KnownFileOrDiagnosticName -Value $v)) { return $true }
    }
    if ($Prefix -eq 'BLOB' -and -not (Test-LooksLikeBase64Blob -Value $v)) { return $true }
    if (($Prefix -eq 'GUID' -or $Prefix -eq 'CERT') -and (Test-DiagnosticContext -Text $Text -Index $Index -Length $Length)) { return $true }
    return $false
}

# Override: shape fallback should not classify obvious local dotted artifact names as DNS.
function __ULS_Legacy_Get_ValueShapePrefix_5912 {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim()
    if ($v -match '^S-1-\d+-')                                                  { return 'SID' }
    if ($v -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') { return 'GUID' }
    if ($v -match '^[0-9a-fA-F]{32,}$')                                         { return 'CERT' }
    if ($v -match '^[^@\s]+@[^@\s]+\.[^@\s]+$')                              { return 'UNMAPPED_UPN' }
    if ($v -match '^\d{1,3}(\.\d{1,3}){3}$')                                  { return 'IP' }
    if ($v -match '^[A-Za-z0-9_.-]+\\[A-Za-z0-9_.\-$]+$')                     { return 'PRINCIPAL' }
    if ($v -match '^(CN|OU|DC|O|L|ST|C)=')                                      { return 'X500' }
    if ($v -match '^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$') {
        if (Test-PreserveNonSensitiveDottedArtifactName -Value $v) { return $null }
        return 'DNS'
    }
    return $null
}

# Override: recommendation targets skip generated/local artifacts consistently.
function Resolve-LogRecommendationTargets {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Recurse,
        [string[]]$Include,
        [string[]]$Exclude
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Path is required.' }
    $targets = @()
    if (Test-Path -LiteralPath $Path -PathType Container) {
        $targets = @(Get-ChildItem -LiteralPath $Path -File -Recurse:$Recurse -ErrorAction SilentlyContinue)
    }
    elseif (Test-Path -LiteralPath $Path -PathType Leaf) {
        $targets = @(Get-Item -LiteralPath $Path)
    }
    else { throw "Path not found: $Path" }

    $targets = @($targets | Where-Object { -not (Test-GeneratedScrubArtifactName -Name $_.Name) })
    if ($Include -and $Include.Count -gt 0) {
        $targets = @($targets | Where-Object {
            $ok = $false
            foreach ($pat in $Include) { if ($_.Name -like $pat) { $ok = $true; break } }
            $ok
        })
    }
    if ($Exclude -and $Exclude.Count -gt 0) {
        $targets = @($targets | Where-Object {
            $skip = $false
            foreach ($pat in $Exclude) { if ($_.Name -like $pat) { $skip = $true; break } }
            -not $skip
        })
    }
    return @($targets | Sort-Object FullName)
}

# END ULS v4.13 current-version bugfixes

# BEGIN ULS v4.13 hotfix: positive detection review rows
# Current-version bugfix only: no version/banner/schema bump.

# Override: return detector/reason metadata and add Tokenized trace rows for positive dry-run detections.
function __ULS_Legacy_Find_Identifiers_6388 {
    param([Parameter(Mandatory)][string]$Text)

    $found = @{}   # normalizedKey -> identifier object

    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

    function _AddFoundIdentifier {
        param(
            [string]$Raw,
            [string]$Prefix,
            [string]$Detector,
            [string]$Reason,
            [int]$Index = -1,
            [int]$Length = 0,
            [string]$ColumnName = ''
        )

        if ([string]::IsNullOrWhiteSpace($Raw)) { return }
        if ([string]::IsNullOrWhiteSpace($Prefix)) { return }

        $norm = Normalize-TokenKey -Value $Raw
        if (-not $norm -or $found.ContainsKey($norm)) { return }

        $tokenPreview = ''
        try { $tokenPreview = Get-Token -Value $Raw -Prefix $Prefix } catch { $tokenPreview = '' }

        Add-DetectionTrace `
            -Detector $Detector `
            -Action 'Tokenized' `
            -Value $Raw `
            -Token $tokenPreview `
            -Reason $Reason `
            -ColumnName $ColumnName `
            -Context (Get-DetectionContext -Text $Text -Index $Index -Length $Length)

        $found[$norm] = [pscustomobject]@{
            Raw      = $Raw
            Prefix   = $Prefix
            Detector = $Detector
            Reason   = $Reason
        }
    }

    foreach ($id in (Find-UniversalLabeledIdentifiers -Text $Text)) {
        $reason = if ($id.Rule) { [string]$id.Rule } else { 'Universal label rule' }
        _AddFoundIdentifier -Raw $id.Raw -Prefix $id.Prefix -Detector 'UniversalLabel' -Reason $reason -ColumnName '(label)'
    }

    foreach ($id in (Find-CustomRegexIdentifiers -Text $Text)) {
        $reason = if ($id.Rule) { [string]$id.Rule } else { 'Custom regex rule' }
        _AddFoundIdentifier -Raw $id.Raw -Prefix $id.Prefix -Detector 'CustomRegex' -Reason $reason -ColumnName '(custom-regex)'
    }

    foreach ($id in (Find-SecretIdentifiers -Text $Text)) {
        $reason = switch ($id.Prefix) {
            'PEM'     { 'Private key block' }
            'CONNSTR' { 'Connection string pattern' }
            'APIKEY'  { 'API key/token pattern' }
            default   { 'Secret pattern' }
        }
        _AddFoundIdentifier -Raw $id.Raw -Prefix $id.Prefix -Detector 'Secret' -Reason $reason -ColumnName '(secret)'
    }

    foreach ($d in $script:ShapeDetectors) {
        # ULS perf patch 6: skip a shape detector when its required literal is absent (the same
        # Sentinel guard the scrub path uses), so discovery short-circuits like the scrub.
        if ($d.Sentinel -and ($Text.IndexOf([string]$d.Sentinel, [System.StringComparison]::OrdinalIgnoreCase) -lt 0)) { continue }
        foreach ($m in [regex]::Matches($Text, $d.Rx)) {
            $raw = $m.Value

            if ([string]::IsNullOrWhiteSpace($raw)) { continue }
            if (Is-AlreadyToken -Value $raw) { continue }
            if (Test-PreserveDottedDecimal -Value $raw) { continue }
            if ($d.Skip -and ($raw -match $d.Skip)) { continue }

            # Keep well-known public domains readable. They are intentionally not
            # positive detections because they are allowlisted public diagnostics.
            if (($d.Prefix -eq 'DNS' -or $d.Prefix -eq 'UNMAPPED_UPN') -and (Test-AllowedDomain -Value $raw)) { continue }

            if (Test-PreserveDetectedValue -Value $raw -Detector $d.Name -Prefix $d.Prefix -Text $Text -Index $m.Index -Length $m.Length) {
                Add-DetectionTrace `
                    -Detector $d.Name `
                    -Action 'Preserved' `
                    -Value $raw `
                    -Token '' `
                    -Reason 'Discovery preserve' `
                    -Context (Get-DetectionContext -Text $Text -Index $m.Index -Length $m.Length)
                continue
            }

            _AddFoundIdentifier `
                -Raw $raw `
                -Prefix $d.Prefix `
                -Detector $d.Name `
                -Reason 'Shape detector' `
                -Index $m.Index `
                -Length $m.Length `
                -ColumnName '(shape)'
        }
    }

    return @($found.Values)
}

# END ULS v4.13 hotfix: positive detection review rows



# BEGIN ULS v4.13 OpenSSH log hardening hotfix
# Addresses common sshd/syslog free-text forms that are not label:value pairs:
#   - syslog emitter hostname after timestamp (for example: "Dec 10 06:55:46 LabSZ sshd[...]")
#   - OpenSSH authentication usernames in prose (Invalid user, Failed password for ...)
#   - reverse-DNS hostnames before IPv4 hardening can split numeric-leading FQDNs
# This is heuristic/contextual matching, not a static allowlist or static denylist.

if (-not (Get-Variable -Name __ULS_FindIdentifiers_BeforeOpenSsh -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_FindIdentifiers_BeforeOpenSsh = ${function:__ULS_Legacy_Find_Identifiers_6388}
}
if (-not (Get-Variable -Name __ULS_InvokeFreeTextHardening_BeforeOpenSsh -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_InvokeFreeTextHardening_BeforeOpenSsh = ${function:__ULS_Legacy_Invoke_FreeTextHardening_3040}
}
if (-not (Get-Variable -Name __ULS_InvokeLeakHardeningText_BeforeOpenSsh -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_InvokeLeakHardeningText_BeforeOpenSsh = ${function:__ULS_Legacy_Invoke_LeakHardeningText_3170}
}

function Test-UlsOpenSshLogText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return ($Text -match '(?im)^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+sshd(?:\[\d+\])?:')
}

function Get-UlsOpenSshValuePrefix {
    param([string]$Value, [string]$DefaultPrefix = 'HOST')
    if ([string]::IsNullOrWhiteSpace($Value)) { return $DefaultPrefix }
    $v = $Value.Trim()
    if ($v -match '^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$') { return 'IP' }
    if ($v -match '^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}$') { return 'DNS' }
    return $DefaultPrefix
}

function Add-UlsOpenSshIdentifier {
    param(
        [Parameter(Mandatory)]$List,
        [Parameter(Mandatory)][hashtable]$Seen,
        [string]$Raw,
        [string]$Prefix,
        [string]$Detector = 'OpenSSHAuth',
        [string]$Reason = 'OpenSSH auth context',
        [int]$Index = -1,
        [int]$Length = 0
    )

    if ([string]::IsNullOrWhiteSpace($Raw)) { return }
    $v = ([string]$Raw).Trim()
    $v = $v.TrimStart([char[]]@('[','('))
    $v = $v.TrimEnd([char[]]@('.', ',', ';', ':', ']', ')'))
    if ([string]::IsNullOrWhiteSpace($v)) { return }
    if (Is-AlreadyToken -Value $v) { return }
    if ($v -match '^(?:-|unknown|none|null|\(null\))$') { return }

    $p = if ([string]::IsNullOrWhiteSpace($Prefix)) { Get-UlsOpenSshValuePrefix -Value $v } else { $Prefix }
    $norm = Normalize-TokenKey -Value $v
    if (-not $norm) { return }
    if ($Seen.ContainsKey($norm)) { return }
    $Seen[$norm] = $true

    [void]$List.Add([pscustomobject]@{
        Raw      = $v
        Prefix   = $p
        Detector = $Detector
        Reason   = $Reason
        Index    = $Index
        Length   = $(if ($Length -gt 0) { $Length } else { $v.Length })
    })
}

function Find-OpenSshAuthIdentifiers {
    param([Parameter(Mandatory)][string]$Text)

    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    if (-not (Test-UlsOpenSshLogText -Text $Text)) { return @() }

    $patterns = @(
        [pscustomobject]@{ Pattern='(?m)^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)([A-Za-z][A-Za-z0-9_.-]{1,127})(?=\s+sshd(?:\[\d+\])?:)'; Group=2; Prefix=''; Reason='Syslog emitter hostname' },
        [pscustomobject]@{ Pattern='(?i)\bgetaddrinfo\s+for\s+([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})(?=\s+\[)'; Group=1; Prefix='DNS'; Reason='OpenSSH reverse-DNS hostname' },
        [pscustomobject]@{ Pattern='(?i)\brhost=([^\s]+)'; Group=1; Prefix=''; Reason='OpenSSH rhost value' },
        [pscustomobject]@{ Pattern='(?i)\bfrom\s+([A-Za-z0-9][A-Za-z0-9_.-]*)(?=\s+(?:port\b|ssh2\b|\[preauth\]|$))'; Group=1; Prefix=''; Reason='OpenSSH remote endpoint' },
        [pscustomobject]@{ Pattern='(?i)\bInvalid user\s+([^\s]+)(?=\s+from\b)'; Group=1; Prefix='PRINCIPAL'; Reason='OpenSSH invalid username' },
        [pscustomobject]@{ Pattern='(?i)\binput_userauth_request:\s+invalid user\s+([^\s\[]+)'; Group=1; Prefix='PRINCIPAL'; Reason='OpenSSH invalid username' },
        [pscustomobject]@{ Pattern='(?i)\bFailed password for invalid user\s+([^\s]+)(?=\s+from\b)'; Group=1; Prefix='PRINCIPAL'; Reason='OpenSSH failed-password username' },
        [pscustomobject]@{ Pattern='(?i)\bFailed password for\s+([^\s]+)(?=\s+from\b)'; Group=1; Prefix='PRINCIPAL'; Reason='OpenSSH failed-password username' },
        [pscustomobject]@{ Pattern='(?i)\bToo many authentication failures for\s+([^\s\[]+)'; Group=1; Prefix='PRINCIPAL'; Reason='OpenSSH auth-failure username' },
        [pscustomobject]@{ Pattern='(?i)\buser=([^\s]+)'; Group=1; Prefix='PRINCIPAL'; Reason='OpenSSH user field' }
    )

    foreach ($spec in $patterns) {
        $rx = New-ScrubRegex -Pattern ([string]$spec.Pattern) -Context "OpenSSH auth detector '$($spec.Reason)'"
        foreach ($m in $rx.Matches($Text)) {
            $g = $m.Groups[[int]$spec.Group]
            if (-not $g.Success) { continue }
            $raw = $g.Value
            $prefix = [string]$spec.Prefix
            if ([string]::IsNullOrWhiteSpace($prefix)) { $prefix = Get-UlsOpenSshValuePrefix -Value $raw }
            Add-UlsOpenSshIdentifier -List $out -Seen $seen -Raw $raw -Prefix $prefix -Reason ([string]$spec.Reason) -Index $g.Index -Length $g.Length
        }
    }

    return @($out.ToArray())
}

function Invoke-OpenSshAuthHardening {
    param([Parameter(Mandatory)][string]$Text, [string]$ColumnName = '')
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    if (-not (Test-UlsOpenSshLogText -Text $Text)) { return $Text }

    $out = $Text

    function _ReplaceOpenSshGroup {
        param(
            [Parameter(Mandatory)][string]$InputText,
            [Parameter(Mandatory)][string]$Pattern,
            [int]$GroupNumber = 1,
            [string]$Prefix = '',
            [string]$Reason = 'OpenSSH auth context'
        )

        $rx = New-ScrubRegex -Pattern $Pattern -Context "OpenSSH hardening '$Reason'"
        return $rx.Replace($InputText, {
            param($m)
            $g = $m.Groups[$GroupNumber]
            if (-not $g.Success) { return $m.Value }

            $raw = $g.Value.Trim()
            $clean = $raw.TrimStart([char[]]@('[','(')).TrimEnd([char[]]@('.', ',', ';', ':', ']', ')'))
            if ([string]::IsNullOrWhiteSpace($clean)) { return $m.Value }
            if (Is-AlreadyToken -Value $clean) { return $m.Value }
            if ($clean -match '^(?:-|unknown|none|null|\(null\))$') { return $m.Value }

            $p = if ([string]::IsNullOrWhiteSpace($Prefix)) { Get-UlsOpenSshValuePrefix -Value $clean } else { $Prefix }
            $tok = Get-Token -Value $clean -Prefix $p
            Add-DetectionTrace -Detector 'OpenSSHAuth' -Action 'Tokenized' -Value $clean -Token $tok -Reason $Reason -ColumnName $ColumnName -Context (Get-DetectionContext -Text $InputText -Index $g.Index -Length $g.Length)

            $rel = $g.Index - $m.Index
            if ($rel -lt 0) { return $m.Value }
            $before = $m.Value.Substring(0, $rel)
            $afterStart = $rel + $g.Length
            $after = if ($afterStart -lt $m.Value.Length) { $m.Value.Substring($afterStart) } else { '' }
            return $before + $tok + $after
        })
    }

    # Do DNS-like OpenSSH fields before the generic IPv4 detector to avoid split tokens
    # such as IP_x.DNS_y for numeric-leading reverse-DNS hostnames.
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?m)^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)([A-Za-z][A-Za-z0-9_.-]{1,127})(?=\s+sshd(?:\[\d+\])?:)' -GroupNumber 2 -Prefix '' -Reason 'Syslog emitter hostname'
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?i)(\bgetaddrinfo\s+for\s+)([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})(?=\s+\[)' -GroupNumber 2 -Prefix 'DNS' -Reason 'OpenSSH reverse-DNS hostname'
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?i)(\brhost=)([^\s]+)' -GroupNumber 2 -Prefix '' -Reason 'OpenSSH rhost value'
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?i)(\bfrom\s+)([A-Za-z0-9][A-Za-z0-9_.-]*)(?=\s+(?:port\b|ssh2\b|\[preauth\]|$))' -GroupNumber 2 -Prefix '' -Reason 'OpenSSH remote endpoint'

    # Then handle auth usernames expressed in prose rather than label:value form.
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?i)(\bInvalid user\s+)([^\s]+)(?=\s+from\b)' -GroupNumber 2 -Prefix 'PRINCIPAL' -Reason 'OpenSSH invalid username'
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?i)(\binput_userauth_request:\s+invalid user\s+)([^\s\[]+)' -GroupNumber 2 -Prefix 'PRINCIPAL' -Reason 'OpenSSH invalid username'
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?i)(\bFailed password for invalid user\s+)([^\s]+)(?=\s+from\b)' -GroupNumber 2 -Prefix 'PRINCIPAL' -Reason 'OpenSSH failed-password username'
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?i)(\bFailed password for\s+)([^\s]+)(?=\s+from\b)' -GroupNumber 2 -Prefix 'PRINCIPAL' -Reason 'OpenSSH failed-password username'
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?i)(\bToo many authentication failures for\s+)([^\s\[]+)' -GroupNumber 2 -Prefix 'PRINCIPAL' -Reason 'OpenSSH auth-failure username'
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?i)(\buser=)([^\s]+)' -GroupNumber 2 -Prefix 'PRINCIPAL' -Reason 'OpenSSH user field'

    return $out
}

function Find-Identifiers {
    param([Parameter(Mandatory)][string]$Text)

    $base = @(& $script:__ULS_FindIdentifiers_BeforeOpenSsh -Text $Text)
    $seen = @{}
    foreach ($id in $base) {
        if ($id -and $id.Raw) {
            $norm = Normalize-TokenKey -Value ([string]$id.Raw)
            if ($norm) { $seen[$norm] = $true }
        }
    }

    $extra = New-Object System.Collections.Generic.List[object]
    foreach ($id in (Find-OpenSshAuthIdentifiers -Text $Text)) {
        if (-not $id -or [string]::IsNullOrWhiteSpace([string]$id.Raw)) { continue }
        $norm = Normalize-TokenKey -Value ([string]$id.Raw)
        if (-not $norm -or $seen.ContainsKey($norm)) { continue }
        $seen[$norm] = $true
        $tok = Get-Token -Value ([string]$id.Raw) -Prefix ([string]$id.Prefix)
        Add-DetectionTrace -Detector 'OpenSSHAuth' -Action 'Tokenized' -Value ([string]$id.Raw) -Token $tok -Reason ([string]$id.Reason) -ColumnName '(openssh)' -Context (Get-DetectionContext -Text $Text -Index ([int]$id.Index) -Length ([int]$id.Length))
        [void]$extra.Add([pscustomobject]@{
            Raw      = [string]$id.Raw
            Prefix   = [string]$id.Prefix
            Detector = 'OpenSSHAuth'
            Reason   = [string]$id.Reason
        })
    }

    return @($base + @($extra.ToArray()))
}

function Invoke-FreeTextHardening {
    param([string]$ColumnName, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $pre = Invoke-OpenSshAuthHardening -Text $Value -ColumnName $ColumnName
    $pre = Invoke-UlsConnectionHostHardening -Text $pre -ColumnName $ColumnName
    return [string](& $script:__ULS_InvokeFreeTextHardening_BeforeOpenSsh -ColumnName $ColumnName -Value $pre)
}

function Invoke-LeakHardeningText {
    param([Parameter(Mandatory)][string]$Text)
    $pre = Invoke-OpenSshAuthHardening -Text $Text -ColumnName ''
    $pre = Invoke-UlsConnectionHostHardening -Text $pre -ColumnName ''
    return [string](& $script:__ULS_InvokeLeakHardeningText_BeforeOpenSsh -Text $pre)
}

# END ULS v4.13 OpenSSH log hardening hotfix

# BEGIN ULS v4.13 hotfix: broad dotted/label FP preservation
# Current-version bugfix only: no version/banner/schema bump.
#
# Purpose:
#   Preserve common non-sensitive diagnostic identifiers that look like DNS/FQDNs,
#   URLs, secrets, or base64 only because of their shape:
#     - Android/Java package/class/action names
#     - Hadoop/Spark/OpenStack logger/config namespaces
#     - local artifact filenames (.jar, .map, .rts, .app in app-path context, etc.)
#     - ACPI/kernel/device diagnostic names
#     - harmless label-rule captures such as "Auth", "Starting", "/dev/sda", and port "80"
#
# Guardrails:
#   - Strict policy still tokenizes.
#   - Network/identity/path forms are not globally preserved here.
#   - Real rhost/reverse-DNS/proxy destination domains remain tokenized unless existing allowlists preserve them.

function __ULS_Legacy_Test_PreserveNonSensitiveDottedArtifactName_6726 {
    param([string]$Value, [string]$Text, [int]$Index = -1, [int]$Length = 0)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    if ($v -notmatch '\.') { return $false }

    # Do not preserve obvious network/identity/path forms here.
    # Local paths are handled separately by label/path-aware preservation.
    if ($v -match '@|://|\\|/') { return $false }

    # Values beginning with digits are often message ids, reverse DNS fragments,
    # timestamps, or generated object ids; do not blanket-preserve them.
    if ($v -match '^\d') { return $false }

    # Obvious local/config/source/log artifacts that commonly false-match FQDN.
    if ($v -match '(?i)\.(properties|conf|cfg|ini|yaml|yml|toml|xml|json|log|txt|pid|lock|policy|rules|template|templates|jar|jhist|map|mapfile|rts|trace)$') { return $true }

    # Kernel/initrd image names in Linux/HPC logs.
    if ($v -match '(?i)^(vmlinuz|initrd)-\d+(?:[.\w-]+)+$') { return $true }

    # .app can be a public TLD, so preserve only when it clearly looks like a
    # macOS bundle/app artifact or appears in app-bundle context.
    if ($v -match '(?i)^[A-Za-z0-9 _-]+\.app$') {
        if (($Value -cmatch '^[A-Z]') -or ($Text -match '(?i)(/Applications/|/System/Library/|CoreServices|PlugIns|\.app/Contents)')) { return $true }
    }

    # ACPI routing paths in Thunderbird/HPC style logs: PCI0.PALO.DOBA, PCI0.PBHI.PXB.
    if ($v -match '^[A-Z0-9_]+(?:\.[A-Z0-9_]+){1,8}$') {
        if ($Text -match '(?i)(ACPI|PCI Interrupt|_PRT|BOOT_IMAGE|kernel command line)') { return $true }
    }

    $parts = @($v -split '\.')
    if ($parts.Count -eq 2) {
        $left = $parts[0]
        $right = $parts[1]

        # Method/context identifiers like workerEnv.init and NIOServerCxn.Factory.
        if (($left -match '[a-z][A-Z]') -and ($right -match '(?i)^(init|start|stop|run|load|save|open|close|read|write|parse|build|handle|process|worker|factory|service|manager|env|activity)$')) { return $true }

        # Known Apache/mod_jk style symbolic names and short ZooKeeper labels.
        if ($v -match '(?i)^(workerEnv|mod_jk|jk2|ajp13|n)\.[A-Za-z_][A-Za-z0-9_]*$') { return $true }
    }

    # Android / Java / Apple diagnostic namespaces.
    if ($v -match '^(android|java|javax|sun|kotlin|scala)\.[A-Za-z0-9_.-]+$') { return $true }
    if ($v -match '^(com\.apple|com\.android|org\.apache)\.[A-Za-z0-9_.-]+$') { return $true }
    if ($v -match '^vnd\.android\.package$') { return $true }

    # Android app/component/plugin names and public framework action strings.
    if ($v -match '^(activity|business|cooperation|plugin|system)\.[A-Za-z0-9_.-]+$') { return $true }

    # Hadoop/Spark/OpenStack config keys and logger namespaces.
    if ($v -match '^(mapred|mapreduce|yarn|hadoop|zookeeper|autopurge|os|user)\.[A-Za-z0-9_.-]+$') { return $true }
    if ($v -match '^http\.requests\.[A-Za-z0-9_.-]+$') { return $true }
    if ($v -match '^SecurityLogger\.org\.apache\.[A-Za-z0-9_.-]+$') { return $true }
    if ($v -match '^(nova|compute)\.[A-Za-z0-9_.-]+$') { return $true }

    # Java/reversed-package class-like symbols with a class/component at the end.
    # Avoid generic public domains by requiring a known code namespace or uppercase class-like final segment.
    if ($v -match '^(com|org|net)\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$') {
        $last = $parts[-1]
        if ($last -cmatch '[A-Z]' -and $last -match '(Activity|Service|Server|Manager|Factory|Driver|Exception|Error|Proxy|Handler|Peer|Cache|Logger|Domain)$') { return $true }
    }

    return $false
}

function __ULS_Legacy_Test_PreserveLikelyBenignUniversalLabelValue_6796 {
    param(
        [string]$Value,
        [string]$Detector,
        [string]$Prefix,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }
    if ($Detector -ne 'UniversalLabel') { return $false }

    $v = $Value.Trim().Trim('"', "'", ',', ';', ')', ']', '}')

    # Label rules can over-capture generic words after "host/address/domain" style labels.
    # Preserve only known harmless diagnostic words, not arbitrary single-word hostnames.
    if ($Prefix -eq 'DNS') {
        if ($v -match '^(?i)(Auth|IPC|Starting|Connection|routing|type|nginx|no|\[?ContainerId:?)$') { return $true }
        if ($v -match '^/dev/[A-Za-z0-9._/-]+$') { return $true }
        if ($v -match '^<KSOmahaServer:0x[0-9a-fA-F]+$') { return $true }
        if (Test-PreserveNonSensitiveDottedArtifactName -Value $v -Text $Text -Index $Index -Length $Length) { return $true }
    }

    # Android log labels produced a principal capture of "0". Preserve only the
    # zero singleton, not real usernames like root/test/mysql.
    if ($Prefix -eq 'PRINCIPAL') {
        if ($v -eq '0') { return $true }
    }

    # Proxifier produced a DomainTenantLabels capture of port "80".
    if ($Prefix -eq 'X500') {
        if ($v -match '^\d{1,5}$') { return $true }
        if ($v -match '^(NS[A-Za-z0-9]+ErrorDomain|kCFErrorDomain[A-Za-z0-9]+|[A-Z][A-Za-z0-9]+ErrorDomain|com\.apple\.[A-Za-z0-9_.-]+)$') { return $true }
    }

    return $false
}

function __ULS_Legacy_Test_PreserveLikelyBenignSecretValue_6836 {
    param([string]$Value, [string]$Text, [int]$Index = -1, [int]$Length = 0)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = $Value.Trim().Trim('"', "'", ',', ';', ')', ']', '}')

    # Java/Android exception class names and Apple XPC activity diagnostics are not secrets.
    if ($v -match '^(android|java|javax|org|com)\.[A-Za-z0-9_.]+Exception$') { return $true }
    if ($v -match '^com\.apple\.xpc\.activity/\d+$') { return $true }

    return $false
}

function __ULS_Legacy_Test_PreserveLikelyBenignBase64FalsePositive_6851 {
    param([string]$Value, [string]$Text, [int]$Index = -1, [int]$Length = 0)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = $Value.Trim().Trim('"', "'", ',', ';', ')', ']', '}')

    # macOS framework/class names can be long mixed-case alphabetic strings and
    # accidentally trip base64-ish shape detectors. Preserve obvious PascalCase symbols.
    if ($v -match '^[A-Za-z]{24,120}$' -and $v -cmatch '[a-z][A-Z]' -and $v -match '(Action|Transport|Controller|Constraint|Constraints|Layout|Bluetooth|Visualize|Server|Manager|Domain)') { return $true }

    return $false
}

function __ULS_Legacy_Test_PreserveDetectedValue_6866 {
    param(
        [string]$Value,
        [string]$Detector,
        [string]$Prefix,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if (Test-ScrubAllowlist -Value $Value) { return $true }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = $Value.Trim()
    if (Is-AlreadyToken -Value $v) { return $true }

    # Additional broad false-positive reducers.
    if (Test-PreserveLikelyBenignUniversalLabelValue -Value $v -Detector $Detector -Prefix $Prefix -Text $Text -Index $Index -Length $Length) { return $true }
    if ($Prefix -eq 'SECRET' -and (Test-PreserveLikelyBenignSecretValue -Value $v -Text $Text -Index $Index -Length $Length)) { return $true }
    if ($Prefix -eq 'BLOB' -and (Test-PreserveLikelyBenignBase64FalsePositive -Value $v -Text $Text -Index $Index -Length $Length)) { return $true }

    # Existing preservation behavior retained.
    if (Test-PreserveDottedDecimal -Value $v) { return $true }
    if (($Prefix -eq 'IP' -or $Prefix -eq 'IP6') -and (Test-PreserveIpAddress -Value $v)) { return $true }
    if ($Prefix -eq 'GUID' -and (Test-PreserveGuid -Value $v)) { return $true }
    if ($Detector -eq 'DOMAIN\user' -or $Prefix -eq 'PRINCIPAL') {
        if (Test-WindowsPathLikeDomainUser -Value $v -Text $Text -Index $Index -Length $Length) { return $true }
    }
    if ($Prefix -eq 'DNS') {
        if (Test-AllowedDomain -Value $v) { return $true }
        if (Test-WindowsDiagnosticDottedName -Value $v) { return $true }
        if (Test-PreserveNonSensitiveDottedArtifactName -Value $v -Text $Text -Index $Index -Length $Length) { return $true }
        if ($script:ScrubPolicy -eq 'Readable' -and (Test-KnownFileOrDiagnosticName -Value $v)) { return $true }
    }
    if ($Prefix -eq 'BLOB' -and -not (Test-LooksLikeBase64Blob -Value $v)) { return $true }
    if (($Prefix -eq 'GUID' -or $Prefix -eq 'CERT') -and (Test-DiagnosticContext -Text $Text -Index $Index -Length $Length)) { return $true }

    return $false
}

function __ULS_Legacy_Get_ValueShapePrefix_6907 {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim().Trim('"', "'", ',', ';', ')', ']', '}')

    if ($v -match '^S-1-\d+-')                                                     { return 'SID' }
    if ($v -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$')  { return 'GUID' }
    if ($v -match '^[0-9a-fA-F]{32,}$')                                            { return 'CERT' }
    if ($v -match '^[^@\s]+@[^@\s]+\.[^@\s]+$')                                    { return 'UNMAPPED_UPN' }
    if ($v -match '^\d{1,3}(\.\d{1,3}){3}$')                                       { return 'IP' }
    if ($v -match '^[A-Za-z0-9_.-]+\\[A-Za-z0-9_.\-$]+$')                          { return 'PRINCIPAL' }
    if ($v -match '^(CN|OU|DC|O|L|ST|C)=')                                         { return 'X500' }

    if ($v -match '^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$') {
        if (Test-PreserveNonSensitiveDottedArtifactName -Value $v) { return $null }
        return 'DNS'
    }

    return $null
}

# END ULS v4.13 hotfix: broad dotted/label FP preservation

# BEGIN ULS v4.13 hotfix: broad FP preservation round 2
# Current-version bugfix only: no version/banner/schema bump.
#
# This later override intentionally shadows the earlier v4.13 preservation helpers.
# It keeps real network/privacy-bearing values tokenized while preserving common
# local diagnostic symbols that only look like DNS/FQDNs because they are dotted.

function Test-UlsCommonPublicNetworkDomain {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}').ToLowerInvariant()

    # Values in these domains are usually real web/proxy/reverse-DNS destinations.
    # Do not blanket-preserve them as software/package namespaces.
    if ($v -match '(^|\.)((com|net|org|edu|gov|mil|io|cn|jp|de|nl|uk|br|mx|tw|hk|at|eu|ru|in|fr|au|ca|us|info|biz|asia)$)') {
        return $true
    }

    return $false
}

function Test-UlsLikelyCodeOrConfigNamespace {
    param([string]$Value, [string]$Text)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')

    # Android package/action/component symbols from Android/HealthApp logs.
    if ($v -match '^(android|vnd\.android|Intent)\.[A-Za-z0-9_.-]+$') { return $true }
    if ($v -match '^(com\.(tencent|qqgame|amap|example|huawei|android)|com\.google\.(Chrome|Keystone)|com\.apple|org\.apache)\.[A-Za-z0-9_.-]+$') { return $true }
    if ($v -match '^(activity|business|cooperation|plugin|system|recents|record|state|tr|ui)\.[A-Za-z0-9_.-]+$') { return $true }
    if ($v -match '^(H|Stub|PowerManagerService|mVisiblity|mVisibility)\.(handleMessage|onTransact|WakeLocks|getValue)$') { return $true }

    # Java/system/config/ZooKeeper property names.
    if ($v -match '^(java|javax|sun|kotlin|scala|zookeeper|autopurge|os|user|host)\.[A-Za-z0-9_.-]+$') { return $true }
    if ($v -match '^(n)\.[A-Za-z_][A-Za-z0-9_]*$') { return $true }

    # Hadoop/HDFS/Spark/OpenStack logger/config namespaces.
    if ($v -match '^(dfs|NameSystem|DefaultSpeculator|maps|mapred|mapreduce|yarn|hadoop|spark|storage|executor|broadcast|output|python|rdd|netty|akka|slf4j|Configuration|util|nova|compute|http\.requests)\.[A-Za-z0-9_.-]+$') { return $true }
    if ($v -match '^SecurityLogger\.org\.apache\.[A-Za-z0-9_.-]+$') { return $true }
    if ($v -match '^org\.(mortbay|apache)\.[A-Za-z0-9_.-]+$') { return $true }

    # BGL/HPC local event-category and source/artifact namespaces.
    if ($v -match '^(SPaSM|XL|mpi|partad|raptor|fdmn|clusterfilesystem|change|unix|net\.niff|home)\.[A-Za-z0-9_.-]+$') { return $true }

    # macOS diagnostic/component symbols.
    if ($v -match '^(DiskStore|EC|ImportBailout|KSOutOfProcessFetcher|Keystone|dispatcher|subject)\.[A-Za-z0-9_.-]+$') { return $true }

    return $false
}

function Test-PreserveNonSensitiveDottedArtifactName {
    param([string]$Value, [string]$Text, [int]$Index = -1, [int]$Length = 0)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    if ($v -notmatch '\.') { return $false }

    # Do not preserve obvious identity/URL/path forms here.
    if ($v -match '@|://|\\|/') { return $false }

    # Local diagnostic/source/package artifact extensions. This intentionally runs
    # before the leading-digit guard so names like 8x4x4.map and 1.jhist survive.
    if ($v -match '(?i)\.(properties|conf|cfg|ini|yaml|yml|toml|xml|json|log|txt|pid|lock|policy|rules|template|templates|jar|jhist|map|mapfile|rts|trace|out|cpp|cc|cxx|h|hpp|pcap|pcapng|plist|bundle|framework|dylib|qlgenerator|db|sqlite|bin|sqm)$') {
        return $true
    }

    # macOS .app can also be a public suffix. Preserve only bundle-looking app names
    # or values in app-bundle context.
    if ($v -match '(?i)^[A-Za-z0-9 _-]+\.app$') {
        if (($Value -cmatch '^[A-Z]') -or ($Text -match '(?i)(/Applications/|/System/Library/|CoreServices|PlugIns|\.app/Contents|LaunchServices)')) { return $true }
    }

    # Linux kernel/initrd image names.
    if ($v -match '(?i)^(vmlinuz|initrd)-\d+(?:[.\w-]+)+$') { return $true }

    # Thunderbird/BGL/HPC timestamp-ish local identifiers like 200511091901.jA.
    if ($v -match '^\d{10,}\.[A-Za-z]{1,3}$') { return $true }

    # If it begins with a digit and is not a known local artifact/timestamp above,
    # keep the conservative behavior.
    if ($v -match '^\d') { return $false }

    # ACPI / PCI route symbols.
    if ($v -match '^[A-Z0-9_]+(?:\.[A-Z0-9_]+){1,8}$') {
        if ($Text -match '(?i)(ACPI|PCI Interrupt|_PRT|BOOT_IMAGE|kernel command line|Thunderbird|BGL|HPC)') { return $true }
    }

    # Explicit package/config/logger namespace families from broad false-positive testing.
    if (Test-UlsLikelyCodeOrConfigNamespace -Value $v -Text $Text) { return $true }

    # Class/method/logger shapes. Avoid obvious public network domains.
    $parts = @($v -split '\.')
    if ($parts.Count -ge 2 -and -not (Test-UlsCommonPublicNetworkDomain -Value $v)) {
        $last = [string]$parts[-1]

        # CamelCase or Java-style method/class symbol in any segment.
        if ($v -cmatch '[a-z][A-Z]' -or $last -cmatch '^[A-Z][A-Za-z0-9_]*$') { return $true }

        # Common short logger/method words.
        if ($last -match '^(?i)(init|start|stop|run|load|save|open|close|read|write|parse|build|handle|process|worker|factory|service|manager|env|activity|isEmpty|baseline|new|rel|old|panic|full|down|up|hw|ticketstore|arpc|OU|Normal|SleepTimer|Error)$') { return $true }
    }

    return $false
}

function Test-PreserveLikelyBenignUniversalLabelValue {
    param(
        [string]$Value,
        [string]$Detector,
        [string]$Prefix,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }
    if ($Detector -ne 'UniversalLabel') { return $false }

    $v = $Value.Trim().Trim('"', "'", ',', ';', ')', ']', '}')

    if ($Prefix -eq 'DNS') {
        if ($v -match '^(?i)(Auth|IPC|Starting|Connection|routing|type|nginx|no|\[?ContainerId:?)$') { return $true }
        if ($v -match '^/dev/[A-Za-z0-9._/-]+$') { return $true }
        if ($v -match '^<KSOmahaServer:0x[0-9a-fA-F]+$') { return $true }
        if (Test-PreserveNonSensitiveDottedArtifactName -Value $v -Text $Text -Index $Index -Length $Length) { return $true }
    }

    if ($Prefix -eq 'PRINCIPAL') {
        # Preserve only the obvious Android zero singleton. Keep real Linux/OpenSSH
        # usernames like root, test, git, mysql tokenized.
        if ($v -eq '0') { return $true }
    }

    if ($Prefix -eq 'X500') {
        if ($v -match '^\d{1,5}$') { return $true }
        if ($v -match '^(NS[A-Za-z0-9]+ErrorDomain|kCFErrorDomain[A-Za-z0-9]+|[A-Z][A-Za-z0-9]+ErrorDomain|com\.apple\.[A-Za-z0-9_.-]+|type)$') { return $true }
    }

    return $false
}

function Test-PreserveLikelyBenignSecretValue {
    param([string]$Value, [string]$Text, [int]$Index = -1, [int]$Length = 0)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = $Value.Trim().Trim('"', "'", ',', ';', ')', ']', '}')

    # Java/Android exception class names and Apple XPC activity diagnostics are not secrets.
    if ($v -match '^(android|java|javax|org|com)\.[A-Za-z0-9_.]+Exception$') { return $true }
    if ($v -match '^com\.apple\.xpc\.activity/\d+$') { return $true }

    return $false
}

function Test-PreserveLikelyBenignBase64FalsePositive {
    param([string]$Value, [string]$Text, [int]$Index = -1, [int]$Length = 0)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = $Value.Trim().Trim('"', "'", ',', ';', ')', ']', '}')

    # macOS framework/class names can be long mixed-case alphabetic strings and
    # accidentally trip base64-ish shape detectors.
    if ($v -match '^[A-Za-z]{24,120}$' -and $v -cmatch '[a-z][A-Z]' -and $v -match '(Action|Transport|Controller|Constraint|Constraints|Layout|Bluetooth|Visualize|Server|Manager|Domain|Display|Power|Notification|Controller|Service)') { return $true }

    return $false
}

function __ULS_Legacy_Test_PreserveDetectedValue_7107 {
    param(
        [string]$Value,
        [string]$Detector,
        [string]$Prefix,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if (Test-ScrubAllowlist -Value $Value) { return $true }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = $Value.Trim()
    if (Is-AlreadyToken -Value $v) { return $true }

    # Additional broad false-positive reducers.
    if (Test-PreserveLikelyBenignUniversalLabelValue -Value $v -Detector $Detector -Prefix $Prefix -Text $Text -Index $Index -Length $Length) { return $true }
    if ($Prefix -eq 'SECRET' -and (Test-PreserveLikelyBenignSecretValue -Value $v -Text $Text -Index $Index -Length $Length)) { return $true }
    if ($Prefix -eq 'BLOB' -and (Test-PreserveLikelyBenignBase64FalsePositive -Value $v -Text $Text -Index $Index -Length $Length)) { return $true }

    # Existing preservation behavior retained.
    if (Test-PreserveDottedDecimal -Value $v) { return $true }
    if (($Prefix -eq 'IP' -or $Prefix -eq 'IP6') -and (Test-PreserveIpAddress -Value $v)) { return $true }
    if ($Prefix -eq 'GUID' -and (Test-PreserveGuid -Value $v)) { return $true }
    if ($Detector -eq 'DOMAIN\user' -or $Prefix -eq 'PRINCIPAL') {
        if (Test-WindowsPathLikeDomainUser -Value $v -Text $Text -Index $Index -Length $Length) { return $true }
    }
    if ($Prefix -eq 'DNS') {
        if (Test-AllowedDomain -Value $v) { return $true }
        if (Test-WindowsDiagnosticDottedName -Value $v) { return $true }
        if (Test-PreserveNonSensitiveDottedArtifactName -Value $v -Text $Text -Index $Index -Length $Length) { return $true }
        if ($script:ScrubPolicy -eq 'Readable' -and (Test-KnownFileOrDiagnosticName -Value $v)) { return $true }
    }
    if ($Prefix -eq 'BLOB' -and -not (Test-LooksLikeBase64Blob -Value $v)) { return $true }
    if (($Prefix -eq 'GUID' -or $Prefix -eq 'CERT') -and (Test-DiagnosticContext -Text $Text -Index $Index -Length $Length)) { return $true }

    return $false
}

function Get-ValueShapePrefix {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim().Trim('"', "'", ',', ';', ')', ']', '}')

    if ($v -match '^S-1-\d+-')                                                     { return 'SID' }
    if ($v -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$')  { return 'GUID' }
    if ($v -match '^[0-9a-fA-F]{32,}$')                                            { return 'CERT' }
    if ($v -match '^[^@\s]+@[^@\s]+\.[^@\s]+$')                                    { return 'UNMAPPED_UPN' }
    if ($v -match '^\d{1,3}(\.\d{1,3}){3}$')                                       { return 'IP' }
    if ($v -match '^[A-Za-z0-9_.-]+\\[A-Za-z0-9_.\-$]+$')                          { return 'PRINCIPAL' }
    if ($v -match '^(CN|OU|DC|O|L|ST|C)=')                                         { return 'X500' }

    if ($v -match '^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$') {
        if (Test-PreserveNonSensitiveDottedArtifactName -Value $v) { return $null }
        return 'DNS'
    }

    return $null
}

# END ULS v4.13 hotfix: broad FP preservation round 2

# BEGIN ULS v4.13 broad false-positive preserve round 3
# Current-version hardening only: no version/banner/schema bump.
# This pass suppresses low-signal false positives found after the Java/ZooKeeper
# and broad dotted-artifact preservation passes, while keeping real network/identity
# identifiers tokenized.

if (-not (Get-Variable -Name __ULS_TestPreserveDetectedValue_BeforeBroadFpRound3 -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_TestPreserveDetectedValue_BeforeBroadFpRound3 = ${function:__ULS_Legacy_Test_PreserveDetectedValue_7107}
}
if (-not (Get-Variable -Name __ULS_FindUniversalLabeledIdentifiers_BeforeBroadFpRound3 -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_FindUniversalLabeledIdentifiers_BeforeBroadFpRound3 = ${function:__ULS_Legacy_Find_UniversalLabeledIdentifiers_1040}
}
if (-not (Get-Variable -Name __ULS_FindSecretIdentifiers_BeforeBroadFpRound3 -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_FindSecretIdentifiers_BeforeBroadFpRound3 = ${function:__ULS_Legacy_Find_SecretIdentifiers_1204}
}

function Test-UlsRound3LowSignalUniversalLabel {
    param(
        [string]$Value,
        [string]$Rule
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = ([string]$Value).Trim()
    $r = ([string]$Rule).Trim()

    # Numeric/word fragments commonly captured by broad "label" rules in prose.
    if ($v -match '^(?:0|80|no|Starting|IPC|Auth|Connection|routing|type|nginx)$') { return $true }
    if ($v -match '^\[?ContainerId:?$') { return $true }

    # Local Unix/Linux device names are useful diagnostics, not hosts.
    if ($v -match '(?i)^/dev/[A-Za-z0-9_.-]+$') { return $true }

    # Apple/macOS diagnostic error domains and service names can look tenant-like.
    if ($v -match '(?i)^(ABAddressBookErrorDomain|kCFErrorDomainCFNetwork|NSURLErrorDomain|NSOSStatusErrorDomain|CoreDAVHTTPStatusErrorDomain)$') { return $true }
    if ($v -match '(?i)^com\.apple\.(?:security\.sos\.error|xpc\.activity)(?:/\d+)?$') { return $true }

    # Objective-C object/debug pointer forms are local diagnostic artifacts.
    if ($v -match '(?i)^<?[A-Za-z][A-Za-z0-9_.$-]*:0x[0-9a-f]+$') { return $true }

    # android/java exception/class symbols may be captured by broad principal/secret-ish rules.
    if ($v -match '(?i)^(?:android|java|javax|org|com)\.[A-Za-z0-9_.$]+(?:Exception|Error|RuntimeException)$') { return $true }

    # ULS patch 9 (high-confidence label capture): a value after a label is only an identity if it
    # LOOKS like one. Suppress common status/enum words, bare numbers, hex status codes, dotted
    # version numbers, single chars, and capture artifacts (a match that ran across a newline). A real
    # word-like identity (e.g. an account literally named "Test") should be caught by a BYOP seed term,
    # not by tokenizing every dictionary word that follows a label. Shape-y values (@, \, S-1-, dotted
    # host, etc.) and ordinary usernames (jdoe, glides) are unaffected. Privileged names (administrator,
    # admin, guest, root) are deliberately NOT in this list. Strict policy already tokenizes everything.
    $vp = $v.TrimEnd('.', ',', ';', ':', ')', ']', '}', '!', '?')
    if ($vp -match '(?i)^(yes|no|y|n|true|false|none|null|n/?a|nil|enabled|disabled|on|off|success|succeeded|successful|failure|failed|error|errors|warning|warnings|info|information|critical|verbose|started|stopped|stopping|starting|running|complete|completed|pending|active|inactive|present|absent|valid|invalid|allow|allowed|deny|denied|block|blocked|security|application|system|setup|service|services|target|source|test|tests|unknown|default|public|private|local|global|normal|high|low|medium|read|write|create|update|delete|open|close|ok|done)$') { return $true }
    if ($vp -match '^[+\-]?\d+(?:\.\d+)*$') { return $true }     # bare number, RID fragment, or dotted version
    if ($vp -match '^0x[0-9A-Fa-f]+$') { return $true }          # hex status / error code
    if ($v -match '[\r\n]') { return $true }                     # capture crossed a newline -> artifact
    if ($vp.Length -le 2) { return $true }                       # too short to be a meaningful identifier

    return $false
}

function Test-UlsRound3LowSignalSecret {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = ([string]$Value).Trim()

    # Java/Android exception class names and Apple diagnostic service identifiers are not secrets.
    if ($v -match '(?i)^(?:android|java|javax|org|com)\.[A-Za-z0-9_.$]+(?:Exception|Error|RuntimeException)$') { return $true }
    if ($v -match '(?i)^com\.apple\.xpc\.activity/\d+$') { return $true }

    return $false
}

function Test-UlsRound3PreserveDetectedValue {
    param(
        [string]$Value,
        [string]$Detector,
        [string]$Prefix,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = ([string]$Value).Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    $ctx = if ($null -ne $Text) { [string]$Text } else { '' }

    if ($Prefix -eq 'DNS') {
        # Local package/archive/app artifacts that are not DNS names.
        if ($v -match '(?i)\.(apk|ipa|app|framework|bundle|dylib|kext|sqm)$') { return $true }

        # Public documentation link in Hadoop sample, not an operational destination.
        if ($v -ieq 'wiki.apache.org' -and $ctx -match '(?i)NoRouteToHost|apache\.org/hadoop|For more details see') { return $true }
    }

    if ($Prefix -eq 'IP') {
        # Non-routable wildcard/bind address: useful to keep readable.
        if ($v -eq '0.0.0.0') { return $true }

        # Windows package/file version strings can look exactly like IPv4 addresses.
        $versionEsc = [regex]::Escape($v)
        if ($ctx -match "(?i)(Package_for_KB|ApplicableState|CurrentState|wcp\.dll version|~~$versionEsc\b)") { return $true }
    }

    if ($Prefix -eq 'IP6') {
        # PCI/ACPI bus/device identifiers and abbreviated status/debug fragments are not IPv6 addresses.
        if ($ctx -match '(?i)\b(PCI|ACPI|GSI|IRQ|Transparent bridge|interrupt|IStorePendingTransaction|coldpatching|onTouchEvent|chip status changed|New ido chip|mLp\()\b') { return $true }

        # Very short :: fragments are almost always parser artifacts in these free-form logs.
        if ($v -match '(?i)^(?:::?[0-9a-f]{1,3}|[0-9a-f]{1,3}::)$') { return $true }

        # ULS patch 9b: a colon-hex value with NO "::" and fewer than 8 groups is NOT a valid IPv6
        # address (a full address is 8 groups; anything shorter must use "::" to compress). These are
        # ESENT lgpos triplets (e.g. "01FF:0038:0268"), PCI/bus ids, and similar diagnostics. Preserving
        # them cannot hide a real IPv6 -- a real compressed ("::") or full (8-group) address is unaffected
        # and still tokenizes. Strict still tokenizes everything.
        if (($v -notmatch '::') -and ($v -match '^[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})+$') -and ((@($v -split ':')).Count -lt 8)) { return $true }
    }

    return $false
}

function __ULS_Legacy_Test_PreserveDetectedValue_7279 {
    param(
        [string]$Value,
        [string]$Detector,
        [string]$Prefix,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )

    try {
        if (& $script:__ULS_TestPreserveDetectedValue_BeforeBroadFpRound3 `
            -Value $Value `
            -Detector $Detector `
            -Prefix $Prefix `
            -Text $Text `
            -Index $Index `
            -Length $Length) {
            return $true
        }
    }
    catch { }

    if (Test-UlsRound3PreserveDetectedValue -Value $Value -Detector $Detector -Prefix $Prefix -Text $Text -Index $Index -Length $Length) {
        return $true
    }

    return $false
}

function Find-UniversalLabeledIdentifiers {
    param([Parameter(Mandatory)][string]$Text)

    $items = @(& $script:__ULS_FindUniversalLabeledIdentifiers_BeforeBroadFpRound3 -Text $Text)
    if ($script:ScrubPolicy -eq 'Strict') { return @($items) }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($id in $items) {
        $raw = ''
        $rule = ''
        try { $raw = [string]$id.Raw } catch { $raw = '' }
        try { $rule = [string]$id.Rule } catch { $rule = '' }

        if (Test-UlsRound3LowSignalUniversalLabel -Value $raw -Rule $rule) { continue }
        [void]$out.Add($id)
    }

    return @($out.ToArray())
}

function Find-SecretIdentifiers {
    param([Parameter(Mandatory)][string]$Text)

    $items = @(& $script:__ULS_FindSecretIdentifiers_BeforeBroadFpRound3 -Text $Text)
    if ($script:ScrubPolicy -eq 'Strict') { return @($items) }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($id in $items) {
        $raw = ''
        try { $raw = [string]$id.Raw } catch { $raw = '' }

        if (Test-UlsRound3LowSignalSecret -Value $raw) { continue }
        [void]$out.Add($id)
    }

    return @($out.ToArray())
}

# END ULS v4.13 broad false-positive preserve round 3

# BEGIN ULS v4.13 broad FP hardening round 4: C++ scope operator IPv6 fragments
# Current-version bugfix only: no version/banner/schema bump.
#
# Some macOS/corecaptured/kernel lines contain C++/IOKit scope operators such as:
#   CCIOReporterFormatter::addRegistryChildToChannelDictionary
#   AppleThunderboltNHIType2::waitForOk2Go2Sx
#   en0::IO80211Interface::postMessage
#
# A generic IPv6 shape regex can see tiny substrings like "::add", "e2::",
# "0::", "face::", or "::f" inside those symbols. In Balanced/Readable mode,
# preserve those when the match is embedded in an alphanumeric symbol context.
# Real standalone IPv6 addresses continue through the previous detector logic.
if (-not (Get-Variable -Name __ULS_TestPreserveDetectedValue_BeforeIpv6ScopeRound4 -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_TestPreserveDetectedValue_BeforeIpv6ScopeRound4 = ${function:__ULS_Legacy_Test_PreserveDetectedValue_7279}
}

function Test-UlsScopeOperatorIpv6FalsePositive {
    param(
        [string]$Value,
        [string]$Prefix,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )

    if ($Prefix -ne 'IP6') { return $false }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }

    $v = ([string]$Value).Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    if ([string]::IsNullOrWhiteSpace($v)) { return $false }

    # Only target the tiny compressed fragments that commonly arise from
    # language scope operators. Do not preserve full multi-hextet IPv6 values here.
    if ($v -notmatch '^(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{0,4})$') { return $false }
    if ($v -match '^(?i)(?:fe80|2607|2001|fd[0-9a-f]{2}|fc[0-9a-f]{2})') { return $false }

    if ([string]::IsNullOrEmpty($Text) -or $Index -lt 0) { return $false }

    $len = if ($Length -gt 0) { $Length } else { $Value.Length }
    if ($len -lt 2) { return $false }

    $before = ''
    $after = ''
    if ($Index -gt 0) {
        $before = $Text.Substring($Index - 1, 1)
    }
    if (($Index + $len) -lt $Text.Length) {
        $after = $Text.Substring($Index + $len, 1)
    }

    # If the detector match is embedded inside an identifier, it is much more
    # likely to be a C++/Obj-C/IOKit scope-operator fragment than a real IPv6.
    if ($before -match '[A-Za-z0-9_]' -or $after -match '[A-Za-z0-9_]') { return $true }

    # Also preserve when the nearby context visibly contains a scoped method/class.
    $start = [Math]::Max(0, $Index - 48)
    $take = [Math]::Min($Text.Length - $start, $len + 96)
    $ctx = $Text.Substring($start, $take)
    if ($ctx -match '[A-Za-z_][A-Za-z0-9_]{1,80}::[A-Za-z_][A-Za-z0-9_]{1,80}') { return $true }

    return $false
}

function Test-PreserveDetectedValue {
    param(
        [string]$Value,
        [string]$Detector,
        [string]$Prefix,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )

    if (Test-UlsScopeOperatorIpv6FalsePositive -Value $Value -Prefix $Prefix -Text $Text -Index $Index -Length $Length) {
        return $true
    }

    return (& $script:__ULS_TestPreserveDetectedValue_BeforeIpv6ScopeRound4 `
        -Value $Value `
        -Detector $Detector `
        -Prefix $Prefix `
        -Text $Text `
        -Index $Index `
        -Length $Length)
}

# END ULS v4.13 broad FP hardening round 4: C++ scope operator IPv6 fragments

# BEGIN ULS v4.14 performance and precision policy layer
if (-not (Get-Variable -Name __ULS_TestPreserveDetectedValue_BeforeV414 -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_TestPreserveDetectedValue_BeforeV414 = ${function:Test-PreserveDetectedValue}
}
if (-not (Get-Variable -Name __ULS_TestPreserveUniversalLabeledValue_BeforeV414 -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_TestPreserveUniversalLabeledValue_BeforeV414 = ${function:Test-PreserveUniversalLabeledValue}
}
if (-not (Get-Variable -Name __ULS_FindIdentifiers_BeforeV414 -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_FindIdentifiers_BeforeV414 = ${function:Find-Identifiers}
}

function Test-UlsHighConfidenceUniversalLabelValue {
    param($Rule, [string]$Label, [string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = ([string]$Value).Trim().Trim('"', "'", '.', ',', ';', ':', '}', ']', ')')
    if ([string]::IsNullOrWhiteSpace($v)) { return $false }
    if ($Rule -and ([string]$Rule.Name -match 'SecretLabels')) { return $true }
    if ($Label -match '(?i)(key|secret|token|password|passwd|pwd|auth|authorization|credential)') { return $true }
    if (Test-UlsWellKnownSid -Value $v) { return $false }
    if (Test-UlsWellKnownWindowsPrincipal -Value $v) { return $false }
    if ($v -match '^S-1-\d+(?:-\d+)+$') { return $true }
    if ($v -match '^[A-Za-z0-9_.-]+\\[A-Za-z0-9_.\-$]+$') { return $true }
    if ($v -match '\$$') { return $true }
    if ($v -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') { return $true }
    if ($v -match '^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$') { return -not (Test-PreserveIpAddress -Value $v) }
    if ($v -match ':' -and (Test-UlsValidIpv6Address -Value $v)) { return -not (Test-PreserveIpAddress -Value $v) }
    if ($v -match '^(CN|OU|DC|O|L|ST|C)=') { return $true }
    if ($v -match '^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}$') {
        if (Test-AllowedDomain -Value $v) { return $false }
        if (Test-WindowsDiagnosticDottedName -Value $v) { return $false }
        return $true
    }
    if ($Label -match '(?i)(host|server|machine|computer|device|workstation|client name|node|instance)') {
        return ($v -match '^[A-Za-z][A-Za-z0-9_-]{2,63}$' -and $v -notmatch '(?i)^(system|security|application|setup|default|unknown|localhost|workgroup)$')
    }
    if ($Label -match '(?i)(account|user|principal|subject|target|caller|login|identity|domain|tenant|realm)') {
        return ($v.Length -ge 3 -and $v -notmatch '(?i)^(system|security|application|setup|default|unknown|localhost|workgroup|nt authority|builtin|local service|network service|anonymous logon)$')
    }
    if ($Label -match '(?i)(url|uri|endpoint|callback|redirect)') {
        return ($v -match '^(?i)[a-z][a-z0-9+.-]*://')
    }
    if ($Label -match '(?i)(request|correlation|trace|session|transaction|object)') {
        return ($v -match '^[0-9a-fA-F]{16,}$' -or $v -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$')
    }
    return $false
}

function Test-UlsV414PreserveUniversalLabeledValue {
    param($Rule, [string]$Label, [string]$Value)

    try {
        if (& $script:__ULS_TestPreserveUniversalLabeledValue_BeforeV414 -Rule $Rule -Label $Label -Value $Value) { return $true }
    }
    catch { }

    if ($script:ScrubPolicy -eq 'Strict') { return $false }
    if (-not (Test-UlsHighConfidenceUniversalLabelValue -Rule $Rule -Label $Label -Value $Value)) { return $true }
    return $false
}

function Test-UlsV414PreserveDetectedValue {
    param(
        [string]$Value,
        [string]$Detector,
        [string]$Prefix,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )

    try {
        if (& $script:__ULS_TestPreserveDetectedValue_BeforeV414 `
            -Value $Value `
            -Detector $Detector `
            -Prefix $Prefix `
            -Text $Text `
            -Index $Index `
            -Length $Length) {
            return $true
        }
    }
    catch { }

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = ([string]$Value).Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    if ([string]::IsNullOrWhiteSpace($v)) { return $true }

    if ($Prefix -eq 'SID' -and (Test-UlsWellKnownSid -Value $v)) { return $true }
    if ($Prefix -eq 'PRINCIPAL' -and (Test-UlsWellKnownWindowsPrincipal -Value $v)) { return $true }
    if ($Prefix -eq 'IP6' -and -not (Test-UlsValidIpv6Address -Value $v)) { return $true }
    if ($Prefix -eq 'GUID') {
        if (Test-PreserveGuid -Value $v) { return $true }
        if (-not (Test-UlsGuidHasSensitiveContext -Text $Text -Index $Index -Length $Length)) { return $true }
    }
    if ($Prefix -eq 'CERT' -and -not (Test-UlsLongHexHasSensitiveContext -Text $Text -Index $Index -Length $Length)) { return $true }
    if ($Prefix -eq 'BLOB' -and -not (Test-LooksLikeBase64Blob -Value $v)) { return $true }
    return $false
}

function Find-UlsConnectionHostIdentifiers {
    param([Parameter(Mandatory)][string]$Text)

    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    if ($Text.IndexOf('://') -lt 0 -and $Text -notmatch '(?i)\b(server|host|address|bootstrap\.servers|broker\.list|data source)\s*=') { return @() }

    function _AddConnectionHostId {
        param([string]$Raw, [string]$Reason)
        if ([string]::IsNullOrWhiteSpace($Raw)) { return }
        $v = ([string]$Raw).Trim().Trim('[',']')
        if ([string]::IsNullOrWhiteSpace($v)) { return }
        if ((Is-AlreadyToken -Value $v) -or (Test-ScrubAllowlist -Value $v) -or (Test-AllowedDomain -Value $v)) { return }
        $prefix = Get-UlsConnectionHostPrefix -HostValue $v
        if (-not $prefix) { return }
        if ($prefix -eq 'IP6' -and -not (Test-UlsValidIpv6Address -Value $v)) { return }
        $norm = Normalize-TokenKey -Value $v
        if (-not $norm -or $seen.ContainsKey($norm)) { return }
        $seen[$norm] = $true
        [void]$out.Add([pscustomobject]@{ Raw = $v; Prefix = $prefix; Detector = 'ConnectionHost'; Reason = $Reason })
    }

    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:jdbc:[a-z0-9+.-]+:)?(?:postgres(?:ql)?|mysql|mariadb|sqlserver|oracle|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|kafka|zookeeper|ws|wss|http|https)://(?:[^@\s/;,?]+@)?(?<host>\[[^\]\s]+\]|[A-Za-z0-9][A-Za-z0-9_.-]{0,252}|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?')) {
        _AddConnectionHostId -Raw $m.Groups['host'].Value -Reason 'URL/connection string host'
    }
    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:server|host|address|bootstrap\.servers|broker\.list|data source)\s*=\s*(?<host>[A-Za-z0-9][A-Za-z0-9_.-]{1,252}|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?')) {
        _AddConnectionHostId -Raw $m.Groups['host'].Value -Reason 'Connection string host key'
    }

    return @($out.ToArray())
}

function Find-UlsWindowsEventCsvTextIdentifiersFast {
    param([Parameter(Mandatory)][string]$Text)

    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

    function _AddFastWindowsEventId {
        param([string]$Raw, [string]$Prefix, [string]$Detector, [string]$Reason)
        if ([string]::IsNullOrWhiteSpace($Raw) -or [string]::IsNullOrWhiteSpace($Prefix)) { return }
        $v = ([string]$Raw).Trim().Trim('"', "'", '.', ',', ';', ':', '}', ']', ')')
        if ([string]::IsNullOrWhiteSpace($v)) { return }
        if ((Is-AlreadyToken -Value $v) -or (Test-ScrubAllowlist -Value $v)) { return }
        if (Test-PreserveDetectedValue -Value $v -Detector $Detector -Prefix $Prefix -Text $Reason -Index 0 -Length $v.Length) { return }
        $norm = Normalize-TokenKey -Value $v
        if (-not $norm -or $seen.ContainsKey($norm)) { return }
        $seen[$norm] = $true
        [void]$out.Add([pscustomobject]@{ Raw = $v; Prefix = $Prefix; Detector = $Detector; Reason = $Reason })
    }

    foreach ($m in [regex]::Matches($Text, '(?m)^(?:"[^"]*",){6}"(?<machine>[^"]+)"')) {
        _AddFastWindowsEventId -Raw $m.Groups['machine'].Value -Prefix 'COMPUTER' -Detector 'WindowsEventCsvColumn' -Reason 'MachineName'
    }
    foreach ($m in [regex]::Matches($Text, '(?m)^(?:"[^"]*",){7}"(?<userid>S-1-\d+(?:-\d+)*)"')) {
        _AddFastWindowsEventId -Raw $m.Groups['userid'].Value -Prefix 'SID' -Detector 'WindowsEventCsvColumn' -Reason 'UserId'
    }
    foreach ($m in [regex]::Matches($Text, '""(?<key>EventData_[^""]+)""\s*:\s*""(?<value>[^""]*)""')) {
        $key = $m.Groups['key'].Value
        $value = $m.Groups['value'].Value
        $prefix = Get-UlsWindowsEventKeyPrefix -KeyName $key -Value $value
        if ($prefix) { _AddFastWindowsEventId -Raw $value -Prefix $prefix -Detector 'WindowsEventJsonKey' -Reason $key }
    }
    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:Security ID|TargetSid|SubjectUserSid)\s*:\s*(?<value>S-1-\d+(?:-\d+)+)')) {
        _AddFastWindowsEventId -Raw $m.Groups['value'].Value -Prefix 'SID' -Detector 'WindowsEventMessageLabel' -Reason 'Security ID'
    }
    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:Account Name|Target User Name|Subject User Name|TargetUserName|SubjectUserName)\s*:\s*(?<value>[^\s,;]+)')) {
        _AddFastWindowsEventId -Raw $m.Groups['value'].Value -Prefix 'PRINCIPAL' -Detector 'WindowsEventMessageLabel' -Reason 'Account/User Name'
    }
    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:Account Domain|Target Domain Name|Subject Domain Name|TargetDomainName|SubjectDomainName|Workstation Name|WorkstationName|Computer Name)\s*:\s*(?<value>[^\s,;]+)')) {
        _AddFastWindowsEventId -Raw $m.Groups['value'].Value -Prefix 'COMPUTER' -Detector 'WindowsEventMessageLabel' -Reason 'Domain/Workstation'
    }
    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:Source Network Address|Client Address|IP Address|IpAddress)\s*:\s*(?<value>[^\s,;]+)')) {
        $rawIp = $m.Groups['value'].Value
        $p = if ($rawIp -match ':' -and (Test-UlsValidIpv6Address -Value $rawIp)) { 'IP6' } else { 'IP' }
        _AddFastWindowsEventId -Raw $rawIp -Prefix $p -Detector 'WindowsEventMessageLabel' -Reason 'Network Address'
    }
    foreach ($m in [regex]::Matches($Text, 'S-1-\d+(?:-\d+)+')) {
        _AddFastWindowsEventId -Raw $m.Value -Prefix 'SID' -Detector 'WindowsEventSid' -Reason 'SID shape'
    }
    foreach ($m in [regex]::Matches($Text, '(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)')) {
        _AddFastWindowsEventId -Raw $m.Value -Prefix 'IP' -Detector 'WindowsEventIPv4' -Reason 'IPv4 shape'
    }
    foreach ($id in (Find-UlsConnectionHostIdentifiers -Text $Text)) {
        _AddFastWindowsEventId -Raw ([string]$id.Raw) -Prefix ([string]$id.Prefix) -Detector 'ConnectionHost' -Reason ([string]$id.Reason)
    }
    foreach ($id in (Find-SecretIdentifiers -Text $Text)) {
        _AddFastWindowsEventId -Raw ([string]$id.Raw) -Prefix ([string]$id.Prefix) -Detector 'Secret' -Reason 'Secret pattern'
    }

    return @($out.ToArray())
}

function Find-UlsV414Identifiers {
    param([Parameter(Mandatory)][string]$Text)

    if ($Text.Length -gt 1MB -and $Text -match 'EventDataJson' -and $Text -match 'ProviderName' -and $Text -match 'MachineName') {
        return @(Find-UlsWindowsEventCsvTextIdentifiersFast -Text $Text)
    }

    $base = @(& $script:__ULS_FindIdentifiers_BeforeV414 -Text $Text)
    $seen = @{}
    foreach ($id in $base) {
        try {
            $norm = Normalize-TokenKey -Value ([string]$id.Raw)
            if ($norm) { $seen[$norm] = $true }
        }
        catch { }
    }

    $extra = New-Object System.Collections.Generic.List[object]
    foreach ($id in (Find-UlsConnectionHostIdentifiers -Text $Text)) {
        $norm = Normalize-TokenKey -Value ([string]$id.Raw)
        if (-not $norm -or $seen.ContainsKey($norm)) { continue }
        $seen[$norm] = $true
        try {
            Add-DetectionTrace -Detector 'ConnectionHost' -Action 'Tokenized' -Value ([string]$id.Raw) -Token (Get-Token -Value ([string]$id.Raw) -Prefix ([string]$id.Prefix)) -Reason ([string]$id.Reason) -ColumnName '(connection)' -Context ''
        }
        catch { }
        [void]$extra.Add($id)
    }

    return @($base + @($extra.ToArray()))
}

${function:Test-PreserveUniversalLabeledValue} = ${function:Test-UlsV414PreserveUniversalLabeledValue}
${function:Test-PreserveDetectedValue} = ${function:Test-UlsV414PreserveDetectedValue}
${function:Find-Identifiers} = ${function:Find-UlsV414Identifiers}

# END ULS v4.14 performance and precision policy layer

Set-Alias -Name Invoke-UniversalLogScrubber -Value Invoke-UniversalScrubber
Set-Alias -Name Invoke-ULSScrubSelfTest -Value Invoke-ScrubSelfTest
Set-Alias -Name Test-ULSLogFormat -Value Test-LogFormat

Export-ModuleMember -Function `
    Invoke-UniversalScrubber, Test-LogFormat, New-ScrubTokenMap, New-ScrubTokenMapFromAD, `
    Import-ScrubTokenMap, Invoke-ScrubFile, Test-ScrubbedForLeaks, Get-ScrubProfile, `
    Invoke-UlsScrubTextBatch, Invoke-UlsDiscoverTextBatch, Invoke-UlsScrubCsvBatch, `
    ConvertFrom-EvtxToCsv, ConvertFrom-EtlToCsv, ConvertFrom-W3CToCsv, ConvertFrom-XlsxToCsv, ConvertFrom-DocxToText, ConvertFrom-PptxToText, `
    Import-ScrubProfileFile, Import-ScrubProfileExtensionFile, Test-ScrubProfile, New-ScrubProfileTemplate, New-ScrubProfileFromSample, `
    Invoke-ScrubSelfTest, Restore-ScrubbedFile, New-SyntheticLog `
    -Alias `
    Invoke-UniversalLogScrubber, Invoke-ULSScrubSelfTest, Test-ULSLogFormat
