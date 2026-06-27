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
    Import-Module .\UniversalLogScrubber.psm1
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
$script:Salt             = $null
$script:HmacLength       = 24
$script:TokenByNorm      = @{}     # normalized-value -> token (the loaded map)
$script:TokenMapCacheKey = $null   # "<path>|<lastwrite>" of the map in memory
$script:AdditionalBroadLabels = @()
$script:ScrubPolicy = 'Balanced'
$script:ExplainDetections = $false
$script:DetectionTrace = $null
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
    try { return (Get-TokenCountInText -Text ([System.IO.File]::ReadAllText($Path))) } catch { return 0 }
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
    return (($Bytes | ForEach-Object { $_.ToString("x2") }) -join "")
}

# Returns "PREFIX_<hex>" or $null if the value cannot be normalized.
function Invoke-HmacToken {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Prefix)
    $normalized = Normalize-TokenKey -Value $Value
    if (-not $normalized) { return $null }
    $salt = Get-SessionSalt
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($salt)
    $msgBytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
    try { $hash = $hmac.ComputeHash($msgBytes) } finally { $hmac.Dispose() }
    $len = [Math]::Min([Math]::Max($script:HmacLength, 4), 64)
    $hex = (ConvertTo-HexString -Bytes $hash).Substring(0, $len).ToUpperInvariant()
    return "$Prefix`_$hex"
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
    $known = Get-CanonicalKnownLabelByValue -Value $clean
    if ($known) { return $known }
    if (Test-PreserveDottedDecimal -Value $clean) { return $clean }   # leave OIDs / versions (not IPs) intact
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
    @{ Name = 'SID';       Prefix = 'SID';  Common = $true; Rx = 'S-1-\d+(?:-\d+)+' },
    @{ Name = 'GUID';      Prefix = 'GUID'; Common = $true; Rx = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' },
    @{ Name = 'Email/UPN'; Prefix = 'UNMAPPED_UPN'; Rx = '[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}' },
    @{ Name = 'IPv4';      Prefix = 'IP';   Rx = '(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)' },
    @{ Name = 'DOMAIN\user'; Prefix = 'PRINCIPAL'; Rx = '(?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]+\\[A-Za-z0-9_.\-$]+' },
    @{ Name = 'FQDN';      Prefix = 'DNS';  Rx = '(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}' },
    @{ Name = 'LongHex';   Prefix = 'CERT'; Rx = '(?<![A-Za-z0-9_])[0-9a-fA-F]{20,}(?![A-Za-z0-9_])' },
    # --- v3 additions (also applied at scrub time by Invoke-CommonDetectors) ---
    @{ Name = 'JWT';       Prefix = 'JWT';  Common = $true; Rx = 'eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}' },
    @{ Name = 'AWS_ARN';   Prefix = 'ARN';  Common = $true; Rx = 'arn:aws[A-Za-z0-9\-]*:[A-Za-z0-9\-]*:[A-Za-z0-9\-]*:[0-9]*:[A-Za-z0-9_/.:\-]+' },
    @{ Name = 'AWS_Key';   Prefix = 'AWSKEY'; Common = $true; Rx = '(?:AKIA|ASIA)[0-9A-Z]{16}' },
    @{ Name = 'CloudInstance'; Prefix = 'INSTANCE'; Common = $true; Rx = '\bi-[0-9a-f]{8,17}\b' },
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
        $v -match '(?i)\.(exe|dll|sys|log|dat|xml|csv|txt|dmp|tmp|etl|evtx|werinternalmetadata)$' -or
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
    $ctx = Get-DetectionContext -Text $Text -Index $Index -Length $Length -Radius 80
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

function Test-PreserveDetectedValue {
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

function Find-UniversalLabeledIdentifiers {
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
        if (-not (Is-AlreadyToken -Value $id.Raw)) { $leaks += ("{0}: {1}" -f $id.Rule, $id.Raw) }
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

function Invoke-WindowsPathUserHardening {
    param([Parameter(Mandatory)][string]$Text)
    return [regex]::Replace($Text, '(?i)((?:\\\\\?\\)?[A-Za-z]:\\Users\\)([^\\/"'',;:]+)', {
        param($m)
        $profile = $m.Groups[2].Value
        if ([string]::IsNullOrWhiteSpace($profile) -or $profile -match '^(Public|Default|Default User|All Users)$') { return $m.Value }
        return $m.Groups[1].Value + (Get-Token -Value $profile -Prefix "PRINCIPAL")
    })
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

function Find-SecretIdentifiers {
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
    $out = Invoke-WindowsPathUserHardening -Text $out

    # UNC path: tokenize the host in \\host\share (before any DOMAIN\user pass).
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

    # URL: tokenize optional userinfo and the host in scheme://[user@]host[:port]/...
    $out = [regex]::Replace($out, '(?i)\b(https?|ftp|ldap|ldaps|smb)://([^/\s"'',;]+)', {
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

    # The simple Common-flagged detectors (JWT, ARN, AWS key, instance id, MAC, IPv6, base64).
    foreach ($d in ($script:ShapeDetectors | Where-Object { $_.Common })) {
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
function Get-ValueShapePrefix {
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
function Find-Identifiers {
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
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = $script:ScrubPolicy
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
            $rows = @(Import-Csv $file)
            $total = $rows.Count
            $rn = 0
            foreach ($row in $rows) {
                $rn++
                if ($rn % 250 -eq 0) {
                    Write-Progress -Activity "Discovering identifiers in $name" -Status "Row $rn of $total ($($seen.Count) unique so far)" -PercentComplete ([int](($rn / [Math]::Max($total,1)) * 100))
                }
                $rowPrincipals = @{}   # localpart -> list of norms seen in THIS row
                foreach ($prop in $row.PSObject.Properties) {
                    $cell = [string]$prop.Value
                    if ([string]::IsNullOrWhiteSpace($cell)) { continue }
                    foreach ($id in (Find-Identifiers -Text $cell)) {
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
            Write-Progress -Activity "Discovering identifiers in $name" -Completed
        }
        else {
            $text = [System.IO.File]::ReadAllText($file)
            foreach ($id in (Find-Identifiers -Text $text)) {
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
        Write-Detail "$hits new identifier(s) from $name"
    }

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
        if ($count % 500 -eq 0) { Write-Progress -Activity "Reading Active Directory" -Status "$count objects ($($seen.Count) aliases)" -PercentComplete -1 }
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
    Write-Progress -Activity "Reading Active Directory" -Completed
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
        PassThroughRegex = '^(Id|EventID|Level|LevelDisplayName|TimeCreated|RecordId|LogName|ProviderName|Task|Opcode|Keywords|ProcessId|ThreadId)$'
        ColumnPrefix = @(
            @{ Pattern = 'account|user|subject|target|caller'; Prefix = 'PRINCIPAL'; DollarComputer = $true },
            @{ Pattern = 'domain'; Prefix = 'X500' },
            @{ Pattern = 'computer|host|workstation|machine'; Prefix = 'DNS' },
            @{ Pattern = 'address|ip'; Prefix = 'IP' },
            @{ Pattern = 'sid'; Prefix = 'SID' }
        )
        FreeTextRegex = 'Message|Account|User|Subject|Target|Caller|Domain|Computer|Host|Workstation|Address|Process|Path|Command'
        DenyByDefault = $true
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
            @{ Pattern='c-ip|s-ip|x-forwarded|ip'; Prefix='IP' },
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
            @{ Pattern='source|client|remote|ip|address'; Prefix='IP' },
            @{ Pattern='host|resource|instance|node|cluster'; Prefix='DNS' },
            @{ Pattern='request|correlation|trace|session|eventid'; Prefix='OBJECT' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $firewall = [pscustomobject]@{
        Name='Firewall'; Description='Firewall and network security logs with source/destination addresses, users, devices, and rules.'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(action|allow|deny|protocol|proto|port|src_port|dst_port|bytes|packets|rule|policy|severity|time|date|timestamp)$'
        ColumnPrefix=@(
            @{ Pattern='src|dst|source|destination|client|remote|ip|addr|address'; Prefix='IP' },
            @{ Pattern='user|account|principal|identity'; Prefix='PRINCIPAL' },
            @{ Pattern='host|device|gateway|server|clientname'; Prefix='DNS' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $vpn = [pscustomobject]@{
        Name='Vpn'; Description='VPN, remote access, and authentication gateway logs.'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(action|status|result|duration|bytes|port|protocol|time|date|timestamp|reason)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|account|principal|identity|login'; Prefix='PRINCIPAL' },
            @{ Pattern='client|remote|assigned|source|ip|address'; Prefix='IP' },
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
            @{ Pattern='client|source|remote|ip|address'; Prefix='IP' },
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
            @{ Pattern='ip|address|client|remote|source'; Prefix='IP' },
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
            @{ Pattern='ip|address|client'; Prefix='IP' },
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
            @{ Pattern='ip|address'; Prefix='IP' },
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
            @{ Pattern='source|ip|address'; Prefix='IP' },
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
            @{ Pattern='ip|address|client|source|remote'; Prefix='IP' },
            @{ Pattern='device|host|machine|computer'; Prefix='DNS' },
            @{ Pattern='session|correlation|request|token|jti'; Prefix='OBJECT' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }

    $all = [ordered]@{ Generic=$generic; CA=$ca; WindowsEventCsv=$win; Text=$text;
                       Tsv=$tsv; Psv=$psv; IIS=$iis; Syslog=$syslog; Apache=$apache; Cef=$cef; Logfmt=$logfmt;
                       WebAccess=$webAccess; CloudAudit=$cloudAudit; Firewall=$firewall; Vpn=$vpn; Proxy=$proxy;
                       AppJson=$appJson; Database=$database; Container=$container; Kubernetes=$kubernetes; IdentityProvider=$identityProvider }
    if ($Name) {
        foreach ($k in $all.Keys) { if ($k -ieq $Name) { return $all[$k] } }
        return $null
    }
    return @($all.Values)
}

# =====================================================================
# REGION: Local log format recommendations (no salt, no scrubbing)
# =====================================================================
function Test-GeneratedScrubArtifactName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -match '(?i)(_scrubbed|\.scrubbed\.|token_map|DO_NOT_UPLOAD|false_positive|detection_report|scrub_run_manifest)') { return $true }
    if ([System.IO.Path]::GetExtension($Name) -ieq '.zip') { return $true }
    return $false
}

function Resolve-LogRecommendationTargets {
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
    if ($ext -in @('.evtx','.xlsx','.zip')) {
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

function New-RecommendedScrubCommand {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Profile,
        [switch]$UseAutoProfile
    )
    $quotedPath = "'" + ($Path -replace "'", "''") + "'"
    $profilePart = if ($UseAutoProfile) { "-AutoProfile" } else { "-Profile $Profile" }
    return "Invoke-UniversalScrubber -Path $quotedPath $profilePart -DryRun -Salt `"preview-only`" -MapSource Discover -NonInteractive"
}

function New-LogFormatRecommendationObject {
    param(
        [Parameter(Mandatory)]$File,
        [Parameter(Mandatory)][string]$DetectedFormat,
        [Parameter(Mandatory)][string]$SuggestedProfile,
        [Parameter(Mandatory)][int]$Confidence,
        [string[]]$Reasons,
        [string[]]$Warnings
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
        RecommendedCommand = (New-RecommendedScrubCommand -Path $File.FullName -Profile $SuggestedProfile)
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
    if ($ext -eq '.xlsx') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'XLSX' -SuggestedProfile 'Generic' -Confidence 90 `
            -Reasons @('The .xlsx extension identifies an Excel workbook.') `
            -Warnings @('Workbook conversion happens locally before scrubbing.')
    }

    if (@($lines | Where-Object { ([string]$_) -match '^#Fields:' }).Count -gt 0) {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'W3C/IIS' -SuggestedProfile 'IIS' -Confidence 98 `
            -Reasons @('A #Fields: header was found.') -Warnings $warnings
    }
    if ($text -match '(?m)^\s*CEF:\d+\|') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'CEF' -SuggestedProfile 'Cef' -Confidence 96 `
            -Reasons @('A CEF prefix was found.') -Warnings $warnings
    }
    if ($text -match '(?m)^\s*LEEF:\d+(?:\.\d+)?\|') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'LEEF' -SuggestedProfile 'Cef' -Confidence 94 `
            -Reasons @('A LEEF prefix was found; the built-in CEF profile handles key=value SIEM extensions.') -Warnings $warnings
    }

    $jsonLinesOk = Test-JsonLines -Lines $lines
    $jsonLineExtensionOk = $jsonLinesOk
    if (-not $jsonLineExtensionOk -and $ext -in @('.jsonl','.ndjson') -and -not [string]::IsNullOrWhiteSpace($firstLine)) {
        $jsonLineExtensionOk = Test-JsonText -Text $firstLine
    }
    if ($jsonLinesOk -or $jsonLineExtensionOk) {
        $profile = 'Generic'
        if ($text -match '(?i)"(eventSource|eventName|awsRegion|userIdentity|tenantId|operationName|operation|principal|resource|sourceIPAddress)"') { $profile = 'CloudAudit' }
        elseif ($text -match '(?i)"(message|level|trace|span|api_key|client_secret|username|host)"') { $profile = 'AppJson' }
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'JSON Lines / NDJSON' -SuggestedProfile $profile -Confidence 92 `
            -Reasons @('Multiple sampled lines parse as standalone JSON objects.') -Warnings $warnings
    }
    if ((Test-JsonText -Text $text) -or ($ext -eq '.json' -and (Test-JsonText -Text $text))) {
        $profile = 'Generic'
        if ($text -match '(?i)"(eventSource|eventName|awsRegion|userIdentity|tenantId|operationName|operation|principal|resource|sourceIPAddress)"') { $profile = 'CloudAudit' }
        elseif ($text -match '(?i)"(message|level|trace|span|api_key|client_secret|username|host)"') { $profile = 'AppJson' }
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'JSON' -SuggestedProfile $profile -Confidence 90 `
            -Reasons @('The sampled content parses as JSON.') -Warnings $warnings
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
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'CSV' -SuggestedProfile 'Generic' -Confidence 82 `
            -Reasons @('The sample appears comma-delimited.') -Warnings $warnings
    }

    if ($text -match '(?m)^\S+\s+\S+\s+\S+\s+\[[^\]]+\]\s+"[A-Z]+ [^"]+ HTTP/[0-9.]+"\s+\d{3}\s+') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'Apache/Nginx access log' -SuggestedProfile 'Apache' -Confidence 86 `
            -Reasons @('The sample matches common/combined web access log shape.') -Warnings $warnings
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
    if ($col -match 'requestid|date|time|when|disposition|validity|count|number|status|flag|enabled|required|approval|candidate') { return $null }
    if ($col -match 'eku|oid|authcapable|published') { return $null }

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
    $known = Get-CanonicalKnownLabelByValue -Value $clean
    if ($known) { return $known }
    if (Test-PreserveDottedDecimal -Value $clean) { return $clean }   # OID / version (not an IP)
    if ($script:ScrubPolicy -ne 'Strict' -and (Test-WindowsDiagnosticDottedName -Value $clean)) { return $clean }
    if ($clean -match '^(true|false)$') { return $clean }        # boolean
    $date = [datetime]::MinValue
    if (($ColumnName -match 'date|time|when|notbefore|notafter') -and [datetime]::TryParse($clean, [ref]$date)) { return $clean }
    $prefix = Get-FallbackPrefix -ColumnName $ColumnName -Value $clean -Profile $Profile
    if ($prefix) {
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

# Per-field free-text hardening (the fuller set; safe because it runs on ONE cell,
# not across the whole CSV). Every match routes through Get-Token.
function Invoke-FreeTextHardening {
    param([string]$ColumnName, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $out = $Value
    $out = Invoke-SecretHardening -Text $out -ColumnName $ColumnName
    $out = Invoke-CustomRegexHardening -Text $out -ColumnName $ColumnName
    $out = Invoke-CommonDetectors -Text $out
    $out = Invoke-UniversalLabelHardening -Text $out -ColumnName $ColumnName
    $out = [regex]::Replace($out, 'S-1-\d+(?:-\d+)+', { param($m) Get-Token -Value $m.Value -Prefix "SID" })
    $out = [regex]::Replace($out, '(?im)(\bCertificateTemplate\s*:\s*)([A-Za-z0-9_.\-]+)', {
        param($m) if (Is-AlreadyToken -Value $m.Groups[2].Value) { return $m.Value } else { return $m.Groups[1].Value + (Get-Token -Value $m.Groups[2].Value -Prefix "TEMPLATE") } })
    $out = [regex]::Replace($out, '(?im)(\b(?:cdc|rmd|ccm)\s*:\s*)([A-Za-z0-9_.\-]+)', {
        param($m) if (Is-AlreadyToken -Value $m.Groups[2].Value) { return $m.Value } else { return $m.Groups[1].Value + (Get-Token -Value $m.Groups[2].Value -Prefix "DNS") } })
    $out = [regex]::Replace($out, '(?im)(\b(?:DNS Name|Principal Name|RFC822 Name|URL|URI|IP Address)\s*=\s*)([^,;\r\n]+)', {
        param($m)
        $label = $m.Groups[1].Value
        $rawVal = $m.Groups[2].Value.Trim()
        if (Is-AlreadyToken -Value $rawVal) { return $label + $rawVal }
        if ($label -match '(?i)IP Address') { return $label + (Get-Token -Value $rawVal -Prefix "IP") }
        if ($label -match '(?i)Principal Name|RFC822 Name') { return $label + (Get-Token -Value $rawVal -Prefix "UNMAPPED_UPN") }
        if ($label -match '(?i)URL|URI') { return $label + (Get-Token -Value $rawVal -Prefix "URI") }
        return $label + (Get-Token -Value $rawVal -Prefix "DNS") })
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
    $out = [regex]::Replace($out, '\b[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', {
        param($m) if ((Is-AlreadyToken -Value $m.Value) -or (Test-AllowedDomain -Value $m.Value)) { return $m.Value } else { return Get-Token -Value $m.Value -Prefix "UNMAPPED_UPN" } })
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
    $out = [regex]::Replace($out, '(?i)\b(?:CN|OU|DC|O|L|ST|C)=[^;,\r\n]+', { param($m) Get-Token -Value $m.Value -Prefix "X500" })
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

        # Profile pass-through columns (analytical / non-identifying) survive intact.
        if ($Profile.PassThroughRegex -and ($ColumnName -match $Profile.PassThroughRegex)) { return $text }

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
function Invoke-LeakHardeningText {
    param([Parameter(Mandatory)][string]$Text)
    $out = $Text
    $out = Invoke-SecretHardening -Text $out
    $out = Invoke-CustomRegexHardening -Text $out
    $out = Invoke-CommonDetectors -Text $out
    $out = Invoke-UniversalLabelHardening -Text $out
    $out = [regex]::Replace($out, '(?im)(\bCertificateTemplate\s*:\s*)([A-Za-z0-9_.\-]+)', {
        param($m) if (Is-AlreadyToken -Value $m.Groups[2].Value) { return $m.Value } else { return $m.Groups[1].Value + (Get-Token -Value $m.Groups[2].Value -Prefix "TEMPLATE") } })
    $out = [regex]::Replace($out, '(?im)(\b(?:cdc|rmd|ccm)\s*:\s*)([A-Za-z0-9_.\-]+)', {
        param($m) if (Is-AlreadyToken -Value $m.Groups[2].Value) { return $m.Value } else { return $m.Groups[1].Value + (Get-Token -Value $m.Groups[2].Value -Prefix "DNS") } })
    $out = [regex]::Replace($out, '(?im)(\b(?:DNS Name|Principal Name|RFC822 Name|URL|URI|IP Address)\s*=\s*)([A-Za-z0-9_.@:\-/]+)', {
        param($m)
        $label = $m.Groups[1].Value
        $value = $m.Groups[2].Value
        if (Is-AlreadyToken -Value $value) { return $m.Value }
        if ($label -match '(?i)IP Address') { return $label + (Get-Token -Value $value -Prefix "IP") }
        if ($label -match '(?i)Principal Name|RFC822 Name') { return $label + (Get-Token -Value $value -Prefix "UNMAPPED_UPN") }
        if ($value -match '@') { return $label + (Get-Token -Value $value -Prefix "UNMAPPED_UPN") }
        return $label + (Get-Token -Value $value -Prefix "DNS") })
    $out = [regex]::Replace($out, '\b[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', {
        param($m) if ((Is-AlreadyToken -Value $m.Value) -or (Test-AllowedDomain -Value $m.Value)) { return $m.Value } else { return Get-Token -Value $m.Value -Prefix "UNMAPPED_UPN" } })
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

function Test-ScrubbedForLeaks {
    param([Parameter(Mandatory)][string]$CsvPath, [string[]]$SensitiveTerms = @())
    Write-Work "Leak check: $([System.IO.Path]::GetFileName($CsvPath))"
    $text = [System.IO.File]::ReadAllText($CsvPath)
    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($term in $SensitiveTerms) {
        if ([string]::IsNullOrWhiteSpace($term)) { continue }
        $count = ([regex]::Matches($text, [regex]::Escape($term.Trim()), 'IgnoreCase')).Count
        if ($count -gt 0) { $findings.Add([pscustomobject]@{ Type = "SensitiveTerm '$($term.Trim())'"; Count = $count; Samples = "" }) }
    }
    $labeledLeaks = @(Find-UniversalLabeledLeaks -Text $text)
    if ($labeledLeaks.Count -gt 0) {
        $findings.Add([pscustomobject]@{ Type = "Universal labeled value"; Count = $labeledLeaks.Count; Samples = (($labeledLeaks | Select-Object -First 5) -join ", ") })
    }
    $customLeaks = @(Find-CustomRegexIdentifiers -Text $text | ForEach-Object { $_.Raw } | Select-Object -Unique)
    if ($customLeaks.Count -gt 0) {
        $findings.Add([pscustomobject]@{ Type = "Custom regex value"; Count = $customLeaks.Count; Samples = (($customLeaks | Select-Object -First 5) -join ", ") })
    }
    $secretLeaks = @(Find-SecretIdentifiers -Text $text | ForEach-Object { $_.Raw } | Select-Object -Unique)
    if ($secretLeaks.Count -gt 0) {
        $findings.Add([pscustomobject]@{ Type = "Secret-like value"; Count = $secretLeaks.Count; Samples = (($secretLeaks | Select-Object -First 5) -join ", ") })
    }

    $patterns = @(
        [pscustomobject]@{ Type = "Email/UPN";   Rx = '\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b' },
        [pscustomobject]@{ Type = "IPv4";        Rx = '(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)' },
        [pscustomobject]@{ Type = "IPv6";        Skip = '^\d{1,5}(:\d{1,5}){1,7}$'; Rx = '(?:[A-Fa-f0-9]{1,4}:){3,7}[A-Fa-f0-9]{1,4}|::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}' },
        [pscustomobject]@{ Type = "MAC";         Rx = '\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b' },
        [pscustomobject]@{ Type = "SID";         Rx = 'S-1-\d+(?:-\d+)+' },
        [pscustomobject]@{ Type = "DOMAIN\user"; Rx = '(?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]+\\[A-Za-z0-9_.\-$]+' },
        [pscustomobject]@{ Type = "Bare FQDN";   Rx = '\b(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b' }
    )
    foreach ($p in $patterns) {
        $leaks = @()
        foreach ($m in [regex]::Matches($text, $p.Rx)) {
            $v = $m.Value
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
                default { '' }
            }
            if (Test-PreserveDetectedValue -Value $v -Detector $p.Type -Prefix $prefixForLeak -Text $text -Index $m.Index -Length $m.Length) { continue }
            if ($p.Type -eq 'DOMAIN\user') {
                # A 'word\word' is NOT a credential leak when it is really a file path.
                $skipDU = $false
                #  (a) a backslash between two already-scrubbed tokens (PRINCIPAL_x\PRINCIPAL_y)
                foreach ($seg in ($v -split '\\')) { if (Is-AlreadyToken -Value $seg) { $skipDU = $true; break } }
                if (-not $skipDU) {
                    #  (b) bordered by a path separator -> it's inside a path
                    $before = if ($m.Index -gt 0) { [string]$text[$m.Index - 1] } else { '' }
                    $aft = $m.Index + $m.Length
                    $after = if ($aft -lt $text.Length) { [string]$text[$aft] } else { '' }
                    if ((@('\', '/', ':') -contains $before) -or (@('\', '/') -contains $after)) { $skipDU = $true }
                    #  (c) a drive root (C:\) or another path segment sits just before it
                    elseif ($m.Index -gt 0) {
                        $cs = [Math]::Max(0, $m.Index - 24)
                        $ctx = $text.Substring($cs, $m.Index - $cs)
                        if (($ctx -match '[A-Za-z]:\\') -or ($ctx -match '\\[^\\"'',;]*$')) { $skipDU = $true }
                    }
                    #  (d) well-known Windows path roots
                    if (-not $skipDU -and ($v -match '(?i)^(windows|winnt|system32|syswow64|sysnative|systemroot|drivers|users|public|default|programdata|appdata|microsoft|program files( \(x86\))?|inf|temp|tmp|config|fonts|assembly|servicing|winsxs|tasks|spool|wbem|registry|device|harddiskvolume\d*)\\')) { $skipDU = $true }
                }
                if ($skipDU) { continue }
            }
            $leaks += $v
        }
        $leaks = @($leaks | Select-Object -Unique)
        if ($leaks.Count -gt 0) {
            $findings.Add([pscustomobject]@{ Type = $p.Type; Count = $leaks.Count; Samples = (($leaks | Select-Object -First 5) -join ", ") })
        }
    }

    if ($findings.Count -eq 0) { Write-Ok "Leak check PASSED: no residual identifiers or sensitive terms."; return $true }
    Write-Fail "Leak check found POTENTIAL leaks -- review before uploading:"
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
#   Numbers / booleans / nulls and all keys pass through unchanged.
# =====================================================================
function Get-JsonNodeIdentity {
    param($Node)
    if ($null -eq $Node) { return $null }
    if ($Node -is [string] -or $Node -is [bool] -or $Node -is [int] -or $Node -is [long] -or $Node -is [double] -or $Node -is [decimal] -or $Node -is [datetime] -or $Node -is [guid]) { return $null }
    try { return [string][System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($Node) } catch { return $null }
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
        if ($Changes) { [void]$Changes.Add([pscustomobject]@{ Field = $KeyName; Original = '(json depth limit)'; Token = $marker }) }
        return $marker
    }
    if ($null -eq $Node) { return $null }
    if ($Node -is [string]) {
        $s = Scrub-Field -ColumnName $KeyName -Value $Node -Profile $Profile
        if ($Changes -and ($s -ne $Node)) { [void]$Changes.Add([pscustomobject]@{ Field = $KeyName; Original = $Node; Token = $s }) }
        return $s
    }
    if ($Node -is [bool] -or $Node -is [int] -or $Node -is [long] -or $Node -is [double] -or $Node -is [decimal] -or $Node -is [datetime] -or $Node -is [guid]) { return $Node }

    $id = Get-JsonNodeIdentity -Node $Node
    if ($id -and $Seen.ContainsKey($id)) {
        $marker = '[SCRUB_JSON_CYCLIC_REFERENCE]'
        if ($Changes) { [void]$Changes.Add([pscustomobject]@{ Field = $KeyName; Original = '(json cycle)'; Token = $marker }) }
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

        if (($Node -is [System.Collections.IEnumerable]) -and -not ($Node -is [string])) {
            $arr = New-Object System.Collections.Generic.List[object]
            foreach ($item in $Node) {
                [void]$arr.Add((Invoke-JsonNodeScrub -Node $item -Profile $Profile -KeyName $KeyName -Changes $Changes -Depth ($Depth + 1) -MaxDepth $MaxDepth -Seen $Seen))
            }
            return ,@($arr.ToArray())
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
    if (-not $Changes) { $Changes = New-Object System.Collections.Generic.List[object] }
    $jsonDepth = [Math]::Min([Math]::Max($MaxDepth, 2), 100)
    if ($IsNdjson) {
        # One JSON object per line (NDJSON / JSON Lines).
        $sb = New-Object System.Text.StringBuilder
        foreach ($line in ($Text -split '\r?\n')) {
            $trim = $line.Trim()
            if ($trim -eq '') { continue }
            try {
                $obj = $trim | ConvertFrom-Json -ErrorAction Stop
                $scrubbed = Invoke-JsonNodeScrub -Node $obj -Profile $Profile -KeyName '' -Changes $Changes -MaxDepth $MaxDepth -Seen @{}
                [void]$sb.AppendLine(($scrubbed | ConvertTo-Json -Depth $jsonDepth -Compress))
            }
            catch { [void]$sb.AppendLine((Invoke-LeakHardeningText -Text $line)) }
        }
        return $sb.ToString()
    }
    try {
        $obj = $Text | ConvertFrom-Json -ErrorAction Stop
        $scrubbed = Invoke-JsonNodeScrub -Node $obj -Profile $Profile -KeyName '' -Changes $Changes -MaxDepth $MaxDepth -Seen @{}
        return ($scrubbed | ConvertTo-Json -Depth $jsonDepth)
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
                Write-Progress -Activity "Indexing EVTX fields in $name" -Status "$total events indexed ($($eventDataColumns.Count) event-data columns)" -PercentComplete -1
            }
        }
        Write-Progress -Activity "Indexing EVTX fields in $name" -Completed
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
                    Write-Progress -Activity "Converting EVTX -> CSV: $name" -Status "$count events (RecordId $($e.RecordId), $tc)" -PercentComplete $pct
                }
            }
            catch { }
        }
    }
    finally {
        $writer.Close()
        Write-Progress -Activity "Converting EVTX -> CSV: $name" -Completed
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
    $script:RuntimeCustomRegexRules = if ($Profile.CustomRegexRules) { @($Profile.CustomRegexRules) } else { @() }
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
    try {
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            if ($null -eq $line) { break }
            if ($line.StartsWith('#')) {
                if ($line -match '^#Fields:\s*(.+)$') { $fields = @($matches[1].Trim() -split '\s+') }
                continue
            }
            if (-not $fields -or [string]::IsNullOrWhiteSpace($line)) { continue }
            $vals = @($line -split '\s+')
            $obj = [ordered]@{}
            for ($i = 0; $i -lt $fields.Count; $i++) { $obj[$fields[$i]] = if ($i -lt $vals.Count) { $vals[$i] } else { '' } }
            $rows.Add([pscustomobject]$obj)
        }
    }
    finally { $reader.Close() }
    $out = Resolve-OutPath -Path $OutCsv
    if ($rows.Count -gt 0) { $rows | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8 }
    else { [pscustomobject]@{ Note = 'No data rows / no #Fields header found.' } | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8 }
    Write-Ok "W3C/IIS converted: $out  ($($rows.Count) rows)"
    Write-Detail "Note: this CSV is UNSCRUBBED -- it gets scrubbed next."
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

# =====================================================================
# REGION: Streaming scrub (bounded memory, opt-in for very large files)
# =====================================================================
function Invoke-ScrubFileStreaming {
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)]$Profile,
        [string[]]$SensitiveTerms = @(),
        [Parameter(Mandatory)][string]$Format,
        [string]$Delimiter = ','
    )
    $name = [System.IO.Path]::GetFileName($InputPath)
    $outFull = Resolve-OutPath -Path $OutputPath
    Write-Work "Streaming scrub ($Format): $name"
    $leakCounts = @{}
    $leakSamples = @{}
    $rx = @(
        @{ T = 'Email/UPN';   R = '\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b' },
        @{ T = 'IPv4';        R = '(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)' },
        @{ T = 'SID';         R = 'S-1-\d+(?:-\d+)+' },
        @{ T = 'DOMAIN\user'; R = '(?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]+\\[A-Za-z0-9_.\-$]+' },
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
    $writer = [System.IO.StreamWriter]::new($outFull, $false, [System.Text.Encoding]::UTF8)
    $n = 0
    try {
        if ($Format -eq 'Csv' -or $Format -eq 'Tsv' -or $Format -eq 'Psv') {
            $headerWritten = $false
            Import-Csv -Path $InputPath -Delimiter $Delimiter | ForEach-Object {
                $row = $_; $n++
                if ($n % 1000 -eq 0) { Write-Progress -Activity "Streaming $name" -Status "$n rows" -PercentComplete -1 }
                $new = [ordered]@{}
                foreach ($prop in $row.PSObject.Properties) { $new[$prop.Name] = Scrub-Field -ColumnName $prop.Name -Value $prop.Value -Profile $Profile }
                $csv = @(([pscustomobject]$new) | ConvertTo-Csv -NoTypeInformation -Delimiter $Delimiter)
                if (-not $headerWritten) { $writer.WriteLine((Protect-SensitiveTerms -Text $csv[0] -SensitiveTerms $SensitiveTerms)); $headerWritten = $true }
                $dataLine = if ($csv.Count -ge 2) { ($csv[1..($csv.Count - 1)] -join "`r`n") } else { '' }
                $dataLine = Invoke-LeakHardeningText -Text $dataLine
                $dataLine = Protect-SensitiveTerms -Text $dataLine -SensitiveTerms $SensitiveTerms
                $writer.WriteLine($dataLine)
                & $updateLeaks $dataLine
            }
        }
        elseif ($Format -eq 'Json') {
            $reader = [System.IO.StreamReader]::new($InputPath)
            try {
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine(); if ($null -eq $line) { break }
                    $t = $line.Trim(); if ($t -eq '') { continue }
                    $n++; if ($n % 1000 -eq 0) { Write-Progress -Activity "Streaming $name" -Status "$n lines" -PercentComplete -1 }
                    $scr = Invoke-ScrubJsonText -Text $t -IsNdjson -Profile $Profile
                    $scr = Protect-SensitiveTerms -Text $scr -SensitiveTerms $SensitiveTerms
                    $writer.WriteLine($scr); & $updateLeaks $scr
                }
            }
            finally { $reader.Close() }
        }
        else {
            $reader = [System.IO.StreamReader]::new($InputPath)
            try {
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine(); if ($null -eq $line) { break }
                    $n++; if ($n % 1000 -eq 0) { Write-Progress -Activity "Streaming $name" -Status "$n lines" -PercentComplete -1 }
                    $h = if ($Format -eq 'Kv') { Invoke-KvValueOnlyText -Text $line } else { $line }
                    $h = Invoke-LeakHardeningText -Text $h
                    $h = Protect-SensitiveTerms -Text $h -SensitiveTerms $SensitiveTerms
                    $writer.WriteLine($h); & $updateLeaks $h
                }
            }
            finally { $reader.Close() }
        }
    }
    finally { $writer.Close(); Write-Progress -Activity "Streaming $name" -Completed }
    $clean = ($leakCounts.Keys.Count -eq 0)
    if ($clean) { Write-Ok "Leak check PASSED (streaming): $name" }
    else {
        Write-Fail "Leak check found residue (streaming) -- review:"
        foreach ($k in $leakCounts.Keys) { Write-Detail ("{0}: {1}  e.g. {2}" -f $k, $leakCounts[$k], (($leakSamples[$k]) -join ', ')) }
    }
    Write-Detail "Output: $([System.IO.Path]::GetFileName($outFull))"
    return [pscustomobject]@{ Input = $InputPath; Output = $outFull; Clean = $clean }
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
    Write-Banner "UNIVERSAL LOG SCRUBBER  v4.11 -- SELF-TEST" "Synthetic data only; no real logs touched."
    $prevSalt = $script:Salt; $prevLen = $script:HmacLength; $prevAllowed = $script:AllowedDomains; $prevPolicy = $script:ScrubPolicy
    $script:Salt = 'selftest-fixed-salt'; $script:HmacLength = 16; $script:AllowedDomains = @($script:AllowedDomainsDefault)
    $script:__stPass = 0; $script:__stFail = 0
    $assert = {
        param($cond, $msg)
        if ($cond) { Write-Ok $msg; $script:__stPass++ } else { Write-Fail $msg; $script:__stFail++ }
    }
    $reset = { $script:TokenByNorm = @{}; $script:TokenMapCacheKey = $null }
    $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("scrubtest_" + ([System.IO.Path]::GetRandomFileName().Replace('.', '')))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    try {
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
            [pscustomobject]@{ Name='apache'; Ext='log'; ExpectedFormat='Apache/Nginx access log'; ExpectedProfile='Apache'; Lines=@('10.0.0.1 - alice [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "curl/8.0"') },
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
                }
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
        }
        finally { $script:Salt = $recSalt }

        # ---- 1) One planted fixture per profile ----
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
            'guid=11112222-3333-4444-5555-666677778888',
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

        # ---- 3) Windows Event false-positive regression ----
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

        # ---- 4) BYOP schema v2 and universal detection ----
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
        $oldProfilePath = Join-Path $byop 'profile-v48.json'
        [System.IO.File]::WriteAllText($oldProfilePath, '{"Name":"Compat48","Format":"Csv","ColumnPrefix":[{"Pattern":"(?i)^User$","Prefix":"PRINCIPAL"}],"FreeTextRegex":".*"}', [System.Text.Encoding]::UTF8)
        $oldProfile = Import-ScrubProfileFile -Path $oldProfilePath
        & $assert ($oldProfile.Name -eq 'Compat48' -and $oldProfile.SchemaVersion -eq 1) "BYOP imports v4.8-style profiles"
        $badProfilePath = Join-Path $byop 'profile-bad.json'
        [System.IO.File]::WriteAllText($badProfilePath, '{"Name":"BadProfile","Format":"Csv","CustomRegexRules":[{"Name":"Broken","Regex":"(","Prefix":"OBJECT"}]}', [System.Text.Encoding]::UTF8)
        $badFailed = $false
        try { [void](Import-ScrubProfileFile -Path $badProfilePath) } catch { $badFailed = ($_.Exception.Message -match 'custom regex rule') }
        & $assert $badFailed "BYOP invalid regex reports rule context"

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
        $missingFailed = $false
        try { [void](New-ScrubProfileFromSample -Path (Join-Path $builder 'missing.log') -ProfileOut (Join-Path $builder 'missing.json') -NonInteractive) } catch { $missingFailed = ($_.Exception.Message -match 'Sample path not found') }
        & $assert $missingFailed "profile builder invalid path reports clearly"
        $overwriteFailed = $false
        try { [void](New-ScrubProfileFromSample -Path (Join-Path $builder 'sample_csv.csv') -ProfileOut (Join-Path $builder 'generated_csv.json') -ProfileReportOut (Join-Path $builder 'report_csv_DO_NOT_UPLOAD.md') -NonInteractive) } catch { $overwriteFailed = ($_.Exception.Message -match 'already exists') }
        & $assert $overwriteFailed "profile builder refuses overwrite without -Force"

        # ---- 6) Streaming vs normal equivalence ----
        Write-Rule "Streaming equivalence"
        $script:ScrubPolicy = 'Balanced'
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
        [switch]$Stream
    )
    if (-not (Test-Path $InputPath)) { throw "Input not found: $InputPath" }
    $script:AdditionalBroadLabels = $AdditionalBroadLabels
    $script:ScrubPolicy = $ScrubPolicy
    if ($ExplainDetections) { $script:ExplainDetections = $true }
    if ($FalsePositiveReport) { $script:FalsePositiveReport = $FalsePositiveReport }
    Initialize-ScrubProfileRuntime -Profile $Profile -AllowlistFiles $AllowlistFile
    [void](Get-SessionSalt)
    $script:__scrubFallback = 0; $script:__scrubFallbackCol = ''

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
        return Invoke-ScrubFileStreaming -InputPath $InputPath -OutputPath $outFull -Profile $Profile -SensitiveTerms $SensitiveTerms -Format $format -Delimiter $delim
    }

    # --- Dry run: report what WOULD change, write nothing. ---
    if ($DryRun) {
        $changes = New-Object System.Collections.Generic.List[object]
        if ($format -eq 'Csv' -or $format -eq 'Tsv' -or $format -eq 'Psv') {
            $rn = 0; $seenPairs = @{}
            Import-Csv -Path $InputPath -Delimiter $delim | ForEach-Object {
                $row = $_
                $rn++
                if ($rn % 250 -eq 0) { Write-Progress -Activity "Dry-run scan $name" -Status "Row $rn" -PercentComplete -1 }
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
            Write-Progress -Activity "Dry-run scan $name" -Completed
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
        return [pscustomobject]@{ Input = $InputPath; Output = $null; Clean = $true; DryRun = $true; ChangeCount = $changes.Count }
    }

    if ($format -eq 'Csv' -or $format -eq 'Tsv' -or $format -eq 'Psv') {
        Write-Work "Scrubbing ($format, profile '$($Profile.Name)'): $name"
        $raw = @(Import-Csv $InputPath -Delimiter $delim)
        $total = $raw.Count
        $rn = 0
        $scrubbed = foreach ($row in $raw) {
            $rn++
            if ($rn % 250 -eq 0) {
                Write-Progress -Activity "Scrubbing $name" -Status "Row $rn of $total" -PercentComplete ([int](($rn / [Math]::Max($total,1)) * 100))
            }
            $new = [ordered]@{}
            foreach ($prop in $row.PSObject.Properties) {
                $new[$prop.Name] = Scrub-Field -ColumnName $prop.Name -Value $prop.Value -Profile $Profile
            }
            [pscustomobject]$new
        }
        Write-Progress -Activity "Scrubbing $name" -Completed

        # Render to delimited text, run the whole-file safety net, redact seed terms.
        $csvText = (($scrubbed | ConvertTo-Csv -NoTypeInformation -Delimiter $delim) -join "`r`n") + "`r`n"
        $csvText = Invoke-LeakHardeningText -Text $csvText
        $csvText = Protect-SensitiveTerms -Text $csvText -SensitiveTerms $SensitiveTerms
        [System.IO.File]::WriteAllText($outFull, $csvText, [System.Text.Encoding]::UTF8)
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
        $text = [System.IO.File]::ReadAllText($InputPath)
        $text = Invoke-KvValueOnlyText -Text $text
        $text = Invoke-LeakHardeningText -Text $text
        $text = Protect-SensitiveTerms -Text $text -SensitiveTerms $SensitiveTerms
        [System.IO.File]::WriteAllText($outFull, $text, [System.Text.Encoding]::UTF8)
        Write-Detail "Output: $([System.IO.Path]::GetFileName($outFull))"
    }
    else {
        Write-Work "Scrubbing (text, profile '$($Profile.Name)'): $name"
        $text = [System.IO.File]::ReadAllText($InputPath)
        Write-Detail "Input size: $($text.Length) characters"
        $text = Invoke-LeakHardeningText -Text $text
        $text = Protect-SensitiveTerms -Text $text -SensitiveTerms $SensitiveTerms
        [System.IO.File]::WriteAllText($outFull, $text, [System.Text.Encoding]::UTF8)
        Write-Detail "Output: $([System.IO.Path]::GetFileName($outFull))"
    }

    # Verify, and auto re-harden once if anything slipped through.
    $clean = Test-ScrubbedForLeaks -CsvPath $outFull -SensitiveTerms $SensitiveTerms
    if (-not $clean) {
        Write-Warn "Residue detected -- re-hardening in place once..."
        $reText = [System.IO.File]::ReadAllText($outFull)
        $reText = Invoke-LeakHardeningText -Text $reText
        $reText = Protect-SensitiveTerms -Text $reText -SensitiveTerms $SensitiveTerms
        [System.IO.File]::WriteAllText($outFull, $reText, [System.Text.Encoding]::UTF8)
        $clean = Test-ScrubbedForLeaks -CsvPath $outFull -SensitiveTerms $SensitiveTerms
    }
    if ($script:__scrubFallback -gt 0) { Write-Warn "$($script:__scrubFallback) cell(s) couldn't be fully hardened and were replaced with a safe token (fail-closed, no leak). First column: '$($script:__scrubFallbackCol)'." }
    if ($FalsePositiveReport) { [void](Write-DetectionReport -Path $FalsePositiveReport) }
    return [pscustomobject]@{ Input = $InputPath; Output = $outFull; Clean = $clean }
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
        if (($r.Output -as [string]) -match '\.csv$') { try { $rows = @(Import-Csv $r.Output).Count } catch { $rows = -1 } }
        if ($r.Output) { $tokenCount = Get-TokenCountInFile -Path $r.Output }
        $entries += [pscustomobject]@{
            file           = $fileName
            inputPathHash  = if ($r.Input) { Get-PathFingerprint -Path $r.Input -Length 12 } else { "" }
            scrubbedPath   = if ($r.Output) { [string]$r.Output } else { "" }
            rows           = $rows
            bytes          = $bytes
            tokenCount     = $tokenCount
            leakCheckClean = [bool]$r.Clean
            error          = [string]$r.Error
        }
    }
    $manifest = [pscustomobject]@{
        tool            = "UniversalLogScrubber_v4_11.psm1"
        schemaVersion   = "4.11"
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

    $script:HmacLength = $HmacLength
    $script:ScrubPolicy = $ScrubPolicy
    $script:TokenMapMode = $TokenMapMode
    $script:EvtxProgressMode = $EvtxProgressMode
    $script:ExplainDetections = [bool]$ExplainDetections
    $script:FalsePositiveReport = $FalsePositiveReport
    $script:DetectionSummaryReport = $DetectionSummaryReport
    $script:DetectionTrace = New-Object System.Collections.Generic.List[object]
    $script:DetectionCounts = @{}

    Write-Banner "UNIVERSAL LOG SCRUBBER  v4.11" "Token-map first, then scrub. Nothing leaves until it's clean."
    if ($RecommendOnly) { Write-Info "RECOMMEND ONLY mode -- local sample analysis only." }
    if ($SafeFirstRun) { Write-Info "SAFE FIRST RUN mode -- local sample analysis only." }
    if ($AutoProfile) { Write-Info "AUTO PROFILE mode -- use one high-confidence recommendation when possible." }
    if ($DryRun) { Write-Info "DRY RUN mode -- nothing will be written." }
    if ($Stream) { Write-Info "STREAM mode -- bounded memory for very large files." }
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
        return New-ScrubProfileFromSample -Path $Path -ProfileOut $ProfileOut -ProfileReportOut $ProfileReportOut -ProfileWizard:$ProfileWizard -MaxSampleRows $MaxSampleRows -SampleFormat $SampleFormat -Force:$Force -NonInteractive:$NonInteractive
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
            Where-Object { $_.Name -notmatch '(?i)(_scrubbed|\.scrubbed\.|token_map|DO_NOT_UPLOAD|false_positive|detection_report)' })
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

    # --- Pre-convert special inputs (EVTX / XLSX / W3C-IIS) to CSV ---
    $evtxConverted = $false
    $iisConverted = $false
    $intermediateTargets = @()
    if (@($targets | Where-Object { $_.Extension -imatch '^\.(evtx|xlsx|log)$' }).Count -gt 0) {
        Write-Host ""
        Write-Step "Preparing special inputs (event logs / workbooks / IIS logs)"
        $conversionNameCounts = @{}
        foreach ($ct in $targets) {
            $cext = ([string]$ct.Extension).ToLowerInvariant()
            $suffix = if ($cext -eq '.evtx') { '.evtx.csv' } elseif ($cext -eq '.xlsx') { '.xlsx.csv' } elseif ($cext -eq '.log') { '.w3c.csv' } else { $null }
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
                elseif ($ext2 -eq '.xlsx') {
                    $key = ($t.BaseName + '.xlsx.csv').ToLowerInvariant()
                    $outCsv = Get-SafeDerivedPath -InputPath $t.FullName -OutDir $WorkDir -Suffix '.xlsx.csv' -UseHash:($conversionNameCounts[$key] -gt 1)
                    [void](ConvertFrom-XlsxToCsv -XlsxPath $t.FullName -OutCsv $outCsv)
                    if (Test-Path -LiteralPath $outCsv) { $converted = Get-Item -LiteralPath $outCsv }
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
            catch { Write-Fail "Conversion failed for $($t.Name): $($_.Exception.Message)" }
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
                [void](New-ScrubTokenMap -InputPath @($targets | ForEach-Object { $_.FullName }) -TokenMapCsv $TokenMapCsv -SeedTerms $SensitiveTerms -NoCorrelate:$NoCorrelate -TokenMapMode $TokenMapMode -ScrubPolicy $script:ScrubPolicy)
            }
            'AD' {
                $res = New-ScrubTokenMapFromAD -TokenMapCsv $TokenMapCsv -SeedTerms $SensitiveTerms
                if (-not $res) {
                    Write-Warn "Falling back to discovery (AD was unavailable)."
                    [void](New-ScrubTokenMap -InputPath @($targets | ForEach-Object { $_.FullName }) -TokenMapCsv $TokenMapCsv -SeedTerms $SensitiveTerms -NoCorrelate:$NoCorrelate -TokenMapMode $TokenMapMode -ScrubPolicy $script:ScrubPolicy)
                }
            }
            'ExistingMap' {
                if (-not (Test-Path $TokenMapCsv)) {
                    if ($NonInteractive) { throw "Token map not found: $TokenMapCsv" }
                    $TokenMapCsv = Read-DefaultString -Prompt "Path to the existing token map CSV"
                }
                [void](Import-ScrubTokenMap -TokenMapCsv $TokenMapCsv)
            }
        }
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
        if (-not $useStream -and -not $DryRun -and $t.Length -gt 50MB) {
            if ($NonInteractive) { $useStream = $true; Write-Info "Large file ($([int]($t.Length / 1MB)) MB) -- streaming." }
            else { $useStream = Read-YesNo -Prompt ("  $($t.Name) is $([int]($t.Length / 1MB)) MB. Stream it (lower memory)") -Default $true }
        }
        try {
            $results += Invoke-ScrubFile -InputPath $t.FullName -OutputPath $outPath -Profile $prof -SensitiveTerms $SensitiveTerms -AllowlistFile $AllowlistFile -ScrubPolicy $script:ScrubPolicy -ExplainDetections:$ExplainDetections -DryRun:$DryRun -Stream:$useStream
        }
        catch {
            Write-Fail "Failed on $($t.Name): $($_.Exception.Message)"
            Write-Detail "type: $($_.Exception.GetType().FullName)"
            foreach ($frame in (@($_.ScriptStackTrace -split "`r?`n") | Select-Object -First 5)) { if ($frame -and $frame.Trim()) { Write-Detail $frame.Trim() } }
            $results += [pscustomobject]@{ Input = $t.FullName; Output = $null; Clean = $false; Error = $_.Exception.Message }
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
    Write-Host ""
    return $results
}

Export-ModuleMember -Function `
    Invoke-UniversalScrubber, Test-LogFormat, New-ScrubTokenMap, New-ScrubTokenMapFromAD, `
    Import-ScrubTokenMap, Invoke-ScrubFile, Test-ScrubbedForLeaks, Get-ScrubProfile, `
    ConvertFrom-EvtxToCsv, ConvertFrom-W3CToCsv, ConvertFrom-XlsxToCsv, `
    Import-ScrubProfileFile, Test-ScrubProfile, New-ScrubProfileTemplate, New-ScrubProfileFromSample, `
    Invoke-ScrubSelfTest, Restore-ScrubbedFile, New-SyntheticLog
