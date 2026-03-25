#requires -version 5.1
<#
.SYNOPSIS
  Applies a desired Sysmon configuration in an idempotent, auditable way and reports drift/compliance.

.DESCRIPTION
  This script selects a target Sysmon XML configuration, validates it, compares it to the last known applied state and the current runtime configuration, and optionally remediates drift by installing/updating Sysmon.
  It supports three configuration source modes:
  - Direct file mode: use -ConfigPath to point to a specific XML file.
  - Directory mode: use -SourceDir to pick a suitable XML from a folder (optionally filtered with -ConfigNameHint).
  - Manifest mode: use -ManifestPath to load JSON settings (optional allowlist + min engine) and optionally pick a config file named by the manifest.

  Validation and decision logic:
  - Validates that the XML is well-formed and has a Sysmon root element.
  - Optionally enforces a SHA256 allowlist if provided by the manifest.
  - Optionally enforces a minimum Sysmon engine version if provided by the manifest or -MinEngine.
  - Detects drift using:
    - The desired config file SHA256 vs. the previously recorded desired SHA256 in the state file.
    - A hash of the current runtime config dump (Sysmon "-c" without a file) vs. the previously recorded runtime dump hash.

  Remediation behavior:
  - If -Mode Remediate is set and Sysmon is not installed, the script installs Sysmon using the selected XML.
  - If -Mode Remediate is set and drift is detected, the script updates Sysmon to use the selected XML.
  - If -Mode Audit is used, the script runs in audit mode and returns a non-OK status when drift/non-compliance is detected.

  Optional logging channel management:
  - If -EnsureChannel is set, the script checks whether the Sysmon Operational channel is enabled and whether its maximum size meets the requested value.
  - If -EnsureChannel is set together with -Mode Remediate, the script attempts to enable/resize the channel to become compliant.

  State and output:
  - Writes a state JSON that records what was applied/observed (host, time, sysmon engine details, desired config SHA256, source, runtime dump hash).
  - Emits a structured summary object to the pipeline (suitable for Export-Csv / ConvertTo-Json / Where-Object).
  - Writes a human-readable console summary at the end (can be disabled).

.PARAMETER ConfigPath
  Path to a Sysmon configuration XML file to apply/audit.

.PARAMETER SourceDir
  Directory containing one or more Sysmon configuration XML files.
  The script selects one file (optionally filtered by -ConfigNameHint, otherwise picks the "best" candidate based on naming/version hint and timestamps).

.PARAMETER ManifestPath
  Path to a manifest JSON file that can define:
  - Config.File: Preferred XML file name to select (typically relative to -SourceDir).
  - AllowedHashes: Array of allowed SHA256 hashes for the selected XML file.
  - MinEngine: Minimum Sysmon engine version required.

.PARAMETER SysmonExePath
  Optional explicit path to sysmon.exe/sysmon64.exe.
  If not provided, the script attempts to discover the Sysmon executable from the installed service configuration or known default locations.

.PARAMETER Mode
  Execution mode:
  - Audit: report drift/non-compliance without changing the system.
  - Remediate: perform changes to reach the desired state (install/update Sysmon config; optionally enable/resize channel when -EnsureChannel is used).

.PARAMETER EnsureChannel
  If set, validates the Sysmon Operational channel status (enabled + minimum size).
  Use together with -Mode Remediate to enforce the desired channel settings.

.PARAMETER ChannelSizeMiB
  Desired minimum maximum size of the Sysmon Operational channel in MiB.
  Only used when -EnsureChannel is set.

.PARAMETER StatePath
  Path to the state JSON file used to track last applied/observed configuration.
  If the state file is missing or invalid JSON, the script uses safe defaults and continues.

.PARAMETER ConfigPathFallback
  Optional fallback XML file path to use if selection via -ConfigPath/-SourceDir/-ManifestPath does not yield a config.

.PARAMETER MinEngine
  Optional minimum Sysmon engine version requirement (for example: "15.0").
  If not provided, the script may use MinEngine from the manifest.

.PARAMETER ConfigNameHint
  Optional regex hint used to filter XML files in -SourceDir (for example: "prod|server" or "v15").

.PARAMETER NoConsoleSummary
  If set, disables the human-readable console summary.
  The structured pipeline output is still produced.

.PARAMETER SanitizeConsoleOutput
  If set, the console summary masks local/UNC paths (helpful when pasting console output into tickets or GitHub issues).
  This does not change the structured pipeline output.

.PARAMETER NoColor
  If set, disables colored console output.

.INPUTS
  None. This script does not accept pipeline input.


.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER PassThru
  Emit structured v2 result object to pipeline.

.PARAMETER Strict
  Treat warnings as failures.

.PARAMETER Quiet
  Suppress console output.

.OUTPUTS
  System.Management.Automation.PSCustomObject.
  The script outputs exactly one structured summary object with fields such as:
  - Ok, DriftDetected, Remediate, EnsureChannel, IsAdmin
  - ConfigFile, DesiredSha256, PrevDesiredSha256
  - SysmonService, SysmonExe, EngineVersion, MinEngineRequired
  - CurrentDumpSha256, InstalledNow, StateWritten
  - Actions (string[]), Warnings (string[])

.EXAMPLE
  # Audit a specific config file (no changes)
  .\16-Sysmon-Config-Updater.ps1 -ConfigPath "PATH/TO/sysmon.xml"

.EXAMPLE
  # Remediate: apply the config if drift is detected (or install if missing)
  .\16-Sysmon-Config-Updater.ps1 -ConfigPath "PATH/TO/sysmon.xml" -Mode Remediate

.EXAMPLE
  # Select config from a directory using a name hint, audit-only
  .\16-Sysmon-Config-Updater.ps1 -SourceDir "PATH/TO/configs" -ConfigNameHint "prod"

.EXAMPLE
  # Use a manifest and a directory (manifest may specify Config.File, AllowedHashes, MinEngine)
  .\16-Sysmon-Config-Updater.ps1 -ManifestPath "PATH/TO/manifest.json" -SourceDir "PATH/TO/payload" -Mode Remediate

.EXAMPLE
  # Enforce Sysmon Operational channel settings during remediation
  .\16-Sysmon-Config-Updater.ps1 -ConfigPath "PATH/TO/sysmon.xml" -EnsureChannel -ChannelSizeMiB 256 -Mode Remediate

.EXAMPLE
  # Export the structured result (pipeline-safe)
  .\16-Sysmon-Config-Updater.ps1 -ConfigPath "PATH/TO/sysmon.xml" | Export-Csv -NoTypeInformation -Path "PATH/TO/result.csv"

.NOTES
  Behavior on missing/invalid JSON:
  - Manifest: if missing/invalid, the script continues with empty defaults (no allowlist enforcement, no MinEngine enforcement, no preferred file name).
  - State: if missing/invalid, the script continues with empty defaults (drift detection may rely on runtime dump hash and current desired hash).

  Idempotency and drift:
  - In audit mode (-Mode Audit), the script reports non-OK when it detects drift or required settings are not compliant.
  - In remediate mode, the script only applies changes when drift/non-compliance is detected.

  Security considerations:
  - When using AllowedHashes, ensure the allowlist is maintained securely.
  - Running with -Mode Remediate requires administrative privileges to install/update Sysmon and to change event log channel settings.
#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [string]$ConfigPath,
  [string]$SourceDir,
  [string]$ManifestPath,
  [string]$SysmonExePath,
  [switch]$EnsureChannel,
  [ValidateRange(1, 4096)]
  [int]$ChannelSizeMiB = 256,

  # Anonymized default (override in production)
  [string]$StatePath,

  [string]$ConfigPathFallback,
  [string]$MinEngine,
  [string]$ConfigNameHint,

  # Console output control (does NOT affect pipeline output)
  [switch]$NoConsoleSummary,

  # Sanitizes only console output (pipeline output remains raw/structured)
  [switch]$SanitizeConsoleOutput,

  # Console rendering preferences
  [switch]$NoColor

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Evidence.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest

# v2-init
$null = $Mode, $ConfigPath, $OutputFormat, $OutputPath, $PassThru, $Strict, $Quiet, $NoColor
$script:__V2Context = @{
  Mode = $Mode
  ConfigPath = $ConfigPath
  OutputFormat = $OutputFormat
  OutputPath = $OutputPath
  PassThru = [bool]$PassThru
  Strict = [bool]$Strict
  Quiet = [bool]$Quiet
  NoColor = [bool]$NoColor
}
$Remediate = ($Mode -eq 'Remediate')
if ($Quiet) {
  $InformationPreference = 'SilentlyContinue'
  $VerbosePreference = 'SilentlyContinue'
}
if ($NoColor) {
  $script:NoColor = $true
}
$ErrorActionPreference = 'Stop'

# C10: canonical findings list
$script:Findings = New-FindingsList

# -----------------------------
# Helper functions (EN comments for GitHub)
# -----------------------------


function Parse-Version([string]$s){
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  $m = [regex]::Match($s, '(\d+)\.(\d+)(?:\.(\d+))?')
  if (-not $m.Success) { return $null }
  return [pscustomobject]@{
    A   = [int]$m.Groups[1].Value
    B   = [int]$m.Groups[2].Value
    C   = if($m.Groups[3].Success){[int]$m.Groups[3].Value}else{0}
    Raw = $s
  }
}

function Cmp-Ver($x,$y){
  if (-not $x -and -not $y) { return 0 }
  if (-not $x) { return -1 }
  if (-not $y) { return 1 }
  foreach($k in 'A','B','C'){
    if ($x.$k -gt $y.$k){ return 1 }
    if ($x.$k -lt $y.$k){ return -1 }
  }
  return 0
}

function Resolve-SysmonExe {
  param([string]$Hint)

  foreach($svc in 'Sysmon64','Sysmon'){
    try {
      $s = Get-ItemProperty -Path ("HKLM:\SYSTEM\CurrentControlSet\Services\" + $svc) -ErrorAction Stop
      if ($s -and $s.ImagePath) {
        $img = [Environment]::ExpandEnvironmentVariables([string]$s.ImagePath)

        # Tokenize the ImagePath to robustly get the executable path.
        $nullRef = $null
        $tok = [System.Management.Automation.PSParser]::Tokenize($img, [ref]$nullRef) |
               Where-Object { $_.Type -in @('Command','CommandArgument') } |
               Select-Object -First 1

        if ($tok) {
          $exePath = $tok.Content.Trim('"')
          if (Test-Path -LiteralPath $exePath) { return $exePath }
        }

        # Fallback: best-effort extraction of "<drive>:\...\.exe".
        $m = [regex]::Match($img, '(?i)([a-z]:\\[^"]+?\.exe)')
        if ($m.Success) {
          $cand = $m.Groups[1].Value
          if (Test-Path -LiteralPath $cand) { return $cand }
        }
      }
    } catch { <# best-effort: Sysmon service image path probing #> }
  }

  if ($Hint -and (Test-Path -LiteralPath $Hint)) { return $Hint }

  foreach($c in @(
    "$env:SystemRoot\Sysmon64.exe",
    "$env:SystemRoot\Sysmon.exe",
    "$env:ProgramFiles\Sysmon\Sysmon64.exe",
    "$env:ProgramFiles\Sysmon\Sysmon.exe"
  )){
    if (Test-Path -LiteralPath $c) { return $c }
  }
  return $null
}

function Get-SysmonServiceName(){
  foreach($n in 'Sysmon64','Sysmon'){
    try { $null = Get-Service -Name $n -ErrorAction Stop; return $n } catch { <# best-effort: probing for Sysmon service name variant #> }
  }
  return $null
}

function Get-SysmonEngineVersion([string]$Exe){
  if (-not $Exe -or -not (Test-Path -LiteralPath $Exe)) { return $null }

  # Primary: file version metadata.
  try {
    $pv = (Get-Item -LiteralPath $Exe -ErrorAction Stop).VersionInfo.ProductVersion
    $v  = Parse-Version $pv
    if ($v) { return $v }
  } catch { <# best-effort: file version metadata may not be available #> }

  # Fallback: parse help text (sysmon -?).
  try {
    $tempOut = [IO.Path]::GetTempFileName()
    $tempErr = [IO.Path]::GetTempFileName()
    $p = Start-Process -FilePath $Exe -ArgumentList '-?' -PassThru -WindowStyle Hidden `
         -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr
    $p.WaitForExit() | Out-Null

    $txt = (Get-Content -Raw -LiteralPath $tempOut -ErrorAction SilentlyContinue) + "`n" +
           (Get-Content -Raw -LiteralPath $tempErr -ErrorAction SilentlyContinue)

    Remove-Item $tempOut,$tempErr -Force -ErrorAction SilentlyContinue

    $m = [regex]::Match($txt, '(?i)\bsysmon v(?<v>\d+\.\d+(?:\.\d+)?)\b')
    if ($m.Success) { return Parse-Version $m.Groups['v'].Value }
  } catch { <# best-effort: Sysmon help text version extraction fallback #> }

  return $null
}

function Load-JsonOrDefault {
  param(
    [string]$Path,
    [hashtable]$DefaultObject
  )
  if (-not $DefaultObject) { $DefaultObject = @{} }

  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $DefaultObject }

  try {
    $raw = Get-Content -Raw -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return $DefaultObject }
    $obj = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $obj) { return $DefaultObject }
    return $obj
  } catch {
    return $DefaultObject
  }
}

function Select-ConfigFile([string]$Path,[string]$Dir,[string]$NameHint,[object]$Manifest){
  if ($Path -and (Test-Path -LiteralPath $Path)) { return (Get-Item -LiteralPath $Path) }

  if ($Manifest -and $Manifest.Config -and $Manifest.Config.File) {
    $m = [string]$Manifest.Config.File
    if ($Dir) {
      $cand = Join-Path $Dir $m
      if (Test-Path -LiteralPath $cand) { return (Get-Item -LiteralPath $cand) }
    }
    if ($Path) {
      $cand2 = Join-Path (Split-Path -Parent $Path) $m
      if (Test-Path -LiteralPath $cand2) { return (Get-Item -LiteralPath $cand2) }
    }
  }

  if ($Dir -and (Test-Path -LiteralPath $Dir)) {
    $all = Get-ChildItem -LiteralPath $Dir -Filter '*.xml' -File -ErrorAction SilentlyContinue
    if ($NameHint) { $all = $all | Where-Object { $_.Name -match $NameHint } }
    if (-not $all -or $all.Count -eq 0) { return $null }

    $ranked = $all | ForEach-Object {
      $mm = [regex]::Match($_.Name,'v(\d+\.\d+(\.\d+)?)')
      [pscustomobject]@{
        File  = $_
        Score = if($mm.Success){ [double]($mm.Groups[1].Value -replace '\.','') } else { 0 }
        Time  = $_.LastWriteTimeUtc
      }
    }

    return ($ranked |
      Sort-Object -Property @{Expression='Score';Descending=$true}, @{Expression='Time';Descending=$true} |
      Select-Object -First 1).File
  }

  return $null
}

function Validate-ConfigXml([string]$file){
  try {
    [xml]$x = Get-Content -Raw -LiteralPath $file -Encoding UTF8 -ErrorAction Stop
    if (-not $x) { return $false,"empty xml" }
    $root = $x.DocumentElement
    if (-not $root) { return $false,"no root element" }
    if ($root.Name -notin @('Sysmon','sysmon')) { return $false,("unexpected root: " + $root.Name) }
    $sv = $root.GetAttribute('schemaversion')
    if ($sv) { return $true, ("schema=" + $sv) }
    return $true, "schema=n/a"
  } catch {
    return $false, $_.Exception.Message
  }
}

function Ensure-SysmonChannel([switch]$DoIt,[int]$MiB){
  $name = 'Microsoft-Windows-Sysmon/Operational'
  $ok=$true; $msgs=@()
  try {
    # S9 fix: use Invoke-Wevtutil wrapper with array-based args instead of direct wevtutil calls
    $glResult = Invoke-Wevtutil -Arguments @('gl', $name) -CaptureOutput
    $q = if ($glResult -and $glResult.Output) { $glResult.Output } else { '' }
    $enabled = ($q -match 'enabled:\s*true')
    if (-not $enabled) {
      if ($DoIt) { Invoke-Wevtutil -Arguments @('sl', $name, '/e:true') | Out-Null; $msgs += "enabled" } else { $ok=$false }
    }
    if ($MiB -gt 0) {
      $m = [regex]::Match($q,'maximum size:\s*(\d+)')
      $cur = if ($m.Success){ [int64]$m.Groups[1].Value } else { 0 }
      $want = [int64]$MiB * 1024 * 1024
      if ($cur -lt $want -and $DoIt) { Invoke-Wevtutil -Arguments @('sl', $name, "/ms:$want") | Out-Null; $msgs += ("size=" + $MiB + "MiB") }
      elseif ($cur -lt $want) { $ok=$false }
    }
  } catch { $ok=$false; $msgs += $_.Exception.Message }
  return $ok, ($msgs -join '; ')
}

function Write-State([string]$p,[hashtable]$obj){
  try {
    Ensure-Directory (Split-Path -Parent $p)
    ($obj | ConvertTo-Json -Depth 8) | Out-File -LiteralPath $p -Encoding UTF8 -Force
    return $true
  } catch { return $false }
}

function Get-SysmonCurrentConfigSha256 {
  param([string]$Exe)

  # Sysmon: "-c" without file dumps current configuration.
  if (-not $Exe -or -not (Test-Path -LiteralPath $Exe)) { return $null }

  try {
    $tempOut = [IO.Path]::GetTempFileName()
    $tempErr = [IO.Path]::GetTempFileName()

    $p = Start-Process -FilePath $Exe -ArgumentList '-c' -PassThru -WindowStyle Hidden `
         -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr
    $p.WaitForExit() | Out-Null

    $txt = (Get-Content -Raw -LiteralPath $tempOut -ErrorAction SilentlyContinue) + "`n" +
           (Get-Content -Raw -LiteralPath $tempErr -ErrorAction SilentlyContinue)

    Remove-Item $tempOut,$tempErr -Force -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($txt)) { return $null }

    $norm  = ($txt -replace "`r`n","`n").Trim()
    $bytes = [Text.Encoding]::UTF8.GetBytes($norm)
    $sha   = [Security.Cryptography.SHA256]::Create()
    return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-','').ToLowerInvariant()
  } catch {
    return $null
  }
}

function Sanitize-Text {
  param([string]$Text)
  if (-not $Text) { return $Text }
  $t = $Text
  $t = [regex]::Replace($t, '(?i)\b[a-z]:\\[^\s''"]+', 'PATH/TO/FILE')
  $t = [regex]::Replace($t, '(?i)\\\\[a-z0-9\.\-]+\\[^\s''"]+', 'PATH/TO/UNC')
  return $t
}

function Write-PrettySummary {
  param(
    [hashtable]$Summary,
    [int]$ChannelSizeMiB,
    [switch]$Sanitize,
    [switch]$NoColor
  )

  $useColor = -not $NoColor

  function _Color([string]$Text, [ConsoleColor]$Color) {
    if (-not $useColor) { Write-UiLine $Text; return }
    Write-UiLine $Text -ForegroundColor $Color
  }

  $ok = [bool]$Summary.Ok
  $drift = [bool]$Summary.DriftDetected

  $line = "============================================================"
  if ($Sanitize) { $line = Sanitize-Text $line }

  Write-UiLine $line
  _Color "Sysmon Config Updater" ([ConsoleColor]::Cyan)
  Write-UiLine ("Timestamp      : " + (Get-Date).ToString("s"))
  Write-UiLine $line

  if ($ok) { _Color ("Status         : OK") ([ConsoleColor]::Green) }
  else { _Color ("Status         : NOT OK") ([ConsoleColor]::Red) }

  if ($drift) { _Color ("DriftDetected  : True") ([ConsoleColor]::Yellow) }
  else { Write-UiLine ("DriftDetected  : False") }

  Write-UiLine ("Remediate      : " + $Summary.Remediate + " (IsAdmin=" + $Summary.IsAdmin + ")")
  Write-UiLine ("EnsureChannel  : " + $Summary.EnsureChannel + " (SizeMiB=" + $ChannelSizeMiB + ")")
  Write-UiLine ("ConfigFile     : " + ($(if($Summary.ConfigFile){$Summary.ConfigFile}else{'n/a'})))
  Write-UiLine ("DesiredSha256  : " + ($(if($Summary.DesiredSha256){$Summary.DesiredSha256}else{'n/a'})))
  Write-UiLine ("PrevSha256     : " + ($(if($Summary.PrevDesiredSha256){$Summary.PrevDesiredSha256}else{'n/a'})))
  Write-UiLine ("Service        : " + ($(if($Summary.SysmonService){$Summary.SysmonService}else{'n/a'})))
  Write-UiLine ("Exe            : " + ($(if($Summary.SysmonExe){$Summary.SysmonExe}else{'n/a'})))
  Write-UiLine ("EngineVersion  : " + ($(if($Summary.EngineVersion){$Summary.EngineVersion}else{'n/a'})))
  Write-UiLine ("DumpSha256     : " + ($(if($Summary.CurrentDumpSha256){$Summary.CurrentDumpSha256}else{'n/a'})))
  Write-UiLine ("StateWritten   : " + $Summary.StateWritten)

  if ($Summary.Actions -and $Summary.Actions.Count -gt 0) {
    Write-UiLine ""
    _Color "Actions:" ([ConsoleColor]::Green)
    foreach ($a in $Summary.Actions) { Write-UiLine ("  - " + $a) }
  }

  if ($Summary.Warnings -and $Summary.Warnings.Count -gt 0) {
    Write-UiLine ""
    _Color "Warnings:" ([ConsoleColor]::Yellow)
    foreach ($w in $Summary.Warnings) { Write-UiLine ("  - " + $w) }
  }

  Write-UiLine $line
}

# -----------------------------
# Main
# -----------------------------
Ensure-EventSource

$ok = $true
$needUpdate = $false
$installed = $false

$lines   = @()
$actions = @()
$warns   = @()

# Structured summary object for pipeline and console
$summary = [ordered]@{
  Ok                = $false
  Remediate         = [bool]$Remediate
  EnsureChannel     = [bool]$EnsureChannel
  IsAdmin           = $false
  ConfigFile        = $null
  DesiredSha256     = $null
  PrevDesiredSha256 = $null
  SysmonService     = $null
  SysmonExe         = $null
  EngineVersion     = $null
  MinEngineRequired = $null
  CurrentDumpSha256 = $null
  DriftDetected     = $false
  InstalledNow      = $false
  Actions           = @()
  Warnings          = @()
  StateWritten      = $false
  StatePath         = $StatePath
}

try {
  $isAdmin = Test-IsAdmin
  $summary.IsAdmin = $isAdmin

  if ($Remediate -and -not $isAdmin) {
    $ok = $false
    $warns += "Remediate requested but not elevated."
  }

  # Manifest defaults if missing or invalid JSON
  $manifestDefault = @{
    MinEngine     = $null
    AllowedHashes = @()
    Config        = @{ File = $null }
  }
  $manifest = $manifestDefault
  if ($ManifestPath) {
    $manifest = Load-JsonOrDefault -Path $ManifestPath -DefaultObject $manifestDefault
  }

  if ((-not $MinEngine) -and $manifest -and $manifest.MinEngine) { $MinEngine = [string]$manifest.MinEngine }
  $summary.MinEngineRequired = $MinEngine
  $minEngVer = $null
  if ($MinEngine) { $minEngVer = Parse-Version $MinEngine }

  $allowHashes = @()
  if ($manifest -and $manifest.AllowedHashes) {
    $allowHashes = @($manifest.AllowedHashes | ForEach-Object { $_.ToString().ToLowerInvariant() })
  }

  # Select config file from explicit path, dir or manifest mapping
  $cfgFile = Select-ConfigFile -Path $ConfigPath -Dir $SourceDir -NameHint $ConfigNameHint -Manifest $manifest
  if (-not $cfgFile -and $ConfigPathFallback -and (Test-Path -LiteralPath $ConfigPathFallback)) {
    $cfgFile = Get-Item -LiteralPath $ConfigPathFallback
  }
  if (-not $cfgFile) {
    throw "No config file found. Use -ConfigPath, -SourceDir or -ManifestPath."
  }

  $cfgPath = $cfgFile.FullName
  $summary.ConfigFile = $cfgFile.Name

  $cfgHash = (Get-FileSha256 -Path $cfgPath)
  if (-not $cfgHash) { throw "Could not compute SHA256 for config file." }
  $cfgHash = $cfgHash.ToLowerInvariant()
  $summary.DesiredSha256 = $cfgHash

  $tmp = Validate-ConfigXml $cfgPath
  $valid = [bool]$tmp[0]
  $valMsg = [string]$tmp[1]
  if (-not $valid) { throw ("Config XML invalid: " + $valMsg) }

  $lines += ("Config: " + $cfgFile.Name + " (SHA256=" + $cfgHash + "; " + $valMsg + ")")

  if ($allowHashes.Count -gt 0 -and ($allowHashes -notcontains $cfgHash)) {
    $ok = $false
    $warns += "Config SHA256 not in allowlist."
  }

  # Detect Sysmon
  $exe = Resolve-SysmonExe -Hint $SysmonExePath
  $svcName = Get-SysmonServiceName
  $eng = Get-SysmonEngineVersion -Exe $exe

  $summary.SysmonExe = $exe
  $summary.SysmonService = $svcName
  if ($eng) { $summary.EngineVersion = $eng.Raw }

  if ($svcName) {
    $lines += ("Sysmon: Service=" + $svcName + ", Exe='" + ($(if($exe){$exe}else{'n/a'})) + "', Engine=" + ($(if($eng){$eng.Raw}else{'n/a'})))
  } else {
    $lines += ("Sysmon: Service not installed (Exe=" + ($(if($exe){$exe}else{'n/a'})) + ")")
  }

  if ($minEngVer -and $eng) {
    if ((Cmp-Ver $eng $minEngVer) -lt 0) {
      $ok = $false
      $warns += ("Engine below minimum: Installed=" + $eng.Raw + " Required=" + $minEngVer.Raw)
    }
  } elseif ($minEngVer -and (-not $eng)) {
    $ok = $false
    $warns += ("Cannot determine engine version; minimum required=" + $minEngVer.Raw)
  }

  # State defaults if missing or invalid JSON
  $stateDefault = @{
    Config  = @{ Sha256 = $null }
    Runtime = @{ CurrentDumpSha256 = $null }
  }
  $state = Load-JsonOrDefault -Path $StatePath -DefaultObject $stateDefault

  $prevDesiredHash = $null
  if ($state -and $state.Config -and $state.Config.Sha256) { $prevDesiredHash = [string]$state.Config.Sha256 }
  $summary.PrevDesiredSha256 = $prevDesiredHash

  if ($prevDesiredHash -ne $cfgHash) { $needUpdate = $true }

  # Runtime dump hash (best effort)
  $currentCfgDumpSha = $null
  if ($svcName -and $exe) {
    $currentCfgDumpSha = Get-SysmonCurrentConfigSha256 -Exe $exe
    $summary.CurrentDumpSha256 = $currentCfgDumpSha

    if (-not $currentCfgDumpSha) {
      $warns += "Could not compute runtime config dump hash."
    } else {
      $prevDump = $null
      if ($state -and $state.Runtime -and $state.Runtime.CurrentDumpSha256) { $prevDump = [string]$state.Runtime.CurrentDumpSha256 }
      if ($prevDump -and ($prevDump -ne $currentCfgDumpSha)) {
        $needUpdate = $true
        $warns += "Runtime drift: current dump hash differs from last recorded."
      }
    }
  }

  # Optional channel compliance
  if ($EnsureChannel) {
    $doIt = $false
    if ($Remediate -and $isAdmin) { $doIt = $true }
    $res = Ensure-SysmonChannel -DoIt:$doIt -MiB $ChannelSizeMiB
    $cOk  = [bool]$res[0]
    $cMsg = [string]$res[1]
    if (-not $cOk) { $ok=$false; $warns += ("Channel not compliant: " + $cMsg) }
    else { if ($cMsg) { $actions += ("Channel: " + $cMsg) } }
  }

  # Remediation
  if ($Remediate -and $isAdmin) {
    if (-not $svcName) {
      if (-not $exe) { $ok=$false; throw "Sysmon not installed and SysmonExePath not provided/found." }

      try {
        # Install with config (-i) and accept EULA.
        $p = Start-Process -FilePath $exe -ArgumentList @('-accepteula', '-i', $cfgPath) -Wait -PassThru -WindowStyle Hidden
        if ($p.ExitCode -eq 0) {
          $installed = $true
          $actions += "Installed Sysmon"
          $needUpdate = $false
        } else {
          $ok = $false
          $warns += ("Install exitcode=" + $p.ExitCode)
        }
      } catch {
        $ok = $false
        $warns += ("Install failed: " + $_.Exception.Message)
      }
    }
    elseif ($needUpdate) {
      try {
        # Update config (-c) and accept EULA.
        $p = Start-Process -FilePath $exe -ArgumentList @('-accepteula', '-c', $cfgPath) -Wait -PassThru -WindowStyle Hidden
        if ($p.ExitCode -eq 0) {
          $actions += "Applied config update"
          $needUpdate = $false
        } else {
          $ok = $false
          $warns += ("Update exitcode=" + $p.ExitCode)
        }
      } catch {
        $ok = $false
        $warns += ("Update failed: " + $_.Exception.Message)
      }
    }

    # Re-detect after changes
    $exe = Resolve-SysmonExe -Hint $SysmonExePath
    $svcName = Get-SysmonServiceName
    $eng = Get-SysmonEngineVersion -Exe $exe
    if ($svcName -and $exe) { $currentCfgDumpSha = Get-SysmonCurrentConfigSha256 -Exe $exe }

    $summary.SysmonExe = $exe
    $summary.SysmonService = $svcName
    $summary.CurrentDumpSha256 = $currentCfgDumpSha
    if ($eng) { $summary.EngineVersion = $eng.Raw }
  }

  $summary.InstalledNow = $installed

  # Build anonymized source string (do not leak internal paths)
  $sourceStr = $null
  if ($ManifestPath) { $sourceStr = "manifest:PATH/TO/JSON" }
  elseif ($SourceDir)  { $sourceStr = "dir:PATH/TO/DIR" }
  elseif ($ConfigPath) { $sourceStr = "file:PATH/TO/XML" }
  else { $sourceStr = "file:PATH/TO/XML" }

  # Persist state (best effort; skip if placeholder is still used)
  $engineRaw = $null
  if ($eng) { $engineRaw = $eng.Raw }

  $newState = @{
    Time = (Get-Date).ToString('s')
    Host = $env:COMPUTERNAME
    Engine = @{
      Version = $engineRaw
      ExePath = $exe
      Service = $svcName
    }
    Config = @{
      Path   = $cfgPath
      Sha256 = $cfgHash
      Source = $sourceStr
      Valid  = $valid
    }
    Runtime = @{
      CurrentDumpSha256 = $currentCfgDumpSha
    }
  }

  $stateWritten = $false
  if ($StatePath -and $StatePath -notmatch '^PATH/TO/') {
    $stateWritten = Write-State -p $StatePath -obj $newState
  }
  $summary.StateWritten = [bool]$stateWritten
  if ($stateWritten) {
    $actions += "State updated"
  } else {
    $warns += "State not written (StatePath not set or write failed)."
  }

  # Final drift evaluation
  if ($needUpdate -and (-not $Remediate)) {
    $ok = $false
    $warns += ("Drift detected: desired SHA256=" + $cfgHash + ", last applied=" + ($(if($prevDesiredHash){$prevDesiredHash}else{'n/a'})))
  }

  $summary.DriftDetected = [bool]$needUpdate

  if ($warns.Count -gt 0) { $lines += ("Warnings: " + ($warns -join ' | ')) }
  if ($actions.Count -gt 0) { $lines += ("Actions: " + ($actions -join '; ')) }

  $msg = ($lines -join "`r`n")

  $eventId = 4710
  $level   = 'Warning'
  if ($ok) { $eventId = 4700; $level = 'Information' }

  Write-HealthEvent $eventId $msg $level

  $summary.Ok       = [bool]$ok
  $summary.Actions  = @($actions)
  $summary.Warnings = @($warns)

  # Structured pipeline output (safe for Export-Csv / ConvertTo-Json).
  [pscustomobject]$summary
}
catch {
  $ok = $false
  $summary.Ok = $false
  $summary.Warnings = @($summary.Warnings + ("Fatal: " + $_.Exception.Message))

  Write-HealthEvent 4710 ("Sysmon Config Updater: error " + $_.Exception.Message) 'Error'

  # Structured pipeline output even on failure.
  [pscustomobject]$summary
}
finally {
  if (-not $NoConsoleSummary) {
    $pretty = $summary
    if ($SanitizeConsoleOutput) {
      # Sanitize only string fields (keep booleans as-is).
      $pretty = @{}
      foreach ($k in $summary.Keys) {
        $v = $summary[$k]
        if ($v -is [string]) { $pretty[$k] = Sanitize-Text $v }
        elseif ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
          $arr = @()
          foreach ($i in $v) {
            if ($i -is [string]) { $arr += (Sanitize-Text $i) } else { $arr += $i }
          }
          $pretty[$k] = $arr
        } else { $pretty[$k] = $v }
      }
    }

    Write-PrettySummary -Summary $pretty -ChannelSizeMiB $ChannelSizeMiB -Sanitize:$false -NoColor:$NoColor
  }
}

# C10: populate canonical findings from warnings
foreach ($w in @($warns)) {
  $code = 'SYSMON-Warning'
  $sev = 'Medium'
  if ($w -match 'allowlist')     { $code = 'SYSMON-AllowlistFail'; $sev = 'High' }
  if ($w -match 'Engine below')  { $code = 'SYSMON-EngineOld'; $sev = 'High' }
  if ($w -match 'drift')         { $code = 'SYSMON-Drift'; $sev = 'Medium' }
  if ($w -match 'Install|Update'){ $code = 'SYSMON-ApplyFail'; $sev = 'High' }
  if ($w -match 'Channel')       { $code = 'SYSMON-Channel'; $sev = 'Low' }
  if ($w -match 'not elevated')  { $code = 'SYSMON-NoAdmin'; $sev = 'Medium' }
  Add-Finding -FindingList $script:Findings -Code $code -Severity $sev -Message $w
}

# V2 output contract
$resultToken = if ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = New-V2ResultObject -ScriptName '16-Sysmon-Config-Updater.ps1' -Mode $Mode -Result $resultToken -Findings @($script:Findings) -Summary ([pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Timestamp = Get-Date }) -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
