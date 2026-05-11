#requires -version 5.1
<#
.SYNOPSIS
  Performs a health check and optional self-healing actions for WinGet on a Windows device.
.DESCRIPTION
  This script validates a working WinGet environment and produces both:
  - A human-friendly console summary (colored output).
  - A structured, automation-friendly result object for the pipeline.
  The script is designed for enterprise automation scenarios (scheduled tasks, MDM, build agents),
  but can also be run interactively by administrators.
  High-level workflow:
  1) Load optional JSON configuration (if available) and merge with parameter overrides.
  2) Detect WinGet and validate the installed WinGet version against the built-in minimum.
  3) Check Microsoft Visual C++ Redistributables:
     - x64 is required (missing => Error).
     - x86 is optional (missing => Warning).
     If -Remediate is used and installer paths are available, the script attempts installation.
  4) Validate presence of a private WinGet source (name + URL) when RequirePrivateSource is enabled.
     If -Remediate is used, the script can add the missing source (and update it if already present).
  5) Run "winget source update" to refresh sources.
     A failure is Warning by default, or Error when -FailOnSourceUpdateError is set.
  6) Write a short audit message to the Windows Application Event Log (best-effort).
  7) Print a final console summary and return structured results to the pipeline.
  Output conventions:
  - Pipeline output is always structured objects only (no formatted strings).
  - Console output uses Write-UiLine / Write-Information only and is suppressed with -NoConsole.
.PARAMETER Remediate
  Enables remediation actions.
  When set, the script may:
  - Install missing VC++ Redistributables (if installer paths are configured).
  - Add a missing private WinGet source (if name and URL are configured).
.PARAMETER RequirePrivateSource
  Controls whether a private WinGet source is required for an overall "OK" status.
  - $true  : Missing private source => overall NOT OK.
  - $false : Private source check is marked as Skipped and does not influence overall status.
.PARAMETER ConfigPath
  Path to an optional JSON configuration file.
  If the file does not exist or cannot be parsed, the script continues with defaults and parameter
  overrides and marks the Config check as Warning.
  The JSON (if present) can provide:
  - VC++ installer paths and arguments.
  - Private source name, URL, and source type.
.PARAMETER PrivateSourceName
  Sets/overrides the private WinGet source name.
  Use this when no JSON is available or when you want to override the JSON value.
.PARAMETER PrivateSourceUrl
  Sets/overrides the private WinGet source URL.
  Use this when no JSON is available or when you want to override the JSON value.
.PARAMETER FailOnSourceUpdateError
  Controls how "winget source update" failures affect the overall result.
  - Not set: source update failure is recorded as Warning.
  - Set:     source update failure is recorded as Error (overall NOT OK).
.PARAMETER DiagnoseWingetErrors
  Adds extended error details for failing WinGet calls by running:
  "winget error --input <ExitCode>".
  This helps translate WinGet HRESULT-style return codes into readable messages.
.PARAMETER NoConsole
  Suppresses all console output.
  Use this for silent automation runs where only pipeline output is desired.
.PARAMETER PassThruRecords
  Changes pipeline output mode:
  - Not set (default): outputs one result object containing a Records array.
  - Set:              outputs each record in the Records array as a separate pipeline object.
.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.
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
.PARAMETER NoColor
  Disable colored output.
.OUTPUTS
  Default output (single object):
    PSCustomObject with:
    - Time                 : Timestamp of the run.
    - OverallStatus        : 'OK' or 'NOT_OK'.
    - Remediate            : Boolean indicating whether remediation was enabled.
    - RequirePrivateSource : Boolean indicating whether private source was required.
    - ConfigPath           : The configured (anonymized) config path used by the run.
    - WingetVersion        : Raw WinGet version string (when available).
    - Records              : Array of check records.
  With -PassThruRecords:
    PSCustomObject (one per check) with:
    - Time, Name, Status, Message, Data
.NOTES
  Exit codes:
  - 0 indicates overall success (OverallStatus = OK).
  - 1 indicates overall failure (OverallStatus = NOT_OK).
  Event Log:
  The script attempts to write an audit entry to the Windows Application event log.
  This is best-effort and does not fail the run if event log write access is unavailable.
  Configuration precedence:
  Parameter values override JSON values, and JSON values override built-in defaults.
.EXAMPLE
  PS C:\> .\08-WinGet-SelfHeal.ps1
  Runs health checks only (no remediation) and prints a console summary.
  Returns a single structured result object to the pipeline.
.EXAMPLE
  PS C:\> .\08-WinGet-SelfHeal.ps1 -NoConsole | ConvertTo-Json -Depth 6
  Runs in "pipeline-only" mode and emits a JSON report suitable for logging.
.EXAMPLE
  PS C:\> .\08-WinGet-SelfHeal.ps1 -Remediate -PrivateSourceName "MyPrivateRepo" -PrivateSourceUrl "https://PACKAGE-SOURCE/api" -DiagnoseWingetErrors
  Runs checks and attempts remediation.
  If the private source is missing, it will attempt to add it (name + URL provided via parameters).
  Also includes additional WinGet error decoding on failures.
.EXAMPLE
  PS C:\> .\08-WinGet-SelfHeal.ps1 -PassThruRecords | Where-Object Status -ne 'OK'
  Emits each record as a pipeline object and filters for non-OK results.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [bool]$RequirePrivateSource = $true,
  [string]$ConfigPath,
  [string]$PrivateSourceName = $null,
  [string]$PrivateSourceUrl  = $null,
  [switch]$FailOnSourceUpdateError,
  [switch]$DiagnoseWingetErrors,
  [switch]$NoConsole,
  [switch]$PassThruRecords
,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)
. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
$script:NoConsole = [bool]$NoConsole
$script:PassThruRecords = [bool]$PassThruRecords
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

$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $result = New-V2ResultObject -ScriptName '08-WinGet-SelfHeal.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

# ---------------- Defaults ----------------
$MinWingetVersionMajor = 1
$MinWingetVersionMinor = 6
$MinWingetVersionPatch = 0
$DefaultVcArgs = "/install /quiet /norestart"
$DefaultPrivateSourceType = "Microsoft.Rest"
$EventSource  = "WinGet-SelfHeal"
$EventLogName = "Application"
# ---------------- Console Helpers ----------------
# Get-StatusColor imported from lib/Console.psm1
# ---------------- Event Log Helpers ----------------
# ---------------- Structured Output Helpers ----------------
function Get-TextOrEmpty {
  [CmdletBinding()]
  param([AllowNull()][AllowEmptyString()]$Value)
  if ($null -eq $Value) { return '' }
  return [string]$Value
}
function New-CheckRecord {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [ValidateSet('OK','Warning','Error','Skipped')] [string]$Status,
    [string]$Message = $null,
    [hashtable]$Data = $null
  )
  [pscustomobject]@{
    Time    = (Get-Date).ToString('s')
    Name    = $Name
    Status  = $Status
    Message = $Message
    Data    = if ($Data) { [pscustomobject]$Data } else { $null }
  }
}
function Add-Record {
  [CmdletBinding()]
  param(
    # Collections must allow empty, otherwise PS rejects empty collections during binding.
    [ValidateNotNull()]
    [AllowEmptyCollection()]
    [System.Collections.Generic.List[object]]$List,
    [Parameter(Mandatory)]
    [ValidateNotNull()]
    [object]$Record
  )
  [void]$List.Add($Record)
}
function Get-OverallOk {
  [CmdletBinding()]
  param([AllowNull()][object[]]$Records)
  if ($null -eq $Records -or $Records.Count -eq 0) { return $false }
  foreach ($r in $Records) {
    if ($null -ne $r -and $r.Status -eq 'Error') { return $false }
  }
  return $true
}
# ---------------- Config Helpers ----------------
function Get-Config {
  [CmdletBinding()]
  param([string]$Path)
  try {
    $sanitized = Sanitize-Path -Path $Path -MustExist
    if ($sanitized) {
      return Get-Content -Raw -LiteralPath $sanitized -Encoding UTF8 | ConvertFrom-Json
    }
    $here = Split-Path -Parent $MyInvocation.MyCommand.Path
    if ($here) {
      $alt = Join-Path (Split-Path -Parent $here) "config\config.json"
      $sanitizedAlt = Sanitize-Path -Path $alt -MustExist
      if ($sanitizedAlt) {
        return Get-Content -Raw -LiteralPath $sanitizedAlt -Encoding UTF8 | ConvertFrom-Json
      }
    }
  } catch { <# best-effort: fallback config file may not exist or be invalid JSON #> }
  return $null
}
function Get-NestedPropValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$Object,
    [Parameter(Mandatory)][string[]]$Path
  )
  $cur = $Object
  foreach ($name in $Path) {
    if ($null -eq $cur) { return $null }
    try {
      $prop = $cur.PSObject.Properties[$name]
      if ($null -eq $prop) { return $null }
      $cur = $prop.Value
    } catch { return $null }
  }
  return $cur
}
# ---------------- WinGet Helpers ----------------
function Resolve-WingetPath {
  [CmdletBinding()]
  param()
  $cmd = Get-Command winget -ErrorAction SilentlyContinue
  if ($cmd -and $cmd.Source -and (Test-Path -LiteralPath $cmd.Source)) { return $cmd.Source }
  $wa = Join-Path $env:ProgramFiles 'WindowsApps'
  if (Test-Path -LiteralPath $wa) {
    try {
      $cand = Get-ChildItem -LiteralPath $wa -Directory -Filter 'Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe' -ErrorAction Stop |
        Sort-Object Name -Descending | Select-Object -First 1
      if ($cand) {
        $p = Join-Path $cand.FullName 'winget.exe'
        if (Test-Path -LiteralPath $p) { return $p }
      }
    } catch { <# best-effort: WindowsApps directory may not be accessible #> }
  }
  return $null
}
function ConvertTo-QuotedArg {
  param([Parameter(Mandatory)][string]$Value)
  # Basic robust quoting for cmd.exe/shell characters
  # We escape existing quotes and wrap the whole thing.
  $escaped = $Value -replace '"', '\"'
  return '"' + $escaped + '"'
}
function Invoke-Winget {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$WingetPath,
    [Parameter(Mandatory)][string[]]$WingetArgs,
    [int]$TimeoutSec = 120
  )
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $WingetPath
  $psi.Arguments = ($WingetArgs | ForEach-Object { ConvertTo-QuotedArg $_ }) -join ' '
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  $null = $p.Start()
  if (-not $p.WaitForExit($TimeoutSec * 1000)) {
    try { $p.Kill() } catch { <# best-effort: process may have already exited #> }
    return @{
      ExitCode = 408
      StdOut   = ''
      StdErr   = "Timeout after $TimeoutSec s"
      Args     = $WingetArgs
    }
  }
  return @{
    ExitCode = $p.ExitCode
    StdOut   = $p.StandardOutput.ReadToEnd()
    StdErr   = $p.StandardError.ReadToEnd()
    Args     = $WingetArgs
  }
}
function Convert-ExitCodeToHex32 {
  [CmdletBinding()]
  param([Parameter(Mandatory)][int]$ExitCode)
  $bytes = [System.BitConverter]::GetBytes([int]$ExitCode)
  $u = [System.BitConverter]::ToUInt32($bytes, 0)
  return ("0x{0:X8}" -f $u)
}
function Get-WingetErrorText {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$WingetPath,
    [Parameter(Mandatory)][int]$ExitCode
  )
  try {
    $res = Invoke-Winget -WingetPath $WingetPath -WingetArgs @('error','--input',"$ExitCode") -TimeoutSec 30
    $t = ($res.StdOut + "`n" + $res.StdErr).Trim()
    if ($t) { return $t }
  } catch { <# best-effort: winget error diagnostics may not be available #> }
  return $null
}
function Parse-Version {
  [CmdletBinding()]
  param([string]$s)
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  $m = [regex]::Match($s, 'v?(\d+)\.(\d+)\.(\d+)')
  if (-not $m.Success) { $m = [regex]::Match($s, 'v?(\d+)\.(\d+)') }
  if (-not $m.Success) { return $null }
  $maj = [int]$m.Groups[1].Value
  $min = [int]$m.Groups[2].Value
  $pat = 0
  if ($m.Groups.Count -ge 4 -and $m.Groups[3].Value) { $pat = [int]$m.Groups[3].Value }
  return [pscustomobject]@{ Major=$maj; Minor=$min; Patch=$pat; Raw=$s.Trim() }
}
function Is-Version-AtLeast {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$v,
    [Parameter(Mandatory)][int]$maj,
    [Parameter(Mandatory)][int]$min,
    [int]$pat = 0
  )
  if (-not $v) { return $false }
  if ($v.Major -gt $maj) { return $true }
  if ($v.Major -lt $maj) { return $false }
  if ($v.Minor -gt $min) { return $true }
  if ($v.Minor -lt $min) { return $false }
  return ($v.Patch -ge $pat)
}
function Test-WingetSupportsAcceptSourceAgreements {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$WingetPath)
  try {
    $h = Invoke-Winget -WingetPath $WingetPath -WingetArgs @('source','update','--help') -TimeoutSec 30
    $t = ($h.StdOut + "`n" + $h.StdErr)
    if ($t -match '--accept-source-agreements') { return $true }
  } catch { <# best-effort: source update help check #> }
  return $false
}
function Invoke-WingetSourceUpdate {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$WingetPath,
    [string]$SourceName,
    [bool]$SupportAcceptSourceAgreements
  )
  # Use "-n <name>" for compatibility with documented syntax. [web:12]
  $wingetArgs = @('source','update')
  if ($SourceName) { $wingetArgs += @('-n', $SourceName) }
  if ($SupportAcceptSourceAgreements) { $wingetArgs += '--accept-source-agreements' }
  return Invoke-Winget -WingetPath $WingetPath -WingetArgs $wingetArgs
}
# ---------------- VC++ Helpers ----------------
function Test-VcRedistInstalled {
  [CmdletBinding()]
  param([ValidateSet('x64','x86')]$Arch='x64')
  $paths = @(
    "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\$Arch",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\$Arch"
  )
  foreach ($key in $paths) {
    if (Test-Path $key) {
      try {
        $p = Get-ItemProperty -Path $key -ErrorAction Stop
        $installed = ($p.Installed -eq 1) -or ($p.PSObject.Properties['Version'] -and $p.Version)
        if ($installed) { return $true, ($p.Version) }
      } catch { <# best-effort: VC++ registry key may not exist #> }
    }
  }
  return $false, $null
}
function Install-VcRedist {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param(
    [Parameter(Mandatory)][string]$Path,
    [string]$InstallArgs = "/install /quiet /norestart"
  )
  if (-not (Test-Path -LiteralPath $Path)) { return $false, "Installer not found: $Path" }
  try {
    if (-not $PSCmdlet.ShouldProcess($Path, 'Install VC++ redistributable')) {
      return $false, 'Skipped by ShouldProcess'
    }
    $p = Start-Process -FilePath $Path -ArgumentList $InstallArgs -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -eq 0) { return $true, "OK" }
    return $false, "ExitCode=$($p.ExitCode)"
  } catch { return $false, $_.Exception.Message }
}
# ---------------- Source Helpers ----------------
function Test-WingetSourcePresent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$WingetPath,
    [Parameter(Mandatory)][string]$Name
  )
  $res = Invoke-Winget -WingetPath $WingetPath -WingetArgs @('source','list','-n',$Name)
  if ($res.ExitCode -eq 0) {
    if ($res.StdOut -match [regex]::Escape($Name)) { return $true, "Found via 'source list -n'" }
    return $true, "ExitCode=0 (assumed present)"
  }
  $res2 = Invoke-Winget -WingetPath $WingetPath -WingetArgs @('source','list')
  if ($res2.ExitCode -eq 0 -and $res2.StdOut -match ("(?im)^\s*" + [regex]::Escape($Name) + "\b")) {
    return $true, "Found via 'source list'"
  }
  $err = (($res.StdErr + "`n" + $res.StdOut).Trim())
  if (-not $err) { $err = "ExitCode=$($res.ExitCode)" }
  return $false, $err
}
function Ensure-PrivateSource {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$WingetPath,
    [string]$Name,
    [string]$Url,
    [string]$Type,
    [switch]$DoIt,
    [bool]$SupportAcceptSourceAgreementsForSourceUpdate
  )
  if ([string]::IsNullOrWhiteSpace($Name)) { return $false, "No private source name configured" }
  $present = $false; $detail = $null
  $present, $detail = Test-WingetSourcePresent -WingetPath $WingetPath -Name $Name
  if ($present) {
    $up = Invoke-WingetSourceUpdate -WingetPath $WingetPath -SourceName $Name -SupportAcceptSourceAgreements:$SupportAcceptSourceAgreementsForSourceUpdate
    if ($up.ExitCode -eq 0) { return $true, "Present; update OK" }
    return $true, "Present; update failed (ec=$($up.ExitCode)): $(($up.StdErr + ' ' + $up.StdOut).Trim())"
  }
  if (-not $DoIt) { return $false, "Missing (no remediation). Detail: $detail" }
  if ([string]::IsNullOrWhiteSpace($Url)) { return $false, "Missing and no URL configured. Detail: $detail" }
  $add = Invoke-Winget -WingetPath $WingetPath -WingetArgs @(
    'source','add',
    '-n', $Name,
    '-t', $Type,
    '-a', $Url,
    '--accept-source-agreements'
  )
  if ($add.ExitCode -eq 0) { return $true, "Added" }
  $txt = (($add.StdErr + ' ' + $add.StdOut).Trim())
  if (-not $txt) { $txt = "ExitCode=$($add.ExitCode)" }
  return $false, "Add failed: $txt"
}
# ---------------- Main ----------------
$script:Findings = New-FindingsList
$records = New-Object System.Collections.Generic.List[object]
# Settings with sane defaults when config missing:
# - VC++ install paths are optional; remediation will log a clear error if missing.
# - Private source stays policy-driven by RequirePrivateSource + parameter overrides.
$cfgLoaded = $false
$vcX64Path = $null
$vcX86Path = $null
$vcArgs    = $DefaultVcArgs
$privName  = $PrivateSourceName
$privUrl   = $PrivateSourceUrl
$privType  = $DefaultPrivateSourceType
$wg = $null
$wingetVersionRaw = $null
$supportAcceptForSourceUpdate = $false
try {
  # Do not fail the run if event source registration isn't possible (commonly needs admin). [web:2]
  try { Ensure-EventSource -Source $EventSource -LogName $EventLogName } catch { <# best-effort: event source registration commonly needs admin #> }
  $cfg = Get-Config -Path $ConfigPath
  if ($cfg) {
    $cfgLoaded = $true
    $tmp = Get-NestedPropValue -Object $cfg -Path @('VCppRedist','x64'); if ($tmp) { $vcX64Path = [string]$tmp }
    $tmp = Get-NestedPropValue -Object $cfg -Path @('VCppRedist','x86'); if ($tmp) { $vcX86Path = [string]$tmp }
    $tmp = Get-NestedPropValue -Object $cfg -Path @('VCppRedist','Args'); if ($tmp) { $vcArgs    = [string]$tmp }
    if (-not $privName) { $tmp = Get-NestedPropValue -Object $cfg -Path @('Winget','PrivateSourceName'); if ($tmp) { $privName = [string]$tmp } }
    if (-not $privUrl)  { $tmp = Get-NestedPropValue -Object $cfg -Path @('Winget','PrivateSourceUrl');  if ($tmp) { $privUrl  = [string]$tmp } }
    $tmp = Get-NestedPropValue -Object $cfg -Path @('Winget','PrivateSourceType'); if ($tmp) { $privType = [string]$tmp }
  }
  $configStatus = 'Warning'
  $configMsg = 'Not loaded. Using defaults/parameters.'
  if ($cfgLoaded) { $configStatus = 'OK'; $configMsg = 'Loaded (path redacted).' }
  Add-Record -List $records -Record (New-CheckRecord -Name 'Config' -Status $configStatus -Message $configMsg -Data @{
    ConfigPath = 'PATH/TO/JSON'
    RequirePrivateSource = $RequirePrivateSource
  })
  $wg = Resolve-WingetPath
  if (-not $wg) {
    Add-Record -List $records -Record (New-CheckRecord -Name 'WinGet' -Status 'Error' -Message 'winget.exe not found.')
  } else {
    $env:WINGET_SUPPRESS_PROMPT = "1"
  $verRes = Invoke-Winget -WingetPath $wg -WingetArgs @('--version')
    $v = Parse-Version $verRes.StdOut
    $wingetVersionRaw = ($verRes.StdOut.Trim())
    if ($verRes.ExitCode -ne 0 -or -not $v) {
      Add-Record -List $records -Record (New-CheckRecord -Name 'WinGet' -Status 'Error' -Message 'Version check failed.' -Data @{
        ExitCode = $verRes.ExitCode; StdErr = $verRes.StdErr.Trim(); StdOut = $verRes.StdOut.Trim()
      })
    } elseif (-not (Is-Version-AtLeast -v $v -maj $MinWingetVersionMajor -min $MinWingetVersionMinor -pat $MinWingetVersionPatch)) {
      Add-Record -List $records -Record (New-CheckRecord -Name 'WinGet' -Status 'Error' -Message 'Version too old.' -Data @{
        Have = $v.Raw; Need = "$MinWingetVersionMajor.$MinWingetVersionMinor.$MinWingetVersionPatch"
      })
    } else {
      Add-Record -List $records -Record (New-CheckRecord -Name 'WinGet' -Status 'OK' -Message 'OK.' -Data @{
        Version = $v.Raw; Path = $wg
      })
      Add-Finding -FindingList $script:Findings -Code 'Winget-Found' -Severity 'Low' -Message "WinGet version $($v.Raw) located at $wg"
    }
    $supportAcceptForSourceUpdate = Test-WingetSupportsAcceptSourceAgreements -WingetPath $wg
    Add-Record -List $records -Record (New-CheckRecord -Name 'WinGetSourceUpdateCapabilities' -Status 'OK' -Message 'Capability probe done.' -Data @{
      AcceptSourceAgreementsForSourceUpdate = $supportAcceptForSourceUpdate
    })
  }
  $vcx64 = $false; $vcx64v = $null
  $vcx64, $vcx64v = Test-VcRedistInstalled -Arch 'x64'
  if (-not $vcx64) {
    Add-Record -List $records -Record (New-CheckRecord -Name 'VcRedistX64' -Status 'Error' -Message 'Missing.')
    if ($Remediate) {
      if ($vcX64Path) {
        $r = $false; $m = $null
        $r, $m = Install-VcRedist -Path $vcX64Path -InstallArgs $vcArgs
        $st = 'Error'; $ms = 'Install failed.'
        if ($m -eq 'Skipped by ShouldProcess') { $st = 'Skipped'; $ms = $m }
        elseif ($r) { $st = 'OK'; $ms = 'Installed.' }
        Add-Record -List $records -Record (New-CheckRecord -Name 'VcRedistX64Remediation' -Status $st -Message $ms -Data @{
          Detail = $m; InstallerPath = $vcX64Path
        })
      } else {
        Add-Record -List $records -Record (New-CheckRecord -Name 'VcRedistX64Remediation' -Status 'Error' -Message 'Remediation requested but installer path not configured.')
      }
    }
  } else {
    Add-Record -List $records -Record (New-CheckRecord -Name 'VcRedistX64' -Status 'OK' -Message 'OK.' -Data @{ Version = $vcx64v })
  }
  $vcx86 = $false; $vcx86v = $null
  $vcx86, $vcx86v = Test-VcRedistInstalled -Arch 'x86'
  if ($vcx86) {
    Add-Record -List $records -Record (New-CheckRecord -Name 'VcRedistX86' -Status 'OK' -Message 'OK.' -Data @{ Version = $vcx86v })
  } else {
    Add-Record -List $records -Record (New-CheckRecord -Name 'VcRedistX86' -Status 'Warning' -Message 'Not installed (optional).')
    if ($Remediate -and $vcX86Path) {
      $r = $false; $m = $null
      $r, $m = Install-VcRedist -Path $vcX86Path -InstallArgs $vcArgs
      $st = 'Error'; $ms = 'Install failed.'
      if ($m -eq 'Skipped by ShouldProcess') { $st = 'Skipped'; $ms = $m }
      elseif ($r) { $st = 'OK'; $ms = 'Installed.' }
      Add-Record -List $records -Record (New-CheckRecord -Name 'VcRedistX86Remediation' -Status $st -Message $ms -Data @{
        Detail = $m; InstallerPath = $vcX86Path
      })
    }
  }
  if ($RequirePrivateSource) {
    if (-not $wg) {
      Add-Record -List $records -Record (New-CheckRecord -Name 'PrivateSource' -Status 'Error' -Message 'Skipped (winget missing).')
    } else {
      $havePriv = $false; $privMsg = $null
      $havePriv, $privMsg = Ensure-PrivateSource -WingetPath $wg -Name $privName -Url $privUrl -Type $privType -DoIt:$Remediate -SupportAcceptSourceAgreementsForSourceUpdate:$supportAcceptForSourceUpdate
      $st = 'Error'
      if ($havePriv) { $st = 'OK' }
      Add-Record -List $records -Record (New-CheckRecord -Name 'PrivateSource' -Status $st -Message $privMsg -Data @{
        Name = $privName; Url = $privUrl; Type = $privType
      })
    }
  } else {
    Add-Record -List $records -Record (New-CheckRecord -Name 'PrivateSource' -Status 'Skipped' -Message 'Not required.')
  }
  if ($wg) {
    $upd = Invoke-WingetSourceUpdate -WingetPath $wg -SupportAcceptSourceAgreements:$supportAcceptForSourceUpdate
    if ($upd.ExitCode -eq 0) {
      Add-Record -List $records -Record (New-CheckRecord -Name 'SourceUpdate' -Status 'OK' -Message 'OK.')
    } else {
      $hex = Convert-ExitCodeToHex32 -ExitCode $upd.ExitCode
      $diag = $null
      if ($DiagnoseWingetErrors) { $diag = Get-WingetErrorText -WingetPath $wg -ExitCode $upd.ExitCode }
      $st = 'Warning'
      if ($FailOnSourceUpdateError) { $st = 'Error' }
      Add-Record -List $records -Record (New-CheckRecord -Name 'SourceUpdate' -Status $st -Message 'Failed.' -Data @{
        ExitCode = $upd.ExitCode
        ExitCodeHex = $hex
        StdErr = $upd.StdErr.Trim()
        StdOut = $upd.StdOut.Trim()
        WingetError = $diag
        Args = ($upd.Args -join ' ')
      })
    }
  } else {
    Add-Record -List $records -Record (New-CheckRecord -Name 'SourceUpdate' -Status 'Skipped' -Message 'Skipped (winget missing).')
  }
} catch {
  Add-Record -List $records -Record (New-CheckRecord -Name 'UnhandledException' -Status 'Error' -Message $_.Exception.Message -Data @{
    Position = (Get-TextOrEmpty $_.InvocationInfo.PositionMessage)
  })
} finally {
  if ($records.Count -eq 0) {
    Add-Record -List $records -Record (New-CheckRecord -Name 'Runtime' -Status 'Error' -Message 'No records were produced (early termination).')
  }
  $overallOk = Get-OverallOk -Records $records.ToArray()
  # ---- Event log ----
  $eventLines = New-Object System.Collections.Generic.List[string]
  foreach ($r in $records) {
    $msg = Get-TextOrEmpty $r.Message
    [void]$eventLines.Add(("[{0}] {1}: {2}" -f $r.Status, $r.Name, $msg))
  }
  $eventMsg = ($eventLines.ToArray() -join "`r`n")
  $eventId = 4110
  $eventLevel = 'Warning'
  if ($overallOk) { $eventId = 4100; $eventLevel = 'Information' }
  Write-HealthEvent -Id $eventId -Msg $eventMsg -Level $eventLevel -Source $EventSource -LogName $EventLogName
  # ---- Pretty console output ----
  Write-ConsoleHeader -Title 'WinGet Self-Heal Summary'
  $statusText = 'NOT OK'
  $statusColor = 'Red'
  if ($overallOk) { $statusText = 'OK'; $statusColor = 'Green' }
  Write-KeyValue -Key 'Status' -Value $statusText -ValueColor $statusColor
  Write-KeyValue -Key 'Remediate' -Value ($(if ($Remediate) { 'Yes' } else { 'No' })) -ValueColor ($(if ($Remediate) { 'Yellow' } else { 'Gray' }))
  Write-KeyValue -Key 'RequirePrivateSource' -Value ([string]$RequirePrivateSource) -ValueColor ($(if ($RequirePrivateSource) { 'Yellow' } else { 'Gray' }))
  Write-KeyValue -Key 'ConfigPath' -Value 'PATH/TO/JSON' -ValueColor 'Gray'
  if ($wingetVersionRaw) { Write-KeyValue -Key 'WinGetVersion' -Value $wingetVersionRaw -ValueColor 'White' }
  if (-not $script:NoConsole) {
    Write-UiLine ""
    Write-UiLine "Checks:" -ForegroundColor Cyan
    foreach ($r in $records) {
      $c = Get-StatusColor -Status $r.Status
      $msg = Get-TextOrEmpty $r.Message
      Write-UiLine ("- {0,-32} {1,-8} {2}" -f $r.Name, $r.Status, $msg) -ForegroundColor $c
    }
  }
  # V2 output contract
  $resultToken = if (-not $overallOk) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
  $v2Summary = [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Mode = $Mode; OverallOk = $overallOk; Timestamp = Get-Date }
  $v2Result = New-V2ResultObject -ScriptName '08-WinGet-SelfHeal.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $v2Summary -Metadata @{ Records = @($records) }
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $v2Result }
  if ($overallOk) { exit 0 } else { exit 1 }
}
