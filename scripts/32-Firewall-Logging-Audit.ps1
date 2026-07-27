#Requires -RunAsAdministrator
#requires -version 5.1
<#
.SYNOPSIS
Audit and optionally remediate Windows Defender Firewall logging settings per profile (Windows PowerShell 5.1).

.DESCRIPTION
Audits Domain/Private/Public firewall profile logging settings and produces findings.
Optionally remediates: LogFileName, LogMaxSizeKilobytes, LogBlocked (dropped), LogAllowed (allowed).
Optionally loads desired settings from JSON; falls back to defaults when JSON is missing/invalid/empty.

Best-practice output model:
- Pipeline output: structured objects only (safe for Export-Csv / ConvertTo-Json / Where-Object).
- Console output: formatted summary via Write-UiLine (information stream in PS 5.1).

.PARAMETER Mode
Audit | Remediate

.PARAMETER SettingsJsonPath
Optional JSON path supplied with $SettingsJsonPath.
Expected keys (all optional): EnableDropped, EnableAllowed, LogFileName, LogMaxSizeKB

.PARAMETER EnableDropped
Override desired dropped logging. Values: true/false/1/0/yes/no/on/off.

.PARAMETER EnableAllowed
Override desired allowed logging. Values: true/false/1/0/yes/no/on/off.

.PARAMETER LogFileName
Override desired firewall log file path.

.PARAMETER LogMaxSizeKB
Override desired log max size KB (1..32767).

.PARAMETER ExportPath
Optional base path for CSV exports (writes _summary/_desired/_before/_after/_findings).

.PARAMETER FailOnHigh
If set, reports FAIL at the end when High findings exist.

.PARAMETER NoConsoleSummary
If set, do not print the console summary.


.PARAMETER ConfigPath
  Path to JSON configuration file.

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
One PSCustomObject with:
Summary, Desired, Findings, ProfilesBefore, ProfilesAfter.
.EXAMPLE
  .\32-Firewall-Logging-Audit.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateSet('Audit','Remediate')]
  [string]$Mode = 'Audit',

  [string]$SettingsJsonPath,

  [object]$EnableDropped,
  [object]$EnableAllowed,

  [string]$LogFileName,
  [object]$LogMaxSizeKB,

  [string]$ExportPath,

  [switch]$FailOnHigh,

  [switch]$NoConsoleSummary

,
  [string]$ConfigPath,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '32-Firewall-Logging-Audit.ps1' -BoundParameters $PSBoundParameters `
  -Mode $Mode -ConfigPath $ConfigPath -OutputFormat $OutputFormat -OutputPath $OutputPath `
  -PassThru:$PassThru -Strict:$Strict -Quiet:$Quiet -NoColor:$NoColor
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
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
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '32-Firewall-Logging-Audit.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# region Helpers


# Ensure-Cmdlet imported from lib/External.psm1

function TryParse-Bool {
  param([object]$Value)

  if ($null -eq $Value) { return $null }
  if ($Value -is [bool]) { return [bool]$Value }

  $s = ([string]$Value).Trim()
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }

  switch -Regex ($s.ToLowerInvariant()) {
    '^(true|1|yes|y|on|enable|enabled)$' { return $true }
    '^(false|0|no|n|off|disable|disabled)$' { return $false }
    default { return $null }
  }
}

function TryParse-Int {
  param([object]$Value)

  if ($null -eq $Value) { return $null }
  if ($Value -is [int]) { return [int]$Value }

  $s = ([string]$Value).Trim()
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }

  $out = 0
  if ([int]::TryParse($s, [ref]$out)) { return $out }
  return $null
}

function Get-DesiredSettingsFromJson {
  param([string]$Path)

  $sanitized = Sanitize-Path -Path $Path -MustExist
  if (-not $sanitized) { return $null }

  try {
    $raw = Get-BoundedUtf8FileContent -Path $sanitized -MaximumBytes 1048576
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return ($raw | ConvertFrom-Json -ErrorAction Stop)
  } catch {
    return $null
  }
}

function Resolve-DesiredSettings {
  param(
    [object]$JsonSettings,
    [hashtable]$BoundParams
  )

  # Defaults: Microsoft recommends >= 20480 KB, max is 32767 KB.
  $windowsRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
  if ([string]::IsNullOrWhiteSpace($windowsRoot) -and [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { $windowsRoot = 'C:\Windows' }
  if ([string]::IsNullOrWhiteSpace($windowsRoot)) { throw 'Trusted Windows directory is unavailable.' }
  $defaultLogFileName = "{0}\System32\LogFiles\Firewall\pfirewall.log" -f $windowsRoot.TrimEnd('\')
  $enableDropped = $true
  $enableAllowed = $false
  $logFileName   = $defaultLogFileName
  $logMaxSizeKB  = 20480
  $source        = 'Defaults'

  if ($JsonSettings) {
    $jDropped = TryParse-Bool $JsonSettings.EnableDropped
    $jAllowed = TryParse-Bool $JsonSettings.EnableAllowed
    $jPath    = $null
    $jMax     = $null

    if ($JsonSettings.PSObject.Properties.Name -contains 'LogFileName') { $jPath = [string]$JsonSettings.LogFileName }
    if ($JsonSettings.PSObject.Properties.Name -contains 'LogMaxSizeKB') { $jMax = TryParse-Int $JsonSettings.LogMaxSizeKB }

    if ($null -ne $jDropped) { $enableDropped = $jDropped }
    if ($null -ne $jAllowed) { $enableAllowed = $jAllowed }
    if (-not [string]::IsNullOrWhiteSpace($jPath)) { $logFileName = $jPath }
    if ($null -ne $jMax) { $logMaxSizeKB = $jMax }

    $source = 'JSON'
  }

  # Parameter overrides only if user actually provided them
  if ($BoundParams.ContainsKey('EnableDropped')) {
    $p = TryParse-Bool $BoundParams['EnableDropped']
    if ($null -eq $p) { Add-Finding -FindingList $script:Findings -Code 'FW-InvalidParamEnableDropped' -Severity 'Medium' -Message 'EnableDropped could not be parsed; using JSON/defaults.' -TimeUtc }
    else { $enableDropped = $p; $source = 'Params' }
  }

  if ($BoundParams.ContainsKey('EnableAllowed')) {
    $p = TryParse-Bool $BoundParams['EnableAllowed']
    if ($null -eq $p) { Add-Finding -FindingList $script:Findings -Code 'FW-InvalidParamEnableAllowed' -Severity 'Medium' -Message 'EnableAllowed could not be parsed; using JSON/defaults.' -TimeUtc }
    else { $enableAllowed = $p; $source = 'Params' }
  }

  if ($BoundParams.ContainsKey('LogFileName') -and -not [string]::IsNullOrWhiteSpace($BoundParams['LogFileName'])) {
    $logFileName = [string]$BoundParams['LogFileName']
    $source = 'Params'
  }

  if ($BoundParams.ContainsKey('LogMaxSizeKB')) {
    $p = TryParse-Int $BoundParams['LogMaxSizeKB']
    if ($null -eq $p) { Add-Finding -FindingList $script:Findings -Code 'FW-InvalidParamLogMaxSizeKB' -Severity 'Medium' -Message 'LogMaxSizeKB could not be parsed; using JSON/defaults.' -TimeUtc }
    else { $logMaxSizeKB = $p; $source = 'Params' }
  }

  # Set-NetFirewallProfile max log size: 1..32767 KB.
  if ($logMaxSizeKB -lt 1 -or $logMaxSizeKB -gt 32767) {
    Add-Finding -FindingList $script:Findings -Code 'FW-InvalidDesiredLogMaxSize' -Severity 'Medium' -Message ("Desired LogMaxSizeKB '" + $logMaxSizeKB + "' is outside 1..32767; using default 20480.") -TimeUtc
    $logMaxSizeKB = 20480
    if ($source -eq 'Params') { $source = 'Params(DefaultFallback)' } else { $source = 'JSON/Defaults' }
  }

  if ([string]::IsNullOrWhiteSpace($logFileName)) {
    Add-Finding -FindingList $script:Findings -Code 'FW-InvalidDesiredLogFileName' -Severity 'Medium' -Message 'Desired LogFileName is empty; using default firewall log path.' -TimeUtc
    $logFileName = $defaultLogFileName
    if ($source -eq 'Params') { $source = 'Params(DefaultFallback)' } else { $source = 'JSON/Defaults' }
  }

  return [pscustomobject]@{
    EnableDropped = $enableDropped
    EnableAllowed = $enableAllowed
    LogFileName   = $logFileName
    LogMaxSizeKB  = $logMaxSizeKB
    Source        = $source
  }
}

function Get-ProfileSnapshot {
  Get-NetFirewallProfile |
    Select-Object Name, Enabled, LogFileName, LogMaxSizeKilobytes, LogAllowed, LogBlocked
}

function Set-ProfileLoggingIfNeeded {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][string]$ProfileName,
    [Parameter(Mandatory)][string]$DesiredLogFileName,
    [Parameter(Mandatory)][int]$DesiredMaxKB,
    [Parameter(Mandatory)][bool]$DesiredLogBlocked,
    [Parameter(Mandatory)][bool]$DesiredLogAllowed
  )

  $current = Get-NetFirewallProfile -Name $ProfileName

  if ($current.LogFileName -ne $DesiredLogFileName) {
    if ($PSCmdlet.ShouldProcess($ProfileName, "Set firewall log file to $DesiredLogFileName")) {
      Set-NetFirewallProfile -Name $ProfileName -LogFileName $DesiredLogFileName
    }
  }
  if ([int]$current.LogMaxSizeKilobytes -ne $DesiredMaxKB) {
    if ($PSCmdlet.ShouldProcess($ProfileName, "Set firewall log max size to $DesiredMaxKB KB")) {
      Set-NetFirewallProfile -Name $ProfileName -LogMaxSizeKilobytes $DesiredMaxKB
    }
  }
  if ([bool]$current.LogBlocked -ne $DesiredLogBlocked) {
    if ($PSCmdlet.ShouldProcess($ProfileName, "Set firewall blocked logging to $DesiredLogBlocked")) {
      Set-NetFirewallProfile -Name $ProfileName -LogBlocked $DesiredLogBlocked
    }
  }
  if ([bool]$current.LogAllowed -ne $DesiredLogAllowed) {
    if ($PSCmdlet.ShouldProcess($ProfileName, "Set firewall allowed logging to $DesiredLogAllowed")) {
      Set-NetFirewallProfile -Name $ProfileName -LogAllowed $DesiredLogAllowed
    }
  }
}

function Get-SeverityCounts {
  param([System.Collections.IEnumerable]$Findings)

  $items = @($Findings)
  $grp = $items | Group-Object Severity
  $get = {
    param($name)
    $v = ($grp | Where-Object Name -eq $name | Select-Object -First 1 -ExpandProperty Count -ErrorAction SilentlyContinue)
    if ($null -eq $v) { 0 } else { [int]$v }
  }

  [pscustomobject]@{
    High   = & $get 'High'
    Medium = & $get 'Medium'
    Low    = & $get 'Low'
    Total  = $items.Count
  }
}

function Write-PrettySummary {
  param([Parameter(Mandatory)][pscustomobject]$Result)

  $s  = $Result.Summary
  $d  = $Result.Desired
  $fc = Get-SeverityCounts -Findings $Result.Findings

  $colorOk    = 'Green'
  $colorWarn  = 'Yellow'
  $colorBad   = 'Red'
  $colorInfo  = 'Cyan'
  $colorMuted = 'DarkGray'

  $statusText  = 'OK'
  $statusColor = $colorOk
  if ($fc.Medium -gt 0 -or $fc.Low -gt 0) { $statusText = 'WARN'; $statusColor = $colorWarn }
  if ($fc.High -gt 0) { $statusText = 'FAIL'; $statusColor = $colorBad }

  Write-UiLine ""
  Write-UiLine "==================== Firewall Logging Audit ====================" -ForegroundColor $colorMuted
  Write-UiLine ("Status       : {0}" -f $statusText) -ForegroundColor $statusColor
  Write-UiLine ("ComputerName : {0}" -f $s.ComputerName) -ForegroundColor $colorInfo
  Write-UiLine ("Mode         : {0}" -f $s.Mode) -ForegroundColor $colorInfo
  Write-UiLine ("Timestamp    : {0}" -f $s.Timestamp) -ForegroundColor $colorMuted
  Write-UiLine "---------------------------------------------------------------" -ForegroundColor $colorMuted

  Write-UiLine "Desired settings" -ForegroundColor $colorInfo
  Write-UiLine ("  Source        : {0}" -f $d.Source)
  Write-UiLine ("  LogFileName    : {0}" -f $d.LogFileName)
  Write-UiLine ("  LogMaxSizeKB   : {0}" -f $d.LogMaxSizeKB)
  Write-UiLine ("  EnableDropped  : {0}" -f $d.EnableDropped)
  Write-UiLine ("  EnableAllowed  : {0}" -f $d.EnableAllowed)

  Write-UiLine "---------------------------------------------------------------" -ForegroundColor $colorMuted

  Write-UiLine "Findings" -ForegroundColor $colorInfo
  Write-UiLine ("  High   : {0}" -f $fc.High) -ForegroundColor ($(if ($fc.High -gt 0) { $colorBad } else { $colorOk }))
  Write-UiLine ("  Medium : {0}" -f $fc.Medium) -ForegroundColor ($(if ($fc.Medium -gt 0) { $colorWarn } else { $colorOk }))
  Write-UiLine ("  Low    : {0}" -f $fc.Low) -ForegroundColor $colorMuted
  Write-UiLine ("  Total  : {0}" -f $fc.Total) -ForegroundColor $colorMuted

  if ($fc.Total -gt 0) {
    Write-UiLine "---------------------------------------------------------------" -ForegroundColor $colorMuted
    Write-UiLine "Top findings (up to 10)" -ForegroundColor $colorInfo

    $top = @($Result.Findings) |
      Sort-Object @{ Expression = { switch ($_.Severity) { 'High' {0} 'Medium' {1} 'Low' {2} default {3} } }; Ascending = $true }, TimeUtc |
      Select-Object -First 10

    foreach ($f in $top) {
      $c = $colorMuted
      if ($f.Severity -eq 'High') { $c = $colorBad }
      elseif ($f.Severity -eq 'Medium') { $c = $colorWarn }
      Write-UiLine ("  [{0}] {1} ({2}) - {3}" -f $f.Severity, $f.Code, $f.Profile, $f.Message) -ForegroundColor $c
    }
  }

  Write-UiLine "===============================================================" -ForegroundColor $colorMuted
  Write-UiLine ""
}

# endregion Helpers

# region Preconditions

Require-Admin

Ensure-Cmdlet -Name 'Get-NetFirewallProfile'
Ensure-Cmdlet -Name 'Set-NetFirewallProfile'

# endregion Preconditions

# region Execution

$script:Findings = Get-FindingsList

$jsonSettings = Get-DesiredSettingsFromJson -Path $SettingsJsonPath
if (-not $jsonSettings) {
  if (-not [string]::IsNullOrWhiteSpace($SettingsJsonPath)) {
    Add-Finding -FindingList $script:Findings -Code 'FW-JsonNotLoaded' -Severity 'Low' -Message ("Settings JSON not loaded or invalid: '" + $SettingsJsonPath + "'. Using parameters/defaults.") -TimeUtc
  }
}

$desired = Resolve-DesiredSettings -JsonSettings $jsonSettings -BoundParams $PSBoundParameters

$before = Get-ProfileSnapshot

foreach ($p in $before) {

  if ($p.Enabled -ne $true) {
    Add-Finding -FindingList $script:Findings -Code 'FW-ProfileDisabled' -Severity 'High' -Message ("Firewall profile '" + $p.Name + "' is disabled (Enabled=False).") -Extra @{ Profile = $p.Name } -TimeUtc
  }

  if ([string]::IsNullOrWhiteSpace($p.LogFileName)) {
    Add-Finding -FindingList $script:Findings -Code 'FW-LogPathEmpty' -Severity 'Medium' -Message ("Firewall profile '" + $p.Name + "' has an empty LogFileName.") -Extra @{ Profile = $p.Name } -TimeUtc
  }

  # Recommendation: change logging size to at least 20480 KB.
  if ([int]$p.LogMaxSizeKilobytes -lt 20480) {
    Add-Finding -FindingList $script:Findings -Code 'FW-LogSizeTooSmall' -Severity 'Medium' -Message ("Firewall profile '" + $p.Name + "' has LogMaxSizeKilobytes=" + $p.LogMaxSizeKilobytes + "KB (recommended >= 20480KB).") -Extra @{ Profile = $p.Name; Size = $p.LogMaxSizeKilobytes } -TimeUtc
  }

  if ($p.LogFileName -and ($p.LogFileName -ne $desired.LogFileName)) {
    Add-Finding -FindingList $script:Findings -Code 'FW-LogPathMismatch' -Severity 'Low' -Message ("Firewall profile '" + $p.Name + "' LogFileName='" + $p.LogFileName + "', desired='" + $desired.LogFileName + "'.") -Extra @{ Profile = $p.Name; Current = $p.LogFileName; Desired = $desired.LogFileName } -TimeUtc
  }

  if ([bool]$p.LogBlocked -ne [bool]$desired.EnableDropped) {
    Add-Finding -FindingList $script:Findings -Code 'FW-LogBlockedMismatch' -Severity 'Low' -Message ("Firewall profile '" + $p.Name + "' LogBlocked=" + $p.LogBlocked + ", desired=" + $desired.EnableDropped + ".") -Extra @{ Profile = $p.Name; Current = $p.LogBlocked; Desired = $desired.EnableDropped } -TimeUtc
  }

  if ([bool]$p.LogAllowed -ne [bool]$desired.EnableAllowed) {
    Add-Finding -FindingList $script:Findings -Code 'FW-LogAllowedMismatch' -Severity 'Low' -Message ("Firewall profile '" + $p.Name + "' LogAllowed=" + $p.LogAllowed + ", desired=" + $desired.EnableAllowed + ".") -Extra @{ Profile = $p.Name; Current = $p.LogAllowed; Desired = $desired.EnableAllowed } -TimeUtc
  }
}

if ($Mode -eq 'Remediate') {

  $logDir = Split-Path -Path $desired.LogFileName -Parent
  if ($logDir -and -not (Test-Path -LiteralPath $logDir)) {
    if ($PSCmdlet.ShouldProcess($logDir, 'Create firewall log directory')) {
      [void](Ensure-Directory -Path $logDir)
    }
  }

  if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Configure Windows Firewall logging (per profile)')) {
    foreach ($profileName in @('Domain','Private','Public')) {
      Set-ProfileLoggingIfNeeded -ProfileName $profileName `
        -DesiredLogFileName $desired.LogFileName `
        -DesiredMaxKB ([int]$desired.LogMaxSizeKB) `
        -DesiredLogBlocked ([bool]$desired.EnableDropped) `
        -DesiredLogAllowed ([bool]$desired.EnableAllowed)
    }
  }
}

$after = Get-ProfileSnapshot

$result = [pscustomobject]@{
  Summary        = [pscustomobject]@{
    ComputerName  = $env:COMPUTERNAME
    Mode          = $Mode
    FindingsCount = $script:Findings.Count
    Timestamp     = Get-Date
  }
  Desired        = $desired
  Findings       = @($script:Findings)
  ProfilesBefore = $before
  ProfilesAfter  = $after
}

if ($ExportPath) {
  $folder = Split-Path -Path $ExportPath -Parent
  if (-not $folder) { $folder = (Get-Location).Path }
  if (-not (Test-Path -LiteralPath $folder)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null }

  $base = [IO.Path]::GetFileNameWithoutExtension($ExportPath)

  $result.Summary        | Export-Csv -Path (Join-Path $folder ($base + "_summary.csv"))  -NoTypeInformation -Encoding UTF8
  $result.Desired        | Export-Csv -Path (Join-Path $folder ($base + "_desired.csv"))  -NoTypeInformation -Encoding UTF8
  $result.Findings       | Export-Csv -Path (Join-Path $folder ($base + "_findings.csv")) -NoTypeInformation -Encoding UTF8
  $result.ProfilesBefore | Export-Csv -Path (Join-Path $folder ($base + "_before.csv"))   -NoTypeInformation -Encoding UTF8
  $result.ProfilesAfter  | Export-Csv -Path (Join-Path $folder ($base + "_after.csv"))    -NoTypeInformation -Encoding UTF8
}

if (-not $NoConsoleSummary) {
  Write-PrettySummary -Result $result
}

$highCount = 0
if ($FailOnHigh) {
  $highCount = (@($result.Findings) | Where-Object Severity -eq 'High' | Measure-Object).Count
  if ($highCount -gt 0) {
    Add-Finding -FindingList $script:Findings -Code 'FW-FailOnHigh' -Severity 'High' `
      -Message ("FailOnHigh: {0} High severity finding(s) detected." -f $highCount) -TimeUtc
    $result.Summary.FindingsCount = $script:Findings.Count
  }
}

# V2 output contract
$resultToken = if (($Strict -and $script:Findings.Count -gt 0) -or ($FailOnHigh -and $highCount -gt 0)) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = Get-V2ResultObject -ScriptName '32-Firewall-Logging-Audit.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $result.Summary -Metadata @{ Desired = $result.Desired; ProfilesBefore = $result.ProfilesBefore; ProfilesAfter = $result.ProfilesAfter }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }

# endregion Execution
exit (Get-V2ExitCode -Result $resultToken)
