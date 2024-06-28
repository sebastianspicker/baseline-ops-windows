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
- Console output: human-readable "pretty" summary via Write-Host (information stream in PS 5.1). [web:148]

.PARAMETER Mode
AuditOnly | Remediate

.PARAMETER SettingsJsonPath
Optional JSON path (example: PATH/TO/JSON/firewall-logging.json).
Expected keys (all optional): EnableDropped, EnableAllowed, LogFileName, LogMaxSizeKB

.PARAMETER EnableDropped
Override desired dropped logging. Values: true/false/1/0/yes/no/on/off.

.PARAMETER EnableAllowed
Override desired allowed logging. Values: true/false/1/0/yes/no/on/off.

.PARAMETER LogFileName
Override desired firewall log file path.

.PARAMETER LogMaxSizeKB
Override desired log max size KB (1..32767). [web:21]

.PARAMETER ExportPath
Optional base path for CSV exports (writes _summary/_desired/_before/_after/_findings).

.PARAMETER FailOnHigh
If set, throws at the end when High findings exist.

.PARAMETER NoConsoleSummary
If set, do not print the console summary.

.OUTPUTS
One PSCustomObject with:
Summary, Desired, Findings, ProfilesBefore, ProfilesAfter.
.EXAMPLE
  .\32-Firewall-Logging-Audit.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateSet('AuditOnly','Remediate')]
  [string]$Mode = 'AuditOnly',

  [string]$SettingsJsonPath = 'PATH/TO/JSON/firewall-logging.json',

  [object]$EnableDropped,
  [object]$EnableAllowed,

  [string]$LogFileName,
  [object]$LogMaxSizeKB,

  [string]$ExportPath,

  [switch]$FailOnHigh,

  [switch]$NoConsoleSummary
)

$script:LibPath = Join-Path $PSScriptRoot 'lib'
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force


Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

# region Helpers


function Ensure-Cmdlet {
  param([Parameter(Mandatory)][string]$Name)
  if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
    throw "Required cmdlet missing: $Name (check NetSecurity module / OS support)."
  }
}

$script:FindingsTimeUtc = $true


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

  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  if (-not (Test-Path -LiteralPath $Path)) { return $null }

  try {
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
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

  # Defaults: Microsoft recommends >= 20480 KB, max is 32767 KB. [web:6]
  $enableDropped = $true
  $enableAllowed = $false
  $logFileName   = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
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
    if ($null -eq $p) { Add-Finding -Code 'FW-InvalidParamEnableDropped' -Severity 'Medium' -ProfileName '' -Message 'EnableDropped could not be parsed; using JSON/defaults.' }
    else { $enableDropped = $p; $source = 'Params' }
  }

  if ($BoundParams.ContainsKey('EnableAllowed')) {
    $p = TryParse-Bool $BoundParams['EnableAllowed']
    if ($null -eq $p) { Add-Finding -Code 'FW-InvalidParamEnableAllowed' -Severity 'Medium' -ProfileName '' -Message 'EnableAllowed could not be parsed; using JSON/defaults.' }
    else { $enableAllowed = $p; $source = 'Params' }
  }

  if ($BoundParams.ContainsKey('LogFileName') -and -not [string]::IsNullOrWhiteSpace($BoundParams['LogFileName'])) {
    $logFileName = [string]$BoundParams['LogFileName']
    $source = 'Params'
  }

  if ($BoundParams.ContainsKey('LogMaxSizeKB')) {
    $p = TryParse-Int $BoundParams['LogMaxSizeKB']
    if ($null -eq $p) { Add-Finding -Code 'FW-InvalidParamLogMaxSizeKB' -Severity 'Medium' -ProfileName '' -Message 'LogMaxSizeKB could not be parsed; using JSON/defaults.' }
    else { $logMaxSizeKB = $p; $source = 'Params' }
  }

  # Set-NetFirewallProfile max log size: 1..32767 KB. [web:21]
  if ($logMaxSizeKB -lt 1 -or $logMaxSizeKB -gt 32767) {
    Add-Finding -Code 'FW-InvalidDesiredLogMaxSize' -Severity 'Medium' -ProfileName '' -Message ("Desired LogMaxSizeKB '" + $logMaxSizeKB + "' is outside 1..32767; using default 20480.")
    $logMaxSizeKB = 20480
    if ($source -eq 'Params') { $source = 'Params(DefaultFallback)' } else { $source = 'JSON/Defaults' }
  }

  if ([string]::IsNullOrWhiteSpace($logFileName)) {
    Add-Finding -Code 'FW-InvalidDesiredLogFileName' -Severity 'Medium' -ProfileName '' -Message 'Desired LogFileName is empty; using default firewall log path.'
    $logFileName = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
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
  param(
    [Parameter(Mandatory)][string]$ProfileName,
    [Parameter(Mandatory)][string]$DesiredLogFileName,
    [Parameter(Mandatory)][int]$DesiredMaxKB,
    [Parameter(Mandatory)][bool]$DesiredLogBlocked,
    [Parameter(Mandatory)][bool]$DesiredLogAllowed
  )

  $current = Get-NetFirewallProfile -Name $ProfileName

  if ($current.LogFileName -ne $DesiredLogFileName) {
    Set-NetFirewallProfile -Name $ProfileName -LogFileName $DesiredLogFileName
  }
  if ([int]$current.LogMaxSizeKilobytes -ne $DesiredMaxKB) {
    Set-NetFirewallProfile -Name $ProfileName -LogMaxSizeKilobytes $DesiredMaxKB
  }
  if ([bool]$current.LogBlocked -ne $DesiredLogBlocked) {
    Set-NetFirewallProfile -Name $ProfileName -LogBlocked $DesiredLogBlocked
  }
  if ([bool]$current.LogAllowed -ne $DesiredLogAllowed) {
    Set-NetFirewallProfile -Name $ProfileName -LogAllowed $DesiredLogAllowed
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

  Write-Host ""
  Write-Host "==================== Firewall Logging Audit ====================" -ForegroundColor $colorMuted
  Write-Host ("Status       : {0}" -f $statusText) -ForegroundColor $statusColor
  Write-Host ("ComputerName : {0}" -f $s.ComputerName) -ForegroundColor $colorInfo
  Write-Host ("Mode         : {0}" -f $s.Mode) -ForegroundColor $colorInfo
  Write-Host ("Timestamp    : {0}" -f $s.Timestamp) -ForegroundColor $colorMuted
  Write-Host "---------------------------------------------------------------" -ForegroundColor $colorMuted

  Write-Host "Desired settings" -ForegroundColor $colorInfo
  Write-Host ("  Source        : {0}" -f $d.Source)
  Write-Host ("  LogFileName    : {0}" -f $d.LogFileName)
  Write-Host ("  LogMaxSizeKB   : {0}" -f $d.LogMaxSizeKB)
  Write-Host ("  EnableDropped  : {0}" -f $d.EnableDropped)
  Write-Host ("  EnableAllowed  : {0}" -f $d.EnableAllowed)

  Write-Host "---------------------------------------------------------------" -ForegroundColor $colorMuted

  Write-Host "Findings" -ForegroundColor $colorInfo
  Write-Host ("  High   : {0}" -f $fc.High) -ForegroundColor ($(if ($fc.High -gt 0) { $colorBad } else { $colorOk }))
  Write-Host ("  Medium : {0}" -f $fc.Medium) -ForegroundColor ($(if ($fc.Medium -gt 0) { $colorWarn } else { $colorOk }))
  Write-Host ("  Low    : {0}" -f $fc.Low) -ForegroundColor $colorMuted
  Write-Host ("  Total  : {0}" -f $fc.Total) -ForegroundColor $colorMuted

  if ($fc.Total -gt 0) {
    Write-Host "---------------------------------------------------------------" -ForegroundColor $colorMuted
    Write-Host "Top findings (up to 10)" -ForegroundColor $colorInfo

    $top = @($Result.Findings) |
      Sort-Object @{ Expression = { switch ($_.Severity) { 'High' {0} 'Medium' {1} 'Low' {2} default {3} } }; Ascending = $true }, TimeUtc |
      Select-Object -First 10

    foreach ($f in $top) {
      $c = $colorMuted
      if ($f.Severity -eq 'High') { $c = $colorBad }
      elseif ($f.Severity -eq 'Medium') { $c = $colorWarn }
      Write-Host ("  [{0}] {1} ({2}) - {3}" -f $f.Severity, $f.Code, $f.Profile, $f.Message) -ForegroundColor $c
    }
  }

  Write-Host "===============================================================" -ForegroundColor $colorMuted
  Write-Host ""
}

# endregion Helpers

# region Preconditions

if (-not (Test-IsAdmin)) { throw "Administrative privileges are required." }

Ensure-Cmdlet -Name 'Get-NetFirewallProfile'
Ensure-Cmdlet -Name 'Set-NetFirewallProfile'

# endregion Preconditions

# region Execution

$script:Findings = New-FindingsList

$jsonSettings = Get-DesiredSettingsFromJson -Path $SettingsJsonPath
if (-not $jsonSettings) {
  if (-not [string]::IsNullOrWhiteSpace($SettingsJsonPath) -and $SettingsJsonPath -ne 'PATH/TO/JSON/firewall-logging.json') {
    Add-Finding -Code 'FW-JsonNotLoaded' -Severity 'Low' -ProfileName '' -Message ("Settings JSON not loaded or invalid: '" + $SettingsJsonPath + "'. Using parameters/defaults.")
  }
}

$desired = Resolve-DesiredSettings -JsonSettings $jsonSettings -BoundParams $PSBoundParameters

$before = Get-ProfileSnapshot

foreach ($p in $before) {

  if ($p.Enabled -ne $true) {
    Add-Finding -Code 'FW-ProfileDisabled' -Severity 'High' -ProfileName $p.Name -Message ("Firewall profile '" + $p.Name + "' is disabled (Enabled=False).")
  }

  if ([string]::IsNullOrWhiteSpace($p.LogFileName)) {
    Add-Finding -Code 'FW-LogPathEmpty' -Severity 'Medium' -ProfileName $p.Name -Message ("Firewall profile '" + $p.Name + "' has an empty LogFileName.")
  }

  # Recommendation: change logging size to at least 20480 KB. [web:6]
  if ([int]$p.LogMaxSizeKilobytes -lt 20480) {
    Add-Finding -Code 'FW-LogSizeTooSmall' -Severity 'Medium' -ProfileName $p.Name -Message ("Firewall profile '" + $p.Name + "' has LogMaxSizeKilobytes=" + $p.LogMaxSizeKilobytes + "KB (recommended >= 20480KB).")
  }

  if ($p.LogFileName -and ($p.LogFileName -ne $desired.LogFileName)) {
    Add-Finding -Code 'FW-LogPathMismatch' -Severity 'Low' -ProfileName $p.Name -Message ("Firewall profile '" + $p.Name + "' LogFileName='" + $p.LogFileName + "', desired='" + $desired.LogFileName + "'.")
  }

  if ([bool]$p.LogBlocked -ne [bool]$desired.EnableDropped) {
    Add-Finding -Code 'FW-LogBlockedMismatch' -Severity 'Low' -ProfileName $p.Name -Message ("Firewall profile '" + $p.Name + "' LogBlocked=" + $p.LogBlocked + ", desired=" + $desired.EnableDropped + ".")
  }

  if ([bool]$p.LogAllowed -ne [bool]$desired.EnableAllowed) {
    Add-Finding -Code 'FW-LogAllowedMismatch' -Severity 'Low' -ProfileName $p.Name -Message ("Firewall profile '" + $p.Name + "' LogAllowed=" + $p.LogAllowed + ", desired=" + $desired.EnableAllowed + ".")
  }
}

if ($Mode -eq 'Remediate') {

  $logDir = Split-Path -Path $desired.LogFileName -Parent
  if ($logDir -and -not (Test-Path -LiteralPath $logDir)) {
    if ($PSCmdlet.ShouldProcess($logDir, 'Create firewall log directory')) {
      Ensure-Directory -Path $logDir
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

if ($FailOnHigh) {
  $highCount = (@($result.Findings) | Where-Object Severity -eq 'High' | Measure-Object).Count
  if ($highCount -gt 0) { throw "FailOnHigh: High severity findings detected." }
}

# Pipeline output: structured object only
# $result

# endregion Execution
