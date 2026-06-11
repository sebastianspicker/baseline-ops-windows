#Requires -RunAsAdministrator
#requires -version 5.1
<#
.SYNOPSIS
Audit + optional remediation for "Added LSA protection" (RunAsPPL / LSA PPL).

.DESCRIPTION
Registry:
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL (REG_DWORD)
  1 = Enabled with UEFI lock
  2 = Enabled without UEFI lock (enforced on Windows 11 22H2+)
  0 = Disabled (or delete the value)

Reboot required. Verification uses Wininit Event ID 12.

ASCII-only content for Windows PowerShell 5.1 stability.
Recommended file encoding: UTF-8 with BOM or UTF-16LE.

.CONFIGURATION
Optional JSON config:
  ... Config PATH/TO/JSON

Example JSON:
{
  "Mode": "Audit",
  "TargetRunAsPPL": 1,
  "ManageRunAsPPLBoot": false,
  "DisableMethod": "SetZero",
  "Verify": false,
  "VerifyLookbackHours": 24,
  "CollectCodeIntegrity": false,
  "CILookbackHours": 24,
  "ExportPath": "PATH/TO/JSON",
  "Quiet": false
}

.USAGE (positional args)
  .\40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1
  .\40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1 Remediate 2 Boot Verify 168 CI 168 SetZero Export PATH/TO/JSON
  .\40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1 Audit 1 x x 24 x 24 SetZero x x Config PATH/TO/JSON Quiet

ARGS (positional)
  0: Mode                 Audit | Remediate
  1: TargetRunAsPPL       0 | 1 | 2
  2: Boot                 literal "Boot" to also set RunAsPPLBoot
  3: Verify               literal "Verify"
  4: VerifyLookbackHours  integer (default 24)
  5: CI                   literal "CI"
  6: CILookbackHours      integer (default 24)
  7: DisableMethod        SetZero | DeleteValue (default SetZero; only relevant if TargetRunAsPPL=0)
  8: Export               literal "Export"
  9: ExportPath           PATH/TO/JSON
 10: Config               literal "Config"
 11: ConfigPath           PATH/TO/JSON
 12: Quiet                literal "Quiet"

.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

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
  None by default.
  When -PassThru is used, emits a PSCustomObject v2 result with Script, Mode, Result, Findings, Summary, and Metadata properties.

.EXAMPLE
  .\40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1

#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateSet('Audit','Remediate')]
  [string]$Mode = 'Audit',
  [string]$ConfigPath,
  [ValidateSet('Console','Json','Csv','None')]
  [string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor,
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$LegacyArgs
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
Initialize-V2Context -ScriptName '40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1' -BoundParameters $PSBoundParameters
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
  $result = Get-V2ResultObject -ScriptName '40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

# ----------------------------
# Console helpers (no pipeline output)
# ----------------------------

function Write-Badge {
  param(
    [Parameter(Mandatory)][string]$Label,
    [Parameter(Mandatory)][string]$Value,
    [ConsoleColor]$Color = [ConsoleColor]::Gray
  )

  Write-UiLine ("{0,-20}: {1}" -f $Label, $Value) -ForegroundColor $Color
}


# ----------------------------
# Common helpers
# ----------------------------

function Format-Nullable {
  param([AllowNull()][object]$Value)
  if ($null -eq $Value) { return '<null>' }
  return [string]$Value
}

function To-Bool {
  param([AllowNull()][object]$Value, [bool]$Default = $false)
  if ($null -eq $Value) { return $Default }
  try { return [bool]$Value } catch { return $Default }
}

function To-Int {
  param([AllowNull()][object]$Value, [int]$Default)
  if ($null -eq $Value) { return $Default }
  try { return [int]$Value } catch { return $Default }
}

function To-StringOrNull {
  param([AllowNull()][object]$Value)
  if ($null -eq $Value) { return $null }
  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  return $s
}

# ----------------------------
# Registry helpers
# ----------------------------


# ----------------------------
# Event log helpers
# ----------------------------
function Get-LsaProtectionWinInitEvent {
  param([Parameter(Mandatory)][int]$LookbackHours)

  $start = (Get-Date).AddHours(-1 * $LookbackHours)
  try {
    $filter = @{
      LogName      = 'System'
      ProviderName = 'Microsoft-Windows-Wininit'
      Id           = [int[]]@(12)
      StartTime    = $start
    }

    $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop |
      Sort-Object TimeCreated -Descending

    $match = $events |
      Where-Object { $_.Message -match 'LSASS\.exe was started as a protected process with level:\s*4' } |
      Select-Object -First 1

    if ($match) {
      return [pscustomobject]@{
        Found         = $true
        TimeCreated   = $match.TimeCreated
        EventRecordId = $match.RecordId
        Message       = $match.Message
        Error         = $null
      }
    }

    return [pscustomobject]@{
      Found         = $false
      TimeCreated   = $null
      EventRecordId = $null
      Message       = $null
      Error         = $null
    }
  } catch {
    return [pscustomobject]@{
      Found         = $false
      TimeCreated   = $null
      EventRecordId = $null
      Message       = $null
      Error         = $_.Exception.Message
    }
  }
}

function Get-CodeIntegrityLsaEvents {
  param([Parameter(Mandatory)][int]$LookbackHours)

  $start = (Get-Date).AddHours(-1 * $LookbackHours)
  $log   = 'Microsoft-Windows-CodeIntegrity/Operational'
  $ids   = [int[]]@(3033, 3063, 3065, 3066)

  try {
    $filter = @{
      LogName   = $log
      Id        = $ids
      StartTime = $start
    }

    $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop |
      Sort-Object TimeCreated -Descending

    $lsassEvents = $events | Where-Object { $_.Message -match '(?i)lsass\.exe' }

    $items = foreach ($e in $lsassEvents) {
      [pscustomobject]@{
        TimeCreated   = $e.TimeCreated
        Id            = $e.Id
        ProviderName  = $e.ProviderName
        EventRecordId = $e.RecordId
        Message       = $e.Message
      }
    }

    return [pscustomobject]@{
      LogName     = $log
      LookbackHrs = $LookbackHours
      Count       = @($items).Count
      Items       = @($items)
      Error       = $null
    }
  } catch {
    return [pscustomobject]@{
      LogName     = $log
      LookbackHrs = $LookbackHours
      Count       = 0
      Items       = @()
      Error       = $_.Exception.Message
    }
  }
}

# ----------------------------
# Config (defaults + JSON overlay)
# ----------------------------
function Get-DefaultConfig {
  return @{
    Mode                 = 'Audit'
    TargetRunAsPPL       = 1
    ManageRunAsPPLBoot   = $false
    DisableMethod        = 'SetZero'
    Verify               = $false
    VerifyLookbackHours  = 24
    CollectCodeIntegrity = $false
    CILookbackHours      = 24
    ExportPath           = $null
    Quiet                = $false
  }
}

function Get-TokenValue {
  param(
    [AllowNull()][object[]]$ArgsList,
    [Parameter(Mandatory)][string]$Token
  )
  if ($null -eq $ArgsList -or $ArgsList.Count -eq 0) { return $null }

  for ($i = 0; $i -lt $ArgsList.Count; $i++) {
    if ([string]$ArgsList[$i] -ieq $Token) {
      if ($i + 1 -lt $ArgsList.Count) { return [string]$ArgsList[$i + 1] }
    }
  }
  return $null
}

function Has-Token {
  param(
    [AllowNull()][object[]]$ArgsList,
    [Parameter(Mandatory)][string]$Token
  )
  if ($null -eq $ArgsList -or $ArgsList.Count -eq 0) { return $false }

  foreach ($a in $ArgsList) {
    if ([string]$a -ieq $Token) { return $true }
  }
  return $false
}


function Apply-ArgsOverlay {
  param(
    [Parameter(Mandatory)][hashtable]$Config,
    [AllowNull()][object[]]$ArgsList
  )

  if ($null -eq $ArgsList -or $ArgsList.Count -eq 0) { return $Config }

  if ($ArgsList.Count -ge 1 -and $ArgsList[0]) {
    if ([string]$ArgsList[0] -notin @('Audit', 'Remediate')) {
      throw "Invalid Mode '$([string]$ArgsList[0])'. Must be 'Audit' or 'Remediate'."
    }
    Write-Warning "LegacyArgs overriding parameter 'Mode' to value '$([string]$ArgsList[0])'"
    $Config['Mode'] = [string]$ArgsList[0]
  }
  if ($ArgsList.Count -ge 2 -and $ArgsList[1]) {
    try {
      $parsedTarget = [int]$ArgsList[1]
    } catch {
      throw "Invalid TargetRunAsPPL '$($ArgsList[1])'. Must be an integer (0, 1, or 2)."
    }
    Write-Warning "LegacyArgs overriding parameter 'TargetRunAsPPL' to value '$parsedTarget'"
    $Config['TargetRunAsPPL'] = $parsedTarget
  }

  if ($ArgsList.Count -ge 3 -and $ArgsList[2]) { if ([string]$ArgsList[2] -ieq 'Boot') {
    Write-Warning "LegacyArgs overriding parameter 'ManageRunAsPPLBoot' to value 'True'"
    $Config['ManageRunAsPPLBoot'] = $true
  } }
  if ($ArgsList.Count -ge 4 -and $ArgsList[3]) { if ([string]$ArgsList[3] -ieq 'Verify') {
    Write-Warning "LegacyArgs overriding parameter 'Verify' to value 'True'"
    $Config['Verify'] = $true
  } }
  if ($ArgsList.Count -ge 5 -and $ArgsList[4]) {
    Write-Warning "LegacyArgs overriding parameter 'VerifyLookbackHours' to value '$([int]$ArgsList[4])'"
    $Config['VerifyLookbackHours'] = [int]$ArgsList[4]
  }
  if ($ArgsList.Count -ge 6 -and $ArgsList[5]) { if ([string]$ArgsList[5] -ieq 'CI') {
    Write-Warning "LegacyArgs overriding parameter 'CollectCodeIntegrity' to value 'True'"
    $Config['CollectCodeIntegrity'] = $true
  } }
  if ($ArgsList.Count -ge 7 -and $ArgsList[6]) {
    Write-Warning "LegacyArgs overriding parameter 'CILookbackHours' to value '$([int]$ArgsList[6])'"
    $Config['CILookbackHours'] = [int]$ArgsList[6]
  }
  if ($ArgsList.Count -ge 8 -and $ArgsList[7]) {
    Write-Warning "LegacyArgs overriding parameter 'DisableMethod' to value '$([string]$ArgsList[7])'"
    $Config['DisableMethod'] = [string]$ArgsList[7]
  }

  if ($ArgsList.Count -ge 10 -and $ArgsList[8] -and $ArgsList[9]) {
    if ([string]$ArgsList[8] -ieq 'Export') {
      Write-Warning "LegacyArgs overriding parameter 'ExportPath' to value '$([string]$ArgsList[9])'"
      $Config['ExportPath'] = [string]$ArgsList[9]
    }
  }

  if (Has-Token -ArgsList $ArgsList -Token 'Quiet') {
    Write-Warning "LegacyArgs overriding parameter 'Quiet' to value 'True'"
    $Config['Quiet'] = $true
  }
  return $Config
}

function Normalize-ConfigTypes {
  param([Parameter(Mandatory)][hashtable]$Config)

  $Config['Mode'] = [string]$Config['Mode']
  $Config['TargetRunAsPPL'] = To-Int -Value $Config['TargetRunAsPPL'] -Default 1
  $Config['ManageRunAsPPLBoot'] = To-Bool -Value $Config['ManageRunAsPPLBoot'] -Default $false
  $Config['DisableMethod'] = [string]$Config['DisableMethod']
  $Config['Verify'] = To-Bool -Value $Config['Verify'] -Default $false
  $Config['VerifyLookbackHours'] = To-Int -Value $Config['VerifyLookbackHours'] -Default 24
  $Config['CollectCodeIntegrity'] = To-Bool -Value $Config['CollectCodeIntegrity'] -Default $false
  $Config['CILookbackHours'] = To-Int -Value $Config['CILookbackHours'] -Default 24
  $Config['ExportPath'] = To-StringOrNull -Value $Config['ExportPath']
  $Config['Quiet'] = To-Bool -Value $Config['Quiet'] -Default $false
  return $Config
}

function Validate-Config {
  param([Parameter(Mandatory)][hashtable]$Config)

  if ($Config['Mode'] -eq 'AuditOnly') { $Config['Mode'] = 'Audit' }
  if ($Config['Mode'] -notin @('Audit','Remediate')) { throw "Mode must be Audit or Remediate. Got: $($Config['Mode'])" }
  if ($Config['TargetRunAsPPL'] -notin @(0,1,2)) { throw "TargetRunAsPPL must be 0, 1, or 2. Got: $($Config['TargetRunAsPPL'])" }
  if ($Config['VerifyLookbackHours'] -lt 1 -or $Config['VerifyLookbackHours'] -gt 168) { throw "VerifyLookbackHours must be 1..168. Got: $($Config['VerifyLookbackHours'])" }
  if ($Config['CILookbackHours'] -lt 1 -or $Config['CILookbackHours'] -gt 168) { throw "CILookbackHours must be 1..168. Got: $($Config['CILookbackHours'])" }
  if ($Config['DisableMethod'] -notin @('SetZero','DeleteValue')) { throw "DisableMethod must be SetZero or DeleteValue. Got: $($Config['DisableMethod'])" }
}

# ----------------------------
# Export
# ----------------------------
function Export-ResultJson {
  param(
    [Parameter(Mandatory)][object]$Result,
    [Parameter(Mandatory)][string]$Path
  )

  $dir = Split-Path -Path $Path -Parent
  if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }

  $json = $Result | ConvertTo-Json -Depth 8
  Set-Content -Path $Path -Value $json -Encoding UTF8
}

# ----------------------------
# Pretty console output (no pipeline output)
# ----------------------------
function Write-PrettySummary {
  param([Parameter(Mandatory)][object]$Result)

  $s = $Result.Summary

  $overallText = 'OK'
  $overallColor = [ConsoleColor]::Green
  if ($s.FindingsCount -gt 0) { $overallText = 'ATTENTION'; $overallColor = [ConsoleColor]::Yellow }
  if ($s.RebootRequired) { $overallText = 'REBOOT REQUIRED'; $overallColor = [ConsoleColor]::Yellow }

  $findingsColor = [ConsoleColor]::Green
  if ($s.FindingsCount -gt 0) { $findingsColor = [ConsoleColor]::Yellow }

  $rebootColor = [ConsoleColor]::Green
  if ($s.RebootRequired) { $rebootColor = [ConsoleColor]::Yellow }

  Write-Section -Title 'LSA PPL (RunAsPPL)'
  Write-Badge -Label 'Overall'            -Value $overallText -Color $overallColor
  Write-Badge -Label 'ComputerName'       -Value $s.ComputerName -Color Gray
  Write-Badge -Label 'Mode'               -Value $s.Mode -Color Gray
  Write-Badge -Label 'TargetRunAsPPL'     -Value ([string]$s.TargetRunAsPPL) -Color Cyan
  Write-Badge -Label 'RunAsPPL (before)'  -Value (Format-Nullable $Result.Current.RunAsPPL) -Color Gray
  Write-Badge -Label 'RunAsPPL (after)'   -Value (Format-Nullable $Result.After.RunAsPPL) -Color Gray

  if ($s.ManageRunAsPPLBoot) {
    Write-Badge -Label 'RunAsPPLBoot (before)' -Value (Format-Nullable $Result.Current.RunAsPPLBoot) -Color Gray
    Write-Badge -Label 'RunAsPPLBoot (after)'  -Value (Format-Nullable $Result.After.RunAsPPLBoot) -Color Gray
  }

  Write-Badge -Label 'DisableMethod'      -Value $s.DisableMethod -Color DarkGray
  Write-Badge -Label 'FindingsCount'      -Value ([string]$s.FindingsCount) -Color $findingsColor
  Write-Badge -Label 'RebootRequired'     -Value ([string]$s.RebootRequired) -Color $rebootColor
  Write-Badge -Label 'Timestamp'          -Value ([string]$s.Timestamp) -Color DarkGray

  if ($s.Changes -and $s.Changes.Count -gt 0) {
    Write-Section -Title 'Changes'
    foreach ($c in $s.Changes) { Write-UiLine ("  + {0}" -f $c) -ForegroundColor Cyan }
  }

  if ($Result.Findings -and $Result.Findings.Count -gt 0) {
    Write-Section -Title 'Findings'
    foreach ($f in $Result.Findings) {
      $c = [ConsoleColor]::Yellow
      if ([string]$f.Severity -ieq 'High') { $c = [ConsoleColor]::Red }
      elseif ([string]$f.Severity -ieq 'Low') { $c = [ConsoleColor]::Gray }
      Write-UiLine ("  ! [{0}] {1} - {2}" -f $f.Severity, $f.Code, $f.Message) -ForegroundColor $c
    }
  }

  if ($null -ne $Result.Verification) {
    Write-Section -Title 'Verify (Wininit Event 12)'
    if ($Result.Verification.Found) {
      Write-UiLine "  OK Wininit event found indicating PPL level 4." -ForegroundColor Green
      Write-UiLine ("  TimeCreated   : {0}" -f $Result.Verification.TimeCreated) -ForegroundColor DarkGray
      Write-UiLine ("  EventRecordId : {0}" -f $Result.Verification.EventRecordId) -ForegroundColor DarkGray
    } else {
      Write-UiLine "  WARN No matching Wininit event found in lookback window." -ForegroundColor Yellow
      if ($Result.Verification.Error) { Write-UiLine ("  Error: {0}" -f $Result.Verification.Error) -ForegroundColor Yellow }
    }
  }

  if ($null -ne $Result.CodeIntegrity) {
    Write-Section -Title 'CodeIntegrity (Operational)'
    if ($Result.CodeIntegrity.Error) {
      Write-UiLine ("  WARN Unable to read log: {0}" -f $Result.CodeIntegrity.Error) -ForegroundColor Yellow
    } else {
      Write-UiLine ("  Events (lsass.exe) in last {0}h: {1}" -f $Result.CodeIntegrity.LookbackHrs, $Result.CodeIntegrity.Count) -ForegroundColor Gray
    }
  }
}

# ----------------------------
# MAIN
# ----------------------------
Require-Admin

$configPath = if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) { $ConfigPath } else { Get-TokenValue -ArgsList $LegacyArgs -Token 'Config' }
$cfgResult = Read-ConfigWithDefaults -Path $configPath -Defaults (Get-DefaultConfig) -AsHashtable -OnWarning { param($m) Write-Warn $m }
$config = $cfgResult.Config
$config = Apply-ArgsOverlay -Config $config -ArgsList $LegacyArgs
$config['Mode'] = if ($Mode -eq 'Remediate') { 'Remediate' } else { 'Audit' }
if ($PSBoundParameters.ContainsKey('Quiet')) { $config['Quiet'] = [bool]$Quiet }
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) { $config['ExportPath'] = $OutputPath }
$config = Normalize-ConfigTypes -Config $config
Validate-Config -Config $config

$Mode = $config['Mode']
$TargetRunAsPPL = $config['TargetRunAsPPL']
$ManageBoot = $config['ManageRunAsPPLBoot']
$DisableMethod = $config['DisableMethod']
$DoVerify = $config['Verify']
$VerifyLookbackHours = $config['VerifyLookbackHours']
$CollectCI = $config['CollectCodeIntegrity']
$CILookbackHours = $config['CILookbackHours']
$ExportPath = $config['ExportPath']
$Quiet = $config['Quiet']

$Findings = Get-FindingsList
$Changes  = New-Object 'System.Collections.Generic.List[string]'
$rebootRequired = $false
$registryWriteFailed = $false

if ($cfgResult.Meta.Error) {
  [void](Add-Finding -FindingList $Findings -Code 'LSA-ConfigLoadFailed' -Severity 'Medium' `
    -Message ("Config JSON could not be loaded; using parameters/defaults. Error: {0}" -f $cfgResult.Meta.Error))
}

function Add-LsaRegistryWriteFailureFinding {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][int]$Value
  )

  $null = Add-Finding -FindingList $Findings -Code 'LSA-RegWriteFailed' -Severity 'High' `
    -Message ("Failed to write LSA protection registry value '{0}' at '{1}'. Hardening not applied." -f $Name, $Path) `
    -Extra @{ Path = $Path; Name = $Name; Value = $Value }
}

$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

$current = [pscustomobject]@{
  RunAsPPL     = Get-RegValue -Path $lsaPath -Name 'RunAsPPL'
  RunAsPPLBoot = Get-RegValue -Path $lsaPath -Name 'RunAsPPLBoot'
}

if ($null -eq $current.RunAsPPL) {
  Add-Finding -FindingList $Findings -Code 'LSA-PPL-Missing' -Severity 'High' -Message 'RunAsPPL is not set (effectively disabled).'
} elseif ($current.RunAsPPL -eq 0) {
  Add-Finding -FindingList $Findings -Code 'LSA-PPL-Off' -Severity 'High' -Message 'RunAsPPL is 0 (Added LSA protection disabled).'
} elseif ($current.RunAsPPL -notin @(1,2)) {
  Add-Finding -FindingList $Findings -Code 'LSA-PPL-Invalid' -Severity 'Medium' -Message ("RunAsPPL has unexpected value: {0}" -f $current.RunAsPPL)
}

if ($Mode -eq 'Remediate') {

  if ($TargetRunAsPPL -eq 0) {

    if ($DisableMethod -ieq 'DeleteValue') {
      if ($null -ne $current.RunAsPPL) {
        if ($PSCmdlet.ShouldProcess("$lsaPath\RunAsPPL", "Remove registry value")) {
          if (Remove-RegValueIfExists -Path $lsaPath -Name 'RunAsPPL') {
            $rebootRequired = $true
            $Changes.Add(("RunAsPPL: {0} -> <deleted>" -f (Format-Nullable $current.RunAsPPL))) | Out-Null
          }
        }
      }
    } else {
      if ($current.RunAsPPL -ne 0) {
        if ($PSCmdlet.ShouldProcess("$lsaPath\RunAsPPL", "Set registry value to 0")) {
          if (Set-RegDword -Path $lsaPath -Name 'RunAsPPL' -Value 0) {
            $rebootRequired = $true
            $Changes.Add(("RunAsPPL: {0} -> 0" -f (Format-Nullable $current.RunAsPPL))) | Out-Null
          } else {
            Add-LsaRegistryWriteFailureFinding -Path $lsaPath -Name 'RunAsPPL' -Value 0
            $registryWriteFailed = $true
          }
        }
      }
    }

    if ($ManageBoot) {
      if ($current.RunAsPPLBoot -ne 0) {
        if ($PSCmdlet.ShouldProcess("$lsaPath\RunAsPPLBoot", "Set registry value to 0")) {
          if (Set-RegDword -Path $lsaPath -Name 'RunAsPPLBoot' -Value 0) {
            $rebootRequired = $true
            $Changes.Add(("RunAsPPLBoot: {0} -> 0" -f (Format-Nullable $current.RunAsPPLBoot))) | Out-Null
          } else {
            Add-LsaRegistryWriteFailureFinding -Path $lsaPath -Name 'RunAsPPLBoot' -Value 0
            $registryWriteFailed = $true
          }
        }
      }
    }

  } else {

    if ($current.RunAsPPL -ne $TargetRunAsPPL) {
      if ($PSCmdlet.ShouldProcess("$lsaPath\RunAsPPL", "Set registry value to $TargetRunAsPPL")) {
        if (Set-RegDword -Path $lsaPath -Name 'RunAsPPL' -Value $TargetRunAsPPL) {
          $rebootRequired = $true
          $Changes.Add(("RunAsPPL: {0} -> {1}" -f (Format-Nullable $current.RunAsPPL), $TargetRunAsPPL)) | Out-Null
        } else {
          Add-LsaRegistryWriteFailureFinding -Path $lsaPath -Name 'RunAsPPL' -Value $TargetRunAsPPL
          $registryWriteFailed = $true
        }
      }
    }

    if ($ManageBoot) {
      if ($current.RunAsPPLBoot -ne $TargetRunAsPPL) {
        if ($PSCmdlet.ShouldProcess("$lsaPath\RunAsPPLBoot", "Set registry value to $TargetRunAsPPL")) {
          if (Set-RegDword -Path $lsaPath -Name 'RunAsPPLBoot' -Value $TargetRunAsPPL) {
            $rebootRequired = $true
            $Changes.Add(("RunAsPPLBoot: {0} -> {1}" -f (Format-Nullable $current.RunAsPPLBoot), $TargetRunAsPPL)) | Out-Null
          } else {
            Add-LsaRegistryWriteFailureFinding -Path $lsaPath -Name 'RunAsPPLBoot' -Value $TargetRunAsPPL
            $registryWriteFailed = $true
          }
        }
      }
    }

  }
}

$after = [pscustomobject]@{
  RunAsPPL     = Get-RegValue -Path $lsaPath -Name 'RunAsPPL'
  RunAsPPLBoot = Get-RegValue -Path $lsaPath -Name 'RunAsPPLBoot'
}

$verification = $null
if ($DoVerify) { $verification = Get-LsaProtectionWinInitEvent -LookbackHours $VerifyLookbackHours }

$codeIntegrity = $null
if ($CollectCI) { $codeIntegrity = Get-CodeIntegrityLsaEvents -LookbackHours $CILookbackHours }

$result = [pscustomobject]@{
  Summary = [pscustomobject]@{
    ComputerName        = $env:COMPUTERNAME
    Mode                = $Mode
    TargetRunAsPPL      = $TargetRunAsPPL
    ManageRunAsPPLBoot  = $ManageBoot
    DisableMethod       = $DisableMethod
    RebootRequired      = $rebootRequired
    RegistryWriteFailed = $registryWriteFailed
    FindingsCount       = [int]$Findings.Count
    Changes             = @($Changes.ToArray())
    Timestamp           = (Get-Date)
    ConfigPathUsed      = if ($configPath) { 'PATH/TO/JSON' } else { $null }
    ExportPathUsed      = if ($ExportPath) { 'PATH/TO/JSON' } else { $null }
    VerifyLookbackHours = $VerifyLookbackHours
    CILookbackHours     = $CILookbackHours
  }
  Current       = $current
  After         = $after
  Findings      = @($Findings.ToArray())
  Verification  = $verification
  CodeIntegrity = $codeIntegrity
}

if ($ExportPath) {
  Export-ResultJson -Result $result -Path $ExportPath
}

if ($OutputFormat -eq 'Console' -and -not $Quiet) { Write-PrettySummary -Result $result }

# V2 output contract
$resultToken = if ($registryWriteFailed) { 'FAIL' } elseif ($Strict -and $Findings.Count -gt 0) { 'FAIL' } elseif ($Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = Get-V2ResultObject -ScriptName '40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $Findings.ToArray()) -Summary $result.Summary -Metadata @{ Current = $result.Current; After = $result.After }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
