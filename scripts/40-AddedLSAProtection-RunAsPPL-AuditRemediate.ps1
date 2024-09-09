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
  "Mode": "AuditOnly",
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
  .\40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1 AuditOnly 1 x x 24 x 24 SetZero x x Config PATH/TO/JSON Quiet

ARGS (positional)
  0: Mode                 AuditOnly | Remediate
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
.EXAMPLE
  .\40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1

#>

$script:LibPath = Join-Path $PSScriptRoot 'lib'
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force


Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# ----------------------------
# Console helpers (no pipeline output)
# ----------------------------

function Write-Badge {
  param(
    [Parameter(Mandatory)][string]$Label,
    [Parameter(Mandatory)][string]$Value,
    [ConsoleColor]$Color = [ConsoleColor]::Gray
  )

  Write-Host ("{0,-20}: {1}" -f $Label, $Value) -ForegroundColor $Color
}

function Write-WarnLine {
  param([Parameter(Mandatory)][string]$Message)
  Write-Host ("[WARN] {0}" -f $Message) -ForegroundColor Yellow
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
function New-DefaultConfig {
  return @{
    Mode                 = 'AuditOnly'
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

  if ($ArgsList.Count -ge 1 -and $ArgsList[0]) { $Config['Mode'] = [string]$ArgsList[0] }
  if ($ArgsList.Count -ge 2 -and $ArgsList[1]) { $Config['TargetRunAsPPL'] = [int]$ArgsList[1] }

  if ($ArgsList.Count -ge 3 -and $ArgsList[2]) { if ([string]$ArgsList[2] -ieq 'Boot') { $Config['ManageRunAsPPLBoot'] = $true } }
  if ($ArgsList.Count -ge 4 -and $ArgsList[3]) { if ([string]$ArgsList[3] -ieq 'Verify') { $Config['Verify'] = $true } }
  if ($ArgsList.Count -ge 5 -and $ArgsList[4]) { $Config['VerifyLookbackHours'] = [int]$ArgsList[4] }
  if ($ArgsList.Count -ge 6 -and $ArgsList[5]) { if ([string]$ArgsList[5] -ieq 'CI') { $Config['CollectCodeIntegrity'] = $true } }
  if ($ArgsList.Count -ge 7 -and $ArgsList[6]) { $Config['CILookbackHours'] = [int]$ArgsList[6] }
  if ($ArgsList.Count -ge 8 -and $ArgsList[7]) { $Config['DisableMethod'] = [string]$ArgsList[7] }

  if ($ArgsList.Count -ge 10 -and $ArgsList[8] -and $ArgsList[9]) {
    if ([string]$ArgsList[8] -ieq 'Export') { $Config['ExportPath'] = [string]$ArgsList[9] }
  }

  if (Has-Token -ArgsList $ArgsList -Token 'Quiet') { $Config['Quiet'] = $true }
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

  if ($Config['Mode'] -notin @('AuditOnly','Remediate')) { throw "Mode must be AuditOnly or Remediate. Got: $($Config['Mode'])" }
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
    foreach ($c in $s.Changes) { Write-Host ("  + {0}" -f $c) -ForegroundColor Cyan }
  }

  if ($Result.Findings -and $Result.Findings.Count -gt 0) {
    Write-Section -Title 'Findings'
    foreach ($f in $Result.Findings) {
      $c = [ConsoleColor]::Yellow
      if ([string]$f.Severity -ieq 'High') { $c = [ConsoleColor]::Red }
      elseif ([string]$f.Severity -ieq 'Low') { $c = [ConsoleColor]::Gray }
      Write-Host ("  ! [{0}] {1} - {2}" -f $f.Severity, $f.Code, $f.Message) -ForegroundColor $c
    }
  }

  if ($null -ne $Result.Verification) {
    Write-Section -Title 'Verify (Wininit Event 12)'
    if ($Result.Verification.Found) {
      Write-Host "  OK Wininit event found indicating PPL level 4." -ForegroundColor Green
      Write-Host ("  TimeCreated   : {0}" -f $Result.Verification.TimeCreated) -ForegroundColor DarkGray
      Write-Host ("  EventRecordId : {0}" -f $Result.Verification.EventRecordId) -ForegroundColor DarkGray
    } else {
      Write-Host "  WARN No matching Wininit event found in lookback window." -ForegroundColor Yellow
      if ($Result.Verification.Error) { Write-Host ("  Error: {0}" -f $Result.Verification.Error) -ForegroundColor Yellow }
    }
  }

  if ($null -ne $Result.CodeIntegrity) {
    Write-Section -Title 'CodeIntegrity (Operational)'
    if ($Result.CodeIntegrity.Error) {
      Write-Host ("  WARN Unable to read log: {0}" -f $Result.CodeIntegrity.Error) -ForegroundColor Yellow
    } else {
      Write-Host ("  Events (lsass.exe) in last {0}h: {1}" -f $Result.CodeIntegrity.LookbackHrs, $Result.CodeIntegrity.Count) -ForegroundColor Gray
    }
  }
}

# ----------------------------
# MAIN
# ----------------------------
if (-not (Test-IsAdmin)) { throw 'Administrative privileges required.' }

$configPath = Get-TokenValue -ArgsList $args -Token 'Config'
$cfgResult = Read-ConfigWithDefaults -Path $configPath -Defaults (New-DefaultConfig) -AsHashtable -OnWarning { param($m) Write-WarnLine $m }
$config = $cfgResult.Config
$config = Apply-ArgsOverlay -Config $config -ArgsList $args
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

$Findings = New-Object 'System.Collections.Generic.List[object]'
$Changes  = New-Object 'System.Collections.Generic.List[string]'
$rebootRequired = $false

$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

$current = [pscustomobject]@{
  RunAsPPL     = Get-RegValue -Path $lsaPath -Name 'RunAsPPL'
  RunAsPPLBoot = Get-RegValue -Path $lsaPath -Name 'RunAsPPLBoot'
}

if ($null -eq $current.RunAsPPL) {
  $Findings.Add([pscustomobject]@{ Code='LSA-PPL-Missing'; Severity='High'; Message='RunAsPPL is not set (effectively disabled).' }) | Out-Null
} elseif ($current.RunAsPPL -eq 0) {
  $Findings.Add([pscustomobject]@{ Code='LSA-PPL-Off'; Severity='High'; Message='RunAsPPL is 0 (Added LSA protection disabled).' }) | Out-Null
} elseif ($current.RunAsPPL -notin @(1,2)) {
  $Findings.Add([pscustomobject]@{ Code='LSA-PPL-Invalid'; Severity='Medium'; Message=("RunAsPPL has unexpected value: {0}" -f $current.RunAsPPL) }) | Out-Null
}

if ($Mode -eq 'Remediate') {

  if ($TargetRunAsPPL -eq 0) {

    if ($DisableMethod -ieq 'DeleteValue') {
      if ($null -ne $current.RunAsPPL) {
        if (Remove-RegValueIfExists -Path $lsaPath -Name 'RunAsPPL') {
          $rebootRequired = $true
          $Changes.Add(("RunAsPPL: {0} -> <deleted>" -f (Format-Nullable $current.RunAsPPL))) | Out-Null
        }
      }
    } else {
      if ($current.RunAsPPL -ne 0) {
        Set-RegDword -Path $lsaPath -Name 'RunAsPPL' -Value 0
        $rebootRequired = $true
        $Changes.Add(("RunAsPPL: {0} -> 0" -f (Format-Nullable $current.RunAsPPL))) | Out-Null
      }
    }

    if ($ManageBoot) {
      if ($current.RunAsPPLBoot -ne 0) {
        Set-RegDword -Path $lsaPath -Name 'RunAsPPLBoot' -Value 0
        $rebootRequired = $true
        $Changes.Add(("RunAsPPLBoot: {0} -> 0" -f (Format-Nullable $current.RunAsPPLBoot))) | Out-Null
      }
    }

  } else {

    if ($current.RunAsPPL -ne $TargetRunAsPPL) {
      Set-RegDword -Path $lsaPath -Name 'RunAsPPL' -Value $TargetRunAsPPL
      $rebootRequired = $true
      $Changes.Add(("RunAsPPL: {0} -> {1}" -f (Format-Nullable $current.RunAsPPL), $TargetRunAsPPL)) | Out-Null
    }

    if ($ManageBoot) {
      if ($current.RunAsPPLBoot -ne $TargetRunAsPPL) {
        Set-RegDword -Path $lsaPath -Name 'RunAsPPLBoot' -Value $TargetRunAsPPL
        $rebootRequired = $true
        $Changes.Add(("RunAsPPLBoot: {0} -> {1}" -f (Format-Nullable $current.RunAsPPLBoot), $TargetRunAsPPL)) | Out-Null
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

if ($ExportPath) { Export-ResultJson -Result $result -Path $ExportPath }
if (-not $Quiet) { Write-PrettySummary -Result $result }

# $result
