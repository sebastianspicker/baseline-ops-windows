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
  ... Config $ConfigPath

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
  "ExportPath": "[configured path]",
  "Quiet": false
}

.USAGE (positional args)
  .\40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1
  .\40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1 Remediate 2 Boot Verify 168 CI 168 SetZero Export $ExportPath
  .\40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1 Audit 1 x x 24 x 24 SetZero x x Config $ConfigPath Quiet

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
  9: ExportPath           $ExportPath
 10: Config               literal "Config"
 11: ConfigPath           $ConfigPath
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
function Initialize-Capability40Runtime {
  param($EntryBoundParameters)
  $RunState = @{

  }
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'internal/40-AddedLSAProtection-RunAsPPL-AuditRemediate.helpers.ps1')
$script:__V2Context = Initialize-V2Context -ScriptName '40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1' -BoundParameters $EntryBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$RunState.isWindowsHost = ($env:OS -eq 'Windows_NT')
  $script:RunState = $RunState
}

. Initialize-Capability40Runtime -EntryBoundParameters $PSBoundParameters
if (-not $RunState.isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# ----------------------------
# Console helpers (no pipeline output)
# ----------------------------

# ----------------------------
# Common helpers
# ----------------------------







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

  if ((Test-AnyCondition -Conditions @({ $null -eq $ArgsList }, { $ArgsList.Count -eq 0 }))) { return $Config }

  Set-LsaLegacyModeAndTarget -Config $Config -ArgsList $ArgsList
  Set-LsaLegacySwitches -Config $Config -ArgsList $ArgsList
  Set-LsaLegacyValues -Config $Config -ArgsList $ArgsList
  Set-LsaLegacyExport -Config $Config -ArgsList $ArgsList
  if (Has-Token -ArgsList $ArgsList -Token 'Quiet') {
    Write-Warning "LegacyArgs overriding parameter 'Quiet' to value 'True'"
    $Config['Quiet'] = $true
  }
  return $Config
}
function Set-LsaLegacyModeAndTarget {
  param($Config, $ArgsList)
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
}
function Set-LsaLegacySwitches {
  param($Config, $ArgsList)
  Set-LsaLegacyNamedSwitch -Config $Config -ArgsList $ArgsList -Index 2 -Token 'Boot' -Name 'ManageRunAsPPLBoot'
  Set-LsaLegacyNamedSwitch -Config $Config -ArgsList $ArgsList -Index 3 -Token 'Verify' -Name 'Verify'
  Set-LsaLegacyNamedSwitch -Config $Config -ArgsList $ArgsList -Index 5 -Token 'CI' -Name 'CollectCodeIntegrity'
}
function Set-LsaLegacyNamedSwitch {
  param($Config, $ArgsList, [int]$Index, [string]$Token, [string]$Name)
  if ($ArgsList.Count -le $Index) { return }
  if (-not $ArgsList[$Index]) { return }
  if ([string]$ArgsList[$Index] -ine $Token) { return }
  Write-Warning "LegacyArgs overriding parameter '$Name' to value 'True'"
  $Config[$Name] = $true
}
function Set-LsaLegacyValues {
  param($Config, $ArgsList)
  if ($ArgsList.Count -ge 5 -and $ArgsList[4]) {
    Write-Warning "LegacyArgs overriding parameter 'VerifyLookbackHours' to value '$([int]$ArgsList[4])'"
    $Config['VerifyLookbackHours'] = [int]$ArgsList[4]
  }
  if ($ArgsList.Count -ge 7 -and $ArgsList[6]) {
    Write-Warning "LegacyArgs overriding parameter 'CILookbackHours' to value '$([int]$ArgsList[6])'"
    $Config['CILookbackHours'] = [int]$ArgsList[6]
  }
  if ($ArgsList.Count -ge 8 -and $ArgsList[7]) {
    Write-Warning "LegacyArgs overriding parameter 'DisableMethod' to value '$([string]$ArgsList[7])'"
    $Config['DisableMethod'] = [string]$ArgsList[7]
  }
}
function Set-LsaLegacyExport {
  param($Config, $ArgsList)
  if ($ArgsList.Count -ge 10 -and $ArgsList[8] -and $ArgsList[9]) {
    if ([string]$ArgsList[8] -ieq 'Export') {
      Write-Warning "LegacyArgs overriding parameter 'ExportPath' to value '$([string]$ArgsList[9])'"
      $Config['ExportPath'] = [string]$ArgsList[9]
    }
  }
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

function Validate-ConfigSection01 {
  param([hashtable]$RunState)
if ($RunState.Config['Mode'] -eq 'AuditOnly') { $RunState.Config['Mode'] = 'Audit' }
  if ($RunState.Config['Mode'] -notin @('Audit','Remediate')) { throw "Mode must be Audit or Remediate. Got: $($RunState.Config['Mode'])" }
  if ($RunState.Config['TargetRunAsPPL'] -notin @(0,1,2)) { throw "TargetRunAsPPL must be 0, 1, or 2. Got: $($RunState.Config['TargetRunAsPPL'])" }
  if ($RunState.Config['VerifyLookbackHours'] -lt 1 -or $RunState.Config['VerifyLookbackHours'] -gt 168) { throw "VerifyLookbackHours must be 1..168. Got: $($RunState.Config['VerifyLookbackHours'])" }
}

function Validate-ConfigSection02 {
  param([hashtable]$RunState)
if ($RunState.Config['CILookbackHours'] -lt 1 -or $RunState.Config['CILookbackHours'] -gt 168) { throw "CILookbackHours must be 1..168. Got: $($RunState.Config['CILookbackHours'])" }
  if ($RunState.Config['DisableMethod'] -notin @('SetZero','DeleteValue')) { throw "DisableMethod must be SetZero or DeleteValue. Got: $($RunState.Config['DisableMethod'])" }
}

function Validate-Config {
  param([Parameter(Mandatory)][hashtable]$Config, [hashtable]$RunState)
  $RunState.Config = $Config

    . Validate-ConfigSection01 -RunState $RunState
    . Validate-ConfigSection02 -RunState $RunState
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
# Formatted console output (no pipeline output)
# ----------------------------
# ----------------------------
# MAIN
# ----------------------------
function Initialize-LsaProtectionConfiguration {
  param($EntryBoundParameters, [hashtable]$RunState)
Require-Admin

$configPath = if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) { $ConfigPath } else { Get-TokenValue -ArgsList $LegacyArgs -Token 'Config' }
$cfgResult = Read-ConfigWithDefaults -Path $configPath -Defaults (Get-DefaultConfig) -AsHashtable -OnWarning { param($m) Write-Warn $m }
$RunState.config = $cfgResult.Config
$RunState.config = Apply-ArgsOverlay -Config $RunState.config -ArgsList $LegacyArgs
$RunState.config['Mode'] = if ($Mode -eq 'Remediate') { 'Remediate' } else { 'Audit' }
if ($EntryBoundParameters.ContainsKey('Quiet')) { $RunState.config['Quiet'] = [bool]$Quiet }
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) { $RunState.config['ExportPath'] = $OutputPath }
$RunState.config = Normalize-ConfigTypes -Config $RunState.config
Validate-Config -Config $RunState.config -RunState $RunState

$Mode = $RunState.config['Mode']
$RunState.TargetRunAsPPL = $RunState.config['TargetRunAsPPL']
$RunState.ManageBoot = $RunState.config['ManageRunAsPPLBoot']
$RunState.DisableMethod = $RunState.config['DisableMethod']
$RunState.DoVerify = $RunState.config['Verify']
$RunState.VerifyLookbackHours = $RunState.config['VerifyLookbackHours']
$RunState.CollectCI = $RunState.config['CollectCodeIntegrity']
$RunState.CILookbackHours = $RunState.config['CILookbackHours']
$RunState.ExportPath = $RunState.config['ExportPath']
$Quiet = $RunState.config['Quiet']

$Findings = Get-FindingsList
$RunState.Changes  = New-Object 'System.Collections.Generic.List[string]'
$RunState.rebootRequired = $false
$RunState.registryWriteFailed = $false

if ($cfgResult.Meta.Error) {
  [void](Add-Finding -FindingList $Findings -Code 'LSA-ConfigLoadFailed' -Severity 'Medium' `
    -Message ("Config JSON could not be loaded; using parameters/defaults. Error: {0}" -f $cfgResult.Meta.Error))
}
}
. Initialize-LsaProtectionConfiguration -EntryBoundParameters $PSBoundParameters -RunState $RunState

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

function Invoke-Capability40MainPhase01 {
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
}
function Invoke-Capability40MainPhase02Step01 {
  param([hashtable]$RunState)
if ($RunState.DisableMethod -ieq 'DeleteValue') {
        . Remove-LsaRunAsPplValue -RunState $RunState
      } else {
        . Disable-LsaRunAsPplValue -RunState $RunState
      }
}
function Remove-LsaRunAsPplValue {
  param([hashtable]$RunState)
  if ($null -eq $current.RunAsPPL) { return }
  if (-not $script:__EntryCmdlet.ShouldProcess("$lsaPath\RunAsPPL", 'Remove registry value')) { return }
  if (Remove-RegValueIfExists -Path $lsaPath -Name 'RunAsPPL') {
    $RunState.rebootRequired = $true
    $RunState.Changes.Add(("RunAsPPL: {0} -> <deleted>" -f (Format-Nullable $current.RunAsPPL))) | Out-Null
  }
}
function Disable-LsaRunAsPplValue {
  param([hashtable]$RunState)
  if ($current.RunAsPPL -eq 0) { return }
  if (-not $script:__EntryCmdlet.ShouldProcess("$lsaPath\RunAsPPL", 'Set registry value to 0')) { return }
  if (Set-RegDword -Path $lsaPath -Name 'RunAsPPL' -Value 0) {
    $RunState.rebootRequired = $true
    $RunState.Changes.Add(("RunAsPPL: {0} -> 0" -f (Format-Nullable $current.RunAsPPL))) | Out-Null
  } else {
    Add-LsaRegistryWriteFailureFinding -Path $lsaPath -Name 'RunAsPPL' -Value 0
    $RunState.registryWriteFailed = $true
  }
}

function Invoke-Capability40MainPhase02Step02 {
  param([hashtable]$RunState)
if ($RunState.ManageBoot) {
        if ($current.RunAsPPLBoot -ne 0) {
          if ($script:__EntryCmdlet.ShouldProcess("$lsaPath\RunAsPPLBoot", "Set registry value to 0")) {
            if (Set-RegDword -Path $lsaPath -Name 'RunAsPPLBoot' -Value 0) {
              $RunState.rebootRequired = $true
              $RunState.Changes.Add(("RunAsPPLBoot: {0} -> 0" -f (Format-Nullable $current.RunAsPPLBoot))) | Out-Null
            } else {
              Add-LsaRegistryWriteFailureFinding -Path $lsaPath -Name 'RunAsPPLBoot' -Value 0
              $RunState.registryWriteFailed = $true
            }
          }
        }
      }
}

function Invoke-Capability40MainPhase02Stage01 {
  param([hashtable]$RunState)
if ($current.RunAsPPL -ne $RunState.TargetRunAsPPL) {
        if ($script:__EntryCmdlet.ShouldProcess("$lsaPath\RunAsPPL", "Set registry value to $($RunState.TargetRunAsPPL)")) {
          if (Set-RegDword -Path $lsaPath -Name 'RunAsPPL' -Value $RunState.TargetRunAsPPL) {
            $RunState.rebootRequired = $true
            $RunState.Changes.Add(("RunAsPPL: {0} -> {1}" -f (Format-Nullable $current.RunAsPPL), $RunState.TargetRunAsPPL)) | Out-Null
          } else {
            Add-LsaRegistryWriteFailureFinding -Path $lsaPath -Name 'RunAsPPL' -Value $RunState.TargetRunAsPPL
            $RunState.registryWriteFailed = $true
          }
        }
      }
}

function Invoke-Capability40MainPhase02Stage02 {
  param([hashtable]$RunState)
if ($RunState.ManageBoot) {
        if ($current.RunAsPPLBoot -ne $RunState.TargetRunAsPPL) {
          if ($script:__EntryCmdlet.ShouldProcess("$lsaPath\RunAsPPLBoot", "Set registry value to $($RunState.TargetRunAsPPL)")) {
            if (Set-RegDword -Path $lsaPath -Name 'RunAsPPLBoot' -Value $RunState.TargetRunAsPPL) {
              $RunState.rebootRequired = $true
              $RunState.Changes.Add(("RunAsPPLBoot: {0} -> {1}" -f (Format-Nullable $current.RunAsPPLBoot), $RunState.TargetRunAsPPL)) | Out-Null
            } else {
              Add-LsaRegistryWriteFailureFinding -Path $lsaPath -Name 'RunAsPPLBoot' -Value $RunState.TargetRunAsPPL
              $RunState.registryWriteFailed = $true
            }
          }
        }
      }
}

function Invoke-Capability40MainPhase02 {
  param([hashtable]$RunState)
  if ($Mode -eq 'Remediate') {

    if ($RunState.TargetRunAsPPL -eq 0) {

      . Invoke-Capability40MainPhase02Step01 -RunState $RunState
. Invoke-Capability40MainPhase02Step02 -RunState $RunState

    } else {

      . Invoke-Capability40MainPhase02Stage01 -RunState $RunState
. Invoke-Capability40MainPhase02Stage02 -RunState $RunState

    }
  }
}
function Invoke-Capability40MainPhase03 {
  param([hashtable]$RunState)
  $after = [pscustomobject]@{
    RunAsPPL     = Get-RegValue -Path $lsaPath -Name 'RunAsPPL'
    RunAsPPLBoot = Get-RegValue -Path $lsaPath -Name 'RunAsPPLBoot'
  }

  $verification = $null
  if ($RunState.DoVerify) { $verification = Get-LsaProtectionWinInitEvent -LookbackHours $RunState.VerifyLookbackHours }

  $codeIntegrity = $null
  if ($RunState.CollectCI) { $codeIntegrity = Get-CodeIntegrityLsaEvents -LookbackHours $RunState.CILookbackHours }

  $result = [pscustomobject]@{
    Summary = [pscustomobject]@{
      ComputerName        = $env:COMPUTERNAME
      Mode                = $Mode
      TargetRunAsPPL      = $RunState.TargetRunAsPPL
      ManageRunAsPPLBoot  = $RunState.ManageBoot
      DisableMethod       = $RunState.DisableMethod
      RebootRequired      = $RunState.rebootRequired
      RegistryWriteFailed = $RunState.registryWriteFailed
      FindingsCount       = [int]$Findings.Count
      Changes             = @($RunState.Changes.ToArray())
      Timestamp           = (Get-Date)
      ConfigPathUsed      = if ($configPath) { '[configured path]' } else { $null }
      ExportPathUsed      = if ($RunState.ExportPath) { '[configured path]' } else { $null }
      VerifyLookbackHours = $RunState.VerifyLookbackHours
      CILookbackHours     = $RunState.CILookbackHours
    }
    Current       = $current
    After         = $after
    Findings      = @($Findings.ToArray())
    Verification  = $verification
    CodeIntegrity = $codeIntegrity
  }

  if ($RunState.ExportPath) {
    Export-ResultJson -Result $result -Path $RunState.ExportPath
  }
}
function Invoke-Capability40MainPhase04 {
  param([hashtable]$RunState)
  if ($OutputFormat -eq 'Console' -and -not $Quiet) { Write-PrettySummary -Result $RunState.result -RunState $RunState }
}
function Invoke-Capability40Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation, [hashtable]$RunState)
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability40MainPhase01
  . Invoke-Capability40MainPhase02 -RunState $RunState
  . Invoke-Capability40MainPhase03 -RunState $RunState
  . Invoke-Capability40MainPhase04 -RunState $RunState
}
. Invoke-Capability40Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation -RunState $RunState

# V2 output contract
function Get-Capability40ResultToken {
  param([hashtable]$RunState)
  $resultToken = if ($RunState.registryWriteFailed) { 'FAIL' } elseif ($Strict -and $Findings.Count -gt 0) { 'FAIL' } elseif ($Findings.Count -gt 0) { 'WARN' } else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability40ResultToken -RunState $RunState
$v2Result = Get-V2ResultObject -ScriptName '40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $Findings.ToArray()) -Summary $result.Summary -Metadata @{ Current = $result.Current; After = $result.After }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
