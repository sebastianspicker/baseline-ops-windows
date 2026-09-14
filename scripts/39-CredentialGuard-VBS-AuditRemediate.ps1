#Requires -RunAsAdministrator
#requires -version 5.1
<#
.SYNOPSIS
Audit + optional remediation for Credential Guard / VBS via registry (client-focused).

.DESCRIPTION
Microsoft notes that deleting the registry values may not disable Credential Guard; values must be set to 0, and a reboot is required.

Best-practice output model (PowerShell 5.1):
- Pipeline: exactly one structured object (safe for Export-Csv / ConvertTo-Json / Where-Object).
- Console: formatted output uses Write-UiLine so the pipeline stays clean.

.PARAMETER Mode
Audit | Remediate

.PARAMETER ConfigPath
Optional JSON config path supplied with $ConfigPath.
If missing/empty/invalid: continues with parameter defaults (non-fatal).

Supported JSON properties:
{
  "RequirePlatformSecurityFeatures": 1,
  "LsaCfgFlags": 1,
  "ExportPath": "[configured path]",
  "ExportCsvBasePath": "[configured path]",
  "ShowSummary": true
}

.PARAMETER RequirePlatformSecurityFeatures
1 = Secure Boot, 3 = Secure Boot + DMA protection.

.PARAMETER LsaCfgFlags
0 = Disabled, 1 = Enabled with UEFI lock, 2 = Enabled without lock.

.PARAMETER ExportPath
Optional JSON export path.

.PARAMETER ExportCsvBasePath
Optional CSV export directory (summary.csv and findings.csv).

.PARAMETER ShowSummary
Write a readable console summary at the end (default: $true).


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
PSCustomObject with Summary, Current, After, Findings, Config.
.EXAMPLE
  .\39-CredentialGuard-VBS-AuditRemediate.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateSet('Audit', 'Remediate')]
  [string]$Mode = 'Audit',

  [string]$ConfigPath,

  [ValidateSet(1, 3)]
  [int]$RequirePlatformSecurityFeatures = 1,

  [ValidateSet(0, 1, 2)]
  [int]$LsaCfgFlags = 1,

  [string]$ExportPath,

  [string]$ExportCsvBasePath,

  [bool]$ShowSummary = $true

,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
function Test-AllConditions {
  param([scriptblock[]]$Conditions)
  foreach ($condition in $Conditions) {
    if (-not (. $condition)) { return $false }
  }
  return $true
}
function Test-AnyCondition {
  param([scriptblock[]]$Conditions)
  foreach ($condition in $Conditions) {
    if (. $condition) { return $true }
  }
  return $false
}
function Initialize-Capability39Runtime {
  param($EntryBoundParameters)
  $RunState = @{

  }
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '39-CredentialGuard-VBS-AuditRemediate.ps1' -BoundParameters $EntryBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$RunState.isWindowsHost = ($env:OS -eq 'Windows_NT')
  $script:RunState = $RunState
}

. Initialize-Capability39Runtime -EntryBoundParameters $PSBoundParameters
if (-not $RunState.isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $RunState.result = Get-V2ResultObject -ScriptName '39-CredentialGuard-VBS-AuditRemediate.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $RunState.result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $RunState.result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# -----------------------------
# Helpers (PS 5.1 compatible)
# -----------------------------


# Ensure-Key removed; Ensure-RegistryKey available from lib/Registry.psm1


function Apply-ConfigOverridesSection01 {
  param([hashtable]$RunState)
if ($null -ne $RunState.Config.RequirePlatformSecurityFeatures) {
    if ($RunState.Config.RequirePlatformSecurityFeatures -in 1, 3) {
      $RunState.Effective.RequirePlatformSecurityFeatures = [int]$RunState.Config.RequirePlatformSecurityFeatures
    } else {
      $RunState.Warnings.Add("Config: RequirePlatformSecurityFeatures invalid ($($RunState.Config.RequirePlatformSecurityFeatures)); keeping defaults/parameters.") | Out-Null
    }
  }

  if ($null -ne $RunState.Config.LsaCfgFlags) {
    if ($RunState.Config.LsaCfgFlags -in 0, 1, 2) {
      $RunState.Effective.LsaCfgFlags = [int]$RunState.Config.LsaCfgFlags
    } else {
      $RunState.Warnings.Add("Config: LsaCfgFlags invalid ($($RunState.Config.LsaCfgFlags)); keeping defaults/parameters.") | Out-Null
    }
  }
}

function Apply-ConfigOverridesSection02 {
  param([hashtable]$RunState)
if ($null -ne $RunState.Config.ExportPath -and -not [string]::IsNullOrWhiteSpace([string]$RunState.Config.ExportPath)) {
    $RunState.Effective.ExportPath = [string]$RunState.Config.ExportPath
  }

  if ($null -ne $RunState.Config.ExportCsvBasePath -and -not [string]::IsNullOrWhiteSpace([string]$RunState.Config.ExportCsvBasePath)) {
    $RunState.Effective.ExportCsvBasePath = [string]$RunState.Config.ExportCsvBasePath
  }
}

function Apply-ConfigOverridesSection03 {
  param([hashtable]$RunState)
if ($null -ne $RunState.Config.ShowSummary) {
    try {
      $RunState.Effective.ShowSummary = [bool]$RunState.Config.ShowSummary
    } catch {
      $RunState.Warnings.Add("Config: ShowSummary invalid ($($RunState.Config.ShowSummary)); keeping defaults/parameters.") | Out-Null
    }
  }
}

function Apply-ConfigOverrides {
  param(
    [Parameter(Mandatory)][object]$Config,
    [Parameter(Mandatory)][hashtable]$Effective,
    [Parameter(Mandatory)][System.Collections.Generic.List[string]]$Warnings
  , [hashtable]$RunState)
  $RunState.Config = $Config
  $RunState.Effective = $Effective
  $RunState.Warnings = $Warnings

    . Apply-ConfigOverridesSection01 -RunState $RunState
    . Apply-ConfigOverridesSection02 -RunState $RunState
    . Apply-ConfigOverridesSection03 -RunState $RunState
}

function Write-PrettySummarySection01 {
  param([hashtable]$RunState)
$cGood   = 'Green'
  $cWarn   = 'Yellow'
  $cBad    = 'Red'
  $cInfo   = 'Cyan'
  $cDim    = 'DarkGray'

  function Show-Kv {
    param(
      [string]$Key,
      [string]$Value,
      [string]$Color
    )
    if (-not $Color) { $Color = 'Gray' }
    Write-UiLine ("{0,-30}: " -f $Key) -NoNewline -ForegroundColor $cDim
    Write-UiLine $Value -ForegroundColor $Color
  }

  # Get-SeverityColor from lib/Console.psm1

  # Precompute colors/strings (avoid inline if-expressions in argument position in PS 5.1).
  $RunState.compliant = [bool]$RunState.Result.Summary.Compliant
  $reboot    = [bool]$RunState.Result.Summary.RebootRequired

  $compliantColor = if ($RunState.compliant) { $cGood } else { $cBad }
  $rebootColor    = if ($reboot) { $cWarn } else { $cGood }
  $modeColor      = if ($RunState.Result.Summary.Mode -eq 'Remediate') { $cWarn } else { $cInfo }

  $findingsCount = [int]$RunState.Result.Summary.FindingsCount
  $findingsColor = if ($findingsCount -gt 0) { $cWarn } else { $cGood }

  Write-Section -Title 'Credential Guard / VBS'
  Show-Kv -Key 'ComputerName' -Value ([string]$RunState.Result.Summary.ComputerName) -Color $cInfo
  Show-Kv -Key 'Mode' -Value ([string]$RunState.Result.Summary.Mode) -Color $modeColor
  Show-Kv -Key 'Compliant (registry)' -Value ([string]$RunState.compliant) -Color $compliantColor
  Show-Kv -Key 'Reboot required' -Value ([string]$reboot) -Color $rebootColor
  Show-Kv -Key 'Findings count' -Value ([string]$findingsCount) -Color $findingsColor

  Write-Section -Title 'Target (effective)'
  Show-Kv -Key 'EnableVBS' -Value '1' -Color $cInfo
  Show-Kv -Key 'RequirePlatformSecurityFeatures' -Value ([string]$RunState.Result.Summary.Target.RequirePlatformSecurityFeatures) -Color $cInfo
  Show-Kv -Key 'LsaCfgFlags' -Value ([string]$RunState.Result.Summary.Target.LsaCfgFlags) -Color $cInfo
}

function Write-PrettySummarySection02 {
  param([hashtable]$RunState)
Write-Section -Title 'State (before -> after)'
  $b = $RunState.Result.Current
  $a = $RunState.Result.After

  $enableLine = ("{0} -> {1}" -f $b.EnableVirtualizationBasedSecurity, $a.EnableVirtualizationBasedSecurity)
  $rpsfLine   = ("{0} -> {1}" -f $b.RequirePlatformSecurityFeatures,   $a.RequirePlatformSecurityFeatures)
  $lsaLine    = ("{0} -> {1}" -f $b.LsaCfgFlags,                       $a.LsaCfgFlags)

  $enableColor = if ($a.EnableVirtualizationBasedSecurity -eq 1) { $cGood } else { $cBad }
  $rpsfColor   = if ($a.RequirePlatformSecurityFeatures -in 1, 3) { $cGood } else { $cBad }
  $lsaColor    = if ($a.LsaCfgFlags -in 1, 2) { $cGood } else { $cBad }

  Show-Kv -Key 'EnableVBS' -Value $enableLine -Color $enableColor
  Show-Kv -Key 'RequirePlatformSecurityFeatures' -Value $rpsfLine -Color $rpsfColor
  Show-Kv -Key 'LsaCfgFlags' -Value $lsaLine -Color $lsaColor
}

function Write-PrettySummarySection03 {
  param([hashtable]$RunState)
if ($RunState.Result.Config -and $RunState.Result.Config.Warnings -and $RunState.Result.Config.Warnings.Count -gt 0) {
    Write-Section -Title 'Config warnings'
    foreach ($w in $RunState.Result.Config.Warnings) {
      Write-UiLine ("- {0}" -f $w) -ForegroundColor $cWarn
    }
  }
}

function Write-PrettySummarySection04 {
  param([hashtable]$RunState)
if ($RunState.Result.Summary.Changes -and $RunState.Result.Summary.Changes.Count -gt 0) {
    Write-Section -Title 'Changes'
    foreach ($c in $RunState.Result.Summary.Changes) {
      Write-UiLine ("- {0}" -f $c) -ForegroundColor $cInfo
    }
  }
}

function Write-PrettySummarySection05 {
  param([hashtable]$RunState)
if ($RunState.Result.Findings -and $RunState.Result.Findings.Count -gt 0) {
    Write-Section -Title 'Findings'
    foreach ($f in $RunState.Result.Findings) {
      $sevColor = Get-SeverityColor -Severity ([string]$f.Severity)
      Write-UiLine ("- [{0}] {1}: {2}" -f $f.Severity, $f.Code, $f.Message) -ForegroundColor $sevColor
    }
  }

  Write-UiLine ''
}

function Write-PrettySummary {
  param([Parameter(Mandatory)][object]$Result, [hashtable]$RunState)
  $RunState.Result = $Result

  # Host-only output. Do NOT use Write-Output here (keeps pipeline clean).
    . Write-PrettySummarySection01 -RunState $RunState
    . Write-PrettySummarySection02 -RunState $RunState
    . Write-PrettySummarySection03 -RunState $RunState
    . Write-PrettySummarySection04 -RunState $RunState
    . Write-PrettySummarySection05 -RunState $RunState
}

# -----------------------------
# Start
# -----------------------------

function Initialize-CredentialGuardAuditState {
  param([hashtable]$RunState)
Require-Admin
. Initialize-Capability39RunState -RunState $RunState
. Read-Capability39CurrentState -RunState $RunState
. Add-Capability39AuditFindings -RunState $RunState
}
function Initialize-Capability39RunState {
  param([hashtable]$RunState)
$Findings       = Get-FindingsList
$RunState.Changes        = New-Object System.Collections.Generic.List[string]
$ConfigWarnings = New-Object System.Collections.Generic.List[string]

# Effective settings start with parameters (sensible defaults).
$RunState.effective = @{
  RequirePlatformSecurityFeatures = $RequirePlatformSecurityFeatures
  LsaCfgFlags                     = $LsaCfgFlags
  ExportPath                      = $ExportPath
  ExportCsvBasePath               = $ExportCsvBasePath
  ShowSummary                     = $ShowSummary
}

# Optional JSON overrides (never fatal).
$cfgResult = Read-ConfigWithDefaults -Path $ConfigPath -Defaults @{} -ReturnNullWhenMissing -ReturnNullOnError
$cfg     = $cfgResult.Config
$cfgMeta = $cfgResult.Meta

if ($cfgMeta.Error) {
  $ConfigWarnings.Add("Config load failed: $($cfgMeta.Error); using parameters/defaults.") | Out-Null
  [void](Add-Finding -FindingList $Findings -Code 'CG-ConfigLoadFailed' -Severity 'Medium' `
    -Message ("Config JSON could not be loaded; using parameters/defaults. Error: {0}" -f $cfgMeta.Error))
}

if ((Test-AllConditions -Conditions @({ $cfgMeta.Loaded }, { $null -ne $cfg }))) {
  Apply-ConfigOverrides -Config $cfg -Effective $RunState.effective -Warnings $ConfigWarnings -RunState $RunState
}
$RunState.rebootRequired = $false
$RunState.registryWriteFailed = $false
}
function Read-Capability39CurrentState {
  param([hashtable]$RunState)
$dgPath  = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

$RunState.current = [pscustomobject]@{
  EnableVirtualizationBasedSecurity = Get-RegValue -Path $dgPath  -Name 'EnableVirtualizationBasedSecurity'
  RequirePlatformSecurityFeatures   = Get-RegValue -Path $dgPath  -Name 'RequirePlatformSecurityFeatures'
  LsaCfgFlags                       = Get-RegValue -Path $lsaPath -Name 'LsaCfgFlags'
}
}
function Add-Capability39AuditFindings {
  param([hashtable]$RunState)
Add-Capability39VbsFinding -RunState $RunState
Add-Capability39PlatformFinding -RunState $RunState
Add-Capability39LsaFinding -RunState $RunState
Add-Capability39UefiLockFinding -RunState $RunState
}
function Add-Capability39VbsFinding {
  param([hashtable]$RunState)
if ($null -eq $RunState.current.EnableVirtualizationBasedSecurity) {
  Add-Finding -FindingList $Findings -Code 'CG-VBS-NotConfigured' -Severity 'High' -Message 'VBS not configured (registry key absent).'
} elseif ($RunState.current.EnableVirtualizationBasedSecurity -ne 1) {
  Add-Finding -FindingList $Findings -Code 'CG-VBS-NotEnabled' -Severity 'High' -Message 'EnableVirtualizationBasedSecurity is not 1.'
}
}
function Add-Capability39PlatformFinding {
  param([hashtable]$RunState)
if ($null -eq $RunState.current.RequirePlatformSecurityFeatures) {
  Add-Finding -FindingList $Findings -Code 'CG-PlatformSecurityFeatures-NotConfigured' -Severity 'Medium' -Message 'RequirePlatformSecurityFeatures not configured (registry key absent).'
} elseif ($RunState.current.RequirePlatformSecurityFeatures -notin 1, 3) {
  Add-Finding -FindingList $Findings -Code 'CG-PlatformSecurityFeatures-Invalid' -Severity 'Medium' -Message 'RequirePlatformSecurityFeatures is not 1 or 3.'
}
}
function Add-Capability39LsaFinding {
  param([hashtable]$RunState)
if ($null -eq $RunState.current.LsaCfgFlags) {
  Add-Finding -FindingList $Findings -Code 'CG-LsaCfgFlags-NotConfigured' -Severity 'Medium' -Message 'LsaCfgFlags not configured (registry key absent).'
} elseif ($RunState.current.LsaCfgFlags -notin 0, 1, 2) {
  Add-Finding -FindingList $Findings -Code 'CG-LsaCfgFlags-Invalid' -Severity 'Medium' -Message ("LsaCfgFlags has an unexpected value: {0}" -f $RunState.current.LsaCfgFlags)
} elseif ($RunState.current.LsaCfgFlags -eq 0) {
  Add-Finding -FindingList $Findings -Code 'CG-LsaCfgFlags-Disabled' -Severity 'High' -Message 'LsaCfgFlags=0 (Credential Guard configured as disabled).'
}
}
function Add-Capability39UefiLockFinding {
  param([hashtable]$RunState)
  $currentLsaCfgFlags = $RunState.current.LsaCfgFlags
  $effectiveLsaCfgFlags = $RunState.effective.LsaCfgFlags
if ((Test-AllConditions -Conditions @({ (Test-AllConditions -Conditions @({ $currentLsaCfgFlags -eq 1 }, { $Mode -eq 'Remediate' })) }, { $effectiveLsaCfgFlags -ne 1 }))) {
  Add-Finding -FindingList $Findings -Code 'CG-UEFI-Lock-Note' -Severity 'Low' -Message 'LsaCfgFlags=1 (UEFI lock) may prevent changing/disabling it via registry.'
}
}

# -----------------------------
# Remediation (idempotent)
# -----------------------------

. Initialize-CredentialGuardAuditState -RunState $RunState

function Add-CgRegistryWriteFailureFinding {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][int]$Value
  )

  $null = Add-Finding -FindingList $Findings -Code 'CG-RegWriteFailed' -Severity 'High' `
    -Message ("Failed to write Credential Guard registry value '{0}' at '{1}'. Hardening not applied." -f $Name, $Path) `
    -Extra @{ Path = $Path; Name = $Name; Value = $Value }
}

function Invoke-Capability39MainPhase01Step01 {
  param([hashtable]$RunState)
if ($RunState.current.EnableVirtualizationBasedSecurity -ne 1) {
      $action = 'Set EnableVirtualizationBasedSecurity=1 (reboot required)'
      if ($script:__EntryCmdlet.ShouldProcess($env:COMPUTERNAME, $action)) {
        if (Set-RegDword -Path $dgPath -Name 'EnableVirtualizationBasedSecurity' -Value 1) {
          $RunState.rebootRequired = $true
          $RunState.Changes.Add(("EnableVirtualizationBasedSecurity: {0} -> 1" -f $RunState.current.EnableVirtualizationBasedSecurity)) | Out-Null
        } else {
          Add-CgRegistryWriteFailureFinding -Path $dgPath -Name 'EnableVirtualizationBasedSecurity' -Value 1
          $RunState.registryWriteFailed = $true
        }
      }
    }
}

function Invoke-Capability39MainPhase01Step02 {
  param([hashtable]$RunState)
if ($RunState.current.RequirePlatformSecurityFeatures -ne $RunState.effective.RequirePlatformSecurityFeatures) {
      $action = "Set RequirePlatformSecurityFeatures=$($RunState.effective.RequirePlatformSecurityFeatures) (reboot required)"
      if ($script:__EntryCmdlet.ShouldProcess($env:COMPUTERNAME, $action)) {
        if (Set-RegDword -Path $dgPath -Name 'RequirePlatformSecurityFeatures' -Value $RunState.effective.RequirePlatformSecurityFeatures) {
          $RunState.rebootRequired = $true
          $RunState.Changes.Add(("RequirePlatformSecurityFeatures: {0} -> {1}" -f $RunState.current.RequirePlatformSecurityFeatures, $RunState.effective.RequirePlatformSecurityFeatures)) | Out-Null
        } else {
          Add-CgRegistryWriteFailureFinding -Path $dgPath -Name 'RequirePlatformSecurityFeatures' -Value $RunState.effective.RequirePlatformSecurityFeatures
          $RunState.registryWriteFailed = $true
        }
      }
    }
}

function Invoke-Capability39MainPhase01Step03 {
  param([hashtable]$RunState)
if ($RunState.current.LsaCfgFlags -ne $RunState.effective.LsaCfgFlags) {
      $action = "Set LsaCfgFlags=$($RunState.effective.LsaCfgFlags) (reboot required)"
      if ($script:__EntryCmdlet.ShouldProcess($env:COMPUTERNAME, $action)) {
        if (Set-RegDword -Path $lsaPath -Name 'LsaCfgFlags' -Value $RunState.effective.LsaCfgFlags) {
          $RunState.rebootRequired = $true
          $RunState.Changes.Add(("LsaCfgFlags: {0} -> {1}" -f $RunState.current.LsaCfgFlags, $RunState.effective.LsaCfgFlags)) | Out-Null
        } else {
          Add-CgRegistryWriteFailureFinding -Path $lsaPath -Name 'LsaCfgFlags' -Value $RunState.effective.LsaCfgFlags
          $RunState.registryWriteFailed = $true
        }
      }
    }
}

function Invoke-Capability39MainPhase01 {
  param([hashtable]$RunState)
  if ($Mode -eq 'Remediate') {

    . Invoke-Capability39MainPhase01Step01 -RunState $RunState
. Invoke-Capability39MainPhase01Step02 -RunState $RunState
. Invoke-Capability39MainPhase01Step03 -RunState $RunState
  }
}
function Invoke-Capability39MainPhase02 {
  param([hashtable]$RunState)
  $after = [pscustomobject]@{
    EnableVirtualizationBasedSecurity = Get-RegValue -Path $dgPath  -Name 'EnableVirtualizationBasedSecurity'
    RequirePlatformSecurityFeatures   = Get-RegValue -Path $dgPath  -Name 'RequirePlatformSecurityFeatures'
    LsaCfgFlags                       = Get-RegValue -Path $lsaPath -Name 'LsaCfgFlags'
  }

  # Registry-only compliance (effective behavior requires reboot).
  $RunState.compliant = ($after.EnableVirtualizationBasedSecurity -eq 1) -and
               ($after.RequirePlatformSecurityFeatures -in 1, 3) -and
               ($after.LsaCfgFlags -in 1, 2)

  # -----------------------------
  # Build result (structured pipeline output only)
  # -----------------------------

  $RunState.publicConfigPath = $null
  if ($ConfigPath) { $RunState.publicConfigPath = '[configured path]' }
}
function Invoke-Capability39MainPhase03 {
  param([hashtable]$RunState)
  $RunState.result = [pscustomobject]@{
    Summary = [pscustomobject]@{
      ComputerName   = $env:COMPUTERNAME
      Mode           = $Mode
      Target         = [pscustomobject]@{
        EnableVirtualizationBasedSecurity = 1
        RequirePlatformSecurityFeatures   = $RunState.effective.RequirePlatformSecurityFeatures
        LsaCfgFlags                       = $RunState.effective.LsaCfgFlags
      }
      RebootRequired = $RunState.rebootRequired
      RegistryWriteFailed = $RunState.registryWriteFailed
      Compliant      = $RunState.compliant
      FindingsCount  = $Findings.Count
      Changes        = $RunState.Changes
      Timestamp      = Get-Date
    }
    Current  = $RunState.current
    After    = $after
    Findings = $Findings
    Config   = [pscustomobject]@{
      ConfigPath = $RunState.publicConfigPath
      Meta       = $cfgMeta
      Warnings   = $ConfigWarnings
      Effective  = [pscustomobject]@{
        RequirePlatformSecurityFeatures = $RunState.effective.RequirePlatformSecurityFeatures
        LsaCfgFlags                     = $RunState.effective.LsaCfgFlags
        ExportPath                      = $RunState.effective.ExportPath
        ExportCsvBasePath               = $RunState.effective.ExportCsvBasePath
        ShowSummary                     = $RunState.effective.ShowSummary
      }
    }
  }

  # -----------------------------
  # Export (does not pollute pipeline)
  # -----------------------------

  if ($RunState.effective.ExportPath) {
    $dir = Split-Path -Path $RunState.effective.ExportPath -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](Ensure-Directory -Path $dir) }
    $RunState.result | ConvertTo-Json -Depth 6 | Set-Content -Path $RunState.effective.ExportPath -Encoding UTF8
  }
}
function Invoke-Capability39MainPhase04 {
  param([hashtable]$RunState)
  if ($RunState.effective.ExportCsvBasePath) {
    if (-not (Test-Path -LiteralPath $RunState.effective.ExportCsvBasePath)) {
      [void](Ensure-Directory -Path $RunState.effective.ExportCsvBasePath)
    }

    ($RunState.result.Summary | Select-Object * ) |
      Export-Csv -Path (Join-Path $RunState.effective.ExportCsvBasePath 'summary.csv') -NoTypeInformation -Encoding UTF8

    ($RunState.result.Findings) |
      Export-Csv -Path (Join-Path $RunState.effective.ExportCsvBasePath 'findings.csv') -NoTypeInformation -Encoding UTF8
  }

  # -----------------------------
  # Console summary (host-only) + return object (pipeline)
  # -----------------------------

  if ($RunState.effective.ShowSummary) {
    Write-PrettySummary -Result $RunState.result -RunState $RunState
  }
}
function Invoke-Capability39Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation, [hashtable]$RunState)
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability39MainPhase01 -RunState $RunState
  . Invoke-Capability39MainPhase02 -RunState $RunState
  . Invoke-Capability39MainPhase03 -RunState $RunState
  . Invoke-Capability39MainPhase04 -RunState $RunState
}
. Invoke-Capability39Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation -RunState $RunState

# V2 output contract
function Get-Capability39ResultToken {
  param([hashtable]$RunState)
  $resultToken = if ($RunState.registryWriteFailed) { 'FAIL' } elseif ($Strict -and $Findings.Count -gt 0) { 'FAIL' } elseif ($Findings.Count -gt 0) { 'WARN' } else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability39ResultToken -RunState $RunState
$v2Result = Get-V2ResultObject -ScriptName '39-CredentialGuard-VBS-AuditRemediate.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $Findings.ToArray()) -Summary $RunState.result.Summary -Metadata @{ Current = $RunState.result.Current; After = $RunState.result.After; Config = $RunState.result.Config }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
