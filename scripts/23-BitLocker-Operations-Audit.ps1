#Requires -RunAsAdministrator
#requires -version 5.1
<#
.SYNOPSIS
Audits BitLocker state for a single volume and returns one structured result object, plus an optional console summary and CSV export.

.DESCRIPTION
This script collects BitLocker operational data for a target volume using a structured PowerShell API first and then uses a command-line fallback to cross-check protection state.

The script always emits exactly one PSCustomObject to the pipeline. This makes it safe to use with common PowerShell tooling such as Export-Csv, ConvertTo-Json, Where-Object, and logging pipelines.

Console output (banners, colors, readability formatting) is written separately using host/information output so it does not interfere with pipeline processing.

Data sources and behavior:
- Primary: Structured BitLocker volume data (volume status, protection status, encryption percentage, method, etc.).
- Secondary: manage-bde status text capture (optional).
- Secondary: manage-bde protection check (exit code based) to derive a boolean protection indicator when possible.

If a JSON config file is supplied but cannot be loaded or parsed, the script automatically falls back to built-in defaults and continues.

.PARAMETER MountPoint
The target volume mount point to audit.
Typical values:
- "C:" (recommended)
- "C" or "C:\" (these are normalized internally to "C:")

Default: the current system drive.

.PARAMETER ExportPath
Optional path to export the result as a CSV file.
If omitted, the script does not export unless export is enabled via the JSON configuration.

Notes:
- The script creates the parent directory if it does not exist.
- Exported CSV contains the same fields as the returned object (except very large optional text fields unless enabled).

.PARAMETER IncludeManageBdeText
When specified, adds an additional property containing the full manage-bde status output as plain text.
This output can be large; the script truncates it to a configurable maximum length.

Use this option for troubleshooting (runbooks, support bundles) rather than routine SIEM ingestion.

.PARAMETER ConfigPath
Optional path to a JSON configuration file supplied with $ConfigPath.

The JSON can override defaults such as:
- Whether the console summary is printed
- Whether the console uses color
- Whether CSV export is enabled and the default export path
- Whether manage-bde text is included by default and maximum text length
- Whether to include key protector IDs and protector count
- Whether to run the manage-bde protection exit-code check

If the file is missing, empty, unreadable, or invalid JSON, built-in defaults are used automatically.

.INPUTS
None. This script does not accept pipeline input.


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
System.Management.Automation.PSCustomObject

The returned object includes (best-effort) fields such as:
- ComputerName, MountPoint, Timestamp
- VolumeType, VolumeStatus, ProtectionStatus
- EncryptionPercentage, EncryptionMethod, LockStatus
- CapacityGB, MetadataVersion
- KeyProtectorTypes, KeyProtectorCount, KeyProtectorIds (IDs are not secrets)
- ManageBdeProtectionExitCode, ManageBdeIsProtected
- GetBitLockerVolumeError, ManageBdeError
- Findings (human-readable aggregated findings)

.NOTES
Requirements / expectations:
- Must be run elevated (Administrator), otherwise the script stops.
- The script never returns secrets (no recovery passwords or key material).
- Some environments may report unexpected values (e.g., missing protector data or non-standard exit codes); these are surfaced via Findings and error fields rather than silently ignored.

Recommended usage pattern:
- Treat the returned object as the source of truth for automation and SIEM ingestion.
- Use the console summary for interactive troubleshooting only.

.EXAMPLE
.\23-BitLocker-Operations-Audit.ps1

Runs an audit for the system drive and prints a console summary (default behavior), while also returning one result object to the pipeline.

.EXAMPLE
.\23-BitLocker-Operations-Audit.ps1 -MountPoint D:

Audits the volume mounted at D:.

.EXAMPLE
.\23-BitLocker-Operations-Audit.ps1 -ExportPath "C:\Temp\bitlocker-audit.csv"

Audits the default volume and writes a CSV export to the given path.

.EXAMPLE
.\23-BitLocker-Operations-Audit.ps1 -ConfigPath $ConfigPath

Runs the audit using JSON-provided defaults (if available). If the JSON cannot be loaded, built-in defaults are used.

.EXAMPLE
# Troubleshooting run: include manage-bde text in the returned object
.\23-BitLocker-Operations-Audit.ps1 -IncludeManageBdeText | ConvertTo-Json -Depth 4

Adds manage-bde status text (truncated) to the output object and converts it to JSON for support or log ingestion.
#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateNotNullOrEmpty()]
  [string]$MountPoint = $env:SystemDrive,

  [string]$ExportPath,

  [switch]$IncludeManageBdeText,

  [string]$ConfigPath

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
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '23-BitLocker-Operations-Audit.ps1' -BoundParameters $PSBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
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
  $result = Get-V2ResultObject -ScriptName '23-BitLocker-Operations-Audit.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}


# Ensure-Cmdlet imported from lib/External.psm1

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
function Normalize-MountPoint {
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Value
  )

  # manage-bde <drive> expects drive letter followed by a colon.
  if ($Value -match '^[A-Za-z]$')     { return ($Value + ':') }
  if ($Value -match '^[A-Za-z]:\\$')  { return $Value.TrimEnd('\') }
  return $Value
}

function Get-DefaultConfig {
  [pscustomobject]@{
    # Console output
    SummaryToHost                  = $true
    PrettyConsole                  = $true

    # manage-bde text output (optional)
    IncludeManageBdeTextDefault    = $false
    ManageBdeMaxChars              = 12000

    # CSV export
    ExportEnabledDefault           = $false
    ExportPathDefault              = (Join-Path ([System.IO.Path]::GetTempPath()) 'bitlocker-audit.csv')

    # Extra structured fields
    IncludeProtectorCount          = $true
    IncludeKeyProtectorIds         = $true

    # Protection boolean derived from the manage-bde exit code.
    UseManageBdeProtectionExitCode = $true
  }
}

function Import-JsonConfigOrDefault {
  param([string]$Path)

  $cfg = Get-DefaultConfig
  if ([string]::IsNullOrWhiteSpace($Path)) { return $cfg }

  try {
    if (-not (Test-Path -LiteralPath $Path)) { return $cfg }

    $raw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
    if ([string]::IsNullOrWhiteSpace($raw)) { return $cfg }

    # ConvertFrom-Json should be guarded via try/catch for invalid JSON.
    $parsed = $raw | ConvertFrom-Json

    Set-BitLockerBooleanConfigDefaults -Defaults $cfg -Parsed $parsed
    if (Test-BitLockerExportPath -Value $parsed.ExportPathDefault) {
      $cfg.ExportPathDefault = [string]$parsed.ExportPathDefault
    }

    Set-BitLockerManageBdeLimit -Defaults $cfg -Parsed $parsed

    return $cfg
  } catch {
    return $cfg
  }
}
function Test-BitLockerExportPath {
  param([AllowNull()]$Value)
  if ($null -eq $Value) { return $false }
  return (-not [string]::IsNullOrWhiteSpace([string]$Value))
}
function Set-BitLockerManageBdeLimit {
  param($Defaults, $Parsed)
  if ($null -eq $Parsed.ManageBdeMaxChars) { return }
  $value = 0
  if ([int]::TryParse([string]$Parsed.ManageBdeMaxChars, [ref]$value) -and $value -ge 0) {
    $Defaults.ManageBdeMaxChars = $value
  }
}
function Set-BitLockerBooleanConfigDefaults {
  param($Defaults, $Parsed)
  foreach ($name in @(
      'SummaryToHost',
      'PrettyConsole',
      'IncludeManageBdeTextDefault',
      'ExportEnabledDefault',
      'IncludeProtectorCount',
      'IncludeKeyProtectorIds',
      'UseManageBdeProtectionExitCode'
    )) {
    $property = $Parsed.PSObject.Properties[$name]
    if ($null -ne $property) { $Defaults.$name = [bool]$property.Value }
  }
}

function Truncate-Text {
  param(
    [AllowNull()]
    [string]$Text,
    [int]$MaxChars
  )

  if ($null -eq $Text) { return $null }
  if ($MaxChars -le 0) { return '' }
  if ($Text.Length -le $MaxChars) { return $Text }
  return ($Text.Substring(0, $MaxChars) + '... (truncated)')
}

function Get-StatusColor {
  param([AllowNull()][object]$Value, [ConsoleColor]$Ok = [ConsoleColor]::Green, [ConsoleColor]$Warn = [ConsoleColor]::Yellow, [ConsoleColor]$Bad = [ConsoleColor]::Red)

  if ($null -eq $Value) { return [ConsoleColor]::DarkGray }
  $s = [string]$Value

  switch -Regex ($s) {
    '^On$'             { return $Ok }
    '^Off$'            { return $Bad }
    '^FullyEncrypted$' { return $Ok }
    '^EncryptionInProgress$' { return $Warn }
    '^FullyDecrypted$' { return $Bad }
    default            { return [ConsoleColor]::Cyan }
  }
}


function Write-SummaryToConsoleSection01 {
  param([hashtable]$RunState)
$titleColor = if ($RunState.PrettyConsole) { [ConsoleColor]::White } else { [ConsoleColor]::Gray }
  $lineColor  = if ($RunState.PrettyConsole) { [ConsoleColor]::DarkGray } else { [ConsoleColor]::Gray }

  Write-UiLine ""
  Write-UiLine ("=" * 60) -ForegroundColor $lineColor
  Write-UiLine "BitLocker audit summary" -ForegroundColor $titleColor
  Write-UiLine ("=" * 60) -ForegroundColor $lineColor

  Write-KeyValue -Key 'ComputerName'         -Value $RunState.Result.ComputerName -ValueColor ([ConsoleColor]::Gray)
  Write-KeyValue -Key 'MountPoint'           -Value $RunState.Result.MountPoint -ValueColor ([ConsoleColor]::Gray)

  Write-KeyValue -Key 'VolumeType'           -Value $RunState.Result.VolumeType -ValueColor ([ConsoleColor]::Cyan)
  Write-KeyValue -Key 'VolumeStatus'         -Value $RunState.Result.VolumeStatus -ValueColor (Get-StatusColor -Value $RunState.Result.VolumeStatus)
  Write-KeyValue -Key 'ProtectionStatus'     -Value $RunState.Result.ProtectionStatus -ValueColor (Get-StatusColor -Value $RunState.Result.ProtectionStatus)
  Write-KeyValue -Key 'EncryptionPercentage' -Value $RunState.Result.EncryptionPercentage -ValueColor ([ConsoleColor]::Cyan)
  Write-KeyValue -Key 'EncryptionMethod'     -Value $RunState.Result.EncryptionMethod -ValueColor ([ConsoleColor]::Cyan)
  Write-KeyValue -Key 'LockStatus'           -Value $RunState.Result.LockStatus -ValueColor ([ConsoleColor]::Cyan)
  Write-KeyValue -Key 'AutoUnlockEnabled'    -Value $RunState.Result.AutoUnlockEnabled -ValueColor ([ConsoleColor]::Cyan)

  Write-KeyValue -Key 'KeyProtectorTypes'    -Value $RunState.Result.KeyProtectorTypes -ValueColor ([ConsoleColor]::Cyan)
  if ($null -ne $RunState.Result.KeyProtectorCount) {
    $countColor = if ($RunState.Result.KeyProtectorCount -gt 0) { [ConsoleColor]::Green } else { [ConsoleColor]::Yellow }
    Write-KeyValue -Key 'KeyProtectorCount'  -Value $RunState.Result.KeyProtectorCount -ValueColor $countColor
  }

  if (-not [string]::IsNullOrWhiteSpace($RunState.Result.Findings)) {
    Write-UiLine ("-" * 60) -ForegroundColor $lineColor
    Write-KeyValue -Key 'Finding(s)' -Value $RunState.Result.Findings -ValueColor ([ConsoleColor]::Yellow) -KeyWidth 28
  }

  Write-UiLine ("-" * 60) -ForegroundColor $lineColor
}

function Write-SummaryToConsoleSection02 {
  param([hashtable]$RunState)
$gbvState = if ([string]::IsNullOrWhiteSpace($RunState.Result.GetBitLockerVolumeError)) { 'OK' } else { 'ERROR' }
  $gbvColor = if ($gbvState -eq 'OK') { [ConsoleColor]::Green } else { [ConsoleColor]::Red }
  Write-KeyValue -Key 'Get-BitLockerVolume' -Value $gbvState -ValueColor $gbvColor
  if (-not [string]::IsNullOrWhiteSpace($RunState.Result.GetBitLockerVolumeError)) {
    Write-KeyValue -Key 'GBV error' -Value $RunState.Result.GetBitLockerVolumeError -ValueColor ([ConsoleColor]::Red)
  }

  $mbState = if ([string]::IsNullOrWhiteSpace($RunState.Result.ManageBdeError)) { 'OK' } else { 'ERROR' }
  $mbColor = if ($mbState -eq 'OK') { [ConsoleColor]::Green } else { [ConsoleColor]::Red }
  Write-KeyValue -Key 'manage-bde' -Value $mbState -ValueColor $mbColor
}

function Write-SummaryToConsoleSection03 {
  param([hashtable]$RunState)
if (-not [string]::IsNullOrWhiteSpace($RunState.Result.ManageBdeError)) {
    Write-KeyValue -Key 'manage-bde error' -Value $RunState.Result.ManageBdeError -ValueColor ([ConsoleColor]::Red)
  }

  if ($null -ne $RunState.Result.ManageBdeProtectionExitCode) {
    $exitColor = if ($RunState.Result.ManageBdeProtectionExitCode -in 0,1) { [ConsoleColor]::Cyan } else { [ConsoleColor]::Yellow }
    Write-KeyValue -Key 'mb protect exit' -Value $RunState.Result.ManageBdeProtectionExitCode -ValueColor $exitColor
    Write-KeyValue -Key 'mb protected'    -Value $RunState.Result.ManageBdeIsProtected -ValueColor ([ConsoleColor]::Cyan)
  }

  if (-not [string]::IsNullOrWhiteSpace($RunState.EffectiveExportPath)) {
    Write-KeyValue -Key 'CSV export' -Value $RunState.EffectiveExportPath -ValueColor ([ConsoleColor]::Gray)
  }

  Write-KeyValue -Key 'Timestamp' -Value $RunState.Result.Timestamp -ValueColor ([ConsoleColor]::Gray)

  Write-UiLine ("=" * 60) -ForegroundColor $lineColor
  Write-UiLine ""
}

function Write-SummaryToConsole {
  param(
    [Parameter(Mandatory)]
    [pscustomobject]$Result,

    [AllowNull()]
    [string]$EffectiveExportPath,

    [bool]$PrettyConsole
  , [hashtable]$RunState)
  $RunState.EffectiveExportPath = $EffectiveExportPath
  $RunState.PrettyConsole = $PrettyConsole
  $RunState.Result = $Result

    . Write-SummaryToConsoleSection01 -RunState $RunState
    . Write-SummaryToConsoleSection02 -RunState $RunState
    . Write-SummaryToConsoleSection03 -RunState $RunState
}

# -------------------------
# Pre-flight
# -------------------------
function Invoke-Capability23MainPhase01 {
  param([hashtable]$RunState)
  Require-Admin

  $cfg = Import-JsonConfigOrDefault -Path $ConfigPath
  $mp  = Normalize-MountPoint -Value $MountPoint

  Ensure-Cmdlet -Name 'Get-BitLockerVolume'

  $RunState.effectiveIncludeManageBdeText = $IncludeManageBdeText.IsPresent -or $cfg.IncludeManageBdeTextDefault

  $RunState.effectiveExportPath = $ExportPath
  if ([string]::IsNullOrWhiteSpace($RunState.effectiveExportPath) -and $cfg.ExportEnabledDefault) {
    $RunState.effectiveExportPath = $cfg.ExportPathDefault
  }

  # -------------------------
  # Data collection (primary): Get-BitLockerVolume
  # -------------------------
  $RunState.vol = $null
  $RunState.gbvErrorText = $null
  try {
    $RunState.vol = Get-BitLockerVolume -MountPoint $mp  # Structured source.
  } catch {
    $RunState.gbvErrorText = $_.Exception.Message
  }

  $RunState.keyProtectorTypes = @()
  $RunState.keyProtectorIds   = @()
}
function Invoke-Capability23MainPhase02Step01 {
  param([hashtable]$RunState)
foreach ($kp in $RunState.vol.KeyProtector) {
      if ($kp -and $kp.KeyProtectorType) { $RunState.keyProtectorTypes += [string]$kp.KeyProtectorType }
      if ($cfg.IncludeKeyProtectorIds -and $kp -and $kp.KeyProtectorId) { $RunState.keyProtectorIds += [string]$kp.KeyProtectorId }
    }
}

function Invoke-Capability23MainPhase02Step02 {
  param([hashtable]$RunState)
$RunState.keyProtectorTypes = $RunState.keyProtectorTypes | Select-Object -Unique
    $RunState.keyProtectorIds   = $RunState.keyProtectorIds   | Select-Object -Unique
}

function Invoke-Capability23MainPhase02 {
  param([hashtable]$RunState)
  if ($RunState.vol -and $RunState.vol.KeyProtector) {
    . Invoke-Capability23MainPhase02Step01 -RunState $RunState
. Invoke-Capability23MainPhase02Step02 -RunState $RunState
  }
}
function Invoke-Capability23MainPhase03 {
  param([hashtable]$RunState)
  $RunState.keyProtectorCount = $null
  if ($cfg.IncludeProtectorCount) {
    $RunState.keyProtectorCount = $(if ($RunState.vol -and $RunState.vol.KeyProtector) { @($RunState.vol.KeyProtector).Count } else { 0 })
  }

  # -------------------------
  # Data collection (secondary): manage-bde
  # -------------------------
  $RunState.manageBdeText = $null
  $RunState.manageBdeErrorText = $null
}
function Invoke-Capability23MainPhase04 {
  param([hashtable]$RunState)
  try {
    $manageBdeStatus = Invoke-NativeCommand -Command 'manage-bde.exe' -Arguments @('-status',$mp) -CaptureOutput -Quiet -TimeoutSeconds 60 -MaxOutputBytes 1048576
    if ($null -eq $manageBdeStatus -or -not $manageBdeStatus.Success -or $manageBdeStatus.TimedOut -or $manageBdeStatus.OutputTruncated -or $manageBdeStatus.StderrTruncated) { throw 'manage-bde status timed out, failed, or produced truncated output.' }
    $RunState.manageBdeText = $manageBdeStatus.Output.Trim()  # Documented.
  } catch {
    $RunState.manageBdeErrorText = $_.Exception.Message
    $RunState.manageBdeText = $null
  }
}
function Invoke-Capability23MainPhase05 {
  param([hashtable]$RunState)
  if ($RunState.effectiveIncludeManageBdeText -and $null -ne $RunState.manageBdeText) {
    $RunState.manageBdeText = Truncate-Text -Text $RunState.manageBdeText -MaxChars $cfg.ManageBdeMaxChars
  }

  # manage-bde -status -protectionaserrorlevel: expected 0 (protected) or 1 (unprotected).
  $RunState.manageBdeProtectionExitCode = $null
  $RunState.manageBdeIsProtected = $null
  $RunState.manageBdeProtectionCheckError = $null
}
function Invoke-Capability23MainPhase06Step01 {
  param([hashtable]$RunState)
$manageBdeProtection = Invoke-NativeCommand -Command 'manage-bde.exe' -Arguments @('-status',$mp,'-protectionaserrorlevel') -CaptureOutput -Quiet -TimeoutSeconds 60 -MaxOutputBytes 65536
      if ($null -eq $manageBdeProtection -or $manageBdeProtection.TimedOut -or $manageBdeProtection.OutputTruncated -or $manageBdeProtection.StderrTruncated) { throw 'manage-bde protection check timed out or produced truncated output.' }
      $RunState.manageBdeProtectionExitCode = $manageBdeProtection.ExitCode
}

function Invoke-Capability23MainPhase06Step02 {
  param([hashtable]$RunState)
if ($RunState.manageBdeProtectionExitCode -eq 0) { $RunState.manageBdeIsProtected = $true }
      elseif ($RunState.manageBdeProtectionExitCode -eq 1) { $RunState.manageBdeIsProtected = $false }
      else {
        $RunState.manageBdeIsProtected = $null
        $RunState.manageBdeProtectionCheckError = "Unexpected exit code from manage-bde -protectionaserrorlevel: $($RunState.manageBdeProtectionExitCode) (expected 0 or 1)."
      }
}

function Invoke-Capability23MainPhase06 {
  param([hashtable]$RunState)
  if ($cfg.UseManageBdeProtectionExitCode) {
    try {
      . Invoke-Capability23MainPhase06Step01 -RunState $RunState
. Invoke-Capability23MainPhase06Step02 -RunState $RunState
    } catch {
      $RunState.manageBdeProtectionCheckError = $_.Exception.Message
    }
  }
}
function Invoke-Capability23MainPhase07 {
  param([hashtable]$RunState)
  $RunState.findings = Get-FindingsList
}
function Invoke-Capability23MainPhase08 {
  param([hashtable]$RunState)
  if ($RunState.vol) {
    if ($RunState.vol.VolumeStatus -eq 'FullyEncrypted' -and $RunState.vol.ProtectionStatus -eq 'Off') {
      Add-Finding -FindingList $RunState.findings -Code 'BLKR-ProtectionSuspended' -Severity 'High' -Message "Volume is fully encrypted but protection is OFF (likely suspended)."
    }
    if (($RunState.vol.VolumeType -eq 'OperatingSystem') -and ($RunState.keyProtectorCount -eq 0)) {
      Add-Finding -FindingList $RunState.findings -Code 'BLKR-NoKeyProtectors' -Severity 'High' -Message "No key protectors detected for OS volume (unexpected configuration or query failure)."
    }
  } else {
    if (-not [string]::IsNullOrWhiteSpace($RunState.gbvErrorText)) {
      Add-Finding -FindingList $RunState.findings -Code 'BLKR-GetBitLockerVolumeFailed' -Severity 'Medium' -Message "Get-BitLockerVolume failed; rely on manage-bde output for troubleshooting."
    }
  }
}
function Invoke-Capability23MainPhase09 {
  param([hashtable]$RunState)
  if ($cfg.UseManageBdeProtectionExitCode -and -not [string]::IsNullOrWhiteSpace($RunState.manageBdeProtectionCheckError)) {
    Add-Finding -FindingList $RunState.findings -Code 'BLKR-ManageBdeProtectionCheckIssue' -Severity 'Medium' -Message ("manage-bde protection check issue: " + $RunState.manageBdeProtectionCheckError)
  }
}
function Invoke-Capability23MainPhase10 {
  param([hashtable]$RunState)
  if ((Test-AllConditions -Conditions @({ $cfg.UseManageBdeProtectionExitCode }, { ($null -ne $RunState.manageBdeIsProtected) })) -and $RunState.vol) {
    $psProtected =
      if ($RunState.vol.ProtectionStatus -eq 'On') { $true }
      elseif ($RunState.vol.ProtectionStatus -eq 'Off') { $false }
      else { $null }

    if ((Test-AllConditions -Conditions @({ ($null -ne $psProtected) }, { ($psProtected -ne $RunState.manageBdeIsProtected) }))) {
      Add-Finding -FindingList $RunState.findings -Code 'BLKR-ProtectionStateMismatch' -Severity 'Medium' -Message "Protection state mismatch between Get-BitLockerVolume and manage-bde exit code."
    }
  }
}
function Invoke-Capability23MainPhase11 {
  param([hashtable]$RunState)
  $RunState.result = [pscustomobject]@{
    ComputerName                = $env:COMPUTERNAME
    MountPoint                  = $mp
    Timestamp                   = (Get-Date)

    VolumeType                  = Get-BitLockerVolumeProperty -Volume $RunState.vol -Name 'VolumeType'
    VolumeStatus                = Get-BitLockerVolumeProperty -Volume $RunState.vol -Name 'VolumeStatus'
    ProtectionStatus            = Get-BitLockerVolumeProperty -Volume $RunState.vol -Name 'ProtectionStatus'
    EncryptionPercentage        = Get-BitLockerVolumeProperty -Volume $RunState.vol -Name 'EncryptionPercentage'
    AutoUnlockEnabled           = Get-BitLockerVolumeProperty -Volume $RunState.vol -Name 'AutoUnlockEnabled'

    EncryptionMethod            = Get-BitLockerVolumeProperty -Volume $RunState.vol -Name 'EncryptionMethod'
    LockStatus                  = Get-BitLockerVolumeProperty -Volume $RunState.vol -Name 'LockStatus'
    CapacityGB                  = Get-BitLockerVolumeProperty -Volume $RunState.vol -Name 'CapacityGB'
    MetadataVersion             = Get-BitLockerVolumeProperty -Volume $RunState.vol -Name 'MetadataVersion'

    KeyProtectorTypes           = ($RunState.keyProtectorTypes -join ', ')
    KeyProtectorCount           = $RunState.keyProtectorCount
    KeyProtectorIds             = Get-BitLockerProtectorIds -Include $cfg.IncludeKeyProtectorIds -Ids $RunState.keyProtectorIds

    GetBitLockerVolumeError     = $RunState.gbvErrorText
    ManageBdeError              = $RunState.manageBdeErrorText

    ManageBdeProtectionExitCode = $RunState.manageBdeProtectionExitCode
    ManageBdeIsProtected        = $RunState.manageBdeIsProtected

    Findings                    = Get-BitLockerFindingText -Findings $RunState.findings
  }
}
function Get-BitLockerVolumeProperty {
  param([AllowNull()]$Volume, [string]$Name)
  if (-not $Volume) { return $null }
  return $Volume.$Name
}
function Get-BitLockerProtectorIds {
  param([bool]$Include, [object[]]$Ids)
  if (-not $Include) { return $null }
  return ($Ids -join ', ')
}
function Get-BitLockerFindingText {
  param([object[]]$Findings)
  if ($Findings.Count -eq 0) { return '' }
  return (($Findings | ForEach-Object { $_.Message }) -join ' | ')
}
function Invoke-Capability23MainPhase12 {
  param([hashtable]$RunState)
  if ($RunState.effectiveIncludeManageBdeText) {
    $RunState.result | Add-Member -NotePropertyName ManageBdeStatusText -NotePropertyValue $RunState.manageBdeText
  }

  # -------------------------
  # Optional CSV export
  # -------------------------
  if (-not [string]::IsNullOrWhiteSpace($RunState.effectiveExportPath)) {
    $dir = Split-Path -Path $RunState.effectiveExportPath -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
      New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
    $RunState.result | Export-Csv -Path $RunState.effectiveExportPath -NoTypeInformation -Encoding UTF8
  }

  # -------------------------
  # Console summary (no pipeline pollution)
  # -------------------------
  if ($cfg.SummaryToHost) {
    # Write-UiLine supports ForegroundColor/BackgroundColor for console output.
    Write-SummaryToConsole -Result $RunState.result -EffectiveExportPath $RunState.effectiveExportPath -PrettyConsole $cfg.PrettyConsole -RunState $RunState
  }
}
function Invoke-Capability23Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation)
  $RunState = @{

  }
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability23MainPhase01 -RunState $RunState
  . Invoke-Capability23MainPhase02 -RunState $RunState
  . Invoke-Capability23MainPhase03 -RunState $RunState
  . Invoke-Capability23MainPhase04 -RunState $RunState
  . Invoke-Capability23MainPhase05 -RunState $RunState
  . Invoke-Capability23MainPhase06 -RunState $RunState
  . Invoke-Capability23MainPhase07 -RunState $RunState
  . Invoke-Capability23MainPhase08 -RunState $RunState
  . Invoke-Capability23MainPhase09 -RunState $RunState
  . Invoke-Capability23MainPhase10 -RunState $RunState
  . Invoke-Capability23MainPhase11 -RunState $RunState
  . Invoke-Capability23MainPhase12 -RunState $RunState
  $script:RunState = $RunState
}

. Invoke-Capability23Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation

# V2 output contract
function Get-Capability23ResultToken {
  param([hashtable]$RunState)
  $resultToken = if ($Strict -and $RunState.findings.Count -gt 0) { 'FAIL' } elseif ($RunState.findings.Count -gt 0) { 'WARN' } else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability23ResultToken -RunState $RunState
$v2Result = Get-V2ResultObject -ScriptName '23-BitLocker-Operations-Audit.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $RunState.findings) -Summary $RunState.result -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
