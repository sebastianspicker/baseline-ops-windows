#Requires -RunAsAdministrator
#requires -version 5.1
<#
.SYNOPSIS
Audits BitLocker state for a single volume and returns one structured result object, plus an optional human-friendly console summary and optional CSV export.

.DESCRIPTION
This script collects BitLocker operational data for a target volume using a structured PowerShell API first and then supplements it with a command-line fallback for robustness.

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
Optional path to a JSON configuration file (example: "PATH/TO/JSON/bitlocker-audit.json").

The JSON can override defaults such as:
- Whether the console summary is printed
- Whether the console is "pretty" (colors)
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
.\23-BitLocker-Operations-Audit.ps1 -ConfigPath "PATH/TO/JSON/bitlocker-audit.json"

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
# v2-init (migrated to Initialize-V2Context)
Initialize-V2Context -ScriptName '23-BitLocker-Operations-Audit.ps1' -BoundParameters $PSBoundParameters
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
  $result = Get-V2ResultObject -ScriptName '23-BitLocker-Operations-Audit.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}


# Ensure-Cmdlet imported from lib/External.psm1

function Normalize-MountPoint {
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Value
  )

  # manage-bde <drive> expects drive letter followed by a colon. [web:21]
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
    ExportPathDefault              = 'PATH/TO/EXPORT/bitlocker-audit.csv'

    # Extra structured fields
    IncludeProtectorCount          = $true
    IncludeKeyProtectorIds         = $true

    # Robust protection boolean from manage-bde exit code. [web:21]
    UseManageBdeProtectionExitCode = $true
  }
}

function Import-JsonConfigOrDefault {
  param([string]$Path)

  $cfg = Get-DefaultConfig
  if ([string]::IsNullOrWhiteSpace($Path)) { return $cfg }

  try {
    if (-not (Test-Path -LiteralPath $Path)) { return $cfg }

    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return $cfg }

    # ConvertFrom-Json should be guarded via try/catch for invalid JSON. [web:56]
    $parsed = $raw | ConvertFrom-Json

    if ($null -ne $parsed.SummaryToHost)                   { $cfg.SummaryToHost                  = [bool]$parsed.SummaryToHost }
    if ($null -ne $parsed.PrettyConsole)                   { $cfg.PrettyConsole                  = [bool]$parsed.PrettyConsole }

    if ($null -ne $parsed.IncludeManageBdeTextDefault)     { $cfg.IncludeManageBdeTextDefault    = [bool]$parsed.IncludeManageBdeTextDefault }
    if ($null -ne $parsed.ExportEnabledDefault)            { $cfg.ExportEnabledDefault           = [bool]$parsed.ExportEnabledDefault }
    if ($null -ne $parsed.ExportPathDefault -and -not [string]::IsNullOrWhiteSpace([string]$parsed.ExportPathDefault)) {
      $cfg.ExportPathDefault = [string]$parsed.ExportPathDefault
    }

    if ($null -ne $parsed.ManageBdeMaxChars) {
      $n = 0
      if ([int]::TryParse([string]$parsed.ManageBdeMaxChars, [ref]$n) -and $n -ge 0) { $cfg.ManageBdeMaxChars = $n }
    }

    if ($null -ne $parsed.IncludeProtectorCount)           { $cfg.IncludeProtectorCount          = [bool]$parsed.IncludeProtectorCount }
    if ($null -ne $parsed.IncludeKeyProtectorIds)          { $cfg.IncludeKeyProtectorIds         = [bool]$parsed.IncludeKeyProtectorIds }
    if ($null -ne $parsed.UseManageBdeProtectionExitCode)  { $cfg.UseManageBdeProtectionExitCode = [bool]$parsed.UseManageBdeProtectionExitCode }

    return $cfg
  } catch {
    return $cfg
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


function Write-SummaryToConsole {
  param(
    [Parameter(Mandatory)]
    [pscustomobject]$Result,

    [AllowNull()]
    [string]$EffectiveExportPath,

    [bool]$PrettyConsole
  )

  $titleColor = if ($PrettyConsole) { [ConsoleColor]::White } else { [ConsoleColor]::Gray }
  $lineColor  = if ($PrettyConsole) { [ConsoleColor]::DarkGray } else { [ConsoleColor]::Gray }

  Write-UiLine ""
  Write-UiLine ("=" * 60) -ForegroundColor $lineColor
  Write-UiLine "BitLocker audit summary" -ForegroundColor $titleColor
  Write-UiLine ("=" * 60) -ForegroundColor $lineColor

  Write-KeyValue -Key 'ComputerName'         -Value $Result.ComputerName -ValueColor ([ConsoleColor]::Gray)
  Write-KeyValue -Key 'MountPoint'           -Value $Result.MountPoint -ValueColor ([ConsoleColor]::Gray)

  Write-KeyValue -Key 'VolumeType'           -Value $Result.VolumeType -ValueColor ([ConsoleColor]::Cyan)
  Write-KeyValue -Key 'VolumeStatus'         -Value $Result.VolumeStatus -ValueColor (Get-StatusColor -Value $Result.VolumeStatus)
  Write-KeyValue -Key 'ProtectionStatus'     -Value $Result.ProtectionStatus -ValueColor (Get-StatusColor -Value $Result.ProtectionStatus)
  Write-KeyValue -Key 'EncryptionPercentage' -Value $Result.EncryptionPercentage -ValueColor ([ConsoleColor]::Cyan)
  Write-KeyValue -Key 'EncryptionMethod'     -Value $Result.EncryptionMethod -ValueColor ([ConsoleColor]::Cyan)
  Write-KeyValue -Key 'LockStatus'           -Value $Result.LockStatus -ValueColor ([ConsoleColor]::Cyan)
  Write-KeyValue -Key 'AutoUnlockEnabled'    -Value $Result.AutoUnlockEnabled -ValueColor ([ConsoleColor]::Cyan)

  Write-KeyValue -Key 'KeyProtectorTypes'    -Value $Result.KeyProtectorTypes -ValueColor ([ConsoleColor]::Cyan)
  if ($null -ne $Result.KeyProtectorCount) {
    $countColor = if ($Result.KeyProtectorCount -gt 0) { [ConsoleColor]::Green } else { [ConsoleColor]::Yellow }
    Write-KeyValue -Key 'KeyProtectorCount'  -Value $Result.KeyProtectorCount -ValueColor $countColor
  }

  if (-not [string]::IsNullOrWhiteSpace($Result.Findings)) {
    Write-UiLine ("-" * 60) -ForegroundColor $lineColor
    Write-KeyValue -Key 'Finding(s)' -Value $Result.Findings -ValueColor ([ConsoleColor]::Yellow) -KeyWidth 28
  }

  Write-UiLine ("-" * 60) -ForegroundColor $lineColor

  $gbvState = if ([string]::IsNullOrWhiteSpace($Result.GetBitLockerVolumeError)) { 'OK' } else { 'ERROR' }
  $gbvColor = if ($gbvState -eq 'OK') { [ConsoleColor]::Green } else { [ConsoleColor]::Red }
  Write-KeyValue -Key 'Get-BitLockerVolume' -Value $gbvState -ValueColor $gbvColor
  if (-not [string]::IsNullOrWhiteSpace($Result.GetBitLockerVolumeError)) {
    Write-KeyValue -Key 'GBV error' -Value $Result.GetBitLockerVolumeError -ValueColor ([ConsoleColor]::Red)
  }

  $mbState = if ([string]::IsNullOrWhiteSpace($Result.ManageBdeError)) { 'OK' } else { 'ERROR' }
  $mbColor = if ($mbState -eq 'OK') { [ConsoleColor]::Green } else { [ConsoleColor]::Red }
  Write-KeyValue -Key 'manage-bde' -Value $mbState -ValueColor $mbColor
  if (-not [string]::IsNullOrWhiteSpace($Result.ManageBdeError)) {
    Write-KeyValue -Key 'manage-bde error' -Value $Result.ManageBdeError -ValueColor ([ConsoleColor]::Red)
  }

  if ($null -ne $Result.ManageBdeProtectionExitCode) {
    $exitColor = if ($Result.ManageBdeProtectionExitCode -in 0,1) { [ConsoleColor]::Cyan } else { [ConsoleColor]::Yellow }
    Write-KeyValue -Key 'mb protect exit' -Value $Result.ManageBdeProtectionExitCode -ValueColor $exitColor
    Write-KeyValue -Key 'mb protected'    -Value $Result.ManageBdeIsProtected -ValueColor ([ConsoleColor]::Cyan)
  }

  if (-not [string]::IsNullOrWhiteSpace($EffectiveExportPath)) {
    Write-KeyValue -Key 'CSV export' -Value $EffectiveExportPath -ValueColor ([ConsoleColor]::Gray)
  }

  Write-KeyValue -Key 'Timestamp' -Value $Result.Timestamp -ValueColor ([ConsoleColor]::Gray)

  Write-UiLine ("=" * 60) -ForegroundColor $lineColor
  Write-UiLine ""
}

# -------------------------
# Pre-flight
# -------------------------
Require-Admin

$cfg = Import-JsonConfigOrDefault -Path $ConfigPath
$mp  = Normalize-MountPoint -Value $MountPoint

Ensure-Cmdlet -Name 'Get-BitLockerVolume'

$effectiveIncludeManageBdeText = $IncludeManageBdeText.IsPresent -or $cfg.IncludeManageBdeTextDefault

$effectiveExportPath = $ExportPath
if ([string]::IsNullOrWhiteSpace($effectiveExportPath) -and $cfg.ExportEnabledDefault) {
  $effectiveExportPath = $cfg.ExportPathDefault
}

# -------------------------
# Data collection (primary): Get-BitLockerVolume
# -------------------------
$vol = $null
$gbvErrorText = $null
try {
  $vol = Get-BitLockerVolume -MountPoint $mp  # Structured source. [web:26]
} catch {
  $gbvErrorText = $_.Exception.Message
}

$keyProtectorTypes = @()
$keyProtectorIds   = @()

if ($vol -and $vol.KeyProtector) {
  foreach ($kp in $vol.KeyProtector) {
    if ($kp -and $kp.KeyProtectorType) { $keyProtectorTypes += [string]$kp.KeyProtectorType }
    if ($cfg.IncludeKeyProtectorIds -and $kp -and $kp.KeyProtectorId) { $keyProtectorIds += [string]$kp.KeyProtectorId }
  }
  $keyProtectorTypes = $keyProtectorTypes | Select-Object -Unique
  $keyProtectorIds   = $keyProtectorIds   | Select-Object -Unique
}

$keyProtectorCount = $null
if ($cfg.IncludeProtectorCount) {
  $keyProtectorCount = $(if ($vol -and $vol.KeyProtector) { @($vol.KeyProtector).Count } else { 0 })
}

# -------------------------
# Data collection (secondary): manage-bde
# -------------------------
$manageBdeText = $null
$manageBdeErrorText = $null
try {
  $manageBdeText = (& manage-bde -status $mp 2>&1 | Out-String).Trim()  # Documented. [web:21]
} catch {
  $manageBdeErrorText = $_.Exception.Message
  $manageBdeText = $null
}

if ($effectiveIncludeManageBdeText -and $null -ne $manageBdeText) {
  $manageBdeText = Truncate-Text -Text $manageBdeText -MaxChars $cfg.ManageBdeMaxChars
}

# manage-bde -status -protectionaserrorlevel: expected 0 (protected) or 1 (unprotected). [web:21]
$manageBdeProtectionExitCode = $null
$manageBdeIsProtected = $null
$manageBdeProtectionCheckError = $null

if ($cfg.UseManageBdeProtectionExitCode) {
  try {
    $null = & manage-bde -status $mp -protectionaserrorlevel 2>$null
    $manageBdeProtectionExitCode = $LASTEXITCODE

    if ($manageBdeProtectionExitCode -eq 0) { $manageBdeIsProtected = $true }
    elseif ($manageBdeProtectionExitCode -eq 1) { $manageBdeIsProtected = $false }
    else {
      $manageBdeIsProtected = $null
      $manageBdeProtectionCheckError = "Unexpected exit code from manage-bde -protectionaserrorlevel: $manageBdeProtectionExitCode (expected 0 or 1)."
    }
  } catch {
    $manageBdeProtectionCheckError = $_.Exception.Message
  }
}

# -------------------------
# Findings
# -------------------------
$findings = Get-FindingsList

if ($vol) {
  if ($vol.VolumeStatus -eq 'FullyEncrypted' -and $vol.ProtectionStatus -eq 'Off') {
    Add-Finding -FindingList $findings -Code 'BLKR-ProtectionSuspended' -Severity 'High' -Message "Volume is fully encrypted but protection is OFF (likely suspended)."
  }
  if (($vol.VolumeType -eq 'OperatingSystem') -and ($keyProtectorCount -eq 0)) {
    Add-Finding -FindingList $findings -Code 'BLKR-NoKeyProtectors' -Severity 'High' -Message "No key protectors detected for OS volume (unexpected configuration or query failure)."
  }
} else {
  if (-not [string]::IsNullOrWhiteSpace($gbvErrorText)) {
    Add-Finding -FindingList $findings -Code 'BLKR-GetBitLockerVolumeFailed' -Severity 'Medium' -Message "Get-BitLockerVolume failed; rely on manage-bde output for troubleshooting."
  }
}

if ($cfg.UseManageBdeProtectionExitCode -and -not [string]::IsNullOrWhiteSpace($manageBdeProtectionCheckError)) {
  Add-Finding -FindingList $findings -Code 'BLKR-ManageBdeProtectionCheckIssue' -Severity 'Medium' -Message ("manage-bde protection check issue: " + $manageBdeProtectionCheckError)
}

if ($cfg.UseManageBdeProtectionExitCode -and ($null -ne $manageBdeIsProtected) -and $vol) {
  $psProtected =
    if ($vol.ProtectionStatus -eq 'On') { $true }
    elseif ($vol.ProtectionStatus -eq 'Off') { $false }
    else { $null }

  if (($null -ne $psProtected) -and ($psProtected -ne $manageBdeIsProtected)) {
    Add-Finding -FindingList $findings -Code 'BLKR-ProtectionStateMismatch' -Severity 'Medium' -Message "Protection state mismatch between Get-BitLockerVolume and manage-bde exit code."
  }
}

# -------------------------
# Result object (pipeline output only)
# -------------------------
$result = [pscustomobject]@{
  ComputerName                = $env:COMPUTERNAME
  MountPoint                  = $mp
  Timestamp                   = (Get-Date)

  VolumeType                  = $(if ($vol) { $vol.VolumeType } else { $null })
  VolumeStatus                = $(if ($vol) { $vol.VolumeStatus } else { $null })
  ProtectionStatus            = $(if ($vol) { $vol.ProtectionStatus } else { $null })
  EncryptionPercentage        = $(if ($vol) { $vol.EncryptionPercentage } else { $null })
  AutoUnlockEnabled           = $(if ($vol) { $vol.AutoUnlockEnabled } else { $null })

  EncryptionMethod            = $(if ($vol) { $vol.EncryptionMethod } else { $null })
  LockStatus                  = $(if ($vol) { $vol.LockStatus } else { $null })
  CapacityGB                  = $(if ($vol) { $vol.CapacityGB } else { $null })
  MetadataVersion             = $(if ($vol) { $vol.MetadataVersion } else { $null })

  KeyProtectorTypes           = ($keyProtectorTypes -join ', ')
  KeyProtectorCount           = $keyProtectorCount
  KeyProtectorIds             = $(if ($cfg.IncludeKeyProtectorIds) { ($keyProtectorIds -join ', ') } else { $null })

  GetBitLockerVolumeError     = $gbvErrorText
  ManageBdeError              = $manageBdeErrorText

  ManageBdeProtectionExitCode = $manageBdeProtectionExitCode
  ManageBdeIsProtected        = $manageBdeIsProtected

  Findings                    = $(if ($findings.Count -gt 0) { (($findings | ForEach-Object { $_.Message }) -join ' | ') } else { '' })
}

if ($effectiveIncludeManageBdeText) {
  $result | Add-Member -NotePropertyName ManageBdeStatusText -NotePropertyValue $manageBdeText
}

# -------------------------
# Optional CSV export
# -------------------------
if (-not [string]::IsNullOrWhiteSpace($effectiveExportPath)) {
  $dir = Split-Path -Path $effectiveExportPath -Parent
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
  }
  $result | Export-Csv -Path $effectiveExportPath -NoTypeInformation -Encoding UTF8
}

# -------------------------
# Console summary (no pipeline pollution)
# -------------------------
if ($cfg.SummaryToHost) {
  # Write-UiLine supports ForegroundColor/BackgroundColor for human-friendly output. [web:154]
  Write-SummaryToConsole -Result $result -EffectiveExportPath $effectiveExportPath -PrettyConsole $cfg.PrettyConsole
}

# V2 output contract
$resultToken = if ($Strict -and $findings.Count -gt 0) { 'FAIL' } elseif ($findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = Get-V2ResultObject -ScriptName '23-BitLocker-Operations-Audit.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $findings) -Summary $result -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
