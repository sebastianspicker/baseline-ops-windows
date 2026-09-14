#requires -version 5.1
<#
.SYNOPSIS
  Audits Windows hardware security posture (TPM, Secure Boot, BitLocker, BIOS) and evaluates it against a simple baseline catalog.

.DESCRIPTION
  This script performs a local hardware security audit and produces:
  - A single structured result object on the success output stream (pipeline-friendly).
  - A human-readable, colorized console summary (written via Write-UiLine/Write-Information only).
  - A JSON “proof” file containing the full structured result.
  - A Windows Event Log entry in the Application log for monitoring/alerting.

  The baseline (expected values) is taken from a "catalog" JSON. If no catalog is provided or it cannot be loaded,
  built-in defaults are used automatically.

  Checks performed:
  - TPM:
    - Presence and basic identity (e.g., SpecVersion, Manufacturer)
    - Status: Owned, Enabled, Activated, Ready (queried via TPM provider methods where available)
    - Optional hint whether a firmware TPM is used (only if the property exists on the platform)
  - Secure Boot:
    - Determines if Secure Boot is enabled
  - BitLocker:
    - Determines if the OS volume is protected (ProtectionStatus)
    - Captures additional diagnostics (encryption percentage, volume status, method) for troubleshooting
  - BIOS:
    - Captures basic BIOS inventory fields (serial, version, vendor, release date)

.PARAMETER CatalogPath
  Optional path to a compliance catalog JSON file.
  If provided, it is the first source used for baseline settings.

  Expected catalog schema (example):
  {
    "TPM": {
      "MinVersion": "2.0",
      "OwnerRequired": true,
      "PCRsRequired": [7],
      "AllowFirmware": false,
      "BitLockerRequired": true,
      "SecureBootRequired": true
    },
    "Proof": {
      "OutFile": null
    }
  }

.PARAMETER ConfigPath
  Optional path to a configuration JSON file.
  If present and readable, the script looks for:
    Hardware.CatalogPath
  and uses that catalog if found.

  This provides a central indirection so that the catalog location can be controlled without changing the script.

.PARAMETER Strict
  When set, any detected drift forces the script to write a Warning event (EventId 4900).
  Without -Strict, a fully compliant result writes an Information event (EventId 4890) and a non-compliant result writes a Warning event (EventId 4900).


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER PassThru
  Emit structured v2 result object to pipeline.

.PARAMETER Quiet
  Suppress console output.

.PARAMETER NoColor
  Disable colored output.

.OUTPUTS
  System.Management.Automation.PSCustomObject

  The script writes exactly one object to the pipeline, with the following top-level properties:
  - Time     (string): Timestamp of the run.
  - Hostname (string): Computer name.
  - Context  (object): Execution context (user, admin status, PowerShell version, etc.).
  - Results  (object): Per-check results (TPM/SecureBoot/BitLocker/BIOS) plus:
      - OverallOk (bool): True when all required baseline checks pass.
      - Drifts    (string[]): Human-readable list of failed checks / deviations.
      - Notes     (string[]): Additional context (e.g., checks not implemented or data not available).
  - Errors   (string[]): Reserved for captured internal errors (when used).

  Example pipeline usage:
    $r = .\15-HardwareTPM-Audit.ps1
    $r.Results.OverallOk
    $r | ConvertTo-Json -Depth 10
    $r.Results.Drifts | Where-Object { $_ -match 'BitLocker' }

.NOTES
  Event logging:
  - The script writes to the Application log using a dedicated Source name.
  - If the Source cannot be created/used (for example due to permissions), the script falls back to writing the event message to the console.

  JSON proof file:
  - The proof file path is taken from the catalog (Proof.OutFile). If missing/unusable, a built-in default path is used.
  - The directory is created automatically if needed.

  Platform variability:
  - Some TPM provider properties (e.g., PCRBanks, firmware hint flags) are not guaranteed to exist on all systems.
    The script treats these as optional and records Notes when a requirement cannot be evaluated.

.EXAMPLE
  PS> .\15-HardwareTPM-Audit.ps1

  Runs with built-in default baseline settings and writes:
  - One result object to the pipeline
  - A console summary
  - A proof JSON file
  - An event log entry

.EXAMPLE
  PS> .\15-HardwareTPM-Audit.ps1 -CatalogPath $CatalogPath

  Runs using the specified baseline catalog JSON.

.EXAMPLE
  PS> .\15-HardwareTPM-Audit.ps1 -ConfigPath $ConfigPath

  Runs using the catalog referenced by Hardware.CatalogPath inside the config JSON (if present),
  otherwise falls back to built-in defaults.

.EXAMPLE
  PS> .\15-HardwareTPM-Audit.ps1 -Strict

  Runs with stricter event semantics: any drift results in a Warning event (EventId 4900).

.EXAMPLE
  PS> $result = .\15-HardwareTPM-Audit.ps1
  PS> if (-not $result.Results.OverallOk) { $result.Results.Drifts }

  Integrates the script into a larger automation pipeline without parsing console text.

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$CatalogPath,
  [switch]$Strict,
  [string]$ConfigPath

  ,
  [ValidateSet('Audit', 'Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console', 'Json', 'Csv', 'None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
function Import-HardwareAuditServices {
  Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
  Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
  Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
  Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
  Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
  Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


}
. Import-HardwareAuditServices

Set-StrictMode -Version Latest
function Get-HardwareV2Context {
  param($BoundParameters)
  return Initialize-V2Context -ScriptName '15-HardwareTPM-Audit.ps1' -BoundParameters $BoundParameters `
    -Values @{ Mode = $Mode
    ConfigPath = $ConfigPath
    OutputFormat = $OutputFormat
    OutputPath = $OutputPath
    PassThru = $PassThru
    Strict = $Strict
    Quiet = $Quiet
    NoColor = $NoColor
    DeriveRemediate = $false
  }
}
$script:__V2Context = Get-HardwareV2Context -BoundParameters $PSBoundParameters
if ($script:__V2Context.Quiet) {
  $InformationPreference = 'SilentlyContinue'
  $VerbosePreference = 'SilentlyContinue'
}
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

function Write-HardwareUnsupportedResult {
  param([string]$UnsupportedResult)
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp = Get-Date
    Mode = $Mode
    Supported = $false
    Notes = @('Skipped: this script is only supported on Windows hosts.')
  }
  $result = Get-V2ResultObject -ScriptName '15-HardwareTPM-Audit.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) {
    $result
  }
}

$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $unsupportedResult = if ($Strict) {
    'FAIL'
  }
  else {
    'WARN'
  }
  Write-HardwareUnsupportedResult -UnsupportedResult $unsupportedResult
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

$script:Findings = Get-FindingsList

. (Join-Path $PSScriptRoot 'internal/15-HardwareTPM-Audit.helpers.ps1')
$runState = New-HardwareRunState -Inputs @{CatalogPath = $CatalogPath
  ConfigPath = $ConfigPath
  Strict = $Strict
}
Invoke-HardwareAudit -RunState $runState

function Get-HardwareResultToken {
  param($RunState)
  return if ($RunState.errors.Count -gt 0 -or $RunState.fatalComplianceFailure) {
    'FAIL'
  }
  elseif ($script:Findings.Count -gt 0) {
    'WARN'
  }
  else {
    'OK'
  }
}

function Write-HardwareV2Result {
  param($RunState, [string]$ResultToken)
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp = Get-Date
    Drifts = $RunState.drifts.ToArray()
    Errors = $RunState.errors.ToArray()
    FatalComplianceFailure = $RunState.fatalComplianceFailure
    EventSourceSucceeded = $RunState.eventSourceOk
    EventWriteSucceeded = $RunState.eventWriteSucceeded
  }
  $v2Result = Get-V2ResultObject -ScriptName '15-HardwareTPM-Audit.ps1' -Mode $Mode -Result $resultToken -Findings $script:Findings.ToArray() -Summary $summary -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) {
    $v2Result
  }
}

# V2 output contract
$resultToken = Get-HardwareResultToken -RunState $RunState
Write-HardwareV2Result -RunState $RunState -ResultToken $resultToken
exit (Get-V2ExitCode -Result $resultToken)
