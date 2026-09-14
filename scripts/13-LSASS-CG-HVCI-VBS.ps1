#requires -version 5.1
<#
.SYNOPSIS
  Audits and (optionally) remediates Windows hardening controls related to LSASS protection, virtualization-based security, and driver abuse prevention.

.DESCRIPTION
  This script evaluates several Windows security features that help protect credentials and reduce kernel attack surface:
  - LSASS PPL (LSA Protection): checks whether LSASS is configured to run as a protected process.
  - Credential Guard: checks both registry configuration and runtime state (via Device Guard runtime data).
  - VBS (Virtualization-Based Security): checks registry configuration and whether VBS is actually running.
  - HVCI / Memory Integrity: checks registry configuration and runtime state.
  - Microsoft Vulnerable Driver Blocklist: checks whether the blocklist is enabled.

  The script can run in two modes:
  - Audit mode (default): reads configuration and runtime state and returns a single structured result object.
  - Remediation mode (-Mode Remediate): applies a baseline configuration (idempotent) and reports whether a reboot is required.

  Output behavior:
  - Pipeline output is always exactly ONE structured object (suitable for Export-Csv / ConvertTo-Json / Where-Object).
  - A colorized console summary is printed at the end without writing to the pipeline.
  - A detailed, plain-text summary is written to the Windows Event Log.

.PARAMETER Strict
  Controls pass/fail semantics:
  - When Strict is True (default), the script is compliant only if VBS is running AND Credential Guard and HVCI are running.
  - When Strict is False, the script accepts "configured" (registry or runtime configured) even if not currently running.

  Use Strict=True for enforcement/compliance.
  Use Strict=False for staged rollouts where configuration may be present but runtime activation is pending.

.PARAMETER RequireBlockList
  When True (default), the script is compliant only if the Microsoft Vulnerable Driver Blocklist is enabled.
  When False, blocklist state is reported but does not affect overall compliance.

.PARAMETER ConfigPath
  Optional path to a JSON configuration file to override defaults such as:
  - EventSource / EventLog name
  - Strict / RequireBlockList default behavior
  - Baseline registry values applied by Remediate mode
  - Console output colors

  If the JSON file is missing or invalid, the script continues with built-in defaults.

.INPUTS
  None. This script does not accept pipeline input.


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.
  In Remediate mode, the script applies baseline registry settings for the checked controls.
  The script does not force a reboot; it only reports RebootRequired=True when changes were made.

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

  The script writes exactly one object to the pipeline with (high-level) fields such as:
  - ComputerName, TimestampUtc
  - Strict, RequireBlockList, RemediateRequested, IsAdmin
  - Registry state (e.g., LsaCfgFlags, EnableVirtualizationBasedSecurity, HVCI Enabled, Blocklist value)
  - Runtime state (Device Guard security services configured/running, VBS status)
  - Compliant (bool), Issues (string[]), Warnings (string[])
  - RemediationPerformed (bool), RemediationActions (string[]), RebootRequired (bool)
  - ExitCode and EventId; process exit codes are 0=OK, 2=WARN, 1=FAIL

  This enables examples like:
    .\Script.ps1 | ConvertTo-Json -Depth 5
    .\Script.ps1 | Export-Csv .\report.csv -NoTypeInformation
    .\Script.ps1 | Where-Object { -not $_.Compliant }

.EXAMPLE
  PS> .\13-LSASS-CG-HVCI-VBS.ps1

  Runs an audit only. Prints a console summary and returns a single result object to the pipeline.

.EXAMPLE
  PS> .\13-LSASS-CG-HVCI-VBS.ps1 -Mode Remediate

  Applies baseline registry values (if not blocked by policy), reports the actions taken and whether a reboot is required.

.EXAMPLE
  PS> .\13-LSASS-CG-HVCI-VBS.ps1 -Strict:$false

  Runs in non-strict mode. Useful during rollout to distinguish "configured" from "running".

.EXAMPLE
  PS> .\13-LSASS-CG-HVCI-VBS.ps1 -RequireBlockList:$false

  Audits blocklist state but does not fail compliance if the blocklist is disabled.

.EXAMPLE
  PS> .\13-LSASS-CG-HVCI-VBS.ps1 -ConfigPath $ConfigPath -Mode Remediate | ConvertTo-Json -Depth 6

  Loads settings from JSON (if present) and runs remediation. The structured output is serialized to JSON for logging or upload.

.NOTES
  Policy awareness:
  - If a Device Guard policy key is detected, remediation is skipped to avoid writing conflicting settings.
    The script continues auditing and will report a warning explaining why remediation did not run.

  Permissions:
  - Remediation requires administrative privileges to write to HKLM.
  - Event source creation may require administrative privileges; if unavailable, event logging may fall back to console output.

  Reboot behavior:
  - Many of the security controls checked by this script only fully activate after a reboot.
    The script reports RebootRequired=True when it changes registry configuration that typically requires reboot.

  Operational guidance:
  - Treat Remediate mode as a configuration change: pilot first, ensure rollback options, and schedule reboots.
  - Use the pipeline object for automation; use the console summary for interactive runs.

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [bool]$Strict = $true,
  [bool]$RequireBlockList = $true,
  [string]$ConfigPath,
  [ValidateSet('Audit', 'Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console', 'Json', 'Csv', 'None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
function Import-CredentialServices {
  Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
  Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
  Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force -DisableNameChecking
  Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
  Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
  Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force

}
. Import-CredentialServices

Set-StrictMode -Version Latest
function Get-CredentialV2Context {
  param($BoundParameters)
  return Initialize-V2Context -ScriptName '13-LSASS-CG-HVCI-VBS.ps1' -BoundParameters $BoundParameters `
    -Values @{ Mode = $Mode
    ConfigPath = $ConfigPath
    OutputFormat = $OutputFormat
    OutputPath = $OutputPath
    PassThru = $PassThru
    Strict = $Strict
    Quiet = $Quiet
    NoColor = $NoColor
    DeriveRemediate = $true
  }
}
$script:__V2Context = Get-CredentialV2Context -BoundParameters $PSBoundParameters
$Remediate = [bool]$script:__V2Context.Remediate
if ($script:__V2Context.Quiet) {
  $InformationPreference = 'SilentlyContinue'
  $VerbosePreference = 'SilentlyContinue'
}
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

function Write-CredentialUnsupportedResult {
  param([string]$UnsupportedResult)
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp = Get-Date
    Mode = $Mode
    Supported = $false
    Notes = @('Skipped: this script is only supported on Windows hosts.')
  }
  $result = Get-V2ResultObject -ScriptName '13-LSASS-CG-HVCI-VBS.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
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
  Write-CredentialUnsupportedResult -UnsupportedResult $unsupportedResult
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# -----------------------------
# Helper functions (PS 5.1 compatible)
# -----------------------------

. (Join-Path $PSScriptRoot 'internal/13-LSASS-CG-HVCI-VBS.helpers.ps1')
$script:Findings = Get-FindingsList
$RunState = New-CredentialRunState -Inputs @{ConfigPath = $ConfigPath
  Strict = $Strict
  RequireBlockList = $RequireBlockList
  Remediate = $Remediate
  BoundParameters = $PSBoundParameters
  DecisionContext = $PSCmdlet
}
Invoke-CredentialAudit -RunState $RunState

function Get-CredentialResultToken {
  param($RunState)
  return if ($RunState.result.ExitCode -ne 0) {
    'FAIL'
  }
  elseif ($script:Findings.Count -gt 0) {
    'WARN'
  }
  else {
    'OK'
  }
}

function Write-CredentialV2Result {
  param($RunState, [string]$ResultToken)
  $v2Result = Get-V2ResultObject -ScriptName '13-LSASS-CG-HVCI-VBS.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $RunState.result -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) {
    $v2Result
  }

}

# V2 output contract
$resultToken = Get-CredentialResultToken -RunState $RunState
Write-CredentialV2Result -RunState $RunState -ResultToken $resultToken
exit (Get-V2ExitCode -Result $resultToken)
