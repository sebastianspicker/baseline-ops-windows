#requires -version 5.1
<#
.SYNOPSIS
  Generates a timestamped support bundle (ZIP) that collects system diagnostics, selected Windows event logs, optional proof files, and optional Microsoft Defender information.

.DESCRIPTION
  This script is designed to create a single “support bundle” artifact for troubleshooting and incident triage.
  It builds a working directory under a configurable proof root, exports logs and reports into subfolders, writes a structured summary (JSON), and compresses everything into a ZIP file.

  The script supports two execution modes:
  - Triggered mode (default): runs only if a registry “Request” flag is set; this is intended for controlled/remote triggering.
  - Forced mode (-Force): bypasses the registry trigger and always runs.

  Configuration is optionally loaded from a JSON file.
  If the implicit JSON file is missing or invalid, the script continues with built-in defaults.
  An explicitly supplied invalid configuration fails closed.

  Output streams are separated by design:
  - Console: status, separators, and colored messages are written via Write-UiLine or Write-Information.
  - Pipeline: only structured objects are emitted, and only when -EmitObject is specified (enables clean Export-Csv/ConvertTo-Json/Where-Object usage).

.PARAMETER Force
  Bypasses the registry trigger and runs the bundle creation immediately.
  Use this for interactive troubleshooting or when the registry trigger mechanism is not used.

.PARAMETER Days
  Number of days to include when exporting event logs.
  The script attempts to export only events newer than the specified window.

.PARAMETER IncludeSecurity
  Includes the Security event log in the export list.
  This typically requires elevated execution; if not elevated, the script records a note and skips Security.

.PARAMETER IncludeDefenderSupport
  Collects additional Microsoft Defender diagnostics.
  This can include a Defender support CAB (if available) and Defender status/preference outputs.

.PARAMETER Reason
  Optional free-text reason for why the bundle was collected.
  The value is stored in the summary object and summary JSON for traceability.

.PARAMETER EmitObject
  When set, emits exactly one structured summary object to the pipeline at the end of the run.
  If not set (default), nothing is emitted to the pipeline (console-only run).

.PARAMETER UseInformationStream
  When set, writes console UI to the Information stream instead of using Write-UiLine.
  This can be useful if the calling environment wants to suppress/capture informational UI separately.


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
  By default, the script writes no objects to the pipeline.

  If -EmitObject is specified:
  - System.Management.Automation.PSCustomObject (Summary)
    Properties include:
    - Hostname, Time, User, Admin
    - DaysBack, IncludeSec, IncludeDef
    - ConfigPath, ProofDir, Reason
    - WorkDir, ZipPath
    - Records (array of step results with Name/Ok/ArtifactPath/Note/Error/Time)

.NOTES
  Registry trigger behavior:
  - When -Force is NOT used, the script reads
    HKLM:\SOFTWARE\BaselineOps\SupportBundle for a Request flag.
  - If Request is not set, the script exits early and still prints a console summary.
  - When a bundle is successfully created, the script attempts to reset the trigger flag and writes last bundle metadata.

  Bundle layout (high level):
  - <WorkDir>\eventlogs\        Exported .evtx and/or fallback .csv/.txt logs
  - <WorkDir>\reports\          Text and JSON reports (e.g., systeminfo, ipconfig, hotfix list)
  - <WorkDir>\proofs\           Copies of configured proof artifacts if paths exist
  - <WorkDir>\defender\         Defender status/preference (if available)
  - <WorkDir>\defender-support\ Defender support CAB (optional)
  - <WorkDir>\Summary.json      Structured summary saved inside the bundle

  Error handling:
  - Individual collection steps are recorded as success/failure records.
  - The script always attempts to print a final console summary (best effort), even if some steps fail.

.EXAMPLE
  # Default triggered execution (runs only if registry Request flag is set)
  .\09-SupportBundle.ps1

.EXAMPLE
  # Force execution (bypass registry trigger)
  .\09-SupportBundle.ps1 -Force

.EXAMPLE
  # Collect last 3 days of logs and include Security log (requires elevation)
  .\09-SupportBundle.ps1 -Force -Days 3 -IncludeSecurity

.EXAMPLE
  # Collect bundle including Defender diagnostics and emit a structured summary object
  $summary = .\09-SupportBundle.ps1 -Force -IncludeDefenderSupport -EmitObject
  $summary.Records | Where-Object { -not $_.Ok } | Export-Csv .\SupportBundleErrors.csv -NoTypeInformation

.EXAMPLE
  # Emit summary as JSON for automation pipelines
  .\09-SupportBundle.ps1 -Force -EmitObject | ConvertTo-Json -Depth 10

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [switch]$Force,

  [ValidateRange(1,365)]
  [int]$Days = 7,

  [switch]$IncludeSecurity,
  [switch]$IncludeDefenderSupport,

  [string]$Reason,

  # Interactive default: do not emit objects unless requested.
  [switch]$EmitObject,

  # Optional: write UI to information stream instead of host.
  [switch]$UseInformationStream

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [string]$ConfigPath,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
. (Join-Path $PSScriptRoot 'internal/09-SupportBundle.helpers.ps1')
. (Join-Path $PSScriptRoot 'internal/09-SupportBundle.runtime.ps1')

Set-StrictMode -Version Latest
Initialize-SupportBundleV2Context -BoundParameters $PSBoundParameters
if ($env:OS -ne 'Windows_NT') {
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = New-SupportBundleUnsupportedResult -ResultToken $unsupportedResult
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}
$script:EventSource = 'SupportBundle'

# -------------------- Main --------------------
$runState = Invoke-NewSupportBundleRun -BoundParameters $PSBoundParameters
$resultToken = $runState.ResultToken
$findings = @($runState.FailedRecords | ForEach-Object { SB_NewRecordFinding -Record $_ })
$v2Result = Get-V2ResultObject -ScriptName '09-SupportBundle.ps1' -Mode $Mode -Result $resultToken -Findings $findings -Summary $runState.Summary -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
