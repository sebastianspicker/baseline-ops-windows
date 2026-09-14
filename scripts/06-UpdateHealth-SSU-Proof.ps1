#requires -version 5.1
<#
.SYNOPSIS
Generates a compliance-style proof report for Microsoft Update Health Tools (UHT), Servicing Stack (SSU), and core Windows Update services, with optional remediation.
.DESCRIPTION
This script inspects the local system for:
- Microsoft Update Health Tools (installation presence and version).
- The Update Health service (uhssvc) configuration and state.
- Update Health scheduled tasks under a configurable task folder.
- Servicing Stack (SSU) version evidence (best-effort detection).
- Core Windows Update related services (state and startup type evidence).
The script produces:
- A readable, colorized console summary (written only via host output).
- A JSON proof file with full evidence, notes, findings, and actions.
- A best-effort entry in the Windows Application Event Log (falls back to a text log file if Event Log write fails).
The pipeline output remains clean: the script emits exactly one structured object at the end, suitable for piping to Export-Csv, ConvertTo-Json, or Where-Object.
.PARAMETER CatalogPath
Optional path to a JSON catalog file that defines policy thresholds and proof output settings (for example minimum UHT/SSU versions, allowed service start modes, task folder, and proof output file path).
If CatalogPath is not specified or cannot be loaded, the script uses a built-in default catalog.
.PARAMETER Strict
Controls how the final status is calculated:
- If Strict is not set: only Findings affect the final Status.
- If Strict is set: Notes are treated as Findings for status evaluation (for example, missing config/catalog paths can raise the overall Status).
.PARAMETER ConfigPath
Optional path to a JSON configuration file.
If present and readable, the script looks for a catalog path at:
  UpdateHealth.CatalogPath
If ConfigPath is missing/invalid, or if it does not contain UpdateHealth.CatalogPath, the script continues with the built-in default catalog.
.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.
  In Remediate mode, the script attempts selected best-effort drift fixes:
  set/start/stop the Update Health service and enable scheduled tasks under the configured task folder.
  No software installation is performed by this script.
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
A single object is emitted to the pipeline with the following properties:
- Status: 'OK' or 'WARNING'
- CatalogSource: Indicates which catalog source was used (Default, CatalogPath, ConfigPath->CatalogPath)
- Remediate: Boolean indicating whether remediation was enabled
- Strict: Boolean indicating whether Strict mode was enabled
- IsAdmin: Boolean indicating whether the script ran elevated
- JsonPath: Path to the written JSON proof file (best-effort)
- Findings: Array of finding objects (Time, Area, Severity, Message)
- Actions: Array of action objects (Time, Target, Operation, Result, Message)
- Notes: Array of note objects (same schema as Findings)
- DurationMs: Execution time in milliseconds
.NOTES
Behavior and conventions:
- Console output is intended for humans and is written via host output only; it is not emitted into the pipeline.
- JSON output is written best-effort; if writing fails, a note is added and a fallback log entry may be created.
- Event logging is best-effort; if Event Log source creation or write fails, the script writes a line to a fallback text log file.
- Some checks rely on best-effort evidence (for example SSU detection); when evidence cannot be determined, the script reports an appropriate note/finding instead of failing.
Exit behavior:
- The script is designed to complete and return a structured result even when some probes fail.
- Unhandled exceptions are captured and recorded as a runtime note/finding, then included in the output object.
.EXAMPLE
PS C:\> .\06-UpdateHealth-SSU-Proof.ps1
Runs in audit mode using default catalog behavior.
Writes a console summary, attempts to write the JSON proof, attempts Event Log write, and returns one object to the pipeline.
.EXAMPLE
PS C:\> .\06-UpdateHealth-SSU-Proof.ps1 -CatalogPath $CatalogPath
Runs in audit mode using the specified catalog file.
.EXAMPLE
PS C:\> .\06-UpdateHealth-SSU-Proof.ps1 -ConfigPath $ConfigPath
Runs in audit mode and tries to load the catalog path from UpdateHealth.CatalogPath inside the config file.
Falls back to the built-in catalog if the config or referenced catalog is unavailable.
.EXAMPLE
PS C:\> .\06-UpdateHealth-SSU-Proof.ps1 -Mode Remediate
Runs in remediation mode (best-effort) and returns the actions taken in the output object.
.EXAMPLE
PS C:\> .\06-UpdateHealth-SSU-Proof.ps1 -Strict | Where-Object Status -ne 'OK'
Runs in strict mode and filters for non-OK outcomes using pipeline-safe output.
.EXAMPLE
PS C:\> .\06-UpdateHealth-SSU-Proof.ps1 | Select-Object Status,CatalogSource,JsonPath | Format-Table -AutoSize
Runs and displays only key output fields while preserving the full JSON proof file for details.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$CatalogPath,
  [switch]$Strict,
  [string]$ConfigPath,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Quiet,
  [switch]$NoColor
)
. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'internal/06-UpdateHealth-SSU-Proof.helpers.ps1')
. (Join-Path $PSScriptRoot 'internal/06-UpdateHealth-SSU-Proof.runtime.ps1')
$script:__V2Context = Initialize-V2Context -ScriptName '06-UpdateHealth-SSU-Proof.ps1' -BoundParameters $PSBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $true }
$Remediate = Initialize-UpdateHealthEntry -V2Context $script:__V2Context

$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $summary = New-UpdateHealthUnsupportedSummary -Mode $Mode
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '06-UpdateHealth-SSU-Proof.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

$script:EventSource = 'UpdateHealth-SSU-Proof'
$script:EventLog = 'Application'
$script:FallbackLog = $null
$script:Findings = Get-FindingsList
$defaultProofPath = Get-DefaultUpdateHealthProofPath
$defaultCatalog = Get-DefaultUpdateHealthCatalog
$runState = New-UpdateHealthRunState -DefaultProofPath $defaultProofPath
Invoke-UpdateHealthRun -RunState $runState -DefaultCatalog $defaultCatalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath -Remediate ([bool]$Remediate) -Strict ([bool]$Strict)

# V2 output contract
$v2Summary = New-UpdateHealthV2Summary -RunState $runState -Remediate ([bool]$Remediate) -Strict ([bool]$Strict)
$resultToken = Get-UpdateHealthResultToken -RunState $runState
$v2Result = Get-V2ResultObject -ScriptName '06-UpdateHealth-SSU-Proof.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $v2Summary -Metadata @{ Actions = @($runState.Actions); Notes = @($runState.Notes); CatalogSource = $runState.CatalogSource }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
