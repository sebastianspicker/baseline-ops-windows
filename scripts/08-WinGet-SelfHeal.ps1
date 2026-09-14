#requires -version 5.1
<#
.SYNOPSIS
  Performs a health check and optional self-healing actions for WinGet on a Windows device.
.DESCRIPTION
  This script validates a working WinGet environment and produces both:
  - A colorized console summary.
  - A structured, automation-friendly result object for the pipeline.
  The script is designed for enterprise automation scenarios (scheduled tasks, MDM, build workers),
  but can also be run interactively by administrators.
  High-level workflow:
  1) Load optional JSON configuration (if available) and merge with parameter overrides.
  2) Detect WinGet and validate the installed WinGet version against the built-in minimum.
  3) Check Microsoft Visual C++ Redistributables:
     - x64 is required (missing => Error).
     - x86 is optional (missing => Warning).
     In Remediate mode, if installer paths are available, the script attempts installation.
  4) Validate presence of a private WinGet source when RequirePrivateSource is enabled.
     In Remediate mode, the script can add the missing source from a validated name, URL, and type.
  5) In Remediate mode, run "winget source update" to refresh sources.
     A failure is Warning by default, or Error when -FailOnSourceUpdateError is set.
  6) Write a short audit message to the Windows Application Event Log (best-effort).
  7) Print a final console summary and return structured results to the pipeline.
  Output conventions:
  - Pipeline output is always structured objects only (no formatted strings).
  - Console output uses Write-UiLine / Write-Information only and is suppressed with -NoConsole.
.PARAMETER RequirePrivateSource
  Controls whether a private WinGet source is required for an overall "OK" status.
  - $true  : Missing private source => overall NOT OK.
  - $false : Private source check is marked as Skipped and does not influence overall status.
.PARAMETER ConfigPath
  Path to an optional JSON configuration file.
  If the file does not exist or cannot be parsed, the script continues with defaults and parameter
  overrides and marks the Config check as Warning.
  The JSON (if present) can provide an audit-only private source name.
  Remediation authority for installers and source endpoints is accepted only
  from explicit operator parameters.
.PARAMETER PrivateSourceName
  Sets/overrides the private WinGet source name.
  Use this when no JSON is available or when you want to override the JSON value.
.PARAMETER PrivateSourceUrl
  Sets/overrides the private WinGet source URL.
  Required as an explicit operator parameter when remediation may add a source.
  It must be an HTTPS endpoint path without credentials, query, or fragment
  components. Configure source authentication out of band through the
  organization-managed WinGet or OS credential mechanism.
.PARAMETER InstallerX64Path
  Explicit operator-selected path to the Microsoft x64 VC++ Redistributable installer.
  Configuration files cannot grant installer execution authority.
.PARAMETER InstallerX86Path
  Explicit operator-selected path to the Microsoft x86 VC++ Redistributable installer.
  Configuration files cannot grant installer execution authority.
.PARAMETER FailOnSourceUpdateError
  Controls how "winget source update" failures affect the overall result.
  - Not set: source update failure is recorded as Warning.
  - Set:     source update failure is recorded as Error (overall NOT OK).
.PARAMETER DiagnoseWingetErrors
  Adds extended error details for failing WinGet calls by running:
  "winget error --input <ExitCode>".
  This helps translate WinGet HRESULT-style return codes into readable messages.
.PARAMETER NoConsole
  Suppresses all console output.
  Use this for silent automation runs where only pipeline output is desired.
.PARAMETER PassThruRecords
  Changes pipeline output mode:
  - Not set (default): outputs one result object containing a Records array.
  - Set:              outputs each record in the Records array as a separate pipeline object.
.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.
  In Remediate mode, the script may install missing VC++ Redistributables and add a missing private WinGet source when configured.
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
  Default output (single object):
    PSCustomObject with:
    - Time                 : Timestamp of the run.
    - OverallStatus        : 'OK' or 'NOT_OK'.
    - Remediate            : Boolean indicating whether remediation was enabled.
    - RequirePrivateSource : Boolean indicating whether private source was required.
    - ConfigPath           : The configured (anonymized) config path used by the run.
    - WingetVersion        : Raw WinGet version string (when available).
    - Records              : Array of check records.
  With -PassThruRecords:
    PSCustomObject (one per check) with:
    - Time, Name, Status, Message, Data
.NOTES
  Exit codes:
  - 0 = OK, 2 = WARN, 1 = FAIL.
  Event Log:
  The script attempts to write an audit entry to the Windows Application event log.
  This is best-effort and does not fail the run if event log write access is unavailable.
  Configuration precedence:
  Parameter values override JSON values, and JSON values override built-in defaults.
.EXAMPLE
  PS C:\> .\08-WinGet-SelfHeal.ps1
  Runs health checks only (no remediation) and prints a console summary.
  Returns a single structured result object to the pipeline.
.EXAMPLE
  PS C:\> .\08-WinGet-SelfHeal.ps1 -NoConsole | ConvertTo-Json -Depth 6
  Runs in "pipeline-only" mode and emits a JSON report suitable for logging.
.EXAMPLE
  PS C:\> .\08-WinGet-SelfHeal.ps1 -Mode Remediate -PrivateSourceName $PrivateSourceName -PrivateSourceUrl $PrivateSourceUrl -DiagnoseWingetErrors
  Runs checks and attempts remediation.
  The source name and URL variables must contain reviewed organization values.
  If the private source is missing, the script attempts to add it.
  Also includes additional WinGet error decoding on failures.
.EXAMPLE
  PS C:\> .\08-WinGet-SelfHeal.ps1 -PassThruRecords | Where-Object Status -ne 'OK'
  Emits each record as a pipeline object and filters for non-OK results.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [bool]$RequirePrivateSource = $true,
  [string]$ConfigPath,
  [string]$PrivateSourceName = $null,
  [string]$PrivateSourceUrl  = $null,
  [string]$InstallerX64Path,
  [string]$InstallerX86Path,
  [switch]$FailOnSourceUpdateError,
  [switch]$DiagnoseWingetErrors,
  [switch]$NoConsole,
  [switch]$PassThruRecords
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
function Import-WinGetSelfHealServices {
  Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
  Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
  Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
  Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
  Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
  Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
  Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
  Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
}
. Import-WinGetSelfHealServices
function Initialize-WinGetSelfHealPresentation {
  $script:NoConsole = [bool]$NoConsole
  $script:PassThruRecords = [bool]$PassThruRecords
}
. Initialize-WinGetSelfHealPresentation
Set-StrictMode -Version Latest
function Get-WinGetSelfHealV2Context {
  param($BoundParameters)
  return Initialize-V2Context -ScriptName '08-WinGet-SelfHeal.ps1' -BoundParameters $BoundParameters `
    -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $true }
}
$script:__V2Context = Get-WinGetSelfHealV2Context -BoundParameters $PSBoundParameters
$Remediate = [bool]$script:__V2Context.Remediate
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$isWindowsHost = ($env:OS -eq 'Windows_NT')
function Write-WinGetSelfHealUnsupportedResult {
  param([string]$ResultToken)
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp = Get-Date
    Mode = $Mode
    Supported = $false
    Notes = @('Skipped: this script is only supported on Windows hosts.')
  }
  $result = Get-V2ResultObject -ScriptName '08-WinGet-SelfHeal.ps1' -Mode $Mode -Result $ResultToken -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
}
if (-not $isWindowsHost) {
  $resultToken = if ($Strict) { 'FAIL' } else { 'WARN' }
  Write-WinGetSelfHealUnsupportedResult -ResultToken $resultToken
  exit (Get-V2ExitCode -Result $resultToken)
}

# Capability-private record, process, source, and installer helpers.
. (Join-Path $PSScriptRoot 'internal/08-WinGet-SelfHeal.records.ps1')
. (Join-Path $PSScriptRoot 'internal/08-WinGet-SelfHeal.winget.ps1')
. (Join-Path $PSScriptRoot 'internal/08-WinGet-SelfHeal.install.ps1')
# ---------------- Console Helpers ----------------
# Get-StatusColor imported from lib/Console.psm1
# ---------------- Event Log Helpers ----------------
# ---------------- Structured Output Helpers ----------------






# ---------------- Config Helpers ----------------


# ---------------- WinGet Helpers ----------------









# ---------------- VC++ Helpers ----------------


# ---------------- Source Helpers ----------------




# ---------------- Main ----------------
. (Join-Path $PSScriptRoot 'internal/08-WinGet-SelfHeal.runtime.ps1')
$script:Findings = Get-FindingsList
$inputs = New-WinGetSelfHealInputs -BoundParameters $PSBoundParameters -DecisionContext $PSCmdlet -Remediate $Remediate
$runState = New-WinGetSelfHealState -Inputs $inputs
Invoke-WinGetSelfHeal -RunState $runState
$resultToken = $runState.ResultToken
$v2Summary = [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Mode = $Mode; OverallOk = $runState.OverallOk; Timestamp = Get-Date }
$v2Result = Get-V2ResultObject -ScriptName '08-WinGet-SelfHeal.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings.ToArray()) -Summary $v2Summary -Metadata @{ Records = $runState.Records.ToArray() }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
