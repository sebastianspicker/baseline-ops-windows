#requires -version 5.1
<#
.SYNOPSIS
  Collects endpoint artifacts and packages them into a structured incident-response bundle.

.DESCRIPTION
  This script gathers common forensic/IR artifacts from a Windows endpoint and writes them to a timestamped working
  directory, a JSON summary, and a ZIP bundle.

  Collection is normally gated by a trigger (registry value and/or file flag). Use -Force to run immediately.

  The script is designed for two consumers at once:
  - Console: a colorized summary with optional Top-N suspicious items.
  - Automation: structured outputs (CSV and JSON) that remain pipeline-friendly and easy to parse.

  Artifacts collected (high level):
  - Processes: PID, name, command line, executable path; optional SHA256 hashing; optional Authenticode info.
  - Network: TCP connections, listeners, UDP endpoints (best-effort), routing, IP configuration, DNS cache (best-effort).
  - Scheduled Tasks: flattened CSV; optional XML export for suspicious tasks.
  - WMI persistence: event filters, bindings, and multiple consumer types.
  - Autoruns: Run/RunOnce keys for HKLM and HKCU.
  - Samples (optional): copies selected executables into an evidence folder (size-limited and policy-controlled).

.PARAMETER CatalogPath
  Optional path to a JSON “catalog” that defines trigger locations and collection policies.

  OutputBase is constrained to the protected local evidence root
  C:\ProgramData\BaselineOpsForWindows\Evidence\IR-Grabber on Windows; remote, device,
  mapped-remote, and alternate local output roots are rejected.

  If provided, it overrides the built-in defaults and must exist and parse successfully. Invalid explicit input fails
  before any collection begins.

.PARAMETER ConfigPath
  Optional path to a JSON config file that can point to a catalog (for example, via a property like Grabber.CatalogPath).

  If CatalogPath is not specified, the script attempts to load a catalog reference via ConfigPath. An explicitly
  provided ConfigPath must parse successfully; a valid config without a catalog reference uses built-in defaults.

.PARAMETER Force
  Runs the script immediately, even if no registry/file trigger is present.

  Use this for manual/interactive runs or when a trigger mechanism is not deployed.

.PARAMETER CollectSamples
  Forces sample collection (copying files into the evidence folder) subject to the configured size limits
  and filtering rules.

  This is additive: it enables samples even if the trigger did not request samples.

.PARAMETER HashAllProcesses
  Hashes all process executable paths (when readable), not only “userland” paths.

  Note: hashing all processes increases runtime and I/O.

.PARAMETER Strict
  Makes the run more “fail loud” from an operational perspective by treating findings/errors as warnings for status/logging.
  Data collection still follows best-effort behavior where applicable.

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

.PARAMETER Quiet
  Suppress console output.

.PARAMETER NoColor
  Disable colored output.

.OUTPUTS
  This script writes files to disk and prints a human-readable summary to the host.

  Primary on-disk outputs (within the working directory):
  - Summary.json
    A structured summary object containing run metadata, counts, findings, errors/notes (if any), and optional Top-N items.
  - CSV files per collector (for example processes.csv, tasks.csv, network CSVs, autoruns CSVs, WMI CSVs).
  - Optional XML exports for suspicious scheduled tasks.
  - Optional evidence copies under a samples/ folder (policy-controlled).

  Final bundle:
  - A ZIP archive containing the full working directory content.

  Pipeline output:
  - None by default. All console formatting uses host output to keep the pipeline clean.

.EXAMPLE
  # Run using deployed triggers (registry/file flag)
  .\scripts\12-Suspicious-Artifact-Grabber.ps1

.EXAMPLE
  # Force a run (ignores triggers)
  .\scripts\12-Suspicious-Artifact-Grabber.ps1 -Force

.EXAMPLE
  # Force a run and enable sample collection
  .\scripts\12-Suspicious-Artifact-Grabber.ps1 -Force -CollectSamples

.EXAMPLE
  # Load a specific catalog JSON
  .\scripts\12-Suspicious-Artifact-Grabber.ps1 -CatalogPath "C:\ProgramData\BaselineOpsForWindows\grabber.catalog.json" -Force

.EXAMPLE
  # Hash all process images (more I/O)
  .\scripts\12-Suspicious-Artifact-Grabber.ps1 -Force -HashAllProcesses

.EXAMPLE
  # Automated usage: run and then consume the generated summary
  .\scripts\12-Suspicious-Artifact-Grabber.ps1 -Force
  Get-Content -Raw "$env:ProgramData\BaselineOpsForWindows\Evidence\IR-Grabber\<timestamp>\Summary.json" | ConvertFrom-Json

.NOTES
  Operational guidance:
  - Run from an elevated console if you expect restricted artifacts (some registry areas, task exports, event source creation)
    to be accessible.
  - Sample collection is intentionally constrained by size limits and filtering rules to reduce risk and volume.
  - Network and DNS cache collection are best-effort; availability varies by OS features and permissions.

  Using Get-Help:
  - Get full help:    Get-Help .\scripts\12-Suspicious-Artifact-Grabber.ps1 -Full
  - View examples:   Get-Help .\scripts\12-Suspicious-Artifact-Grabber.ps1 -Examples
#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$CatalogPath,
  [switch]$Force,
  [switch]$CollectSamples,
  [switch]$HashAllProcesses,
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
function Import-ArtifactServices {
  Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
  Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
  Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
  Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
  Import-Module (Join-Path $script:LibPath 'Evidence.psm1') -Force
  Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
  Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
  Import-Module (Join-Path $script:LibPath 'JsonCatalog.psm1') -Force
  Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


}
. Import-ArtifactServices

Set-StrictMode -Version Latest
function Get-ArtifactV2Context {
  param($BoundParameters)
  return Initialize-V2Context -ScriptName '12-Suspicious-Artifact-Grabber.ps1' -BoundParameters $BoundParameters `
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
$script:__V2Context = Get-ArtifactV2Context -BoundParameters $PSBoundParameters
if ($script:__V2Context.Quiet) {
  $InformationPreference = 'SilentlyContinue'
  $VerbosePreference = 'SilentlyContinue'
}
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

function Write-ArtifactUnsupportedResult {
  param([string]$UnsupportedResult)
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp = Get-Date
    Mode = $Mode
    Supported = $false
    Notes = @('Skipped: this script is only supported on Windows hosts.')
  }
  $result = Get-V2ResultObject -ScriptName '12-Suspicious-Artifact-Grabber.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
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
  Write-ArtifactUnsupportedResult -UnsupportedResult $unsupportedResult
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# Make Write-Information visible for humans; it is controlled by InformationPreference.
if (-not $Quiet) {
  $InformationPreference = 'Continue'
}

# -------------------------
# Globals
# -------------------------
$ScriptVersion = '2025.12.22-ps51'

# -------------------------
# Console helpers (no pipeline output)
# -------------------------




# -------------------------
# Logging helpers
# -------------------------


# -------------------------
# Generic helpers
# -------------------------

# Expand-Env imported from lib/Evidence.psm1

# Save-Json: using canonical Save-Json from lib/Serialization.psm1

# Read-Json replaced by Read-JsonFileSafe from lib/JsonCatalog.psm1

. (Join-Path $PSScriptRoot 'internal/12-Suspicious-Artifact-Grabber.helpers.ps1')

# -------------------------
# MAIN
# -------------------------
$script:Findings = Get-FindingsList

function New-ArtifactInvocationState {
  return New-ArtifactRunState -Inputs @{ ScriptVersion = $ScriptVersion
    CatalogPath = $CatalogPath
    ConfigPath = $ConfigPath
    Force = $Force
    CollectSamples = $CollectSamples
    HashAllProcesses = $HashAllProcesses
    Strict = $Strict
  }
}
$RunState = New-ArtifactInvocationState
Invoke-ArtifactCollection -RunState $RunState

function Get-ArtifactResultToken {
  param($RunState)
  return if ($RunState.errors.Count -gt 0) {
    'FAIL'
  }
  elseif ($RunState.hasFindings -or $script:Findings.Count -gt 0) {
    'WARN'
  }
  else {
    'OK'
  }
}

function Write-ArtifactV2Result {
  param($RunState, [string]$ResultToken)
  $v2Result = Get-V2ResultObject -ScriptName '12-Suspicious-Artifact-Grabber.ps1' -Mode $Mode -Result $resultToken -Findings $script:Findings.ToArray() -Summary $RunState.summary -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) {
    $v2Result
  }
}

# V2 output contract
$resultToken = Get-ArtifactResultToken -RunState $RunState
Write-ArtifactV2Result -RunState $RunState -ResultToken $resultToken
exit (Get-V2ExitCode -Result $resultToken)
