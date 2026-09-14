#requires -version 5.1
<#
.SYNOPSIS
  Audits and optionally remediates Windows Update policy registry settings to enforce a desired update source
  (Windows Update for Business or WSUS) and related policy intent, then writes a proof JSON and prints a
  human-readable summary.

.DESCRIPTION
  This script reads a "catalog" JSON (baseline/desired state) and compares it with the current Windows Update
  policy registry configuration under HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate (and subkeys).

  It can run in two modes:
  - Audit mode (default): Detects drift only and produces a DRIFT result when differences are found.
  - Remediation mode (-Mode Remediate): Applies idempotent registry changes to match the catalog and reports changes.

  The script always:
  - Collects evidence (selected registry values and basic OS information).
  - Writes a proof JSON file (path configurable in the catalog; safe defaults are used if missing/invalid).
  - Prints a colored console summary (intended for humans).

  Pipeline behavior:
  - By default, the script writes no objects to the pipeline (console output only).
  - With -PassThru, the script emits exactly one structured object suitable for Export-Csv/ConvertTo-Json/etc.

  Catalog loading behavior:
  - If -CatalogPath is provided, that file is used as the catalog.
  - Otherwise, -ConfigPath may be used to point to a configuration JSON that references a catalog path.
  - If no valid JSON can be loaded, built-in defaults are used so the script remains functional.

.PARAMETER CatalogPath
  Path to a baseline catalog JSON file describing the desired Windows Update policy intent.
  If the file doesn't exist or cannot be parsed, the script falls back to built-in defaults.

.PARAMETER ConfigPath
  Path to a configuration JSON file.
  The config may reference a catalog file path (for example: config.WUfB.CatalogPath).
  If the config doesn't exist or cannot be parsed, the script falls back to built-in defaults unless -CatalogPath
  was provided.

.PARAMETER Strict
  Changes result handling when drift is detected.
  - Without -Strict: drift is reported as DRIFT (useful for audit reporting without failing a pipeline).
  - With -Strict: drift is treated as WARNING and the script exits with a non-zero status code to signal attention.

.PARAMETER PassThru
  Emits one structured result object to the pipeline at the end of the run.
  The object includes the overall result, counts, proof path, evidence snapshot, the loaded catalog, and lists of
  drift/changes/notes.


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER Quiet
  Suppress console output.

.PARAMETER NoColor
  Disable colored output.

.OUTPUTS
  By default, this script outputs nothing to the pipeline (console output only).

  With -PassThru, this script outputs a single PSCustomObject with (at minimum) the following properties:
  - Time, Hostname
  - Result, Elevated, Remediate, Strict
  - HasDrift, DriftCount, ChangesCount, NotesCount
  - ProofPath, EventLog
  - Drift (string[]), Changes (string[]), Notes (string[])
  - Evidence (hashtable/object), Catalog (object), Operations (object[])

.EXAMPLE
  # Audit only using built-in defaults (no JSON required)
  .\05-WUFB-Proofing.ps1

.EXAMPLE
  # Audit using an explicit catalog JSON
  .\scripts\05-WUFB-Proofing.ps1 -CatalogPath .\examples\configs\wufb-proofing.json

.EXAMPLE
  # Audit using a config JSON that references a catalog path
  .\05-WUFB-Proofing.ps1 -ConfigPath $ConfigPath

.EXAMPLE
  # Remediate and show structured output for further processing
  .\scripts\05-WUFB-Proofing.ps1 -CatalogPath .\examples\configs\wufb-proofing.json -Mode Remediate -PassThru

.EXAMPLE
  # Integrate in reporting pipelines (one object only)
  .\05-WUFB-Proofing.ps1 -PassThru | ConvertTo-Json -Depth 6

.EXAMPLE
  # Export a single-run result to CSV (flattening may be required for nested properties)
  .\05-WUFB-Proofing.ps1 -PassThru | Select-Object Time,Hostname,Result,HasDrift,DriftCount,ChangesCount,ProofPath | Export-Csv -NoTypeInformation -Path $OutputPath

.NOTES
  Requires local administrator privileges only for operations that write to HKLM policy registry keys and for
  registering/writing to a Windows Event Log source (if enabled by the script).
  If not elevated, the script can still audit but remediation may fail and is reported accordingly.

  Exit codes:
  - 0 = OK, 2 = WARN, 1 = FAIL.

  Proof output:
  - A proof JSON is written even in error cases (best effort), using a safe fallback path when necessary.
#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$CatalogPath,
  [string]$ConfigPath,
  [switch]$Strict,
  [switch]$PassThru

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'internal/05-WUFB-Proofing.helpers.ps1')
. (Join-Path $PSScriptRoot 'internal/05-WUFB-Proofing.runtime.ps1')
$script:__V2Context = Initialize-V2Context -ScriptName '05-WUFB-Proofing.ps1' -BoundParameters $PSBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $true }
$Remediate = Initialize-WufbEntry -V2Context $script:__V2Context

$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $summary = New-WufbUnsupportedSummary -Mode $Mode
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '05-WUFB-Proofing.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

$script:Findings = Get-FindingsList

# -----------------------------
# Console helpers (no pipeline)
# -----------------------------





# -----------------------------
# Event log (best-effort)
# -----------------------------


# -----------------------------
# Security / registry / file helpers
# -----------------------------

# Test-IsAdmin imported from lib/Common.psm1

# Ensure-Key replaced by Ensure-RegistryKey from lib/Registry.psm1

$runState = New-WufbRunState -Remediate ([bool]$Remediate) -Strict ([bool]$Strict)
Write-WufbStart -Remediate ([bool]$Remediate)
Invoke-WufbRun -RunState $runState -CatalogPath $CatalogPath -ConfigPath $ConfigPath -Remediate ([bool]$Remediate) -Strict ([bool]$Strict)

# V2 output contract
$resultToken = Get-WufbResultToken -RunState $runState
$v2Result = Get-V2ResultObject -ScriptName '05-WUFB-Proofing.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary (New-WufbV2Summary -RunState $runState) -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
