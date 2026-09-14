#requires -version 5.1
<#
.SYNOPSIS
  Sweeps the local Windows host for IOC indicators, optional Defender scans, and optional evidence collection.
.DESCRIPTION
  Loads an IOC catalog from -CatalogPath, ConfigPath -> IOC.CatalogPath, or built-in defaults. Checks files, file globs, registry values, services, scheduled tasks, processes, remote IPs, and DNS cache domains. Remediate mode applies catalog-requested non-destructive containment actions.
.PARAMETER CatalogPath
  Path to an IOC catalog JSON file.
.PARAMETER ConfigPath
  Configuration JSON that can provide IOC.CatalogPath.
.PARAMETER ScanType
  Defender scan type: Full, Quick, or None.
.PARAMETER CustomScanPaths
  Defender custom scan paths used when ScanType is None.
.PARAMETER CollectEvidence
  Copy matched files and export matched registry keys into the evidence directory.
.PARAMETER Strict
  Treat a no-finding run as noteworthy for compliance/audit signaling.
.PARAMETER PassThru
  Emit the final proof object to the success pipeline.
.PARAMETER Mode
  Audit reports only; Remediate applies catalog-requested containment.
.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.
.PARAMETER OutputPath
  File path for Json/Csv output.
.PARAMETER Quiet
  Suppress console output.
.PARAMETER NoColor
  Disable colored output.
.OUTPUTS
  By default, none. With -PassThru, emits the structured proof object.
.NOTES
  Process exit codes: 0 = OK, 2 = WARN, 1 = FAIL. Evidence collection failures are recorded in Proof.Errors.
.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1
.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1 -CatalogPath $CatalogPath -CollectEvidence
.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1 -ScanType Quick
.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1 -ScanType None -CustomScanPaths "C:\Temp","C:\Users\Public" -CollectEvidence
.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1 -Mode Remediate -Strict
.EXAMPLE
  $proof = .\11-IOC-Sweep-Defender.ps1 -PassThru
  $proof.Findings.Files | Where-Object { $_.Signed -eq $false } | ConvertTo-Json -Depth 5
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$CatalogPath,
  [switch]$CollectEvidence,
  [ValidateSet('Quick','Full','None')] [string]$ScanType = 'Full',
  [string[]]$CustomScanPaths,
  [switch]$Strict,
  [string]$ConfigPath,
  [switch]$PassThru,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$Quiet,
  [switch]$NoColor
)
function Get-IocUnsupportedSummary {
  param([string]$Mode)
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  return $summary
}

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Evidence.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'JsonCatalog.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
$script:__V2Context = Initialize-V2Context -ScriptName '11-IOC-Sweep-Defender.ps1' -BoundParameters $PSBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $true }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') {
  $summary = Get-IocUnsupportedSummary -Mode $Mode
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '11-IOC-Sweep-Defender.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

. (Join-Path $PSScriptRoot 'internal/11-IOC-Sweep-Defender.helpers.ps1')
Initialize-IocRuntimeContext


Set-StrictMode -Version Latest
# -----------------------------
# Globals / Defaults (anonymized)
# -----------------------------
# -----------------------------
# Console helpers (host-only)
# -----------------------------
# -----------------------------
# Core helpers
# -----------------------------
# Save-Json: using canonical Save-Json from lib/Serialization.psm1
# Expand-Env imported from lib/Evidence.psm1
# Read-Json replaced by Read-JsonFileSafe from lib/JsonCatalog.psm1
# -----------------------------
# Sweep orchestration and terminal v2 contract
# -----------------------------
$script:IocRun = New-IocRunState -PublicCmdlet $PSCmdlet
if (-not (Ensure-EventSource)) { Write-Warning 'EventSource could not be registered. EventLog tracing will be unavailable.' }
Invoke-IocSweepWork
$summaryState = Set-IocRunSummary
Write-IocRunConsole -Summary $summaryState
$resultToken = Get-IocResultToken -Summary $summaryState
$v2Result = Get-V2ResultObject -ScriptName '11-IOC-Sweep-Defender.ps1' -Mode $Mode -Result $resultToken -Findings $script:IocRun.Findings.ToArray() -Summary $script:IocRun.Proof -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
