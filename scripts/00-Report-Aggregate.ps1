#requires -version 5.1
<#
.SYNOPSIS
Aggregate v2 JSON result objects into one report.

.DESCRIPTION
Validates individual v2 result files before combining their findings and
summary data. Keeping aggregation schema-aware prevents malformed or unrelated
JSON from being presented as trusted security evidence.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory)][string[]]$InputPath,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [string]$ConfigPath,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1')
$reportAggregateHelperPath = Join-Path $PSScriptRoot 'internal/00-Report-Aggregate.helpers.ps1'
. $reportAggregateHelperPath

Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '00-Report-Aggregate.ps1' -BoundParameters $PSBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

# The post-bootstrap helper constructs the terminal Get-V2ResultObject. Its
# strict contract is that $Strict -and $resultToken -eq 'WARN' yields FAIL.
Invoke-ReportAggregate
