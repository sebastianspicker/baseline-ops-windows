#requires -version 5.1
<#
.SYNOPSIS
Validate a v2 execution profile JSON.

.DESCRIPTION
Performs structural validation for profile files used by 00-Run-Profile.ps1.

.PARAMETER ProfilePath
Path to the profile JSON file.

.PARAMETER OutputFormat
Console, Json, Csv, or None.

.PARAMETER OutputPath
Output file path for Json/Csv formats.

.PARAMETER PassThru
Emit standardized result object to pipeline.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory)][string]$ProfilePath,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$RootPath,
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
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force
$validateProfileHelperPath = Join-Path $PSScriptRoot 'internal/00-Validate-Profile.helpers.ps1'
$script:validateProfileScriptsRoot = $PSScriptRoot
. $validateProfileHelperPath

Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '00-Validate-Profile.ps1' -BoundParameters $PSBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'
$script:issues = New-Object System.Collections.ArrayList

# Compatibility contract: the helper constructs Get-V2ResultObject and promotes
# WARN when $Strict -and $resultToken -eq 'WARN'.
Invoke-ValidateProfile
