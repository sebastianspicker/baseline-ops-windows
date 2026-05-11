#requires -version 5.1
<#
.SYNOPSIS
Run a categorized batch of scripts via profile orchestration.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [ValidateSet('All','Audit','Remediation','Collection','Utility','Monitoring')]
  [string]$Category = 'Audit',

  [ValidateSet('Audit','Remediate')]
  [string]$Mode = 'Audit',

  [string]$RootPath = 'C:\install\mdm\ps1',

  [switch]$ContinueOnError,

  [ValidateSet('Console','Json','Csv','None')]
  [string]$OutputFormat = 'Console',

  [string]$OutputPath,

  [switch]$PassThru,

  [switch]$Strict,

  [switch]$RequireSigned

,
  [string]$ConfigPath,
  [switch]$Quiet,
  [switch]$NoColor
)

Set-StrictMode -Version Latest
# v2-init
$null = $Mode, $ConfigPath, $OutputFormat, $OutputPath, $PassThru, $Strict, $Quiet, $NoColor
$script:__V2Context = @{
  Mode = $Mode
  ConfigPath = $ConfigPath
  OutputFormat = $OutputFormat
  OutputPath = $OutputPath
  PassThru = [bool]$PassThru
  Strict = [bool]$Strict
  Quiet = [bool]$Quiet
  NoColor = [bool]$NoColor
}
if ($Quiet) {
  $InformationPreference = 'SilentlyContinue'
  $VerbosePreference = 'SilentlyContinue'
}
if ($NoColor) {
  $script:NoColor = $true
}
$ErrorActionPreference = 'Stop'

$runProfilePath = Join-Path $PSScriptRoot '00-Run-Profile.ps1'
if (-not (Test-Path -LiteralPath $runProfilePath -PathType Leaf)) {
  throw "Missing Run-Profile script: $runProfilePath"
}

if ($RootPath -eq 'C:\install\mdm\ps1') {
  $repoRootCandidate = Split-Path -Parent $PSScriptRoot
  if (Test-Path -LiteralPath (Join-Path $repoRootCandidate 'scripts') -PathType Container) {
    $RootPath = $repoRootCandidate
  }
}

$categoryMap = @{
  Audit       = @('01','02','03','04','05','06','07','09','10','11','13','14','15','18','19','20','22','23','24','26','27','28','29','30','31','32','33','34','35','36','37','38','39','40','41','42','43','44','45')
  Remediation = @('01','02','03','04','05','06','07','08','13','14','16','18','21','22','25','31','32','33','38','39','40','44')
  Collection  = @('09','10','11','12','20')
  Utility     = @('08','25')
  Monitoring  = @('17','32','34','38')
}

$scriptsDir = Join-Path $RootPath 'scripts'
if (-not (Test-Path -LiteralPath $scriptsDir -PathType Container)) {
  throw "Scripts directory not found: $scriptsDir"
}

$allScripts = @(Get-ChildItem -LiteralPath $scriptsDir -Filter '*.ps1' -File | Where-Object { $_.Name -match '^\d{2}-' })
$selected = @()

if ($Category -eq 'All') {
  $selected = @($allScripts | Sort-Object Name | Select-Object -ExpandProperty Name)
} else {
  $prefixes = $categoryMap[$Category]
  foreach ($prefix in $prefixes) {
    $match = @($allScripts | Where-Object { $_.Name -like "$prefix-*" } | Select-Object -ExpandProperty Name)
    $selected += $match
  }
  $selected = @($selected | Sort-Object -Unique)
}

if ($selected.Count -eq 0) {
  throw "No scripts found for category '$Category'."
}

$batchProfile = [ordered]@{
  ProfileName = "batch-$($Category.ToLowerInvariant())"
  Version     = '2.0'
  Defaults    = [ordered]@{
    Mode         = $Mode
    Strict       = [bool]$Strict
    OutputFormat = 'Console'
    OutputPath   = $null
  }
  Steps        = @()
  Integrity    = [ordered]@{
    RequireSigned = [bool]$RequireSigned
    ExpectedHashes = @{}
  }
}

foreach ($scriptName in $selected) {
  $batchProfile.Steps += [ordered]@{
    Script          = $scriptName
    Args            = @()
    ContinueOnError = [bool]$ContinueOnError
    DependsOn       = @()
  }
}

$tempProfile = [System.IO.Path]::GetTempFileName()
$batchProfile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tempProfile -Encoding UTF8

try {
  if (-not $PSCmdlet.ShouldProcess("batch-$($Category.ToLowerInvariant())", "Execute $($selected.Count) scripts via profile")) {
    exit 0
  }

  $params = @{
    ProfilePath  = $tempProfile
    Mode         = $Mode
    RootPath     = $RootPath
    OutputFormat = $OutputFormat
    OutputPath   = $OutputPath
    Strict       = $Strict
    RequireSigned = $RequireSigned
  }
  if ($PassThru) { $params.PassThru = $true }
  if ($WhatIfPreference) { $params.WhatIf = $true }
  if ($PSBoundParameters.ContainsKey('Confirm')) { $params.Confirm = [bool]$PSBoundParameters['Confirm'] }

  & $runProfilePath @params
  $exitCode = $LASTEXITCODE
} finally {
  if (Test-Path -LiteralPath $tempProfile) {
    Remove-Item -LiteralPath $tempProfile -Force -ErrorAction SilentlyContinue
  }
}

if ($null -ne $exitCode) { exit [int]$exitCode }
exit 0
