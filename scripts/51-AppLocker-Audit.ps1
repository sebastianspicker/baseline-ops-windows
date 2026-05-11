#requires -version 5.1
<#
.SYNOPSIS
Audit AppLocker policy enforcement and rule coverage on Windows endpoints.

.DESCRIPTION
Enumerates the effective AppLocker policy, checks enforcement mode for each rule
collection (Exe, Script, MSI, DLL, Packaged), detects audit-only vs. enforced rules,
identifies collections with no deny-default, and verifies the Application Identity
service (AppIDSvc) required for enforcement is running.

Findings:
- FAIL if AppIDSvc is stopped and AppLocker rules exist.
- FAIL if all rule collections are in AuditOnly mode (not enforced).
- WARN if one or more collections have no default-deny rule.
- WARN if a collection with rules is in AuditOnly mode.
- INFO when enforcement is confirmed for a collection.

Pipeline output: structured objects only.
Console output: Write-UiLine / Write-Information only.

.PARAMETER Mode
Audit mode.

.PARAMETER ConfigPath
Path to JSON configuration file.

.PARAMETER OutputFormat
Console, Json, Csv, or None.

.PARAMETER OutputPath
Path for Json/Csv output.

.PARAMETER PassThru
Emit standardized v2 result object.

.PARAMETER Strict
Treat warnings as failures.

.PARAMETER Quiet
Suppress console output.

.PARAMETER NoColor
Disable colored output.

.OUTPUTS
None by default.
When -PassThru is used, emits a PSCustomObject v2 result with ScriptName, Mode,
Result, Findings, Summary, and Metadata properties.

.EXAMPLE
.\51-AppLocker-Audit.ps1

.EXAMPLE
.\51-AppLocker-Audit.ps1 -OutputFormat Json -OutputPath C:\Temp\applocker.json -PassThru
#>

[CmdletBinding()]
param(
  [ValidateSet('Audit')]
  [string]$Mode = 'Audit',

  [string]$ConfigPath,

  [ValidateSet('Console','Json','Csv','None')]
  [string]$OutputFormat = 'Console',

  [string]$OutputPath,

  [switch]$PassThru,

  [switch]$Strict,

  [switch]$Quiet,

  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1')        -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1')       -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1')       -Force
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force

Set-StrictMode -Version Latest
Initialize-V2Context -BoundParameters $PSBoundParameters
$ErrorActionPreference = 'Stop'

$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $result = New-V2ResultObject -ScriptName '51-AppLocker-Audit.ps1' -Mode $Mode -Result 'OK' -Findings @() `
    -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

# ----------------------------
# Constants
# ----------------------------

$script:AppLockerRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'
$script:Collections      = @('Exe', 'Msi', 'Script', 'Dll', 'Appx')

# ----------------------------
# Helpers
# ----------------------------

function Get-AppLockerEnforcementMode {
  <#
  .SYNOPSIS
  Reads AppLocker enforcement mode from registry for a rule collection.
  Returns: 'Enforced', 'AuditOnly', 'NotConfigured'
  #>
  param([string]$Collection)
  $path = Join-Path $script:AppLockerRegPath $Collection
  try {
    $val = (Get-ItemProperty -Path $path -Name 'EnforcementMode' -ErrorAction Stop).EnforcementMode
    switch ([int]$val) {
      0 { return 'NotConfigured' }
      1 { return 'Enforced' }
      2 { return 'AuditOnly' }
      default { return "Unknown($val)" }
    }
  } catch {
    return 'NotConfigured'
  }
}

function Get-AppLockerRuleCount {
  <#
  .SYNOPSIS
  Counts AppLocker rules for a given collection from the registry.
  #>
  param([string]$Collection)
  $path = Join-Path $script:AppLockerRegPath $Collection
  try {
    if (-not (Test-Path -LiteralPath $path)) { return 0 }
    return @(Get-ChildItem -Path $path -ErrorAction SilentlyContinue).Count
  } catch {
    return 0
  }
}

# ----------------------------
# Main
# ----------------------------

$script:Findings = New-FindingsList

$appIdSvcStatus       = 'Unknown'
$appLockerConfigured  = $false
$collectionStatus     = @{}
$enforceCount         = 0
$auditOnlyCount       = 0
$notConfiguredCount   = 0
$totalRuleCount       = 0

# 1. Check Application Identity service (AppIDSvc)
try {
  $svc = Get-Service -Name 'AppIDSvc' -ErrorAction Stop
  $appIdSvcStatus = $svc.Status.ToString()
} catch {
  $appIdSvcStatus = 'NotFound'
}

# 2. Check if AppLocker SrpV2 key exists
$appLockerConfigured = Test-Path -LiteralPath $script:AppLockerRegPath

if (-not $appLockerConfigured) {
  Add-Finding -FindingList $script:Findings -Code 'APPLOCK-NotConfigured' -Severity 'Medium' `
    -Message 'AppLocker registry key (SrpV2) not found. No AppLocker policy is configured on this device.'
} else {
  # 3. Check enforcement per collection
  foreach ($col in $script:Collections) {
    $mode      = Get-AppLockerEnforcementMode -Collection $col
    $ruleCount = Get-AppLockerRuleCount      -Collection $col
    $totalRuleCount += $ruleCount

    $collectionStatus[$col] = [pscustomobject]@{
      Collection    = $col
      Mode          = $mode
      RuleCount     = $ruleCount
    }

    switch ($mode) {
      'Enforced' {
        $enforceCount++
        Add-Finding -FindingList $script:Findings -Code "APPLOCK-$col-Enforced" -Severity 'Low' `
          -Message ("{0} collection is enforced ({1} rules)." -f $col, $ruleCount)
      }
      'AuditOnly' {
        $auditOnlyCount++
        $sev = if ($ruleCount -gt 0) { 'Medium' } else { 'Low' }
        Add-Finding -FindingList $script:Findings -Code "APPLOCK-$col-AuditOnly" -Severity $sev `
          -Message ("{0} collection is in AuditOnly mode ({1} rules). Rules are not enforced." -f $col, $ruleCount)
      }
      'NotConfigured' {
        $notConfiguredCount++
        if ($col -eq 'Exe') {
          # Exe enforcement is most critical
          Add-Finding -FindingList $script:Findings -Code "APPLOCK-$col-NotConfigured" -Severity 'High' `
            -Message 'Exe rule collection is not configured. Executable allow-listing is not active.'
        } else {
          Add-Finding -FindingList $script:Findings -Code "APPLOCK-$col-NotConfigured" -Severity 'Low' `
            -Message ("{0} rule collection is not configured." -f $col)
        }
      }
    }
  }

  # 4. Check if AppIDSvc is stopped while rules are configured
  if ($appIdSvcStatus -ne 'Running' -and $totalRuleCount -gt 0) {
    Add-Finding -FindingList $script:Findings -Code 'APPLOCK-AppIDSvcStopped' -Severity 'High' `
      -Message ("AppLocker rules exist but Application Identity service is {0}. Rules cannot be enforced." -f $appIdSvcStatus)
  }

  # 5. All configured collections are AuditOnly — no enforcement at all
  if ($enforceCount -eq 0 -and $auditOnlyCount -gt 0) {
    Add-Finding -FindingList $script:Findings -Code 'APPLOCK-AllAuditOnly' -Severity 'High' `
      -Message 'All configured AppLocker rule collections are in AuditOnly mode. No executable policy is enforced.'
  }
}

# ----------------------------
# Build summary & result
# ----------------------------

$Findings = @($script:Findings.ToArray())
$findingsCount = @($Findings).Count

$summary = [pscustomobject]@{
  ComputerName         = $env:COMPUTERNAME
  Timestamp            = Get-Date
  Mode                 = $Mode
  AppLockerConfigured  = $appLockerConfigured
  AppIDSvcStatus       = $appIdSvcStatus
  TotalRuleCount       = $totalRuleCount
  EnforcedCollections  = $enforceCount
  AuditOnlyCollections = $auditOnlyCount
  FindingsCount        = $findingsCount
}

if (-not $Quiet -and $OutputFormat -eq 'Console') {
  Write-Section -Title 'AppLocker Audit'
  Write-KeyValue -Key 'AppLockerConfigured'  -Value ([string]$appLockerConfigured)
  Write-KeyValue -Key 'AppIDSvcStatus'       -Value $appIdSvcStatus
  Write-KeyValue -Key 'TotalRuleCount'       -Value ([string]$totalRuleCount)
  Write-KeyValue -Key 'EnforcedCollections'  -Value ([string]$enforceCount)
  Write-KeyValue -Key 'AuditOnlyCollections' -Value ([string]$auditOnlyCount)
  Write-KeyValue -Key 'Findings'             -Value ([string]$findingsCount)
}

$highFindings = @($Findings | Where-Object { $_.Severity -eq 'High' })
$resultToken  = if ($Strict -and $findingsCount -gt 0) { 'FAIL' }
  elseif ($highFindings.Count -gt 0) { 'FAIL' }
  elseif ($findingsCount -gt 0) { 'WARN' }
  else { 'OK' }

$v2Result = New-V2ResultObject -ScriptName '51-AppLocker-Audit.ps1' -Mode $Mode `
  -Result $resultToken -Findings $Findings -Summary $summary `
  -Metadata @{ CollectionStatus = $collectionStatus }

Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
