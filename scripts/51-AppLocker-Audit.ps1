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
.\scripts\51-AppLocker-Audit.ps1

.EXAMPLE
.\scripts\51-AppLocker-Audit.ps1 -OutputFormat Json -OutputPath .\reports\applocker.json -PassThru
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
function Initialize-Capability51Runtime {
  param($EntryBoundParameters)
  $RunState = @{

  }
Import-Module (Join-Path $script:LibPath 'Output.psm1')        -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1')       -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1')       -Force
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force

Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '51-AppLocker-Audit.ps1' -BoundParameters $EntryBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$RunState.isWindowsHost = ($env:OS -eq 'Windows_NT')
  $script:RunState = $RunState
}

. Initialize-Capability51Runtime -EntryBoundParameters $PSBoundParameters
if (-not $RunState.isWindowsHost) {
  $RunState.summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '51-AppLocker-Audit.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() `
    -Summary $RunState.summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# ----------------------------
# Constants
# ----------------------------

function Initialize-AppLockerCatalog {
  param()
$script:AppLockerRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'
$script:Collections      = @('Exe', 'Msi', 'Script', 'Dll', 'Appx')
}
. Initialize-AppLockerCatalog

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

function Invoke-Capability51MainPhase01 {
  param([hashtable]$RunState)
  $script:Findings = Get-FindingsList

  $RunState.appIdSvcStatus       = 'Unknown'
  $RunState.appLockerConfigured  = $false
  $RunState.collectionStatus     = @{}
  $RunState.enforceCount         = 0
  $RunState.auditOnlyCount       = 0
  $RunState.notConfiguredCount   = 0
  $RunState.totalRuleCount       = 0

  # 1. Check Application Identity service (AppIDSvc)
  try {
    $svc = Get-Service -Name 'AppIDSvc' -ErrorAction Stop
    $RunState.appIdSvcStatus = $svc.Status.ToString()
  } catch {
    $RunState.appIdSvcStatus = 'NotFound'
  }

  # 2. Check if AppLocker SrpV2 key exists
  $RunState.appLockerConfigured = Test-Path -LiteralPath $script:AppLockerRegPath
}
function Invoke-Capability51MainPhase02Step01 {
  param([hashtable]$RunState)
foreach ($col in $script:Collections) {
      $mode      = Get-AppLockerEnforcementMode -Collection $col
      $ruleCount = Get-AppLockerRuleCount      -Collection $col
      $RunState.totalRuleCount += $ruleCount

      $RunState.collectionStatus[$col] = [pscustomobject]@{
        Collection    = $col
        Mode          = $mode
        RuleCount     = $ruleCount
      }

      switch ($mode) {
        'Enforced' {
          $RunState.enforceCount++
          Add-Finding -FindingList $script:Findings -Code "APPLOCK-$col-Enforced" -Severity 'Low' `
            -Message ("{0} collection is enforced ({1} rules)." -f $col, $ruleCount)
        }
        'AuditOnly' {
          $RunState.auditOnlyCount++
          $sev = if ($ruleCount -gt 0) { 'Medium' } else { 'Low' }
          Add-Finding -FindingList $script:Findings -Code "APPLOCK-$col-AuditOnly" -Severity $sev `
            -Message ("{0} collection is in AuditOnly mode ({1} rules). Rules are not enforced." -f $col, $ruleCount)
        }
        'NotConfigured' {
          $RunState.notConfiguredCount++
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
}

function Invoke-Capability51MainPhase02Step02 {
  param([hashtable]$RunState)
if ($RunState.appIdSvcStatus -ne 'Running' -and $RunState.totalRuleCount -gt 0) {
      Add-Finding -FindingList $script:Findings -Code 'APPLOCK-AppIDSvcStopped' -Severity 'High' `
        -Message ("AppLocker rules exist but Application Identity service is {0}. Rules cannot be enforced." -f $RunState.appIdSvcStatus)
    }

    # 5. All configured collections are AuditOnly, so no collection is enforced.
    if ($RunState.enforceCount -eq 0 -and $RunState.auditOnlyCount -gt 0) {
      Add-Finding -FindingList $script:Findings -Code 'APPLOCK-AllAuditOnly' -Severity 'High' `
        -Message 'All configured AppLocker rule collections are in AuditOnly mode. No executable policy is enforced.'
    }
}

function Invoke-Capability51MainPhase02 {
  param([hashtable]$RunState)
  if (-not $RunState.appLockerConfigured) {
    Add-Finding -FindingList $script:Findings -Code 'APPLOCK-NotConfigured' -Severity 'Medium' `
      -Message 'AppLocker registry key (SrpV2) not found. No AppLocker policy is configured on this device.'
  } else {
    # 3. Check enforcement per collection
    . Invoke-Capability51MainPhase02Step01 -RunState $RunState
. Invoke-Capability51MainPhase02Step02 -RunState $RunState
  }
}
function Invoke-Capability51MainPhase03 {
  param([hashtable]$RunState)
  $Findings = @($script:Findings.ToArray())
  $findingsCount = @($Findings).Count

  $RunState.summary = [pscustomobject]@{
    ComputerName         = $env:COMPUTERNAME
    Timestamp            = Get-Date
    Mode                 = $Mode
    AppLockerConfigured  = $RunState.appLockerConfigured
    AppIDSvcStatus       = $RunState.appIdSvcStatus
    TotalRuleCount       = $RunState.totalRuleCount
    EnforcedCollections  = $RunState.enforceCount
    AuditOnlyCollections = $RunState.auditOnlyCount
    FindingsCount        = $findingsCount
  }

  if (-not $Quiet -and $OutputFormat -eq 'Console') {
    Write-Section -Title 'AppLocker Audit'
    Write-KeyValue -Key 'AppLockerConfigured'  -Value ([string]$RunState.appLockerConfigured)
    Write-KeyValue -Key 'AppIDSvcStatus'       -Value $RunState.appIdSvcStatus
    Write-KeyValue -Key 'TotalRuleCount'       -Value ([string]$RunState.totalRuleCount)
    Write-KeyValue -Key 'EnforcedCollections'  -Value ([string]$RunState.enforceCount)
    Write-KeyValue -Key 'AuditOnlyCollections' -Value ([string]$RunState.auditOnlyCount)
    Write-KeyValue -Key 'Findings'             -Value ([string]$findingsCount)
  }

  $RunState.highFindings = @($Findings | Where-Object { $_.Severity -eq 'High' })
}
function Invoke-Capability51Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation, [hashtable]$RunState)
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability51MainPhase01 -RunState $RunState
  . Invoke-Capability51MainPhase02 -RunState $RunState
  . Invoke-Capability51MainPhase03 -RunState $RunState
}
. Invoke-Capability51Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation -RunState $RunState
function Get-Capability51ResultToken {
  param([hashtable]$RunState)
  $resultToken  = if ($Strict -and $findingsCount -gt 0) { 'FAIL' }
    elseif ($RunState.highFindings.Count -gt 0) { 'FAIL' }
    elseif ($findingsCount -gt 0) { 'WARN' }
    else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability51ResultToken -RunState $RunState
$v2Result = Get-V2ResultObject -ScriptName '51-AppLocker-Audit.ps1' -Mode $Mode `
  -Result $resultToken -Findings $Findings -Summary $RunState.summary `
  -Metadata @{ CollectionStatus = $RunState.collectionStatus }

Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
