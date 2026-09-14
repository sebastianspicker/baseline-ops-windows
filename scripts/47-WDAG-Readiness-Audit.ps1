#requires -version 5.1
<#
.SYNOPSIS
Audit Windows Defender Application Guard readiness.

.DESCRIPTION
Checks whether the prerequisites for Windows Defender Application Guard (WDAG)
are met on the current system:
- Hyper-V feature installed (Microsoft-Hyper-V-All).
- WDAG feature installed (Windows-Defender-ApplicationGuard).
- WDAG policy settings via registry (HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI).
- Hardware virtualization support indicators.

Findings:
- INFO if required features are not available on this OS edition.
- WARN if features are available but not enabled.
- WARN if WDAG policies are not configured.

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
When -PassThru is used, emits a PSCustomObject v2 result with ScriptName, Mode, Result, Findings, Summary, and Metadata properties.

.EXAMPLE
.\47-WDAG-Readiness-Audit.ps1

.EXAMPLE
.\47-WDAG-Readiness-Audit.ps1 -OutputFormat Json -OutputPath C:\Temp\wdag.json -PassThru
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
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force -DisableNameChecking

Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '47-WDAG-Readiness-Audit.ps1' -BoundParameters $PSBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
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
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '47-WDAG-Readiness-Audit.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# ----------------------------
# Main
# ----------------------------

function Invoke-Capability47MainPhase01 {
  param([hashtable]$RunState)
  $script:Findings = Get-FindingsList

  $hyperVState      = $null
  $wdagState        = $null
  $RunState.hyperVAvailable  = $false
  $RunState.wdagAvailable    = $false
  $RunState.virtualizationOk = $false

  # 1. Check Hyper-V feature
  try {
    $hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Hyper-V-All' -ErrorAction Stop
    $hyperVState   = $hyperVFeature.State
    $RunState.hyperVAvailable = $true

    if ($hyperVState -ne 'Enabled') {
      Add-Finding -FindingList $script:Findings -Code 'WDAG-HyperVNotEnabled' -Severity 'Medium' `
        -Message ("Hyper-V feature is available but not enabled (State={0})." -f $hyperVState)
    } else {
      Add-Finding -FindingList $script:Findings -Code 'WDAG-HyperVEnabled' -Severity 'Low' `
        -Message 'Hyper-V feature is enabled.'
    }
  } catch {
    Add-Finding -FindingList $script:Findings -Code 'WDAG-HyperVNotAvailable' -Severity 'Low' `
      -Message ("Hyper-V feature query failed (may not be available on this edition): {0}" -f $_.Exception.Message)
  }

  # 2. Check WDAG feature
  try {
    $wdagFeature = Get-WindowsOptionalFeature -Online -FeatureName 'Windows-Defender-ApplicationGuard' -ErrorAction Stop
    $wdagState   = $wdagFeature.State
    $RunState.wdagAvailable = $true

    if ($wdagState -ne 'Enabled') {
      Add-Finding -FindingList $script:Findings -Code 'WDAG-FeatureNotEnabled' -Severity 'Medium' `
        -Message ("WDAG feature is available but not enabled (State={0})." -f $wdagState)
    } else {
      Add-Finding -FindingList $script:Findings -Code 'WDAG-FeatureEnabled' -Severity 'Low' `
        -Message 'Windows Defender Application Guard feature is enabled.'
    }
  } catch {
    Add-Finding -FindingList $script:Findings -Code 'WDAG-FeatureNotAvailable' -Severity 'Low' `
      -Message ("WDAG feature query failed (may not be available on this edition): {0}" -f $_.Exception.Message)
  }

  # 3. Check WDAG policy settings
  $RunState.wdagPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI'
  $RunState.wdagPolicies   = @{}
}
function Invoke-Capability47MainPhase02 {
  param([hashtable]$RunState)
  try {
    if (Test-Path -LiteralPath $RunState.wdagPolicyPath) {
      $policyProps = Get-ItemProperty -LiteralPath $RunState.wdagPolicyPath -ErrorAction Stop
      foreach ($prop in $policyProps.PSObject.Properties) {
        if ($prop.Name -notmatch '^PS') {
          $RunState.wdagPolicies[$prop.Name] = $prop.Value
        }
      }

      if ($RunState.wdagPolicies.Count -eq 0) {
        Add-Finding -FindingList $script:Findings -Code 'WDAG-PolicyEmpty' -Severity 'Medium' `
          -Message 'WDAG policy registry key exists but contains no configured values.'
      } else {
        Add-Finding -FindingList $script:Findings -Code 'WDAG-PolicyConfigured' -Severity 'Low' `
          -Message ("WDAG policy key has {0} configured value(s)." -f $RunState.wdagPolicies.Count)
      }
    } else {
      Add-Finding -FindingList $script:Findings -Code 'WDAG-PolicyMissing' -Severity 'Medium' `
        -Message 'WDAG policy registry key (AppHVSI) not found. WDAG policies are not configured via GPO/MDM.'
    }
  } catch {
    Add-Finding -FindingList $script:Findings -Code 'WDAG-PolicyReadFailed' -Severity 'Medium' `
      -Message ("Failed to read WDAG policy registry: {0}" -f $_.Exception.Message)
  }
}
function Invoke-Capability47MainPhase03 {
  param([hashtable]$RunState)
  try {
    $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
    if ($cpu) {
      $RunState.virtualizationOk = [bool]$cpu.VirtualizationFirmwareEnabled
      if (-not $RunState.virtualizationOk) {
        Add-Finding -FindingList $script:Findings -Code 'WDAG-VirtDisabled' -Severity 'Medium' `
          -Message 'Hardware virtualization is not enabled in firmware (VirtualizationFirmwareEnabled=false).'
      } else {
        Add-Finding -FindingList $script:Findings -Code 'WDAG-VirtEnabled' -Severity 'Low' `
          -Message 'Hardware virtualization is enabled in firmware.'
      }
    }
  } catch {
    Add-Finding -FindingList $script:Findings -Code 'WDAG-VirtQueryFailed' -Severity 'Low' `
      -Message ("Could not query virtualization support: {0}" -f $_.Exception.Message)
  }

  # ----------------------------
  # Build summary & result
  # ----------------------------

  $Findings      = @($script:Findings.ToArray())
  $findingsCount = @($Findings).Count

  $RunState.summary = [pscustomobject]@{
    ComputerName          = $env:COMPUTERNAME
    Timestamp             = Get-Date
    HyperVAvailable       = $RunState.hyperVAvailable
    HyperVState           = $hyperVState
    WDAGAvailable         = $RunState.wdagAvailable
    WDAGState             = $wdagState
    WDAGPolicyConfigured  = ($RunState.wdagPolicies.Count -gt 0)
    VirtualizationEnabled = $RunState.virtualizationOk
    FindingsCount         = $findingsCount
  }

  if (-not $Quiet -and $OutputFormat -eq 'Console') {
    Write-Section -Title 'WDAG Readiness Audit'
    Write-KeyValue -Key 'HyperV'          -Value ([string]$hyperVState)
    Write-KeyValue -Key 'WDAG'            -Value ([string]$wdagState)
    Write-KeyValue -Key 'Virtualization'  -Value ([string]$RunState.virtualizationOk)
    Write-KeyValue -Key 'Findings'        -Value ([string]$findingsCount)
  }
}
function Invoke-Capability47Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation)
  $RunState = @{

  }
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability47MainPhase01 -RunState $RunState
  . Invoke-Capability47MainPhase02 -RunState $RunState
  . Invoke-Capability47MainPhase03 -RunState $RunState
  $script:RunState = $RunState
}

. Invoke-Capability47Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation

function Get-Capability47ResultToken {
  $resultToken = if ($Strict -and $findingsCount -gt 0) { 'FAIL' }
    elseif (@($Findings | Where-Object { $_.Severity -eq 'High' }).Count -gt 0) { 'FAIL' }
    elseif (@($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count -gt 0) { 'WARN' }
    else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability47ResultToken
$v2Result = Get-V2ResultObject -ScriptName '47-WDAG-Readiness-Audit.ps1' -Mode $Mode `
  -Result $resultToken -Findings $Findings -Summary $RunState.summary `
  -Metadata @{ WDAGPolicies = $RunState.wdagPolicies }

Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
