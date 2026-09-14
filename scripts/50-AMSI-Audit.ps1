#requires -version 5.1
<#
.SYNOPSIS
Audit AMSI (Antimalware Scan Interface) provider registration and bypass indicators.

.DESCRIPTION
Verifies that AMSI providers are registered and not tampered with, checks for known
AMSI bypass artifacts in the registry, and validates AMSI integration with PowerShell
and Windows Script Host scripting engines.

Findings:
- FAIL if the Windows Defender AMSI provider CLSID is missing or deregistered.
- FAIL if known AMSI bypass registry artifacts are detected.
- WARN if additional unexpected AMSI providers are registered (potential injection).
- WARN if Windows Script Host is disabled user-wide (suppresses AMSI scanning).
- INFO findings for each registered provider.

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
.\scripts\50-AMSI-Audit.ps1

.EXAMPLE
.\scripts\50-AMSI-Audit.ps1 -OutputFormat Json -OutputPath .\reports\amsi.json -PassThru
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
Import-Module (Join-Path $script:LibPath 'Output.psm1')       -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1')      -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1')      -Force
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force

Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '50-AMSI-Audit.ps1' -BoundParameters $PSBoundParameters `
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
  $result = Get-V2ResultObject -ScriptName '50-AMSI-Audit.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() `
    -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# ----------------------------
# Constants
# ----------------------------

# Windows Defender AMSI provider CLSID (well-known, documented by Microsoft)
function Invoke-Capability50MainPhase01 {
  param([hashtable]$RunState)
  $script:DefenderAmsiClsid = '{2781761E-28E0-4109-99FE-B9D127C57AFE}'

  # Registry paths
  $script:AmsiProvidersPath  = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
  $script:WshMachinePath     = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'
  $script:WshUserPath        = 'HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings'
  $script:PsLoggingPath      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'

  # ----------------------------
  # Main
  # ----------------------------

  $script:Findings = Get-FindingsList

  $RunState.registeredProviders   = @()
  $RunState.defenderPresent       = $false
  $RunState.wshMachineEnabled     = $null
  $RunState.wshUserEnabled        = $null
  $RunState.scriptBlockLogging    = $null
  $RunState.bypassArtifactsFound  = @()
}
function Invoke-Capability50MainPhase02 {
  param([hashtable]$RunState)
  try {
    if (Test-Path $script:AmsiProvidersPath) {
      $RunState.registeredProviders = @(Get-ChildItem -Path $script:AmsiProvidersPath -ErrorAction Stop |
        Select-Object -ExpandProperty PSChildName)

      foreach ($clsid in $RunState.registeredProviders) {
        . Add-AmsiProviderFinding -Clsid $clsid -RunState $RunState
      }

      if (-not $RunState.defenderPresent) {
        Add-Finding -FindingList $script:Findings -Code 'AMSI-DefenderMissing' -Severity 'High' `
          -Message ('Windows Defender AMSI provider CLSID {0} is not registered. AMSI scanning by Defender is disabled or the provider was removed.' `
            -f $script:DefenderAmsiClsid)
      }
    } else {
      Add-Finding -FindingList $script:Findings -Code 'AMSI-ProvidersKeyMissing' -Severity 'High' `
        -Message 'AMSI Providers registry key does not exist. AMSI may be disabled or the registry has been tampered with.'
    }
  } catch {
    Add-Finding -FindingList $script:Findings -Code 'AMSI-ProviderQueryFailed' -Severity 'Medium' `
      -Message ("Failed to query AMSI providers: {0}" -f $_.Exception.Message)
  }
}
function Add-AmsiProviderFinding {
  param([string]$Clsid, [hashtable]$RunState)
  if ($Clsid -eq $script:DefenderAmsiClsid) {
    $RunState.defenderPresent = $true
    Add-Finding -FindingList $script:Findings -Code 'AMSI-DefenderRegistered' -Severity 'Low' `
      -Message ("Windows Defender AMSI provider is registered ({0})." -f $Clsid)
    return
  }
  $providerName = try {
    (Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\$Clsid" -ErrorAction SilentlyContinue).'(default)'
  } catch { $null }
  $nameStr = if ($providerName) { " ($providerName)" } else { '' }
  Add-Finding -FindingList $script:Findings -Code 'AMSI-UnknownProvider' -Severity 'Medium' `
    -Message ("Unknown AMSI provider registered: {0}{1}. Verify this is an authorized security product." -f $Clsid, $nameStr)
}
function Invoke-Capability50MainPhase03 {
  param([hashtable]$RunState)
  $bypassChecks = @(
    @{
      Path    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
      Name    = 'AMSI_BYPASS'
      Code    = 'AMSI-BypassEnvVar'
      Message = 'AMSI_BYPASS environment variable found in the system environment; this may be a bypass artifact.'
    },
    @{
      Path    = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
      Name    = 'DisableAMSI'
      Code    = 'AMSI-PolicyDisabled'
      Message = 'Group Policy key DisableAMSI found under PowerShell policy; AMSI may be policy-disabled.'
    }
  )

  foreach ($check in $bypassChecks) {
    try {
      $val = Get-RegValue -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue
      if ($null -ne $val) {
        $RunState.bypassArtifactsFound += $check.Code
        Add-Finding -FindingList $script:Findings -Code $check.Code -Severity 'High' `
          -Message $check.Message
    }
  } catch {
    Write-Verbose ("AMSI bypass registry artifact query failed for '{0}\\{1}': {2}" -f $check.Path,$check.Name,$_.Exception.Message)
  }
  }
}
function Invoke-Capability50MainPhase04 {
  param([hashtable]$RunState)
  try {
    $sbEnabled = Get-RegValue -Path $script:PsLoggingPath -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue
    $RunState.scriptBlockLogging = ($null -ne $sbEnabled -and [int]$sbEnabled -eq 1)
    if (-not $RunState.scriptBlockLogging) {
      Add-Finding -FindingList $script:Findings -Code 'AMSI-PSLoggingOff' -Severity 'Medium' `
        -Message 'PowerShell Script Block Logging is not enabled. AMSI detections from PS scripts will not be logged in the event log.'
    } else {
      Add-Finding -FindingList $script:Findings -Code 'AMSI-PSLoggingOn' -Severity 'Low' `
        -Message 'PowerShell Script Block Logging is enabled.'
    }
  } catch {
    Add-Finding -FindingList $script:Findings -Code 'AMSI-PSLoggingQueryFailed' -Severity 'Low' `
      -Message ("Could not check Script Block Logging state: {0}" -f $_.Exception.Message)
  }
}
function Invoke-Capability50MainPhase05 {
  param([hashtable]$RunState)
  try {
    $RunState.wshMachineEnabled = Get-RegValue -Path $script:WshMachinePath -Name 'Enabled' -ErrorAction SilentlyContinue
    $RunState.wshUserEnabled    = Get-RegValue -Path $script:WshUserPath    -Name 'Enabled' -ErrorAction SilentlyContinue

    if ($null -ne $RunState.wshMachineEnabled -and [int]$RunState.wshMachineEnabled -eq 0) {
      Add-Finding -FindingList $script:Findings -Code 'AMSI-WSHDisabledMachine' -Severity 'Medium' `
        -Message 'Windows Script Host is disabled machine-wide (Enabled=0). AMSI cannot scan WSH scripts.'
    }
    if ($null -ne $RunState.wshUserEnabled -and [int]$RunState.wshUserEnabled -eq 0) {
      Add-Finding -FindingList $script:Findings -Code 'AMSI-WSHDisabledUser' -Severity 'Medium' `
        -Message 'Windows Script Host is disabled for the current user (HKCU Enabled=0). AMSI cannot scan WSH scripts for this user.'
    }
  } catch {
    Write-Verbose ("Windows Script Host AMSI registry query failed: {0}" -f $_.Exception.Message)
  }

  # ----------------------------
  # Build summary & result
  # ----------------------------

  $Findings = @($script:Findings.ToArray())
  $findingsCount = @($Findings).Count

  $RunState.summary = [pscustomobject]@{
    ComputerName         = $env:COMPUTERNAME
    Timestamp            = Get-Date
    Mode                 = $Mode
    RegisteredProviders  = $RunState.registeredProviders.Count
    DefenderAmsiPresent  = $RunState.defenderPresent
    BypassArtifacts      = $RunState.bypassArtifactsFound.Count
    PSScriptBlockLogging = $RunState.scriptBlockLogging
    FindingsCount        = $findingsCount
  }
}
function Invoke-Capability50MainPhase06 {
  param([hashtable]$RunState)
  if (-not $Quiet -and $OutputFormat -eq 'Console') {
    Write-Section -Title 'AMSI Audit'
    Write-KeyValue -Key 'RegisteredProviders'  -Value ([string]$RunState.registeredProviders.Count)
    Write-KeyValue -Key 'DefenderAmsiPresent'  -Value ([string]$RunState.defenderPresent)
    Write-KeyValue -Key 'BypassArtifacts'      -Value ([string]$RunState.bypassArtifactsFound.Count)
    Write-KeyValue -Key 'PSScriptBlockLogging' -Value ([string]$RunState.scriptBlockLogging)
    Write-KeyValue -Key 'Findings'             -Value ([string]$findingsCount)
  }

  $RunState.highFindings = @($Findings | Where-Object { $_.Severity -eq 'High' })
}
function Invoke-Capability50Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation)
  $RunState = @{

  }
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability50MainPhase01 -RunState $RunState
  . Invoke-Capability50MainPhase02 -RunState $RunState
  . Invoke-Capability50MainPhase03 -RunState $RunState
  . Invoke-Capability50MainPhase04 -RunState $RunState
  . Invoke-Capability50MainPhase05 -RunState $RunState
  . Invoke-Capability50MainPhase06 -RunState $RunState
  $script:RunState = $RunState
}

. Invoke-Capability50Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation
function Get-Capability50ResultToken {
  param([hashtable]$RunState)
  $resultToken  = if ($Strict -and $findingsCount -gt 0) { 'FAIL' }
    elseif ($RunState.highFindings.Count -gt 0) { 'FAIL' }
    elseif ($findingsCount -gt 0) { 'WARN' }
    else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability50ResultToken -RunState $RunState
$v2Result = Get-V2ResultObject -ScriptName '50-AMSI-Audit.ps1' -Mode $Mode `
  -Result $resultToken -Findings $Findings -Summary $RunState.summary `
  -Metadata @{ BypassArtifactCodes = $RunState.bypassArtifactsFound }

Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
