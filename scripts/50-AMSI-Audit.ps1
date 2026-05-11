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
.\50-AMSI-Audit.ps1

.EXAMPLE
.\50-AMSI-Audit.ps1 -OutputFormat Json -OutputPath C:\Temp\amsi.json -PassThru
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
  $result = New-V2ResultObject -ScriptName '50-AMSI-Audit.ps1' -Mode $Mode -Result 'OK' -Findings @() `
    -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

# ----------------------------
# Constants
# ----------------------------

# Windows Defender AMSI provider CLSID (well-known, documented by Microsoft)
$script:DefenderAmsiClsid = '{2781761E-28E0-4109-99FE-B9D127C57AFE}'

# Registry paths
$script:AmsiProvidersPath  = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
$script:WshMachinePath     = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'
$script:WshUserPath        = 'HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings'
$script:PsLoggingPath      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'

# ----------------------------
# Main
# ----------------------------

$script:Findings = New-FindingsList

$registeredProviders   = @()
$defenderPresent       = $false
$wshMachineEnabled     = $null
$wshUserEnabled        = $null
$scriptBlockLogging    = $null
$bypassArtifactsFound  = @()

# 1. Enumerate AMSI providers
try {
  if (Test-Path $script:AmsiProvidersPath) {
    $registeredProviders = @(Get-ChildItem -Path $script:AmsiProvidersPath -ErrorAction Stop |
      Select-Object -ExpandProperty PSChildName)

    foreach ($clsid in $registeredProviders) {
      if ($clsid -eq $script:DefenderAmsiClsid) {
        $defenderPresent = $true
        Add-Finding -FindingList $script:Findings -Code 'AMSI-DefenderRegistered' -Severity 'Low' `
          -Message ("Windows Defender AMSI provider is registered ({0})." -f $clsid)
      } else {
        # Unknown provider — could be a third-party AV or injected payload
        $providerName = try {
          (Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\$clsid" -ErrorAction SilentlyContinue).'(default)'
        } catch { $null }
        $nameStr = if ($providerName) { " ($providerName)" } else { '' }
        Add-Finding -FindingList $script:Findings -Code 'AMSI-UnknownProvider' -Severity 'Medium' `
          -Message ("Unknown AMSI provider registered: {0}{1}. Verify this is an authorized security product." `
            -f $clsid, $nameStr)
      }
    }

    if (-not $defenderPresent) {
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

# 2. Check for known AMSI bypass artifacts
# Bypass technique: setting 'amsiInitFailed' or disabling AMSI via registry
$bypassChecks = @(
  @{
    Path    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    Name    = 'AMSI_BYPASS'
    Code    = 'AMSI-BypassEnvVar'
    Message = 'AMSI_BYPASS environment variable found in system environment — potential bypass artifact.'
  },
  @{
    Path    = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    Name    = 'DisableAMSI'
    Code    = 'AMSI-PolicyDisabled'
    Message = 'Group Policy key DisableAMSI found under PowerShell policy — AMSI may be policy-disabled.'
  }
)

foreach ($check in $bypassChecks) {
  try {
    $val = Get-RegValue -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue
    if ($null -ne $val) {
      $bypassArtifactsFound += $check.Code
      Add-Finding -FindingList $script:Findings -Code $check.Code -Severity 'High' `
        -Message $check.Message
    }
  } catch {
    # Key absence is normal; silently continue
  }
}

# 3. PowerShell Script Block Logging (indicates AMSI integration is meaningful)
try {
  $sbEnabled = Get-RegValue -Path $script:PsLoggingPath -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue
  $scriptBlockLogging = ($null -ne $sbEnabled -and [int]$sbEnabled -eq 1)
  if (-not $scriptBlockLogging) {
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

# 4. Windows Script Host AMSI integration
try {
  $wshMachineEnabled = Get-RegValue -Path $script:WshMachinePath -Name 'Enabled' -ErrorAction SilentlyContinue
  $wshUserEnabled    = Get-RegValue -Path $script:WshUserPath    -Name 'Enabled' -ErrorAction SilentlyContinue

  if ($null -ne $wshMachineEnabled -and [int]$wshMachineEnabled -eq 0) {
    Add-Finding -FindingList $script:Findings -Code 'AMSI-WSHDisabledMachine' -Severity 'Medium' `
      -Message 'Windows Script Host is disabled machine-wide (Enabled=0). AMSI cannot scan WSH scripts.'
  }
  if ($null -ne $wshUserEnabled -and [int]$wshUserEnabled -eq 0) {
    Add-Finding -FindingList $script:Findings -Code 'AMSI-WSHDisabledUser' -Severity 'Medium' `
      -Message 'Windows Script Host is disabled for the current user (HKCU Enabled=0). AMSI cannot scan WSH scripts for this user.'
  }
} catch {
  # Non-critical — WSH may not be present on all systems
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
  RegisteredProviders  = $registeredProviders.Count
  DefenderAmsiPresent  = $defenderPresent
  BypassArtifacts      = $bypassArtifactsFound.Count
  PSScriptBlockLogging = $scriptBlockLogging
  FindingsCount        = $findingsCount
}

if (-not $Quiet -and $OutputFormat -eq 'Console') {
  Write-Section -Title 'AMSI Audit'
  Write-KeyValue -Key 'RegisteredProviders'  -Value ([string]$registeredProviders.Count)
  Write-KeyValue -Key 'DefenderAmsiPresent'  -Value ([string]$defenderPresent)
  Write-KeyValue -Key 'BypassArtifacts'      -Value ([string]$bypassArtifactsFound.Count)
  Write-KeyValue -Key 'PSScriptBlockLogging' -Value ([string]$scriptBlockLogging)
  Write-KeyValue -Key 'Findings'             -Value ([string]$findingsCount)
}

$highFindings = @($Findings | Where-Object { $_.Severity -eq 'High' })
$resultToken  = if ($Strict -and $findingsCount -gt 0) { 'FAIL' }
  elseif ($highFindings.Count -gt 0) { 'FAIL' }
  elseif ($findingsCount -gt 0) { 'WARN' }
  else { 'OK' }

$v2Result = New-V2ResultObject -ScriptName '50-AMSI-Audit.ps1' -Mode $Mode `
  -Result $resultToken -Findings $Findings -Summary $summary `
  -Metadata @{ BypassArtifactCodes = $bypassArtifactsFound }

Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
