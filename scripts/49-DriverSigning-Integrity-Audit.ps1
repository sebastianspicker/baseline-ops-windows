#requires -version 5.1
<#
.SYNOPSIS
Audit driver signing enforcement and kernel code integrity.

.DESCRIPTION
Checks driver signing and code integrity settings:
- TESTSIGNING flag via bcdedit (should be OFF for production systems).
- NOINTEGRITYCHECKS flag via bcdedit (should be OFF).
- Memory integrity (Core Isolation / HVCI) via registry
  HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity.
- HVCI running status (connects to script 13).

Findings:
- HIGH if TESTSIGNING is enabled (allows unsigned drivers).
- HIGH if NOINTEGRITYCHECKS is enabled (disables driver signature verification).
- WARN if HVCI / Memory Integrity is not enabled.

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
.\49-DriverSigning-Integrity-Audit.ps1

.EXAMPLE
.\49-DriverSigning-Integrity-Audit.ps1 -OutputFormat Json -OutputPath C:\Temp\driver-signing.json -PassThru
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
# v2-init (migrated to Initialize-V2Context)
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
  $result = New-V2ResultObject -ScriptName '49-DriverSigning-Integrity-Audit.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

# ----------------------------
# Main
# ----------------------------

$script:Findings = New-FindingsList

$testSigning       = $null
$noIntegrityChecks = $null
$hvciEnabled       = $null
$hvciRunning       = $null
$bcdeditRaw        = $null

# 1. Check bcdedit flags (TESTSIGNING, NOINTEGRITYCHECKS)
try {
  $bcdeditOutput = (& bcdedit.exe /enum '{current}' 2>&1 | Out-String).Trim()
  $bcdeditRaw = $bcdeditOutput

  # Parse testsigning
  if ($bcdeditOutput -match '(?mi)^\s*testsigning\s+(Yes|No)\s*$') {
    $testSigning = $Matches[1]
    if ($testSigning -eq 'Yes') {
      Add-Finding -FindingList $script:Findings -Code 'DS-TestSigningEnabled' -Severity 'High' `
        -Message 'TESTSIGNING is enabled. Unsigned/test-signed drivers can load. This is a critical security risk in production.'
    } else {
      Add-Finding -FindingList $script:Findings -Code 'DS-TestSigningOff' -Severity 'Low' `
        -Message 'TESTSIGNING is disabled (expected for production systems).'
    }
  } else {
    # If testsigning is not listed, it defaults to No
    $testSigning = 'No'
    Add-Finding -FindingList $script:Findings -Code 'DS-TestSigningDefault' -Severity 'Low' `
      -Message 'TESTSIGNING not explicitly set in BCD (defaults to No/disabled).'
  }

  # Parse nointegritychecks
  if ($bcdeditOutput -match '(?mi)^\s*nointegritychecks\s+(Yes|No)\s*$') {
    $noIntegrityChecks = $Matches[1]
    if ($noIntegrityChecks -eq 'Yes') {
      Add-Finding -FindingList $script:Findings -Code 'DS-NoIntegrityChecks' -Severity 'High' `
        -Message 'NOINTEGRITYCHECKS is enabled. Driver signature verification is disabled. Critical security risk.'
    } else {
      Add-Finding -FindingList $script:Findings -Code 'DS-IntegrityChecksOn' -Severity 'Low' `
        -Message 'NOINTEGRITYCHECKS is disabled (integrity checks active).'
    }
  } else {
    # If not listed, defaults to No (integrity checks on)
    $noIntegrityChecks = 'No'
    Add-Finding -FindingList $script:Findings -Code 'DS-IntegrityChecksDefault' -Severity 'Low' `
      -Message 'NOINTEGRITYCHECKS not explicitly set in BCD (defaults to No/enabled).'
  }
} catch {
  Add-Finding -FindingList $script:Findings -Code 'DS-BcdeditFailed' -Severity 'Medium' `
    -Message ("bcdedit query failed (may require elevation): {0}" -f $_.Exception.Message)
}

# 2. Memory integrity (Core Isolation) via registry - HVCI
$hvciRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
try {
  $hvciValue = Get-RegValue -Path $hvciRegPath -Name 'Enabled'
  if ($null -ne $hvciValue) {
    $hvciEnabled = ([int]$hvciValue -eq 1)
    if ($hvciEnabled) {
      Add-Finding -FindingList $script:Findings -Code 'DS-HVCIEnabled' -Severity 'Low' `
        -Message 'Memory integrity (HVCI) is enabled via registry.'
    } else {
      Add-Finding -FindingList $script:Findings -Code 'DS-HVCIDisabled' -Severity 'Medium' `
        -Message ("Memory integrity (HVCI) is not enabled (Enabled={0})." -f $hvciValue)
    }
  } else {
    Add-Finding -FindingList $script:Findings -Code 'DS-HVCINotConfigured' -Severity 'Medium' `
      -Message 'HVCI registry key exists but Enabled value not found. Memory integrity may not be configured.'
  }
} catch {
  Add-Finding -FindingList $script:Findings -Code 'DS-HVCIRegMissing' -Severity 'Medium' `
    -Message 'HVCI registry path not found. Memory integrity (Core Isolation) is not configured on this system.'
}

# 3. Check DeviceGuard status via CIM for running HVCI state
try {
  $dgStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
  if ($null -ne $dgStatus) {
    $runningServices = @()
    if ($null -ne $dgStatus.SecurityServicesRunning) {
      $runningServices = @($dgStatus.SecurityServicesRunning)
    }
    # SecurityServicesRunning: 1 = Credential Guard, 2 = HVCI
    $hvciRunning = ($runningServices -contains 2)
    if ($hvciRunning) {
      Add-Finding -FindingList $script:Findings -Code 'DS-HVCIRunning' -Severity 'Low' `
        -Message 'HVCI is actively running (confirmed via DeviceGuard WMI).'
    } else {
      Add-Finding -FindingList $script:Findings -Code 'DS-HVCINotRunning' -Severity 'Medium' `
        -Message 'HVCI is not in the running security services list.'
    }
  }
} catch {
  Add-Finding -FindingList $script:Findings -Code 'DS-DeviceGuardQueryFailed' -Severity 'Low' `
    -Message ("DeviceGuard WMI query failed: {0}" -f $_.Exception.Message)
}

# ----------------------------
# Build summary & result
# ----------------------------

$Findings      = @($script:Findings.ToArray())
$findingsCount = @($Findings).Count

$summary = [pscustomobject]@{
  ComputerName       = $env:COMPUTERNAME
  Timestamp          = Get-Date
  TestSigning        = $testSigning
  NoIntegrityChecks  = $noIntegrityChecks
  HVCIEnabled        = $hvciEnabled
  HVCIRunning        = $hvciRunning
  FindingsCount      = $findingsCount
}

if (-not $Quiet -and $OutputFormat -eq 'Console') {
  Write-Section -Title 'Driver Signing / Integrity Audit'
  Write-KeyValue -Key 'TestSigning'       -Value ([string]$testSigning)
  Write-KeyValue -Key 'NoIntegrityChecks' -Value ([string]$noIntegrityChecks)
  Write-KeyValue -Key 'HVCI Enabled'      -Value ([string]$hvciEnabled)
  Write-KeyValue -Key 'HVCI Running'      -Value ([string]$hvciRunning)
  Write-KeyValue -Key 'Findings'          -Value ([string]$findingsCount)
}

$resultToken = if ($Strict -and $findingsCount -gt 0) { 'FAIL' }
  elseif (@($Findings | Where-Object { $_.Severity -eq 'High' }).Count -gt 0) { 'FAIL' }
  elseif (@($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count -gt 0) { 'WARN' }
  else { 'OK' }

$v2Result = New-V2ResultObject -ScriptName '49-DriverSigning-Integrity-Audit.ps1' -Mode $Mode `
  -Result $resultToken -Findings $Findings -Summary $summary `
  -Metadata @{ BcdeditRaw = $bcdeditRaw }

Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
