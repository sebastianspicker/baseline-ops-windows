#requires -version 5.1
<#
.SYNOPSIS
Audit Secure Boot status and UEFI configuration.

.DESCRIPTION
Checks the system firmware type, Secure Boot enablement, and platform Secure Boot
enforcement state. Uses Confirm-SecureBootUEFI, registry queries under
HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State, and firmware environment
indicators to determine whether the device is booting securely.

Findings:
- FAIL if Secure Boot is disabled.
- WARN if UEFI firmware is detected but Secure Boot is not enforced.
- INFO for legacy BIOS systems where Secure Boot is not applicable.

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
.\46-SecureBoot-UEFI-Audit.ps1

.EXAMPLE
.\46-SecureBoot-UEFI-Audit.ps1 -OutputFormat Json -OutputPath C:\Temp\secureboot.json -PassThru
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
$script:__V2Context = Initialize-V2Context -ScriptName '46-SecureBoot-UEFI-Audit.ps1' -BoundParameters $PSBoundParameters `
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
  $result = Get-V2ResultObject -ScriptName '46-SecureBoot-UEFI-Audit.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# ----------------------------
# Main
# ----------------------------

function Invoke-Capability46MainPhase01 {
  param([hashtable]$RunState)
  $script:Findings = Get-FindingsList

  $RunState.secureBootEnabled   = $null
  $RunState.secureBootUefiError = $null
  $RunState.firmwareType        = 'Unknown'
  $RunState.sbRegPath           = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
  $RunState.sbRegValue          = $null
  $RunState.platformSBEnabled   = $null

  # 1. Check Secure Boot via Confirm-SecureBootUEFI
  try {
    $RunState.secureBootEnabled = Confirm-SecureBootUEFI
  } catch {
    $RunState.secureBootEnabled   = $false
    $RunState.secureBootUefiError = $_.Exception.Message
  }
}
function Invoke-Capability46MainPhase02 {
  param([hashtable]$RunState)
  try {
    # Method 1: Registry BiosFirmwareType (most reliable; 1=BIOS, 2=UEFI)
    $biosFwType = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation' -Name 'BiosFirmwareType' -ErrorAction SilentlyContinue).BiosFirmwareType
    if ($biosFwType -eq 2) {
      $RunState.firmwareType = 'UEFI'
    } elseif ($biosFwType -eq 1) {
      $RunState.firmwareType = 'Legacy BIOS'
    } else {
      # Method 2: Check for SecureBoot\State key (present on UEFI systems)
      if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State') {
        $RunState.firmwareType = 'UEFI'
      } else {
        # Method 3: Check if BootDevice pattern indicates UEFI
        $fwEnv = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($fwEnv -and $fwEnv.BootDevice -match 'HarddiskVolume') {
          $RunState.firmwareType = 'UEFI'
        } else {
          $RunState.firmwareType = 'Legacy BIOS'
        }
      }
    }
  } catch {
    Add-Finding -FindingList $script:Findings -Code 'SB-FirmwareQueryFailed' -Severity 'Medium' `
      -Message ("Could not determine firmware type: {0}" -f $_.Exception.Message)
  }
}
function Invoke-Capability46MainPhase03 {
  param([hashtable]$RunState)
  try {
    $RunState.sbRegValue = Get-RegValue -Path $RunState.sbRegPath -Name 'UEFISecureBootEnabled'
  } catch {
    # Key may not exist on legacy BIOS
    $RunState.sbRegValue = $null
  }

  # 4. Platform Secure Boot
  try {
    $RunState.platformSBEnabled = Get-RegValue -Path $RunState.sbRegPath -Name 'PlatformSecureBootEnabled'
  } catch {
    $RunState.platformSBEnabled = $null
  }
}
function Invoke-Capability46MainPhase04Step01 {
  param([hashtable]$RunState)
if (-not $RunState.secureBootEnabled) {
      $msg = 'Secure Boot is disabled on this UEFI system.'
      if ($RunState.secureBootUefiError) {
        $msg = "Secure Boot is not enabled. Confirm-SecureBootUEFI error: $($RunState.secureBootUefiError)"
      }
      Add-Finding -FindingList $script:Findings -Code 'SB-Disabled' -Severity 'High' -Message $msg
    } else {
      Add-Finding -FindingList $script:Findings -Code 'SB-Enabled' -Severity 'Low' `
        -Message 'Secure Boot is enabled.'
    }

    if ($null -ne $RunState.sbRegValue -and [int]$RunState.sbRegValue -ne 1) {
      Add-Finding -FindingList $script:Findings -Code 'SB-RegNotEnforced' -Severity 'Medium' `
        -Message ("Registry UEFISecureBootEnabled = {0} (expected 1)." -f $RunState.sbRegValue)
    }
}

function Invoke-Capability46MainPhase04Step02 {
  param([hashtable]$RunState)
if ($null -ne $RunState.platformSBEnabled -and [int]$RunState.platformSBEnabled -ne 1) {
      Add-Finding -FindingList $script:Findings -Code 'SB-PlatformNotEnabled' -Severity 'Medium' `
        -Message ("Platform Secure Boot is not enabled (PlatformSecureBootEnabled = {0})." -f $RunState.platformSBEnabled)
    } elseif ($null -eq $RunState.platformSBEnabled) {
      Add-Finding -FindingList $script:Findings -Code 'SB-PlatformUnknown' -Severity 'Low' `
        -Message 'PlatformSecureBootEnabled registry value not found; platform Secure Boot status unknown.'
    }
}

function Invoke-Capability46MainPhase04 {
  param([hashtable]$RunState)
  if ($RunState.firmwareType -eq 'Legacy BIOS') {
    Add-Finding -FindingList $script:Findings -Code 'SB-LegacyBIOS' -Severity 'Low' `
      -Message 'System uses Legacy BIOS firmware. Secure Boot is not applicable.'
  } else {
    # UEFI system
    . Invoke-Capability46MainPhase04Step01 -RunState $RunState
. Invoke-Capability46MainPhase04Step02 -RunState $RunState
  }
}
function Invoke-Capability46MainPhase05 {
  param([hashtable]$RunState)
  $Findings = @($script:Findings.ToArray())
  $findingsCount = @($Findings).Count

  $RunState.summary = [pscustomobject]@{
    ComputerName       = $env:COMPUTERNAME
    Timestamp          = Get-Date
    FirmwareType       = $RunState.firmwareType
    SecureBootEnabled  = $RunState.secureBootEnabled
    UEFISecureBootReg  = $RunState.sbRegValue
    PlatformSecureBoot = $RunState.platformSBEnabled
    FindingsCount      = $findingsCount
  }

  if (-not $Quiet -and $OutputFormat -eq 'Console') {
    Write-Section -Title 'Secure Boot / UEFI Audit'
    Write-KeyValue -Key 'FirmwareType'      -Value $RunState.firmwareType
    Write-KeyValue -Key 'SecureBootEnabled' -Value ([string]$RunState.secureBootEnabled)
    Write-KeyValue -Key 'Findings'          -Value ([string]$findingsCount)
  }
}
function Invoke-Capability46Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation)
  $RunState = @{

  }
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability46MainPhase01 -RunState $RunState
  . Invoke-Capability46MainPhase02 -RunState $RunState
  . Invoke-Capability46MainPhase03 -RunState $RunState
  . Invoke-Capability46MainPhase04 -RunState $RunState
  . Invoke-Capability46MainPhase05 -RunState $RunState
  $script:RunState = $RunState
}

. Invoke-Capability46Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation

function Get-Capability46ResultToken {
  $resultToken = if ($Strict -and $findingsCount -gt 0) { 'FAIL' }
    elseif (@($Findings | Where-Object { $_.Severity -eq 'High' }).Count -gt 0) { 'FAIL' }
    elseif ($findingsCount -gt 0) { 'WARN' }
    else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability46ResultToken
$v2Result = Get-V2ResultObject -ScriptName '46-SecureBoot-UEFI-Audit.ps1' -Mode $Mode `
  -Result $resultToken -Findings $Findings -Summary $RunState.summary `
  -Metadata @{ SecureBootUefiError = $RunState.secureBootUefiError }

Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
