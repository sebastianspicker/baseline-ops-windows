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
  $result = New-V2ResultObject -ScriptName '46-SecureBoot-UEFI-Audit.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

# ----------------------------
# Main
# ----------------------------

$script:Findings = New-FindingsList

$secureBootEnabled   = $null
$secureBootUefiError = $null
$firmwareType        = 'Unknown'
$sbRegPath           = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
$sbRegValue          = $null
$platformSBEnabled   = $null

# 1. Check Secure Boot via Confirm-SecureBootUEFI
try {
  $secureBootEnabled = Confirm-SecureBootUEFI
} catch {
  $secureBootEnabled   = $false
  $secureBootUefiError = $_.Exception.Message
}

# 2. Determine firmware type using multiple reliable indicators
try {
  # Method 1: Registry BiosFirmwareType (most reliable; 1=BIOS, 2=UEFI)
  $biosFwType = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation' -Name 'BiosFirmwareType' -ErrorAction SilentlyContinue).BiosFirmwareType
  if ($biosFwType -eq 2) {
    $firmwareType = 'UEFI'
  } elseif ($biosFwType -eq 1) {
    $firmwareType = 'Legacy BIOS'
  } else {
    # Method 2: Check for SecureBoot\State key (present on UEFI systems)
    if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State') {
      $firmwareType = 'UEFI'
    } else {
      # Method 3: Check if BootDevice pattern indicates UEFI
      $fwEnv = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
      if ($fwEnv -and $fwEnv.BootDevice -match 'HarddiskVolume') {
        $firmwareType = 'UEFI'
      } else {
        $firmwareType = 'Legacy BIOS'
      }
    }
  }
} catch {
  Add-Finding -FindingList $script:Findings -Code 'SB-FirmwareQueryFailed' -Severity 'Medium' `
    -Message ("Could not determine firmware type: {0}" -f $_.Exception.Message)
}

# 3. Read Secure Boot registry state
try {
  $sbRegValue = Get-RegValue -Path $sbRegPath -Name 'UEFISecureBootEnabled'
} catch {
  # Key may not exist on legacy BIOS
  $sbRegValue = $null
}

# 4. Platform Secure Boot
try {
  $platformSBEnabled = Get-RegValue -Path $sbRegPath -Name 'PlatformSecureBootEnabled'
} catch {
  $platformSBEnabled = $null
}

# ----------------------------
# Evaluate findings
# ----------------------------

if ($firmwareType -eq 'Legacy BIOS') {
  Add-Finding -FindingList $script:Findings -Code 'SB-LegacyBIOS' -Severity 'Low' `
    -Message 'System uses Legacy BIOS firmware. Secure Boot is not applicable.'
} else {
  # UEFI system
  if (-not $secureBootEnabled) {
    $msg = 'Secure Boot is disabled on this UEFI system.'
    if ($secureBootUefiError) {
      $msg = "Secure Boot is not enabled. Confirm-SecureBootUEFI error: $secureBootUefiError"
    }
    Add-Finding -FindingList $script:Findings -Code 'SB-Disabled' -Severity 'High' -Message $msg
  } else {
    Add-Finding -FindingList $script:Findings -Code 'SB-Enabled' -Severity 'Low' `
      -Message 'Secure Boot is enabled.'
  }

  if ($null -ne $sbRegValue -and [int]$sbRegValue -ne 1) {
    Add-Finding -FindingList $script:Findings -Code 'SB-RegNotEnforced' -Severity 'Medium' `
      -Message ("Registry UEFISecureBootEnabled = {0} (expected 1)." -f $sbRegValue)
  }

  if ($null -ne $platformSBEnabled -and [int]$platformSBEnabled -ne 1) {
    Add-Finding -FindingList $script:Findings -Code 'SB-PlatformNotEnabled' -Severity 'Medium' `
      -Message ("Platform Secure Boot is not enabled (PlatformSecureBootEnabled = {0})." -f $platformSBEnabled)
  } elseif ($null -eq $platformSBEnabled) {
    Add-Finding -FindingList $script:Findings -Code 'SB-PlatformUnknown' -Severity 'Low' `
      -Message 'PlatformSecureBootEnabled registry value not found; platform Secure Boot status unknown.'
  }
}

# ----------------------------
# Build summary & result
# ----------------------------

$Findings = @($script:Findings.ToArray())
$findingsCount = @($Findings).Count

$summary = [pscustomobject]@{
  ComputerName       = $env:COMPUTERNAME
  Timestamp          = Get-Date
  FirmwareType       = $firmwareType
  SecureBootEnabled  = $secureBootEnabled
  UEFISecureBootReg  = $sbRegValue
  PlatformSecureBoot = $platformSBEnabled
  FindingsCount      = $findingsCount
}

if (-not $Quiet -and $OutputFormat -eq 'Console') {
  Write-Section -Title 'Secure Boot / UEFI Audit'
  Write-KeyValue -Key 'FirmwareType'      -Value $firmwareType
  Write-KeyValue -Key 'SecureBootEnabled' -Value ([string]$secureBootEnabled)
  Write-KeyValue -Key 'Findings'          -Value ([string]$findingsCount)
}

$resultToken = if ($Strict -and $findingsCount -gt 0) { 'FAIL' }
  elseif (($Findings | Where-Object { $_.Severity -eq 'High' }).Count -gt 0) { 'FAIL' }
  elseif ($findingsCount -gt 0) { 'WARN' }
  else { 'OK' }

$v2Result = New-V2ResultObject -ScriptName '46-SecureBoot-UEFI-Audit.ps1' -Mode $Mode `
  -Result $resultToken -Findings $Findings -Summary $summary `
  -Metadata @{ SecureBootUefiError = $secureBootUefiError }

Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
