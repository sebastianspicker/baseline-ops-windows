#requires -version 5.1
<#
.SYNOPSIS
  Provides private credential protection audit phases.
.DESCRIPTION
  Preserves capability-local security policy, explicit confirmation, registry and runtime observations, and result serialization behavior.
#>

function Get-DeviceGuardInfo {
  try {
    return Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
  }
  catch {
    return $null
  }
}

function Get-OsInfo {
  try {
    return Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
  }
  catch {
    return $null
  }
}

function Try-LoadJsonConfig {
  param([string]$Path)

  $cfg = Get-CredentialDefaultConfig

  $sanitized = if ([string]::IsNullOrWhiteSpace($Path)) {
    $null
  }
  else {
    Sanitize-Path -Path $Path -MustExist
  }
  if (-not $sanitized) {
    return [pscustomobject]@{ Config = $cfg
      Loaded = $false
      Reason = 'ConfigPath not set or not found (using defaults)'
    }
  }

  try {
    $raw = Get-BoundedUtf8FileContent -Path $sanitized -MaximumBytes 1048576
    $obj = $raw | ConvertFrom-Json -ErrorAction Stop

    foreach ($k in $cfg.Keys) {
      if ($obj.PSObject.Properties.Name -contains $k) {
        $cfg[$k] = $obj.$k
      }
    }

    Write-CredentialConfigurationWarnings -Config $cfg

    return [pscustomobject]@{ Config = $cfg
      Loaded = $true
      Reason = 'Config loaded'
    }
  }
  catch {
    return [pscustomobject]@{ Config = $cfg
      Loaded = $false
      Reason = ('Invalid JSON (using defaults): ' + $_.Exception.Message)
    }
  }
}

function Get-EmptyResult {
  param(
    [bool]$Strict,
    [bool]$RequireBlockList,
    [bool]$Remediate,
    [bool]$IsAdmin,
    [string]$ConfigPath,
    [bool]$ConfigLoaded,
    [string]$ConfigLoadReason
  )

  # One object to the pipeline, everything else is console/eventlog.
  $result = [ordered]@{
    ComputerName = $env:COMPUTERNAME
    TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')

    IsAdmin = $IsAdmin
    Strict = $Strict
    RequireBlockList = $RequireBlockList
    RemediateRequested = $Remediate

    ConfigPath = $ConfigPath
    ConfigLoaded = $ConfigLoaded
    ConfigLoadReason = $ConfigLoadReason

    OsCaption = $null
    OsBuildNumber = $null
    OsVersion = $null

    PolicyDeviceGuardKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    PolicyDeviceGuardPresent = $false


  }
  Add-CredentialResultRegistry -Result $result
  Add-CredentialResultRuntime -Result $result
  return [pscustomobject]$result
}

function Get-ConsoleColorSafe {
  param([string]$Name, [string]$Fallback = 'Gray')
  try {
    [void][System.Enum]::Parse([System.ConsoleColor], $Name, $true)
    return $Name
  }
  catch {
    return $Fallback
  }
}

function Get-CredentialDefaultConfig {
  # Defaults (safe, conservative; no UEFI lock by default)
  return [ordered]@{
    EventSource = 'WinSecBaseline'
    EventLog = 'Application'
    Strict = $true
    RequireBlockList = $true
    ConsoleSummary = $true

    # Console colors (can be overridden by JSON)
    ColorOk = 'Green'
    ColorWarn = 'Yellow'
    ColorBad = 'Red'
    ColorInfo = 'Cyan'
    ColorDim = 'DarkGray'

    # Baseline values (registry)
    Baseline_LsaPpl_RunAsPPL = 1
    Baseline_LsaPpl_RunAsPPLBoot = 1

    # Credential Guard registry: 1 (UEFI lock), 2 (without lock)
    Baseline_CredentialGuard_LsaCfgFlags = 2

    # VBS registry: EnableVirtualizationBasedSecurity + RequirePlatformSecurityFeatures
    Baseline_Vbs_EnableVbs = 1
    Baseline_Vbs_RequirePlatformSecurityFeatures = 1  # 1=Secure Boot requirement (commonly recommended)
    Baseline_Vbs_Locked = 0

    # HVCI registry: Enabled + Locked
    Baseline_Hvci_Enabled = 1
    Baseline_Hvci_Locked = 0

    # Vulnerable Driver Blocklist
    Baseline_Blocklist_Enable = 1
  }

}

function Write-CredentialConfigurationWarnings {
  param($Config)
  $cfg = $Config
  # Warn if any Baseline_* value has been set to 0 or disabled by the config file
  foreach ($k in $cfg.Keys) {
    if ($k -like 'Baseline_*') {
      $val = $cfg[$k]
      if ($val -eq 0 -or $val -eq $false) {
        Write-Warning "Configuration weakens security: $k set to $val"
      }
    }
  }

}

function Add-CredentialResultRegistry {
  param($Result)
  $fields = [ordered]@{
    # Registry
    Lsa_RunAsPPL = $null
    Lsa_RunAsPPLBoot = $null
    Lsa_PplConfigured = $false

    Lsa_LsaCfgFlags = $null
    Cg_RegistryConfigured = $false

    Dg_EnableVbs = $null
    Dg_RequirePlatformSec = $null
    Dg_Locked = $null

    Hvci_Enabled = $null
    Hvci_Locked = $null

    Ci_Blocklist_Value = $null
    Ci_Blocklist_Active = $false


  }
  foreach ($key in $fields.Keys) {
    $Result[$key] = $fields[$key]
  }
}

function Add-CredentialResultRuntime {
  param($Result)
  $fields = [ordered]@{
    # Runtime
    Dg_SecurityServicesConfigured = @()
    Dg_SecurityServicesRunning = @()
    Dg_VbsStatus = $null

    Vbs_Running = $false
    Cg_Configured_Runtime = $false
    Cg_Running = $false
    Hvci_Configured_Runtime = $false
    Hvci_Running = $false

    HypervisorPresent = $false

    # Outcome
    Compliant = $true
    Issues = @()
    Warnings = @()

    RemediationPerformed = $false
    RemediationActions = @()
    RebootRequired = $false

    EventSource = $null
    EventLog = $null
    EventId = 3600
    ExitCode = 0
  }
  foreach ($key in $fields.Keys) {
    $Result[$key] = $fields[$key]
  }
}

. (Join-Path $PSScriptRoot '13-LSASS-CG-HVCI-VBS.observations.ps1')
. (Join-Path $PSScriptRoot '13-LSASS-CG-HVCI-VBS.policy.ps1')
. (Join-Path $PSScriptRoot '13-LSASS-CG-HVCI-VBS.remediation.ps1')
. (Join-Path $PSScriptRoot '13-LSASS-CG-HVCI-VBS.presentation.ps1')
. (Join-Path $PSScriptRoot '13-LSASS-CG-HVCI-VBS.runtime.ps1')
