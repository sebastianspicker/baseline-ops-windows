#requires -version 5.1
<#
.SYNOPSIS
  Audits and (optionally) remediates Windows hardening controls related to LSASS protection, virtualization-based security, and driver abuse prevention.

.DESCRIPTION
  This script evaluates several Windows security features that help protect credentials and reduce kernel attack surface:
  - LSASS PPL (LSA Protection): checks whether LSASS is configured to run as a protected process.
  - Credential Guard: checks both registry configuration and runtime state (via Device Guard runtime data).
  - VBS (Virtualization-Based Security): checks registry configuration and whether VBS is actually running.
  - HVCI / Memory Integrity: checks registry configuration and runtime state.
  - Microsoft Vulnerable Driver Blocklist: checks whether the blocklist is enabled.

  The script can run in two modes:
  - Audit mode (default): reads configuration and runtime state and returns a single structured result object.
  - Remediation mode (-Remediate): applies a baseline configuration (idempotent) and reports whether a reboot is required.

  Output behavior:
  - Pipeline output is always exactly ONE structured object (suitable for Export-Csv / ConvertTo-Json / Where-Object).
  - Human-friendly console output is printed at the end (pretty summary with color) and does not pollute the pipeline.
  - A detailed, plain-text summary is written to the Windows Event Log.

.PARAMETER Remediate
  If specified, the script applies the baseline registry settings for the checked controls.
  The script does not force a reboot; it only reports RebootRequired=True when changes were made.

.PARAMETER Strict
  Controls pass/fail semantics:
  - When Strict is True (default), the script is compliant only if VBS is running AND Credential Guard and HVCI are running.
  - When Strict is False, the script accepts "configured" (registry or runtime configured) even if not currently running.

  Use Strict=True for enforcement/compliance.
  Use Strict=False for staged rollouts where configuration may be present but runtime activation is pending.

.PARAMETER RequireBlockList
  When True (default), the script is compliant only if the Microsoft Vulnerable Driver Blocklist is enabled.
  When False, blocklist state is reported but does not affect overall compliance.

.PARAMETER ConfigPath
  Optional path to a JSON configuration file to override defaults such as:
  - EventSource / EventLog name
  - Strict / RequireBlockList default behavior
  - Baseline registry values applied by -Remediate
  - Console output colors

  If the JSON file is missing or invalid, the script continues with built-in defaults.

.INPUTS
  None. This script does not accept pipeline input.


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER PassThru
  Emit structured v2 result object to pipeline.

.PARAMETER Quiet
  Suppress console output.

.PARAMETER NoColor
  Disable colored output.

.OUTPUTS
  System.Management.Automation.PSCustomObject

  The script writes exactly one object to the pipeline with (high-level) fields such as:
  - ComputerName, TimestampUtc
  - Strict, RequireBlockList, RemediateRequested, IsAdmin
  - Registry state (e.g., LsaCfgFlags, EnableVirtualizationBasedSecurity, HVCI Enabled, Blocklist value)
  - Runtime state (Device Guard security services configured/running, VBS status)
  - Compliant (bool), Issues (string[]), Warnings (string[])
  - RemediationPerformed (bool), RemediationActions (string[]), RebootRequired (bool)
  - ExitCode (0=OK, 1=NonCompliant, 2=Error) and EventId

  This enables examples like:
    .\Script.ps1 | ConvertTo-Json -Depth 5
    .\Script.ps1 | Export-Csv .\report.csv -NoTypeInformation
    .\Script.ps1 | Where-Object { -not $_.Compliant }

.EXAMPLE
  PS> .\13-LSASS-CG-HVCI-VBS.ps1

  Runs an audit only. Prints a console summary and returns a single result object to the pipeline.

.EXAMPLE
  PS> .\13-LSASS-CG-HVCI-VBS.ps1 -Remediate

  Applies baseline registry values (if not blocked by policy), reports the actions taken and whether a reboot is required.

.EXAMPLE
  PS> .\13-LSASS-CG-HVCI-VBS.ps1 -Strict:$false

  Runs in non-strict mode. Useful during rollout to distinguish "configured" from "running".

.EXAMPLE
  PS> .\13-LSASS-CG-HVCI-VBS.ps1 -RequireBlockList:$false

  Audits blocklist state but does not fail compliance if the blocklist is disabled.

.EXAMPLE
  PS> .\13-LSASS-CG-HVCI-VBS.ps1 -ConfigPath "PATH/TO/JSON" -Remediate | ConvertTo-Json -Depth 6

  Loads settings from JSON (if present) and runs remediation. The structured output is serialized to JSON for logging or upload.

.NOTES
  Policy awareness:
  - If a Device Guard policy key is detected, remediation is skipped to avoid writing conflicting settings.
    The script continues auditing and will report a warning explaining why remediation did not run.

  Permissions:
  - Remediation requires administrative privileges to write to HKLM.
  - Event source creation may require administrative privileges; if unavailable, event logging may fall back to console output.

  Reboot behavior:
  - Many of the security controls checked by this script only fully activate after a reboot.
    The script reports RebootRequired=True when it changes registry configuration that typically requires reboot.

  Operational guidance:
  - Treat -Remediate as a configuration change: pilot first, ensure rollback options, and schedule reboots.
  - Use the pipeline object for automation; use the console summary for interactive runs.

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [bool]$Strict = $true,
  [bool]$RequireBlockList = $true,
  [string]$ConfigPath,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force

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
$Remediate = ($Mode -eq 'Remediate')
if ($Quiet) {
  $InformationPreference = 'SilentlyContinue'
  $VerbosePreference = 'SilentlyContinue'
}
if ($NoColor) {
  $script:NoColor = $true
}
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -----------------------------
# Helper functions (PS 5.1 compatible)
# -----------------------------

function Get-DeviceGuardInfo {
  try {
    return Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
  } catch { return $null }
}

function Get-OsInfo {
  try { return Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch { return $null }
}

function Try-LoadJsonConfig {
  param([string]$Path)

  # Defaults (safe, conservative; no UEFI lock by default)
  $cfg = [ordered]@{
    EventSource                         = 'WinSecBaseline'
    EventLog                            = 'Application'
    Strict                              = $true
    RequireBlockList                    = $true
    ConsoleSummary                      = $true

    # Console colors (can be overridden by JSON)
    ColorOk                             = 'Green'
    ColorWarn                           = 'Yellow'
    ColorBad                            = 'Red'
    ColorInfo                           = 'Cyan'
    ColorDim                            = 'DarkGray'

    # Baseline values (registry)
    Baseline_LsaPpl_RunAsPPL            = 1
    Baseline_LsaPpl_RunAsPPLBoot        = 1

    # Credential Guard registry: 1 (UEFI lock), 2 (without lock)
    Baseline_CredentialGuard_LsaCfgFlags = 2

    # VBS registry: EnableVirtualizationBasedSecurity + RequirePlatformSecurityFeatures
    Baseline_Vbs_EnableVbs              = 1
    Baseline_Vbs_RequirePlatformSecurityFeatures = 1  # 1=Secure Boot requirement (commonly recommended)
    Baseline_Vbs_Locked                 = 0

    # HVCI registry: Enabled + Locked
    Baseline_Hvci_Enabled               = 1
    Baseline_Hvci_Locked                = 0

    # Vulnerable Driver Blocklist
    Baseline_Blocklist_Enable           = 1
  }

  $sanitized = Sanitize-Path -Path $Path -MustExist
  if (-not $sanitized) {
    return [pscustomobject]@{ Config=$cfg; Loaded=$false; Reason='ConfigPath not set or not found (using defaults)' }
  }

  try {
    $raw = Get-Content -LiteralPath $sanitized -Raw -Encoding UTF8 -ErrorAction Stop
    $obj = $raw | ConvertFrom-Json -ErrorAction Stop

    foreach ($k in $cfg.Keys) {
      if ($obj.PSObject.Properties.Name -contains $k) {
        $cfg[$k] = $obj.$k
      }
    }

    # Warn if any Baseline_* value has been set to 0 or disabled by the config file
    foreach ($k in $cfg.Keys) {
      if ($k -like 'Baseline_*') {
        $val = $cfg[$k]
        if ($val -eq 0 -or $val -eq $false) {
          Write-Warning "Configuration weakens security: $k set to $val"
        }
      }
    }

    return [pscustomobject]@{ Config=$cfg; Loaded=$true; Reason='Config loaded' }
  } catch {
    return [pscustomobject]@{ Config=$cfg; Loaded=$false; Reason=('Invalid JSON (using defaults): ' + $_.Exception.Message) }
  }
}

function New-EmptyResult {
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
  return [pscustomobject][ordered]@{
    ComputerName                  = $env:COMPUTERNAME
    TimestampUtc                  = (Get-Date).ToUniversalTime().ToString('o')

    IsAdmin                       = $IsAdmin
    Strict                        = $Strict
    RequireBlockList              = $RequireBlockList
    RemediateRequested            = $Remediate

    ConfigPath                    = $ConfigPath
    ConfigLoaded                  = $ConfigLoaded
    ConfigLoadReason              = $ConfigLoadReason

    OsCaption                     = $null
    OsBuildNumber                 = $null
    OsVersion                     = $null

    PolicyDeviceGuardKey          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    PolicyDeviceGuardPresent      = $false

    # Registry
    Lsa_RunAsPPL                  = $null
    Lsa_RunAsPPLBoot              = $null
    Lsa_PplConfigured             = $false

    Lsa_LsaCfgFlags               = $null
    Cg_RegistryConfigured         = $false

    Dg_EnableVbs                  = $null
    Dg_RequirePlatformSec         = $null
    Dg_Locked                     = $null

    Hvci_Enabled                  = $null
    Hvci_Locked                   = $null

    Ci_Blocklist_Value            = $null
    Ci_Blocklist_Active           = $false

    # Runtime
    Dg_SecurityServicesConfigured = @()
    Dg_SecurityServicesRunning    = @()
    Dg_VbsStatus                  = $null

    Vbs_Running                   = $false
    Cg_Configured_Runtime         = $false
    Cg_Running                    = $false
    Hvci_Configured_Runtime       = $false
    Hvci_Running                  = $false

    HypervisorPresent             = $false

    # Outcome
    Compliant                     = $true
    Issues                        = @()
    Warnings                      = @()

    RemediationPerformed          = $false
    RemediationActions            = @()
    RebootRequired                = $false

    EventSource                   = $null
    EventLog                      = $null
    EventId                       = 3600
    ExitCode                      = 0
  }
}

function Add-Text {
  param([ref]$Arr,[string]$Text)
  if ($null -eq $Arr.Value) { $Arr.Value = @() }
  $Arr.Value += $Text
}

function Get-ConsoleColorSafe {
  param([string]$Name,[string]$Fallback='Gray')
  try {
    [void][System.Enum]::Parse([System.ConsoleColor], $Name, $true)
    return $Name
  } catch {
    return $Fallback
  }
}

function Write-PrettySummary {
  param(
    [pscustomobject]$Result,
    [hashtable]$Cfg,
    [string]$SanitizedConfigPath
  )

  if (-not [bool]$Cfg.ConsoleSummary) { return }

  $cOk   = Get-ConsoleColorSafe -Name ([string]$Cfg.ColorOk)   -Fallback 'Green'
  $cWarn = Get-ConsoleColorSafe -Name ([string]$Cfg.ColorWarn) -Fallback 'Yellow'
  $cBad  = Get-ConsoleColorSafe -Name ([string]$Cfg.ColorBad)  -Fallback 'Red'
  $cInfo = Get-ConsoleColorSafe -Name ([string]$Cfg.ColorInfo) -Fallback 'Cyan'
  $cDim  = Get-ConsoleColorSafe -Name ([string]$Cfg.ColorDim)  -Fallback 'DarkGray'

  $statusText  = $(if ($Result.Compliant) { 'OK' } else { 'NONCOMPLIANT' })
  $statusColor = $(if ($Result.Compliant) { $cOk } else { $cBad })

  Write-UiLine ""
  Write-UiLine "============================================================" -ForegroundColor $cDim
  Write-UiLine "LSASS / Credential Guard / VBS / HVCI / Driver Blocklist" -ForegroundColor $cInfo
  Write-UiLine "============================================================" -ForegroundColor $cDim

  Write-UiLine ("Computer   : {0}" -f $Result.ComputerName)
  if ($Result.OsCaption) {
    Write-UiLine ("OS         : {0} (Build {1}, Version {2})" -f $Result.OsCaption,$Result.OsBuildNumber,$Result.OsVersion)
  }

  Write-UiLine ("Result     : {0}" -f $statusText) -ForegroundColor $statusColor
  Write-UiLine ("Mode       : Strict={0}  RequireBlockList={1}  Remediate={2}  IsAdmin={3}" -f $Result.Strict,$Result.RequireBlockList,$Result.RemediateRequested,$Result.IsAdmin) -ForegroundColor $cDim

  Write-UiLine ""
  Write-UiLine "Signals" -ForegroundColor $cInfo
  Write-UiLine ("- LSASS PPL                : {0}" -f $(if ($Result.Lsa_PplConfigured) { 'Configured' } else { 'Not configured' })) -ForegroundColor $(if ($Result.Lsa_PplConfigured) { $cOk } else { $cBad })
  Write-UiLine ("- Credential Guard         : Reg={0}  Running={1}" -f $Result.Cg_RegistryConfigured,$Result.Cg_Running) -ForegroundColor $(if ($Result.Cg_Running) { $cOk } else { $cBad })
  Write-UiLine ("- VBS                      : RegEnabled={0}  Running={1}  Status={2}" -f ($Result.Dg_EnableVbs -eq 1),$Result.Vbs_Running,$Result.Dg_VbsStatus) -ForegroundColor $(if ($Result.Vbs_Running) { $cOk } else { $cBad })
  Write-UiLine ("- HVCI (Memory Integrity)  : RegEnabled={0}  Running={1}" -f ($Result.Hvci_Enabled -eq 1),$Result.Hvci_Running) -ForegroundColor $(if ($Result.Hvci_Running) { $cOk } else { $cBad })
  Write-UiLine ("- Vulnerable Driver Blocklist: Active={0} (Value={1})" -f $Result.Ci_Blocklist_Active,$Result.Ci_Blocklist_Value) -ForegroundColor $(if ($Result.Ci_Blocklist_Active) { $cOk } else { $cBad })

  if ($Result.PolicyDeviceGuardPresent) {
    Write-UiLine ""
    Write-UiLine ("Policy     : DeviceGuard policy key present -> remediation skipped ({0})" -f $Result.PolicyDeviceGuardKey) -ForegroundColor $cWarn
  }

  Write-UiLine ""
  Write-UiLine ("Config     : Loaded={0}  Reason={1}  Path={2}" -f $Result.ConfigLoaded,$Result.ConfigLoadReason,$SanitizedConfigPath) -ForegroundColor $cDim

  if ($Result.RemediationActions.Count -gt 0) {
    Write-UiLine ""
    Write-UiLine "Remediation actions" -ForegroundColor $cInfo
    foreach ($a in $Result.RemediationActions) {
      Write-UiLine ("- {0}" -f $a) -ForegroundColor $cWarn
    }
  }

  if ($Result.RebootRequired) {
    Write-UiLine ""
    Write-UiLine "RebootRequired: True (changes take effect after reboot)" -ForegroundColor $cWarn
  }

  if ($Result.Issues.Count -gt 0) {
    Write-UiLine ""
    Write-UiLine "Issues" -ForegroundColor $cInfo
    foreach ($m in $Result.Issues) { Write-UiLine ("- {0}" -f $m) -ForegroundColor $cBad }
  }

  if ($Result.Warnings.Count -gt 0) {
    Write-UiLine ""
    Write-UiLine "Warnings" -ForegroundColor $cInfo
    foreach ($w in $Result.Warnings) { Write-UiLine ("- {0}" -f $w) -ForegroundColor $cWarn }
  }

  Write-UiLine ""
  Write-UiLine ("ExitCode   : {0}" -f $Result.ExitCode) -ForegroundColor $cDim
  Write-UiLine "============================================================" -ForegroundColor $cDim
}

# -----------------------------
# Main
# -----------------------------
$script:Findings = New-FindingsList

$eventOkId  = 3600
$eventBadId = 3610
$eventErrId = 3611

$cfgLoad = Try-LoadJsonConfig -Path $ConfigPath
$cfg = $cfgLoad.Config

# Apply config-driven defaults only if caller did not supply explicit parameters
if ($PSBoundParameters.ContainsKey('Strict') -eq $false) { $Strict = [bool]$cfg.Strict }
if ($PSBoundParameters.ContainsKey('RequireBlockList') -eq $false) { $RequireBlockList = [bool]$cfg.RequireBlockList }

$source  = [string]$cfg.EventSource
$logName = [string]$cfg.EventLog
Ensure-EventSource -Source $source -Log $logName

$sanitizedConfigPath = $(if ([string]::IsNullOrWhiteSpace($ConfigPath) -or $ConfigPath -eq 'PATH/TO/JSON') { 'PATH/TO/JSON' } else { $ConfigPath })

$result = New-EmptyResult -Strict $Strict -RequireBlockList $RequireBlockList -Remediate $Remediate -IsAdmin (Test-IsAdmin) -ConfigPath $sanitizedConfigPath -ConfigLoaded $cfgLoad.Loaded -ConfigLoadReason $cfgLoad.Reason
$result.EventSource = $source
$result.EventLog    = $logName

try {
  # OS info
  $os = Get-OsInfo
  if ($os) {
    $result.OsCaption     = $os.Caption
    $result.OsBuildNumber = $os.BuildNumber
    $result.OsVersion     = $os.Version
  }

  # Registry paths
  $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  $dgRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
  $scHVCI = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
  $ciCfg  = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'

  # Policy presence (policy-respecting for remediation)
  $result.PolicyDeviceGuardPresent = Test-Path -LiteralPath $result.PolicyDeviceGuardKey

  # Registry checks
  $result.Lsa_RunAsPPL      = Get-RegDword -Path $lsaKey -Name 'RunAsPPL'
  $result.Lsa_RunAsPPLBoot  = Get-RegDword -Path $lsaKey -Name 'RunAsPPLBoot'
  $result.Lsa_PplConfigured = (($result.Lsa_RunAsPPL -in @(1, 2)) -or ($result.Lsa_RunAsPPLBoot -eq 1))

  # Credential Guard uses LsaCfgFlags (1/2) per Microsoft documentation
  $result.Lsa_LsaCfgFlags       = Get-RegDword -Path $lsaKey -Name 'LsaCfgFlags'
  $result.Cg_RegistryConfigured = ($result.Lsa_LsaCfgFlags -in 1,2)

  # VBS/HVCI registry keys (EnableVbs, RequirePlatformSecurityFeatures, Locked, HVCI Enabled/Locked)
  $result.Dg_EnableVbs          = Get-RegDword -Path $dgRoot -Name 'EnableVirtualizationBasedSecurity'
  $result.Dg_RequirePlatformSec = Get-RegDword -Path $dgRoot -Name 'RequirePlatformSecurityFeatures'
  $result.Dg_Locked             = Get-RegDword -Path $dgRoot -Name 'Locked'

  $result.Hvci_Enabled          = Get-RegDword -Path $scHVCI -Name 'Enabled'
  $result.Hvci_Locked           = Get-RegDword -Path $scHVCI -Name 'Locked'

  $result.Ci_Blocklist_Value    = Get-RegDword -Path $ciCfg -Name 'VulnerableDriverBlocklistEnable'
  $result.Ci_Blocklist_Active   = ($result.Ci_Blocklist_Value -in 1,2)

  # Runtime (Win32_DeviceGuard)
  $dg = Get-DeviceGuardInfo
  if ($dg) {
    $svcCfg = @()
    $svcRun = @()
    if ($dg.SecurityServicesConfigured) { $svcCfg = @($dg.SecurityServicesConfigured) }
    if ($dg.SecurityServicesRunning)    { $svcRun = @($dg.SecurityServicesRunning) }

    $result.Dg_SecurityServicesConfigured = $svcCfg
    $result.Dg_SecurityServicesRunning    = $svcRun
    $result.Dg_VbsStatus                  = [int]$dg.VirtualizationBasedSecurityStatus

    $result.Cg_Configured_Runtime   = ($svcCfg -contains 1)
    $result.Cg_Running              = ($svcRun -contains 1)
    $result.Hvci_Configured_Runtime = ($svcCfg -contains 2)
    $result.Hvci_Running            = ($svcRun -contains 2)
    $result.Vbs_Running             = ($result.Dg_VbsStatus -eq 2)
  }

  # Hypervisor presence (info only)
  try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $result.HypervisorPresent = [bool]$cs.HypervisorPresent
  } catch { <# best-effort: HypervisorPresent property may not be available #> }

  # -----------------------------
  # Compliance evaluation
  # -----------------------------
  if (-not $result.Lsa_PplConfigured) {
    $result.Compliant = $false
    $result.Issues   += "LSASS PPL not configured"
    Add-Finding -Code 'LSA-PPL-Missing' -Severity 'High' -Message 'LSASS PPL is not configured via registry.'
  }

  if ($Strict) {
    if (-not $result.Vbs_Running)  { $result.Compliant = $false; $result.Issues += "VBS not running (VirtualizationBasedSecurityStatus != 2)" }
    if (-not $result.Cg_Running)   { $result.Compliant = $false; $result.Issues += "Credential Guard not running" }
    if (-not $result.Hvci_Running) { $result.Compliant = $false; $result.Issues += "HVCI not running" }
  } else {
    if (-not ($result.Cg_RegistryConfigured -or $result.Cg_Configured_Runtime -or $result.Cg_Running)) { $result.Compliant = $false; $result.Issues += "Credential Guard neither configured nor running" }
    if (-not (($result.Hvci_Enabled -eq 1) -or $result.Hvci_Configured_Runtime -or $result.Hvci_Running)) { $result.Compliant = $false; $result.Issues += "HVCI neither enabled nor running" }
    if (-not (($result.Dg_EnableVbs -eq 1) -or $result.Vbs_Running)) { $result.Compliant = $false; $result.Issues += "VBS neither enabled nor running" }
  }

  if ($RequireBlockList -and -not $result.Ci_Blocklist_Active) {
    $result.Compliant = $false
    $result.Issues += "Vulnerable Driver Blocklist not active"
    Add-Finding -Code 'Blocklist-Missing' -Severity 'Medium' -Message 'Vulnerable Driver Blocklist is not active.'
  }

  if (-not $result.Vbs_Running) { Add-Finding -Code 'VBS-NotRunning' -Severity 'Medium' -Message 'Virtualization-Based Security is not running.' }
  if (-not $result.Cg_Running)  { Add-Finding -Code 'CG-NotRunning' -Severity 'Medium' -Message 'Credential Guard is not running.' }
  if (-not $result.Hvci_Running) { Add-Finding -Code 'HVCI-NotRunning' -Severity 'Medium' -Message 'Hypervisor-Enforced Code Integrity (HVCI) is not running.' }

  # -----------------------------
  # Remediation gate
  # -----------------------------
  if ($result.PolicyDeviceGuardPresent -and $Remediate) {
    $result.Warnings += "Remediation requested but DeviceGuard policy key exists; skipping to avoid overriding policy."
  }
  if ($Remediate -and -not $result.IsAdmin) {
    $result.Warnings += "Remediation requested but process is not elevated; skipping remediation."
  }

  $canRemediate = ($Remediate -and $result.IsAdmin -and (-not $result.PolicyDeviceGuardPresent))

  # -----------------------------
  # Remediation (idempotent)
  # -----------------------------
  if ($canRemediate) {
    $result.RemediationPerformed = $true

    # LSASS PPL
    if ($result.Lsa_RunAsPPL -ne [int]$cfg.Baseline_LsaPpl_RunAsPPL) {
      if ($PSCmdlet.ShouldProcess($lsaKey, "Set RunAsPPL=$([int]$cfg.Baseline_LsaPpl_RunAsPPL)")) {
        if (Set-RegDword -Path $lsaKey -Name 'RunAsPPL' -Value ([int]$cfg.Baseline_LsaPpl_RunAsPPL)) {
          $result.RemediationActions += ("Set RunAsPPL={0}" -f [int]$cfg.Baseline_LsaPpl_RunAsPPL)
          $result.RebootRequired = $true
        }
      }
    }
    if ($result.Lsa_RunAsPPLBoot -ne [int]$cfg.Baseline_LsaPpl_RunAsPPLBoot) {
      if ($PSCmdlet.ShouldProcess($lsaKey, "Set RunAsPPLBoot=$([int]$cfg.Baseline_LsaPpl_RunAsPPLBoot)")) {
        if (Set-RegDword -Path $lsaKey -Name 'RunAsPPLBoot' -Value ([int]$cfg.Baseline_LsaPpl_RunAsPPLBoot)) {
          $result.RemediationActions += ("Set RunAsPPLBoot={0}" -f [int]$cfg.Baseline_LsaPpl_RunAsPPLBoot)
          $result.RebootRequired = $true
        }
      }
    }

    # VBS
    if ($result.Dg_EnableVbs -ne [int]$cfg.Baseline_Vbs_EnableVbs) {
      if ($PSCmdlet.ShouldProcess($dgRoot, "Set EnableVirtualizationBasedSecurity=$([int]$cfg.Baseline_Vbs_EnableVbs)")) {
        if (Set-RegDword -Path $dgRoot -Name 'EnableVirtualizationBasedSecurity' -Value ([int]$cfg.Baseline_Vbs_EnableVbs)) {
          $result.RemediationActions += ("Set EnableVirtualizationBasedSecurity={0}" -f [int]$cfg.Baseline_Vbs_EnableVbs)
          $result.RebootRequired = $true
        }
      }
    }
    if (($null -eq $result.Dg_RequirePlatformSec) -or ($result.Dg_RequirePlatformSec -eq 0) -or ($result.Dg_RequirePlatformSec -ne [int]$cfg.Baseline_Vbs_RequirePlatformSecurityFeatures)) {
      if ($PSCmdlet.ShouldProcess($dgRoot, "Set RequirePlatformSecurityFeatures=$([int]$cfg.Baseline_Vbs_RequirePlatformSecurityFeatures)")) {
        if (Set-RegDword -Path $dgRoot -Name 'RequirePlatformSecurityFeatures' -Value ([int]$cfg.Baseline_Vbs_RequirePlatformSecurityFeatures)) {
          $result.RemediationActions += ("Set RequirePlatformSecurityFeatures={0}" -f [int]$cfg.Baseline_Vbs_RequirePlatformSecurityFeatures)
          $result.RebootRequired = $true
        }
      }
    }
    if (($null -eq $result.Dg_Locked) -or ($result.Dg_Locked -ne [int]$cfg.Baseline_Vbs_Locked)) {
      # Do not downgrade from UEFI lock (Locked=1) to a less secure value
      if ($result.Dg_Locked -ne 1 -or [int]$cfg.Baseline_Vbs_Locked -eq 1) {
        if ($PSCmdlet.ShouldProcess($dgRoot, "Set DeviceGuard Locked=$([int]$cfg.Baseline_Vbs_Locked)")) {
          if (Set-RegDword -Path $dgRoot -Name 'Locked' -Value ([int]$cfg.Baseline_Vbs_Locked)) {
            $result.RemediationActions += ("Set DeviceGuard Locked={0}" -f [int]$cfg.Baseline_Vbs_Locked)
            $result.RebootRequired = $true
          }
        }
      }
    }

    # Credential Guard (LsaCfgFlags 1/2)
    if ($result.Lsa_LsaCfgFlags -notin 1,2) {
      if ($PSCmdlet.ShouldProcess($lsaKey, "Set LsaCfgFlags=$([int]$cfg.Baseline_CredentialGuard_LsaCfgFlags)")) {
        if (Set-RegDword -Path $lsaKey -Name 'LsaCfgFlags' -Value ([int]$cfg.Baseline_CredentialGuard_LsaCfgFlags)) {
          $result.RemediationActions += ("Set LsaCfgFlags={0}" -f [int]$cfg.Baseline_CredentialGuard_LsaCfgFlags)
          $result.RebootRequired = $true
        }
      }
    }

    # HVCI
    if ($result.Hvci_Enabled -ne [int]$cfg.Baseline_Hvci_Enabled) {
      if ($PSCmdlet.ShouldProcess($scHVCI, "Set HVCI Enabled=$([int]$cfg.Baseline_Hvci_Enabled)")) {
        if (Set-RegDword -Path $scHVCI -Name 'Enabled' -Value ([int]$cfg.Baseline_Hvci_Enabled)) {
          $result.RemediationActions += ("Set HVCI Enabled={0}" -f [int]$cfg.Baseline_Hvci_Enabled)
          $result.RebootRequired = $true
        }
      }
    }
    if (($null -eq $result.Hvci_Locked) -or ($result.Hvci_Locked -ne [int]$cfg.Baseline_Hvci_Locked)) {
      # Do not downgrade from UEFI lock (Locked=1) to a less secure value
      if ($result.Hvci_Locked -ne 1 -or [int]$cfg.Baseline_Hvci_Locked -eq 1) {
        if ($PSCmdlet.ShouldProcess($scHVCI, "Set HVCI Locked=$([int]$cfg.Baseline_Hvci_Locked)")) {
          if (Set-RegDword -Path $scHVCI -Name 'Locked' -Value ([int]$cfg.Baseline_Hvci_Locked)) {
            $result.RemediationActions += ("Set HVCI Locked={0}" -f [int]$cfg.Baseline_Hvci_Locked)
            $result.RebootRequired = $true
          }
        }
      }
    }

    # Vulnerable Driver Blocklist
    if (-not $result.Ci_Blocklist_Active) {
      if ($PSCmdlet.ShouldProcess($ciCfg, "Set VulnerableDriverBlocklistEnable=$([int]$cfg.Baseline_Blocklist_Enable)")) {
        if (Set-RegDword -Path $ciCfg -Name 'VulnerableDriverBlocklistEnable' -Value ([int]$cfg.Baseline_Blocklist_Enable)) {
          $result.RemediationActions += ("Set VulnerableDriverBlocklistEnable={0}" -f [int]$cfg.Baseline_Blocklist_Enable)
          $result.RebootRequired = $true
        }
      }
    }
  }

  # Exit/event decision
  if ($result.Compliant) {
    $result.ExitCode = 0
    $result.EventId  = $eventOkId
  } else {
    $result.ExitCode = 1
    $result.EventId  = $eventBadId
  }

  # Event log payload (plain text, no console formatting)
  $logLines = @()
  if ($result.OsCaption) { $logLines += ("OS: {0} Build={1} Version={2}" -f $result.OsCaption,$result.OsBuildNumber,$result.OsVersion) }
  $logLines += ("RunContext: Computer={0}; IsAdmin={1}; Strict={2}; Remediate={3}; RequireBlockList={4}" -f $result.ComputerName,$result.IsAdmin,$result.Strict,$result.RemediateRequested,$result.RequireBlockList)
  $logLines += ("Config: Loaded={0}; Reason={1}; Path={2}" -f $result.ConfigLoaded,$result.ConfigLoadReason,$sanitizedConfigPath)
  $logLines += ("Policy: DeviceGuardPresent={0} Key={1}" -f $result.PolicyDeviceGuardPresent,$result.PolicyDeviceGuardKey)
  $logLines += ("LSASS PPL: RunAsPPL={0}; RunAsPPLBoot={1}; Configured={2}" -f $result.Lsa_RunAsPPL,$result.Lsa_RunAsPPLBoot,$result.Lsa_PplConfigured)
  $logLines += ("Credential Guard: LsaCfgFlags={0}; RegConfigured={1}; Running={2}" -f $result.Lsa_LsaCfgFlags,$result.Cg_RegistryConfigured,$result.Cg_Running)
  $logLines += ("VBS/HVCI (Reg): VBS={0}; RequirePlatformSecurityFeatures={1}; DG.Locked={2}; HVCI.Enabled={3}; HVCI.Locked={4}" -f $result.Dg_EnableVbs,$result.Dg_RequirePlatformSec,$result.Dg_Locked,$result.Hvci_Enabled,$result.Hvci_Locked)
  $logLines += ("Blocklist: Value={0}; Active={1}; Key={2}" -f $result.Ci_Blocklist_Value,$result.Ci_Blocklist_Active,$ciCfg)
  $logLines += ("DeviceGuard (Runtime): Configured=({0}); Running=({1}); VBS.Status={2}" -f ($result.Dg_SecurityServicesConfigured -join ','),($result.Dg_SecurityServicesRunning -join ','),$result.Dg_VbsStatus)
  $logLines += ("Runtime flags: VBS.Running={0}; CG.Running={1}; HVCI.Running={2}" -f $result.Vbs_Running,$result.Cg_Running,$result.Hvci_Running)
  $logLines += ("HypervisorPresent={0}" -f $result.HypervisorPresent)

  foreach ($m in $result.Issues)   { $logLines += ("Issue: {0}" -f $m) }
  foreach ($w in $result.Warnings) { $logLines += ("Warning: {0}" -f $w) }

  if ($result.RemediationPerformed -and $result.RemediationActions.Count -gt 0) {
    $logLines += ("RemediationApplied: {0}" -f ($result.RemediationActions -join '; '))
  }
  if ($result.RebootRequired) { $logLines += "RebootRequired=True (changes take effect after reboot)" }

  $logText = $logLines -join "`r`n"

  if ($result.ExitCode -eq 0) {
    Write-HealthEvent -Id $result.EventId -Msg $logText -Level 'Information' -Source $source
  } else {
    Write-HealthEvent -Id $result.EventId -Msg $logText -Level 'Warning' -Source $source
  }

  # Pretty console output (Write-UiLine only; does not pollute pipeline)
  Write-PrettySummary -Result $result -Cfg $cfg -SanitizedConfigPath $sanitizedConfigPath

} catch {
  $result.Compliant = $false
  $result.ExitCode  = 2
  $result.EventId   = $eventErrId
  $result.Issues   += ("Unhandled error: {0}" -f $_.Exception.Message)

  $errText = ("LSASS/CG/HVCI/VBS/Blocklist Check: error: {0}" -f $_.Exception.Message)
  Write-HealthEvent -Id $eventErrId -Msg $errText -Level 'Error' -Source $source
  Write-UiLine $errText -ForegroundColor (Get-ConsoleColorSafe -Name ([string]$cfg.ColorBad) -Fallback 'Red')
}

# V2 output contract
$resultToken = if ($result.ExitCode -ne 0) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = New-V2ResultObject -ScriptName '13-LSASS-CG-HVCI-VBS.ps1' -Mode $Mode -Result $resultToken -Findings @($script:Findings) -Summary $result -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }

exit $result.ExitCode



