#requires -version 5.1
<#
.SYNOPSIS
  Provides private credential protection audit phases.
.DESCRIPTION
  Preserves capability-local security policy, explicit confirmation, registry and runtime observations, and result serialization behavior.
#>

function Read-CredentialRegistry {
  param($RunState)
  # OS info
  $os = Get-OsInfo
  if ($os) {
    $RunState.result.OsCaption = $os.Caption
    $RunState.result.OsBuildNumber = $os.BuildNumber
    $RunState.result.OsVersion = $os.Version
  }

  # Registry paths
  $RunState.lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  $RunState.dgRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
  $RunState.scHVCI = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
  $RunState.ciCfg = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'

  # Policy presence (policy-respecting for remediation)
  $RunState.result.PolicyDeviceGuardPresent = Test-Path -LiteralPath $RunState.result.PolicyDeviceGuardKey

  # Registry checks
  $RunState.result.Lsa_RunAsPPL = Get-RegDword -Path $RunState.lsaKey -Name 'RunAsPPL'
  $RunState.result.Lsa_RunAsPPLBoot = Get-RegDword -Path $RunState.lsaKey -Name 'RunAsPPLBoot'
  $RunState.result.Lsa_PplConfigured = (($RunState.result.Lsa_RunAsPPL -in @(1, 2)) -or ($RunState.result.Lsa_RunAsPPLBoot -eq 1))

  # Credential Guard uses LsaCfgFlags (1/2) per Microsoft documentation
  $RunState.result.Lsa_LsaCfgFlags = Get-RegDword -Path $RunState.lsaKey -Name 'LsaCfgFlags'
  $RunState.result.Cg_RegistryConfigured = ($RunState.result.Lsa_LsaCfgFlags -in 1, 2)

  # VBS/HVCI registry keys (EnableVbs, RequirePlatformSecurityFeatures, Locked, HVCI Enabled/Locked)
  $RunState.result.Dg_EnableVbs = Get-RegDword -Path $RunState.dgRoot -Name 'EnableVirtualizationBasedSecurity'
  $RunState.result.Dg_RequirePlatformSec = Get-RegDword -Path $RunState.dgRoot -Name 'RequirePlatformSecurityFeatures'
  $RunState.result.Dg_Locked = Get-RegDword -Path $RunState.dgRoot -Name 'Locked'

  $RunState.result.Hvci_Enabled = Get-RegDword -Path $RunState.scHVCI -Name 'Enabled'
  $RunState.result.Hvci_Locked = Get-RegDword -Path $RunState.scHVCI -Name 'Locked'

  $RunState.result.Ci_Blocklist_Value = Get-RegDword -Path $RunState.ciCfg -Name 'VulnerableDriverBlocklistEnable'
  $RunState.result.Ci_Blocklist_Active = ($RunState.result.Ci_Blocklist_Value -in 1, 2)


}

function Read-CredentialRuntime {
  param($RunState)
  # Runtime (Win32_DeviceGuard)
  $dg = Get-DeviceGuardInfo
  if ($dg) {
    $svcCfg = @()
    $svcRun = @()
    if ($dg.SecurityServicesConfigured) {
      $svcCfg = @($dg.SecurityServicesConfigured)
    }
    if ($dg.SecurityServicesRunning) {
      $svcRun = @($dg.SecurityServicesRunning)
    }

    $RunState.result.Dg_SecurityServicesConfigured = $svcCfg
    $RunState.result.Dg_SecurityServicesRunning = $svcRun
    $RunState.result.Dg_VbsStatus = [int]$dg.VirtualizationBasedSecurityStatus

    $RunState.result.Cg_Configured_Runtime = ($svcCfg -contains 1)
    $RunState.result.Cg_Running = ($svcRun -contains 1)
    $RunState.result.Hvci_Configured_Runtime = ($svcCfg -contains 2)
    $RunState.result.Hvci_Running = ($svcRun -contains 2)
    $RunState.result.Vbs_Running = ($RunState.result.Dg_VbsStatus -eq 2)
  }

  # Hypervisor presence (info only)
  try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $RunState.result.HypervisorPresent = [bool]$cs.HypervisorPresent
  }
  catch {
    Write-Verbose ("HypervisorPresent query failed: {0}" -f $_.Exception.Message)
  }


}
