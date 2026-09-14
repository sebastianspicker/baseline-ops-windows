#requires -version 5.1
<#
.SYNOPSIS
  Provides private credential protection audit phases.
.DESCRIPTION
  Preserves capability-local security policy, explicit confirmation, registry and runtime observations, and result serialization behavior.
#>

function Set-CredentialLsaProtection {
  param($RunState)
  # LSASS PPL
  if ($RunState.result.Lsa_RunAsPPL -ne [int]$RunState.cfg.Baseline_LsaPpl_RunAsPPL) {
    if ($RunState.DecisionContext.ShouldProcess($RunState.lsaKey, "Set RunAsPPL=$([int]$RunState.cfg.Baseline_LsaPpl_RunAsPPL)")) {
      if (Set-RegDword -Path $RunState.lsaKey -Name 'RunAsPPL' -Value ([int]$RunState.cfg.Baseline_LsaPpl_RunAsPPL)) {
        $RunState.result.RemediationActions += ("Set RunAsPPL={0}" -f [int]$RunState.cfg.Baseline_LsaPpl_RunAsPPL)
        $RunState.result.RebootRequired = $true
      }
    }
  }
  if ($RunState.result.Lsa_RunAsPPLBoot -ne [int]$RunState.cfg.Baseline_LsaPpl_RunAsPPLBoot) {
    if ($RunState.DecisionContext.ShouldProcess($RunState.lsaKey, "Set RunAsPPLBoot=$([int]$RunState.cfg.Baseline_LsaPpl_RunAsPPLBoot)")) {
      if (Set-RegDword -Path $RunState.lsaKey -Name 'RunAsPPLBoot' -Value ([int]$RunState.cfg.Baseline_LsaPpl_RunAsPPLBoot)) {
        $RunState.result.RemediationActions += ("Set RunAsPPLBoot={0}" -f [int]$RunState.cfg.Baseline_LsaPpl_RunAsPPLBoot)
        $RunState.result.RebootRequired = $true
      }
    }
  }


}

function Set-CredentialVbsEnable {
  param($RunState)
  # VBS
  if ($RunState.result.Dg_EnableVbs -ne [int]$RunState.cfg.Baseline_Vbs_EnableVbs) {
    if ($RunState.DecisionContext.ShouldProcess($RunState.dgRoot, "Set EnableVirtualizationBasedSecurity=$([int]$RunState.cfg.Baseline_Vbs_EnableVbs)")) {
      if (Set-RegDword -Path $RunState.dgRoot -Name 'EnableVirtualizationBasedSecurity' -Value ([int]$RunState.cfg.Baseline_Vbs_EnableVbs)) {
        $RunState.result.RemediationActions += ("Set EnableVirtualizationBasedSecurity={0}" -f [int]$RunState.cfg.Baseline_Vbs_EnableVbs)
        $RunState.result.RebootRequired = $true
      }
    }
  }

}

function Set-CredentialPlatformSecurity {
  param($RunState)
  if (($null -eq $RunState.result.Dg_RequirePlatformSec) -or ($RunState.result.Dg_RequirePlatformSec -eq 0) -or ($RunState.result.Dg_RequirePlatformSec -ne [int]$RunState.cfg.Baseline_Vbs_RequirePlatformSecurityFeatures)) {
    if ($RunState.DecisionContext.ShouldProcess($RunState.dgRoot, "Set RequirePlatformSecurityFeatures=$([int]$RunState.cfg.Baseline_Vbs_RequirePlatformSecurityFeatures)")) {
      if (Set-RegDword -Path $RunState.dgRoot -Name 'RequirePlatformSecurityFeatures' -Value ([int]$RunState.cfg.Baseline_Vbs_RequirePlatformSecurityFeatures)) {
        $RunState.result.RemediationActions += ("Set RequirePlatformSecurityFeatures={0}" -f [int]$RunState.cfg.Baseline_Vbs_RequirePlatformSecurityFeatures)
        $RunState.result.RebootRequired = $true
      }
    }
  }

}

function Set-CredentialVbsLock {
  param($RunState)
  if (($null -eq $RunState.result.Dg_Locked) -or ($RunState.result.Dg_Locked -ne [int]$RunState.cfg.Baseline_Vbs_Locked)) {
    # Do not downgrade from UEFI lock (Locked=1) to a less secure value
    if ($RunState.result.Dg_Locked -ne 1 -or [int]$RunState.cfg.Baseline_Vbs_Locked -eq 1) {
      if ($RunState.DecisionContext.ShouldProcess($RunState.dgRoot, "Set DeviceGuard Locked=$([int]$RunState.cfg.Baseline_Vbs_Locked)")) {
        if (Set-RegDword -Path $RunState.dgRoot -Name 'Locked' -Value ([int]$RunState.cfg.Baseline_Vbs_Locked)) {
          $RunState.result.RemediationActions += ("Set DeviceGuard Locked={0}" -f [int]$RunState.cfg.Baseline_Vbs_Locked)
          $RunState.result.RebootRequired = $true
        }
      }
    }
  }


}

function Set-CredentialGuardFlags {
  param($RunState)
  # Credential Guard (LsaCfgFlags 1/2)
  if ($RunState.result.Lsa_LsaCfgFlags -notin 1, 2) {
    if ($RunState.DecisionContext.ShouldProcess($RunState.lsaKey, "Set LsaCfgFlags=$([int]$RunState.cfg.Baseline_CredentialGuard_LsaCfgFlags)")) {
      if (Set-RegDword -Path $RunState.lsaKey -Name 'LsaCfgFlags' -Value ([int]$RunState.cfg.Baseline_CredentialGuard_LsaCfgFlags)) {
        $RunState.result.RemediationActions += ("Set LsaCfgFlags={0}" -f [int]$RunState.cfg.Baseline_CredentialGuard_LsaCfgFlags)
        $RunState.result.RebootRequired = $true
      }
    }
  }


}

function Set-CredentialHvciEnable {
  param($RunState)
  # HVCI
  if ($RunState.result.Hvci_Enabled -ne [int]$RunState.cfg.Baseline_Hvci_Enabled) {
    if ($RunState.DecisionContext.ShouldProcess($RunState.scHVCI, "Set HVCI Enabled=$([int]$RunState.cfg.Baseline_Hvci_Enabled)")) {
      if (Set-RegDword -Path $RunState.scHVCI -Name 'Enabled' -Value ([int]$RunState.cfg.Baseline_Hvci_Enabled)) {
        $RunState.result.RemediationActions += ("Set HVCI Enabled={0}" -f [int]$RunState.cfg.Baseline_Hvci_Enabled)
        $RunState.result.RebootRequired = $true
      }
    }
  }

}

function Set-CredentialHvciLock {
  param($RunState)
  if (($null -eq $RunState.result.Hvci_Locked) -or ($RunState.result.Hvci_Locked -ne [int]$RunState.cfg.Baseline_Hvci_Locked)) {
    # Do not downgrade from UEFI lock (Locked=1) to a less secure value
    if ($RunState.result.Hvci_Locked -ne 1 -or [int]$RunState.cfg.Baseline_Hvci_Locked -eq 1) {
      if ($RunState.DecisionContext.ShouldProcess($RunState.scHVCI, "Set HVCI Locked=$([int]$RunState.cfg.Baseline_Hvci_Locked)")) {
        if (Set-RegDword -Path $RunState.scHVCI -Name 'Locked' -Value ([int]$RunState.cfg.Baseline_Hvci_Locked)) {
          $RunState.result.RemediationActions += ("Set HVCI Locked={0}" -f [int]$RunState.cfg.Baseline_Hvci_Locked)
          $RunState.result.RebootRequired = $true
        }
      }
    }
  }


}

function Set-CredentialDriverBlocklist {
  param($RunState)
  # Vulnerable Driver Blocklist
  if (-not $RunState.result.Ci_Blocklist_Active) {
    if ($RunState.DecisionContext.ShouldProcess($RunState.ciCfg, "Set VulnerableDriverBlocklistEnable=$([int]$RunState.cfg.Baseline_Blocklist_Enable)")) {
      if (Set-RegDword -Path $RunState.ciCfg -Name 'VulnerableDriverBlocklistEnable' -Value ([int]$RunState.cfg.Baseline_Blocklist_Enable)) {
        $RunState.result.RemediationActions += ("Set VulnerableDriverBlocklistEnable={0}" -f [int]$RunState.cfg.Baseline_Blocklist_Enable)
        $RunState.result.RebootRequired = $true
      }
    }
  }

}

function Invoke-CredentialRemediation {
  param($RunState)
  if ($RunState.canRemediate) {
    $RunState.result.RemediationPerformed = $true
    Set-CredentialLsaProtection -RunState $RunState
    Set-CredentialVbsEnable -RunState $RunState
    Set-CredentialPlatformSecurity -RunState $RunState
    Set-CredentialVbsLock -RunState $RunState
    Set-CredentialGuardFlags -RunState $RunState
    Set-CredentialHvciEnable -RunState $RunState
    Set-CredentialHvciLock -RunState $RunState
    Set-CredentialDriverBlocklist -RunState $RunState
  }
}
