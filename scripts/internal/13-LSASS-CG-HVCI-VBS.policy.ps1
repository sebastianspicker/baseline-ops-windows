#requires -version 5.1
<#
.SYNOPSIS
  Provides private credential protection audit phases.
.DESCRIPTION
  Preserves capability-local security policy, explicit confirmation, registry and runtime observations, and result serialization behavior.
#>

function Test-CredentialCompliance {
  param($RunState)
  if (-not $RunState.result.Lsa_PplConfigured) {
    $RunState.result.Compliant = $false
    $RunState.result.Issues += "LSASS PPL not configured"
    Add-Finding -FindingList $script:Findings -Code 'LSA-PPL-Missing' -Severity 'High' -Message 'LSASS PPL is not configured via registry.'
  }

  if ($RunState.Strict) {
    Test-CredentialStrictRuntime -RunState $RunState
  }
  else {
    Test-CredentialConfiguredRuntime -RunState $RunState
  }

  if ($RunState.RequireBlockList -and -not $RunState.result.Ci_Blocklist_Active) {
    $RunState.result.Compliant = $false
    $RunState.result.Issues += "Vulnerable Driver Blocklist not active"
    Add-Finding -FindingList $script:Findings -Code 'Blocklist-Missing' -Severity 'Medium' -Message 'Vulnerable Driver Blocklist is not active.'
  }

  Add-CredentialRuntimeFindings -RunState $RunState


}

function Test-CredentialStrictRuntime {
  param($RunState)
  if (-not $RunState.result.Vbs_Running) {
    $RunState.result.Compliant = $false
    $RunState.result.Issues += "VBS not running (VirtualizationBasedSecurityStatus != 2)"
  }
  if (-not $RunState.result.Cg_Running) {
    $RunState.result.Compliant = $false
    $RunState.result.Issues += "Credential Guard not running"
  }
  if (-not $RunState.result.Hvci_Running) {
    $RunState.result.Compliant = $false
    $RunState.result.Issues += "HVCI not running"
  }

}

function Test-CredentialConfiguredRuntime {
  param($RunState)
  Test-CredentialGuardConfigured -RunState $RunState
  Test-CredentialHvciConfigured -RunState $RunState
  Test-CredentialVbsConfigured -RunState $RunState
}

function Test-CredentialGuardConfigured {
  param($RunState)
  if (-not ($RunState.result.Cg_RegistryConfigured -or $RunState.result.Cg_Configured_Runtime -or $RunState.result.Cg_Running)) {
    $RunState.result.Compliant = $false
    $RunState.result.Issues += "Credential Guard neither configured nor running"
  }

}

function Test-CredentialHvciConfigured {
  param($RunState)
  if (-not (($RunState.result.Hvci_Enabled -eq 1) -or $RunState.result.Hvci_Configured_Runtime -or $RunState.result.Hvci_Running)) {
    $RunState.result.Compliant = $false
    $RunState.result.Issues += "HVCI neither enabled nor running"
  }

}

function Test-CredentialVbsConfigured {
  param($RunState)
  if (-not (($RunState.result.Dg_EnableVbs -eq 1) -or $RunState.result.Vbs_Running)) {
    $RunState.result.Compliant = $false
    $RunState.result.Issues += "VBS neither enabled nor running"
  }

}

function Test-CredentialRemediationGate {
  param($RunState)
  # -----------------------------
  # Remediation gate
  # -----------------------------
  if ($RunState.result.PolicyDeviceGuardPresent -and $RunState.Remediate) {
    $RunState.result.Warnings += "Remediation requested but DeviceGuard policy key exists; skipping to avoid overriding policy."
  }
  if ($RunState.Remediate -and -not $RunState.result.IsAdmin) {
    $RunState.result.Warnings += "Remediation requested but process is not elevated; skipping remediation."
  }

  $RunState.canRemediate = ($RunState.Remediate -and $RunState.result.IsAdmin -and (-not $RunState.result.PolicyDeviceGuardPresent))


}

function Add-CredentialRuntimeFindings {
  param($RunState)
  if (-not $RunState.result.Vbs_Running) {
    Add-Finding -FindingList $script:Findings -Code 'VBS-NotRunning' -Severity 'Medium' -Message 'Virtualization-Based Security is not running.'
  }
  if (-not $RunState.result.Cg_Running) {
    Add-Finding -FindingList $script:Findings -Code 'CG-NotRunning' -Severity 'Medium' -Message 'Credential Guard is not running.'
  }
  if (-not $RunState.result.Hvci_Running) {
    Add-Finding -FindingList $script:Findings -Code 'HVCI-NotRunning' -Severity 'Medium' -Message 'Hypervisor-Enforced Code Integrity (HVCI) is not running.'
  }
}
