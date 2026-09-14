#requires -version 5.1
<#
.SYNOPSIS
  Provides private credential protection audit phases.
.DESCRIPTION
  Preserves capability-local security policy, explicit confirmation, registry and runtime observations, and result serialization behavior.
#>

function Initialize-CredentialAudit {
  param($RunState)
  $RunState.eventOkId = 3600
  $RunState.eventBadId = 3610
  $RunState.eventErrId = 3611

  $RunState.cfgLoad = Try-LoadJsonConfig -Path $RunState.ConfigPath
  $RunState.cfg = $RunState.cfgLoad.Config

  # Apply config-driven defaults only if caller did not supply explicit parameters
  if ($RunState.BoundParameters.ContainsKey('Strict') -eq $false) {
    $RunState.Strict = [bool]$RunState.cfg.Strict
  }
  if ($RunState.BoundParameters.ContainsKey('RequireBlockList') -eq $false) {
    $RunState.RequireBlockList = [bool]$RunState.cfg.RequireBlockList
  }

  $RunState.source = [string]$RunState.cfg.EventSource
  $RunState.logName = [string]$RunState.cfg.EventLog
  if (-not (Ensure-EventSource -Source $RunState.source -Log $RunState.logName)) {
    Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
  }

  $RunState.sanitizedConfigPath = $(if ([string]::IsNullOrWhiteSpace($RunState.ConfigPath)) {
      $null
    }
    else {
      '[configured path]'
    })

  $RunState.result = Get-EmptyResult -Strict $RunState.Strict -RequireBlockList $RunState.RequireBlockList -Remediate $RunState.Remediate -IsAdmin (Test-IsAdmin) -ConfigPath $RunState.sanitizedConfigPath -ConfigLoaded $RunState.cfgLoad.Loaded -ConfigLoadReason $RunState.cfgLoad.Reason
  $RunState.result.EventSource = $RunState.source
  $RunState.result.EventLog = $RunState.logName


}

function Write-CredentialHealthEvent {
  param($RunState)
  # Exit/event decision
  if ($RunState.result.Compliant) {
    $RunState.result.ExitCode = 0
    $RunState.result.EventId = $RunState.eventOkId
  }
  else {
    $RunState.result.ExitCode = 1
    $RunState.result.EventId = $RunState.eventBadId
  }

  $logText = Get-CredentialEventText -RunState $RunState

  if ($RunState.result.ExitCode -eq 0) {
    Write-HealthEvent -Id $RunState.result.EventId -Msg $logText -Level 'Information' -Source $RunState.source
  }
  else {
    Write-HealthEvent -Id $RunState.result.EventId -Msg $logText -Level 'Warning' -Source $RunState.source
  }


}

function Write-CredentialAuditError {
  param($RunState, $ErrorRecord)

  $RunState.result.Compliant = $false
  $RunState.result.ExitCode = 2
  $RunState.result.EventId = $RunState.eventErrId
  $RunState.result.Issues += ("Unhandled error: {0}" -f $ErrorRecord.Exception.Message)

  $errText = ("LSASS/CG/HVCI/VBS/Blocklist Check: error: {0}" -f $ErrorRecord.Exception.Message)
  Write-HealthEvent -Id $RunState.eventErrId -Msg $errText -Level 'Error' -Source $RunState.source
  Write-UiLine $errText -ForegroundColor (Get-ConsoleColorSafe -Name ([string]$RunState.cfg.ColorBad) -Fallback 'Red')

}
function Invoke-CredentialAudit {
  param($RunState)
  Initialize-CredentialAudit -RunState $RunState
  try {
    Read-CredentialRegistry -RunState $RunState
    Read-CredentialRuntime -RunState $RunState
    Test-CredentialCompliance -RunState $RunState
    Test-CredentialRemediationGate -RunState $RunState
    Invoke-CredentialRemediation -RunState $RunState
    Write-CredentialHealthEvent -RunState $RunState
    Write-PrettySummary -Result $RunState.result -Cfg $RunState.cfg -SanitizedConfigPath $RunState.sanitizedConfigPath
  }
  catch {
    Write-CredentialAuditError -RunState $RunState -ErrorRecord $_
  }
}

function New-CredentialRunState {
  param([hashtable]$Inputs)
  $state = @{
    ConfigPath = $null
    Strict = $null
    RequireBlockList = $null
    Remediate = $null
    eventOkId = $null
    eventBadId = $null
    eventErrId = $null
    cfgLoad = $null
    cfg = $null
    source = $null
    logName = $null
    sanitizedConfigPath = $null
    result = $null
    lsaKey = $null
    dgRoot = $null
    scHVCI = $null
    ciCfg = $null
    canRemediate = $null
    BoundParameters = $null
    DecisionContext = $null
  }
  foreach ($key in $Inputs.Keys) {
    $state[$key] = $Inputs[$key]
  }
  return $state
}

function Get-CredentialEventText {
  param($RunState)
  # Event log payload (plain text, no console formatting)
  $logLines = @()
  if ($RunState.result.OsCaption) {
    $logLines += ("OS: {0} Build={1} Version={2}" -f $RunState.result.OsCaption, $RunState.result.OsBuildNumber, $RunState.result.OsVersion)
  }
  $logLines += ("RunContext: Computer={0}; IsAdmin={1}; Strict={2}; Remediate={3}; RequireBlockList={4}" -f $RunState.result.ComputerName, $RunState.result.IsAdmin, $RunState.result.Strict, $RunState.result.RemediateRequested, $RunState.result.RequireBlockList)
  $logLines += ("Config: Loaded={0}; Reason={1}; Path={2}" -f $RunState.result.ConfigLoaded, $RunState.result.ConfigLoadReason, $RunState.sanitizedConfigPath)
  $logLines += ("Policy: DeviceGuardPresent={0} Key={1}" -f $RunState.result.PolicyDeviceGuardPresent, $RunState.result.PolicyDeviceGuardKey)
  $logLines += ("LSASS PPL: RunAsPPL={0}; RunAsPPLBoot={1}; Configured={2}" -f $RunState.result.Lsa_RunAsPPL, $RunState.result.Lsa_RunAsPPLBoot, $RunState.result.Lsa_PplConfigured)
  $logLines += ("Credential Guard: LsaCfgFlags={0}; RegConfigured={1}; Running={2}" -f $RunState.result.Lsa_LsaCfgFlags, $RunState.result.Cg_RegistryConfigured, $RunState.result.Cg_Running)
  $logLines += ("VBS/HVCI (Reg): VBS={0}; RequirePlatformSecurityFeatures={1}; DG.Locked={2}; HVCI.Enabled={3}; HVCI.Locked={4}" -f $RunState.result.Dg_EnableVbs, $RunState.result.Dg_RequirePlatformSec, $RunState.result.Dg_Locked, $RunState.result.Hvci_Enabled, $RunState.result.Hvci_Locked)
  $logLines += ("Blocklist: Value={0}; Active={1}; Key={2}" -f $RunState.result.Ci_Blocklist_Value, $RunState.result.Ci_Blocklist_Active, $RunState.ciCfg)
  $logLines += ("DeviceGuard (Runtime): Configured=({0}); Running=({1}); VBS.Status={2}" -f ($RunState.result.Dg_SecurityServicesConfigured -join ','), ($RunState.result.Dg_SecurityServicesRunning -join ','), $RunState.result.Dg_VbsStatus)
  $logLines += ("Runtime flags: VBS.Running={0}; CG.Running={1}; HVCI.Running={2}" -f $RunState.result.Vbs_Running, $RunState.result.Cg_Running, $RunState.result.Hvci_Running)
  $logLines += ("HypervisorPresent={0}" -f $RunState.result.HypervisorPresent)

  foreach ($m in $RunState.result.Issues) {
    $logLines += ("Issue: {0}" -f $m)
  }
  foreach ($w in $RunState.result.Warnings) {
    $logLines += ("Warning: {0}" -f $w)
  }

  if ($RunState.result.RemediationPerformed -and $RunState.result.RemediationActions.Count -gt 0) {
    $logLines += ("RemediationApplied: {0}" -f ($RunState.result.RemediationActions -join '; '))
  }
  if ($RunState.result.RebootRequired) {
    $logLines += "RebootRequired=True (changes take effect after reboot)"
  }

  $logText = $logLines -join "`r`n"

  return $logText
}
