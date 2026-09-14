#requires -version 5.1
<#
.SYNOPSIS
  Provides private credential protection audit phases.
.DESCRIPTION
  Preserves capability-local security policy, explicit confirmation, registry and runtime observations, and result serialization behavior.
#>

function Write-PrettySummary {
  param([pscustomobject]$Result, [hashtable]$Cfg, [string]$SanitizedConfigPath)
  $View = @{Result = $Result
    Cfg = $Cfg
    SanitizedConfigPath = $SanitizedConfigPath
  }
  if (-not [bool]$View.Cfg.ConsoleSummary) {
    return
  }

  $View.cOk = Get-ConsoleColorSafe -Name ([string]$View.Cfg.ColorOk)   -Fallback 'Green'
  $View.cWarn = Get-ConsoleColorSafe -Name ([string]$View.Cfg.ColorWarn) -Fallback 'Yellow'
  $View.cBad = Get-ConsoleColorSafe -Name ([string]$View.Cfg.ColorBad)  -Fallback 'Red'
  $View.cInfo = Get-ConsoleColorSafe -Name ([string]$View.Cfg.ColorInfo) -Fallback 'Cyan'
  $View.cDim = Get-ConsoleColorSafe -Name ([string]$View.Cfg.ColorDim)  -Fallback 'DarkGray'

  $View.statusText = $(if ($View.Result.Compliant) {
      'OK'
    }
    else {
      'NONCOMPLIANT'
    })
  $View.statusColor = $(if ($View.Result.Compliant) {
      $View.cOk
    }
    else {
      $View.cBad
    })

  Write-CredentialSummaryHeader -View $View
  Write-CredentialSummarySignals -View $View
  Write-CredentialSummaryConfig -View $View
  Write-CredentialSummaryRemediation -View $View
  Write-CredentialSummaryIssues -View $View
}
function Write-CredentialSummaryHeader {
  param($View)
  Write-UiLine ""
  Write-UiLine "============================================================" -ForegroundColor $View.cDim
  Write-UiLine "LSASS / Credential Guard / VBS / HVCI / Driver Blocklist" -ForegroundColor $View.cInfo
  Write-UiLine "============================================================" -ForegroundColor $View.cDim

  Write-UiLine ("Computer   : {0}" -f $View.Result.ComputerName)
  if ($View.Result.OsCaption) {
    Write-UiLine ("OS         : {0} (Build {1}, Version {2})" -f $View.Result.OsCaption, $View.Result.OsBuildNumber, $View.Result.OsVersion)
  }

  Write-UiLine ("Result     : {0}" -f $View.statusText) -ForegroundColor $View.statusColor
  Write-UiLine ("Mode       : Strict={0}  RequireBlockList={1}  Remediate={2}  IsAdmin={3}" -f $View.Result.Strict, $View.Result.RequireBlockList, $View.Result.RemediateRequested, $View.Result.IsAdmin) -ForegroundColor $View.cDim


}
function Write-CredentialSummarySignals {
  param($View)
  Write-UiLine ""
  Write-UiLine "Signals" -ForegroundColor $View.cInfo
  Write-UiLine ("- LSASS PPL                : {0}" -f $(if ($View.Result.Lsa_PplConfigured) {
        'Configured'
      }
      else {
        'Not configured'
      })) -ForegroundColor $(if ($View.Result.Lsa_PplConfigured) {
      $View.cOk
    }
    else {
      $View.cBad
    })
  Write-UiLine ("- Credential Guard         : Reg={0}  Running={1}" -f $View.Result.Cg_RegistryConfigured, $View.Result.Cg_Running) -ForegroundColor $(if ($View.Result.Cg_Running) {
      $View.cOk
    }
    else {
      $View.cBad
    })
  Write-UiLine ("- VBS                      : RegEnabled={0}  Running={1}  Status={2}" -f ($View.Result.Dg_EnableVbs -eq 1), $View.Result.Vbs_Running, $View.Result.Dg_VbsStatus) -ForegroundColor $(if ($View.Result.Vbs_Running) {
      $View.cOk
    }
    else {
      $View.cBad
    })
  Write-UiLine ("- HVCI (Memory Integrity)  : RegEnabled={0}  Running={1}" -f ($View.Result.Hvci_Enabled -eq 1), $View.Result.Hvci_Running) -ForegroundColor $(if ($View.Result.Hvci_Running) {
      $View.cOk
    }
    else {
      $View.cBad
    })
  Write-UiLine ("- Vulnerable Driver Blocklist: Active={0} (Value={1})" -f $View.Result.Ci_Blocklist_Active, $View.Result.Ci_Blocklist_Value) -ForegroundColor $(if ($View.Result.Ci_Blocklist_Active) {
      $View.cOk
    }
    else {
      $View.cBad
    })


}
function Write-CredentialSummaryConfig {
  param($View)
  if ($View.Result.PolicyDeviceGuardPresent) {
    Write-UiLine ""
    Write-UiLine ("Policy     : DeviceGuard policy key present -> remediation skipped ({0})" -f $View.Result.PolicyDeviceGuardKey) -ForegroundColor $View.cWarn
  }

  Write-UiLine ""
  Write-UiLine ("Config     : Loaded={0}  Reason={1}  Path={2}" -f $View.Result.ConfigLoaded, $View.Result.ConfigLoadReason, $View.SanitizedConfigPath) -ForegroundColor $View.cDim


}
function Write-CredentialSummaryRemediation {
  param($View)
  if ($View.Result.RemediationActions.Count -gt 0) {
    Write-UiLine ""
    Write-UiLine "Remediation actions" -ForegroundColor $View.cInfo
    foreach ($a in $View.Result.RemediationActions) {
      Write-UiLine ("- {0}" -f $a) -ForegroundColor $View.cWarn
    }
  }

  if ($View.Result.RebootRequired) {
    Write-UiLine ""
    Write-UiLine "RebootRequired: True (changes take effect after reboot)" -ForegroundColor $View.cWarn
  }


}
function Write-CredentialSummaryIssues {
  param($View)
  if ($View.Result.Issues.Count -gt 0) {
    Write-UiLine ""
    Write-UiLine "Issues" -ForegroundColor $View.cInfo
    foreach ($m in $View.Result.Issues) {
      Write-UiLine ("- {0}" -f $m) -ForegroundColor $View.cBad
    }
  }

  if ($View.Result.Warnings.Count -gt 0) {
    Write-UiLine ""
    Write-UiLine "Warnings" -ForegroundColor $View.cInfo
    foreach ($w in $View.Result.Warnings) {
      Write-UiLine ("- {0}" -f $w) -ForegroundColor $View.cWarn
    }
  }

  Write-UiLine ""
  Write-UiLine ("ExitCode   : {0}" -f $View.Result.ExitCode) -ForegroundColor $View.cDim
  Write-UiLine "============================================================" -ForegroundColor $View.cDim

}
