#requires -version 5.1
<#
.SYNOPSIS
  Provides private hardware compliance audit phases.
.DESCRIPTION
  Keeps hardware observations, policy decisions, proof output, and failure classification local to the hardware capability.
#>

function Write-HardwareSummary {
  param($RunState)
  # Formatted console output (host stream)
  $summaryObj = [pscustomobject]@{ ComputerName = $env:COMPUTERNAME
    Timestamp = Get-Date
  }
  $findingsAL = [System.Collections.ArrayList]::new()
  foreach ($finding in @($script:Findings.ToArray())) {
    [void]$findingsAL.Add($finding)
  }
  Write-ConsoleSummary -Summary $summaryObj -Findings $findingsAL `
    -CustomFields ([ordered]@{
      Status = $(if ($RunState.ok) {
          'COMPLIANT'
        }
        else {
          'NON-COMPLIANT'
        })
      Proof = $RunState.outFile
    })

}

function Write-HardwareTpmSummary {
  param($RunState)
  # TPM status
  $tpm = $RunState.proof.Results.TPM
  if ($tpm) {
    $tpmPresent = [bool]$tpm.Present
    $tpmKind = if ($tpmPresent) {
      'OK'
    }
    else {
      'ERR'
    }
    Write-UiLine -Text ("TPM    : {0}" -f $(if ($tpmPresent) {
          "Present"
        }
        else {
          "Missing/No Access"
        })) -Color $tpmKind
    if ($tpmPresent) {
      Write-UiLine -Text ("         SpecVersion={0}, Owned={1}, Enabled={2}, Activated={3}, Ready={4}" -f $tpm.SpecVersion, $tpm.IsOwned, $tpm.Enabled, $tpm.Activated, $tpm.Ready) -Color 'DIM'
    }
  }

}

function Write-HardwareBootSummary {
  param($RunState)
  # SecureBoot status
  Write-UiLine -Text ("Secure : {0}" -f $(if ($RunState.proof.Results.SecureBoot) {
        "Secure Boot ON"
      }
      else {
        "Secure Boot OFF/Unknown"
      })) -Color $(if ($RunState.proof.Results.SecureBoot) {
      'OK'
    }
    else {
      'WARN'
    })
  # BitLocker status
  $blOk = $RunState.proof.Results.BitLockerOsProtected
  Write-UiLine -Text ("BL(OS) : {0}" -f $(if ($blOk) {
        "Protection ON"
      }
      else {
        "Protection OFF/Unknown"
      })) -Color $(if ($blOk) {
      'OK'
    }
    else {
      'WARN'
    })

}

function Write-HardwareDriftSummary {
  param($RunState)
  # Drifts
  Write-UiLine ""
  if ($RunState.drifts.Count -gt 0) {
    Write-UiLine -Text "Drifts :" -Color 'ERR'
    foreach ($d in $RunState.drifts) {
      Write-UiLine -Text ("- {0}" -f $d) -Color 'ERR'
    }
  }
  else {
    Write-UiLine -Text "Drifts : (none)" -Color 'OK'
  }

}

function Write-HardwareNotesSummary {
  param($RunState)
  # Notes
  if ($RunState.notes.Count -gt 0) {
    Write-UiLine ""
    Write-UiLine -Text "Notes  :" -Color 'WARN'
    foreach ($n in $RunState.notes) {
      Write-UiLine -Text ("- {0}" -f $n) -Color 'WARN'
    }
  }
  else {
    Write-UiLine -Text "Notes  : (none)" -Color 'DIM'
  }


}
