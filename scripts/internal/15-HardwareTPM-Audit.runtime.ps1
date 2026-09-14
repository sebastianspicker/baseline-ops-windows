#requires -version 5.1
<#
.SYNOPSIS
  Provides private hardware compliance audit phases.
.DESCRIPTION
  Keeps hardware observations, policy decisions, proof output, and failure classification local to the hardware capability.
#>

function Initialize-HardwareAudit {
  param($RunState)
  $RunState.isAdmin = Test-IsAdmin
  $RunState.eventSourceOk = $true
  if (-not (Ensure-EventSource -Source $RunState.EventSource -LogName $RunState.EventLogName)) {
    $RunState.eventSourceOk = $false
    Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
  }

  $RunState.drifts = New-Object System.Collections.Generic.List[string]
  $RunState.notes = New-Object System.Collections.Generic.List[string]
  $RunState.errors = New-Object System.Collections.Generic.List[string]
  $RunState.ok = $true
  $RunState.fatalComplianceFailure = $false
  $RunState.eventWriteSucceeded = $null

  $RunState.proof = [ordered]@{
    Time = (Get-Date).ToString('s')
    Hostname = $env:COMPUTERNAME
    Context = [ordered]@{
      UserName = $env:USERNAME
      IsAdmin = $RunState.isAdmin
      PSVersion = $PSVersionTable.PSVersion.ToString()
      EventSourceOk = $RunState.eventSourceOk
      CatalogPath = $(if ($RunState.CatalogPath) {
          $RunState.CatalogPath
        }
        else {
          $null
        })
      ConfigPath = $(if ($RunState.ConfigPath) {
          $RunState.ConfigPath
        }
        else {
          $null
        })
    }
    Results = [ordered]@{}
    Errors = @()
  }


}

function Read-HardwareAuditCatalog {
  param($RunState)
  $RunState.cat = Load-Catalog -CatalogPath $RunState.CatalogPath -ConfigPath $RunState.ConfigPath -DefaultOutFile $RunState.DefaultOutFile

  $RunState.outFile = $RunState.DefaultOutFile
  if ($RunState.cat -and $RunState.cat.Proof -and $RunState.cat.Proof.OutFile) {
    $RunState.outFile = [string]$RunState.cat.Proof.OutFile
  }
  if (-not $RunState.outFile) {
    $RunState.outFile = $RunState.DefaultOutFile
  }


}

function Save-HardwareProof {
  param($RunState)
  # Finalize
  $RunState.proof.Results.OverallOk = $RunState.ok
  $RunState.proof.Results.Drifts = $RunState.drifts.ToArray()
  $RunState.proof.Results.Notes = $RunState.notes.ToArray()
  $RunState.proof.Errors = $RunState.errors.ToArray()

  Save-Json -InputObject $RunState.proof -Path $RunState.outFile -Depth 10


}

function Write-HardwareHealthEvent {
  param($RunState)
  $msg = Get-HardwareEventMessage -RunState $RunState

  $eventId = 4890
  $level = 'Information'
  if (-not $RunState.ok) {
    $eventId = 4900
    $level = 'Warning'
  }
  if ($RunState.Strict -and $RunState.drifts.Count -gt 0) {
    $eventId = 4900
    $level = 'Warning'
  }

  $RunState.eventWriteSucceeded = Write-HealthEvent -Id $eventId -Message $msg -Level $level -Source $RunState.EventSource -LogName $RunState.EventLogName
  if ($RunState.eventWriteSucceeded -eq $false) {
    Add-ListItem -List ([ref]$RunState.notes) -Text 'Required event log write failed.'
  }


}

function Add-HardwareFindings {
  param($RunState)
  foreach ($d in @($RunState.drifts)) {
    # Map drift strings to finding codes based on content keywords
    $code = 'HW-Drift'
    if ($d -match 'TPM') {
      $code = 'HW-TPMDrift'
    }
    if ($d -match 'Secure') {
      $code = 'HW-SecureBootDrift'
    }
    if ($d -match 'BitLocker') {
      $code = 'HW-BitLockerDrift'
    }
    [void](Add-Finding -FindingList $script:Findings -Code $code -Severity 'High' -Message $d)
  }
  foreach ($e in @($RunState.errors)) {
    [void](Add-Finding -FindingList $script:Findings -Code 'HW-Error' -Severity 'High' -Message $e)
  }
  if ($RunState.eventWriteSucceeded -eq $false) {
    [void](Add-Finding -FindingList $script:Findings -Code 'HW-EventLogWriteFailed' -Severity 'Medium' -Message 'Required event log write failed.')
  }


}
function Invoke-HardwareAudit {
  param($RunState)
  Initialize-HardwareAudit -RunState $RunState
  try {
    Read-HardwareAuditCatalog -RunState $RunState
    Read-HardwareTpm -RunState $RunState
    Read-HardwareSecureBoot -RunState $RunState
    Read-HardwareBitLocker -RunState $RunState
    Read-HardwareBios -RunState $RunState
    Save-HardwareProof -RunState $RunState
    Write-HardwareHealthEvent -RunState $RunState
    Write-HardwareSummary -RunState $RunState
    Write-HardwareTpmSummary -RunState $RunState
    Write-HardwareBootSummary -RunState $RunState
    Write-HardwareDriftSummary -RunState $RunState
    Write-HardwareNotesSummary -RunState $RunState
    [pscustomobject]$RunState.proof
  }
  catch {
    $errMsg = "Hardware/TPM-Audit failed: " + $_.Exception.Message
    Add-ListItem -List ([ref]$RunState.errors) -Text $errMsg
    Write-HealthEvent -Id 4900 -Message $errMsg -Level 'Error' -Source $RunState.EventSource -LogName $RunState.EventLogName
    Write-UiHeader -Title "Hardware/TPM Audit Summary"
    Write-UiLine -Text $errMsg -Color 'ERR'
  }

  Add-HardwareFindings -RunState $RunState
}

function New-HardwareRunState {
  param([hashtable]$Inputs)
  $state = @{
    CatalogPath = $null
    ConfigPath = $null
    Strict = $null
    EventLogName = $null
    EventSource = $null
    DefaultOutFile = $null
    isAdmin = $null
    eventSourceOk = $null
    drifts = $null
    notes = $null
    errors = $null
    ok = $null
    fatalComplianceFailure = $null
    eventWriteSucceeded = $null
    proof = $null
    cat = $null
    outFile = $null
  }
  foreach ($key in $Inputs.Keys) {
    $state[$key] = $Inputs[$key]
  }
  $state.EventLogName = 'Application'
  $state.EventSource = 'HardwareTPM-Audit'
  $state.DefaultOutFile = Join-Path ([System.IO.Path]::GetTempPath()) 'HardwareCompliance.json'
  return $state
}

function Get-HardwareEventMessage {
  param($RunState)
  # Event message (keep compact)
  $lines = @()
  if ($RunState.drifts.Count -gt 0) {
    $lines += ("Drift: " + ($RunState.drifts.ToArray() -join " | "))
  }
  if ($RunState.notes.Count -gt 0) {
    $lines += ("Notes: " + ($RunState.notes.ToArray() -join " | "))
  }
  if ($lines.Count -eq 0) {
    $lines += "TPM/BitLocker/SecureBoot baseline compliant."
  }
  $msg = $lines -join "`r`n"

  return $msg
}
