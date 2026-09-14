#requires -version 5.1
<#
.SYNOPSIS
  Provides private Defender allowlist phases.
.DESCRIPTION
  Preserves normalization, risky-entry policy, remediation decisions, and reporting for the public capability.
#>

function Write-AllowlistConsole {
  param($RunState)
  $summaryObj = [pscustomobject]@{ ComputerName = $RunState.final.ComputerName
    Timestamp = $RunState.final.Timestamp
  }
  $findingsAL = ConvertTo-ArrayList -InputObject $script:Findings
  Write-ConsoleSummary -Summary $summaryObj -Findings $findingsAL `
    -CustomFields ([ordered]@{
      Mode = $(if ($RunState.final.Remediate) {
          'Remediate'
        }
        else {
          'Audit'
        })
      Baseline = $RunState.final.BaselineUsed
      JSON = $RunState.final.SourceJson
      Audit = $RunState.final.AuditPath
      JsonLoaded = [string]$RunState.final.JsonLoaded
      Add = [string]$RunState.final.TotalAdd
      Remove = [string]$RunState.final.TotalRemove
      Rejected = [string]$RunState.final.TotalRejected
      Errors = [string]$RunState.final.TotalErrors
      Result = $RunState.final.Result
    })
  Write-AllowlistNotes -RunState $RunState
  if ($RunState.final.PerCategory -and $RunState.final.PerCategory.Count -gt 0) {
    Write-UiLine "Per-category diff:" -ForegroundColor DarkGray
    foreach ($row in ($RunState.final.PerCategory | Sort-Object Name)) {
      Write-UiLine ("{0,-45}  Add={1,3}  Rem={2,3}  Rej={3,3}" -f $row.Name, $row.Add, $row.Remove, $row.Rejected) -ForegroundColor Gray
    }
  }
}

function Write-AllowlistNotes {
  param($RunState)
  if ($RunState.final.Notes -and $RunState.final.Notes.Count -gt 0) {
    Write-UiLine "Notes:" -ForegroundColor DarkGray
    foreach ($n in $RunState.final.Notes) {
      Write-UiLine ("- " + $n) -ForegroundColor DarkGray
    }
  }
}

function Initialize-AllowlistUnsupported {
  param($RunState)
  $RunState.final = [pscustomobject]@{
    Timestamp = (Get-Date).ToString("o")
    ComputerName = $env:COMPUTERNAME
    Remediate = [bool]$RunState.Remediate
    SourceJson = $(if ($RunState.ExceptionsPath) {
        $RunState.ExceptionsPath
      }
      else {
        "(not provided)"
      })
    AuditPath = $RunState.AuditPath
    JsonLoaded = $false
    JsonError = $null
    BaselineUsed = 'UnsupportedHost'
    Notes = @('Skipped: Microsoft Defender allowlist auditing is only supported on Windows hosts.')
    TotalAdd = 0
    TotalRemove = 0
    TotalRejected = 0
    TotalErrors = 0
    Result = 'OK_NO_DRIFT'
    Diffs = @()
    Results = @()
    ErrorsFlat = @()
    PerCategory = @()
  }

}

function Initialize-AllowlistSource {
  param($RunState)
  $cfg = Get-Config -Path $RunState.ConfigPath
  if (-not $RunState.ExceptionsPath) {
    if ($cfg -and $cfg.DefenderAllowlistPath) {
      $RunState.ExceptionsPath = [string]$cfg.DefenderAllowlistPath
    }
    elseif ($cfg -and $cfg.DefenderAllowListPath) {
      $RunState.ExceptionsPath = [string]$cfg.DefenderAllowListPath
    }
  }

  $RunState.sourceJson = $(if ($RunState.ExceptionsPath) {
      $RunState.ExceptionsPath
    }
    else {
      "(not provided)"
    })

}

function Read-AllowlistDesired {
  param($RunState)
  if ($RunState.ExceptionsPath -and (Test-Path -LiteralPath $RunState.ExceptionsPath)) {
    . Read-AllowlistJsonFile -RunState $RunState
  }
  else {
    $RunState.jsonError = "Allowlist JSON not found."
    if ($RunState.StrictJson) {
      throw $RunState.jsonError
    }
    $RunState.baselineUsed = $RunState.BaselineMode
  }

}

function Read-AllowlistJsonFile {
  param($RunState)
  try {
    $raw = Get-BoundedUtf8FileContent -Path $RunState.ExceptionsPath -MaximumBytes 1048576
    if ([string]::IsNullOrWhiteSpace($raw)) {
      $RunState.jsonError = "Allowlist JSON file is empty."
      if ($RunState.StrictJson) {
        throw $RunState.jsonError
      }
      $RunState.baselineUsed = $RunState.BaselineMode
    }
    else {
      $RunState.desired = $raw | ConvertFrom-Json
      $RunState.jsonLoaded = $true
    }
  }
  catch {
    $RunState.jsonError = $_.Exception.Message
    if ($RunState.StrictJson) {
      throw $RunState.jsonError
    }
    $RunState.baselineUsed = $RunState.BaselineMode
  }
}

function Initialize-AllowlistFallback {
  param($RunState)
  if (-not $RunState.jsonLoaded) {
    switch ($RunState.BaselineMode) {
      'Current' {
        $RunState.notes.Add("No usable JSON; baseline applied: desired state equals current state (no changes).")
        $RunState.desired = Get-NullSafeDesiredFromCurrent -Preference $RunState.pref
      }
      'Minimum' {
        $RunState.notes.Add("No usable JSON; baseline applied: minimum baseline (conservative, no broad default exclusions).")
        $RunState.desired = Get-MinimumBaselineDesiredConfig -Preference $RunState.pref
      }
    }
  }

  if (-not $RunState.desired) {
    $RunState.baselineUsed = 'DefaultSchema'
    $RunState.notes.Add("Internal fallback used (empty schema).")
    $RunState.desired = Get-DefaultDesiredConfig
  }

}

function Initialize-AllowlistDiffs {
  param($RunState)
  $jDef = $RunState.desired.Defender
  $jAsr = $RunState.desired.ASR
  $jCfa = $RunState.desired.CFA

  $RunState.diffs = @()
  $RunState.diffs += Diff-Lists -Name 'ExclusionPath'        -Kind 'path'    -Current $RunState.pref.ExclusionPath      -Desired $jDef.ExclusionPaths
  $RunState.diffs += Diff-Lists -Name 'ExclusionProcess'     -Kind 'process' -Current $RunState.pref.ExclusionProcess   -Desired $jDef.ExclusionProcesses
  $RunState.diffs += Diff-Lists -Name 'ExclusionExtension'   -Kind 'ext'     -Current $RunState.pref.ExclusionExtension -Desired $jDef.ExclusionExtensions
  $RunState.diffs += Diff-Lists -Name 'AttackSurfaceReductionOnlyExclusions' -Kind 'path'   -Current $RunState.pref.AttackSurfaceReductionOnlyExclusions -Desired $jAsr.OnlyExclusions
  $RunState.diffs += Diff-Lists -Name 'ControlledFolderAccessAllowedApplications' -Kind 'cfaapp' -Current $RunState.pref.ControlledFolderAccessAllowedApplications -Desired $jCfa.AllowedApplications
  $RunState.diffs += Diff-Lists -Name 'ControlledFolderAccessProtectedFolders'   -Kind 'path'   -Current $RunState.pref.ControlledFolderAccessProtectedFolders   -Desired $jCfa.ProtectedFolders

  $RunState.totalAdd = [int](($RunState.diffs | ForEach-Object { $_.ToAdd.Count } | Measure-Object -Sum).Sum)
  $RunState.totalRem = [int](($RunState.diffs | ForEach-Object { $_.ToRemove.Count } | Measure-Object -Sum).Sum)
  $RunState.totalBad = [int](($RunState.diffs | ForEach-Object { $_.Rejected.Count } | Measure-Object -Sum).Sum)

}

function Invoke-AllowlistDecision {
  param($RunState)
  $RunState.resultCode = $null
  $RunState.results = @()
  $RunState.errsFlat = @()

  if (($RunState.totalAdd + $RunState.totalRem + $RunState.totalBad) -eq 0) {
    $RunState.resultCode = "OK_NO_DRIFT"
    $null = Write-HealthEvent -Id 3200 -Msg "Defender/ASR allowlist OK: no drift. JSON=$($RunState.sourceJson) Audit=$($RunState.AuditPath)" -Level Information
  }
  elseif (-not $RunState.Remediate) {
    $RunState.resultCode = "DRIFT_NO_REMEDIATION"
    $null = Write-HealthEvent -Id 3210 -Msg "Defender/ASR allowlist drift: add=$($RunState.totalAdd) remove=$($RunState.totalRem) rejected=$($RunState.totalBad) (no remediation). JSON=$($RunState.sourceJson) Audit=$($RunState.AuditPath)" -Level Warning
    Add-AllowlistDriftFindings -RunState $RunState
  }
  else {
    . Invoke-AllowlistRemediation -RunState $RunState
  }

}

function Add-AllowlistDriftFindings {
  param($RunState)
  foreach ($d in $RunState.diffs) {
    if ($d.ToAdd.Count -gt 0) {
      Add-Finding -FindingList $script:Findings -Code 'ASR-Drift-Add' -Severity 'Low' -Message "ASR drift (missing): $($d.Name)" -Extra @{ Missing = $d.ToAdd }
    }
    if ($d.ToRemove.Count -gt 0) {
      Add-Finding -FindingList $script:Findings -Code 'ASR-Drift-Remove' -Severity 'Low' -Message "ASR drift (extra): $($d.Name)" -Extra @{ Extra = $d.ToRemove }
    }
    if ($d.Rejected.Count -gt 0) {
      Add-Finding -FindingList $script:Findings -Code 'ASR-Rejected' -Severity 'Medium' -Message "ASR risky entry rejected: $($d.Name)" -Extra @{ Rejected = $d.Rejected }
    }
  }
}

function Invoke-AllowlistRemediation {
  param($RunState)
  foreach ($d in $RunState.diffs) {
    $RunState.results += Apply-Diff -Diff $d -Remediate:$true
  }
  $RunState.errsFlat = @($RunState.results | ForEach-Object { $_.Errors } | Where-Object { $_ -and $_.Length -gt 0 })

  if ($RunState.errsFlat.Count -gt 0) {
    $RunState.resultCode = "REMEDIATION_ERRORS"
    $null = Write-HealthEvent -Id 3210 -Msg ("Defender/ASR allowlist sync completed with errors. add=$($RunState.totalAdd) remove=$($RunState.totalRem) rejected=$($RunState.totalBad) JSON=$($RunState.sourceJson) Audit=$($RunState.AuditPath)`r`nErrors: " + ($RunState.errsFlat -join ' | ')) -Level Error
  }
  else {
    $RunState.resultCode = "REMEDIATION_OK"
    $null = Write-HealthEvent -Id 3200 -Msg "Defender/ASR allowlist sync OK. add=$($RunState.totalAdd) remove=$($RunState.totalRem) rejected=$($RunState.totalBad) JSON=$($RunState.sourceJson) Audit=$($RunState.AuditPath)" -Level Information
  }
}

function Initialize-AllowlistResult {
  param($RunState)
  $perCategory = $RunState.diffs | ForEach-Object {
    [pscustomobject]@{
      Name = $_.Name
      Add = [int]$_.ToAdd.Count
      Remove = [int]$_.ToRemove.Count
      Rejected = [int]$_.Rejected.Count
    }
  }

  $RunState.final = [pscustomobject]@{
    Timestamp = (Get-Date).ToString("o")
    ComputerName = $env:COMPUTERNAME
    Remediate = [bool]$RunState.Remediate
    SourceJson = $RunState.sourceJson
    AuditPath = $RunState.AuditPath
    JsonLoaded = [bool]$RunState.jsonLoaded
    JsonError = $RunState.jsonError
    BaselineUsed = $RunState.baselineUsed
    Notes = @($RunState.notes)

    TotalAdd = $RunState.totalAdd
    TotalRemove = $RunState.totalRem
    TotalRejected = $RunState.totalBad
    TotalErrors = [int]@($RunState.errsFlat).Count
    Result = $RunState.resultCode

    Diffs = $RunState.diffs
    Results = $RunState.results
    ErrorsFlat = $RunState.errsFlat
    PerCategory = $perCategory
  }

}

function Initialize-AllowlistFailure {
  param($RunState)
  $msg = "Defender/ASR allowlist failed: $($_.Exception.Message)"
  $null = Write-HealthEvent -Id 3210 -Msg $msg -Level Error

  $RunState.final = [pscustomobject]@{
    Timestamp = (Get-Date).ToString("o")
    ComputerName = $env:COMPUTERNAME
    Remediate = [bool]$RunState.Remediate
    SourceJson = $(if ($RunState.ExceptionsPath) {
        $RunState.ExceptionsPath
      }
      else {
        "(not provided)"
      })
    AuditPath = $RunState.AuditPath
    JsonLoaded = $false
    JsonError = $msg
    BaselineUsed = 'None'
    Notes = @()

    TotalAdd = 0
    TotalRemove = 0
    TotalRejected = 0
    TotalErrors = 1
    Result = "FAILED"

    Diffs = @()
    Results = @()
    ErrorsFlat = @($msg)
    PerCategory = @()
  }

}

function Invoke-AllowlistRun {
  param($RunState)
  try {
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
      throw "Defender PowerShell module/cmdlets not available (Get-MpPreference missing)."
    }

    $RunState.pref = Get-MpPreference

    . Initialize-AllowlistSource -RunState $RunState
    $RunState.jsonLoaded = $false
    $RunState.jsonError = $null
    $RunState.baselineUsed = 'None'
    $RunState.notes = New-Object System.Collections.Generic.List[string]
    $RunState.desired = $null

    . Read-AllowlistDesired -RunState $RunState
    . Initialize-AllowlistFallback -RunState $RunState
    . Initialize-AllowlistDiffs -RunState $RunState
    . Invoke-AllowlistDecision -RunState $RunState
    . Initialize-AllowlistResult -RunState $RunState
    Write-AuditJson -Path $RunState.AuditPath -Object $RunState.final
    Write-AllowlistConsole -RunState $RunState
  }
  catch {
    . Initialize-AllowlistFailure -RunState $RunState
    Write-AuditJson -Path $RunState.AuditPath -Object $RunState.final
    Write-AllowlistConsole -RunState $RunState
  }

}

function Initialize-AllowlistEventSource {
  if (-not (Ensure-EventSource)) {
    Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
  }

}

function Write-AllowlistUnsupported {
  param($RunState)
  . Initialize-AllowlistUnsupported -RunState $RunState
  Write-AuditJson -Path $RunState.AuditPath -Object $RunState.final
  Write-AllowlistConsole -RunState $RunState
  $unsupportedResult = if ($Strict) {
    'FAIL'
  }
  else {
    'WARN'
  }
  $v2Result = Get-V2ResultObject -ScriptName '01-ASR-Defender-Allowlist.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $RunState.final -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) {
    $v2Result
  }
}

function New-AllowlistRunState {
  param([hashtable]$Inputs)
  $state = @{
    diffs = $null
    final = $null
    sourceJson = $null
    baselineUsed = $null
    desired = $null
    jsonLoaded = $null
    jsonError = $null
    totalAdd = $null
    totalRem = $null
    totalBad = $null
    resultCode = $null
    results = $null
    errsFlat = $null
    pref = $null
    notes = $null
    ConfigPath = $null
    ExceptionsPath = $null
    AuditPath = $null
    StrictJson = $null
    BaselineMode = $null
    Remediate = $null
  }
  foreach ($key in $Inputs.Keys) { $state[$key] = $Inputs[$key] }
  return $state
}
