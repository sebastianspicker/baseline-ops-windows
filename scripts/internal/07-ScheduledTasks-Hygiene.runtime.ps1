<#
.SYNOPSIS
Coordinates scheduled task hygiene collection and reporting.

.DESCRIPTION
Maintains the capability run state across catalog loading, task observations,
optional remediation, evidence persistence, and presentation.
#>

function New-ScheduledTaskHygieneState {
  param([hashtable]$Inputs)
  return @{
    Inputs = $Inputs
    Proof = [pscustomobject]([ordered]@{
      Time = (Get-Date).ToString('s')
      Hostname = $env:COMPUTERNAME
      Summary = [pscustomobject]([ordered]@{})
      Notes = @()
      Critical = @()
      Risky = @()
      Actions = @()
      Drift = @()
    })
    Ok = $true
    Drifts = New-Object System.Collections.Generic.List[string]
    Changes = New-Object System.Collections.Generic.List[string]
    EnumerationSucceeded = $true
    EnumerationError = $null
    ErrorMessage = $null
  }
}

function New-ScheduledTaskHygieneInputs {
  param(
    [string]$CatalogPath,
    [string]$ConfigPath,
    [bool]$Remediate,
    [bool]$Strict
  )
  return @{
    CatalogPath = $CatalogPath
    ConfigPath = $ConfigPath
    Remediate = $Remediate
    Strict = $Strict
    EventSource = 'TasksHygiene'
    DefaultQuarantineDir = Join-Path ([System.IO.Path]::GetTempPath()) 'TasksHygiene-Quarantine'
    DefaultProofOutFile = Join-Path ([System.IO.Path]::GetTempPath()) 'TasksHygiene-proof.json'
  }
}

function Read-ScheduledTaskInventory {
  param([hashtable]$RunState)
  try {
    $tasks = @(Get-ScheduledTask -ErrorAction Stop)
  }
  catch {
    $RunState.EnumerationSucceeded = $false
    $RunState.EnumerationError = $_.Exception.Message
    $RunState.Ok = $false
    $RunState.Drifts.Add("Scheduled task enumeration failed: $($RunState.EnumerationError)")
    $tasks = @()
  }
  $RunState.TaskInfos = @(foreach ($task in $tasks) { Get-TaskInfo -Task $task })
}

function Initialize-ScheduledTaskHygiene {
  param([hashtable]$RunState)
  $RunState.IsAdmin = Test-IsAdmin
  if (-not $RunState.IsAdmin) {
    $RunState.Proof.Notes += 'Not elevated - remediation may fail.'
    if ($RunState.Inputs.Strict) { $RunState.Ok = $false }
  }
  $fallback = Get-DefaultCatalog -QuarantineDir $RunState.Inputs.DefaultQuarantineDir `
    -ProofOutFile $RunState.Inputs.DefaultProofOutFile
  $RunState.Catalog = Load-Catalog -CatalogPath $RunState.Inputs.CatalogPath `
    -ConfigPath $RunState.Inputs.ConfigPath -DefaultCatalog $fallback
  Initialize-TaskCatalogRegex -Catalog $RunState.Catalog
  if (-not (Ensure-EventSource -Source $RunState.Inputs.EventSource)) {
    Write-Warning 'EventSource could not be registered. EventLog tracing will be unavailable.'
  }
  $RunState.Catalog.QuarantineDir = Coalesce-String `
    (Get-PropValue $RunState.Catalog 'QuarantineDir' $null) $RunState.Inputs.DefaultQuarantineDir
  $proof = Get-PropValue $RunState.Catalog 'Proof' $null
  if ($null -eq $proof) {
    $RunState.Catalog | Add-Member -NotePropertyName Proof `
      -NotePropertyValue ([pscustomobject]([ordered]@{ OutFile = $RunState.Inputs.DefaultProofOutFile })) -Force
    $proof = $RunState.Catalog.Proof
  }
  $proof.OutFile = Coalesce-String (Get-PropValue $proof 'OutFile' $null) $RunState.Inputs.DefaultProofOutFile
  $RunState.ProofSettings = $proof
  Read-ScheduledTaskInventory -RunState $RunState
}

function Add-CriticalTaskRecord {
  param([hashtable]$RunState, $TaskInfo, $Records)
  $result = Enable-TaskIfPresent -TaskName $TaskInfo.Name -TaskPath $TaskInfo.TaskPath `
    -Remediate:$RunState.Inputs.Remediate
  if (-not $result.Ok -and $result.Message) {
    $RunState.Ok = $false
    $RunState.Drifts.Add($result.Message)
  }
  elseif ($result.Message) {
    $RunState.Changes.Add($result.Message)
    $RunState.Proof.Actions += $result.Message
  }
  $Records.Add([pscustomobject]([ordered]@{
    FullPath = $TaskInfo.FullPath
    Enabled = $TaskInfo.Enabled
    LastRun = $TaskInfo.LastRunTime
    NextRun = $TaskInfo.NextRunTime
  }))
}

function Test-CriticalScheduledTasks {
  param([hashtable]$RunState)
  $records = New-Object System.Collections.Generic.List[object]
  foreach ($pattern in @($RunState.Catalog.CriticalTasks)) {
    $taskMatches = @($RunState.TaskInfos | Where-Object { $pattern.IsMatch($_.FullPath) })
    if ($taskMatches.Count -eq 0) {
      $RunState.Drifts.Add("Critical missing: $pattern")
      $RunState.Ok = $false
      continue
    }
    foreach ($taskInfo in $taskMatches) {
      Add-CriticalTaskRecord -RunState $RunState -TaskInfo $taskInfo -Records $records
    }
  }
  $RunState.Proof.Critical = $records.ToArray()
}

function Add-ScheduledTaskQuarantineResult {
  param([hashtable]$RunState, $TaskInfo)
  $result = Quarantine-Task -TaskName $TaskInfo.Name -TaskPath $TaskInfo.TaskPath `
    -QuarantineDir $RunState.Catalog.QuarantineDir -Remediate:$RunState.Inputs.Remediate
  if ($result.Ok -and @($result.Actions).Count -gt 0) {
    foreach ($action in @($result.Actions)) {
      $RunState.Changes.Add($action)
      $RunState.Proof.Actions += $action
    }
  }
  elseif ($result.Error) {
    $RunState.Ok = $false
    $RunState.Drifts.Add($result.Error)
  }
}

function Add-RiskyScheduledTaskRecord {
  param([hashtable]$RunState, $TaskInfo, $Risk, $Records)
  $Records.Add([pscustomobject]([ordered]@{
    FullPath = $TaskInfo.FullPath
    Enabled = $TaskInfo.Enabled
    RunLevel = $TaskInfo.RunLevel
    Hidden = $TaskInfo.Hidden
    Triggers = $TaskInfo.Triggers
    ActionPath = $Risk.ActionPath
    CommandLine = $Risk.CommandLine
    WorkingDirectory = $Risk.WorkingDirectory
    PublisherSubject = $Risk.PublisherSubject
    SignedValid = $Risk.PublisherValid
    SignatureStatus = $Risk.SignatureStatus
    Reasons = $Risk.Reasons
  }))
  $reason = (@($Risk.Reasons) -join '; ')
  if ([string]::IsNullOrWhiteSpace($reason)) { $reason = 'risk rule matched' }
  $RunState.Ok = $false
  $RunState.Drifts.Add(("Suspicious scheduled task: {0} ({1})" -f $TaskInfo.FullPath, $reason))
  if ([bool]$RunState.Catalog.PurgeUnapproved) {
    Add-ScheduledTaskQuarantineResult -RunState $RunState -TaskInfo $TaskInfo
  }
}

function Find-RiskyScheduledTasks {
  param([hashtable]$RunState)
  $records = New-Object System.Collections.Generic.List[object]
  foreach ($taskInfo in $RunState.TaskInfos) {
    $risk = Evaluate-TaskRisk -TaskInfo $taskInfo -Catalog $RunState.Catalog
    if ($risk.IsCritical -or $risk.IsAllowed -or -not $risk.Risky) { continue }
    Add-RiskyScheduledTaskRecord -RunState $RunState -TaskInfo $taskInfo -Risk $risk -Records $records
  }
  $RunState.Proof.Risky = $records.ToArray()
}

function Set-ScheduledTaskHygieneSummary {
  param([hashtable]$RunState)
  $RunState.Proof.Summary = [pscustomobject]([ordered]@{
    TotalTasks = @($RunState.TaskInfos).Count
    CriticalKnown = @($RunState.Proof.Critical).Count
    RiskyDetected = @($RunState.Proof.Risky).Count
    PurgeEnabled = [bool]$RunState.Catalog.PurgeUnapproved
    Remediate = [bool]$RunState.Inputs.Remediate
    Strict = [bool]$RunState.Inputs.Strict
    IsAdmin = [bool]$RunState.IsAdmin
    EnumerationSucceeded = [bool]$RunState.EnumerationSucceeded
    EnumerationError = $RunState.EnumerationError
    ProofOutFile = $RunState.ProofSettings.OutFile
    QuarantineDir = $RunState.Catalog.QuarantineDir
  })
  Save-Json -InputObject $RunState.Proof -Path $RunState.ProofSettings.OutFile -Depth 25
  $RunState.Changes.Add("Proof JSON: $($RunState.ProofSettings.OutFile)")
  foreach ($note in @($RunState.Proof.Notes)) { $RunState.Drifts.Add($note) }
}

function Write-ScheduledTaskHygieneEvent {
  param([hashtable]$RunState)
  $lines = Get-ScheduledTaskHygieneEventLines -RunState $RunState
  $eventId = if ($RunState.Ok -and -not $RunState.Inputs.Strict) { 5040 } else { 5050 }
  $level = if ($RunState.Ok -and -not $RunState.Inputs.Strict) { 'Information' } else { 'Warning' }
  Write-HealthEvent -Id $eventId -Msg ($lines -join "`r`n") -Level $level -Source $RunState.Inputs.EventSource
}

function Get-ScheduledTaskHygieneEventLines {
  param([hashtable]$RunState)
  $lines = New-Object System.Collections.Generic.List[string]
  if ($RunState.Changes.Count -gt 0) {
    $lines.Add('Changed: ' + (($RunState.Changes | Select-Object -Unique) -join ' | '))
  }
  if ($RunState.Drifts.Count -gt 0) {
    $lines.Add('Drift:   ' + (($RunState.Drifts | Select-Object -Unique) -join ' | '))
  }
  if ($lines.Count -eq 0) {
    $lines.Add('Scheduled tasks compliant; critical enabled; no risky tasks found.')
  }
  return $lines.ToArray()
}

function Write-ScheduledTaskHygieneStatus {
  param([hashtable]$RunState)
  if ($RunState.Ok -and -not $RunState.Inputs.Strict) {
    Write-UiStatus -Label 'OK' -State OK -Text 'No drift detected (or Strict is off).'
  }
  elseif ($RunState.Ok) {
    Write-UiStatus -Label 'WARN' -State WARN -Text 'Strict mode enabled; review drift messages below.'
  }
  else {
    Write-UiStatus -Label 'FAIL' -State FAIL -Text 'Drift detected.'
  }
}

function Write-ScheduledTaskHygieneLists {
  param([hashtable]$RunState)
  if ($RunState.Changes.Count -gt 0) {
    Write-UiLine ''
    Write-UiLine 'Changes:' DarkGray
    foreach ($change in ($RunState.Changes | Select-Object -Unique)) {
      Write-UiStatus -Label 'CHG' -State INFO -Text $change
    }
  }
  if ($RunState.Drifts.Count -gt 0) {
    Write-UiLine ''
    Write-UiLine 'Drifts:' DarkGray
    foreach ($drift in ($RunState.Drifts | Select-Object -Unique)) {
      Write-UiStatus -Label 'DRF' -State WARN -Text $drift
    }
  }
}

function Write-ScheduledTaskHygieneSummary {
  param([hashtable]$RunState)
  Write-UiHeader 'Scheduled Tasks Hygiene Summary'
  Write-KeyValue 'Host' $RunState.Proof.Hostname
  Write-KeyValue 'Time' $RunState.Proof.Time
  Write-KeyValue 'Admin' $RunState.Proof.Summary.IsAdmin
  Write-KeyValue 'Remediate' $RunState.Proof.Summary.Remediate
  Write-KeyValue 'Purge' $RunState.Proof.Summary.PurgeEnabled
  Write-KeyValue 'Strict' $RunState.Proof.Summary.Strict
  Write-UiLine ''
  Write-KeyValue 'Tasks' $RunState.Proof.Summary.TotalTasks
  Write-KeyValue 'Critical' $RunState.Proof.Summary.CriticalKnown
  Write-KeyValue 'Risky' $RunState.Proof.Summary.RiskyDetected
  Write-UiLine ''
  Write-KeyValue 'Proof JSON' $RunState.Proof.Summary.ProofOutFile
  Write-KeyValue 'Quarantine' $RunState.Proof.Summary.QuarantineDir
  Write-UiLine ''
  Write-ScheduledTaskHygieneStatus -RunState $RunState
  Write-ScheduledTaskHygieneLists -RunState $RunState
  Write-UiLine ''
  Write-UiLine ('-' * 44) -ForegroundColor DarkGray
}

function Set-ScheduledTaskHygieneError {
  param([hashtable]$RunState, $ErrorRecord)
  $regexTimeout = $ErrorRecord.Exception -is [System.Text.RegularExpressions.RegexMatchTimeoutException] -or
    $ErrorRecord.Exception.InnerException -is [System.Text.RegularExpressions.RegexMatchTimeoutException]
  $prefix = if ($regexTimeout) { 'Tasks hygiene incomplete evidence: regex match timed out: ' } else { 'Tasks hygiene error: ' }
  $RunState.ErrorMessage = $prefix + $ErrorRecord.Exception.Message
  Write-HealthEvent -Id 5050 -Msg $RunState.ErrorMessage -Level Error -Source $RunState.Inputs.EventSource
  Write-UiHeader 'Scheduled Tasks Hygiene Summary'
  Write-UiStatus -Label FAIL -State FAIL -Text $RunState.ErrorMessage
  [void](Add-Finding -FindingList $script:Findings -Code 'TASK-Error' -Severity High -Message $RunState.ErrorMessage)
}

function Add-ScheduledTaskHygieneFindings {
  param([hashtable]$RunState)
  foreach ($drift in @($RunState.Drifts)) {
    $finding = Get-ScheduledTaskHygieneFinding -Message $drift
    [void](Add-Finding -FindingList $script:Findings -Code $finding.Code -Severity $finding.Severity -Message $drift)
  }
}

function Get-ScheduledTaskHygieneFinding {
  param([string]$Message)
  if ($Message -match 'Critical missing') { return @{ Code = 'TASK-CriticalMissing'; Severity = 'High' } }
  if ($Message -match 'Scheduled task enumeration failed') { return @{ Code = 'TASK-EnumerationFailed'; Severity = 'High' } }
  if ($Message -match 'Suspicious') { return @{ Code = 'TASK-Suspicious'; Severity = 'High' } }
  if ($Message -match 'quarantine') { return @{ Code = 'TASK-QuarantineIssue'; Severity = 'Medium' } }
  return @{ Code = 'TASK-Drift'; Severity = 'Medium' }
}

function Invoke-ScheduledTaskHygiene {
  param([hashtable]$RunState)
  try {
    Initialize-ScheduledTaskHygiene -RunState $RunState
    Test-CriticalScheduledTasks -RunState $RunState
    Find-RiskyScheduledTasks -RunState $RunState
    Set-ScheduledTaskHygieneSummary -RunState $RunState
    Write-ScheduledTaskHygieneEvent -RunState $RunState
    Write-ScheduledTaskHygieneSummary -RunState $RunState
    Add-ScheduledTaskHygieneFindings -RunState $RunState
  }
  catch {
    Set-ScheduledTaskHygieneError -RunState $RunState -ErrorRecord $_
  }
}

function Get-ScheduledTaskHygieneV2Summary {
  param([hashtable]$RunState)
  if ($RunState.ErrorMessage) { return @{ Error = $RunState.ErrorMessage } }
  return [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp = Get-Date
    TotalTasks = $RunState.Proof.Summary.TotalTasks
    CriticalKnown = $RunState.Proof.Summary.CriticalKnown
    RiskyDetected = $RunState.Proof.Summary.RiskyDetected
    EnumerationSucceeded = [bool]$RunState.EnumerationSucceeded
    EnumerationError = $RunState.EnumerationError
  }
}
