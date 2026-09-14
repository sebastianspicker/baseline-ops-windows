#requires -version 5.1
<#
.SYNOPSIS
  Provides private LAPS hygiene phases.
.DESCRIPTION
  Preserves policy precedence, rotation decisions, diagnostics, and result reporting for the public capability.
#>

function Initialize-LapsConfiguration {
  param($RunState)
  $Defaults = [pscustomobject]@{
    EventLog = [pscustomobject]@{
      Enabled = $true
      LogName = 'Application'
      Source = 'LAPS-Hygiene'
      OkEventId = 3400
      WarnEventId = 3410
    }
    PolicyDefaults = [pscustomobject]@{
      PasswordAgeDays = 30
    }
    Remediation = [pscustomobject]@{
      SleepAfterRotateSec = 3
      CollectDiagnosticsOnFail = $true
      DiagnosticsFolder = "$env:TEMP\LapsDiagnostics"
    }
    Console = [pscustomobject]@{
      Enabled = $true
      UseWriteInformation = $false  # colors only via Write-UiLine
      ShowConfigPath = $false
      Width = 60
    }
  }
  $RunState.Config = Get-ConfigFromJson -Path $RunState.ConfigPath -DefaultsObject $Defaults
  # Clamp values
  if ($RunState.MinDaysBeforeRotate -lt 0) {
    $RunState.MinDaysBeforeRotate = 0
  }
  if ([int]$RunState.Config.PolicyDefaults.PasswordAgeDays -lt 1) {
    $RunState.Config.PolicyDefaults.PasswordAgeDays = 30
  }
  if ([int]$RunState.Config.Remediation.SleepAfterRotateSec -lt 0) {
    $RunState.Config.Remediation.SleepAfterRotateSec = 0
  }
  if ([int]$RunState.Config.Console.Width -lt 40) {
    $RunState.Config.Console.Width = 60
  }
}
function Merge-LapsEventLogConfig {
  param($Base, $Override)
  $o = $Override.EventLog
  if ($o.PSObject.Properties['Enabled']) {
    $Base.EventLog.Enabled = [bool]$o.Enabled
  }
  if ($o.PSObject.Properties['LogName']) {
    $Base.EventLog.LogName = [string]$o.LogName
  }
  if ($o.PSObject.Properties['Source']) {
    $Base.EventLog.Source = [string]$o.Source
  }
  if ($o.PSObject.Properties['OkEventId']) {
    $Base.EventLog.OkEventId = [int]$o.OkEventId
  }
  if ($o.PSObject.Properties['WarnEventId']) {
    $Base.EventLog.WarnEventId = [int]$o.WarnEventId
  }
}
function Merge-LapsPolicyDefaultsConfig {
  param($Base, $Override)
  $o = $Override.PolicyDefaults
  if ($o.PSObject.Properties['PasswordAgeDays']) {
    $Base.PolicyDefaults.PasswordAgeDays = [int]$o.PasswordAgeDays
  }
}
function Merge-LapsRemediationConfig {
  param($Base, $Override)
  $o = $Override.Remediation
  if ($o.PSObject.Properties['SleepAfterRotateSec']) {
    $Base.Remediation.SleepAfterRotateSec = [int]$o.SleepAfterRotateSec
  }
  if ($o.PSObject.Properties['CollectDiagnosticsOnFail']) {
    $Base.Remediation.CollectDiagnosticsOnFail = [bool]$o.CollectDiagnosticsOnFail
  }
  if ($o.PSObject.Properties['DiagnosticsFolder']) {
    $Base.Remediation.DiagnosticsFolder = [string]$o.DiagnosticsFolder
  }
}
function Merge-LapsConsoleConfig {
  param($Base, $Override)
  $o = $Override.Console
  if ($o.PSObject.Properties['Enabled']) {
    $Base.Console.Enabled = [bool]$o.Enabled
  }
  if ($o.PSObject.Properties['UseWriteInformation']) {
    $Base.Console.UseWriteInformation = [bool]$o.UseWriteInformation
  }
  if ($o.PSObject.Properties['ShowConfigPath']) {
    $Base.Console.ShowConfigPath = [bool]$o.ShowConfigPath
  }
  if ($o.PSObject.Properties['Width']) {
    $Base.Console.Width = [int]$o.Width
  }
}
function ConvertTo-LapsTextBool {
  param($Value, [bool]$Default)
  $s = [string]$Value
  switch ($s.Trim().ToLowerInvariant()) {
    'true' {
      return $true
    }
    'false' {
      return $false
    }
    'yes' {
      return $true
    }
    'no' {
      return $false
    }
    '1' {
      return $true
    }
    '0' {
      return $false
    }
    default {
      return $Default
    }
  }
}
function Initialize-LapsResult {
  param($RunState)
  if ($RunState.Config.EventLog.Enabled) {
    if (-not (Ensure-EventSource -Source $RunState.Config.EventLog.Source -LogName $RunState.Config.EventLog.LogName)) {
      Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
    }
  }
  $script:Findings = Get-FindingsList
  $RunState.reasonsList = New-Object System.Collections.Generic.List[string]
  $RunState.result = [pscustomobject]@{
    TimestampUtc = (Get-Date).ToUniversalTime()
    Remediate = [bool]$RunState.Remediate
    MinDaysBeforeRotate = [int]$RunState.MinDaysBeforeRotate
    PolicyType = 'None'
    PolicyMechanism = 'n/a'
    PolicyRoot = 'n/a'
    ManagedAccount = $null
    ManagedAccountExists = $false
    ManagedAccountEnabled = $false
    PasswordLastSet = $null
    PasswordAgeDays = $null
    PolicyPasswordAgeDays = $null
    ThresholdDays = $null
    PasswordComplexity = $null
    BackupDirectoryRaw = $null
    BackupDirectory = '(n/a)'
    AADJoined = $false
    ADJoined = $false
    NeedsRotate = $false
    Rotated = $false
    RotationMethod = '(n/a)'
    RotationError = $null
    DiagnosticsCollected = $false
    DiagnosticsInfo = $null
    OkOverall = $false
    Reasons = @()
  }
}
function Initialize-LapsPolicyState {
  param($RunState)
  $RunState.active = Get-ActiveLapsPolicy
  $RunState.policyType = 'None'
  $RunState.mechanism = 'n/a'
  $RunState.rootPath = 'n/a'
  $RunState.policyObj = $null
  if ($RunState.active) {
    $RunState.policyType = [string]$RunState.active.Type
    $RunState.mechanism = [string]$RunState.active.Mechanism
    $RunState.rootPath = [string]$RunState.active.RootPath
    $RunState.policyObj = $RunState.active.Policy
  }
  $RunState.result.PolicyType = $RunState.policyType
  $RunState.result.PolicyMechanism = $RunState.mechanism
  $RunState.result.PolicyRoot = $RunState.rootPath
  $RunState.isWin = ($RunState.policyType -eq 'WindowsLAPS')
  $RunState.isLeg = ($RunState.policyType -eq 'LegacyLAPS')
  $RunState.result.PolicyPasswordAgeDays = Get-PolicyPasswordAgeDays -PolicyType $RunState.policyType -PolicyObject $RunState.policyObj -DefaultAgeDays $RunState.Config.PolicyDefaults.PasswordAgeDays
  $RunState.result.PasswordComplexity = Get-PolicyComplexity -PolicyObject $RunState.policyObj
  $RunState.result.ManagedAccount = Get-ManagedAdminAccountName -PolicyType $RunState.policyType -PolicyObject $RunState.policyObj
}
function Initialize-LapsAccountState {
  param($RunState)
  $RunState.adminInfo = Get-LocalAdminInfo -Name $RunState.result.ManagedAccount
  $RunState.result.ManagedAccountExists = [bool]$RunState.adminInfo.Exists
  $RunState.result.ManagedAccountEnabled = [bool]$RunState.adminInfo.Enabled
  $RunState.result.PasswordLastSet = $RunState.adminInfo.PasswordLastSet
  if ($RunState.adminInfo.PasswordLastSet) {
    try {
      $RunState.result.PasswordAgeDays = [math]::Floor((New-TimeSpan -Start $RunState.adminInfo.PasswordLastSet -End (Get-Date)).TotalDays)
    }
    catch {
      <# best-effort: date arithmetic may fail on invalid timestamps #> $RunState.result.PasswordAgeDays = $null
    }
  }
  $RunState.result.AADJoined = [bool](Get-AADJoin)
  $RunState.result.ADJoined = [bool](Get-ADJoin)
  if ($RunState.isWin) {
    $bd = Get-WindowsLapsBackupDirectory -PolicyObject $RunState.policyObj
    $RunState.result.BackupDirectoryRaw = $bd
    $RunState.result.BackupDirectory = Convert-BackupDirectoryToText -BackupDirectory $bd
  }
  if ($null -ne $RunState.result.PolicyPasswordAgeDays) {
    $RunState.result.ThresholdDays = [math]::Max(0, ([int]$RunState.result.PolicyPasswordAgeDays - [int]$RunState.MinDaysBeforeRotate))
  }
}
function Set-LapsRotationRequirement {
  param($RunState)
  if (-not $RunState.active) {
    $RunState.reasonsList.Add("No LAPS policy detected")
  }
  else {
    if (-not $RunState.result.ManagedAccountExists) {
      $RunState.reasonsList.Add("Managed admin account not found: $($RunState.result.ManagedAccount)")
      $RunState.result.NeedsRotate = $true
    }
    Set-LapsPasswordRotationRequirement -RunState $RunState
    if ($RunState.isWin -and ($null -eq $RunState.result.BackupDirectoryRaw -or $RunState.result.BackupDirectoryRaw -eq 0)) {
      $RunState.reasonsList.Add("BackupDirectory is not configured or disabled")
      Add-Finding -FindingList $script:Findings -Code 'LAPS-MissingBackup' -Severity 'High' -Message "Windows LAPS backup directory is not configured or is disabled."
    }
  }
}
function Set-LapsPasswordRotationRequirement {
  param($RunState)
  if ($null -eq $RunState.result.PasswordAgeDays) {
    $RunState.reasonsList.Add("PasswordLastSet unknown (source=$($RunState.adminInfo.Source))")
    if ($RunState.isWin) {
      $RunState.result.NeedsRotate = $true
    }
  }
  else {
    if ($null -ne $RunState.result.ThresholdDays -and $RunState.result.PasswordAgeDays -ge $RunState.result.ThresholdDays) {
      $RunState.reasonsList.Add("Password age $($RunState.result.PasswordAgeDays) d >= threshold $($RunState.result.ThresholdDays) d")
      $RunState.result.NeedsRotate = $true
    }
  }
}
function Invoke-LapsRotation {
  param($RunState)
  if ($RunState.result.NeedsRotate -and $RunState.Remediate -and $RunState.isWin) {
    $tmp = @(Try-RotateWindowsLAPS -DoIt)
    $RunState.result.Rotated = ($tmp.Count -ge 1) -and ([bool]$tmp[0])
    $RunState.result.RotationMethod = if ($tmp.Count -ge 2) {
      [string]$tmp[1]
    }
    else {
      ''
    }
    if (-not $RunState.result.Rotated) {
      $RunState.result.RotationError = $RunState.result.RotationMethod
      Invoke-LapsFailureDiagnostics -RunState $RunState
    }
    else {
      Update-LapsPostRotationState -RunState $RunState
    }
  }
}
function Invoke-LapsFailureDiagnostics {
  param($RunState)
  if ($RunState.Config.Remediation.CollectDiagnosticsOnFail) {
    $dtmp = @(Try-CollectLapsDiagnostics -DoIt -OutputFolder $RunState.Config.Remediation.DiagnosticsFolder)
    $RunState.result.DiagnosticsCollected = ($dtmp.Count -ge 1) -and ([bool]$dtmp[0])
    $RunState.result.DiagnosticsInfo = if ($dtmp.Count -ge 2) {
      [string]$dtmp[1]
    }
    else {
      ''
    }
  }
}
function Update-LapsPostRotationState {
  param($RunState)
  Start-Sleep -Seconds $RunState.Config.Remediation.SleepAfterRotateSec
  $adminInfo2 = Get-LocalAdminInfo -Name $RunState.result.ManagedAccount
  $RunState.result.PasswordLastSet = $adminInfo2.PasswordLastSet
  if ($adminInfo2.PasswordLastSet) {
    try {
      $RunState.result.PasswordAgeDays = [math]::Floor((New-TimeSpan -Start $adminInfo2.PasswordLastSet -End (Get-Date)).TotalDays)
    }
    catch {
      Write-Verbose ("Post-rotation password age calculation failed: {0}" -f $_.Exception.Message)
    }
  }
}
function Set-LapsOverallStatus {
  param($RunState)
  $RunState.ok = Test-LapsBaseHealth -RunState $RunState
  if ($RunState.Remediate -and $RunState.isWin -and $RunState.result.NeedsRotate -and -not $RunState.result.Rotated) {
    $RunState.ok = $false
  }
  . Set-LapsLegacyRemediationStatus -RunState $RunState
  $RunState.result.OkOverall = $RunState.ok
  if (-not $RunState.result.OkOverall) {
    Add-Finding -FindingList $script:Findings -Code 'LAPS-NotCompliant' -Severity 'Medium' -Message "LAPS health check failed: $([string]::Join('; ', $RunState.result.Reasons))" -Extra @{ Reasons = $RunState.result.Reasons }
  }
}
function Set-LapsLegacyRemediationStatus {
  param($RunState)
  if ($RunState.Remediate -and $RunState.isLeg -and $RunState.result.NeedsRotate) {
    $RunState.ok = $false
    $RunState.reasonsList.Add("Remediation for Legacy LAPS is not implemented")
  }
}
function Write-LapsHealthEvent {
  param($RunState)
  # Event log (best effort)
  $eventMessage = @(
    "LAPS Hygiene",
    "PolicyType=$($RunState.result.PolicyType) Mechanism=$($RunState.result.PolicyMechanism) Root=$($RunState.result.PolicyRoot)",
    "Account=$($RunState.result.ManagedAccount) Exists=$($RunState.result.ManagedAccountExists) Enabled=$($RunState.result.ManagedAccountEnabled)",
    "PasswordLastSet=$(To-Iso $RunState.result.PasswordLastSet) AgeDays=$(if ($null -ne $RunState.result.PasswordAgeDays) { $RunState.result.PasswordAgeDays } else { 'n/a' })",
    "PolicyAgeDays=$($RunState.result.PolicyPasswordAgeDays) MinDaysBeforeRotate=$($RunState.result.MinDaysBeforeRotate) ThresholdDays=$(if ($null -ne $RunState.result.ThresholdDays) { $RunState.result.ThresholdDays } else { 'n/a' })",
    "BackupDirectory=$($RunState.result.BackupDirectory)",
    "Joined: AAD=$($RunState.result.AADJoined) AD=$($RunState.result.ADJoined)",
    "NeedsRotate=$($RunState.result.NeedsRotate) Remediate=$($RunState.result.Remediate) Rotated=$($RunState.result.Rotated) Via=$($RunState.result.RotationMethod)",
    "OkOverall=$($RunState.result.OkOverall)",
    "Reasons=$([string]::Join('; ', @($RunState.result.Reasons)))"
  ) -join "`r`n"
  if ($RunState.Config.EventLog.Enabled) {
    $eventId = $RunState.Config.EventLog.WarnEventId
    $eventLevel = 'Warning'
    if ($RunState.result.OkOverall) {
      $eventId = $RunState.Config.EventLog.OkEventId
      $eventLevel = 'Information'
    }
    $null = Try-WriteHealthEvent -Enabled $RunState.Config.EventLog.Enabled -Id $eventId -Msg $eventMessage -Level $eventLevel -Source $RunState.Config.EventLog.Source -LogName $RunState.Config.EventLog.LogName
  }
}
function Invoke-LapsHygiene {
  param($RunState)
  # --------------------------- Main --------------------------------------------------
  . Initialize-LapsResult -RunState $RunState
  try {
    . Initialize-LapsPolicyState -RunState $RunState
    . Initialize-LapsAccountState -RunState $RunState
    . Set-LapsRotationRequirement -RunState $RunState
    . Invoke-LapsRotation -RunState $RunState
    . Set-LapsOverallStatus -RunState $RunState
  }
  catch {
    $RunState.result.OkOverall = $false
    $msg = "Unhandled error: $($_.Exception.Message)"
    $RunState.reasonsList.Add($msg)
    Add-Finding -FindingList $script:Findings -Code 'LAPS-Error' -Severity 'High' -Message $msg
  }
  $RunState.result.Reasons = @($RunState.reasonsList)
  Write-LapsHealthEvent -RunState $RunState
  Write-LapsConsole -RunState $RunState
}

function Test-LapsBaseHealth {
  param($RunState)
  $RunState.ok = $true
  if (-not $RunState.active) {
    $RunState.ok = $false
  }
  if ($RunState.isWin -and ($null -eq $RunState.result.BackupDirectoryRaw -or $RunState.result.BackupDirectoryRaw -eq 0)) {
    $RunState.ok = $false
  }
  return $RunState.ok
}

function New-LapsRunState {
  param([hashtable]$Inputs)
  $state = @{
    result = $null
    reasonsList = $null
    isWin = $null
    isLeg = $null
    ok = $null
    active = $null
    policyType = $null
    mechanism = $null
    rootPath = $null
    policyObj = $null
    adminInfo = $null
    Remediate = $null
    MinDaysBeforeRotate = $null
    ConfigPath = $null
    Config = $null
    rotateStyle = $null
  }
  foreach ($key in $Inputs.Keys) { $state[$key] = $Inputs[$key] }
  return $state
}
