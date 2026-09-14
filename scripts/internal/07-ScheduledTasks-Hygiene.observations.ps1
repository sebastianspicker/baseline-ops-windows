<#
.SYNOPSIS
Scheduled task hygiene observations helpers.

.DESCRIPTION
Contains capability-private observations behavior for scheduled task inventory and policy evaluation.
#>
function Export-TaskXmlObject {
  param([string]$TaskName,[string]$TaskPath)
  $TaskPath = Normalize-TaskPath $TaskPath
  try {
    # Export-ScheduledTask returns an XML string.
    $xml = Export-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
    return [xml]$xml
  } catch { return $null }
}

function ConvertFrom-TaskExecAction {
  param($Action)
  $command = Expand-NormalizePath ([string](Get-PropValue $Action 'Command' $null))
  $arguments = [string](Get-PropValue $Action 'Arguments' $null)
  $workingDirectory = Expand-NormalizePath ([string](Get-PropValue $Action 'WorkingDirectory' $null))
  return [pscustomobject]([ordered]@{
    Command = $command
    Arguments = $arguments
    WorkingDirectory = $workingDirectory
    CommandLine = ((@($command, $arguments) -join ' ').Trim())
    ActionType = 'Exec'
  })
}

function Get-TaskActionsFromXml {
  param([xml]$Xml)
  if ($null -eq $Xml -or $null -eq $Xml.Task) { return @() }
  $actNode = $Xml.Task.Actions
  if ($null -eq $actNode) { return @() }
  # Exec is optional; other action types may exist.
  if (-not ($actNode.PSObject.Properties.Name -contains 'Exec')) { return @() }
  $actions = @()
  foreach($a in @($actNode.Exec)) {
    if ($null -eq $a) { continue }
    $actions += ConvertFrom-TaskExecAction -Action $a
  }
  return $actions
}

function Get-TaskPrincipalMeta {
  param([xml]$Xml)
  $result = @{ PrincipalUser = $null; RunLevel = $null }
  if ($Xml.Task.Principals -and $Xml.Task.Principals.Principal) {
    try { $result.PrincipalUser = $Xml.Task.Principals.Principal.UserId } catch { $result.PrincipalUser = $null }
    try { $result.RunLevel = $Xml.Task.Principals.Principal.RunLevel } catch { $result.RunLevel = $null }
  }
  return $result
}

function Get-TaskHiddenSetting {
  param([xml]$Xml)
  $hiddenRaw = $null
  if ($Xml.Task.Settings) {
    try { $hiddenRaw = [string]$Xml.Task.Settings.Hidden } catch { $hiddenRaw = $null }
  }
  if ([string]::IsNullOrWhiteSpace($hiddenRaw)) { return $false }
  try { return [bool]::Parse($hiddenRaw) } catch { return $false }
}

function Get-TaskTriggerNames {
  param([xml]$Xml)
  $triggers = @()
  if ($Xml.Task.Triggers -and $Xml.Task.Triggers.ChildNodes) {
    foreach($n in $Xml.Task.Triggers.ChildNodes) { $triggers += $n.Name }
  }
  return @($triggers)
}

function Get-TaskMetaFromXml {
  param([xml]$Xml)
  if ($null -eq $Xml -or $null -eq $Xml.Task) {
    return [pscustomobject]([ordered]@{ Author=$null; PrincipalUser=$null; RunLevel=$null; Hidden=$false; Triggers=@() })
  }
  $author = try { $Xml.Task.RegistrationInfo.Author } catch { $null }
  $principal = Get-TaskPrincipalMeta -Xml $Xml
  return [pscustomobject]([ordered]@{
    Author = $author
    PrincipalUser = $principal.PrincipalUser
    RunLevel = $principal.RunLevel
    Hidden = Get-TaskHiddenSetting -Xml $Xml
    Triggers = @(Get-TaskTriggerNames -Xml $Xml)
  })
}

function Get-ValidTaskRunTime {
  param($TaskInfo, [string]$Property)
  try {
    $value = $TaskInfo.$Property
    if ($value -and $value -gt (Get-Date '2000-01-01')) { return $value }
  }
  catch { return $null }
  return $null
}

function Get-TaskInfoStateName {
  param($TaskInfo)
  try { if ($TaskInfo.State) { return $TaskInfo.State.ToString() } } catch { return 'Unknown' }
  return 'Unknown'
}

function Get-TaskStateEnabled {
  param([string]$State)
  if ($state -eq 'Disabled') { $enabled = $false }
  elseif ($state -in @('Ready','Running','Queued')) { $enabled = $true }
  else { $enabled = $null }
  return $enabled
}

function Get-TaskStateInfo {
  param([string]$TaskName,[string]$TaskPath)
  $TaskPath = Normalize-TaskPath $TaskPath
  try { $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop } catch { $taskInfo = $null }
  $state = if ($taskInfo) { Get-TaskInfoStateName -TaskInfo $taskInfo } else { 'Unknown' }
  $lastResult = try { if ($taskInfo) { $taskInfo.LastTaskResult } else { $null } } catch { $null }
  return [pscustomobject]([ordered]@{
    State          = $state
    Enabled        = Get-TaskStateEnabled -State $state
    NextRunTime    = if ($taskInfo) { Get-ValidTaskRunTime -TaskInfo $taskInfo -Property NextRunTime } else { $null }
    LastRunTime    = if ($taskInfo) { Get-ValidTaskRunTime -TaskInfo $taskInfo -Property LastRunTime } else { $null }
    LastTaskResult = $lastResult
  })
}

function Get-TaskInfo {
  param($Task)
  $taskName = [string](Get-PropValue -Object $Task -Name 'TaskName' -Default $null)
  $taskPath = Normalize-TaskPath ([string](Get-PropValue -Object $Task -Name 'TaskPath' -Default "\"))
  if ([string]::IsNullOrWhiteSpace($taskName)) {
    return [pscustomobject]([ordered]@{
      Name           = $null
      TaskPath       = $taskPath
      FullPath       = $null
      Enabled        = $null
      State          = "Unknown"
      NextRunTime    = $null
      LastRunTime    = $null
      LastTaskResult = $null
      Author         = $null
      PrincipalUser  = $null
      RunLevel       = $null
      Hidden         = $false
      Triggers       = @()
      Actions        = @()
    })
  }
  $xml     = Export-TaskXmlObject -TaskName $taskName -TaskPath $taskPath
  $actions = @(Get-TaskActionsFromXml -Xml $xml)
  $meta    = Get-TaskMetaFromXml -Xml $xml
  $si      = Get-TaskStateInfo -TaskName $taskName -TaskPath $taskPath
  return [pscustomobject]([ordered]@{
    Name           = $taskName
    TaskPath       = $taskPath
    FullPath       = Normalize-FullTaskPath -TaskPath $taskPath -TaskName $taskName
    Enabled        = $si.Enabled
    State          = $si.State
    NextRunTime    = $si.NextRunTime
    LastRunTime    = $si.LastRunTime
    LastTaskResult = $si.LastTaskResult
    Author         = $meta.Author
    PrincipalUser  = $meta.PrincipalUser
    RunLevel       = $meta.RunLevel
    Hidden         = $meta.Hidden
    Triggers       = @($meta.Triggers)
    Actions        = $actions
  })
}

function Get-PublisherInfo {
  param([string]$FilePath)
  if (-not $FilePath -or -not (Test-Path $FilePath)) {
    return [pscustomobject]([ordered]@{ Subject=$null; IsSigned=$false; IsValid=$false; Status=$null })
  }
  try {
    $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
    $subject = $null
    try { $subject = $sig.SignerCertificate.Subject } catch { $subject = $null }
    return [pscustomobject]([ordered]@{
      Subject  = $subject
      IsSigned = [bool]$sig.SignerCertificate
      IsValid  = ($sig.Status -eq 'Valid')
      Status   = [string]$sig.Status
    })
  } catch {
    return [pscustomobject]([ordered]@{ Subject=$null; IsSigned=$false; IsValid=$false; Status="Error" })
  }
}

function New-TaskRiskRecord {
  return [pscustomobject]([ordered]@{
    IsCritical       = $false
    IsAllowed        = $false
    Risky            = $false
    Reasons          = @()
    ActionPath       = $null
    CommandLine      = $null
    WorkingDirectory = $null
    PublisherSubject = $null
    PublisherValid   = $null
    SignatureStatus  = $null
  })
}

function Set-TaskRiskActionMetadata {
  param($Risk, $TaskInfo)
  $actions = @($TaskInfo.Actions)
  if ($actions.Count -eq 0) { return }
  $action = $actions[0]
  $Risk.ActionPath = $action.Command
  $Risk.CommandLine = $action.CommandLine
  $Risk.WorkingDirectory = $action.WorkingDirectory
  if (-not $Risk.ActionPath) { return }
  $publisher = Get-PublisherInfo -FilePath $Risk.ActionPath
  $Risk.PublisherSubject = $publisher.Subject
  $Risk.PublisherValid = $publisher.IsValid
  $Risk.SignatureStatus = $publisher.Status
}

function Add-TaskActionPathRisks {
  param($Risk, [object]$Catalog, [bool]$Enabled)
  if (-not $Enabled -or -not $Risk.ActionPath) { return }
  $denyPaths = Get-PropValue $Catalog 'DenyActionPathRegex' @()
  if (Match-AnyRegex $Risk.ActionPath $denyPaths) {
    $Risk.Risky = $true; $Risk.Reasons += 'ActionPath in denied location'
  }
  if ($Risk.WorkingDirectory -and (Match-AnyRegex $Risk.WorkingDirectory $denyPaths)) {
    $Risk.Risky = $true; $Risk.Reasons += 'WorkingDirectory in denied location'
  }
  if (-not (StartsWithAny $Risk.ActionPath (Get-PropValue $Catalog 'AllowActionPathPrefixes' @()))) {
    $Risk.Risky = $true; $Risk.Reasons += 'ActionPath not under allowed prefixes'
  }
}

function Test-TaskPublisherApproved {
  param($Risk, [object]$Catalog)
  foreach ($regex in @(Get-PropValue $Catalog 'AllowPublisherOrgRegex' @())) {
    if ($Risk.PublisherSubject -and $regex.IsMatch($Risk.PublisherSubject)) { return $true }
  }
  return $false
}

function Add-TaskPrivilegeRisk {
  param($Risk, $TaskInfo, [object]$Catalog)
  if ($TaskInfo.RunLevel -notmatch 'Highest' -or -not $Risk.ActionPath) { return }
  if (-not $Risk.PublisherValid) {
    $Risk.Risky = $true; $Risk.Reasons += 'HighestPrivileges with non-valid signature'
  }
  elseif (-not (Test-TaskPublisherApproved -Risk $Risk -Catalog $Catalog)) {
    $Risk.Risky = $true; $Risk.Reasons += 'HighestPrivileges with unapproved publisher'
  }
}

function Get-TaskEffectiveEnabled {
  param($TaskInfo)
  if ($null -ne $TaskInfo.Enabled) { return [bool]$TaskInfo.Enabled }
  return [bool]($TaskInfo.State -and $TaskInfo.State -ne 'Disabled')
}

function Add-HiddenTaskRisk {
  param($Risk, $TaskInfo)
  if ($TaskInfo.Hidden -and (@($TaskInfo.Triggers) -contains 'LogonTrigger')) {
    $Risk.Risky = $true
    $Risk.Reasons += 'Hidden + LogonTrigger'
  }
}

function Evaluate-TaskRisk {
  param([pscustomobject]$TaskInfo,[object]$Catalog)
  $risk = New-TaskRiskRecord
  $full = [string]$TaskInfo.FullPath
  if (Match-AnyRegex $full (Get-PropValue $Catalog 'CriticalTasks' @()))  { $risk.IsCritical = $true }
  if (Match-AnyRegex $full (Get-PropValue $Catalog 'AllowTaskExact' @())) { $risk.IsAllowed  = $true }
  Set-TaskRiskActionMetadata -Risk $risk -TaskInfo $TaskInfo
  $enabled = Get-TaskEffectiveEnabled -TaskInfo $TaskInfo
  Add-TaskActionPathRisks -Risk $risk -Catalog $Catalog -Enabled $enabled
  if ($enabled -and $risk.CommandLine -and (Match-AnyRegex $risk.CommandLine (Get-PropValue $Catalog 'DenyCommandLineRegex' @()))) {
    $risk.Risky = $true; $risk.Reasons += 'CommandLine matches denied patterns'
  }
  Add-TaskPrivilegeRisk -Risk $risk -TaskInfo $TaskInfo -Catalog $Catalog
  Add-HiddenTaskRisk -Risk $risk -TaskInfo $TaskInfo
  return $risk
}
