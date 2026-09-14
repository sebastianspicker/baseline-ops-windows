#requires -version 5.1
<#
.SYNOPSIS
  Coordinates local Administrators guardrail phases.
.DESCRIPTION
  Retains fail-safe membership decisions, explicit ShouldProcess authority, and result reporting.
#>

function Initialize-GuardrailAllowInput {
  param($RunState)
  # Load config (optional)
  $cfg = Get-Config -Path $RunState.ConfigPath
  if ($cfg) {
    $RunState.result.ConfigLoaded = $true
    if (-not $RunState.AllowListPath -and $cfg.LocalAdmins -and $cfg.LocalAdmins.AllowListPath) {
      $RunState.AllowListPath = [string]$cfg.LocalAdmins.AllowListPath
    }
  }
  $RunState.result.AllowListPathUsed = $RunState.AllowListPath

  # Read allow-list (optional) + defaults
  $allowInput = @(Read-AllowList -AllowListPath $RunState.AllowListPath -Extra $RunState.ExtraAllow)
  if (-not $allowInput -or $allowInput.Count -eq 0) {
    $allowInput = @($script:DefaultAllowList)
  }
  $RunState.result.AllowInput = @($allowInput)

}

function Initialize-GuardrailPolicy {
  param($RunState)
  . Initialize-GuardrailAllowInput -RunState $RunState

  # Resolve allow-list entries -> SIDs
  $allowResolved = @()
  $unresolvedAllow = @()

  foreach ($a in $allowInput) {
    $sid = Resolve-ToSid -IdOrName $a
    if ($sid) {
      $allowResolved += [pscustomobject]@{ Input = $a
        SID = $sid
      }
    }
    else {
      $unresolvedAllow += $a
    }
  }

  $allowSIDs = @($allowResolved | Select-Object -ExpandProperty SID | Sort-Object -Unique)

  $RunState.result.AllowResolved = @($allowResolved)
  $RunState.result.AllowSIDs = @($allowSIDs)
  $RunState.result.UnresolvedAllowInput = @($unresolvedAllow)

  # Always keep built-in Administrator (RID 500)
  $sid500 = Get-BuiltinAdministratorSid
  $RunState.result.BuiltinAdminSid500 = $sid500
  if ($sid500) {
    $RunState.result.AlwaysKeepSIDs = @($sid500)
  }

  # Fail-safe removals:
  # - unresolved allow entries OR no effective allow-list
  $noEffectiveAllowList = (@($allowSIDs).Count -eq 0)
  $RunState.result.FailSafeNoRemove = ((@($unresolvedAllow).Count -gt 0) -or $noEffectiveAllowList)

}

function Get-GuardrailMemberDiff {
  param($RunState, $Members)
  $currentSids = @($Members | Where-Object { $_.SID } | Select-Object -ExpandProperty SID | Sort-Object -Unique)
  $add = @()
  if (@($allowSIDs).Count -gt 0) {
    $add = @($allowSIDs | Where-Object { $currentSids -notcontains $_ })
  }
  $remove = @()
  foreach ($member in $Members) {
    if (Test-GuardrailRemovalCandidate -RunState $RunState -Member $member) {
      $remove += $member
    }
  }
  return [pscustomobject]@{ Add = $add
    Remove = $remove
  }
}

function Test-GuardrailRemovalCandidate {
  param($RunState, $Member)
  if (-not $Member.SID) {
    return $false
  }
  if ($allowSIDs -contains $Member.SID) {
    return $false
  }
  if ($RunState.result.AlwaysKeepSIDs -contains $Member.SID) {
    return $false
  }
  $isDomainLike = Is-DomainLikePrincipal -MemberRecord $Member
  if (-not $RunState.AllowDomainRemediation -and $isDomainLike) {
    return $false
  }
  return (-not $RunState.result.FailSafeNoRemove)
}

function Initialize-GuardrailMemberState {
  param($RunState)
  $membersBefore = @(Get-AdministratorsGroupMembers -GroupName $adminGroupName)
  $RunState.result.MembersBefore = $membersBefore
  $diff = Get-GuardrailMemberDiff -RunState $RunState -Members $membersBefore
  $toAddSIDs = $diff.Add
  $toRemove = $diff.Remove
  $RunState.result.ToAddSIDs = $toAddSIDs
  $RunState.result.ToRemove = $toRemove
  $RunState.result.DriftDetected = (
    (@($unresolvedAllow).Count -gt 0) -or
    (@($toAddSIDs).Count -gt 0) -or
    (@($toRemove).Count -gt 0)
  )
}

function Invoke-GuardrailAdditions {
  param($RunState, $DecisionContext)
  foreach ($sid in $toAddSIDs) {
    try {
      if ($DecisionContext.ShouldProcess($adminGroupName, "Add SID $sid")) {
        # Add by SID using -SID.
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sid)
        Add-LocalGroupMember -Group $adminGroupName -SID $sidObj -ErrorAction Stop
        $RunState.result.AddedSIDs += $sid
      }
    }
    catch {
      $RunState.result.Errors += "Add $sid failed: $($_.Exception.Message)"
    }
  }

}

function Get-GuardrailRemovalIdentity {
  param($Member)
  $memberId = $null
  if ($Member.SID) {
    $memberId = $Member.SID
  }
  elseif ($Member.Name) {
    $memberId = $Member.Name
  }
  if (-not $memberId) {
    throw "Cannot determine member identity for removal."
  }
  return $memberId
}

function Invoke-GuardrailRemovals {
  param($RunState, $DecisionContext)
  foreach ($m in $toRemove) {
    try {
      # Remove by name or SID string via -Member.
      $memberId = Get-GuardrailRemovalIdentity -Member $m

      if ($DecisionContext.ShouldProcess($adminGroupName, "Remove $memberId")) {
        Remove-LocalGroupMember -Group $adminGroupName -Member $memberId -ErrorAction Stop
        $RunState.result.RemovedIds += $memberId
      }
    }
    catch {
      $disp = if ($m.Name) {
        $m.Name
      }
      elseif ($m.SID) {
        $m.SID
      }
      else {
        "(unknown)"
      }
      $RunState.result.Errors += "Remove $disp failed: $($_.Exception.Message)"
    }
  }

}

function Set-GuardrailPostState {
  param($RunState)
  $membersAfter = @(Get-AdministratorsGroupMembers -GroupName $adminGroupName)
  $RunState.result.MembersAfter = $membersAfter
  $postDiff = Get-GuardrailMemberDiff -RunState $RunState -Members $membersAfter
  $RunState.result.PostCompliant = (
    (@($unresolvedAllow).Count -eq 0) -and
    (@($postDiff.Add).Count -eq 0) -and
    (@($postDiff.Remove).Count -eq 0) -and
    (@($RunState.result.Errors).Count -eq 0)
  )
}

function Set-GuardrailStatus {
  param($RunState)
  # Status + event
  $ok = $true
  if (@($RunState.result.Errors).Count -gt 0) {
    $ok = $false
  }
  elseif ((-not $RunState.Remediate) -and $RunState.result.DriftDetected) {
    $ok = $false
  }
  elseif ($RunState.Remediate -and ($RunState.result.PostCompliant -ne $true)) {
    $ok = $false
  }

  if ($ok) {
    $RunState.result.EventId = 3500
    $RunState.result.EventLevel = 'Information'
  }
  else {
    $RunState.result.EventId = 3510
    $RunState.result.EventLevel = 'Warning'
  }

}

function Write-GuardrailEvent {
  param($RunState)
  $RunState.result.EventMessage = @(
    "Local Admins Guardrail"
    ("Group={0}; Remediate={1}; AllowDomainRemediation={2}" -f $RunState.result.GroupName, $RunState.result.Remediate, $RunState.result.AllowDomainRemediation)
    ("ConfigLoaded={0}; AllowListPath={1}" -f $RunState.result.ConfigLoaded, ($(if ($RunState.result.AllowListPathUsed) {
          $RunState.result.AllowListPathUsed
        }
        else {
          "(none)"
        })))
    ("AllowResolvedSidCount={0}; UnresolvedAllowCount={1}; FailSafeNoRemove={2}" -f @($RunState.result.AllowSIDs).Count, @($RunState.result.UnresolvedAllowInput).Count, $RunState.result.FailSafeNoRemove)
    ("MembersBefore={0}; ToAdd={1}; ToRemove={2}; Errors={3}" -f @($RunState.result.MembersBefore).Count, @($RunState.result.ToAddSIDs).Count, @($RunState.result.ToRemove).Count, @($RunState.result.Errors).Count)
    ($(if ($RunState.result.Remediate) {
        "PostCompliant=$($RunState.result.PostCompliant)"
      }
      else {
        "DriftDetected=$($RunState.result.DriftDetected)"
      }))
  ) -join "`r`n"

  Write-HealthEvent -Id $RunState.result.EventId -Message $RunState.result.EventMessage -Level $RunState.result.EventLevel
}

function Set-GuardrailFatalError {
  param($RunState)

  $errMsg = $_.Exception.Message

  if (-not $RunState.result) {
    $groupNameFallback = '(unknown)'
    try {
      $groupNameFallback = Get-AdministratorsGroupName
    }
    catch {
      Write-Verbose ("Fallback administrators group name resolution failed: {0}" -f $_.Exception.Message)
    }
    $RunState.result = Get-GuardrailResult -RunState $RunState -GroupName $groupNameFallback
  }

  $RunState.result.Errors += ("Fatal error: " + $errMsg)
  $RunState.result.EventId = 3510
  $RunState.result.EventLevel = 'Error'
  $RunState.result.EventMessage = "Local Admins Guardrail error: $errMsg"

  Write-HealthEvent -Id 3510 -Message $RunState.result.EventMessage -Level 'Error'
}

function Write-GuardrailConsole {
  param($RunState)

  if ($RunState.result -and -not $RunState.Quiet) {
    $summaryObj = [pscustomobject]@{ ComputerName = $RunState.result.ComputerName
      Timestamp = Get-Date
    }
    Write-ConsoleSummary -Summary $summaryObj -Findings ([System.Collections.ArrayList]::new()) `
      -CustomFields ([ordered]@{
        Group = $RunState.result.GroupName
        Status = ("{0} (EventId {1})" -f $RunState.result.EventLevel, $RunState.result.EventId)
        Remediate = [string]$RunState.result.Remediate
        DriftDetected = [string]$RunState.result.DriftDetected
        ToAdd = @($RunState.result.ToAddSIDs).Count
        ToRemove = @($RunState.result.ToRemove).Count
        FailSafeNoRemove = [string]$RunState.result.FailSafeNoRemove
        ConfigLoaded = [string]$RunState.result.ConfigLoaded
      })
    if (@($RunState.result.Errors).Count -gt 0) {
      Write-UiLine "Errors:" 'Red'
      foreach ($e in $RunState.result.Errors) {
        Write-UiLine ("- {0}" -f $e) 'Red'
      }
      Write-UiLine ""
    }
  }
}

function Invoke-LocalAdminsGuardrail {
  param($RunState, $DecisionContext)
  if (-not (Ensure-EventSource -Source $script:EventSource -LogName $script:EventLogName)) {
    Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
  }
  $RunState.result = $null
  try {
    $adminGroupName = Get-AdministratorsGroupName
    $RunState.result = Get-GuardrailResult -RunState $RunState -GroupName $adminGroupName
    . Initialize-GuardrailPolicy -RunState $RunState
    . Initialize-GuardrailMemberState -RunState $RunState
    if ($RunState.Remediate) {
      Invoke-GuardrailAdditions -RunState $RunState -DecisionContext $DecisionContext
      Invoke-GuardrailRemovals -RunState $RunState -DecisionContext $DecisionContext
      Set-GuardrailPostState -RunState $RunState
    }
    Set-GuardrailStatus -RunState $RunState
    Write-GuardrailEvent -RunState $RunState
  }
  catch {
    . Set-GuardrailFatalError -RunState $RunState
  }
  finally {
    Write-GuardrailConsole -RunState $RunState
  }
}

function New-GuardrailRunState {
  param([hashtable]$Inputs)
  $state = @{
    result = $null
    Remediate = $null
    AllowDomainRemediation = $null
    ConfigPath = $null
    AllowListPath = $null
    ExtraAllow = $null
    Quiet = $null
  }
  foreach ($key in $Inputs.Keys) { $state[$key] = $Inputs[$key] }
  return $state
}
