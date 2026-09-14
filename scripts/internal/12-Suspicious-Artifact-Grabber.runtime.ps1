#requires -version 5.1
<#
.SYNOPSIS
  Provides private artifact collection phases.
.DESCRIPTION
  Preserves protected evidence paths, bounded observations, trigger decisions, and artifact proof ordering within this capability.
#>

function Initialize-ArtifactRun {
  param($RunState)
  $RunState.errors = New-Object System.Collections.Generic.List[string]
  $RunState.hasFindings = $false
  $RunState.ok = $true
  $RunState.summary = $null
  $RunState.catalogNote = $null


}

function Read-ArtifactRunCatalog {
  param($RunState)
  Write-Information ("IR Grabber starting (v{0})" -f $RunState.ScriptVersion)

  $catalogNote = $RunState.catalogNote
  try {
    $RunState.cat = Load-Catalog -CatalogPath $RunState.CatalogPath -ConfigPath $RunState.ConfigPath -CatalogLoadNote ([ref]$catalogNote)
  }
  finally {
    $RunState.catalogNote = $catalogNote
  }
  if (-not $RunState.cat) {
    $RunState.cat = Get-BaseClone $DefaultCatalog
  }
  Initialize-ArtifactRegexRules -Catalog $RunState.cat
  if (-not (Ensure-EventSource)) {
    Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
  }

  $RunState.base = Assert-ArtifactEvidenceOutputBase -OutputBase ([string]$RunState.cat.OutputBase)


}

function Write-ArtifactNoTrigger {
  param($RunState)
  $msg = "IR Grabber: no trigger set (registry/fileflag), aborted. Hint: run with -Force."
  Write-HealthEvent 10021 $msg 'Warning'

  $RunState.summary = [ordered]@{
    Host = $env:COMPUTERNAME
    Time = (Get-Date).ToString('s')
    Reason = $RunState.tr.Reason
    Trigger = @{
      Registry = [string]$RunState.cat.Trigger.Registry
      FileFlag = [string]$RunState.cat.Trigger.FileFlag
      Force = [bool]$RunState.Force
    }
    Output = @{ WorkDir = $null
      Zip = $null
    }
    Counts = @{}
    Errors = @()
    Notes = @()
    Samples = @()
  }


}

function Initialize-ArtifactBundle {
  param($RunState)
  $RunState.ts = Get-RunId

  $RunState.work = Join-Path $RunState.base $RunState.ts
  $RunState.zip = Join-Path $RunState.base ("Grabber-{0}-{1}.zip" -f $env:COMPUTERNAME, $RunState.ts)

  [void](Ensure-Directory $RunState.work)

  $RunState.summary = [ordered]@{
    Host = $env:COMPUTERNAME
    Time = (Get-Date).ToString('s')
    Reason = $RunState.tr.Reason
    Trigger = @{
      Registry = [string]$RunState.cat.Trigger.Registry
      FileFlag = [string]$RunState.cat.Trigger.FileFlag
      Force = [bool]$RunState.Force
    }
    Output = @{ WorkDir = $RunState.work
      Zip = $RunState.zip
    }
    Counts = @{}
    Errors = @()
    Notes = @()
    Samples = @()
  }


}

function Save-ArtifactBundle {
  param($RunState)
  if ($RunState.errors.Count -gt 0) {
    $RunState.summary.Errors = @($RunState.errors)
  }
  Save-Json -InputObject $RunState.summary -Path (Join-Path $RunState.work 'Summary.json') -Depth 30

  try {
    if (Test-Path -LiteralPath $RunState.zip) {
      Remove-Item -LiteralPath $RunState.zip -Force -ErrorAction SilentlyContinue
    }
    Compress-Archive -Path (Join-Path $RunState.work '*') -DestinationPath $RunState.zip -Force
  }
  catch {
    [void]$RunState.errors.Add("zip: " + $_.Exception.Message)
    $RunState.ok = $false
  }


}

function Write-ArtifactBundleEvent {
  param($RunState)
  $msg = "IR Grabber: bundle created -> " + $RunState.zip
  if ($RunState.errors.Count -gt 0) {
    $msg = $msg + " | Errors: " + (@($RunState.errors) -join " | ")
  }

  $warn = ($RunState.errors.Count -gt 0) -or [bool]$RunState.Strict -or $RunState.hasFindings -or (-not $RunState.ok)
  $eventId = 10020
  $level = 'Information'
  if ($warn) {
    $eventId = 10021
    $level = 'Warning'
  }

  Write-HealthEvent $eventId $msg $level

}

function Complete-ArtifactRunError {
  param($RunState, $ErrorRecord)
  $isRegexTimeout = $ErrorRecord.Exception -is [System.Text.RegularExpressions.RegexMatchTimeoutException] -or $ErrorRecord.Exception.InnerException -is [System.Text.RegularExpressions.RegexMatchTimeoutException]
  $prefix = if ($isRegexTimeout) {
    'IR Grabber incomplete evidence: regex match timed out: '
  }
  else {
    'IR Grabber fatal: '
  }
  $errMsg = $prefix + $ErrorRecord.Exception.Message
  [void]$RunState.errors.Add($errMsg)
  if ($null -eq $RunState.summary) {
    $RunState.summary = [ordered]@{ Errors = @($RunState.errors)
      IncompleteEvidence = $isRegexTimeout
    }
  }
  elseif ($isRegexTimeout) {
    $RunState.summary['IncompleteEvidence'] = $true
  }
  Write-HealthEvent 10021 $errMsg 'Error'

}

function Write-ArtifactRunSummary {
  param($RunState)
  if ($null -ne $RunState.summary) {
    if ($RunState.errors.Count -gt 0) {
      $RunState.summary.Errors = @($RunState.errors)
    }
    try {
      Print-ConsoleSummary -Summary $RunState.summary -Errors $RunState.errors -Findings $RunState.hasFindings -CatalogLoadNote $RunState.catalogNote -ScriptVersion $RunState.ScriptVersion
    }
    catch {
      Write-Verbose ("IR grabber console summary failed: {0}" -f $_.Exception.Message)
    }
  }
  else {
    Write-UiStatus -Label 'IR Grabber' -State 'FAIL' -Text "No summary object created."
  }

}
function Invoke-ArtifactCollection {
  param($RunState)
  Initialize-ArtifactRun -RunState $RunState
  try {
    Read-ArtifactRunCatalog -RunState $RunState
    $RunState.tr = Read-Trigger -cat $RunState.cat -Force:$RunState.Force -CollectSamples:$RunState.CollectSamples
    if (-not $RunState.tr.Want) {
      Write-ArtifactNoTrigger -RunState $RunState
    }
    else {
      Invoke-ArtifactBundle -RunState $RunState
    }
  }
  catch {
    Complete-ArtifactRunError -RunState $RunState -ErrorRecord $_
  }
  finally {
    Write-ArtifactRunSummary -RunState $RunState
  }
}

function Invoke-ArtifactBundle {
  param($RunState)
  Initialize-ArtifactBundle -RunState $RunState
  Collect-ArtifactProcesses -RunState $RunState
  Collect-ArtifactNetwork -RunState $RunState
  Collect-ArtifactTasks -RunState $RunState
  Collect-ArtifactWmi -RunState $RunState
  Collect-ArtifactAutoruns -RunState $RunState
  if ($RunState.tr.Samples -or (Safe-ToBool $RunState.cat.Samples.Enable $false)) {
    Collect-ArtifactSamples -RunState $RunState
  }
  Save-ArtifactBundle -RunState $RunState
  Write-ArtifactBundleEvent -RunState $RunState
  Reset-Trigger -cat $RunState.cat
}

function New-ArtifactRunState {
  param([hashtable]$Inputs)
  $state = @{
    ScriptVersion = $null
    CatalogPath = $null
    ConfigPath = $null
    Force = $null
    CollectSamples = $null
    HashAllProcesses = $null
    Strict = $null
    errors = $null
    hasFindings = $null
    ok = $null
    summary = $null
    catalogNote = $null
    cat = $null
    base = $null
    tr = $null
    ts = $null
    work = $null
    zip = $null
    pDir = $null
    sDir = $null
    maxFileMB = $null
    maxTotalMB = $null
    totalBytes = $null
  }
  foreach ($key in $Inputs.Keys) {
    $state[$key] = $Inputs[$key]
  }
  return $state
}
