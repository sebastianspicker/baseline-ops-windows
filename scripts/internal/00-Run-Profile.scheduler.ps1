#requires -version 5.1
<#
.SYNOPSIS
Schedules validated Run-Profile steps.
.DESCRIPTION
Executes dependency-ready steps in declaration order and records child outcomes, skips, and dependency cycles.
#>
function Get-RunProfileDependencyState {
  param($Step, $StepStatus)

  $dependsOn = if ((Has-Property -Object $Step -Name 'DependsOn') -and $null -ne $Step.DependsOn) {
    @($Step.DependsOn)
  } else {
    @()
  }
  $failed = $false
  foreach ($dependency in $dependsOn) {
    if (-not $StepStatus.ContainsKey([string]$dependency)) {
      return [pscustomobject]@{ Ready = $false; Failed = $false }
    }
    if ($StepStatus[[string]$dependency] -notin @('Success', 'Partial')) {
      $failed = $true
    }
  }
  return [pscustomobject]@{ Ready = $true; Failed = $failed }
}

function Add-RunProfileDependencySkip {
  param($State, [string]$ScriptName)

  $State.StepStatus[$ScriptName] = 'Skipped'
  [void]$State.Results.Add([pscustomobject]@{
    ScriptName = $ScriptName
    Status = 'Skipped'
    ExitCode = 2
    DurationMs = 0
    Message = 'Skipped due to failed dependency.'
  })
  Write-UiLine -Text ("[SKIP] {0} (dependency failure)" -f $ScriptName) -Style 'Muted'
}

function New-RunProfileStepParameters {
  param($Options, $State, $Step)

  $stepArguments = @('-Mode', $Options.Mode)
  if ($State.ProfileStrict) {
    $stepArguments += '-Strict'
  }
  $parameters = @{
    ScriptName = [string]$Step.Script
    ScriptArgs = $stepArguments
    RootPath = $Options.RootPath
    OutputFormat = 'None'
    PassThru = $true
  }
  if ($State.ProfileStrict) {
    $parameters.Strict = $true
  }
  if ($State.ProfileRequireSigned) {
    $parameters.RequireSigned = $true
  }
  if ($State.ExpectedHashes.ContainsKey([string]$Step.Script)) {
    $parameters.ExpectedHash = [string]$State.ExpectedHashes[[string]$Step.Script]
  }
  if ($Options.WhatIf) {
    $parameters.WhatIf = $true
  }
  if ($Options.ConfirmBound) {
    $parameters.Confirm = $Options.Confirm
  }
  return $parameters
}

function Get-RunProfileChildResultObjects {
  param([object[]]$Output)

  return @($Output | Where-Object {
    $null -ne $_ -and
    $_.PSObject.Properties.Name -contains 'Result' -and
    @('OK', 'WARN', 'FAIL') -contains [string]$_.Result
  })
}

function Get-RunProfileDeclaredChildResult {
  param($ChildResult)

  if (Has-Property -Object $ChildResult -Name 'RunnerDeclaredResult') {
    return [string]$ChildResult.RunnerDeclaredResult
  }
  return [string]$ChildResult.Result
}

function Add-RunProfileChildFindings {
  param($State, $ChildResult)

  if (-not (Has-Property -Object $ChildResult -Name 'Findings') -or
      $null -eq $ChildResult.Findings) {
    return
  }
  foreach ($finding in @($ChildResult.Findings)) {
    if ($null -ne $finding) {
      [void]$State.Findings.Add($finding)
    }
  }
}

function Add-RunProfileExitMismatch {
  param(
    $State,
    [string]$ScriptName,
    $ChildResult,
    [string]$DeclaredResult,
    [int]$ProcessExitCode,
    $Outcome
  )

  $expectedExitCode = Get-RunProfileExpectedExitCode $DeclaredResult
  $actualExitCode = Get-RunProfileActualExitCode $ChildResult $ProcessExitCode
  if ($actualExitCode -eq $expectedExitCode) {
    return
  }
  [void]$State.Findings.Add([pscustomobject]@{
    Code = 'Profile-ChildResultExitMismatch'
    Severity = if ($DeclaredResult -eq 'OK') { 'High' } else { 'Medium' }
    Message = "Child V2 result '$DeclaredResult' does not match process exit code $actualExitCode for $ScriptName."
    ScriptName = $ScriptName
    ChildResult = $DeclaredResult
    ExpectedExitCode = $expectedExitCode
    ActualExitCode = $actualExitCode
  })
  $Outcome.Message = "$($Outcome.Message); V2 result/exit-code mismatch"
  if ($DeclaredResult -eq 'OK') {
    $Outcome.ExitCode = 1
    $Outcome.Status = 'Failed'
  }
}

function Get-RunProfileExpectedExitCode {
  param([string]$Result)

  switch ($Result) {
    'OK' { return 0 }
    'WARN' { return 2 }
    'FAIL' { return 1 }
  }
}

function Get-RunProfileActualExitCode {
  param($ChildResult, [int]$ProcessExitCode)

  $actualExitCode = $ProcessExitCode
  if (Has-Property -Object $ChildResult -Name 'RunnerActualExitCode') {
    $actualExitCode = [int]$ChildResult.RunnerActualExitCode
  }
  return $actualExitCode
}

function Get-RunProfileChildOutcome {
  param(
    $State,
    [string]$ScriptName,
    [object[]]$ChildOutput,
    [int]$ProcessExitCode
  )

  $childResults = Get-RunProfileChildResultObjects $ChildOutput
  if ($childResults.Count -eq 0) {
    return [pscustomobject]@{
      ExitCode = 1
      Status = 'Failed'
      Message = "Child did not emit a valid V2 result. Process exit code: $ProcessExitCode"
      ProcessExitCode = $ProcessExitCode
      ChildResult = $null
      DeclaredResult = $null
    }
  }
  $childResult = $childResults[-1]
  $declaredResult = Get-RunProfileDeclaredChildResult $childResult
  $outcome = switch ([string]$childResult.Result) {
    'OK' { [pscustomobject]@{ ExitCode = 0; Status = 'Success' } }
    'WARN' { [pscustomobject]@{ ExitCode = 2; Status = 'Partial' } }
    'FAIL' { [pscustomobject]@{ ExitCode = 1; Status = 'Failed' } }
  }
  $outcome | Add-Member -NotePropertyName 'Message' -NotePropertyValue "Child V2 result: $($childResult.Result); process exit code: $ProcessExitCode"
  $outcome | Add-Member -NotePropertyName 'ProcessExitCode' -NotePropertyValue $ProcessExitCode
  $outcome | Add-Member -NotePropertyName 'ChildResult' -NotePropertyValue $childResult
  $outcome | Add-Member -NotePropertyName 'DeclaredResult' -NotePropertyValue $declaredResult
  Add-RunProfileExitMismatch $State $ScriptName $childResult $declaredResult $ProcessExitCode $outcome
  Add-RunProfileChildFindings $State $childResult
  return $outcome
}

function Invoke-RunProfileStep {
  param($Options, $State, $Bootstrap, $Step)

  $scriptName = [string]$Step.Script
  $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    if ($Options.WhatIf) {
      Write-UiLine -Text ("[SKIP] {0} (-WhatIf)" -f $scriptName) -Style 'Muted'
      return [pscustomobject]@{
        ExitCode = 0
        Status = 'Skipped'
        Message = 'Skipped (-WhatIf).'
        ProcessExitCode = $null
        ChildResult = $null
        DeclaredResult = $null
        Stopwatch = $stopwatch
      }
    }
    Write-UiLine -Text ("[RUN ] {0}" -f $scriptName) -Style 'Header'
    $parameters = New-RunProfileStepParameters $Options $State $Step
    $childOutput = @(Invoke-RunProfileChild $Bootstrap $parameters)
    $processExitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    $outcome = Get-RunProfileChildOutcome $State $scriptName $childOutput $processExitCode
    $outcome | Add-Member -NotePropertyName 'Stopwatch' -NotePropertyValue $stopwatch
    return $outcome
  } catch {
    Write-UiLine -Text ("[FAIL] {0} - {1}" -f $scriptName, $_.Exception.Message) -Style 'Error'
    return [pscustomobject]@{
      ExitCode = 1
      Status = 'Failed'
      Message = $_.Exception.Message
      ProcessExitCode = $null
      ChildResult = $null
      DeclaredResult = $null
      Stopwatch = $stopwatch
    }
  }
}

function Complete-RunProfileStep {
  param($State, $Step, $Outcome)

  $Outcome.Stopwatch.Stop()
  $scriptName = [string]$Step.Script
  $State.StepStatus[$scriptName] = $Outcome.Status
  $runnerExitCode = if ($null -ne $Outcome.ProcessExitCode) {
    $Outcome.ProcessExitCode
  } else {
    $Outcome.ExitCode
  }
  $effectiveResult = if ($null -ne $Outcome.ChildResult) {
    [string]$Outcome.ChildResult.Result
  } else {
    $null
  }
  [void]$State.Results.Add([pscustomobject]@{
    ScriptName = $scriptName
    Status = $Outcome.Status
    ExitCode = $Outcome.ExitCode
    RunnerExitCode = $runnerExitCode
    ChildResult = $Outcome.DeclaredResult
    ChildEffectiveResult = $effectiveResult
    DurationMs = $Outcome.Stopwatch.ElapsedMilliseconds
    Message = $Outcome.Message
  })
  if ($Outcome.Status -eq 'Success') {
    Write-UiLine -Text ("[ OK ] {0} ({1} ms)" -f $scriptName, $Outcome.Stopwatch.ElapsedMilliseconds) -Style 'Success'
  } elseif ($Outcome.Status -eq 'Partial') {
    Write-UiLine -Text ("[WARN] {0} ({1} ms)" -f $scriptName, $Outcome.Stopwatch.ElapsedMilliseconds) -Style 'Warning'
  }
}

function Stop-RunProfileAfterFailure {
  param($State, [string]$FailedScript)

  Write-UiLine -Text ("Stopping profile run due to failure in {0} (ContinueOnError=false)." -f $FailedScript) -Style 'Error'
  foreach ($remaining in @($State.Pending)) {
    $name = [string]$remaining.Script
    $State.StepStatus[$name] = 'Skipped'
    [void]$State.Results.Add([pscustomobject]@{
      ScriptName = $name
      Status = 'Skipped'
      ExitCode = 2
      DurationMs = 0
      Message = "Not run because the profile stopped after failure in $FailedScript."
    })
    Write-UiLine -Text ("[SKIP] {0} (profile stopped after failure)" -f $name) -Style 'Muted'
  }
  $State.Pending.Clear()
}

function Add-RunProfileDependencyCycle {
  param($State)

  $State.DependencyCycleDetected = $true
  $State.DependencyCycleScripts = @($State.Pending | ForEach-Object { [string]$_.Script })
  [void]$State.Findings.Add([pscustomobject]@{
    Code = 'Profile-DependencyCycle'
    Severity = 'High'
    Message = "Dependency cycle or unresolved dependency. Scripts not run: $($State.DependencyCycleScripts -join ', ')"
    Scripts = $State.DependencyCycleScripts
  })
  foreach ($remaining in @($State.Pending)) {
    [void]$State.Results.Add([pscustomobject]@{
      ScriptName = [string]$remaining.Script
      Status = 'Skipped'
      ExitCode = 2
      DurationMs = 0
      Message = 'Dependency cycle or unresolved dependency.'
    })
  }
}

function Invoke-RunProfileSchedulePass {
  param($Options, $State, $Bootstrap)

  $progress = $false
  for ($index = 0; $index -lt $State.Pending.Count; $index++) {
    $step = $State.Pending[$index]
    $dependency = Get-RunProfileDependencyState $step $State.StepStatus
    if (-not $dependency.Ready) {
      continue
    }
    $State.Pending.RemoveAt($index)
    $progress = $true
    $scriptName = [string]$step.Script
    if ($dependency.Failed) {
      Add-RunProfileDependencySkip $State $scriptName
      break
    }
    $outcome = Invoke-RunProfileStep $Options $State $Bootstrap $step
    Complete-RunProfileStep $State $step $outcome
    $continueOnError = if (Has-Property -Object $step -Name 'ContinueOnError') {
      [bool]$step.ContinueOnError
    } else {
      $false
    }
    if ($outcome.Status -eq 'Failed' -and -not $continueOnError) {
      Stop-RunProfileAfterFailure $State $scriptName
      break
    }
  }
  return $progress
}

function Invoke-RunProfileSchedule {
  param($Options, $State, $Bootstrap)

  while ($State.Pending.Count -gt 0) {
    $progress = Invoke-RunProfileSchedulePass $Options $State $Bootstrap
    if (-not $progress -and $State.Pending.Count -gt 0) {
      Add-RunProfileDependencyCycle $State
      break
    }
  }
}
