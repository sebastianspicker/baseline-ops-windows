#requires -version 5.1
<#
.SYNOPSIS
Builds and presents the terminal Run-Profile result.
.DESCRIPTION
Calculates status counts and strict promotion, writes the console summary, and returns the final v2 object for public serialization.
#>
function Get-RunProfileResultCounts {
  param($State)

  $results = $State.Results.ToArray()
  $failed = @($results | Where-Object { $_.Status -eq 'Failed' }).Count
  $partial = @($results | Where-Object { $_.Status -eq 'Partial' }).Count
  $skipped = @($results | Where-Object { $_.Status -eq 'Skipped' }).Count
  $failedForResult = $failed
  if ($State.DependencyCycleDetected) {
    $failedForResult++
  }
  return [pscustomobject]@{
    Results = $results
    Failed = $failed
    FailedForResult = $failedForResult
    Partial = $partial
    Skipped = $skipped
  }
}

function Get-RunProfileResultStatus {
  param($Options, $State, $Counts)

  $result = Get-RunProfileBaseResult $State $Counts
  $whatIfOnlyWarning = Test-RunProfileWhatIfOnlyWarning $Options $State $Counts
  $strictPromoted = [bool](
    $State.ProfileStrict -and
    $result -eq 'WARN' -and
    -not $whatIfOnlyWarning
  )
  if ($strictPromoted) {
    $result = 'FAIL'
  }
  return [pscustomobject]@{
    Result = $result
    StrictPromoted = $strictPromoted
  }
}

function Test-RunProfileWhatIfOnlyWarning {
  param($Options, $State, $Counts)

  return [bool](
    $Options.WhatIf -and
    -not $State.ValidationWarned -and
    $Counts.FailedForResult -eq 0 -and
    $Counts.Partial -eq 0 -and
    $Counts.Skipped -eq $State.DeclaredStepCount
  )
}

function Get-RunProfileBaseResult {
  param($State, $Counts)

  if ($Counts.FailedForResult -gt 0) {
    return 'FAIL'
  }
  if ($State.ValidationWarned -or $Counts.Partial -gt 0 -or $Counts.Skipped -gt 0) {
    return 'WARN'
  }
  return 'OK'
}

function New-RunProfileSummary {
  param($Options, $State, $Counts, $Status)

  return [pscustomobject]@{
    ProfileName = [string]$State.ProfileDocument.ProfileName
    Version = [string]$State.ProfileDocument.Version
    Mode = $Options.Mode
    StepsTotal = $State.DeclaredStepCount
    StepsFailed = $Counts.FailedForResult
    StepsPartial = $Counts.Partial
    StepsSkipped = $Counts.Skipped
    Strict = $State.ProfileStrict
    StrictPromoted = $Status.StrictPromoted
    ValidationWarnings = @(
      $State.Validation.Findings | Where-Object Severity -in @('Medium', 'Low')
    ).Count
    DependencyCycle = $State.DependencyCycleDetected
    DependencyCycleScripts = $State.DependencyCycleScripts
  }
}

function Write-RunProfileSummary {
  param($Summary)

  Write-Section -Title 'Profile Summary'
  Write-KeyValue -Key 'Profile' -Value $Summary.ProfileName
  Write-KeyValue -Key 'Mode' -Value $Summary.Mode
  Write-KeyValue -Key 'Total' -Value $Summary.StepsTotal
  Write-KeyValue -Key 'Failed' -Value $Summary.StepsFailed
  Write-KeyValue -Key 'Partial' -Value $Summary.StepsPartial
  Write-KeyValue -Key 'Skipped' -Value $Summary.StepsSkipped
}

function New-RunProfileResultTerminal {
  param($Options, $State)

  $counts = Get-RunProfileResultCounts $State
  $status = Get-RunProfileResultStatus $Options $State $counts
  $summary = New-RunProfileSummary $Options $State $counts $status
  $result = Get-V2ResultObject `
    -ScriptName '00-Run-Profile.ps1' `
    -Mode $Options.Mode `
    -Result $status.Result `
    -Findings $State.Findings.ToArray() `
    -Summary $summary `
    -Metadata @{ Steps = $counts.Results; Validation = $State.Validation }
  if ($Options.OutputFormat -eq 'Console') {
    Write-RunProfileSummary $summary
  }
  $script:__V2Context.OutputFormat = $Options.OutputFormat
  $script:__V2Context.OutputPath = $Options.OutputPath
  return New-RunProfileTerminal `
    -ResultObject $result `
    -OutputFormat $Options.OutputFormat `
    -OutputPath $Options.OutputPath
}
