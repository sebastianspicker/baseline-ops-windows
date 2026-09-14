#requires -version 5.1
<#
.SYNOPSIS
Capability-private presentation and normalization helpers.

.DESCRIPTION
Provides bounded helper functions loaded by the matching public capability
after repository bootstrap and trust validation complete.
#>

function Test-AllConditions {
  param([scriptblock[]]$Conditions)
  foreach ($condition in $Conditions) {
    if (-not (. $condition)) { return $false }
  }
  return $true
}

function Test-AnyCondition {
  param([scriptblock[]]$Conditions)
  foreach ($condition in $Conditions) {
    if (. $condition) { return $true }
  }
  return $false
}

function Write-Badge {
  param(
    [Parameter(Mandatory)][string]$Label,
    [Parameter(Mandatory)][string]$Value,
    [ConsoleColor]$Color = [ConsoleColor]::Gray
  )

  Write-UiLine ("{0,-20}: {1}" -f $Label, $Value) -ForegroundColor $Color
}

function Format-Nullable {
  param([AllowNull()][object]$Value)
  if ($null -eq $Value) { return '<null>' }
  return [string]$Value
}

function Write-PrettySummarySection01 {
  param([hashtable]$RunState)
$s = $RunState.Result.Summary

  $overallText = 'OK'
  $overallColor = [ConsoleColor]::Green
  if ($s.FindingsCount -gt 0) { $overallText = 'ATTENTION'; $overallColor = [ConsoleColor]::Yellow }
  if ($s.RebootRequired) { $overallText = 'REBOOT REQUIRED'; $overallColor = [ConsoleColor]::Yellow }

  $findingsColor = [ConsoleColor]::Green
  if ($s.FindingsCount -gt 0) { $findingsColor = [ConsoleColor]::Yellow }

  $rebootColor = [ConsoleColor]::Green
  if ($s.RebootRequired) { $rebootColor = [ConsoleColor]::Yellow }

  Write-Section -Title 'LSA PPL (RunAsPPL)'
  Write-Badge -Label 'Overall'            -Value $overallText -Color $overallColor
  Write-Badge -Label 'ComputerName'       -Value $s.ComputerName -Color Gray
  Write-Badge -Label 'Mode'               -Value $s.Mode -Color Gray
  Write-Badge -Label 'TargetRunAsPPL'     -Value ([string]$s.TargetRunAsPPL) -Color Cyan
  Write-Badge -Label 'RunAsPPL (before)'  -Value (Format-Nullable $RunState.Result.Current.RunAsPPL) -Color Gray
  Write-Badge -Label 'RunAsPPL (after)'   -Value (Format-Nullable $RunState.Result.After.RunAsPPL) -Color Gray

  if ($s.ManageRunAsPPLBoot) {
    Write-Badge -Label 'RunAsPPLBoot (before)' -Value (Format-Nullable $RunState.Result.Current.RunAsPPLBoot) -Color Gray
    Write-Badge -Label 'RunAsPPLBoot (after)'  -Value (Format-Nullable $RunState.Result.After.RunAsPPLBoot) -Color Gray
  }

  Write-Badge -Label 'DisableMethod'      -Value $s.DisableMethod -Color DarkGray
  Write-Badge -Label 'FindingsCount'      -Value ([string]$s.FindingsCount) -Color $findingsColor
  Write-Badge -Label 'RebootRequired'     -Value ([string]$s.RebootRequired) -Color $rebootColor
  Write-Badge -Label 'Timestamp'          -Value ([string]$s.Timestamp) -Color DarkGray
}

function Write-PrettySummarySection02 {
if ($s.Changes -and $s.Changes.Count -gt 0) {
    Write-Section -Title 'Changes'
    foreach ($c in $s.Changes) { Write-UiLine ("  + {0}" -f $c) -ForegroundColor Cyan }
  }
}

function Write-PrettySummarySection03 {
  param([hashtable]$RunState)
if ($RunState.Result.Findings -and $RunState.Result.Findings.Count -gt 0) {
    Write-Section -Title 'Findings'
    foreach ($f in $RunState.Result.Findings) {
      $c = [ConsoleColor]::Yellow
      if ([string]$f.Severity -ieq 'High') { $c = [ConsoleColor]::Red }
      elseif ([string]$f.Severity -ieq 'Low') { $c = [ConsoleColor]::Gray }
      Write-UiLine ("  ! [{0}] {1} - {2}" -f $f.Severity, $f.Code, $f.Message) -ForegroundColor $c
    }
  }
}

function Write-PrettySummarySection04 {
  param([hashtable]$RunState)
if ($null -ne $RunState.Result.Verification) {
    Write-Section -Title 'Verify (Wininit Event 12)'
    if ($RunState.Result.Verification.Found) {
      Write-UiLine "  OK Wininit event found indicating PPL level 4." -ForegroundColor Green
      Write-UiLine ("  TimeCreated   : {0}" -f $RunState.Result.Verification.TimeCreated) -ForegroundColor DarkGray
      Write-UiLine ("  EventRecordId : {0}" -f $RunState.Result.Verification.EventRecordId) -ForegroundColor DarkGray
    } else {
      Write-UiLine "  WARN No matching Wininit event found in lookback window." -ForegroundColor Yellow
      if ($RunState.Result.Verification.Error) { Write-UiLine ("  Error: {0}" -f $RunState.Result.Verification.Error) -ForegroundColor Yellow }
    }
  }

  if ($null -ne $RunState.Result.CodeIntegrity) {
    Write-Section -Title 'CodeIntegrity (Operational)'
    if ($RunState.Result.CodeIntegrity.Error) {
      Write-UiLine ("  WARN Unable to read log: {0}" -f $RunState.Result.CodeIntegrity.Error) -ForegroundColor Yellow
    } else {
      Write-UiLine ("  Events (lsass.exe) in last {0}h: {1}" -f $RunState.Result.CodeIntegrity.LookbackHrs, $RunState.Result.CodeIntegrity.Count) -ForegroundColor Gray
    }
  }
}

function Write-PrettySummary {
  param([Parameter(Mandatory)][object]$Result, [hashtable]$RunState)
  $RunState.Result = $Result

    . Write-PrettySummarySection01 -RunState $RunState
    . Write-PrettySummarySection02
    . Write-PrettySummarySection03 -RunState $RunState
    . Write-PrettySummarySection04 -RunState $RunState
}

function To-Bool {
  param([AllowNull()][object]$Value, [bool]$Default = $false)
  if ($null -eq $Value) { return $Default }
  try { return [bool]$Value } catch { return $Default }
}

function To-Int {
  param([AllowNull()][object]$Value, [int]$Default)
  if ($null -eq $Value) { return $Default }
  try { return [int]$Value } catch { return $Default }
}

function To-StringOrNull {
  param([AllowNull()][object]$Value)
  if ($null -eq $Value) { return $null }
  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  return $s
}
