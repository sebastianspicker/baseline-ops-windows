#requires -version 5.1
<#
.SYNOPSIS
  Provides private LAPS hygiene phases.
.DESCRIPTION
  Preserves policy precedence, rotation decisions, diagnostics, and result reporting for the public capability.
#>

function Write-LapsAccountConsole {
  param($RunState)
  Write-KeyValue -Key "Managed account" -Value ([string]$RunState.result.ManagedAccount) -ValueStyle 'Default'
  Write-KeyValue -Key "Account exists"  -Value ([string]$RunState.result.ManagedAccountExists) -ValueStyle (Get-StyleForBool $RunState.result.ManagedAccountExists)
  Write-KeyValue -Key "Account enabled" -Value ([string]$RunState.result.ManagedAccountEnabled) -ValueStyle (Get-StyleForBool $RunState.result.ManagedAccountEnabled)
  Write-KeyValue -Key "Pwd last set"    -Value ([string](To-Iso $RunState.result.PasswordLastSet)) -ValueStyle 'Dim'
  Write-KeyValue -Key "Pwd age (days)"  -Value ([string]($(if ($null -ne $RunState.result.PasswordAgeDays) {
          $RunState.result.PasswordAgeDays
        }
        else {
          'n/a'
        }))) -ValueStyle 'Default'
  Write-UiSeparator -Char '-' -Width $RunState.Config.Console.Width -Style 'Dim'
}
function Write-LapsPolicyConsole {
  param($RunState)
  Write-KeyValue -Key "Policy age (d)"  -Value ([string]$RunState.result.PolicyPasswordAgeDays) -ValueStyle 'Default'
  Write-KeyValue -Key "Threshold (d)"   -Value ([string]($(if ($null -ne $RunState.result.ThresholdDays) {
          $RunState.result.ThresholdDays
        }
        else {
          'n/a'
        }))) -ValueStyle 'Default'
  $bdStyle = 'Dim'
  if ($RunState.result.PolicyType -eq 'WindowsLAPS') {
    if ($null -eq $RunState.result.BackupDirectoryRaw -or $RunState.result.BackupDirectoryRaw -eq 0) {
      $bdStyle = 'Bad'
    }
    else {
      $bdStyle = 'Good'
    }
  }
  Write-KeyValue -Key "BackupDirectory" -Value $RunState.result.BackupDirectory -ValueStyle $bdStyle
  Write-KeyValue -Key "AAD joined"      -Value ([string]$RunState.result.AADJoined) -ValueStyle (Get-StyleForBool $RunState.result.AADJoined)
  Write-KeyValue -Key "AD joined"       -Value ([string]$RunState.result.ADJoined)  -ValueStyle (Get-StyleForBool $RunState.result.ADJoined)
}
function Initialize-LapsRotationStyle {
  param($RunState)
  $RunState.rotateStyle = 'Dim'
  if ($RunState.result.NeedsRotate) {
    if ($RunState.result.Rotated) {
      $RunState.rotateStyle = 'Good'
    }
    elseif ($RunState.result.Remediate) {
      $RunState.rotateStyle = 'Bad'
    }
    else {
      $RunState.rotateStyle = 'Warn'
    }
  }
}
function Write-LapsRotationConsole {
  param($RunState)
  Write-KeyValue -Key "Needs rotate"    -Value ([string]$RunState.result.NeedsRotate) -ValueStyle $RunState.rotateStyle
  Write-KeyValue -Key "Remediate"       -Value ([string]$RunState.result.Remediate) -ValueStyle (Get-StyleForBool $RunState.result.Remediate)
  Write-KeyValue -Key "Rotated"         -Value ("{0} ({1})" -f $RunState.result.Rotated, $RunState.result.RotationMethod) -ValueStyle $RunState.rotateStyle
  Write-UiSeparator -Char '=' -Width $RunState.Config.Console.Width -Style 'Dim'
  Write-KeyValue -Key "Overall"         -Value ($(if ($RunState.result.OkOverall) {
        'OK'
      }
      else {
        'NOT OK'
      })) -ValueStyle (Get-StyleForOk $RunState.result.OkOverall)
}
function Write-LapsConsole {
  param($RunState)
  # Formatted console output (never via pipeline)
  Write-UiLine -Text "" -Style 'Default'
  Write-UiSeparator -Char '=' -Width $RunState.Config.Console.Width -Style 'Dim'
  Write-UiLine -Text "LAPS Hygiene (Windows PowerShell 5.1)" -Style 'Title'
  Write-UiSeparator -Char '=' -Width $RunState.Config.Console.Width -Style 'Dim'
  Write-KeyValue -Key "Time (UTC)"     -Value ((Get-Date $RunState.result.TimestampUtc -Format s) + "Z") -ValueStyle 'Dim'
  if ($RunState.Config.Console.ShowConfigPath) {
    Write-KeyValue -Key "ConfigPath" -Value $RunState.ConfigPath -ValueStyle 'Dim'
  }
  Write-KeyValue -Key "Policy"         -Value ("{0} ({1})" -f $RunState.result.PolicyType, $RunState.result.PolicyMechanism) -ValueStyle 'Default'
  Write-KeyValue -Key "Policy root"    -Value $RunState.result.PolicyRoot -ValueStyle 'Dim'
  Write-UiSeparator -Char '-' -Width $RunState.Config.Console.Width -Style 'Dim'
  Write-LapsAccountConsole -RunState $RunState
  Write-LapsPolicyConsole -RunState $RunState
  Write-UiSeparator -Char '-' -Width $RunState.Config.Console.Width -Style 'Dim'
  . Initialize-LapsRotationStyle -RunState $RunState
  Write-LapsRotationConsole -RunState $RunState
  if ($RunState.result.Reasons.Count -gt 0) {
    Write-UiLine -Text "" -Style 'Default'
    Write-UiLine -Text "Reasons" -Style 'Title'
    foreach ($r in $RunState.result.Reasons) {
      Write-UiLine -Text (" - {0}" -f $r) -Style 'Warn'
    }
  }
  if ($RunState.result.DiagnosticsCollected) {
    Write-UiLine -Text "" -Style 'Default'
    Write-UiLine -Text "Diagnostics" -Style 'Title'
    Write-UiLine -Text (" {0}" -f $RunState.result.DiagnosticsInfo) -Style 'Dim'
  }
}
