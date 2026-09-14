#requires -version 5.1
<#
.SYNOPSIS
Renders the Sysmon updater summary.
.DESCRIPTION
Sanitizes optional console values and writes the existing human-readable summary.
#>
function Sanitize-Text {
  param([string]$Text)
  if (-not $Text) { return $Text }
  $t = $Text
  $t = [regex]::Replace($t, '(?i)\b[a-z]:\\[^\s''"]+', '[local file]')
  $t = [regex]::Replace($t, '(?i)\\\\[a-z0-9\.\-]+\\[^\s''"]+', '[network file]')
  return $t
}
function Write-PrettySummary {
  param(
    [hashtable]$Summary,
    [int]$ChannelSizeMiB,
    [switch]$Sanitize,
    [switch]$NoColor
  )
  $line = '============================================================'
  if ($Sanitize) { $line = Sanitize-Text $line }
  Write-SysmonSummaryHeader $line ([bool]$NoColor)
  Write-SysmonSummaryStatus $Summary ([bool]$NoColor)
  Write-SysmonSummaryFields $Summary $ChannelSizeMiB
  Write-SysmonSummaryCollection Actions $Summary.Actions Green ([bool]$NoColor)
  Write-SysmonSummaryCollection Warnings $Summary.Warnings Yellow ([bool]$NoColor)
  Write-UiLine $line
}
function Write-SysmonSummaryColor([string]$Text,[ConsoleColor]$Color,[bool]$NoColor) {
  if ($NoColor) { Write-UiLine $Text; return }
  Write-UiLine $Text -ForegroundColor $Color
}
function Write-SysmonSummaryHeader([string]$Line,[bool]$NoColor) {
  Write-UiLine $Line
  Write-SysmonSummaryColor 'Sysmon Config Updater' Cyan $NoColor
  Write-UiLine ('Timestamp      : ' + (Get-Date).ToString('s'))
  Write-UiLine $Line
}
function Write-SysmonSummaryStatus($Summary,[bool]$NoColor) {
  if ([bool]$Summary.Ok) { Write-SysmonSummaryColor 'Status         : OK' Green $NoColor }
  else { Write-SysmonSummaryColor 'Status         : NOT OK' Red $NoColor }
  if ([bool]$Summary.DriftDetected) { Write-SysmonSummaryColor 'DriftDetected  : True' Yellow $NoColor }
  else { Write-UiLine 'DriftDetected  : False' }
}
function Get-SysmonSummaryValue($Value) {
  if ($Value) { return $Value }
  return 'n/a'
}
function Write-SysmonSummaryFields($Summary,[int]$ChannelSizeMiB) {
  Write-UiLine ('Remediate      : ' + $Summary.Remediate + ' (IsAdmin=' + $Summary.IsAdmin + ')')
  Write-UiLine ('EnsureChannel  : ' + $Summary.EnsureChannel + ' (SizeMiB=' + $ChannelSizeMiB + ')')
  Write-UiLine ('ConfigFile     : ' + (Get-SysmonSummaryValue $Summary.ConfigFile))
  Write-UiLine ('DesiredSha256  : ' + (Get-SysmonSummaryValue $Summary.DesiredSha256))
  Write-UiLine ('PrevSha256     : ' + (Get-SysmonSummaryValue $Summary.PrevDesiredSha256))
  Write-UiLine ('Service        : ' + (Get-SysmonSummaryValue $Summary.SysmonService))
  Write-UiLine ('Exe            : ' + (Get-SysmonSummaryValue $Summary.SysmonExe))
  Write-UiLine ('EngineVersion  : ' + (Get-SysmonSummaryValue $Summary.EngineVersion))
  Write-UiLine ('DumpSha256     : ' + (Get-SysmonSummaryValue $Summary.CurrentDumpSha256))
  Write-UiLine ('StateWritten   : ' + $Summary.StateWritten)
}
function Write-SysmonSummaryCollection([string]$Title,$Items,[ConsoleColor]$Color,[bool]$NoColor) {
  if (-not $Items -or $Items.Count -eq 0) { return }
  Write-UiLine ''
  Write-SysmonSummaryColor "${Title}:" $Color $NoColor
  foreach ($item in $Items) { Write-UiLine ('  - ' + $item) }
}
