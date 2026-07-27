<#
.SYNOPSIS
Pure scheduled-task normalization helpers for the hygiene audit.

.DESCRIPTION
Converts inconsistent Task Scheduler objects into stable paths, strings, and
classification values. The helpers remain side-effect free so audit decisions
can be tested without querying or modifying the Windows task service.
#>

function Get-PropValue {
  param(
    [Parameter(Mandatory=$true)]$Object,
    [Parameter(Mandatory=$true)][string]$Name,
    $Default = $null
  )
  if ($null -eq $Object) { return $Default }
  try {
    if ($Object.PSObject -and $Object.PSObject.Properties -and $null -ne $Object.PSObject.Properties[$Name]) {
      return $Object.PSObject.Properties[$Name].Value
    }
  } catch {
    Write-Verbose ("Property lookup failed for '{0}': {1}" -f $Name,$_.Exception.Message)
  }
  return $Default
}

function Coalesce-String {
  param([object]$Value,[string]$Default)
  $s = $null
  try { $s = [string]$Value } catch { $s = $null }
  if ([string]::IsNullOrWhiteSpace($s)) { return $Default }
  return $s
}

function Normalize-TaskPath {
  param([string]$TaskPath)
  if ([string]::IsNullOrWhiteSpace($TaskPath)) { return "\" }
  if ($TaskPath[0] -ne '\') { $TaskPath = "\" + $TaskPath }
  if ($TaskPath[-1] -ne '\') { $TaskPath = $TaskPath + "\" }
  return $TaskPath
}

function Normalize-FullTaskPath {
  param([string]$TaskPath,[string]$TaskName)
  $tp = Normalize-TaskPath $TaskPath
  return ($tp + $TaskName)
}
