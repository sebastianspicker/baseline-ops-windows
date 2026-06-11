Set-StrictMode -Version Latest

function Get-CallerValue {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Name)

  foreach ($scope in 1..3) {
    try {
      $var = Get-Variable -Name $Name -Scope $scope -ErrorAction Stop
      return $var.Value
    } catch {
      # Continue searching outer scopes.
    }
  }
  try {
    $var = Get-Variable -Name $Name -Scope Global -ErrorAction Stop
    return $var.Value
  } catch {
    # No caller/global fallback value was found.
  }
  return $null
}

<#
.SYNOPSIS
Windows Event Log helpers for health scripts.

.DESCRIPTION
Provides functions to ensure an event source exists and to write structured
health events to the Windows Application Event Log.
#>

function Get-EventLogCallerValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$CanonicalName,
    [Parameter(Mandatory)][string]$DeprecatedName,
    [Parameter(Mandatory)][string]$WarningMessage
  )

  $value = Get-CallerValue -Name $CanonicalName
  if ($value) { return $value }

  $value = Get-CallerValue -Name $DeprecatedName
  if ($value) {
    Write-Warning $WarningMessage
    return $value
  }

  return $null
}

<#
.SYNOPSIS
  Ensures a Windows Event Log source is registered.
.PARAMETER Source
  Event source name to register (alias: SourceName).
.PARAMETER LogName
  Event log name (default: Application).
.PARAMETER OnErrorMessage
  Warning message string to emit on failure (replaces former scriptblock parameter).
#>
function Ensure-EventSource {
  [CmdletBinding()]
  param(
    [Alias('SourceName')][string]$Source,
    [Alias('Log')][string]$LogName,
    [string]$OnErrorMessage
  )
  if ([string]::IsNullOrWhiteSpace($Source)) {
    $Source = Get-EventLogCallerValue -CanonicalName 'EventSource' -DeprecatedName 'EventSourceName' -WarningMessage 'Use EventSource, not EventSourceName (deprecated)'
  }
  if ([string]::IsNullOrWhiteSpace($LogName)) {
    $LogName = Get-EventLogCallerValue -CanonicalName 'EventLogName' -DeprecatedName 'EventLog' -WarningMessage 'Use EventLogName, not EventLog (deprecated)'
    if ([string]::IsNullOrWhiteSpace($LogName)) { $LogName = 'Application' }
  }
  if ([string]::IsNullOrWhiteSpace($Source)) {
    if ($OnErrorMessage) { Write-Warning $OnErrorMessage } else { Write-Warning 'Ensure-EventSource: -Source or -SourceName is required, or set EventSource in caller scope.' }
    return $false
  }

  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
      New-EventLog -LogName $LogName -Source $Source -ErrorAction Stop | Out-Null
    }
    return $true
  } catch {
    if ($OnErrorMessage) { Write-Warning $OnErrorMessage } else { Write-Warning $_.Exception.Message }
    return $false
  }
}

<#
.SYNOPSIS
  Writes a health event to the Windows Event Log.
.PARAMETER Id
  Event ID for the log entry.
.PARAMETER Message
  Event message text.
.PARAMETER Level
  Entry type: Information, Warning, or Error.
.PARAMETER Source
  Event source name. Falls back to caller-scope EventSource variable.
.PARAMETER LogName
  Event log name. Falls back to caller-scope EventLogName variable.
.PARAMETER OnErrorMessage
  Warning message string to emit on failure (replaces former scriptblock parameter).
#>
function Write-HealthEvent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][int]$Id,
    [Parameter(Mandatory)][Alias('Msg')][string]$Message,
    [ValidateSet('Information','Warning','Error')][string]$Level = 'Information',
    [string]$Source,
    [Alias('Log')][string]$LogName,
    [string]$OnErrorMessage
  )

  if (-not $Source) {
    $Source = Get-EventLogCallerValue -CanonicalName 'EventSource' -DeprecatedName 'EventSourceName' -WarningMessage 'Use EventSource, not EventSourceName (deprecated)'
  }
  if (-not $LogName) {
    $LogName = Get-EventLogCallerValue -CanonicalName 'EventLogName' -DeprecatedName 'EventLog' -WarningMessage 'Use EventLogName, not EventLog (deprecated)'
  }

  if ([string]::IsNullOrWhiteSpace($Source) -or [string]::IsNullOrWhiteSpace($LogName)) {
    $msg = 'Write-HealthEvent: Source or LogName is missing. Set EventSource and EventLogName in caller scope or pass -Source and -LogName.'
    if ($OnErrorMessage) { Write-Warning $OnErrorMessage } else { Write-Warning $msg }
    return $false
  }

  try {
    Write-EventLog -LogName $LogName -Source $Source -EntryType $Level -EventId $Id -Message $Message -ErrorAction Stop
    return $true
  } catch {
    if ($OnErrorMessage) { Write-Warning $OnErrorMessage } else { Write-Warning $_.Exception.Message }
    return $false
  }
}

Export-ModuleMember -Function Ensure-EventSource,Write-HealthEvent
