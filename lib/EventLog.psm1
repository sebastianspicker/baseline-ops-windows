<#
.SYNOPSIS
Windows Event Log helpers for health scripts.

.DESCRIPTION
Provides functions to ensure an event source exists and to write structured
health events to the Windows Application Event Log.
#>

Set-StrictMode -Version Latest
Microsoft.PowerShell.Core\Import-Module ([System.IO.Path]::Combine($PSScriptRoot, 'Common.psm1')) -DisableNameChecking

<#
.SYNOPSIS
Resolves one event-log setting from canonical or deprecated caller state.
.DESCRIPTION
Prefers the current setting name and emits a warning when compatibility fallback
to the deprecated name is required.
#>
function Get-EventLogSetting {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$CanonicalName,
    [Parameter(Mandatory)][string]$DeprecatedName,
    [Parameter(Mandatory)][string]$DeprecationWarning
  )

  $value = Get-CallerValue -Name $CanonicalName -IncludeGlobal
  if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
    return [string]$value
  }

  $value = Get-CallerValue -Name $DeprecatedName -IncludeGlobal
  if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
    Write-Warning $DeprecationWarning
    return [string]$value
  }

  return $null
}

<#
.SYNOPSIS
  Tests whether a Windows Event Log source is registered.
.DESCRIPTION
  Isolates the platform source lookup used before event writing.
#>
function Test-EventLogSourceExists {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Source)

  return [System.Diagnostics.EventLog]::SourceExists($Source)
}

<#
.SYNOPSIS
  Registers a Windows Event Log source.
.DESCRIPTION
  Creates the source for the requested event log when it is absent.
#>
function Register-EventLogSource {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$LogName
  )

  $sourceData = [System.Diagnostics.EventSourceCreationData]::new($Source, $LogName)
  [System.Diagnostics.EventLog]::CreateEventSource($sourceData)
}

<#
.SYNOPSIS
  Writes one structured Windows Event Log entry.
.DESCRIPTION
  Creates and disposes the event-log writer around a single record.
#>
function Write-EventLogEntry {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$LogName,
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][int]$Id,
    [Parameter(Mandatory)][string]$Message,
    [Parameter(Mandatory)][ValidateSet('Information','Warning','Error')][string]$Level
  )

  $entryType = [System.Diagnostics.EventLogEntryType]$Level
  $eventLog = [System.Diagnostics.EventLog]::new($LogName, '.', $Source)
  try {
    $eventLog.WriteEntry($Message, $entryType, $Id)
  } finally {
    $eventLog.Dispose()
  }
}

<#
.SYNOPSIS
  Resolves the event source from parameters or compatible caller state.
#>
function Resolve-HealthEventSource {
  [CmdletBinding()]
  param([string]$Source)

  if (-not [string]::IsNullOrWhiteSpace($Source)) { return $Source }
  return Get-EventLogSetting -CanonicalName 'EventSource' -DeprecatedName 'EventSourceName' `
    -DeprecationWarning 'Use EventSource, not EventSourceName (deprecated)'
}

<#
.SYNOPSIS
  Resolves the event log name from parameters or compatible caller state.
#>
function Resolve-HealthEventLogName {
  [CmdletBinding()]
  param([string]$LogName)

  if (-not [string]::IsNullOrWhiteSpace($LogName)) { return $LogName }
  return Get-EventLogSetting -CanonicalName 'EventLogName' -DeprecatedName 'EventLog' `
    -DeprecationWarning 'Use EventLogName, not EventLog (deprecated)'
}

<#
.SYNOPSIS
  Writes an event-log failure warning.
#>
function Write-EventLogFailureWarning {
  [CmdletBinding()]
  param(
    [string]$OnErrorMessage,
    [Parameter(Mandatory)][string]$DefaultMessage
  )

  if ($OnErrorMessage) { Write-Warning $OnErrorMessage } else { Write-Warning $DefaultMessage }
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

  $Source = Resolve-HealthEventSource -Source $Source
  $LogName = Resolve-HealthEventLogName -LogName $LogName
  if ([string]::IsNullOrWhiteSpace($LogName)) { $LogName = 'Application' }
  if ([string]::IsNullOrWhiteSpace($Source)) {
    Write-EventLogFailureWarning -OnErrorMessage $OnErrorMessage `
      -DefaultMessage 'Ensure-EventSource: -Source or -SourceName is required, or set EventSource in caller scope.'
    return $false
  }

  try {
    if (-not (Test-EventLogSourceExists -Source $Source)) {
      Register-EventLogSource -Source $Source -LogName $LogName
    }
    return $true
  } catch {
    Write-EventLogFailureWarning -OnErrorMessage $OnErrorMessage -DefaultMessage $_.Exception.Message
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

  if (-not $Source) { $Source = Resolve-HealthEventSource -Source $Source }
  if (-not $LogName) { $LogName = Resolve-HealthEventLogName -LogName $LogName }

  if ([string]::IsNullOrWhiteSpace($Source) -or [string]::IsNullOrWhiteSpace($LogName)) {
    $msg = 'Write-HealthEvent: Source or LogName is missing. Set EventSource and EventLogName in caller scope or pass -Source and -LogName.'
    Write-EventLogFailureWarning -OnErrorMessage $OnErrorMessage -DefaultMessage $msg
    return $false
  }

  try {
    Write-EventLogEntry -LogName $LogName -Source $Source -Id $Id -Message $Message -Level $Level
    return $true
  } catch {
    Write-EventLogFailureWarning -OnErrorMessage $OnErrorMessage -DefaultMessage $_.Exception.Message
    return $false
  }
}

Export-ModuleMember -Function Ensure-EventSource,Write-HealthEvent
