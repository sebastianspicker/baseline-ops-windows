Set-StrictMode -Version Latest

function Get-CallerValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name
  )

  foreach ($scope in 1..3) {
    try {
      $var = Get-Variable -Name $Name -Scope $scope -ErrorAction Stop
      return $var.Value
    } catch {
      # continue
    }
  }
  return $null
}

function Ensure-EventSource {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][Alias('Log')][string]$LogName,
    [scriptblock]$OnError
  )

  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
      New-EventLog -LogName $LogName -Source $Source -ErrorAction Stop | Out-Null
    }
    return $true
  } catch {
    if ($OnError) { & $OnError ($_.Exception.Message) }
    return $false
  }
}

function Write-HealthEvent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][int]$Id,
    [Parameter(Mandatory)][Alias('Msg')][string]$Message,
    [ValidateSet('Information','Warning','Error')][string]$Level = 'Information',
    [string]$Source,
    [Alias('Log','LogName')][string]$LogName,
    [scriptblock]$OnError
  )

  if (-not $Source) {
    $Source = Get-CallerValue -Name 'EventSource'
    if (-not $Source) { $Source = Get-CallerValue -Name 'EventSourceName' }
  }
  if (-not $LogName) {
    $LogName = Get-CallerValue -Name 'EventLogName'
    if (-not $LogName) { $LogName = Get-CallerValue -Name 'EventLog' }
  }

  try {
    Write-EventLog -LogName $LogName -Source $Source -EntryType $Level -EventId $Id -Message $Message -ErrorAction Stop
    return $true
  } catch {
    if ($OnError) { & $OnError ($_.Exception.Message) }
    return $false
  }
}

Export-ModuleMember -Function Ensure-EventSource,Write-HealthEvent
