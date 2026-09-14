#requires -version 5.1
<#
.SYNOPSIS
  Provides private LAPS hygiene phases.
.DESCRIPTION
  Preserves policy precedence, rotation decisions, diagnostics, and result reporting for the public capability.
#>

function Copy-ObjectDeep {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$InputObject, [int]$Depth = 12)
  return ($InputObject | ConvertTo-Json -Depth $Depth | ConvertFrom-Json)
}
function Merge-ConfigObject {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Base,
    [Parameter(Mandatory)]$Override
  )
  if ($null -eq $Override) {
    return $Base
  }
  if ($Override.PSObject.Properties['EventLog']) {
    Merge-LapsEventLogConfig -Base $Base -Override $Override
  }
  if ($Override.PSObject.Properties['PolicyDefaults']) {
    Merge-LapsPolicyDefaultsConfig -Base $Base -Override $Override
  }
  if ($Override.PSObject.Properties['Remediation']) {
    Merge-LapsRemediationConfig -Base $Base -Override $Override
  }
  if ($Override.PSObject.Properties['Console']) {
    Merge-LapsConsoleConfig -Base $Base -Override $Override
  }
  return $Base
}
function Get-ConfigFromJson {
  [CmdletBinding()]
  param(
    [string]$Path,
    [Parameter(Mandatory)]$DefaultsObject
  )
  $cfg = Copy-ObjectDeep -InputObject $DefaultsObject -Depth 12
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
    return $cfg
  }
  try {
    $sanitized = Sanitize-Path -Path $Path -MustExist
    if (-not $sanitized) {
      return $cfg
    }
    $raw = Get-BoundedUtf8FileContent -Path $sanitized -MaximumBytes 1048576
    if (-not $raw -or -not $raw.Trim()) {
      return $cfg
    }
    $j = $raw | ConvertFrom-Json -ErrorAction Stop
    return (Merge-ConfigObject -Base $cfg -Override $j)
  }
  catch {
    return $cfg
  }
}
# --------------------------- Formatted Console Helpers --------------------------------
# Never type UI parameters as [bool]; accept anything and normalize internally.
function ConvertTo-BoolSafe {
  [CmdletBinding()]
  param([AllowNull()]$Value, [bool]$Default = $false)
  if ($null -eq $Value) {
    return $Default
  }
  if ($Value -is [bool]) {
    return [bool]$Value
  }
  if ($Value -is [int] -or $Value -is [long]) {
    return ([int]$Value -ne 0)
  }
  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) {
    return $Default
  }
  return ConvertTo-LapsTextBool -Value $s -Default $Default
}
function Get-StyleForOk {
  param([AllowNull()]$Ok)
  if (ConvertTo-BoolSafe -Value $Ok -Default $false) {
    return 'Good'
  }
  return 'Bad'
}
function Get-StyleForBool {
  param([AllowNull()]$Value)
  if (ConvertTo-BoolSafe -Value $Value -Default $false) {
    return 'Good'
  }
  return 'Dim'
}
# --------------------------- Event Log Helpers -------------------------------------
function Try-WriteHealthEvent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][bool]$Enabled,
    [Parameter(Mandatory)][int]$Id,
    [Parameter(Mandatory)][string]$Msg,
    [ValidateSet('Information', 'Warning', 'Error')]
    [string]$Level = 'Information',
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$LogName
  )
  if (-not $Enabled) {
    return $false
  }
  return [bool](Write-HealthEvent -LogName $LogName -Source $Source -Level $Level -Id $Id -Message $Msg)
}
# --------------------------- Core Helpers ------------------------------------------
function To-Iso {
  param($dt)
  if ($null -eq $dt) {
    return $null
  }
  try {
    return (Get-Date $dt).ToString('s')
  }
  catch {
    return [string]$dt
  }
}
function Get-RegistryPropertiesCount {
  param($obj)
  if (-not $obj) {
    return 0
  }
  $skip = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
  return @($obj.PSObject.Properties.Name | Where-Object { $_ -notin $skip }).Count
}

. (Join-Path $PSScriptRoot '02-LAPS-Hygiene.observations.ps1')
. (Join-Path $PSScriptRoot '02-LAPS-Hygiene.runtime.ps1')
. (Join-Path $PSScriptRoot '02-LAPS-Hygiene.presentation.ps1')
