Set-StrictMode -Version Latest

<#
.SYNOPSIS
Findings list creation and management for v2 result objects.

.DESCRIPTION
Provides factory functions to create typed finding objects and manage
ordered finding lists used by the v2 script result contract.
#>

function Get-CallerValue {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Name)

  foreach ($scope in 1..5) {
    try {
      $value = Get-Variable -Name $Name -Scope $scope -ValueOnly -ErrorAction Stop
      if ($null -ne $value) { return $value }
    } catch {
      continue
    }
  }
  return $null
}

<#
.SYNOPSIS
  Creates a new empty findings list.
#>
function Get-FindingsList {
  [CmdletBinding()]
  param()
  $list = New-Object System.Collections.Generic.List[object]
  return , $list
}

<#
.SYNOPSIS
  Creates a single finding object.
.PARAMETER Code
  Short identifier code for the finding.
.PARAMETER Severity
  Severity level string (e.g. OK, WARN, FAIL).
.PARAMETER Message
  Human-readable description of the finding.
.PARAMETER TypeName
  Optional PS type name to insert into PSTypeNames.
.PARAMETER Extra
  Additional properties to attach to the finding object.
#>
function Get-FindingObject {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Code,
    [Parameter(Mandatory)]
    [ValidateSet('Critical','High','Medium','Low','Info','Warning','Warn','Error','OK','Pass','Fail','Skip','Skipped','Debug')]
    [string]$Severity,
    [Parameter(Mandatory)][string]$Message,
    [string]$TypeName,
    [hashtable]$Extra
  )

  $obj = [pscustomobject]@{
    Code     = $Code
    Severity = $Severity
    Message  = $Message
  }

  if ($TypeName) { $obj.PSTypeNames.Insert(0, $TypeName) }
  if ($Extra) {
    foreach ($k in $Extra.Keys) {
      $obj | Add-Member -NotePropertyName $k -NotePropertyValue $Extra[$k] -Force
    }
  }

  return $obj
}

<#
.SYNOPSIS
  Creates a finding and appends it to a findings list.
.PARAMETER FindingList
  Target list. Falls back to caller-scope $Findings variable if not provided.
.PARAMETER Code
  Short identifier code for the finding.
.PARAMETER Severity
  Severity level string (e.g. OK, WARN, FAIL).
.PARAMETER Message
  Human-readable description of the finding.
.PARAMETER TypeName
  Optional PS type name to insert into PSTypeNames.
.PARAMETER ProfileName
  Optional profile name added as a Profile property.
.PARAMETER Extra
  Additional properties to attach to the finding object.
#>
function Add-Finding {
  [CmdletBinding()]
  param(
    [Alias('Findings','List')][System.Collections.Generic.List[object]]$FindingList,
    [Parameter(Mandatory)][string]$Code,
    [Parameter(Mandatory)]
    [ValidateSet('Critical','High','Medium','Low','Info','Warning','Warn','Error','OK','Pass','Fail','Skip','Skipped','Debug')]
    [string]$Severity,
    [Parameter(Mandatory)][string]$Message,
    [string]$TypeName,
    [string]$ProfileName,
    [hashtable]$Extra,
    [switch]$TimeUtc,
    [switch]$TimestampLocal
  )

  if ($null -eq $FindingList) {
    $FindingList = Get-CallerValue -Name 'Findings'
    if ($null -eq $FindingList) { $FindingList = Get-CallerValue -Name 'script:Findings' }
  }
  if ($null -eq $FindingList) {
    throw 'FindingList not provided and no $Findings/$script:Findings found.'
  }

  $extraFields = @{}
  if ($Extra) {
    foreach ($k in $Extra.Keys) { $extraFields[$k] = $Extra[$k] }
  }
  if ($ProfileName) { $extraFields['Profile'] = $ProfileName }

  if ($TimeUtc) { $extraFields['TimeUtc'] = (Get-Date).ToUniversalTime() }
  if ($TimestampLocal) { $extraFields['Timestamp'] = (Get-Date) }

  $obj = Get-FindingObject -Code $Code -Severity $Severity -Message $Message -TypeName $TypeName -Extra $extraFields
  $FindingList.Add($obj) | Out-Null
  return , $FindingList
}

Export-ModuleMember -Function Get-FindingsList,Get-FindingObject,Add-Finding
