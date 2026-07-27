<#
.SYNOPSIS
Findings list creation and management for v2 result objects.

.DESCRIPTION
Provides factory functions to create typed finding objects and manage
ordered finding lists used by the v2 script result contract.
#>

Set-StrictMode -Version Latest
Microsoft.PowerShell.Core\Import-Module ([System.IO.Path]::Combine($PSScriptRoot, 'Common.psm1')) -DisableNameChecking

<#
.SYNOPSIS
  Creates a new empty findings list.
#>
function Get-FindingsList {
  [CmdletBinding()]
  param()
  return , [System.Collections.Generic.List[object]]::new()
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
.DESCRIPTION
  Mutates the supplied list without writing to the success stream unless
  PassThru is requested. This keeps script result pipelines reserved for their
  documented result objects.
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
.PARAMETER PassThru
  Returns the target findings list after appending. The default is no
  success-stream output.
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
    [switch]$TimestampLocal,
    [switch]$PassThru
  )

  if ($null -eq $FindingList) {
    $FindingList = Common\Get-CallerValue -Name 'Findings' -ScopeDepth 5
    if ($null -eq $FindingList) { $FindingList = Common\Get-CallerValue -Name 'script:Findings' -ScopeDepth 5 }
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
  if ($PassThru) { return , $FindingList }
}

Export-ModuleMember -Function Get-FindingsList,Get-FindingObject,Add-Finding
