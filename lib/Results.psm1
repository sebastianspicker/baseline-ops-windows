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
  $extraFields = Copy-FindingExtraFields -Extra $Extra -ProfileName $null -TimeUtc $false -TimestampLocal $false
  foreach ($key in $extraFields.Keys) {
    $obj | Add-Member -NotePropertyName $key -NotePropertyValue $extraFields[$key] -Force
  }

  return $obj
}

<#
.SYNOPSIS
  Resolves the supplied finding list or its compatible caller-scope fallback.
#>
function Resolve-FindingList {
  [CmdletBinding()]
  param([System.Collections.Generic.List[object]]$FindingList)

  if ($null -ne $FindingList) { return , $FindingList }
  $FindingList = Common\Get-CallerValue -Name 'Findings' -ScopeDepth 5
  if ($null -eq $FindingList) { $FindingList = Common\Get-CallerValue -Name 'script:Findings' -ScopeDepth 5 }
  if ($null -eq $FindingList) { throw 'FindingList not provided and no $Findings/$script:Findings found.' }
  return , $FindingList
}

<#
.SYNOPSIS
  Copies optional finding metadata into a new property hashtable.
#>
function Copy-FindingExtraFields {
  [CmdletBinding()]
  param(
    [hashtable]$Extra,
    [string]$ProfileName,
    [bool]$TimeUtc,
    [bool]$TimestampLocal
  )

  $extraFields = @{}
  if ($Extra) { foreach ($key in $Extra.Keys) { $extraFields[$key] = $Extra[$key] } }
  if ($ProfileName) { $extraFields['Profile'] = $ProfileName }
  if ($TimeUtc) { $extraFields['TimeUtc'] = (Get-Date).ToUniversalTime() }
  if ($TimestampLocal) { $extraFields['Timestamp'] = (Get-Date) }
  return $extraFields
}

<#
.SYNOPSIS
  Appends a newly built finding to the target list.
.DESCRIPTION
  Mutates the supplied list without writing to the success stream unless
  PassThru is requested. This keeps script result pipelines reserved for their
  documented result objects.
.PARAMETER FindingList
  Target list. Falls back to caller-scope $Findings variable if not provided.
.PARAMETER Code
  Identifier stored on the appended finding.
.PARAMETER Severity
  Valid severity value for the appended finding.
.PARAMETER Message
  Display text stored on the appended finding.
.PARAMETER TypeName
  Optional leading type name for the generated object.
.PARAMETER ProfileName
  Optional value written to the generated Profile property.
.PARAMETER Extra
  Extra fields copied to the generated object.
.PARAMETER PassThru
  Returns the target findings list after appending. The default is no
  success-stream output.
#>
function Add-Finding {
  [CmdletBinding()]
  param(
    [Alias('Findings','List')][System.Collections.Generic.List[object]]$FindingList,
    [Parameter(Mandatory)][Alias('FindingCode')][System.String]$Code,
    [Parameter(Mandatory)]
    [ValidateSet('Critical','High','Medium','Low','Info','Warning','Warn','Error','OK','Pass','Fail','Skip','Skipped','Debug')]
    [string]$Severity,
    [Parameter(Mandatory)][string]$Message,
    [string]$TypeName,
    [string]$ProfileName,
    [hashtable]$Extra
  )

  dynamicparam {
    $dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
    $attributes = New-Object 'System.Collections.ObjectModel.Collection[System.Attribute]'
    [void]$attributes.Add((New-Object System.Management.Automation.ParameterAttribute))
    $dictionary.Add('TimeUtc', (New-Object System.Management.Automation.RuntimeDefinedParameter('TimeUtc', [switch], $attributes)))
    $dictionary.Add('TimestampLocal', (New-Object System.Management.Automation.RuntimeDefinedParameter('TimestampLocal', [switch], $attributes)))
    $dictionary.Add('PassThru', (New-Object System.Management.Automation.RuntimeDefinedParameter('PassThru', [switch], $attributes)))
    return $dictionary
  }

  process {
    $TimeUtc = [bool]$PSBoundParameters['TimeUtc']
    $TimestampLocal = [bool]$PSBoundParameters['TimestampLocal']
    $PassThru = [bool]$PSBoundParameters['PassThru']

    $FindingList = Resolve-FindingList -FindingList $FindingList
    $extraFields = Copy-FindingExtraFields -Extra $Extra -ProfileName $ProfileName `
      -TimeUtc $TimeUtc -TimestampLocal $TimestampLocal

  $obj = Get-FindingObject -Code $Code -Severity $Severity -Message $Message -TypeName $TypeName -Extra $extraFields
  $FindingList.Add($obj) | Out-Null
    if ($PassThru) { return , $FindingList }
  }
}

Export-ModuleMember -Function Get-FindingsList,Get-FindingObject,Add-Finding
