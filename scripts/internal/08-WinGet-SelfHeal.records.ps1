<#
.SYNOPSIS
WinGet self-heal records helpers.

.DESCRIPTION
Contains capability-private WinGet self-heal records behavior.
#>

function Get-TextOrEmpty {
  [CmdletBinding()]
  param([AllowNull()][AllowEmptyString()]$Value)
  if ($null -eq $Value) { return '' }
  return [string]$Value
}

function Get-CheckRecord {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [ValidateSet('OK','Warning','Error','Skipped')] [string]$Status,
    [string]$Message = $null,
    [hashtable]$Data = $null
  )
  [pscustomobject]@{
    Time    = (Get-Date).ToString('s')
    Name    = $Name
    Status  = $Status
    Message = $Message
    Data    = if ($Data) { [pscustomobject]$Data } else { $null }
  }
}

function Add-Record {
  [CmdletBinding()]
  param(
    # Collections must allow empty, otherwise PS rejects empty collections during binding.
    [ValidateNotNull()]
    [AllowEmptyCollection()]
    [System.Collections.Generic.List[object]]$List,
    [Parameter(Mandatory)]
    [ValidateNotNull()]
    [object]$Record
  )
  [void]$List.Add($Record)
}

function Get-OverallOk {
  [CmdletBinding()]
  param([AllowNull()][object[]]$Records)
  if ($null -eq $Records -or $Records.Count -eq 0) { return $false }
  foreach ($r in $Records) {
    if ($null -ne $r -and $r.Status -eq 'Error') { return $false }
  }
  return $true
}

function Protect-WingetProcessMetadata {
  [CmdletBinding()]
  [OutputType([string])]
  param([AllowNull()][AllowEmptyString()]$Value)

  if ($null -eq $Value) { return '' }
  # Process output and arguments can echo a legacy or rejected source URL.
  # Do not let URL userinfo enter records, pipeline output, or event logging.
  return [regex]::Replace(
    [string]$Value,
    '(?i)https?://[^\s]*(?:@|\?|#)[^\s]*',
    '[credential-bearing URL redacted]'
  )
}

function Get-PrivateSourceResultMetadata {
  [CmdletBinding()]
  [OutputType([hashtable])]
  param(
    [AllowNull()][string]$Name,
    [AllowNull()][string]$Type
  )

  # Source endpoints are execution inputs, not result metadata. Authentication
  # must be provisioned separately and must never be carried in the URL.
  return @{ Name = $Name; Type = $Type; Endpoint = '[not recorded]' }
}

function Get-Config {
  [CmdletBinding()]
  param([string]$Path)
  try {
    $sanitized = Sanitize-Path -Path $Path -MustExist
    if ($sanitized) {
      $configItem = Get-Item -LiteralPath $sanitized -Force -ErrorAction Stop
      if ($configItem.Length -gt 1MB) { throw 'Configuration file exceeds the 1 MiB size limit.' }
      return Get-BoundedUtf8FileContent -Path $sanitized -MaximumBytes 1048576 | ConvertFrom-Json
    }
  } catch {
    Write-Verbose ("WinGet config read failed: {0}" -f $_.Exception.Message)
  }
  return $null
}

function Get-NestedPropValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$Object,
    [Parameter(Mandatory)][string[]]$Path
  )
  $cur = $Object
  foreach ($name in $Path) {
    if ($null -eq $cur) { return $null }
    try {
      $prop = $cur.PSObject.Properties[$name]
      if ($null -eq $prop) { return $null }
      $cur = $prop.Value
    } catch { return $null }
  }
  return $cur
}
