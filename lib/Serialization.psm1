Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Validation.psm1') -Force -Global

function ConvertTo-ObjectArray {
  [CmdletBinding()]
  param([AllowNull()][object]$InputObject)

  if ($null -eq $InputObject) { return ,@() }

  if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($item in $InputObject) {
      $items.Add($item) | Out-Null
    }
    return ,$items.ToArray()
  }

  return ,@($InputObject)
}

<#
.SYNOPSIS
Serialization and v2 result object utilities.

.DESCRIPTION
Provides functions to save objects as JSON or CSV, create standardized v2 result
objects, and write result objects in the configured output format.
#>

<#
.SYNOPSIS
  Serializes an object to a JSON file.
.PARAMETER InputObject
  Object to serialize.
.PARAMETER Path
  Output file path. Parent directory is created if needed.
.PARAMETER Depth
  JSON serialization depth (default 20).
.PARAMETER NoBom
  Write UTF-8 without byte-order mark.
#>
function Save-Json {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [object]$InputObject,
    [Parameter(Mandatory)]
    [string]$Path,
    [int]$Depth = 20,
    [switch]$NoBom
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw 'Save-Json: Path cannot be null or empty.'
  }
  if (Test-PathTraversal -Path $Path) {
    throw 'Save-Json: Path must not contain path traversal segments ("..").'
  }

  $dir = Split-Path -Path $Path -Parent
  if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
  }

  $json = $InputObject | ConvertTo-Json -Depth $Depth
  if ($NoBom) {
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
  } else {
    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
  }
}

<#
.SYNOPSIS
  Exports objects to a CSV file.
.PARAMETER InputObject
  Objects to export.
.PARAMETER Path
  Output CSV file path. Parent directory is created if needed.
#>
function Save-Csv {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [object[]]$InputObject,
    [Parameter(Mandatory)]
    [string]$Path
  )

  if (Test-PathTraversal -Path $Path) {
    throw 'Save-Csv: Path must not contain path traversal segments ("..").'
  }

  $dir = Split-Path -Path $Path -Parent
  if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
  }

  $InputObject | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

<#
.SYNOPSIS
  Creates a standardized v2 result object.
.PARAMETER ScriptName
  Name of the calling script (e.g. '27-Defender-Health-Audit.ps1').
.PARAMETER Mode
  Execution mode: Audit or Remediate.
.PARAMETER Result
  Overall result: OK, WARN, or FAIL.
.PARAMETER Findings
  Array of finding objects to include.
.PARAMETER Summary
  Optional summary object with script-specific details.
.PARAMETER Metadata
  Optional hashtable of additional metadata.
.PARAMETER SchemaVersion
  Schema version string (default '2.0').
#>
function Get-V2ResultObject {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$ScriptName,
    [Parameter(Mandatory)]
    [ValidateSet('Audit','Remediate')]
    [string]$Mode,
    [Parameter(Mandatory)]
    [ValidateSet('OK','WARN','FAIL')]
    [string]$Result,
    [AllowNull()]
    [object]$Findings = @(),
    [object]$Summary = $null,
    [hashtable]$Metadata = @{},
    [string]$SchemaVersion = '2.0'
  )

  $findingArray = @()
  if ($null -ne $Findings) {
    if ($Findings -is [System.Collections.IEnumerable] -and $Findings -isnot [string]) {
      $tmp = New-Object System.Collections.Generic.List[object]
      foreach ($finding in $Findings) {
        $tmp.Add($finding) | Out-Null
      }
      $findingArray = $tmp.ToArray()
    } else {
      $findingArray = @($Findings)
    }
  }

  return [pscustomobject]@{
    SchemaVersion = $SchemaVersion
    ScriptName    = $ScriptName
    Mode          = $Mode
    ComputerName  = $env:COMPUTERNAME
    TimestampUtc  = (Get-Date).ToUniversalTime()
    Result        = $Result
    Findings      = $findingArray
    Summary       = $Summary
    Metadata      = $Metadata
  }
}

<#
.SYNOPSIS
  Writes a result object in the specified output format.
.PARAMETER ResultObject
  The v2 result object to output.
.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.
.PARAMETER OutputPath
  File path required for Json and Csv formats.
#>
function Write-ResultObject {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [object]$ResultObject,
    [ValidateSet('Console','Json','Csv','None')]
    [string]$OutputFormat = 'Console',
    [string]$OutputPath
  )

  switch ($OutputFormat) {
    'None' {
      return
    }
    'Console' {
      return
    }
    'Json' {
      if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        throw 'OutputPath is required when OutputFormat is Json.'
      }
      Save-Json -InputObject $ResultObject -Path $OutputPath -Depth 10 -NoBom
      return
    }
    'Csv' {
      if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        throw 'OutputPath is required when OutputFormat is Csv.'
      }

      if ($ResultObject.PSObject.Properties.Name -contains 'Findings') {
        Save-Csv -InputObject @($ResultObject.Findings) -Path $OutputPath
      } else {
        Save-Csv -InputObject @($ResultObject) -Path $OutputPath
      }
      return
    }
  }
}

<#
.SYNOPSIS
  Returns a v2 result object as a formatted JSON string suitable for machine consumption.
.DESCRIPTION
  Wraps ConvertTo-Json with consistent depth and encoding settings. The output
  uses depth 10 by default, which is sufficient for nested finding objects with
  Extra properties while avoiding circular reference issues.
.PARAMETER ResultObject
  The v2 result object to serialize.
.PARAMETER Depth
  JSON serialization depth (default 10).
#>
function ConvertTo-V2Json {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [object]$ResultObject,
    [int]$Depth = 10
  )

  return ($ResultObject | ConvertTo-Json -Depth $Depth)
}

Export-ModuleMember -Function `
  ConvertTo-ObjectArray, `
  Save-Json, `
  Save-Csv, `
  Get-V2ResultObject, `
  Write-ResultObject, `
  ConvertTo-V2Json
