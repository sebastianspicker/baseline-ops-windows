<#
.SYNOPSIS
Safe JSON reading helper.

.DESCRIPTION
Provides safe JSON file reading that returns $null on any error.
For JSON writing, use Save-Json from Serialization.psm1.
#>

Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Validation.psm1')

<#
.SYNOPSIS
  Reads and parses a JSON file with explicit load status.
.PARAMETER Path
  Path to the JSON file to read.
#>
function Read-JsonFileWithStatus {
  [CmdletBinding()]
  param(
    [AllowNull()][string]$Path
  )

  $meta = [pscustomobject]@{
    Path     = $Path
    Provided = -not [string]::IsNullOrWhiteSpace($Path)
    Loaded   = $false
    Status   = 'NotProvided'
    Error    = $null
  }

  if ([string]::IsNullOrWhiteSpace($Path)) {
    return [pscustomobject]@{ Data = $null; Meta = $meta }
  }

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    $meta.Status = 'Missing'
    $meta.Error = 'JSON file was not found.'
    return [pscustomobject]@{ Data = $null; Meta = $meta }
  }

  try {
    $raw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
  } catch {
    $meta.Status = 'Unreadable'
    $meta.Error = $_.Exception.Message
    return [pscustomobject]@{ Data = $null; Meta = $meta }
  }

  if ([string]::IsNullOrWhiteSpace($raw)) {
    $meta.Status = 'Empty'
    $meta.Error = 'JSON file is empty.'
    return [pscustomobject]@{ Data = $null; Meta = $meta }
  }

  try {
    $data = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $data) {
      $meta.Status = 'Invalid'
      $meta.Error = 'JSON did not produce a configuration object.'
      return [pscustomobject]@{ Data = $null; Meta = $meta }
    }
    $meta.Loaded = $true
    $meta.Status = 'Loaded'
    return [pscustomobject]@{ Data = $data; Meta = $meta }
  } catch {
    $meta.Status = 'Invalid'
    $meta.Error = $_.Exception.Message
    return [pscustomobject]@{ Data = $null; Meta = $meta }
  }
}

<#
.SYNOPSIS
  Reads and parses a JSON file, returning $null on any error.
.PARAMETER Path
  Path to the JSON file to read.
#>
function Read-JsonFileSafe {
  [CmdletBinding()]
  param(
    [string]$Path
  )

  (Read-JsonFileWithStatus -Path $Path).Data
}

Export-ModuleMember -Function Read-JsonFileSafe,Read-JsonFileWithStatus
