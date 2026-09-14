<#
.SYNOPSIS
Private value and result helpers for the client security baseline report.

.DESCRIPTION
Normalizes registry and display values and appends report rows for capability 42.
#>

function Test-RegKey {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)
  try { Test-Path -Path $Path } catch { $false }
}

function ConvertTo-ScalarString {
  [CmdletBinding()]
  param([object]$Value)

  if ($null -eq $Value) { return $null }
  if ($Value -is [System.Array]) { return ($Value | ForEach-Object { $_.ToString() }) -join ',' }
  return $Value.ToString()
}

function ConvertTo-DisplayString {
  [CmdletBinding()]
  param([object]$Value)

  $s = ConvertTo-ScalarString -Value $Value
  if ([string]::IsNullOrWhiteSpace($s)) { return '<not set>' }
  return $s
}

function Get-ObjectList {
  # Strong list internally, but do NOT expose as typed parameter to avoid empty-collection binding issues.
  New-Object 'System.Collections.Generic.List[object]'
}

function Add-Row {
  [CmdletBinding()]
  param(
    # Accept as object to avoid PowerShell "empty collection" parameter binding pitfalls with generic lists.
    [Parameter(Mandatory)]
    [object]$List,

    [Parameter(Mandatory)]
    [hashtable]$Data
  )

  if ($null -eq $List) { throw "Add-Row: List is null." }

  $row = [pscustomobject]$Data
  $row.PSObject.TypeNames.Insert(0, 'BaselineReport.Row')

  # Support both List[T] and arraylist-like types
  if ($List -is [System.Collections.IList]) {
    [void]$List.Add($row)
    return
  }

  throw ("Add-Row: Unsupported list type: {0}" -f $List.GetType().FullName)
}
