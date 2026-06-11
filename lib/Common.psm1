Set-StrictMode -Version Latest

<#
.SYNOPSIS
Common utility functions shared across all scripts.

.DESCRIPTION
Provides general-purpose helpers for caller variable lookup, admin detection,
directory creation, path sanitization, and property existence checks.
#>

<#
.SYNOPSIS
  Retrieves a variable value from a caller scope.
.PARAMETER Name
  Variable name to look up in parent scopes.
#>
function Get-CallerValue {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Name)

  # Ambient variable contract for remaining callers:
  # - Output.psm1: Write-UiLine reads NoConsole, Quiet,
  #   UseWriteInformation, UseInformationStream, NoColor, and UseColor;
  #   Write-ConsoleLine reads NoConsole, Quiet, NoColor, and UseColor;
  #   Write-KeyValue reads UseWriteInformation and UseInformationStream.
  # - EventLog.psm1: Ensure-EventSource and Write-HealthEvent read
  #   EventSource and EventLogName. Deprecated EventSourceName/EventLog
  #   fallback reads warn before use.
  # TODO: Replace these hidden caller-scope contracts with explicit parameters.
  # Search scopes 1 through 3 (immediate caller up to 3 levels up).
  # Scope 1 = direct caller, 2 = caller's caller, 3 = one more level up.
  # Limitation: variables defined more than 3 scopes above will not be found.
  # This covers the common patterns: script -> module function -> helper.
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

<#
.SYNOPSIS
  Converts scalar or enumerable input into a mutable ArrayList.
.PARAMETER InputObject
  Object, array, or enumerable collection to copy into the ArrayList.
#>
function ConvertTo-ArrayList {
  [CmdletBinding()]
  param([AllowNull()][object]$InputObject)

  $list = [System.Collections.ArrayList]::new()
  if ($null -eq $InputObject) { return ,$list }

  if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
    foreach ($item in $InputObject) {
      [void]$list.Add($item)
    }
    return ,$list
  }

  [void]$list.Add($InputObject)
  return ,$list
}

<#
.SYNOPSIS
  Tests whether the current session is running with administrative privileges.
#>
function Test-IsAdmin {
  [CmdletBinding()]
  param()
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    # On non-Windows platforms (like Mac testing), [Security.Principal.WindowsIdentity] won't work.
    return $false
  }
}

<#
.SYNOPSIS
  Throws if the session is not elevated (Windows only).
.PARAMETER Message
  Error message shown when not running as admin.
#>
function Require-Admin {
  [CmdletBinding()]
  param(
    [string]$Message = 'Administrative privileges are required. Run the script elevated.'
  )
  if (-not (Test-IsAdmin)) {
    # $IsWindows automatic variable only exists in PS Core (6+).
    # PS Desktop (5.1) runs exclusively on Windows, so treat it as always-Windows.
    $isWindowsPlatform = if ($PSVersionTable.PSEdition -eq 'Core') { $IsWindows } else { $true }
    if ($isWindowsPlatform) {
      throw $Message
    } else {
      Write-Warning "Non-Windows OS detected; skipping administrative check for testing: $Message"
    }
  }
}

<#
.SYNOPSIS
  Creates a directory if it does not exist.
.PARAMETER Path
  Directory path to ensure exists.
#>
function Ensure-Directory {
  [OutputType([bool])]
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
  if ($Path -match '\.\.') {
    Write-Warning "Ensure-Directory: Path must not contain '..' (path traversal not allowed)."
    return $false
  }
  try {
    if (-not (Test-Path -LiteralPath $Path)) {
      $literalSafePath = [System.Management.Automation.WildcardPattern]::Escape($Path)
      New-Item -Path $literalSafePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    return $true
  } catch {
    Write-Error "Ensure-Directory: Failed to create '$Path': $($_.Exception.Message)"
    return $false
  }
}

<#
.SYNOPSIS
  Creates the parent directory for a file path if it does not exist.
.PARAMETER FilePath
  File path whose parent directory should be ensured.
#>
function Ensure-DirectoryForFile {
  [OutputType([bool])]
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyString()][string]$FilePath)

  $dir = Split-Path -Path $FilePath -Parent
  if ([string]::IsNullOrWhiteSpace($dir)) { return $false }
  return (Ensure-Directory -Path $dir)
}

<#
.SYNOPSIS
  Expands environment variables and normalizes a path, rejecting traversal.
.PARAMETER Path
  Raw path string to sanitize.
.PARAMETER MustExist
  When set, returns $null if the resolved path does not exist on disk.
#>
function Sanitize-Path {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$MustExist
  )

  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

  try {
    # Expand environment variables first
    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    if ([string]::IsNullOrWhiteSpace($expanded)) { return $null }

    # Reject any path containing ".." to prevent traversal (covers "..\", "../", "....\", leading "\..", etc.)
    if ($expanded -match '\.\.') {
      Write-Warning "Path traversal not allowed (contains '..'): path rejected."
      return $null
    }

    if ($MustExist) {
      if (Test-Path -LiteralPath $expanded) {
        $resolved = [System.IO.Path]::GetFullPath($expanded)
        if ($resolved -match '\.\.') { return $null }
        return $resolved
      }
      return $null
    }

    # Normalize and resolve full path; GetFullPath can throw on invalid chars
    return [System.IO.Path]::GetFullPath($expanded)
  } catch {
    Write-Verbose ("Path sanitization failed for '{0}': {1}" -f $Path,$_.Exception.Message)
    return $null
  }
}

<#
.SYNOPSIS
  Tests whether an object has a named property.
.PARAMETER Object
  Object to inspect.
.PARAMETER Name
  Property name to check for.
#>
function Has-Property {
  param([object]$Object, [string]$Name)
  return $null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name
}

<#
.SYNOPSIS
  Replaces characters that are invalid in file names with underscores.
.PARAMETER Name
  The candidate file name to sanitize.
#>
function Get-SafeFileName {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Name)
  return ($Name -replace '[<>:"/\\|?*\x00-\x1F]', '_')
}

Export-ModuleMember -Function `
  Get-CallerValue, `
  ConvertTo-ArrayList, `
  Test-IsAdmin, `
  Require-Admin, `
  Ensure-Directory, `
  Ensure-DirectoryForFile, `
  Sanitize-Path, `
  Has-Property, `
  Get-SafeFileName
