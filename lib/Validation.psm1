Set-StrictMode -Version Latest

<#
.SYNOPSIS
Input validation and security guard functions.

.DESCRIPTION
Provides functions to detect path traversal, validate script names, git refs,
URLs, and directory containment. Used across scripts to enforce input safety.
#>

<#
.SYNOPSIS
  Tests whether a path contains traversal segments ('..').
.PARAMETER Path
  Path string to check.
#>
function Test-PathTraversal {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [string]$Path
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    return $false
  }

  $normalized = $Path -replace '/', '\\'
  if ($normalized -match '(^|\\)\.\.(\\|$)') { return $true }
  if ($normalized -match '\\.\\.\\') { return $true }
  return $false
}

<#
.SYNOPSIS
  Throws if a path contains traversal segments.
.PARAMETER Path
  Path string to validate.
.PARAMETER ParameterName
  Name shown in the error message (default 'Path').
#>
function Assert-NoPathTraversal {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Path,
    [string]$ParameterName = 'Path'
  )

  if (Test-PathTraversal -Path $Path) {
    throw "$ParameterName must not contain path traversal segments ('..')."
  }
}

<#
.SYNOPSIS
  Validates that a script name is safe (no path separators, valid .ps1 extension).
.PARAMETER Name
  Script file name to validate.
#>
function Test-SafeScriptName {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [string]$Name
  )

  if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
  if ($Name -match '[\\/]') { return $false }
  if (Test-PathTraversal -Path $Name) { return $false }
  if ($Name -match '[\x00-\x1F]') { return $false }
  if ($Name -match '[:*?"<>|]') { return $false }
  if ($Name -match '^\s|\s$') { return $false }
  $ext = [System.IO.Path]::GetExtension($Name)
  if ($ext -ne '.ps1') { return $false }
  if ($Name -match '^[.-]') { return $false }
  return $true
}

<#
.SYNOPSIS
  Validates that a string is a safe git ref (branch/tag name).
.PARAMETER Ref
  Git ref string to validate.
#>
function Test-ValidGitRef {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [string]$Ref
  )

  if ([string]::IsNullOrWhiteSpace($Ref)) { return $false }
  if ($Ref -match '^\s*-') { return $false }
  if ($Ref -match '\.\.') { return $false }
  if ($Ref -match '[~^:\?*\[\\]') { return $false }
  if ($Ref -match '@\{') { return $false }
  if ($Ref.EndsWith('.') -or $Ref.EndsWith('/') -or $Ref.EndsWith('.lock')) { return $false }
  return $true
}

<#
.SYNOPSIS
  Validates that a URL uses an allowed scheme and is well-formed.
.PARAMETER Url
  URL string to validate.
.PARAMETER AllowedSchemes
  Permitted URI schemes (default: https, http).
#>
function Test-SafeUrl {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [string]$Url,
    [string[]]$AllowedSchemes = @('https', 'http')
  )

  if ([string]::IsNullOrWhiteSpace($Url)) { return $false }
  if ($Url -match '^\s*-') { return $false }

  $uri = $null
  if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$uri)) {
    return $false
  }

  if (-not $AllowedSchemes -or $AllowedSchemes.Count -eq 0) {
    return $true
  }

  return ($AllowedSchemes -contains $uri.Scheme)
}

<#
.SYNOPSIS
  Tests whether a path is contained within a root directory.
.PARAMETER Path
  Path to check.
.PARAMETER Root
  Root directory that must be a prefix of Path.
#>
function Test-PathUnderRoot {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Path,
    [Parameter(Mandatory)]
    [string]$Root
  )

  try {
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    $rootFull = [System.IO.Path]::GetFullPath($Root)
  } catch {
    return $false
  }

  $sep = [System.IO.Path]::DirectorySeparatorChar
  $rootPrefix = $rootFull.TrimEnd($sep) + $sep
  return $pathFull.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)
}

Export-ModuleMember -Function `
  Test-PathTraversal, `
  Assert-NoPathTraversal, `
  Test-SafeScriptName, `
  Test-ValidGitRef, `
  Test-SafeUrl, `
  Test-PathUnderRoot
