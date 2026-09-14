#requires -version 5.1
<#
.SYNOPSIS
Private runtime helpers for 00-Run-Local.ps1.

.DESCRIPTION
Contains only helpers loaded after the entry script establishes its trusted source closure.
#>

function Write-RunLocalFailureResult {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Code,
    [Parameter(Mandatory)][string]$Message,
    [AllowNull()][string]$TargetPath
  )

  if (-not $PassThru) {
    throw $Message
  }

  $failureResult = Get-V2ResultObject `
    -ScriptName '00-Run-Local.ps1' `
    -Mode $Mode `
    -Result 'FAIL' `
    -Findings @([pscustomobject]@{ Code = $Code; Severity = 'High'; Message = $Message }) `
    -Summary ([pscustomobject]@{ Target = $TargetPath; Error = $Message }) `
    -Metadata @{}
  Write-ResultObject -ResultObject $failureResult -OutputFormat $OutputFormat -OutputPath $OutputPath
  $failureResult
}

function Test-ResolvedPathUnderScriptsRoot {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$ScriptsRootPath
  )

  # Resolve both sides before comparison so relative paths and symlinks cannot
  # escape the deployment scripts directory by string-shape tricks.
  try {
    $resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $resolvedRoot = (Resolve-Path -LiteralPath $ScriptsRootPath -ErrorAction Stop).Path
  } catch {
    return $false
  }

  $sepChars = @([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
  $rootPrefix = $resolvedRoot.TrimEnd($sepChars) + [System.IO.Path]::DirectorySeparatorChar
  return $resolvedPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-PathIsSymlink {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path
  )

  try {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  } catch {
    return $false
  }

  return [bool]($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
}

function Test-PathOrAncestorIsReparsePoint {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$ScriptsRootPath
  )

  # Resolve-Path alone is insufficient here: a junction within scriptsRoot can
  # still resolve to a path that looks in-bounds.  Inspect every component from
  # the root through the leaf before accepting the execution target.
  try {
    $rootFullPath = [System.IO.Path]::GetFullPath($ScriptsRootPath).TrimEnd(@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar))
    $currentPath = [System.IO.Path]::GetFullPath($Path)
    while ($true) {
      $item = Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop
      if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        return $true
      }

      if ([string]::Equals($currentPath, $rootFullPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $false
      }

      $parentPath = Split-Path -Parent $currentPath
      if ([string]::IsNullOrWhiteSpace($parentPath)) {
        return $true
      }
      $currentPath = $parentPath
    }
  } catch {
    # A path component disappearing during validation is not safe to execute.
    return $true
  }
}

function Add-RunLocalForwardedArguments {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][System.Collections.IDictionary]$NamedArguments,
    [Parameter(Mandatory)][System.Collections.IDictionary]$RunnerBoundParameters
  )

  $defaults = Get-RunLocalDefaultForwardedArguments -RunnerBoundParameters $RunnerBoundParameters
  foreach ($name in $defaults.Keys) {
    if (-not $NamedArguments.ContainsKey($name) -and $null -ne $defaults[$name]) {
      $NamedArguments[$name] = $defaults[$name]
    }
  }
}

function Get-RunLocalDefaultForwardedArguments {
  [CmdletBinding()]
  param([Parameter(Mandatory)][System.Collections.IDictionary]$RunnerBoundParameters)

  $defaults = @{ Mode = $Mode; ConfigPath = $null; Strict = $null; Quiet = $null; NoColor = $null }
  if ($RunnerBoundParameters.ContainsKey('ConfigPath')) { $defaults.ConfigPath = $ConfigPath }
  if ($Strict) { $defaults.Strict = $true }
  if ($Quiet) { $defaults.Quiet = $true }
  if ($NoColor) { $defaults.NoColor = $true }
  return $defaults
}

function Test-RunLocalV2ResultShape {
  [CmdletBinding()]
  [OutputType([bool])]
  param([AllowNull()]$InputObject)

  if ($null -eq $InputObject -or $InputObject -is [string] -or $InputObject -is [System.ValueType]) { return $false }
  $propertyNames = @($InputObject.PSObject.Properties.Name)
  foreach ($required in @('SchemaVersion','ScriptName','Mode','Result','Findings','Summary','Metadata')) {
    if ($propertyNames -notcontains $required) { return $false }
  }
  return $true
}

function Test-RunLocalV2ResultValues {
  [CmdletBinding()]
  [OutputType([bool])]
  param([Parameter(Mandatory)]$InputObject)

  if ([string]$InputObject.SchemaVersion -ne '2.0') { return $false }
  if ([string]::IsNullOrWhiteSpace([string]$InputObject.ScriptName)) { return $false }
  if (@('Audit','Remediate') -notcontains [string]$InputObject.Mode) { return $false }
  return (@('OK','WARN','FAIL') -contains [string]$InputObject.Result)
}

function Test-RunLocalV2ResultCollections {
  [CmdletBinding()]
  [OutputType([bool])]
  param([Parameter(Mandatory)]$InputObject)

  if (-not (Test-RunLocalV2Findings -InputObject $InputObject)) { return $false }
  return (Test-RunLocalV2Metadata -InputObject $InputObject)
}

function Test-RunLocalV2Findings {
  [CmdletBinding()]
  [OutputType([bool])]
  param([Parameter(Mandatory)]$InputObject)

  return ($null -ne $InputObject.Findings -and $InputObject.Findings -isnot [string] -and $InputObject.Findings -is [System.Collections.IEnumerable])
}

function Test-RunLocalV2Metadata {
  [CmdletBinding()]
  [OutputType([bool])]
  param([Parameter(Mandatory)]$InputObject)

  return ($null -ne $InputObject.Metadata -and $InputObject.Metadata -isnot [string] -and $InputObject.Metadata -isnot [System.ValueType] -and $InputObject.Metadata -isnot [System.Array])
}

function Test-RunLocalV2ResultObject {
  [CmdletBinding()]
  [OutputType([bool])]
  param([AllowNull()]$InputObject)

  if (-not (Test-RunLocalV2ResultShape -InputObject $InputObject)) { return $false }
  if (-not (Test-RunLocalV2ResultValues -InputObject $InputObject)) { return $false }
  return (Test-RunLocalV2ResultCollections -InputObject $InputObject)
}
