Set-StrictMode -Version Latest

<#
.SYNOPSIS
Configuration loading and merging utilities.

.DESCRIPTION
Provides functions to read JSON configuration files, merge them with built-in
defaults, and convert PSCustomObjects to hashtables.
#>

function Sanitize-ConfigPath {
  [CmdletBinding()]
  param(
    [string]$Path,
    [switch]$MustExist
  )

  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

  try {
    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    if ([string]::IsNullOrWhiteSpace($expanded) -or $expanded -match '\.\.') { return $null }
    if ($MustExist -and -not (Test-Path -LiteralPath $expanded)) { return $null }
    return [System.IO.Path]::GetFullPath($expanded)
  } catch {
    return $null
  }
}

<#
.SYNOPSIS
  Converts a PSCustomObject to a hashtable.
.PARAMETER Object
  Object to convert. Returns an empty hashtable if null.
#>
function ConvertTo-Hashtable {
  [CmdletBinding()]
  param([object]$Object)

  if ($null -eq $Object) { return @{} }
  if ($Object -is [hashtable]) { return $Object }

  $ht = @{}
  foreach ($p in $Object.PSObject.Properties) {
    $ht[$p.Name] = $p.Value
  }
  return $ht
}

<#
.SYNOPSIS
  Reads a JSON config file and merges with default values.
.PARAMETER Path
  Path to the JSON configuration file.
.PARAMETER Defaults
  Hashtable of default values to use when config keys are missing.
.PARAMETER AsHashtable
  Return the merged config as a hashtable instead of PSCustomObject.
.PARAMETER ReturnNullWhenMissing
  Return null Config property when the file is not found.
.PARAMETER ReturnNullOnError
  Return null Config property on parse errors instead of using defaults.
.PARAMETER OnWarning
  Scriptblock invoked with a warning message when fallback occurs.
#>
function Read-ConfigWithDefaults {
  [CmdletBinding()]
  param(
    [AllowNull()][string]$Path,
    [hashtable]$Defaults = @{},
    [switch]$AsHashtable,
    [switch]$ReturnNullWhenMissing,
    [switch]$ReturnNullOnError,
    [scriptblock]$OnWarning
  )

  if ($null -eq $Defaults) { $Defaults = @{} }

  $meta = [pscustomobject]@{
    Path               = $Path
    Provided           = [bool]$Path
    Loaded             = $false
    UsedDefaults       = $true
    UsedDefaultsBecause= $null
    Error              = $null
  }

  $config = @{}
  foreach ($k in $Defaults.Keys) { $config[$k] = $Defaults[$k] }

  $sanitized = if ([string]::IsNullOrWhiteSpace($Path)) { $null } else { Sanitize-ConfigPath -Path $Path -MustExist }
  if (-not $sanitized) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        $meta.UsedDefaultsBecause = 'No ConfigPath provided.'
    } else {
        $meta.Error = 'ConfigPath not found or invalid.'
        $meta.UsedDefaultsBecause = $meta.Error
        if ($OnWarning) { & $OnWarning ($meta.Error + ' Using defaults.') }
    }
    if ($ReturnNullWhenMissing) {
      return [pscustomobject]@{ Config = $null; Meta = $meta }
    }
    $resultConfig = if ($AsHashtable) { $config } else { [pscustomobject]$config }
    return [pscustomobject]@{ Config = $resultConfig; Meta = $meta }
  }

  $Path = $sanitized # Use sanitized path for Get-Content

  try {
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) {
      $meta.Error = 'Config file is empty.'
      $meta.UsedDefaultsBecause = $meta.Error
      if ($OnWarning) { & $OnWarning ($meta.Error + ' Using defaults.') }
      if ($ReturnNullOnError) {
        return [pscustomobject]@{ Config = $null; Meta = $meta }
      }
      $resultConfig = if ($AsHashtable) { $config } else { [pscustomobject]$config }
      return [pscustomobject]@{ Config = $resultConfig; Meta = $meta }
    }

    $obj = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $obj) {
      $meta.Error = 'Config file invalid/unreadable JSON.'
      $meta.UsedDefaultsBecause = $meta.Error
      if ($OnWarning) { & $OnWarning ($meta.Error + ' Using defaults.') }
      if ($ReturnNullOnError) {
        return [pscustomobject]@{ Config = $null; Meta = $meta }
      }
      $resultConfig = if ($AsHashtable) { $config } else { [pscustomobject]$config }
      return [pscustomobject]@{ Config = $resultConfig; Meta = $meta }
    }

    $meta.Loaded = $true
    $meta.UsedDefaults = $false
    $meta.UsedDefaultsBecause = $null

    $objHash = ConvertTo-Hashtable -Object $obj
    # Only accept keys that exist in $Defaults to prevent config key injection
    if ($Defaults.Count -eq 0) {
      $config = $objHash
    } else {
      foreach ($k in $objHash.Keys) {
        if ($Defaults.ContainsKey($k)) { $config[$k] = $objHash[$k] }
      }
    }

    $resultConfig = if ($AsHashtable) { $config } else { [pscustomobject]$config }
    return [pscustomobject]@{ Config = $resultConfig; Meta = $meta }
  } catch {
    $meta.Error = $_.Exception.Message
    $meta.UsedDefaultsBecause = 'Config parse failed.'
    if ($OnWarning) {
      $msg = 'Config parse failed, using defaults.'
      if (-not [string]::IsNullOrWhiteSpace($Path)) { $msg += ' File: ' + (Split-Path -Leaf $Path) }
      & $OnWarning $msg
    }
    if ($ReturnNullOnError) {
      return [pscustomobject]@{ Config = $null; Meta = $meta }
    }
    $resultConfig = if ($AsHashtable) { $config } else { [pscustomobject]$config }
    return [pscustomobject]@{ Config = $resultConfig; Meta = $meta }
  }
}

Export-ModuleMember -Function ConvertTo-Hashtable,Read-ConfigWithDefaults
