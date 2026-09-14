<#
.SYNOPSIS
Configuration loading and merging utilities.

.DESCRIPTION
Provides functions to read JSON configuration files, merge them with built-in
defaults, and convert PSCustomObjects to hashtables.
#>

Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'JsonInput.psm1')

<#
.SYNOPSIS
Normalizes and optionally verifies a configuration path.
.DESCRIPTION
Expands environment variables and rejects traversal or invalid paths before
configuration input reaches the JSON reader.
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
  Creates the standard configuration result envelope.
.DESCRIPTION
  Preserves configuration and load metadata in the caller's requested shape.
#>
function New-ConfigReadResult {
  [CmdletBinding()]
  param(
    [AllowNull()][hashtable]$Config,
    [Parameter(Mandatory)][pscustomobject]$Meta,
    [switch]$AsHashtable,
    [switch]$NullConfig
  )

  if ($NullConfig) {
    return [pscustomobject]@{ Config = $null; Meta = $Meta }
  }

  $resultConfig = if ($AsHashtable) { $Config } else { [pscustomobject]$Config }
  return [pscustomobject]@{ Config = $resultConfig; Meta = $Meta }
}

<#
.SYNOPSIS
  Records and returns a configuration fallback result.
.DESCRIPTION
  Centralizes default-use metadata and optional warning emission.
#>
function Complete-ConfigFallback {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Config,
    [Parameter(Mandatory)][pscustomobject]$Meta,
    [Parameter(Mandatory)][string]$Reason,
    [AllowNull()][string]$ErrorMessage,
    [AllowNull()][string]$WarningMessage,
    [switch]$AsHashtable,
    [switch]$ReturnNull,
    [scriptblock]$OnWarning
  )

  $Meta.UsedDefaultsBecause = $Reason
  if (-not [string]::IsNullOrWhiteSpace($ErrorMessage)) {
    $Meta.Error = $ErrorMessage
  }
  if ($OnWarning -and -not [string]::IsNullOrWhiteSpace($WarningMessage)) {
    & $OnWarning $WarningMessage
  }
  return New-ConfigReadResult -Config $Config -Meta $Meta -AsHashtable:$AsHashtable -NullConfig:$ReturnNull
}

<#
.SYNOPSIS
  Merges permitted input values into configuration defaults.
.DESCRIPTION
  Retains only keys defined by the defaults to prevent unsupported settings.
#>
function Merge-ConfigValues {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Config,
    [Parameter(Mandatory)][hashtable]$Defaults,
    [Parameter(Mandatory)][object]$InputObject
  )

  $inputValues = ConvertTo-Hashtable -Object $InputObject
  if ($Defaults.Count -eq 0) {
    return $inputValues
  }
  foreach ($key in $inputValues.Keys) {
    if ($Defaults.ContainsKey($key)) {
      $Config[$key] = $inputValues[$key]
    }
  }
  return $Config
}

<#
.SYNOPSIS
  Creates configuration load metadata.
#>
function New-ConfigReadMetadata {
  [CmdletBinding()]
  param([AllowNull()][string]$Path)

  return [pscustomobject]@{
    Path                = $Path
    Provided            = [bool]$Path
    Loaded              = $false
    UsedDefaults        = $true
    UsedDefaultsBecause = $null
    Error               = $null
  }
}

<#
.SYNOPSIS
  Copies configuration defaults into a mutable hashtable.
#>
function Copy-ConfigDefaults {
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable]$Defaults)

  $config = @{}
  foreach ($key in $Defaults.Keys) { $config[$key] = $Defaults[$key] }
  return $config
}

<#
.SYNOPSIS
  Completes a fallback for an absent or invalid configuration path.
#>
function Complete-InvalidConfigPathFallback {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Config,
    [Parameter(Mandatory)][pscustomobject]$Meta,
    [AllowNull()][string]$Path,
    [switch]$AsHashtable,
    [switch]$ReturnNullWhenMissing,
    [scriptblock]$OnWarning
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    return Complete-ConfigFallback -Config $Config -Meta $Meta -Reason 'No ConfigPath provided.' `
      -AsHashtable:$AsHashtable -ReturnNull:$ReturnNullWhenMissing
  }
  return Complete-ConfigFallback -Config $Config -Meta $Meta `
    -Reason 'ConfigPath not found or invalid.' -ErrorMessage 'ConfigPath not found or invalid.' `
    -WarningMessage 'ConfigPath not found or invalid. Using defaults.' `
    -AsHashtable:$AsHashtable -ReturnNull:$ReturnNullWhenMissing -OnWarning $OnWarning
}

<#
.SYNOPSIS
  Completes a fallback for invalid JSON input.
#>
function Complete-InvalidConfigJsonFallback {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Config,
    [Parameter(Mandatory)][pscustomobject]$Meta,
    [Parameter(Mandatory)][pscustomobject]$JsonInput,
    [switch]$AsHashtable,
    [switch]$ReturnNullOnError,
    [scriptblock]$OnWarning
  )

  if ([string]::IsNullOrWhiteSpace($JsonInput.Text)) {
    return Complete-ConfigFallback -Config $Config -Meta $Meta `
      -Reason 'Config file is empty.' -ErrorMessage 'Config file is empty.' `
      -WarningMessage 'Config file is empty. Using defaults.' `
      -AsHashtable:$AsHashtable -ReturnNull:$ReturnNullOnError -OnWarning $OnWarning
  }
  if ($null -ne $JsonInput.ParseError) { throw $JsonInput.ParseError }
  if ($null -eq $JsonInput.Data) {
    return Complete-ConfigFallback -Config $Config -Meta $Meta `
      -Reason 'Config file invalid/unreadable JSON.' -ErrorMessage 'Config file invalid/unreadable JSON.' `
      -WarningMessage 'Config file invalid/unreadable JSON. Using defaults.' `
      -AsHashtable:$AsHashtable -ReturnNull:$ReturnNullOnError -OnWarning $OnWarning
  }
  return $null
}

<#
.SYNOPSIS
  Reads and merges JSON from a validated configuration path.
#>
function Read-SanitizedConfigWithDefaults {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][hashtable]$Config,
    [Parameter(Mandatory)][hashtable]$Defaults,
    [Parameter(Mandatory)][pscustomobject]$Meta,
    [switch]$AsHashtable,
    [switch]$ReturnNullOnError,
    [scriptblock]$OnWarning
  )

  try {
    $jsonInput = JsonInput\Read-BoundedUtf8JsonInput -Path $Path -MaximumBytes 1048576
    $fallback = Complete-InvalidConfigJsonFallback -Config $Config -Meta $Meta -JsonInput $jsonInput `
      -AsHashtable:$AsHashtable -ReturnNullOnError:$ReturnNullOnError -OnWarning $OnWarning
    if ($null -ne $fallback) { return $fallback }
    $Meta.Loaded = $true
    $Meta.UsedDefaults = $false
    $Meta.UsedDefaultsBecause = $null
    $config = Merge-ConfigValues -Config $Config -Defaults $Defaults -InputObject $jsonInput.Data
    return New-ConfigReadResult -Config $config -Meta $Meta -AsHashtable:$AsHashtable
  } catch {
    $warning = 'Config parse failed, using defaults.'
    if (-not [string]::IsNullOrWhiteSpace($Path)) { $warning += ' File: ' + (Split-Path -Leaf $Path) }
    return Complete-ConfigFallback -Config $Config -Meta $Meta -Reason 'Config parse failed.' `
      -ErrorMessage $_.Exception.Message -WarningMessage $warning `
      -AsHashtable:$AsHashtable -ReturnNull:$ReturnNullOnError -OnWarning $OnWarning
  }
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

  $meta = New-ConfigReadMetadata -Path $Path
  $config = Copy-ConfigDefaults -Defaults $Defaults

  $sanitized = if ([string]::IsNullOrWhiteSpace($Path)) { $null } else { Sanitize-ConfigPath -Path $Path -MustExist }
  if (-not $sanitized) {
    return Complete-InvalidConfigPathFallback -Config $config -Meta $meta -Path $Path `
      -AsHashtable:$AsHashtable -ReturnNullWhenMissing:$ReturnNullWhenMissing -OnWarning $OnWarning
  }

  return Read-SanitizedConfigWithDefaults -Path $sanitized -Config $config -Defaults $Defaults -Meta $meta `
    -AsHashtable:$AsHashtable -ReturnNullOnError:$ReturnNullOnError -OnWarning $OnWarning
}

Export-ModuleMember -Function ConvertTo-Hashtable,Read-ConfigWithDefaults
