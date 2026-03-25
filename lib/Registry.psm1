Set-StrictMode -Version Latest

<#
.SYNOPSIS
Windows Registry read/write helpers.

.DESCRIPTION
Provides type-safe functions for reading and writing registry values (DWord,
QWord, String, ExpandString, MultiString, Binary) with automatic key creation
and consistent error handling.
#>

<#
.SYNOPSIS
  Creates a registry key if it does not exist.
.PARAMETER Path
  Registry key path to create.
#>
function Ensure-RegistryKey {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -Path $Path -Force | Out-Null
  }
}

<#
.SYNOPSIS
  Reads a registry value, returning $null if the key or value does not exist.
.PARAMETER Path
  Registry key path.
.PARAMETER Name
  Value name to read.
#>
function Get-RegValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name
  )

  try {
    return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
  } catch {
    return $null
  }
}

<#
.SYNOPSIS
  Sets a REG_DWORD registry value, creating the key if needed.
.PARAMETER Path
  Registry key path.
.PARAMETER Name
  Value name.
.PARAMETER Value
  Integer value to write.
#>
function Set-RegDword {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][int]$Value,
    [string[]]$AllowedPrefixes
  )

  if ([string]::IsNullOrWhiteSpace($Name)) { throw "Registry value name cannot be empty." }
  if ($AllowedPrefixes -and -not ($AllowedPrefixes | Where-Object { $Path.StartsWith($_, 'OrdinalIgnoreCase') })) {
    throw "Registry path not in allowed prefixes"
  }

  try {
    Ensure-RegistryKey -Path $Path
    $null = New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType DWord -Value $Value -Force -ErrorAction Stop
    return $true
  } catch {
    Write-Error "Failed to set REG_DWORD '$Name' at '$Path': $($_.Exception.Message)"
    return $false
  }
}

<#
.SYNOPSIS
  Sets a REG_SZ registry value, creating the key if needed.
.PARAMETER Path
  Registry key path.
.PARAMETER Name
  Value name.
.PARAMETER Value
  String value to write.
#>
function Set-RegString {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Value,
    [string[]]$AllowedPrefixes
  )

  if ([string]::IsNullOrWhiteSpace($Name)) { throw "Registry value name cannot be empty." }
  if ($AllowedPrefixes -and -not ($AllowedPrefixes | Where-Object { $Path.StartsWith($_, 'OrdinalIgnoreCase') })) {
    throw "Registry path not in allowed prefixes"
  }

  try {
    Ensure-RegistryKey -Path $Path
    $null = New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType String -Value $Value -Force -ErrorAction Stop
    return $true
  } catch {
    Write-Error "Failed to set REG_SZ '$Name' at '$Path': $($_.Exception.Message)"
    return $false
  }
}

<#
.SYNOPSIS
  Removes a registry value if it exists. Returns $true if removed.
.PARAMETER Path
  Registry key path.
.PARAMETER Name
  Value name to remove.
#>
function Remove-RegValueIfExists {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name
  )

  if (-not (Test-Path -LiteralPath $Path)) { return $false }

  try {
    $props = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
    if ($null -ne $props.PSObject.Properties[$Name]) {
        Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $true
    }
  } catch {
    Write-Error "Failed to remove registry value '$Name' at '$Path': $($_.Exception.Message)"
  }

  return $false
}

<#
.SYNOPSIS
  Sets a REG_QWORD registry value, creating the key if needed.
.PARAMETER Path
  Registry key path.
.PARAMETER Name
  Value name.
.PARAMETER Value
  64-bit integer value to write.
#>
function Set-RegQword {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][int64]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Name)) { throw "Registry value name cannot be empty." }

  try {
    Ensure-RegistryKey -Path $Path
    $null = New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType QWord -Value $Value -Force -ErrorAction Stop
    return $true
  } catch {
    Write-Error "Failed to set REG_QWORD '$Name' at '$Path': $($_.Exception.Message)"
    return $false
  }
}

<#
.SYNOPSIS
  Sets a REG_EXPAND_SZ registry value, creating the key if needed.
.PARAMETER Path
  Registry key path.
.PARAMETER Name
  Value name.
.PARAMETER Value
  String value with expandable environment variables.
#>
function Set-RegExpandString {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Name)) { throw "Registry value name cannot be empty." }

  try {
    Ensure-RegistryKey -Path $Path
    $null = New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType ExpandString -Value $Value -Force -ErrorAction Stop
    return $true
  } catch {
    Write-Error "Failed to set REG_EXPAND_SZ '$Name' at '$Path': $($_.Exception.Message)"
    return $false
  }
}

<#
.SYNOPSIS
  Sets a REG_MULTI_SZ registry value, creating the key if needed.
.PARAMETER Path
  Registry key path.
.PARAMETER Name
  Value name.
.PARAMETER Value
  Array of strings to write.
#>
function Set-RegMultiString {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string[]]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Name)) { throw "Registry value name cannot be empty." }

  try {
    Ensure-RegistryKey -Path $Path
    $null = New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType MultiString -Value $Value -Force -ErrorAction Stop
    return $true
  } catch {
    Write-Error "Failed to set REG_MULTI_SZ '$Name' at '$Path': $($_.Exception.Message)"
    return $false
  }
}

<#
.SYNOPSIS
  Sets a REG_BINARY registry value, creating the key if needed.
.PARAMETER Path
  Registry key path.
.PARAMETER Name
  Value name.
.PARAMETER Value
  Byte array to write.
#>
function Set-RegBinary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][byte[]]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Name)) { throw "Registry value name cannot be empty." }

  try {
    Ensure-RegistryKey -Path $Path
    $null = New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType Binary -Value $Value -Force -ErrorAction Stop
    return $true
  } catch {
    Write-Error "Failed to set REG_BINARY '$Name' at '$Path': $($_.Exception.Message)"
    return $false
  }
}

<#
.SYNOPSIS
  Tests whether a registry key exists.
.PARAMETER Path
  Registry key path to check.
#>
function Get-RegKeyExists {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path
  )

  return (Test-Path -LiteralPath $Path)
}

<#
.SYNOPSIS
  Tests whether a registry value exists under a key.
.PARAMETER Path
  Registry key path.
.PARAMETER Name
  Value name to check.
#>
function Get-RegValueExists {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name
  )

  if (-not (Test-Path -LiteralPath $Path)) { return $false }

  try {
    $props = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
    return ($null -ne $props.PSObject.Properties[$Name])
  } catch {
    return $false
  }
}

<#
.SYNOPSIS
  Reads a REG_DWORD value, returning a default if not found.
.PARAMETER Path
  Registry key path.
.PARAMETER Name
  Value name.
.PARAMETER DefaultValue
  Value returned when the registry entry does not exist.
#>
function Get-RegDword {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [int]$DefaultValue = 0
  )

  $value = Get-RegValue -Path $Path -Name $Name
  if ($null -eq $value) { return $DefaultValue }
  
  try {
    return [int]$value
  } catch {
    return $DefaultValue
  }
}

<#
.SYNOPSIS
  Reads a REG_DWORD value, returning $null if not found.
.PARAMETER Path
  Registry key path.
.PARAMETER Name
  Value name.
#>
function Get-RegDwordOrNull {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name
  )
  $value = Get-RegValue -Path $Path -Name $Name
  if ($null -eq $value) { return $null }
  try {
    return [int]$value
  } catch {
    return $null
  }
}

<#
.SYNOPSIS
  Reads a REG_SZ value, returning a default if not found.
.PARAMETER Path
  Registry key path.
.PARAMETER Name
  Value name.
.PARAMETER DefaultValue
  Value returned when the registry entry does not exist.
#>
function Get-RegString {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [string]$DefaultValue = ''
  )

  $value = Get-RegValue -Path $Path -Name $Name
  if ($null -eq $value) { return $DefaultValue }
  
  return [string]$value
}

<#
.SYNOPSIS
  Removes a registry key if it exists. Returns $true if removed.
.PARAMETER Path
  Registry key path to remove.
.PARAMETER Recurse
  Remove the key and all subkeys.
#>
function Remove-RegistryKeyIfExists {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$Recurse
  )

  if (-not (Test-Path -LiteralPath $Path)) { return $false }

  try {
    if ($Recurse) {
      Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
    } else {
      Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    }
    return $true
  } catch {
    Write-Error "Failed to remove registry key '$Path': $($_.Exception.Message)"
    return $false
  }
}

Export-ModuleMember -Function `
  Ensure-RegistryKey, `
  Get-RegValue, `
  Set-RegDword, `
  Set-RegString, `
  Remove-RegValueIfExists, `
  Set-RegQword, `
  Set-RegExpandString, `
  Set-RegMultiString, `
  Set-RegBinary, `
  Get-RegKeyExists, `
  Get-RegValueExists, `
  Get-RegDword, `
  Get-RegDwordOrNull, `
  Get-RegString, `
  Remove-RegistryKeyIfExists
