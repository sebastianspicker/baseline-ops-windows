Set-StrictMode -Version Latest

function Ensure-RegistryKey {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -Path $Path -Force | Out-Null
  }
}

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

function Get-RegValueSafe {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name
  )

  return (Get-RegValue -Path $Path -Name $Name)
}

function Set-RegDword {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][int]$Value
  )

  Ensure-RegistryKey -Path $Path
  New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

function Remove-RegValueIfExists {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name
  )

  if (-not (Test-Path -LiteralPath $Path)) { return $false }

  $props = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
  if ($null -ne $props.PSObject.Properties[$Name]) {
    Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
    return $true
  }

  return $false
}

Export-ModuleMember -Function Ensure-RegistryKey,Get-RegValue,Get-RegValueSafe,Set-RegDword,Remove-RegValueIfExists
