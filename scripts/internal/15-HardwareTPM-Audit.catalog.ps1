#requires -version 5.1
<#
.SYNOPSIS
  Provides private hardware compliance audit phases.
.DESCRIPTION
  Keeps hardware observations, policy decisions, proof output, and failure classification local to the hardware capability.
#>

function Add-ListItem {
  param([Parameter(Mandatory = $true)][ref]$List, [Parameter(Mandatory = $true)][string]$Text)
  if ($Text) {
    [void]$List.Value.Add($Text)
  }
}

function ConvertFrom-JsonSafe {
  param([Parameter(Mandatory = $true)][string]$JsonText)
  try {
    return ($JsonText | ConvertFrom-Json)
  }
  catch {
    return $null
  }
}

function Get-DefaultCatalog {
  param([string]$DefaultOutFile)
  # Always available defaults (no JSON dependency).
  return (New-Object PSObject -Property @{
      TPM = (New-Object PSObject -Property @{
          MinVersion = '2.0'
          OwnerRequired = $true
          PCRsRequired = @(7)
          AllowFirmware = $false
          BitLockerRequired = $true
          SecureBootRequired = $true
        })
      Proof = (New-Object PSObject -Property @{
          OutFile = $DefaultOutFile
        })
    })
}

function Merge-CatalogWithDefaults {
  param([Parameter(Mandatory = $true)]$Catalog, [Parameter(Mandatory = $true)]$Defaults)

  if (-not $Catalog) {
    return $Defaults
  }

  if (-not $Catalog.TPM) {
    $Catalog | Add-Member -NotePropertyName TPM   -NotePropertyValue (New-Object PSObject)
  }
  if (-not $Catalog.Proof) {
    $Catalog | Add-Member -NotePropertyName Proof -NotePropertyValue (New-Object PSObject)
  }

  Merge-HardwareTpmDefaults -Catalog $Catalog -Defaults $Defaults

  if (-not $Catalog.Proof.OutFile) {
    $Catalog.Proof | Add-Member -NotePropertyName OutFile -NotePropertyValue $Defaults.Proof.OutFile
  }

  return $Catalog
}

function Load-Catalog {
  param([string]$CatalogPath, [string]$ConfigPath, [string]$DefaultOutFile)

  $defaults = Get-DefaultCatalog -DefaultOutFile $DefaultOutFile

  # 1) Explicit catalog
  if ($CatalogPath -and (Test-Path -LiteralPath $CatalogPath)) {
    $raw = Get-BoundedUtf8FileContent -Path $CatalogPath -MaximumBytes 1048576 -ErrorAction SilentlyContinue
    if ($raw) {
      $obj = ConvertFrom-JsonSafe -JsonText $raw
      if ($obj) {
        return (Merge-CatalogWithDefaults -Catalog $obj -Defaults $defaults)
      }
    }
  }

  $configured = Read-HardwareConfiguredCatalog -ConfigPath $ConfigPath -Defaults $defaults
  if ($configured) {
    return $configured
  }

  return $defaults
}

function Test-TpmMinVersion {
  param([Parameter(Mandatory = $true)][string]$SpecVersion, [Parameter(Mandatory = $true)][string]$MinVersion)
  # SpecVersion may contain multiple values like "2.0,1.2".
  return ($SpecVersion -match "(^|,)\s*$([regex]::Escape($MinVersion))(\s*|,|$)")
}

function Invoke-TpmBoolMethod {
  param(
    [Parameter(Mandatory = $true)]$Tpm,
    [Parameter(Mandatory = $true)][string]$MethodName,
    [Parameter(Mandatory = $true)][string]$ReturnPropertyName
  )
  try {
    $r = Invoke-CimMethod -InputObject $Tpm -MethodName $MethodName -ErrorAction Stop
    if ($r -and ($r.PSObject.Properties.Name -contains $ReturnPropertyName)) {
      return [bool]$r.$ReturnPropertyName
    }
    return $null
  }
  catch {
    return $null
  }
}

function Get-CimPropValue {
  param([Parameter(Mandatory = $true)]$Object, [Parameter(Mandatory = $true)][string]$Name)
  if ($null -eq $Object) {
    return $null
  }
  if ($Object.PSObject.Properties.Name -contains $Name) {
    return $Object.$Name
  }
  return $null
}


function Merge-HardwareTpmDefaults {
  param($Catalog, $Defaults)
  if (-not $Catalog.TPM.MinVersion) {
    $Catalog.TPM | Add-Member -NotePropertyName MinVersion         -NotePropertyValue $Defaults.TPM.MinVersion
  }
  if ($null -eq $Catalog.TPM.OwnerRequired) {
    $Catalog.TPM | Add-Member -NotePropertyName OwnerRequired      -NotePropertyValue $Defaults.TPM.OwnerRequired
  }
  if ($null -eq $Catalog.TPM.PCRsRequired) {
    $Catalog.TPM | Add-Member -NotePropertyName PCRsRequired       -NotePropertyValue $Defaults.TPM.PCRsRequired
  }
  if ($null -eq $Catalog.TPM.AllowFirmware) {
    $Catalog.TPM | Add-Member -NotePropertyName AllowFirmware      -NotePropertyValue $Defaults.TPM.AllowFirmware
  }
  if ($null -eq $Catalog.TPM.BitLockerRequired) {
    $Catalog.TPM | Add-Member -NotePropertyName BitLockerRequired  -NotePropertyValue $Defaults.TPM.BitLockerRequired
  }
  if ($null -eq $Catalog.TPM.SecureBootRequired) {
    $Catalog.TPM | Add-Member -NotePropertyName SecureBootRequired -NotePropertyValue $Defaults.TPM.SecureBootRequired
  }

}

function Read-HardwareConfiguredCatalog {
  param([string]$ConfigPath, $Defaults)
  # 2) Config -> Hardware.CatalogPath
  if ($ConfigPath -and (Test-Path -LiteralPath $ConfigPath)) {
    $rawCfg = Get-BoundedUtf8FileContent -Path $ConfigPath -MaximumBytes 1048576 -ErrorAction SilentlyContinue
    if ($rawCfg) {
      $cfg = ConvertFrom-JsonSafe -JsonText $rawCfg
      if ($cfg -and $cfg.Hardware -and $cfg.Hardware.CatalogPath) {
        return (Read-HardwareReferencedCatalog -Path ([string]$cfg.Hardware.CatalogPath) -Defaults $Defaults)
      }
    }
  }
}

function Read-HardwareReferencedCatalog {
  param([string]$Path, $Defaults)
  $p = $Path
  if ($p -and (Test-Path -LiteralPath $p)) {
    $raw2 = Get-BoundedUtf8FileContent -Path $p -MaximumBytes 1048576 -ErrorAction SilentlyContinue
    if ($raw2) {
      $obj2 = ConvertFrom-JsonSafe -JsonText $raw2
      if ($obj2) {
        return (Merge-CatalogWithDefaults -Catalog $obj2 -Defaults $defaults)
      }
    }
  }
}
