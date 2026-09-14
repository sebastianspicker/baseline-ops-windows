#requires -version 5.1
<#
.SYNOPSIS
Provides private Windows Update for Business policy helpers.
.DESCRIPTION
Loads trusted catalog data and performs individual registry policy operations for the public proofing capability.
#>

function Get-REG {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name
  )
  try { (Get-ItemProperty -Path $Path -ErrorAction Stop).$Name } catch { $null }
}

function Set-WufbDword {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][int]$Value,
    [switch]$Remediate
  )

  $cur = Get-REG -Path $Path -Name $Name

  if ($cur -eq $Value) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$false; Message=$null; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='None' }
  }

  if (-not $Remediate) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$true; Message="$Path\$Name drift ($cur != $Value)"; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='Detect' }
  }

  if (-not $PSCmdlet.ShouldProcess("$Path\$Name", "Set DWORD value")) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$true; Message="Skipped setting $Path\$Name due to confirmation/WhatIf."; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='Skipped' }
  }

  try {
    Ensure-RegistryKey -Path $Path
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
    return [pscustomobject]@{ Ok=$true; Changed=$true; Drift=$false; Message="Set $Path\$Name=$Value"; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='SetDword' }
  } catch {
    return [pscustomobject]@{ Ok=$false; Changed=$false; Drift=$false; Message="Set $Path\$Name failed: $($_.Exception.Message)"; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='Error' }
  }
}

function Set-REGSZ {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Value,
    [switch]$Remediate
  )

  $cur = Get-REG -Path $Path -Name $Name

  if ($cur -eq $Value) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$false; Message=$null; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='None' }
  }

  if (-not $Remediate) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$true; Message="$Path\$Name drift ($cur != '$Value')"; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='Detect' }
  }

  if (-not $PSCmdlet.ShouldProcess("$Path\$Name", "Set string value")) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$true; Message="Skipped setting $Path\$Name due to confirmation/WhatIf."; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='Skipped' }
  }

  try {
    Ensure-RegistryKey -Path $Path
    New-ItemProperty -Path $Path -Name $Name -PropertyType String -Value $Value -Force | Out-Null
    return [pscustomobject]@{ Ok=$true; Changed=$true; Drift=$false; Message="Set $Path\$Name='$Value'"; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='SetString' }
  } catch {
    return [pscustomobject]@{ Ok=$false; Changed=$false; Drift=$false; Message="Set $Path\$Name failed: $($_.Exception.Message)"; Path=$Path; Name=$Name; Current=$cur; Desired=$Value; Action='Error' }
  }
}

function Remove-REGValue {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [switch]$Remediate
  )

  $cur = Get-REG -Path $Path -Name $Name

  if ($null -eq $cur) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$false; Message=$null; Path=$Path; Name=$Name; Current=$cur; Desired=$null; Action='None' }
  }

  if (-not $Remediate) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$true; Message="$Path\$Name should be absent, but is present ($cur)"; Path=$Path; Name=$Name; Current=$cur; Desired=$null; Action='Detect' }
  }

  if (-not $PSCmdlet.ShouldProcess("$Path\$Name", "Remove registry value")) {
    return [pscustomobject]@{ Ok=$true; Changed=$false; Drift=$true; Message="Skipped removing $Path\$Name due to confirmation/WhatIf."; Path=$Path; Name=$Name; Current=$cur; Desired=$null; Action='Skipped' }
  }

  try {
    Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop
    return [pscustomobject]@{ Ok=$true; Changed=$true; Drift=$false; Message="Removed $Path\$Name"; Path=$Path; Name=$Name; Current=$cur; Desired=$null; Action='RemoveValue' }
  } catch {
    return [pscustomobject]@{ Ok=$false; Changed=$false; Drift=$false; Message="Remove $Path\$Name failed: $($_.Exception.Message)"; Path=$Path; Name=$Name; Current=$cur; Desired=$null; Action='Error' }
  }
}

# Save-JsonNoBom: replaced by canonical Save-Json from lib/Serialization.psm1

function Add-Result {
  [CmdletBinding()]
  param([Parameter(Mandatory)][pscustomobject]$Result, [Parameter(Mandatory)]$RunState)

  $RunState.Operations.Add($Result) | Out-Null
  if ($Result.Message -and $Result.Changed) { $RunState.Changes.Add($Result.Message) | Out-Null }
  if ($Result.Message -and $Result.Drift) { $RunState.Drifts.Add($Result.Message) | Out-Null }
  if (-not $Result.Ok) { $RunState.Ok = $false }
}

# -----------------------------
# Catalog defaults + loader
# -----------------------------

function Get-WufbTrustedDataRoot {
  $root = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { $root = [IO.Path]::GetTempPath() }
  if ([string]::IsNullOrWhiteSpace($root)) { throw 'CommonApplicationData could not be resolved.' }
  return [IO.Path]::GetFullPath($root)
}

function Get-DefaultCatalog {
  [CmdletBinding()]
  param()

  $defaultProof = Join-Path (Get-WufbTrustedDataRoot) 'WUfB-Proofing\proof.json'

  return [pscustomobject]@{
    UpdateSource = 'WUfB'
    WSUS = [pscustomobject]@{ WUServer = $null; WUStatusServer = $null }
    AllowMU = $true
    Deferrals = [pscustomobject]@{ FeatureDays = 30; QualityDays = 7 }
    TargetRelease = [pscustomobject]@{ Enable = $false; ProductVersion = 'Windows 11'; TargetReleaseVersionInfo = '24H2' }
    ActiveHours = [pscustomobject]@{ Enable = $true; Start = 8; End = 18 }
    DeliveryOptimization = [pscustomobject]@{ DownloadMode = 0 }
    Proof = [pscustomobject]@{ OutFile = $defaultProof }
  }
}

function Read-WufbCatalogFile {
  [CmdletBinding()]
  param([string]$Path, [string]$SuccessNote, [string]$NotFoundNote, [string]$InvalidNote, $Default, [System.Collections.Generic.List[string]]$Notes)

  if (-not (Test-Path -LiteralPath $Path)) {
    $Notes.Add($NotFoundNote) | Out-Null
    return $Default
  }
  try {
    $catalog = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576 | ConvertFrom-Json -ErrorAction Stop
    $Notes.Add($SuccessNote) | Out-Null
    return $catalog
  }
  catch {
    $Notes.Add(($InvalidNote -f $_.Exception.Message)) | Out-Null
    return $Default
  }
}

function Get-WufbReferencedCatalogPath {
  [CmdletBinding()]
  param([string]$ConfigPath, [System.Collections.Generic.List[string]]$Notes)

  if (-not $ConfigPath -or -not (Test-Path -LiteralPath $ConfigPath)) {
    return [pscustomobject]@{ Path = $null; Invalid = $false }
  }
  try {
    $config = Get-BoundedUtf8FileContent -Path $ConfigPath -MaximumBytes 1048576 | ConvertFrom-Json -ErrorAction Stop
    $path = $(if ($config -and $config.WUfB -and $config.WUfB.CatalogPath) { [string]$config.WUfB.CatalogPath } else { $null })
    return [pscustomobject]@{ Path = $path; Invalid = $false }
  }
  catch {
    $Notes.Add(('ConfigPath JSON invalid. Using defaults. Error: {0}' -f $_.Exception.Message)) | Out-Null
    return [pscustomobject]@{ Path = $null; Invalid = $true }
  }
}

function Load-Catalog {
  [CmdletBinding()]
  param([string]$CatalogPath, [string]$ConfigPath, [System.Collections.Generic.List[string]]$Notes)

  $default = Get-DefaultCatalog
  if ($CatalogPath) {
    return Read-WufbCatalogFile -Path $CatalogPath -SuccessNote 'Catalog loaded from CatalogPath.' `
      -NotFoundNote 'CatalogPath not found. Using defaults.' -InvalidNote 'CatalogPath JSON invalid. Using defaults. Error: {0}' -Default $default -Notes $Notes
  }
  $reference = Get-WufbReferencedCatalogPath -ConfigPath $ConfigPath -Notes $Notes
  if ($reference.Invalid) { return $default }
  if ($reference.Path) {
    return Read-WufbCatalogFile -Path $reference.Path -SuccessNote 'Catalog loaded from ConfigPath reference.' `
      -NotFoundNote 'Referenced catalog path not found. Using defaults.' -InvalidNote 'Referenced catalog JSON invalid. Using defaults. Error: {0}' -Default $default -Notes $Notes
  }
  $Notes.Add('No catalog/config provided. Using defaults.') | Out-Null
  return $default
}

function Get-OsEvidence {
  [CmdletBinding()]
  param()

  $osKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $osProps = Get-ItemProperty -Path $osKey -ErrorAction SilentlyContinue

  return @{
    Product        = $osProps.ProductName
    DisplayVersion = $osProps.DisplayVersion
    Build          = $osProps.CurrentBuild
    UBR            = $osProps.UBR
  }
}

function Get-SafeProofPath {
  [CmdletBinding()]
  param([string]$Candidate)

  $fallback = Join-Path (Get-WufbTrustedDataRoot) 'WUfB-Proofing\proof.json'
  if ([string]::IsNullOrWhiteSpace($Candidate)) { return $fallback }

  try {
    $full = [System.IO.Path]::GetFullPath($Candidate)
    $parent = Split-Path -Parent $full
    if ([string]::IsNullOrWhiteSpace($parent)) { return $fallback }
    return $full
  } catch {
    return $fallback
  }
}

function Get-FirstErrorNote {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$ErrorRecord)

  $msg = $ErrorRecord.Exception.Message
  $line = $null
  try { $line = $ErrorRecord.InvocationInfo.ScriptLineNumber } catch { $line = $null }

  if ($line) { return ("Unhandled error: {0} (Line {1})" -f $msg, $line) }
  return ("Unhandled error: {0}" -f $msg)
}
