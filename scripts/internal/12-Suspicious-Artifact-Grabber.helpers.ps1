#requires -version 5.1
<#
.SYNOPSIS
  Provides private artifact collection phases.
.DESCRIPTION
  Preserves protected evidence paths, bounded observations, trigger decisions, and artifact proof ordering within this capability.
#>


function Add-Error([object]$res, [string]$msg) {
  if ($msg) {
    [void]$res.Errors.Add($msg)
  }
}
function Assert-ArtifactEvidenceOutputBase {
  [CmdletBinding()]
  [OutputType([string])]
  param([Parameter(Mandatory)][string]$OutputBase)

  if ([string]::IsNullOrWhiteSpace($OutputBase)) {
    throw 'Catalog.OutputBase must name the protected local evidence root.'
  }
  if ($OutputBase -match '^(\\\\|//|\\\\[?.]\\)') {
    throw "Catalog.OutputBase must not be a UNC, device, or remote path: $OutputBase"
  }
  Assert-NoPathTraversal -Path $OutputBase -ParameterName 'Catalog.OutputBase'

  $evidenceRoot = [System.IO.Path]::GetFullPath((Get-ArtifactEvidenceRoot))
  $candidateRoot = [System.IO.Path]::GetFullPath($OutputBase)
  $comparison = Get-ArtifactPathComparison
  if (-not $candidateRoot.Equals($evidenceRoot, $comparison)) {
    throw "Catalog.OutputBase is restricted to the protected local evidence root: $evidenceRoot"
  }
  if (-not (Ensure-Directory $evidenceRoot)) {
    throw "Unable to create protected local evidence root: $evidenceRoot"
  }
  if (Test-PathContainsReparsePoint -Path $evidenceRoot -Root $evidenceRoot) {
    throw "Protected local evidence root contains a reparse point: $evidenceRoot"
  }
  if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    Assert-TrustedWindowsPathAcl -Path $evidenceRoot -CheckAncestors | Out-Null
  }
  return $evidenceRoot
}
function Safe-ToBool {
  param([object]$Value, [bool]$Default = $false)
  try {
    if ($null -eq $Value) {
      return $Default
    }
    return [bool]$Value
  }
  catch {
    Write-Verbose ("Safe-ToBool fallback to default: {0}" -f $_.Exception.Message)
    return $Default
  }
}
function Get-RunId {
  "{0}-{1}" -f (Get-Date).ToString('yyyyMMdd-HHmmss'), [guid]::NewGuid().ToString('N')
}
function Get-PSObjectPropertyValue {
  param([object]$Obj, [string]$Name)
  try {
    if ($null -eq $Obj) {
      return $null
    }
    if ($Obj.PSObject.Properties.Name -contains $Name) {
      return $Obj.$Name
    }
  }
  catch {
    Write-Verbose ("Property access failed for '{0}': {1}" -f $Name, $_.Exception.Message)
  }
  return $null
}
function Safe-ToInt {
  param([object]$Value, [int]$Default = 0)
  try {
    if ($null -eq $Value) {
      return $Default
    }
    return [int]$Value
  }
  catch {
    Write-Verbose ("Safe-ToInt fallback to default: {0}" -f $_.Exception.Message)
    return $Default
  }
}
function Add-Note ([object]$res, [string]$msg) {
  if ($msg) {
    [void]$res.Notes.Add($msg)
  }
}
function Get-ArtifactEvidenceRoot {
  [CmdletBinding()]
  [OutputType([string])]
  param()

  if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    $programData = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)
    if ([string]::IsNullOrWhiteSpace($programData)) {
      $programData = $env:ProgramData
    }
    if ([string]::IsNullOrWhiteSpace($programData)) {
      throw 'Cannot resolve the local ProgramData evidence root.'
    }
    return (Join-Path $programData 'BaselineOpsForWindows\Evidence\IR-Grabber')
  }

  # Portable tests use one deterministic local root; Windows enforces the
  # protected ProgramData root and its ACL below.
  return (Join-Path ([System.IO.Path]::GetTempPath()) 'baselineops-windows-evidence')
}
function Get-ResultObject([string]$Name) {
  [pscustomobject]@{
    Name = $Name
    Counts = @{}
    Errors = (New-Object System.Collections.Generic.List[string])
    Notes = (New-Object System.Collections.Generic.List[string])
  }
}
function Get-ArtifactPathComparison {
  param()
  return $(if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
      [System.StringComparison]::OrdinalIgnoreCase
    }
    else {
      [System.StringComparison]::Ordinal
    })

}

. (Join-Path $PSScriptRoot '12-Suspicious-Artifact-Grabber.catalog.ps1')
. (Join-Path $PSScriptRoot '12-Suspicious-Artifact-Grabber.process.ps1')
. (Join-Path $PSScriptRoot '12-Suspicious-Artifact-Grabber.network.ps1')
. (Join-Path $PSScriptRoot '12-Suspicious-Artifact-Grabber.persistence.ps1')
. (Join-Path $PSScriptRoot '12-Suspicious-Artifact-Grabber.presentation.ps1')
. (Join-Path $PSScriptRoot '12-Suspicious-Artifact-Grabber.runtime.ps1')
. (Join-Path $PSScriptRoot '12-Suspicious-Artifact-Grabber.collection.ps1')
