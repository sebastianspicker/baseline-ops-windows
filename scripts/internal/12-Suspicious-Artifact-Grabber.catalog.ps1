#requires -version 5.1
<#
.SYNOPSIS
  Provides private artifact collection phases.
.DESCRIPTION
  Preserves protected evidence paths, bounded observations, trigger decisions, and artifact proof ordering within this capability.
#>


function Get-BaseClone {
  param([object]$Obj)
  # JSON roundtrip clone to avoid accidental cross-run mutation
  return ($Obj | ConvertTo-Json -Depth 30 | ConvertFrom-Json)
}
function New-ArtifactRegex {
  param([Parameter(Mandatory)][string]$Pattern, [Parameter(Mandatory)][string]$Label)
  if ($Pattern.Length -gt 1024) {
    throw "Grabber $Label regex exceeds the 1024-character limit."
  }
  try {
    New-Object System.Text.RegularExpressions.Regex($Pattern, [System.Text.RegularExpressions.RegexOptions]::CultureInvariant, ([TimeSpan]::FromMilliseconds(250)))
  }
  catch {
    throw "Grabber $Label regex is invalid: $($_.Exception.Message)"
  }
}
function Initialize-ArtifactRegexRules {
  param([Parameter(Mandatory)]$Catalog)
  foreach ($rule in @(@{ Section = 'Process'
        Property = 'UserPathsRegex'
        Compiled = '__UserPathsRegex'
      }, @{ Section = 'Samples'
        Property = 'PathIncludeRegex'
        Compiled = '__PathIncludeRegex'
      }, @{ Section = 'Tasks'
        Property = 'SuspiciousRegex'
        Compiled = '__SuspiciousRegex'
      })) {
    $section = $Catalog.($rule.Section)
    $patterns = @($section.($rule.Property))
    if ($patterns.Count -gt 256) {
      throw "Grabber $($rule.Section).$($rule.Property) supports at most 256 patterns."
    }
    $compiled = foreach ($pattern in $patterns) {
      if ($pattern -isnot [string]) {
        throw "Grabber $($rule.Section).$($rule.Property) must contain strings."
      }
      New-ArtifactRegex -Pattern $pattern -Label "$($rule.Section).$($rule.Property)"
    }
    $section | Add-Member -NotePropertyName $rule.Compiled -NotePropertyValue @($compiled) -Force
  }
}
function Merge-Catalog {
  param($base, $override)

  if ($null -eq $override) {
    return $base
  }

  foreach ($section in @('OutputBase', 'Trigger', 'Process', 'Samples', 'Tasks')) {
    if ($section -eq 'OutputBase') {
      $v = Get-PSObjectPropertyValue -Obj $override -Name 'OutputBase'
      if ($v) {
        $base.OutputBase = [string]$v
      }
      continue
    }

    $ov = Get-PSObjectPropertyValue -Obj $override -Name $section
    if ($null -eq $ov) {
      continue
    }

    Merge-ArtifactCatalogSection -base $base -ov $ov -section $section
  }

  return $base
}
function Merge-ArtifactCatalogSection {
  param($base, $ov, [string]$section)
  foreach ($p in $base.$section.PSObject.Properties.Name) {
    $v = Get-PSObjectPropertyValue -Obj $ov -Name $p
    if ($null -ne $v -and $v -ne '') {
      $base.$section.$p = $v
    }
  }

  foreach ($p in $ov.PSObject.Properties.Name) {
    if (-not ($base.$section.PSObject.Properties.Name -contains $p)) {
      try {
        $base.$section | Add-Member -NotePropertyName $p -NotePropertyValue $ov.$p -Force
      }
      catch {
        Write-Verbose ("Catalog optional property merge failed for '{0}.{1}': {2}" -f $section, $p, $_.Exception.Message)
      }
    }
  }

}

function Load-Catalog {
  param([string]$CatalogPath, [string]$ConfigPath, [ref]$CatalogLoadNote)

  $CatalogLoadNote.Value = $null
  $cat = $null

  $cat = Read-ArtifactExplicitCatalog -CatalogPath $CatalogPath -CatalogLoadNote $CatalogLoadNote

  if ($null -eq $cat -and $ConfigPath) {
    $cat = Read-ArtifactConfiguredCatalog -ConfigPath $ConfigPath -CatalogLoadNote $CatalogLoadNote
  }

  if ($null -eq $cat) {
    $CatalogLoadNote.Value = "Using defaults (no catalog configured)"
  }

  $baseClone = Get-BaseClone $DefaultCatalog
  return (Merge-Catalog -base $baseClone -override $cat)
}
function Read-Trigger {
  param($cat, [switch]$Force, [switch]$CollectSamples)

  $State = @{}
  $State.reason = $null
  $State.want = $false
  $State.samples = $false

  $State.maxFileMB = Safe-ToInt $cat.Samples.MaxFileSizeMB 20
  $State.maxTotalMB = Safe-ToInt $cat.Samples.MaxTotalMB 100

  if ($Force) {
    $State.want = $true
  }

  Read-ArtifactRegistryTrigger -State $State -Catalog $cat

  try {
    $ff = Expand-Env ([string]$cat.Trigger.FileFlag)
    if ($ff -and (Test-Path -LiteralPath $ff)) {
      $State.want = $true
    }
  }
  catch {
    Write-Verbose ("Trigger file flag check failed: {0}" -f $_.Exception.Message)
  }

  if ($CollectSamples) {
    $State.samples = $true
  }

  [pscustomobject]@{
    Want = $State.want
    Reason = $State.reason
    Samples = $State.samples
    MaxFileMB = $State.maxFileMB
    MaxTotalMB = $State.maxTotalMB
  }
}

function Read-ArtifactExplicitCatalog {
  param([string]$CatalogPath, [ref]$CatalogLoadNote)
  $cat = $null
  if (-not [string]::IsNullOrWhiteSpace($CatalogPath)) {
    $sanitizedCatalog = Sanitize-Path -Path $CatalogPath -MustExist
    if ([string]::IsNullOrWhiteSpace($sanitizedCatalog)) {
      throw 'Explicit artifact catalog path is missing or unsafe.'
    }
    $catalogResult = Read-JsonFileWithStatus -Path $sanitizedCatalog
    if (-not $catalogResult.Meta.Loaded) {
      throw "Explicit artifact catalog failed to load ($($catalogResult.Meta.Status)): $($catalogResult.Meta.Error)"
    }
    $cat = $catalogResult.Data
    $CatalogLoadNote.Value = "Catalog loaded from -CatalogPath"
  }

  return $cat
}

function Read-ArtifactConfiguredCatalog {
  param([string]$ConfigPath, [ref]$CatalogLoadNote)
  $cat = $null
  $sanitizedConfig = Sanitize-Path -Path $ConfigPath -MustExist
  if ([string]::IsNullOrWhiteSpace($sanitizedConfig)) {
    throw 'Explicit artifact config path is missing or unsafe.'
  }
  $configResult = Read-JsonFileWithStatus -Path $sanitizedConfig
  if (-not $configResult.Meta.Loaded) {
    throw "Explicit artifact config failed to load ($($configResult.Meta.Status)): $($configResult.Meta.Error)"
  }
  $cfg = $configResult.Data
  $p = $null
  try {
    $p = $cfg.Grabber.CatalogPath
  }
  catch {
    Write-Verbose ("Config CatalogPath lookup failed: {0}" -f $_.Exception.Message)
    $p = $null
  }
  if ($p) {
    $cat = Read-ArtifactReferencedCatalog -Path $p -CatalogLoadNote $CatalogLoadNote
  }
  return $cat
}

function Read-ArtifactReferencedCatalog {
  param($Path, [ref]$CatalogLoadNote)
  $sanitizedP = Sanitize-Path -Path $Path -MustExist
  if ([string]::IsNullOrWhiteSpace($sanitizedP)) {
    throw 'Artifact catalog referenced by ConfigPath is missing or unsafe.'
  }
  $catalogResult = Read-JsonFileWithStatus -Path $sanitizedP
  if (-not $catalogResult.Meta.Loaded) {
    throw "Artifact catalog referenced by ConfigPath failed to load ($($catalogResult.Meta.Status)): $($catalogResult.Meta.Error)"
  }
  $cat = $catalogResult.Data
  $CatalogLoadNote.Value = "Catalog loaded from ConfigPath reference"
  return $cat
}

function Read-ArtifactRegistryTrigger {
  param($State, $Catalog)
  try {
    $k = [string]$Catalog.Trigger.Registry
    $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
    if ($p) {
      if ($p.Request -eq 1) {
        $State.want = $true
      }
      if ($p.IncludeSamples -eq 1) {
        $State.samples = $true
      }
      Read-ArtifactTriggerOptions -State $State -Properties $p
    }
  }
  catch {
    Write-Verbose ("Trigger registry read failed: {0}" -f $_.Exception.Message)
  }

}

function Read-ArtifactTriggerOptions {
  param($State, $Properties)
  $p = $Properties
  if ($p.PSObject.Properties.Name -contains 'Reason') {
    $State.reason = [string]$p.Reason
  }
  if ($p.PSObject.Properties.Name -contains 'MaxFileSizeMB') {
    $State.maxFileMB = Safe-ToInt $p.MaxFileSizeMB $State.maxFileMB
  }
  if ($p.PSObject.Properties.Name -contains 'MaxTotalMB') {
    $State.maxTotalMB = Safe-ToInt $p.MaxTotalMB $State.maxTotalMB
  }
}

$DefaultCatalog = [pscustomobject]@{
  OutputBase = (Get-ArtifactEvidenceRoot)
  Trigger = [pscustomobject]@{
    Registry = 'HKLM:\SOFTWARE\IR\Grabber'
    FileFlag = $null
  }
  Process = [pscustomobject]@{
    HashUserlandOnly = $true
    UserPathsRegex = @(
      '^C:\\Users\\[^\\]+\\AppData\\',
      '^C:\\ProgramData\\',
      '^C:\\Windows\\Temp\\'
    )
  }
  Samples = [pscustomobject]@{
    Enable = $false
    MaxFileSizeMB = 20
    MaxTotalMB = 100
    OnlyUnsignedOrUnknown = $true
    PathIncludeRegex = @(
      '^C:\\Users\\[^\\]+\\AppData\\',
      '^C:\\ProgramData\\'
    )
  }
  Tasks = [pscustomobject]@{
    ExportXmlForSuspicious = $true
    SuspiciousRegex = @(
      '(?i)\\Users\\[^\\]+\\AppData\\',
      '(?i)\\Temp\\',
      '(?i)\\ProgramData\\'
    )
    MaxXml = 50
  }
}

function Reset-Trigger {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param($cat)
  try {
    $rk = [string]$cat.Trigger.Registry
    if ($rk -and (Test-Path -LiteralPath $rk)) {
      if (-not $PSCmdlet.ShouldProcess($rk, 'Reset artifact grabber trigger registry flag')) {
        return
      }
      New-ItemProperty -Path $rk -Name 'Request' -PropertyType DWord -Value 0 -Force | Out-Null
    }
  }
  catch {
    Write-Verbose ("Artifact grabber trigger registry reset failed: {0}" -f $_.Exception.Message)
  }
}
