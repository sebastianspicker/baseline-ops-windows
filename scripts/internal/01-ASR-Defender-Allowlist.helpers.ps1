#requires -version 5.1
<#
.SYNOPSIS
  Provides private Defender allowlist phases.
.DESCRIPTION
  Preserves normalization, risky-entry policy, remediation decisions, and reporting for the public capability.
#>

function Get-DefaultDesiredConfig {
  [CmdletBinding()]
  param()

  [pscustomobject]@{
    Defender = [pscustomobject]@{
      ExclusionPaths = @()
      ExclusionProcesses = @()
      ExclusionExtensions = @()
    }
    ASR = [pscustomobject]@{
      OnlyExclusions = @()
    }
    CFA = [pscustomobject]@{
      AllowedApplications = @()
      ProtectedFolders = @()
    }
  }
}

function Get-NullSafeDesiredFromCurrent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][object]$Preference
  )

  [pscustomobject]@{
    Defender = [pscustomobject]@{
      ExclusionPaths = @($Preference.ExclusionPath)
      ExclusionProcesses = @($Preference.ExclusionProcess)
      ExclusionExtensions = @($Preference.ExclusionExtension)
    }
    ASR = [pscustomobject]@{
      OnlyExclusions = @($Preference.AttackSurfaceReductionOnlyExclusions)
    }
    CFA = [pscustomobject]@{
      AllowedApplications = @($Preference.ControlledFolderAccessAllowedApplications)
      ProtectedFolders = @($Preference.ControlledFolderAccessProtectedFolders)
    }
  }
}

function Get-MinimumBaselineDesiredConfig {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][object]$Preference
  )

  # Minimal baseline philosophy (safe by default):
  # - Do not add broad AV exclusions (Microsoft generally recommends avoiding unnecessary exclusions).
  # - Keep ASR-only exclusions empty (avoid weakening ASR without evidence).
  # - Keep CFA allow-app list empty (avoid allowing extra apps by default).
  # - Do not force protected folders here: Windows system folders are protected by default; forcing additional folders
  #   without context can cause app compatibility issues.
  #
  # Preserve current lists so the default does not remove operator-managed state.
  $cur = Get-NullSafeDesiredFromCurrent -Preference $Preference

  [pscustomobject]@{
    Defender = [pscustomobject]@{
      ExclusionPaths = @($cur.Defender.ExclusionPaths)
      ExclusionProcesses = @($cur.Defender.ExclusionProcesses)
      ExclusionExtensions = @($cur.Defender.ExclusionExtensions)
    }
    ASR = [pscustomobject]@{
      OnlyExclusions = @()   # baseline: none
    }
    CFA = [pscustomobject]@{
      AllowedApplications = @()  # baseline: none
      ProtectedFolders = @()  # baseline: none (system defaults already exist)
    }
  }
}

function Get-Config {
  [CmdletBinding()]
  param([AllowEmptyString()][string]$Path)

  try {
    $sanitized = if ([string]::IsNullOrWhiteSpace($Path)) {
      $null
    }
    else {
      Sanitize-Path -Path $Path -MustExist
    }
    if ($sanitized) {
      return Get-BoundedUtf8FileContent -Path $sanitized -MaximumBytes 1048576 | ConvertFrom-Json
    }
  }
  catch {
    return $null
  }

  return $null
}


function Write-AuditJson {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path,
    [Parameter(Mandatory = $true)][object]$Object
  )

  try {
    if ([string]::IsNullOrWhiteSpace($Path)) {
      return
    }

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
      New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    ($Object | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $Path -Encoding UTF8
  }
  catch {
    Write-Verbose ("ASR JSON save failed for '{0}': {1}" -f $Path, $_.Exception.Message)
  }
}

function To-NormList {
  [CmdletBinding()]
  param(
    [Alias('Input')]
    [object]$InputValue,
    [ValidateSet('path', 'process', 'ext', 'generic', 'cfaapp')][string]$Kind = 'generic'
  )

  if (-not $InputValue) {
    return @()
  }

  $arr = New-Object System.Collections.Generic.List[string]
  foreach ($v in @($InputValue)) {
    if ($null -eq $v) {
      continue
    }
    $s = ([string]$v).Trim()
    if ([string]::IsNullOrWhiteSpace($s)) {
      continue
    }

    $arr.Add((ConvertTo-AllowlistItem -Text $s -Kind $Kind))
  }

  return $arr | Where-Object { $_.Length -gt 0 } | Sort-Object -Unique
}

function Is-RiskyEntry {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$Item,
    [ValidateSet('path', 'process', 'ext', 'generic', 'cfaapp')][string]$Kind = 'generic'
  )

  $s = $Item.Trim().ToLowerInvariant()

  if (Test-AllowlistSyntaxRisk -Text $s) {
    return $true
  }

  if ($Kind -in @('path', 'cfaapp')) {
    if (Test-AllowlistPathRisk -Text $s) {
      return $true
    }
  }

  if ($Kind -eq 'ext') {
    if ($s -in '.exe', '.dll', '.sys') {
      return $true
    }
  }

  return $false
}

function Diff-Lists {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][ValidateSet('path', 'process', 'ext', 'generic', 'cfaapp')][string]$Kind,
    [string[]]$Current,
    [object]$Desired
  )

  $cur = To-NormList -Input $Current -Kind $Kind
  $desRaw = To-NormList -Input $Desired -Kind $Kind

  $bad = @($desRaw | Where-Object { Is-RiskyEntry -Item $_ -Kind $Kind })
  $des = @($desRaw | Where-Object { $bad -notcontains $_ })

  $toAdd = @($des | Where-Object { $cur -notcontains $_ })
  $toRemove = @($cur | Where-Object { $des -notcontains $_ })

  [pscustomobject]@{
    Name = $Name
    Kind = $Kind
    Current = $cur
    Desired = $des
    ToAdd = $toAdd
    ToRemove = $toRemove
    Rejected = $bad
  }
}

function Apply-Diff {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param(
    [Parameter(Mandatory = $true)][pscustomobject]$Diff,
    [switch]$Remediate
  )

  $name = [string]$Diff.Name
  $errors = New-Object System.Collections.Generic.List[string]

  if ($Remediate) {
    Invoke-AllowlistAddition -DecisionContext $PSCmdlet

    try {
      if ($Diff.ToRemove.Count -gt 0) {
        if ($PSCmdlet.ShouldProcess($name, "Remove Defender allowlist entries")) {
          Remove-AllowlistPreference -Name $name -Entries $Diff.ToRemove
        }
      }
    }
    catch {
      $errors.Add("Remove failed for ${name}: $($_.Exception.Message)")
    }
  }

  [pscustomobject]@{
    Name = $name
    Added = @($Diff.ToAdd)
    Removed = @($Diff.ToRemove)
    Rejected = @($Diff.Rejected)
    Errors = @($errors)
  }
}

function ConvertTo-AllowlistItem {
  param([string]$Text, [string]$Kind)
  $s = $Text
  switch ($Kind) {
    'path' {
      return ConvertTo-AllowlistPath -Text $s
    }
    'process' {
      return $s.ToLowerInvariant()
    }
    'ext' {
      $t = $s.ToLowerInvariant()
      if ($t -notmatch '^\.' ) {
        $t = '.' + $t
      }
      return $t
    }
    'cfaapp' {
      return $s.ToLowerInvariant()
    }
    default {
      return $s
    }
  }
}
function Test-AllowlistPathRisk {
  param([string]$Text)
  $s = $Text
  if ($s -match '^[a-z]:\\$') {
    return $true
  }
  if ($s -match '^[a-z]:\\\*$') {
    return $true
  }

  if (Test-AllowlistSystemPathRisk -Text $s) {
    return $true
  }

  if ($s -like 'c:\users\*') {
    return $true
  }
  return $false
}
function Add-AllowlistPreference {
  param([string]$Name, $Entries)
  switch ($name) {
    'ExclusionPath' {
      Add-MpPreference -ExclusionPath $Entries
    }
    'ExclusionProcess' {
      Add-MpPreference -ExclusionProcess $Entries
    }
    'ExclusionExtension' {
      Add-MpPreference -ExclusionExtension $Entries
    }
    'AttackSurfaceReductionOnlyExclusions' {
      Add-MpPreference -AttackSurfaceReductionOnlyExclusions $Entries
    }
    'ControlledFolderAccessAllowedApplications' {
      Add-MpPreference -ControlledFolderAccessAllowedApplications $Entries
    }
    'ControlledFolderAccessProtectedFolders' {
      Add-MpPreference -ControlledFolderAccessProtectedFolders $Entries
    }
    default {
    }
  }
}
function Remove-AllowlistPreference {
  param([string]$Name, $Entries)
  switch ($name) {
    'ExclusionPath' {
      Remove-MpPreference -ExclusionPath $Entries
    }
    'ExclusionProcess' {
      Remove-MpPreference -ExclusionProcess $Entries
    }
    'ExclusionExtension' {
      Remove-MpPreference -ExclusionExtension $Entries
    }
    'AttackSurfaceReductionOnlyExclusions' {
      Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $Entries
    }
    'ControlledFolderAccessAllowedApplications' {
      Remove-MpPreference -ControlledFolderAccessAllowedApplications $Entries
    }
    'ControlledFolderAccessProtectedFolders' {
      Remove-MpPreference -ControlledFolderAccessProtectedFolders $Entries
    }
    default {
    }
  }
}

. (Join-Path $PSScriptRoot '01-ASR-Defender-Allowlist.runtime.ps1')

function Test-AllowlistSyntaxRisk {
  param([string]$Text)
  $s = $Text
  if ($s -match '[\*\?]') {
    return $true
  }
  if ($s -like '\\*') {
    return $true
  }
  if ($s -like '\\?\*') {
    return $true
  }
  if ($s -like '\device\*') {
    return $true
  }

  return $false
}

function Invoke-AllowlistAddition {
  param($DecisionContext)
  try {
    if ($Diff.ToAdd.Count -gt 0) {
      if ($DecisionContext.ShouldProcess($name, "Add Defender allowlist entries")) {
        Add-AllowlistPreference -Name $name -Entries $Diff.ToAdd
      }
    }
  }
  catch {
    $errors.Add("Add failed for ${name}: $($_.Exception.Message)")
  }

}

function ConvertTo-AllowlistPath {
  param([string]$Text)
  $s = $Text
  $t = $s.TrimEnd('\', '/')
  if ($t.Length -eq 2 -and $t -match '^[a-zA-Z]:$') {
    $t = $t + '\'
  }
  # For UNC paths, ensure we don't accidentally trim the root if it was just \\server\share\
  if ($s -like '\\*\*' -and $t -notlike '\\*\*') {
    $t = $s
  }
  return $t.ToLowerInvariant()
}

function Test-AllowlistSystemPathRisk {
  param([string]$Text)
  $s = $Text
  if ($s -eq 'c:\windows' -or $s -like 'c:\windows\*') {
    return $true
  }
  if ($s -eq 'c:\program files' -or $s -like 'c:\program files\*') {
    return $true
  }
  if ($s -eq 'c:\program files (x86)' -or $s -like 'c:\program files (x86)\*') {
    return $true
  }

  return $false
}
