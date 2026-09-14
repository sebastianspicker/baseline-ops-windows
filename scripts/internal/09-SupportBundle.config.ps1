<#
.SYNOPSIS
Support bundle config helpers.

.DESCRIPTION
Contains capability-private support bundle config behavior.
#>

function SB_NewDefaultConfig {
  param([Parameter(Mandatory)][string]$ProofDirDefault)

  [pscustomobject]@{
    Paths = [pscustomobject]@{
      ProofDir = $ProofDirDefault
    }
    ProofOutFiles = [pscustomobject]@{
      SysmonState       = $null
      SysmonDriftState  = $null
      SoftwareInventory = $null
      FirewallAudit     = $null
      HardwareAudit     = $null
    }
  }
}

function SB_AssertConfigObject {
  param($Value, [Parameter(Mandatory)][string]$Name)
  if ($null -eq $Value -or $Value -is [string] -or $Value -is [System.ValueType] -or
      $Value -is [System.Collections.IEnumerable]) {
    throw "$Name must be an object."
  }
}

function SB_ReadJsonConfig {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "Config file was not found or is not a regular file: $Path"
  }
  $configItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if ($configItem.PSIsContainer -or ($configItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
    throw "Config file must be a regular non-reparse file: $Path"
  }
  $raw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
  if ([string]::IsNullOrWhiteSpace($raw)) { throw 'Config file must not be empty.' }
  return ($raw | ConvertFrom-Json)
}

function SB_AssertConfigRoot {
  param($Config)
  SB_AssertConfigObject -Value $Config -Name 'Config root'
  $rootNames = @($Config.PSObject.Properties | ForEach-Object Name)
  foreach ($name in $rootNames) {
    if ($name -notin @('Paths', 'ProofOutFiles')) { throw "Config contains unsupported property '$name'." }
  }
  if ($rootNames -notcontains 'Paths' -or $rootNames -notcontains 'ProofOutFiles') {
    throw 'Config must contain Paths and ProofOutFiles objects.'
  }
  foreach ($sectionName in @('Paths', 'ProofOutFiles')) {
    SB_AssertConfigObject -Value $Config.$sectionName -Name "Config.$sectionName"
  }
}

function SB_AssertConfigPaths {
  param($Config)
  $pathNames = @($Config.Paths.PSObject.Properties | ForEach-Object Name)
  if ($pathNames.Count -ne 1 -or $pathNames -notcontains 'ProofDir' -or
      $Config.Paths.ProofDir -isnot [string] -or [string]::IsNullOrWhiteSpace($Config.Paths.ProofDir)) {
    throw 'Config.Paths must contain only a non-empty string ProofDir.'
  }
}

function SB_CompleteProofConfig {
  param($Config)
  $expectedNames = @('SysmonState', 'SysmonDriftState', 'SoftwareInventory', 'FirewallAudit', 'HardwareAudit')
  $proofNames = @($Config.ProofOutFiles.PSObject.Properties | ForEach-Object Name)
  foreach ($name in $proofNames) {
    if ($name -notin $expectedNames) { throw "Config.ProofOutFiles contains unsupported property '$name'." }
    $value = $Config.ProofOutFiles.$name
    if ($null -ne $value -and $value -isnot [string]) { throw "Config.ProofOutFiles.$name must be a string or null." }
  }
  foreach ($name in $expectedNames) {
    if ($proofNames -notcontains $name) {
      $Config.ProofOutFiles | Add-Member -NotePropertyName $name -NotePropertyValue $null
    }
  }
}

function SB_LoadJsonConfig {
  param([string]$Path, [Parameter(Mandatory)][pscustomobject]$DefaultConfig, [switch]$AllowDefaults)
  try {
    $config = SB_ReadJsonConfig -Path $Path
    SB_AssertConfigRoot -Config $config
    SB_AssertConfigPaths -Config $config
    SB_CompleteProofConfig -Config $config
    return [pscustomobject]@{ Ok = $true; Config = $config; UsedDefault = $false; Error = $null }
  }
  catch {
    if ($AllowDefaults) {
      return [pscustomobject]@{ Ok = $true; Config = $DefaultConfig; UsedDefault = $true; Error = $_.Exception.Message }
    }
    return [pscustomobject]@{ Ok = $false; Config = $null; UsedDefault = $false; Error = $_.Exception.Message }
  }
}

function SB_EnsureTrustedOutputComponent {
  param([Parameter(Mandatory)][string]$Path)
  if (Test-Path -LiteralPath $Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
      throw "Trusted output root component must be a non-reparse directory: $Path"
    }
  }
  else {
    New-Item -ItemType Directory -Path ([System.Management.Automation.WildcardPattern]::Escape($Path)) -ErrorAction Stop | Out-Null
  }
  SB_SetRestrictedDirectoryAcl -Path $Path
}

function SB_AssertTrustedOutputRoot {
  param([Parameter(Mandatory)][string]$Path)

  $fullPath = [System.IO.Path]::GetFullPath($Path)
  $expectedPath = SB_GetDefaultTrustedOutputRoot
  $comparison = if (SB_IsWindowsPlatform) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
  if (-not $fullPath.Equals($expectedPath, $comparison)) {
    throw 'Trusted output root must equal the fixed CommonApplicationData support-bundle root.'
  }

  $commonData = Split-Path -Parent (Split-Path -Parent $expectedPath)
  if (-not (Test-Path -LiteralPath $commonData -PathType Container)) {
    throw "Trusted output parent does not exist: $commonData"
  }
  $current = $commonData
  foreach ($segment in @('BaselineOpsForWindows', 'SupportBundles')) {
    $current = Join-Path $current $segment
    SB_EnsureTrustedOutputComponent -Path $current
  }

  $resolved = (Resolve-Path -LiteralPath $fullPath -ErrorAction Stop).Path
  if (Test-PathContainsReparsePoint -Path $resolved -Root $commonData) { throw "Trusted output root traverses a reparse point: $resolved" }
  return $resolved
}

function SB_EnsureTrustedChildDirectory {
  param([Parameter(Mandatory)][string]$Path)
  if (Test-Path -LiteralPath $Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
      throw "Support-bundle path must be a non-reparse directory: $Path"
    }
  }
  else {
    New-Item -ItemType Directory -Path ([System.Management.Automation.WildcardPattern]::Escape($Path)) -ErrorAction Stop | Out-Null
  }
}

function SB_AssertTrustedChildDirectory {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$TrustedRoot
  )

  $root = (Resolve-Path -LiteralPath $TrustedRoot -ErrorAction Stop).Path
  $fullPath = [System.IO.Path]::GetFullPath($Path)
  if (-not (Test-PathUnderRoot -Path $fullPath -Root $root) -or $fullPath -eq $root) {
    throw "Support-bundle directory is outside the trusted root: $fullPath"
  }
  $parent = Split-Path -Parent $fullPath
  if (-not (Test-Path -LiteralPath $parent -PathType Container) -or (Test-PathContainsReparsePoint -Path $parent -Root $root)) {
    throw "Support-bundle directory parent is not trusted: $parent"
  }
  SB_EnsureTrustedChildDirectory -Path $fullPath
  $resolved = (Resolve-Path -LiteralPath $fullPath -ErrorAction Stop).Path
  if (Test-PathContainsReparsePoint -Path $resolved -Root $root) {
    throw "Support-bundle directory traverses a reparse point: $resolved"
  }
  SB_SetRestrictedDirectoryAcl -Path $resolved
  return $resolved
}

function SB_GetConfiguredProofCandidate {
  param([string]$ConfiguredPath, [string]$Root)
  if ([System.IO.Path]::IsPathRooted($ConfiguredPath)) {
    return [System.IO.Path]::GetFullPath($ConfiguredPath)
  }
  return [System.IO.Path]::GetFullPath((Join-Path $Root $ConfiguredPath))
}

function SB_AssertExistingProofFile {
  param([string]$Candidate, [string]$Root, [string]$PropertyName)
  $item = Get-Item -LiteralPath $Candidate -Force -ErrorAction Stop
  if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
    throw "Config.ProofOutFiles.$PropertyName must identify a regular non-reparse file."
  }
  $resolved = (Resolve-Path -LiteralPath $Candidate -ErrorAction Stop).Path
  if (-not (Test-PathUnderRoot -Path $resolved -Root $Root) -or
      (Test-PathContainsReparsePoint -Path $resolved -Root $Root)) {
    throw "Config.ProofOutFiles.$PropertyName is outside the trusted proof root or traverses a reparse point."
  }
  return $resolved
}

function SB_ResolveTrustedProofFile {
  param(
    [AllowNull()][string]$ConfiguredPath,
    [Parameter(Mandatory)][string]$TrustedRoot,
    [Parameter(Mandatory)][string]$ExpectedFileName,
    [Parameter(Mandatory)][string]$PropertyName
  )

  if ($null -eq $ConfiguredPath -or [string]::IsNullOrWhiteSpace($ConfiguredPath)) { return $null }
  $root = (Resolve-Path -LiteralPath $TrustedRoot -ErrorAction Stop).Path
  if (Test-PathContainsReparsePoint -Path $root -Root ([System.IO.Path]::GetPathRoot($root))) { throw "Trusted proof root traverses a reparse point: $root" }
  $candidate = SB_GetConfiguredProofCandidate -ConfiguredPath $ConfiguredPath -Root $root
  $expected = [System.IO.Path]::GetFullPath((Join-Path $root $ExpectedFileName))
  if (-not $candidate.Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Config.ProofOutFiles.$PropertyName must identify only $ExpectedFileName beneath the trusted proof root."
  }
  if (Test-Path -LiteralPath $candidate) {
    return SB_AssertExistingProofFile -Candidate $candidate -Root $root -PropertyName $PropertyName
  }
  return $candidate
}
