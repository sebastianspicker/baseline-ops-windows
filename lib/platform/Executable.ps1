<#
.SYNOPSIS
  Tests whether an external command exists in PATH.
.DESCRIPTION
  Implements executable discovery and trust checks for the External module.
.PARAMETER Name
  Executable name to look up.
#>
function Test-CommandExists {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Public compatibility contract')]
  [CmdletBinding()]
  [OutputType([bool])]
  param(
    [Parameter(Mandatory)]
    [string]$Name
  )

  return -not [string]::IsNullOrWhiteSpace((Resolve-NativeExecutablePath -Name $Name))
}

<#
.SYNOPSIS
  Resolves a trusted absolute path for a native executable.
.DESCRIPTION
  Rejects non-file, non-rooted, and reparse-point paths before invocation.
#>
function Test-NativeExecutableRequest {
  [OutputType([bool])]
  param([AllowNull()][string]$Name)

  return -not ([string]::IsNullOrWhiteSpace($Name) -or $Name -match '[\x00-\x1F\x7F]')
}

<#
.SYNOPSIS
  Resolves an approved bare Windows executable name.
.DESCRIPTION
  Limits bare names to the fixed system, package, Git, or current-host policy.
#>
function Resolve-ApprovedWindowsExecutableName {
  [OutputType([string])]
  param([Parameter(Mandatory)][string]$Name)

  $systemExecutables = @(
    'auditpol.exe','bcdedit.exe','certutil.exe','cscript.exe','dism.exe','manage-bde.exe',
    'netstat.exe','reg.exe','sc.exe','schtasks.exe','taskkill.exe','vssadmin.exe',
    'wecutil.exe','wevtutil.exe','w32tm.exe'
  )
  if ($systemExecutables -icontains $Name) { return Resolve-TrustedWindowsSystemFile -LeafName $Name }
  if ($Name -ieq 'winget.exe' -or $Name -ieq 'winget') { return Resolve-TrustedWingetPath }
  if ($Name -ieq 'git.exe' -or $Name -ieq 'git') { return Resolve-TrustedGitPath }
  return Resolve-CurrentNativeHostPath -Name $Name
}

<#
.SYNOPSIS
  Resolves the current PowerShell host only for a matching bare name.
.DESCRIPTION
  Allows controlled self-spawn without broadening the executable trust policy.
#>
function Resolve-CurrentNativeHostPath {
  [OutputType([string])]
  param([Parameter(Mandatory)][string]$Name)

  $hostPath = try { (Get-Process -Id $PID -ErrorAction Stop).Path } catch { $null }
  $requestedLeaf = if ([IO.Path]::HasExtension($Name)) { $Name } else { "$Name.exe" }
  if ([string]::IsNullOrWhiteSpace($hostPath)) { return $null }
  if ([IO.Path]::GetFileName($hostPath) -ine $requestedLeaf) { return $null }
  return [IO.Path]::GetFullPath($hostPath)
}

<#
.SYNOPSIS
  Resolves a non-policy native executable candidate.
.DESCRIPTION
  Canonicalizes either a supplied path or an application discovered from PATH.
#>
function Resolve-UnrestrictedNativeExecutablePath {
  [OutputType([string])]
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][bool]$HasPathComponent
  )

  try {
    if ($HasPathComponent) {
      $providerPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Name)
      return (Resolve-Path -LiteralPath $providerPath -ErrorAction Stop).ProviderPath
    }
    $application = Get-Command -Name $Name -CommandType Application -ErrorAction Stop | Select-Object -First 1
    if ($null -eq $application -or [string]::IsNullOrWhiteSpace([string]$application.Source)) { return $null }
    return (Resolve-Path -LiteralPath $application.Source -ErrorAction Stop).ProviderPath
  } catch {
    return $null
  }
}

<#
.SYNOPSIS
  Validates a canonical native executable path.
.DESCRIPTION
  Rejects non-rooted leaves and paths that cross reparse points.
#>
function Test-TrustedNativeExecutablePath {
  [OutputType([bool])]
  param([AllowNull()][string]$Path)

  if (-not [System.IO.Path]::IsPathRooted($Path)) { return $false }
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
  $volumeRoot = [System.IO.Path]::GetPathRoot($Path)
  return -not (Test-PathContainsReparsePoint -Path $Path -Root $volumeRoot)
}

<#
.SYNOPSIS
  Resolves a trusted absolute path for a native executable.
.DESCRIPTION
  Rejects non-file, non-rooted, and reparse-point paths before invocation.
#>
function Resolve-NativeExecutablePath {
  [CmdletBinding()]
  [OutputType([string])]
  param([Parameter(Mandatory)][string]$Name)

  if (-not (Test-NativeExecutableRequest -Name $Name)) { return $null }

  $windowsHost = $script:IsWindowsHost
  $leafName = [System.IO.Path]::GetFileName($Name)
  $hasPathComponent = $leafName -ne $Name

  if ($windowsHost -and -not $hasPathComponent) {
    return Resolve-ApprovedWindowsExecutableName -Name $Name
  }

  $candidate = Resolve-UnrestrictedNativeExecutablePath -Name $Name -HasPathComponent $hasPathComponent
  if (-not (Test-TrustedNativeExecutablePath -Path $candidate)) { return $null }
  return $candidate
}

<#
.SYNOPSIS
  Resolves a trusted file from the Windows system directory.
.DESCRIPTION
  Validates the resolved system path before returning it to a caller.
#>
function Resolve-TrustedWindowsSystemFile {
  [CmdletBinding()]
  [OutputType([string])]
  param([Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._-]+$')][string]$LeafName)

  if (-not $script:IsWindowsHost) { return $null }
  $systemDirectory = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System)
  if ([string]::IsNullOrWhiteSpace($systemDirectory)) { return $null }
  $candidate = Join-Path $systemDirectory $LeafName
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $null }
  $resolved = (Resolve-Path -LiteralPath $candidate -ErrorAction SilentlyContinue).ProviderPath
  if ([string]::IsNullOrWhiteSpace($resolved)) { return $null }
  $volumeRoot = [System.IO.Path]::GetPathRoot($resolved)
  if (Test-PathContainsReparsePoint -Path $resolved -Root $volumeRoot) { return $null }
  return $resolved
}

<#
.SYNOPSIS
  Resolves an approved WinGet executable path.
.DESCRIPTION
  Searches trusted locations and rejects paths that cross reparse points.
#>
function Get-TrustedWingetCandidatePaths {
  [OutputType([string[]])]
  param([Parameter(Mandatory)][string]$WindowsAppsRoot)

  $candidates = New-Object System.Collections.Generic.List[string]
  try {
    foreach ($directory in @(Get-ChildItem -LiteralPath $WindowsAppsRoot -Directory -Filter 'Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe' -ErrorAction Stop | Sort-Object Name -Descending)) {
      [void]$candidates.Add((Join-Path $directory.FullName 'winget.exe'))
    }
  } catch {
    Write-Verbose "Trusted WindowsApps enumeration failed: $($_.Exception.Message)"
  }
  return $candidates.ToArray()
}

<#
.SYNOPSIS
  Resolves a trusted candidate below an approved root.
.DESCRIPTION
  Rejects absent, escaped, and reparse-point candidate paths.
#>
function Resolve-TrustedExecutableCandidate {
  [OutputType([string])]
  param(
    [Parameter(Mandatory)][string]$Candidate,
    [AllowNull()][string]$ResolvedRoot
  )

  try {
    if (-not (Test-Path -LiteralPath $Candidate -PathType Leaf)) { return $null }
    $resolved = (Resolve-Path -LiteralPath $Candidate -ErrorAction Stop).ProviderPath
    if (-not (Test-PathUnderRoot -Path $resolved -Root $ResolvedRoot)) { return $null }
    if (Test-PathContainsReparsePoint -Path $resolved -Root $ResolvedRoot) { return $null }
    return $resolved
  } catch {
    return $null
  }
}

<#
.SYNOPSIS
  Resolves an approved WinGet executable path.
.DESCRIPTION
  Searches trusted locations and rejects paths that cross reparse points.
#>
function Resolve-TrustedWingetPath {
  [CmdletBinding()]
  [OutputType([string])]
  param()

  if (-not $script:IsWindowsHost) { return $null }
  $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
  if ([string]::IsNullOrWhiteSpace($programFiles)) { return $null }
  $windowsAppsRoot = Join-Path $programFiles 'WindowsApps'
  if (-not (Test-Path -LiteralPath $windowsAppsRoot -PathType Container)) { return $null }

  $resolvedRoot = (Resolve-Path -LiteralPath $windowsAppsRoot -ErrorAction SilentlyContinue).ProviderPath
  foreach ($candidate in @(Get-TrustedWingetCandidatePaths -WindowsAppsRoot $windowsAppsRoot)) {
    $resolved = Resolve-TrustedExecutableCandidate -Candidate $candidate -ResolvedRoot $resolvedRoot
    if (-not [string]::IsNullOrWhiteSpace($resolved)) { return $resolved }
  }
  return $null
}

<#
.SYNOPSIS
  Resolves an approved Git executable path.
.DESCRIPTION
  Limits discovery to validated native executable locations.
#>
function Resolve-TrustedPosixGitPath {
  [OutputType([string])]
  param()

  try {
    $application = Get-Command -Name git -CommandType Application -ErrorAction Stop | Select-Object -First 1
    if ($null -eq $application -or [string]::IsNullOrWhiteSpace([string]$application.Source)) { return $null }
    $resolved = (Resolve-Path -LiteralPath $application.Source -ErrorAction Stop).ProviderPath
    $volumeRoot = [IO.Path]::GetPathRoot($resolved)
    if (Test-PathContainsReparsePoint -Path $resolved -Root $volumeRoot) { return $null }
    return $resolved
  } catch {
    return $null
  }
}

<#
.SYNOPSIS
  Resolves a trusted Git executable below one approved root.
.DESCRIPTION
  Tries the supported Git installation layouts in a deterministic order.
#>
function Resolve-TrustedGitPathFromRoot {
  [OutputType([string])]
  param([Parameter(Mandatory)][string]$Root)

  foreach ($relativePath in @('Git\cmd\git.exe', 'Git\bin\git.exe')) {
    $candidate = Join-Path $Root $relativePath
    $resolved = Resolve-TrustedExecutableCandidate -Candidate $candidate -ResolvedRoot $Root
    if (-not [string]::IsNullOrWhiteSpace($resolved)) { return $resolved }
  }
  return $null
}

<#
.SYNOPSIS
  Resolves an approved Git executable path.
.DESCRIPTION
  Limits discovery to validated native executable locations.
#>
function Resolve-TrustedGitPath {
  [CmdletBinding()]
  [OutputType([string])]
  param()

  if (-not $script:IsWindowsHost) {
    return Resolve-TrustedPosixGitPath
  }

  $roots = @(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
  ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
  foreach ($root in $roots) {
    $resolved = Resolve-TrustedGitPathFromRoot -Root $root
    if (-not [string]::IsNullOrWhiteSpace($resolved)) { return $resolved }
  }
  return $null
}

<#
.SYNOPSIS
  Throws if a required cmdlet or function is not available.
.PARAMETER Name
  Cmdlet or function name to check.
.PARAMETER Message
  Custom error message on failure.
#>
function Ensure-Cmdlet {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Public compatibility contract')]
  [CmdletBinding()]
  [OutputType([bool])]
  param(
    [Parameter(Mandatory)]
    [string]$Name,
    [string]$Message
  )
  if ($null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue)) { return $true }
  $msg = if ($Message) { $Message } else { "Required cmdlet or function not found: $Name" }
  throw $msg
}

<#
.SYNOPSIS
  Throws if a required executable cannot be resolved through the trusted
  native-executable policy.
.PARAMETER Name
  Executable name to check.
.PARAMETER Message
  Custom error message on failure.
#>
function Ensure-Exe {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Public compatibility contract')]
  [CmdletBinding()]
  [OutputType([bool])]
  param(
    [Parameter(Mandatory)]
    [string]$Name,
    [string]$Message
  )
  $exe = Resolve-NativeExecutablePath -Name $Name
  if (-not [string]::IsNullOrWhiteSpace($exe)) { return $true }
  $msg = if ($Message) { $Message } else { "Required executable not found: $Name" }
  throw $msg
}
