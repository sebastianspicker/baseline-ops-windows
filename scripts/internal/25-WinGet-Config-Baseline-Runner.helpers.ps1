<#
.SYNOPSIS
Internal staging and result helpers for the WinGet configuration runner.

.DESCRIPTION
Creates administrator-only staging directories, pins the exact configuration
bytes used by WinGet, and maps phase outcomes into the repository result
contract. These boundaries prevent privileged execution from consuming a
replaceable configuration file.
#>
Set-StrictMode -Version Latest

function Test-WinGetPhaseSuccess {
  [CmdletBinding()]
  [OutputType([bool])]
  param([Parameter(Mandatory)]$PhaseResult)

  return ($PhaseResult.ExitCode -eq 0 -and -not [bool]$PhaseResult.TimedOut)
}

function Get-WinGetAggregateExitCode {
  [CmdletBinding()]
  [OutputType([int])]
  param([AllowEmptyCollection()][object[]]$PhaseResults = @())

  foreach ($phaseResult in @($PhaseResults)) {
    if ($phaseResult.TimedOut -or $phaseResult.ExitCode -ne 0) {
      if ($phaseResult.TimedOut -and $phaseResult.ExitCode -eq 0) { return -1 }
      return [int]$phaseResult.ExitCode
    }
  }
  return 0
}

function Get-WinGetResultToken {
  [CmdletBinding()]
  [OutputType([string])]
  param(
    [int]$FinalExitCode,
    [ValidateRange(0, 2147483647)][int]$FindingsCount,
    [bool]$StrictMode
  )

  $token = if ($FinalExitCode -ne 0) { 'FAIL' } elseif ($FindingsCount -gt 0) { 'WARN' } else { 'OK' }
  if ($StrictMode -and $token -eq 'WARN') { return 'FAIL' }
  return $token
}

# Builds the protected ACL used for every staging directory so inherited local
# user write access cannot affect privileged WinGet input.
function New-WinGetAdminOnlyDirectorySecurity {
  [CmdletBinding()]
  param()

  $security = New-Object System.Security.AccessControl.DirectorySecurity
  $security.SetAccessRuleProtection($true, $false)
  $administrators = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
  $security.SetOwner($administrators)
  $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  foreach ($sidValue in @('S-1-5-18', 'S-1-5-32-544')) {
    $sid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $sidValue
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
      $sid,
      [System.Security.AccessControl.FileSystemRights]::FullControl,
      $inheritance,
      [System.Security.AccessControl.PropagationFlags]::None,
      [System.Security.AccessControl.AccessControlType]::Allow)
    [void]$security.AddAccessRule($rule)
  }
  return $security
}

function New-WinGetAdminOnlyDirectory {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
    return
  }

  $security = New-WinGetAdminOnlyDirectorySecurity
  if ($PSVersionTable.PSEdition -eq 'Desktop') {
    [System.IO.Directory]::CreateDirectory($Path, $security) | Out-Null
  } else {
    [System.IO.FileSystemAclExtensions]::CreateDirectory($security, $Path) | Out-Null
  }
  Assert-TrustedWindowsPathAcl -Path $Path | Out-Null
}

# Resolves the fixed CommonApplicationData staging root and creates each missing
# component with its final ACL, avoiding a create-then-harden race.
function Initialize-WinGetStagingRoot {
  [CmdletBinding()]
  [OutputType([string])]
  param([string]$StagingRoot)

  $commonApplicationData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    if ([string]::IsNullOrWhiteSpace($StagingRoot)) {
      throw 'A staging root is required for non-Windows helper tests.'
    }
    $portableRoot = [System.IO.Path]::GetFullPath($StagingRoot)
    [System.IO.Directory]::CreateDirectory($portableRoot) | Out-Null
    return $portableRoot
  }
  if ([string]::IsNullOrWhiteSpace($commonApplicationData)) {
    throw 'CommonApplicationData could not be resolved for WinGet staging.'
  }

  $fixedRoot = Join-Path $commonApplicationData 'BaselineOpsForWindows\WinGetConfigStaging'
  if (-not [string]::IsNullOrWhiteSpace($StagingRoot) -and
      -not [System.IO.Path]::GetFullPath($StagingRoot).Equals([System.IO.Path]::GetFullPath($fixedRoot), [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'WinGet staging root is fixed under CommonApplicationData.'
  }

  $fullRoot = [System.IO.Path]::GetFullPath($fixedRoot)
  if (Test-Path -LiteralPath $fullRoot) {
    $rootItem = Get-Item -LiteralPath $fullRoot -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
      throw 'WinGet staging root is not a regular directory.'
    }
    Assert-TrustedWindowsPathAcl -Path $rootItem.FullName -CheckAncestors | Out-Null
    return $rootItem.FullName
  }

  $missing = New-Object System.Collections.Generic.List[string]
  $current = $fullRoot
  while (-not (Test-Path -LiteralPath $current)) {
    [void]$missing.Add($current)
    $parent = Split-Path -Path $current -Parent
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) {
      throw 'WinGet staging root has no existing trusted ancestor.'
    }
    $current = $parent
  }

  $existing = Get-Item -LiteralPath $current -Force -ErrorAction Stop
  if (-not $existing.PSIsContainer -or ($existing.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
    throw 'WinGet staging root ancestor is not a regular directory.'
  }

  # A generic ancestor such as C:\ProgramData may legitimately allow users to
  # create children. Validate it with ancestor replacement rights only by
  # checking from each atomically created protected child.
  for ($i = $missing.Count - 1; $i -ge 0; $i--) {
    New-WinGetAdminOnlyDirectory -Path $missing[$i]
    Assert-TrustedWindowsPathAcl -Path $missing[$i] -CheckAncestors | Out-Null
  }
  Assert-TrustedWindowsPathAcl -Path $fullRoot -CheckAncestors | Out-Null
  return $fullRoot
}

# Locks the source, copies bounded bytes into protected staging, and retains a
# read handle so WinGet consumes the exact configuration that was validated.
function New-WinGetStagedConfiguration {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$SourcePath,
    [ValidateRange(1, 16777216)][int64]$MaximumBytes = 16777216,
    [string]$StagingRoot
  )

  $sourceStream = $null
  $writeStream = $null
  $stageStream = $null
  $workDirectory = $null
  try {
    $providerPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SourcePath)
    $item = Get-Item -LiteralPath $providerPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
      throw 'WinGet configuration must be a regular file, not a directory or reparse point.'
    }
    $extension = [System.IO.Path]::GetExtension($item.Name).ToLowerInvariant()
    if ($extension -notin @('.yaml', '.yml', '.json')) {
      throw 'WinGet configuration must use a .yaml, .yml, or .json extension.'
    }
    $volumeRoot = [System.IO.Path]::GetPathRoot($item.FullName)
    if (Test-PathContainsReparsePoint -Path $item.FullName -Root $volumeRoot) {
      throw 'WinGet configuration path contains a reparse point.'
    }

    # Deny writers and replacement while copying the exact source bytes into
    # the protected staging directory.
    $sourceStream = [System.IO.File]::Open($item.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    if ($sourceStream.Length -eq 0 -or $sourceStream.Length -gt $MaximumBytes) {
      throw "WinGet configuration must contain 1..$MaximumBytes bytes."
    }
    $bytes = New-Object byte[] ([int]$sourceStream.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
      $read = $sourceStream.Read($bytes, $offset, $bytes.Length - $offset)
      if ($read -le 0) { throw 'WinGet configuration changed or ended while being staged.' }
      $offset += $read
    }

    $root = Initialize-WinGetStagingRoot -StagingRoot $StagingRoot
    $workDirectory = Join-Path $root ('run-' + [guid]::NewGuid().ToString('N'))
    New-WinGetAdminOnlyDirectory -Path $workDirectory
    Assert-TrustedWindowsPathAcl -Path $workDirectory -CheckAncestors | Out-Null
    $stagePath = Join-Path $workDirectory ('configuration' + $extension)

    # Create and flush with an exclusive writer, then retain a read-only handle.
    # FileShare.Read lets WinGet open the snapshot for reading while denying
    # writers, deletion, rename, and replacement through every phase.
    $writeStream = [System.IO.File]::Open($stagePath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    $writeStream.Write($bytes, 0, $bytes.Length)
    $writeStream.Flush($true)
    $writeStream.Dispose()
    $writeStream = $null
    Assert-TrustedWindowsPathAcl -Path $stagePath -CheckAncestors | Out-Null
    $stageStream = [System.IO.File]::Open($stagePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $contentHash = ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '') }
    finally { $sha.Dispose() }

    return [pscustomobject]@{
      SourcePath = $item.FullName
      Path = $stagePath
      Directory = $workDirectory
      Stream = $stageStream
      Sha256 = $contentHash
    }
  } catch {
    if ($null -ne $writeStream) { $writeStream.Dispose() }
    if ($null -ne $stageStream) { $stageStream.Dispose() }
    if ($workDirectory -and (Test-Path -LiteralPath $workDirectory -PathType Container)) {
      Remove-Item -LiteralPath $workDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
    throw
  } finally {
    if ($null -ne $sourceStream) { $sourceStream.Dispose() }
  }
}

function Remove-WinGetStagedConfiguration {
  [CmdletBinding()]
  param([AllowNull()]$StagedConfiguration)

  if ($null -eq $StagedConfiguration) { return }
  if ($null -ne $StagedConfiguration.Stream) { $StagedConfiguration.Stream.Dispose() }
  if ($StagedConfiguration.Directory -and (Test-Path -LiteralPath $StagedConfiguration.Directory -PathType Container)) {
    Remove-Item -LiteralPath $StagedConfiguration.Directory -Recurse -Force -ErrorAction Stop
  }
}
