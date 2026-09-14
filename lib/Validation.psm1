<#
.SYNOPSIS
Input validation and security guard functions.

.DESCRIPTION
Provides functions to detect path traversal, validate script names, git refs,
URLs, and directory containment. Used across scripts to enforce input safety.
#>

Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Tests whether a path contains traversal segments ('..').
.PARAMETER Path
  Path string to check.
#>
function Test-PathTraversal {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [string]$Path
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    return $false
  }

  $normalized = $Path.Replace('/', '\')
  if ($normalized -match '(^|\\)\.\.(\\|$)') { return $true }
  if ($normalized -match '\\.\\.\\') { return $true }
  return $false
}

<#
.SYNOPSIS
  Throws if a path contains traversal segments.
.PARAMETER Path
  Path string to validate.
.PARAMETER ParameterName
  Name shown in the error message (default 'Path').
#>
function Assert-NoPathTraversal {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Path,
    [string]$ParameterName = 'Path'
  )

  if (Test-PathTraversal -Path $Path) {
    throw "$ParameterName must not contain path traversal segments ('..')."
  }
}

<#
.SYNOPSIS
  Validates that a script name is safe (no path separators, valid .ps1 extension).
.PARAMETER Name
  Script file name to validate.
#>
function Test-UnsafeScriptNameCharacters {
  param([Parameter(Mandatory)][string]$Name)

  return $Name -match '[\\/]|[\x00-\x1F]|[:*?"<>|]|^\s|\s$'
}

function Test-SafeScriptName {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [string]$Name
  )

  if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
  if (Test-PathTraversal -Path $Name) { return $false }
  if (Test-UnsafeScriptNameCharacters -Name $Name) { return $false }
  $ext = [System.IO.Path]::GetExtension($Name)
  if ($ext -ne '.ps1') { return $false }
  if ($Name -match '^[.-]') { return $false }
  return $true
}

<#
.SYNOPSIS
  Validates that a string is a safe git ref (branch/tag name).
.PARAMETER Ref
  Git ref string to validate.
#>
function Test-InvalidGitRefPattern {
  param([Parameter(Mandatory)][string]$Ref)

  return $Ref -match '\.\.|[~^:\?*\[\\]|@\{'
}

function Test-InvalidGitRefSuffix {
  param([Parameter(Mandatory)][string]$Ref)

  return $Ref.EndsWith('.') -or $Ref.EndsWith('/') -or $Ref.EndsWith('.lock')
}

function Test-ValidGitRef {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [string]$Ref
  )

  if ([string]::IsNullOrWhiteSpace($Ref)) { return $false }
  if ($Ref -match '^\s*-') { return $false }
  if (Test-InvalidGitRefPattern -Ref $Ref) { return $false }
  if (Test-InvalidGitRefSuffix -Ref $Ref) { return $false }
  return $true
}

<#
.SYNOPSIS
  Validates that a URL uses an allowed scheme and is well-formed.
.PARAMETER Url
  URL string to validate.
.PARAMETER AllowedSchemes
  Permitted URI schemes (default: https, http).
#>
function Test-SafeUrl {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [string]$Url,
    [string[]]$AllowedSchemes = @('https', 'http')
  )

  if ([string]::IsNullOrWhiteSpace($Url)) { return $false }
  if ($Url -match '^\s*-') { return $false }

  $uri = $null
  if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$uri)) {
    return $false
  }

  if (-not $AllowedSchemes -or $AllowedSchemes.Count -eq 0) {
    return $true
  }

  return ($AllowedSchemes -contains $uri.Scheme)
}

<#
.SYNOPSIS
  Tests whether a path is contained within a root directory.
.PARAMETER Path
  Path to check.
.PARAMETER Root
  Root directory that must be a prefix of Path.
#>
function Test-PathUnderRoot {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Path,
    [Parameter(Mandatory)]
    [string]$Root
  )

  try {
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    $rootFull = [System.IO.Path]::GetFullPath($Root)
  } catch {
    return $false
  }

  $sep = [System.IO.Path]::DirectorySeparatorChar
  $comparison = if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    [System.StringComparison]::OrdinalIgnoreCase
  } else {
    [System.StringComparison]::Ordinal
  }
  $volumeRoot = [System.IO.Path]::GetPathRoot($rootFull)
  $rootNormalized = if ($rootFull.Length -gt $volumeRoot.Length) { $rootFull.TrimEnd($sep) } else { $rootFull }
  $pathNormalized = if ($pathFull.Length -gt ([System.IO.Path]::GetPathRoot($pathFull)).Length) { $pathFull.TrimEnd($sep) } else { $pathFull }
  if ($pathNormalized.Equals($rootNormalized, $comparison)) { return $true }
  $rootPrefix = $rootNormalized.TrimEnd($sep) + $sep
  return $pathNormalized.StartsWith($rootPrefix, $comparison)
}

<#
.SYNOPSIS
  Tests whether a Windows filesystem path is protected from untrusted writers.
.DESCRIPTION
  Uses stable SIDs rather than localized account names. The protected path must
  be owned by, and grant write-capable access only to, SYSTEM, BUILTIN\Administrators,
  or Windows Modules Installer (TrustedInstaller). Optional ancestor checks
  reject an untrusted principal that can delete/replace a protected descendant.
  Non-Windows hosts return true so portable parsing and unit tests remain usable.
#>
function Get-TrustedWindowsAclPolicy {
  return [pscustomobject]@{
    TrustedSids = @{
      'S-1-5-18' = $true
      'S-1-5-32-544' = $true
      'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' = $true
    }
    WriteMask = [System.Security.AccessControl.FileSystemRights]::WriteData -bor
      [System.Security.AccessControl.FileSystemRights]::AppendData -bor
      [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
      [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
      [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
      [System.Security.AccessControl.FileSystemRights]::Delete -bor
      [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
      [System.Security.AccessControl.FileSystemRights]::TakeOwnership
    AncestorReplacementMask = [System.Security.AccessControl.FileSystemRights]::Delete -bor
      [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
      [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
      [System.Security.AccessControl.FileSystemRights]::TakeOwnership
  }
}

function Test-UntrustedAclWriteAccess {
  param($Acl, [hashtable]$TrustedSids, [int64]$EffectiveMask)

  foreach ($rule in @($Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
    if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
    if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
    $sid = [string]$rule.IdentityReference.Value
    if ($TrustedSids.ContainsKey($sid)) { continue }
    if (([int64]$rule.FileSystemRights -band $EffectiveMask) -ne 0) { return $true }
  }
  return $false
}

function Test-TrustedWindowsAclItem {
  param($Item, [hashtable]$TrustedSids, [int64]$EffectiveMask)

  if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
  $acl = Get-Acl -LiteralPath $Item.FullName -ErrorAction Stop
  $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  if (-not $TrustedSids.ContainsKey($ownerSid)) { return $false }
  return -not (Test-UntrustedAclWriteAccess -Acl $acl -TrustedSids $TrustedSids -EffectiveMask $EffectiveMask)
}

function Get-TrustedAclParentPath {
  param([Parameter(Mandatory)]$Item)

  $parent = Split-Path -Parent $Item.FullName
  if ([string]::IsNullOrWhiteSpace($parent)) { return $null }
  if ([string]::Equals($parent, $Item.FullName, [System.StringComparison]::OrdinalIgnoreCase)) { return $null }
  return $parent
}

function Test-TrustedWindowsPathAcl {
  [CmdletBinding()]
  [OutputType([bool])]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$CheckAncestors
  )

  if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { return $true }

  try {
    $policy = Get-TrustedWindowsAclPolicy
    $current = (Get-Item -LiteralPath $Path -Force -ErrorAction Stop).FullName
    $isProtectedItem = $true
    while (-not [string]::IsNullOrWhiteSpace($current)) {
      $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
      $mask = if ($isProtectedItem) { $policy.WriteMask } else { $policy.AncestorReplacementMask }
      if (-not (Test-TrustedWindowsAclItem -Item $item -TrustedSids $policy.TrustedSids -EffectiveMask $mask)) { return $false }
      if (-not $CheckAncestors) { break }
      $current = Get-TrustedAclParentPath -Item $item
      $isProtectedItem = $false
    }
    return $true
  } catch {
    Write-Verbose ("Windows ACL validation failed for '{0}': {1}" -f $Path, $_.Exception.Message)
    return $false
  }
}

<#
.SYNOPSIS
  Throws when a Windows path does not have a trusted ACL.
.DESCRIPTION
  Applies the shared ACL validation so security-sensitive callers fail closed.
#>
function Assert-TrustedWindowsPathAcl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$CheckAncestors
  )

  if (-not (Test-TrustedWindowsPathAcl -Path $Path -CheckAncestors:$CheckAncestors)) {
    throw "Path ACL is not trusted for privileged execution: $Path"
  }
  return (Get-Item -LiteralPath $Path -Force -ErrorAction Stop)
}

<#
.SYNOPSIS
  Tests whether a root or any path component beneath it is a reparse point.
.DESCRIPTION
  Walks the lexical root-to-leaf path instead of checking only the final item.
  Missing, invalid, or out-of-root paths return true so callers fail closed.
.PARAMETER Path
  Existing path to inspect.
.PARAMETER Root
  Existing trusted root containing Path.
#>
function Get-NormalizedReparseRoot {
  param([Parameter(Mandatory)][string]$Root)

  $separatorChars = @([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
  $volumeRoot = [System.IO.Path]::GetPathRoot($Root)
  $normalized = $Root
  while ($normalized.Length -gt $volumeRoot.Length -and $separatorChars -contains $normalized[$normalized.Length - 1]) {
    $normalized = $normalized.Substring(0, $normalized.Length - 1)
  }
  return $normalized
}

function Test-ReparsePointPathSegments {
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Root)

  $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
  if ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { return $true }
  $relativePath = $Path.Substring($Root.Length).TrimStart(@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar))
  $currentPath = $Root
  foreach ($segment in @($relativePath -split '[/\\]' | Where-Object { $_ })) {
    $currentPath = Join-Path $currentPath $segment
    if ((Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { return $true }
  }
  return $false
}

function Test-PathContainsReparsePoint {
  [CmdletBinding()]
  [OutputType([bool])]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Root
  )

  try {
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    $rootFull = [System.IO.Path]::GetFullPath($Root)
  } catch {
    return $true
  }

  if (-not (Test-PathUnderRoot -Path $pathFull -Root $rootFull)) {
    return $true
  }

  try {
    $rootNormalized = Get-NormalizedReparseRoot -Root $rootFull
    return (Test-ReparsePointPathSegments -Path $pathFull -Root $rootNormalized)
  } catch {
    return $true
  }

  return $false
}

<#
.SYNOPSIS
  Tests whether a local output-file path is safe to create or overwrite.
.DESCRIPTION
  Rejects traversal, UNC/device paths, directories, and existing reparse
  points. For a new file it validates the nearest existing parent. This
  predicate never creates directories or otherwise changes filesystem state.
#>
function Test-SafeOutputPathInput {
  param([Parameter(Mandatory)][string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
  if (Test-PathTraversal -Path $Path) { return $false }
  return $Path -notmatch '^[\\/]{2}'
}

function Get-SafeOutputPathInfo {
  param([Parameter(Mandatory)][string]$Path)

  $providerPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
  if ($providerPath -match '^[\\/]{2}') { return $null }
  $fullPath = [System.IO.Path]::GetFullPath($providerPath)
  $parentPath = [System.IO.Path]::GetDirectoryName($fullPath)
  if ([string]::IsNullOrWhiteSpace($parentPath)) { return $null }
  return [pscustomobject]@{ FullPath = $fullPath; ParentPath = $parentPath }
}

function Test-ExistingSafeOutputFilePath {
  param([Parameter(Mandatory)][string]$FullPath)

  $item = Get-Item -LiteralPath $FullPath -Force -ErrorAction Stop
  if ($item.PSIsContainer) { return $false }
  if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { return $true }
  $root = [System.IO.Path]::GetPathRoot($FullPath)
  return -not (Test-PathContainsReparsePoint -Path $FullPath -Root $root)
}

function Test-NewSafeOutputFileParentPath {
  param([Parameter(Mandatory)][string]$ParentPath)

  $existingParent = $ParentPath
  while (-not (Test-Path -LiteralPath $existingParent -PathType Container)) {
    $nextParent = [System.IO.Path]::GetDirectoryName($existingParent)
    if ([string]::IsNullOrWhiteSpace($nextParent)) { return $false }
    if ($nextParent -eq $existingParent) { return $false }
    $existingParent = $nextParent
  }
  $root = [System.IO.Path]::GetPathRoot($existingParent)
  return -not (Test-PathContainsReparsePoint -Path $existingParent -Root $root)
}

function Test-SafeOutputFilePath {
  [CmdletBinding()]
  [OutputType([bool])]
  param(
    [Parameter(Mandatory)][string]$Path
  )

  if (-not (Test-SafeOutputPathInput -Path $Path)) { return $false }

  try {
    $pathInfo = Get-SafeOutputPathInfo -Path $Path
    if ($null -eq $pathInfo) { return $false }
    if (Test-Path -LiteralPath $pathInfo.FullPath) { return (Test-ExistingSafeOutputFilePath -FullPath $pathInfo.FullPath) }
    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { return $true }
    return (Test-NewSafeOutputFileParentPath -ParentPath $pathInfo.ParentPath)
  } catch {
    return $false
  }
}

<#
.SYNOPSIS
  Validates an output path and creates its parent directory when necessary.
.DESCRIPTION
  Performs pure validation before creation and repeats validation afterward so
  callers do not write through traversal, network, device, or reparse paths.
#>
function Initialize-SafeOutputFilePath {
  [CmdletBinding()]
  [OutputType([bool])]
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-SafeOutputFilePath -Path $Path)) {
    return $false
  }

  try {
    $providerPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $fullPath = [System.IO.Path]::GetFullPath($providerPath)
    $parentPath = [System.IO.Path]::GetDirectoryName($fullPath)
    if (-not (Test-Path -LiteralPath $parentPath -PathType Container)) {
      [void][System.IO.Directory]::CreateDirectory($parentPath)
    }
  } catch {
    return $false
  }

  return (Test-SafeOutputFilePath -Path $Path)
}

<#
.SYNOPSIS
  Tests a WinGet private-source type and endpoint against the local policy.
.DESCRIPTION
  The endpoint must be absolute HTTPS with a path only: credentials, query,
  and fragment components are not permitted. Configure private-source
  authentication out of band through the organization-managed WinGet or OS
  credential mechanism. The endpoint must not name a local, loopback,
  wildcard, or link-local address. DNS is deliberately not resolved here so
  validation does not introduce a network side effect.
#>
function Test-SupportedWingetPrivateSourceType {
  param([AllowNull()][string]$Url, [AllowNull()][string]$Type)

  if ([string]::IsNullOrWhiteSpace($Url)) { return $false }
  return $Type -in @('Microsoft.Rest', 'Microsoft.PreIndexed.Package')
}

function Get-ValidWingetPrivateSourceUri {
  param([Parameter(Mandatory)][string]$Url)

  $uri = $null
  if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$uri)) { return $null }
  if (-not $uri.IsAbsoluteUri) { return $null }
  if ($uri.Scheme -ne 'https') { return $null }
  if (-not [string]::IsNullOrWhiteSpace($uri.UserInfo)) { return $null }
  if (-not [string]::IsNullOrWhiteSpace($uri.Query)) { return $null }
  if (-not [string]::IsNullOrWhiteSpace($uri.Fragment)) { return $null }
  return $uri
}

function Test-ValidWingetPrivateSourceHost {
  param([Parameter(Mandatory)][string]$SourceHost)

  if ([string]::IsNullOrWhiteSpace($SourceHost)) { return $false }
  if ($SourceHost -eq 'localhost') { return $false }
  return -not $SourceHost.EndsWith('.local', [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-BlockedSpecialIpAddress {
  param([Parameter(Mandatory)][System.Net.IPAddress]$Address)

  if ([System.Net.IPAddress]::IsLoopback($Address)) { return $true }
  if ($Address.Equals([System.Net.IPAddress]::Any)) { return $true }
  if ($Address.Equals([System.Net.IPAddress]::IPv6Any)) { return $true }
  return $Address.IsIPv6LinkLocal
}

function Test-BlockedIpv6PrivateAddress {
  param([Parameter(Mandatory)][byte[]]$Bytes)

  return $Bytes.Length -eq 16 -and (($Bytes[0] -band 0xFE) -eq 0xFC)
}

function ConvertTo-NormalizedIpAddressBytes {
  param([Parameter(Mandatory)][byte[]]$Bytes)

  if ($Bytes.Length -ne 16) { return ,$Bytes }
  if ($Bytes[10] -ne 0xFF -or $Bytes[11] -ne 0xFF) { return ,$Bytes }
  foreach ($index in 0..9) {
    if ($Bytes[$index] -ne 0) { return ,$Bytes }
  }
  return ,$Bytes[12..15]
}

function Test-PrivateIpv4FirstOctet {
  param([Parameter(Mandatory)][byte]$FirstOctet)

  return $FirstOctet -eq 10 -or $FirstOctet -eq 127
}

function Test-PrivateIpv4LinkLocalAddress {
  param([Parameter(Mandatory)][byte[]]$Bytes)

  return $Bytes[0] -eq 169 -and $Bytes[1] -eq 254
}

function Test-PrivateIpv4Rfc1918Address {
  param([Parameter(Mandatory)][byte[]]$Bytes)

  if ($Bytes[0] -eq 192) { return $Bytes[1] -eq 168 }
  if ($Bytes[0] -eq 172) { return $Bytes[1] -ge 16 -and $Bytes[1] -le 31 }
  return $false
}

function Test-PrivateIpv4Address {
  param([Parameter(Mandatory)][byte[]]$Bytes)

  if ($Bytes.Length -ne 4) { return $false }
  if (Test-PrivateIpv4FirstOctet -FirstOctet $Bytes[0]) { return $true }
  if (Test-PrivateIpv4LinkLocalAddress -Bytes $Bytes) { return $true }
  return (Test-PrivateIpv4Rfc1918Address -Bytes $Bytes)
}

function Test-BlockedWingetPrivateSourceAddress {
  param([Parameter(Mandatory)][string]$SourceHost)

  $address = $null
  if (-not [System.Net.IPAddress]::TryParse($SourceHost, [ref]$address)) { return $false }
  if (Test-BlockedSpecialIpAddress -Address $address) { return $true }
  $bytes = $address.GetAddressBytes()
  if (Test-BlockedIpv6PrivateAddress -Bytes $bytes) { return $true }
  return (Test-PrivateIpv4Address -Bytes (ConvertTo-NormalizedIpAddressBytes -Bytes $bytes))
}

function Test-WingetPrivateSourceDefinition {
  [CmdletBinding()]
  [OutputType([bool])]
  param(
    [AllowNull()][string]$Url,
    [AllowNull()][string]$Type
  )

  if (-not (Test-SupportedWingetPrivateSourceType -Url $Url -Type $Type)) { return $false }
  $uri = Get-ValidWingetPrivateSourceUri -Url $Url
  if ($null -eq $uri) { return $false }
  $sourceHost = $uri.Host.TrimEnd('.')
  if (-not (Test-ValidWingetPrivateSourceHost -SourceHost $sourceHost)) { return $false }
  return -not (Test-BlockedWingetPrivateSourceAddress -SourceHost $sourceHost)
}

<#
.SYNOPSIS
  Reads a UTF-8 text file through a stable, size-bounded file handle.
.DESCRIPTION
  Opens the file with read-only sharing so it cannot be replaced or modified
  while its size is checked and its text is consumed. Invalid UTF-8 fails
  closed instead of being silently replaced.
#>
function Get-BoundedUtf8FileContent {
  [CmdletBinding()]
  [OutputType([string])]
  param(
    [Parameter(Mandatory)][string]$Path,
    [ValidateRange(1, 16777216)][int64]$MaximumBytes = 1048576
  )

  $stream = $null
  $reader = $null
  try {
    $providerPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if (-not (Test-Path -LiteralPath $providerPath -PathType Leaf)) {
      throw "File not found: $Path"
    }
    $stream = [System.IO.File]::Open(
      $providerPath,
      [System.IO.FileMode]::Open,
      [System.IO.FileAccess]::Read,
      [System.IO.FileShare]::Read
    )
    if ($stream.Length -gt $MaximumBytes) {
      throw "File exceeds the $MaximumBytes byte size limit."
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $reader = New-Object System.IO.StreamReader($stream, $utf8, $true)
    return $reader.ReadToEnd()
  } finally {
    if ($null -ne $reader) { $reader.Dispose() }
    elseif ($null -ne $stream) { $stream.Dispose() }
  }
}

<#
.SYNOPSIS
  Computes the SHA-256 hash of text.
.DESCRIPTION
  Uses a deterministic UTF-8 representation for integrity comparisons.
#>
function Get-TextSha256 {
  [CmdletBinding()]
  [OutputType([string])]
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = (New-Object System.Text.UTF8Encoding($false, $true)).GetBytes($Text)
    return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '')
  } finally {
    $sha.Dispose()
  }
}

Export-ModuleMember -Function `
  Test-PathTraversal, `
  Assert-NoPathTraversal, `
  Test-SafeScriptName, `
  Test-ValidGitRef, `
  Test-SafeUrl, `
  Test-PathUnderRoot, `
  Test-PathContainsReparsePoint, `
  Test-SafeOutputFilePath, `
  Initialize-SafeOutputFilePath, `
  Test-WingetPrivateSourceDefinition, `
  Test-TrustedWindowsPathAcl, `
  Assert-TrustedWindowsPathAcl, `
  Get-BoundedUtf8FileContent, `
  Get-TextSha256
