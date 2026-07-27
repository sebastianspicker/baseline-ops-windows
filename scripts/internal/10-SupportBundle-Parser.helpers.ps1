#requires -version 5.1
<#
.SYNOPSIS
Archive validation and extraction helpers for 10-SupportBundle-Parser.ps1.

.DESCRIPTION
Validates untrusted ZIP metadata, path boundaries, reparse points, entry counts,
and expansion limits before extraction. The parser isolates this logic so a
support bundle cannot escape or exhaust its designated working directory.
#>
# Validates the entire archive before extracting into a fresh administrator-only
# directory, preventing stale files and partial validation from mixing.
function Ensure-ExtractedWorkDir {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ZipPath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExtractRoot,
    [Parameter()][switch]$Force
  )
  # The extraction directory deliberately has no stable name. A stable directory
  # can retain files from a different archive, including after a failed extraction.
  $maxEntries = 2048
  # Refuse an oversized container before either hashing or opening it.  The
  # uncompressed limits below protect extraction; this limit protects the
  # validation path itself from an arbitrarily large archive.
  $maxArchiveBytes = 256MB
  $maxEntryBytes = 128MB
  $maxTotalBytes = 512MB
  $maxCompressionRatio = 100
  $dest = $null
  try {
    if ($Force.IsPresent) { Write-Verbose 'ForceExtract requested; a fresh extraction directory is always used.' }
    if (-not (Test-Path -LiteralPath $ZipPath -PathType Leaf)) { return $null }
    $zipItem = Get-Item -LiteralPath $ZipPath -Force -ErrorAction Stop
    if ($zipItem.Length -gt $maxArchiveBytes) {
      throw "ZIP archive exceeds $maxArchiveBytes bytes."
    }
    Test-NoReparsePointAncestor -Path $zipItem.FullName
    Initialize-TrustedExtractRoot -Path $ExtractRoot
    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $archiveStream = [System.IO.File]::Open($zipItem.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
      $archive = New-Object -TypeName System.IO.Compression.ZipArchive -ArgumentList @($archiveStream, [System.IO.Compression.ZipArchiveMode]::Read, $false)
      try {
        $entries = Get-ValidatedZipEntries -Archive $archive -MaxEntries $maxEntries -MaxEntryBytes $maxEntryBytes -MaxTotalBytes $maxTotalBytes -MaxCompressionRatio $maxCompressionRatio
        $archiveHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipItem.FullName -ErrorAction Stop).Hash.Substring(0, 16).ToLowerInvariant()
        $safeBaseName = ($zipItem.BaseName -replace '[^A-Za-z0-9._-]', '_')
        $dest = Join-Path $ExtractRoot ("{0}-{1}-{2}" -f $safeBaseName, $archiveHash, [guid]::NewGuid().ToString('N'))
        New-AdminOnlyDirectory -Path $dest
        Test-NoReparsePointAncestor -Path $dest
        [Int64]$extractedTotal = 0
        foreach ($entryInfo in $entries) {
          $targetPath = Join-Path $dest ($entryInfo.CanonicalPath -replace '/', [string][System.IO.Path]::DirectorySeparatorChar)
          if ($entryInfo.IsDirectory) {
            Ensure-AdminOnlyDirectoryTree -Path $targetPath -Root $dest
            continue
          }
          $parent = Split-Path -Path $targetPath -Parent
          Ensure-AdminOnlyDirectoryTree -Path $parent -Root $dest
          $entryStream = $entryInfo.Entry.Open()
          try {
            $output = [System.IO.File]::Open($targetPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            try {
              $buffer = New-Object byte[] 81920
              [Int64]$written = 0
              while (($read = $entryStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $written += $read
                if ($written -gt $maxEntryBytes -or $written -gt $entryInfo.Entry.Length) { throw "ZIP entry exceeded its validated size: $($entryInfo.CanonicalPath)" }
                $output.Write($buffer, 0, $read)
              }
              if ($written -ne $entryInfo.Entry.Length) { throw "ZIP entry size changed while extracting: $($entryInfo.CanonicalPath)" }
              $extractedTotal += $written
              if ($extractedTotal -gt $maxTotalBytes) { throw "ZIP extracted content exceeds $maxTotalBytes bytes." }
            } finally { $output.Dispose() }
          } finally { $entryStream.Dispose() }
        }
      } finally { $archive.Dispose() }
    } finally { $archiveStream.Dispose() }
    return $dest
  }
  catch {
    if ($dest -and (Test-Path -LiteralPath $dest -PathType Container)) { Remove-Item -LiteralPath $dest -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Warning ("Failed to safely extract ZIP: {0} ({1})" -f (ConvertTo-SafeDisplayPath $ZipPath), $_.Exception.Message)
    return $null
  }
}
# Walks every existing path component because validating only the leaf would
# still allow a junction or symlink higher in the extraction path.
function Test-NoReparsePointAncestor {
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path)
  $current = [System.IO.Path]::GetFullPath($Path)
  while ($current) {
    if (Test-Path -LiteralPath $current) {
      $attributes = [System.IO.File]::GetAttributes($current)
      if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse-point path component is not permitted: $current" }
    }
    $parent = Split-Path -Path $current -Parent
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) { break }
    $current = $parent
  }
}
function Set-AdminOnlyDirectoryAcl {
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path)
  if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) { return }
  $security = New-AdminOnlyDirectorySecurity
  $directory = New-Object System.IO.DirectoryInfo -ArgumentList $Path
  if ($PSVersionTable.PSEdition -eq 'Desktop') {
    [System.IO.Directory]::SetAccessControl($Path, $security)
    return
  }
  [System.IO.FileSystemAclExtensions]::SetAccessControl($directory, $security)
}
function New-AdminOnlyDirectorySecurity {
  [CmdletBinding()]
  param()
  $security = New-Object System.Security.AccessControl.DirectorySecurity
  $security.SetAccessRuleProtection($true, $false)
  $administrators = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
  $security.SetOwner($administrators)
  $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  $propagation = [System.Security.AccessControl.PropagationFlags]::None
  foreach ($sidValue in @('S-1-5-18', 'S-1-5-32-544')) {
    $sid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $sidValue
    $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritance, $propagation, [System.Security.AccessControl.AccessControlType]::Allow)
    [void]$security.AddAccessRule($rule)
  }
  return $security
}
function New-AdminOnlyDirectory {
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path)
  if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
    return
  }
  $security = New-AdminOnlyDirectorySecurity
  if ($PSVersionTable.PSEdition -eq 'Desktop') {
    [System.IO.Directory]::CreateDirectory($Path, $security) | Out-Null
  } else {
    [System.IO.FileSystemAclExtensions]::CreateDirectory($security, $Path) | Out-Null
  }
  $directory = New-Object System.IO.DirectoryInfo -ArgumentList $Path
  Assert-TrustedWindowsPathAcl -Path $directory.FullName | Out-Null
}
# Creates missing root components one at a time with protected ACLs, closing the
# create-before-protect window on privileged Windows extraction paths.
function Initialize-TrustedExtractRoot {
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path)
  $fullPath = [System.IO.Path]::GetFullPath($Path)
  if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
    [System.IO.Directory]::CreateDirectory($fullPath) | Out-Null
    Test-NoReparsePointAncestor -Path $fullPath
    return
  }

  $missing = New-Object System.Collections.Generic.List[string]
  $current = $fullPath
  while (-not (Test-Path -LiteralPath $current)) {
    [void]$missing.Add($current)
    $parent = Split-Path -Path $current -Parent
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) {
      throw 'Extraction root has no existing trusted ancestor.'
    }
    $current = $parent
  }
  $existing = Get-Item -LiteralPath $current -Force -ErrorAction Stop
  if (-not $existing.PSIsContainer -or ($existing.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
    throw 'Extraction root ancestor is not a regular directory.'
  }
  Test-NoReparsePointAncestor -Path $existing.FullName

  # A generic ancestor such as C:\ProgramData may legitimately allow users to
  # create children.  Checking from each atomically created protected child
  # applies only ancestor replacement rights to that generic policy anchor.
  for ($i = $missing.Count - 1; $i -ge 0; $i--) {
    New-AdminOnlyDirectory -Path $missing[$i]
    Test-NoReparsePointAncestor -Path $missing[$i]
    Assert-TrustedWindowsPathAcl -Path $missing[$i] -CheckAncestors | Out-Null
  }
  Test-NoReparsePointAncestor -Path $fullPath
  Assert-TrustedWindowsPathAcl -Path $fullPath -CheckAncestors | Out-Null
}
function Ensure-AdminOnlyDirectoryTree {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Root
  )
  $pathFull = [System.IO.Path]::GetFullPath($Path)
  $rootFull = [System.IO.Path]::GetFullPath($Root)
  if (-not (Test-PathUnderRoot -Path $pathFull -Root $rootFull)) {
    throw 'Extraction directory escaped its trusted root.'
  }
  if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
    [System.IO.Directory]::CreateDirectory($pathFull) | Out-Null
    Test-NoReparsePointAncestor -Path $pathFull
    return
  }

  Test-NoReparsePointAncestor -Path $rootFull
  Assert-TrustedWindowsPathAcl -Path $rootFull | Out-Null
  $relative = $pathFull.Substring($rootFull.Length).TrimStart([char[]]@([char]'/', [char]92))
  $current = $rootFull
  foreach ($segment in @($relative -split '[/\\]' | Where-Object { $_ })) {
    $current = Join-Path $current $segment
    if (Test-Path -LiteralPath $current) {
      $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
      if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw 'Extraction directory contains an unsafe path component.'
      }
      Assert-TrustedWindowsPathAcl -Path $item.FullName | Out-Null
    } else {
      New-AdminOnlyDirectory -Path $current
    }
  }
}
# Canonicalizes and bounds all entries before extraction so collisions, zip-slip,
# decompression bombs, and Windows path aliases fail as one atomic decision.
function Get-ValidatedZipEntries {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][System.IO.Compression.ZipArchive]$Archive,
    [Parameter(Mandatory)][Int32]$MaxEntries,
    [Parameter(Mandatory)][Int64]$MaxEntryBytes,
    [Parameter(Mandatory)][Int64]$MaxTotalBytes,
    [Parameter(Mandatory)][Int32]$MaxCompressionRatio
  )
  if ($Archive.Entries.Count -gt $MaxEntries) { throw "ZIP has more than $MaxEntries entries." }
  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $files = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $allPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $result = New-Object System.Collections.Generic.List[object]
  [Int64]$total = 0
  foreach ($entry in $Archive.Entries) {
    $rawName = $entry.FullName
    if ([string]::IsNullOrWhiteSpace($rawName) -or $rawName -match '[\x00-\x1f\x7f]') { throw 'ZIP entry has an empty or control-character path.' }
    $normalName = $rawName -replace '\\', '/'
    if ([System.IO.Path]::IsPathRooted($normalName) -or $normalName.StartsWith('/') -or $normalName -match '^[A-Za-z]:') { throw "ZIP entry has a rooted path: $rawName" }
    $isDirectory = $normalName.EndsWith('/')
    $parts = @($normalName.TrimEnd('/').Split('/'))
    if ($parts.Count -eq 0 -or @($parts | Where-Object { [string]::IsNullOrWhiteSpace($_) -or $_ -eq '.' -or $_ -eq '..' }).Count -gt 0) { throw "ZIP entry has a traversal or empty path component: $rawName" }
    foreach ($part in $parts) {
      # Windows treats ':' as an alternate-data-stream separator and silently
      # normalizes trailing spaces/dots.  Either behavior could make two ZIP
      # entries target the same extracted object.
      if ($part.Contains(':') -or $part.EndsWith(' ') -or $part.EndsWith('.')) {
        throw "ZIP entry has an unsafe Windows path component: $rawName"
      }
      $deviceBase = $part.Split('.')[0]
      if ($deviceBase -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
        throw "ZIP entry uses a reserved Windows device name: $rawName"
      }
    }
    $canonical = [string]::Join('/', $parts)
    if (-not $seen.Add($canonical)) { throw "ZIP contains a duplicate canonical path: $canonical" }
    [void]$allPaths.Add($canonical)
    if (-not $isDirectory) {
      if ($entry.Length -gt $MaxEntryBytes) { throw "ZIP entry exceeds $MaxEntryBytes bytes: $canonical" }
      $total += $entry.Length
      if ($total -gt $MaxTotalBytes) { throw "ZIP uncompressed content exceeds $MaxTotalBytes bytes." }
      if (($entry.CompressedLength -eq 0 -and $entry.Length -gt 0) -or ($entry.CompressedLength -gt 0 -and ($entry.Length / [double]$entry.CompressedLength) -gt $MaxCompressionRatio)) { throw "ZIP compression ratio exceeds $MaxCompressionRatio:1: $canonical" }
      [void]$files.Add($canonical)
    }
    [void]$result.Add([pscustomobject]@{ Entry = $entry; CanonicalPath = $canonical; IsDirectory = $isDirectory })
  }
  foreach ($filePath in $files) {
    foreach ($path in $allPaths) {
      if ($path.StartsWith($filePath + '/', [System.StringComparison]::OrdinalIgnoreCase)) { throw "ZIP contains a file/directory conflict: $filePath" }
    }
  }
  # Do not wrap a generic list in @(...): PowerShell 7.5 raises an incompatible collection conversion error.
  return $result.ToArray()
}
