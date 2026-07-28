#requires -version 5.1
<#
.SYNOPSIS
Internal discovery, staging, and execution helpers for the Sysmon updater.

.DESCRIPTION
Resolves trusted Sysmon binaries, validates configuration policy, and stages
immutable inputs before invoking Sysmon. The entry script imports dependencies
and enables strict mode before dot-sourcing these implementation helpers.
#>

function Parse-Version([string]$s){
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  $m = [regex]::Match($s, '(\d+)\.(\d+)(?:\.(\d+))?')
  if (-not $m.Success) { return $null }
  return [pscustomobject]@{
    A   = [int]$m.Groups[1].Value
    B   = [int]$m.Groups[2].Value
    C   = if($m.Groups[3].Success){[int]$m.Groups[3].Value}else{0}
    Raw = $s
  }
}
function Cmp-Ver($x,$y){
  if (-not $x -and -not $y) { return 0 }
  if (-not $x) { return -1 }
  if (-not $y) { return 1 }
  foreach($k in 'A','B','C'){
    if ($x.$k -gt $y.$k){ return 1 }
    if ($x.$k -lt $y.$k){ return -1 }
  }
  return 0
}
function Resolve-SysmonExe {
  param([string]$Hint)
  if (-not [string]::IsNullOrWhiteSpace($Hint)) {
    if (-not (Test-Path -LiteralPath $Hint -PathType Leaf)) { return $null }
    if (-not (Test-TrustedSysmonExecutable -Path $Hint)) { return $null }
    return (Get-Item -LiteralPath $Hint -Force -ErrorAction Stop).FullName
  }
  foreach($svc in 'Sysmon64','Sysmon'){
    try {
      $s = Get-ItemProperty -Path ("HKLM:\SYSTEM\CurrentControlSet\Services\" + $svc) -ErrorAction Stop
      if ($s -and $s.ImagePath) {
        $img = [Environment]::ExpandEnvironmentVariables([string]$s.ImagePath)
        # Tokenize ImagePath so quoted executable paths are handled correctly.
        $nullRef = $null
        $tok = [System.Management.Automation.PSParser]::Tokenize($img, [ref]$nullRef) |
               Where-Object { $_.Type -in @('Command','CommandArgument') } |
               Select-Object -First 1
        if ($tok) {
          $exePath = $tok.Content.Trim('"')
          if (Test-Path -LiteralPath $exePath) { return $exePath }
        }
        # Fallback: best-effort extraction of "<drive>:\...\.exe".
        $m = [regex]::Match($img, '(?i)([a-z]:\\[^"]+?\.exe)')
        if ($m.Success) {
          $cand = $m.Groups[1].Value
          if (Test-Path -LiteralPath $cand) { return $cand }
        }
      }
      } catch {
        Write-Verbose ("Sysmon service image path probe failed for '{0}': {1}" -f $svc,$_.Exception.Message)
      }
  }
  $roots = @(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows),
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
  ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
  foreach ($root in $roots) {
    foreach ($relativeCandidate in @('Sysmon64.exe', 'Sysmon.exe', 'Sysmon\Sysmon64.exe', 'Sysmon\Sysmon.exe')) {
      $candidate = [IO.Path]::GetFullPath((Join-Path $root $relativeCandidate))
      $canonicalRoot = [IO.Path]::GetFullPath($root).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
      if (-not $candidate.StartsWith($canonicalRoot, [StringComparison]::OrdinalIgnoreCase)) { continue }
      if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
      $safe = $true
      $current = $canonicalRoot
      foreach ($segment in @($candidate.Substring($canonicalRoot.Length) -split '[/\\]' | Where-Object { $_ })) {
        $current = Join-Path $current $segment
        if ((Get-Item -LiteralPath $current -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) { $safe = $false; break }
      }
      if ($safe) { return $candidate }
    }
  }
  return $null
}
function Get-SysmonServiceName(){
  foreach($n in 'Sysmon64','Sysmon'){
    try { $null = Get-Service -Name $n -ErrorAction Stop; return $n } catch {
      Write-Verbose ("Sysmon service name probe failed for '{0}': {1}" -f $n,$_.Exception.Message)
    }
  }
  return $null
}
function Get-SysmonEngineVersion([string]$Exe){
  if (-not $Exe -or -not (Test-Path -LiteralPath $Exe)) { return $null }
  # Primary: file version metadata.
  try {
    $pv = (Get-Item -LiteralPath $Exe -ErrorAction Stop).VersionInfo.ProductVersion
    $v  = Parse-Version $pv
    if ($v) { return $v }
  } catch {
    Write-Verbose ("Sysmon file version metadata read failed for '{0}': {1}" -f $Exe,$_.Exception.Message)
  }
  # Version discovery is deliberately metadata-only. Never execute a binary
  # merely to decide whether it is safe to execute later.
  return $null
}
function ConvertTo-TrustedStateSidValue {
  param([Parameter(Mandatory)]$IdentityReference)
  try {
    if ($IdentityReference -is [Security.Principal.SecurityIdentifier]) { return $IdentityReference.Value }
    if ($IdentityReference -is [string]) {
      $IdentityReference = New-Object Security.Principal.NTAccount($IdentityReference)
    }
    return $IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
  } catch { throw "State ACL contains an identity that cannot be resolved to a SID: $IdentityReference" }
}
# Rejects state paths writable by identities other than SYSTEM or Administrators
# so persisted hashes cannot be forged between updater runs.
function Assert-TrustedStateAcl {
  param([Parameter(Mandatory)][string]$Path)
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return }
  $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  $trustedSids = @('S-1-5-18','S-1-5-32-544')
  $ownerSid = ConvertTo-TrustedStateSidValue -IdentityReference $acl.Owner
  if ($trustedSids -notcontains $ownerSid) { throw "Sysmon state path '$Path' has an untrusted owner SID '$ownerSid'." }
  if (-not $acl.AreAccessRulesProtected) { throw "Sysmon state path '$Path' must use a protected ACL." }
  $writeMask = [Security.AccessControl.FileSystemRights]::WriteData -bor
    [Security.AccessControl.FileSystemRights]::AppendData -bor
    [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
    [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
    [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [Security.AccessControl.FileSystemRights]::Delete -bor
    [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [Security.AccessControl.FileSystemRights]::TakeOwnership
  foreach ($accessRule in @($acl.Access)) {
    if ($accessRule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
    if (($accessRule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
    if (([int64]$accessRule.FileSystemRights -band [int64]$writeMask) -eq 0) { continue }
    $sid = ConvertTo-TrustedStateSidValue -IdentityReference $accessRule.IdentityReference
    if ($trustedSids -notcontains $sid) { throw "Sysmon state path '$Path' grants write access to untrusted SID '$sid'." }
  }
}
function New-TrustedStateAcl {
  param([switch]$Directory)
  $administrators = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
  if ($Directory) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
  } else {
    $acl = New-Object Security.AccessControl.FileSecurity
    $inheritance = [Security.AccessControl.InheritanceFlags]::None
  }
  $acl.SetOwner($administrators)
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($sid in @($administrators,$system)) {
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid,[Security.AccessControl.FileSystemRights]::FullControl,$inheritance,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
    [void]$acl.AddAccessRule($rule)
  }
  return $acl
}
function New-TrustedStateDirectory {
  param([Parameter(Mandatory)][string]$Path)
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return [IO.Directory]::CreateDirectory($Path) }
  $security = New-TrustedStateAcl -Directory
  if ($PSVersionTable.PSEdition -eq 'Desktop') { return [IO.Directory]::CreateDirectory($Path,$security) }
  return [IO.FileSystemAclExtensions]::CreateDirectory($security,$Path)
}
function Open-TrustedStateFile {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][IO.FileMode]$Mode,
    [Parameter(Mandatory)][IO.FileShare]$Share
  )
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return [IO.File]::Open($Path,$Mode,[IO.FileAccess]::ReadWrite,$Share) }
  $security = New-TrustedStateAcl
  $rights = [Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Write
  $fileInfo = New-Object IO.FileInfo($Path)
  if ($PSVersionTable.PSEdition -eq 'Desktop') { return $fileInfo.Create($Mode,$rights,$Share,4096,[IO.FileOptions]::WriteThrough,$security) }
  return [IO.FileSystemAclExtensions]::Create($fileInfo,$Mode,$rights,$Share,4096,[IO.FileOptions]::WriteThrough,$security)
}
# Validates the complete persisted-state shape before any field influences an
# update decision, preventing permissive JSON deserialization from adding state.
function Assert-SysmonStateSchema {
  param([Parameter(Mandatory)]$State)
  if ($State -isnot [pscustomobject]) { throw 'Sysmon updater state root must be an object.' }
  $allowedRoot = @('Version','Time','Host','Engine','Observed','Applied','Runtime')
  if (@($State.PSObject.Properties.Name | Where-Object { $allowedRoot -notcontains $_ }).Count -gt 0 -or @($State.PSObject.Properties.Name).Count -ne $allowedRoot.Count) { throw 'Sysmon updater state has missing or unsupported fields.' }
  if ($State.Version -isnot [int] -and $State.Version -isnot [long]) { throw 'Sysmon updater state Version must be an integer.' }
  if ([int64]$State.Version -ne 2) { throw 'Sysmon updater state Version is unsupported.' }
  foreach ($field in @('Time','Host')) { if ($State.$field -isnot [string] -or $State.$field.Length -gt 512) { throw "Sysmon updater state $field must be a bounded string." } }
  $schemas = @{
    Engine = @('Version','ExePath','Service')
    Observed = @('Path','DesiredSha256','Source','Valid')
    Applied = @('Sha256')
    Runtime = @('CurrentDumpSha256')
  }
  foreach ($name in $schemas.Keys) {
    $value = $State.$name
    if ($value -isnot [pscustomobject]) { throw "Sysmon updater state $name must be an object." }
    $fields = $schemas[$name]
    if (@($value.PSObject.Properties.Name | Where-Object { $fields -notcontains $_ }).Count -gt 0 -or @($value.PSObject.Properties.Name).Count -ne $fields.Count) { throw "Sysmon updater state $name has missing or unsupported fields." }
  }
  foreach ($field in @('Version','ExePath','Service')) { $value = $State.Engine.$field; if ($null -ne $value -and ($value -isnot [string] -or $value.Length -gt 4096)) { throw "Sysmon updater state Engine.$field has an invalid type or length." } }
  foreach ($field in @('Path','Source')) { $value = $State.Observed.$field; if ($value -isnot [string] -or $value.Length -gt 4096) { throw "Sysmon updater state Observed.$field has an invalid type or length." } }
  if ($State.Observed.Valid -isnot [bool]) { throw 'Sysmon updater state Observed.Valid must be boolean.' }
  foreach ($hash in @($State.Observed.DesiredSha256,$State.Applied.Sha256,$State.Runtime.CurrentDumpSha256)) {
    if ($null -ne $hash -and ($hash -isnot [string] -or $hash -notmatch '^[a-fA-F0-9]{64}$')) { throw 'Sysmon updater state SHA256 fields must be null or exactly 64 hexadecimal characters.' }
  }
}
function Load-JsonOrDefault {
  param(
    [string]$Path,
    [hashtable]$DefaultObject
  )
  if (-not $DefaultObject) { $DefaultObject = @{} }
  if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $DefaultObject }
  try {
    Assert-TrustedStateAcl -Path $Path
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $DefaultObject }
    $raw = Get-BoundedUtf8FileContent -Path $item.FullName -MaximumBytes 65536
    if ([string]::IsNullOrWhiteSpace($raw)) { return $DefaultObject }
    $obj = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $obj) { return $DefaultObject }
    Assert-SysmonStateSchema -State $obj
    return $obj
  } catch {
    return $DefaultObject
  }
}
# Treats the update manifest as untrusted input and returns an explicit validity
# result rather than allowing partial manifest data to drive remediation.
function Test-ManifestPolicy {
  param([string]$Path,[string]$SourceDirectory)
  $result = @{ Valid = $true; Manifest = $null; Reason = $null }
  if (-not $Path) { return $result }
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    $result.Valid = $false; $result.Reason = 'Manifest file does not exist.'; return $result
  }
  try {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Manifest must be a regular non-reparse file.' }
    $raw = Get-BoundedUtf8FileContent -Path $item.FullName -MaximumBytes 1048576
    if ([string]::IsNullOrWhiteSpace($raw)) { throw 'Manifest is empty.' }
    $manifest = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $manifest -or $manifest -is [string] -or $manifest -is [System.ValueType] -or $manifest -is [System.Collections.IEnumerable]) {
      throw 'Manifest root must be an object.'
    }
    $manifestPropertyNames = @{}
    foreach ($property in $manifest.PSObject.Properties) {
      $normalizedPropertyName = $property.Name.ToLowerInvariant()
      if ($manifestPropertyNames.ContainsKey($normalizedPropertyName)) {
        throw ("Manifest contains duplicate property '{0}' (property names are case-insensitive)." -f $property.Name)
      }
      $manifestPropertyNames[$normalizedPropertyName] = $true
      if ($property.Name -inotmatch '^(MinEngine|AllowedHashes|Config)$') {
        throw ("Manifest contains unsupported property '{0}'." -f $property.Name)
      }
    }
    if ($manifest.PSObject.Properties['MinEngine'] -and $null -ne $manifest.MinEngine) {
      if ($manifest.MinEngine -isnot [string] -or -not (Parse-Version ([string]$manifest.MinEngine))) {
        throw 'Manifest MinEngine must be a version string.'
      }
    }
    if ($manifest.PSObject.Properties['AllowedHashes']) {
      if ($null -eq $manifest.AllowedHashes -or $manifest.AllowedHashes -is [string] -or $manifest.AllowedHashes -isnot [System.Collections.IEnumerable] -or @($manifest.AllowedHashes).Count -eq 0) {
        throw 'Manifest AllowedHashes must be an array of SHA256 hashes.'
      }
      foreach ($hash in @($manifest.AllowedHashes)) {
        if ($hash -isnot [string] -or $hash -notmatch '^[a-fA-F0-9]{64}$') {
          throw 'Manifest AllowedHashes must contain SHA256 hashes.'
        }
      }
    }
    if ($manifest.PSObject.Properties['Config'] -and $null -ne $manifest.Config) {
      if ($manifest.Config -is [string] -or $manifest.Config -is [System.ValueType] -or $manifest.Config -is [System.Collections.IEnumerable]) {
        throw 'Manifest Config must be an object.'
      }
      foreach ($property in $manifest.Config.PSObject.Properties) {
        if ($property.Name -inotmatch '^File$') { throw ("Manifest Config contains unsupported property '{0}'." -f $property.Name) }
      }
      if ($manifest.Config.PSObject.Properties['File'] -and $null -ne $manifest.Config.File) {
        $file = $manifest.Config.File
        if ($file -isnot [string] -or [string]::IsNullOrWhiteSpace($file)) {
          throw 'Manifest Config.File must be a non-empty string.'
        }
        if (-not $SourceDirectory -or -not (Test-Path -LiteralPath $SourceDirectory -PathType Container)) {
          throw 'Manifest Config.File requires an existing SourceDir.'
        }
        $sourceRoot = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $SourceDirectory -ErrorAction Stop).Path)
        $candidate = [IO.Path]::GetFullPath((Join-Path $sourceRoot $file))
        $rootWithSeparator = $sourceRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if ([IO.Path]::IsPathRooted($file) -or -not $candidate.StartsWith($rootWithSeparator, [StringComparison]::OrdinalIgnoreCase)) {
          throw 'Manifest Config.File must be a basename or a path beneath SourceDir.'
        }
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
          throw 'Manifest Config.File does not identify an existing file beneath SourceDir.'
        }
        $relativeCandidate = $candidate.Substring($rootWithSeparator.Length)
        $currentCandidate = $sourceRoot
        foreach ($segment in @($relativeCandidate -split '[/\\]' | Where-Object { $_ })) {
          $currentCandidate = Join-Path $currentCandidate $segment
          $candidateItem = Get-Item -LiteralPath $currentCandidate -Force -ErrorAction Stop
          if (($candidateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Manifest Config.File must not traverse a reparse point.'
          }
        }
      }
    }
    $result.Manifest = $manifest
  } catch {
    $result.Valid = $false; $result.Reason = $_.Exception.Message
  }
  return $result
}
function Select-ConfigFile([string]$Path,[string]$Dir,[string]$NameHint,[object]$Manifest){
  if ($Path -and (Test-Path -LiteralPath $Path)) { return (Get-Item -LiteralPath $Path) }
  if ($Manifest -and $Manifest.PSObject.Properties['Config'] -and $Manifest.Config -and $Manifest.Config.PSObject.Properties['File'] -and $Manifest.Config.File) {
    $m = [string]$Manifest.Config.File
    if ($Dir) {
      $cand = Join-Path $Dir $m
      if (Test-Path -LiteralPath $cand) { return (Get-Item -LiteralPath $cand) }
    }
    if ($Path) {
      $cand2 = Join-Path (Split-Path -Parent $Path) $m
      if (Test-Path -LiteralPath $cand2) { return (Get-Item -LiteralPath $cand2) }
    }
  }
  if ($Dir -and (Test-Path -LiteralPath $Dir)) {
    $all = @(Get-ChildItem -LiteralPath $Dir -Filter '*.xml' -File -ErrorAction SilentlyContinue)
    # ConfigNameHint is an operator hint, not a regular expression.  Treating
    # it literally prevents a caller supplied catastrophic regex and makes the
    # requested selection deterministic.
    if ($NameHint) { $all = @($all | Where-Object { $_.Name.IndexOf($NameHint, [StringComparison]::OrdinalIgnoreCase) -ge 0 }) }
    if (-not $all -or $all.Count -eq 0) { return $null }
    if ($NameHint -and $all.Count -ne 1) {
      throw "ConfigNameHint must select exactly one XML configuration; matched $($all.Count)."
    }
    $ranked = $all | ForEach-Object {
      $mm = [regex]::Match($_.Name,'v(\d+\.\d+(\.\d+)?)')
      [pscustomobject]@{
        File  = $_
        Score = if($mm.Success){ [double]($mm.Groups[1].Value -replace '\.','') } else { 0 }
        Time  = $_.LastWriteTimeUtc
      }
    }
    return ($ranked |
      Sort-Object -Property @{Expression='Score';Descending=$true}, @{Expression='Time';Descending=$true} |
      Select-Object -First 1).File
  }
  return $null
}
function Get-ConfigSnapshot {
  param([Parameter(Mandatory)][string]$Path)
  $maxBytes = 4MB
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (-not $item.PSIsContainer -and $item.Length -le $maxBytes) {
    $stream = [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
      $buffer = New-Object byte[] ([int]$item.Length)
      $offset = 0
      while ($offset -lt $buffer.Length) {
        $read = $stream.Read($buffer, $offset, $buffer.Length - $offset)
        if ($read -le 0) { throw 'Config file changed while it was being read.' }
        $offset += $read
      }
      if ($stream.ReadByte() -ne -1) { throw 'Config file exceeds the maximum supported size.' }
      $hash = Get-BytesSha256 -Bytes $buffer
      return [pscustomobject]@{ Path = $item.FullName; Bytes = $buffer; Sha256 = $hash }
    } finally { $stream.Dispose() }
  }
  throw 'Config file must be a leaf no larger than 4 MiB.'
}
function Get-BytesSha256 {
  param([Parameter(Mandatory)][byte[]]$Bytes)
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes)) -replace '-','').ToLowerInvariant() } finally { $sha.Dispose() }
}
function Validate-ConfigXml([byte[]]$Bytes){
  $stream = $null
  $reader = $null
  try {
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 4MB
    $stream = New-Object System.IO.MemoryStream(,$Bytes)
    $reader = [System.Xml.XmlReader]::Create($stream, $settings)
    $x = New-Object System.Xml.XmlDocument
    $x.XmlResolver = $null
    $x.Load($reader)
    if (-not $x) { return $false,"empty xml" }
    $root = $x.DocumentElement
    if (-not $root) { return $false,"no root element" }
    if ($root.Name -notin @('Sysmon','sysmon')) { return $false,("unexpected root: " + $root.Name) }
    $sv = $root.GetAttribute('schemaversion')
    if ($sv) { return $true, ("schema=" + $sv) }
    return $true, "schema=n/a"
  } catch {
    return $false, $_.Exception.Message
  } finally {
    if ($null -ne $reader) { $reader.Dispose() }
    if ($null -ne $stream) { $stream.Dispose() }
  }
}
# Writes configuration bytes to a fresh file and retains the stream so the exact
# validated content remains pinned until Sysmon has consumed it.
function New-StagedConfigFile {
  param([Parameter(Mandatory)][byte[]]$Bytes)
  $directory = [IO.Path]::GetTempPath()
  for ($attempt = 0; $attempt -lt 10; $attempt++) {
    $path = Join-Path $directory ('.sysmon-config-' + [guid]::NewGuid().ToString('N') + '.xml')
    try {
      $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
      $stream.Write($Bytes, 0, $Bytes.Length)
      $stream.Flush($true)
      $stream.Position = 0
      return [pscustomobject]@{ Path = $path; Stream = $stream }
    } catch [IO.IOException] { continue }
  }
  throw 'Could not create a private staged Sysmon configuration file.'
}
# Verifies file shape, path components, signature publisher, and original name;
# a matching basename alone is insufficient for privileged execution.
function Test-TrustedSysmonExecutable {
  param([Parameter(Mandatory)][string]$Path)
  try {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $false }
    if ($item.Name -inotmatch '^Sysmon(?:64)?\.exe$') { return $false }
    $fullPath = [IO.Path]::GetFullPath($item.FullName)
    $pathRoot = [IO.Path]::GetPathRoot($fullPath)
    $relativePath = $fullPath.Substring($pathRoot.Length)
    $currentPath = $pathRoot
    foreach ($segment in @($relativePath -split '[/\\]' | Where-Object { $_ })) {
      $currentPath = Join-Path $currentPath $segment
      $component = Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop
      if ($component.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
    }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
      $signature = Get-AuthenticodeSignature -LiteralPath $item.FullName -ErrorAction Stop
      if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or $signature.SignerCertificate.Subject -notmatch '(?i)(?:^|,\s*)O=Microsoft Corporation(?:,|$)') { return $false }
      if ([string]$item.VersionInfo.OriginalFilename -notmatch '(?i)^Sysmon(?:64)?\.exe$') { return $false }
    }
    return $true
  } catch { return $false }
}
# Copies a locked, trusted Sysmon binary into a private stage and verifies its
# hash, binding later execution to the bytes that passed identity checks.
function New-StagedTrustedSysmonExecutable {
  param([Parameter(Mandatory)][string]$Path)
  # Keep the source locked across its signature validation and byte-for-byte
  # snapshot.  The staged copy is CreateNew and remains read-locked until the
  # native child has exited, so neither path can be swapped between trust and
  # execution.
  $source = $null
  $staged = $null
  $stagePath = $null
  $stageDirectory = $null
  try {
    $source = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    if (-not (Test-TrustedSysmonExecutable -Path $Path)) { throw 'Sysmon executable did not pass trusted executable validation.' }
    if ($source.Length -le 0 -or $source.Length -gt 256MB) { throw 'Sysmon executable has an unsupported size.' }
    $sourceBytes = New-Object byte[] ([int]$source.Length)
    $offset = 0
    while ($offset -lt $sourceBytes.Length) {
      $read = $source.Read($sourceBytes, $offset, $sourceBytes.Length - $offset)
      if ($read -le 0) { throw 'Sysmon executable changed while it was being read.' }
      $offset += $read
    }
    if ($source.ReadByte() -ne -1) { throw 'Sysmon executable changed while it was being read.' }
    $sourceHash = Get-BytesSha256 -Bytes $sourceBytes
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
      $stageDirectory = Join-Path ([IO.Path]::GetTempPath()) ('.sysmon-exe-' + [guid]::NewGuid().ToString('N'))
      try {
        [void][IO.Directory]::CreateDirectory($stageDirectory)
        $directoryItem = Get-Item -LiteralPath $stageDirectory -Force -ErrorAction Stop
        if ($directoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'The staged Sysmon directory is a reparse point.' }
        # Preserve the trusted executable's canonical basename. Sysmon uses the
        # Sysmon/Sysmon64 identity when installing or updating its service.
        $stagePath = Join-Path $stageDirectory ([IO.Path]::GetFileName($Path))
        $staged = [IO.File]::Open($stagePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
        $staged.Write($sourceBytes, 0, $sourceBytes.Length)
        $staged.Flush($true)
        $staged.Position = 0
        break
      } catch [IO.IOException] {
        if ($stageDirectory) { Remove-Item -LiteralPath $stageDirectory -Recurse -Force -ErrorAction SilentlyContinue }
        $stagePath = $null
        $stageDirectory = $null
        continue
      }
    }
    if ($null -eq $staged) { throw 'Could not create a private staged Sysmon executable.' }
    $stagedBytes = New-Object byte[] ([int]$staged.Length)
    $offset = 0
    while ($offset -lt $stagedBytes.Length) {
      $read = $staged.Read($stagedBytes, $offset, $stagedBytes.Length - $offset)
      if ($read -le 0) { throw 'Staged Sysmon executable could not be read back completely.' }
      $offset += $read
    }
    if ((Get-BytesSha256 -Bytes $stagedBytes) -ne $sourceHash) { throw 'Staged Sysmon executable hash did not match the trusted source.' }
    $staged.Position = 0
    return [pscustomobject]@{ Path = $stagePath; Directory = $stageDirectory; SourceStream = $source; Stream = $staged; Sha256 = $sourceHash }
  } catch {
    if ($staged) { $staged.Dispose() }
    if ($source) { $source.Dispose() }
    if ($stagePath) { Remove-Item -LiteralPath $stagePath -Force -ErrorAction SilentlyContinue }
    if ($stageDirectory) { Remove-Item -LiteralPath $stageDirectory -Recurse -Force -ErrorAction SilentlyContinue }
    throw
  }
}
# Keeps source and staged handles open through process completion, then removes
# the private executable so no reusable privileged launch surface remains.
function Invoke-StagedSysmonCommand {
  param(
    [Parameter(Mandatory)][string]$Exe,
    [Parameter(Mandatory)][string[]]$Arguments
  )
  $stage = $null
  try {
    $stage = New-StagedTrustedSysmonExecutable -Path $Exe
    return Invoke-NativeCommand -Command $stage.Path -Arguments $Arguments -CaptureOutput -Quiet -TimeoutSeconds 120 -MaxOutputBytes 1048576
  } finally {
    if ($stage) {
      $stage.Stream.Dispose()
      $stage.SourceStream.Dispose()
      Remove-Item -LiteralPath $stage.Path -Force -ErrorAction SilentlyContinue
      Remove-Item -LiteralPath $stage.Directory -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}
function Ensure-SysmonChannel {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([switch]$DoIt,[int]$MiB,[System.Management.Automation.PSCmdlet]$Cmdlet)
  $name = 'Microsoft-Windows-Sysmon/Operational'
  $ok=$true; $msgs=@()
  try {
    # S9 fix: use Invoke-Wevtutil wrapper with array-based args instead of direct wevtutil calls
    $glResult = Invoke-Wevtutil -Arguments @('gl', $name) -CaptureOutput
    $q = if ($glResult -and $glResult.Output) { $glResult.Output } else { '' }
    $enabled = ($q -match 'enabled:\s*true')
    if (-not $enabled) {
      # Event-channel enable/resize operations mutate host logging state, so
      # they use the parent script's ShouldProcess decision.
      if ($DoIt) {
        if ($Cmdlet.ShouldProcess($name, 'Enable Sysmon Operational event channel')) {
          $wevtOk = Invoke-Wevtutil -Arguments @('sl', $name, '/e:true')
          if ($wevtOk) {
            $msgs += "enabled"
          } else {
            $ok=$false
            $msgs += "enable failed"
          }
        } else {
          $ok=$false
          $msgs += "enable skipped by ShouldProcess"
        }
      } else { $ok=$false }
    }
    if ($MiB -gt 0) {
      $m = [regex]::Match($q,'maximum size:\s*(\d+)')
      $cur = if ($m.Success){ [int64]$m.Groups[1].Value } else { 0 }
      $want = [int64]$MiB * 1024 * 1024
      if ($cur -lt $want -and $DoIt) {
        if ($Cmdlet.ShouldProcess($name, "Resize Sysmon Operational event channel to $MiB MiB")) {
          $wevtOk = Invoke-Wevtutil -Arguments @('sl', $name, "/ms:$want")
          if ($wevtOk) {
            $msgs += ("size=" + $MiB + "MiB")
          } else {
            $ok=$false
            $msgs += "resize failed"
          }
        } else {
          $ok=$false
          $msgs += "resize skipped by ShouldProcess"
        }
      }
      elseif ($cur -lt $want) { $ok=$false }
    }
  } catch { $ok=$false; $msgs += $_.Exception.Message }
  return $ok, ($msgs -join '; ')
}
function Get-SysmonStatePath {
  param([string]$RequestedPath,[Parameter(Mandatory)][string]$FileName)
  $root = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'BaselineOpsForWindows\Sysmon'
  $expected = Join-Path $root $FileName
  if ($RequestedPath -and -not [string]::Equals([IO.Path]::GetFullPath($RequestedPath), [IO.Path]::GetFullPath($expected), [StringComparison]::OrdinalIgnoreCase)) {
    throw 'StatePath is fixed to the admin-owned CommonApplicationData Sysmon state directory.'
  }
  $toolkitRoot = Split-Path -Parent $root
  foreach ($part in @($toolkitRoot, $root)) {
    if (Test-Path -LiteralPath $part) {
      $item = Get-Item -LiteralPath $part -Force -ErrorAction Stop
      if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Sysmon state path must not contain reparse points.' }
      Assert-TrustedStateAcl -Path $item.FullName
    }
  }
  return $expected
}
function Initialize-SysmonStateDirectory([string]$directory) {
  $commonData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  if ([string]::IsNullOrWhiteSpace($commonData) -or -not (Test-PathUnderRoot -Path $directory -Root $commonData)) { throw 'Sysmon state directory is outside CommonApplicationData.' }
  $current = [IO.Path]::GetFullPath($commonData)
  $relative = [IO.Path]::GetFullPath($directory).Substring($current.TrimEnd([IO.Path]::DirectorySeparatorChar).Length).TrimStart([IO.Path]::DirectorySeparatorChar)
  foreach ($segment in @($relative -split '[/\\]' | Where-Object { $_ })) {
    $current = Join-Path $current $segment
    if (Test-Path -LiteralPath $current) {
      $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
      if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Sysmon state directory contains an unsafe path component.' }
      Assert-TrustedStateAcl -Path $item.FullName
    } else { [void](New-TrustedStateDirectory -Path $current) }
    Assert-TrustedStateAcl -Path $current
  }
}
function Write-State([string]$p,[hashtable]$obj){
  try {
    $json = $obj | ConvertTo-Json -Depth 8
    Assert-SysmonStateSchema -State ($json | ConvertFrom-Json -ErrorAction Stop)
    $directory = Split-Path -Parent $p
    Initialize-SysmonStateDirectory -directory $directory
    foreach ($protectedPath in @($p, $p + '.lock')) { if (Test-Path -LiteralPath $protectedPath) { $item = Get-Item -LiteralPath $protectedPath -Force -ErrorAction Stop; if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Sysmon state file or lock path is unsafe.' }; Assert-TrustedStateAcl -Path $item.FullName } }
    $stage = $null
    $lock = Open-TrustedStateFile -Path ($p + '.lock') -Mode OpenOrCreate -Share ([IO.FileShare]::None)
    try {
      Assert-TrustedStateAcl -Path ($p + '.lock')
      $stage = Join-Path $directory ('.state-' + [guid]::NewGuid().ToString('N') + '.json')
      $stageStream = Open-TrustedStateFile -Path $stage -Mode CreateNew -Share ([IO.FileShare]::None)
      try { $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json); $stageStream.Write($bytes,0,$bytes.Length); $stageStream.Flush($true) } finally { $stageStream.Dispose() }
      Assert-TrustedStateAcl -Path $stage
      if (Test-Path -LiteralPath $p) { [IO.File]::Replace($stage, $p, $null) } else { [IO.File]::Move($stage, $p) }
      Assert-TrustedStateAcl -Path $p
    } finally { if ($lock) { $lock.Dispose() }; if ($stage -and (Test-Path -LiteralPath $stage)) { Remove-Item -LiteralPath $stage -Force -ErrorAction SilentlyContinue } }
    return $true
    } catch {
      Write-Verbose ("Sysmon state write failed for '{0}': {1}" -f $p,$_.Exception.Message)
      return $false
    }
}
function Get-SysmonCurrentConfigSha256 {
  param([string]$Exe)
  # Sysmon: "-c" without file dumps current configuration.
  if (-not $Exe -or -not (Test-Path -LiteralPath $Exe)) { return $null }
  try {
    $native = Invoke-StagedSysmonCommand -Exe $Exe -Arguments @('-c')
    if (-not $native -or -not $native.Success -or $native.TimedOut -or $native.OutputTruncated -or $native.StderrTruncated) { return $null }
    $txt = [string]$native.Output
    if ([string]::IsNullOrWhiteSpace($txt)) { return $null }
    $norm  = ($txt -replace "`r`n","`n").Trim()
    $bytes = [Text.Encoding]::UTF8.GetBytes($norm)
    $sha   = [Security.Cryptography.SHA256]::Create()
    return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-','').ToLowerInvariant()
  } catch {
    return $null
  }
}
function Sanitize-Text {
  param([string]$Text)
  if (-not $Text) { return $Text }
  $t = $Text
  $t = [regex]::Replace($t, '(?i)\b[a-z]:\\[^\s''"]+', '[local file]')
  $t = [regex]::Replace($t, '(?i)\\\\[a-z0-9\.\-]+\\[^\s''"]+', '[network file]')
  return $t
}
function Write-PrettySummary {
  param(
    [hashtable]$Summary,
    [int]$ChannelSizeMiB,
    [switch]$Sanitize,
    [switch]$NoColor
  )
  $useColor = -not $NoColor
  function _Color([string]$Text, [ConsoleColor]$Color) {
    if (-not $useColor) { Write-UiLine $Text; return }
    Write-UiLine $Text -ForegroundColor $Color
  }
  $ok = [bool]$Summary.Ok
  $drift = [bool]$Summary.DriftDetected
  $line = "============================================================"
  if ($Sanitize) { $line = Sanitize-Text $line }
  Write-UiLine $line
  _Color "Sysmon Config Updater" ([ConsoleColor]::Cyan)
  Write-UiLine ("Timestamp      : " + (Get-Date).ToString("s"))
  Write-UiLine $line
  if ($ok) { _Color ("Status         : OK") ([ConsoleColor]::Green) }
  else { _Color ("Status         : NOT OK") ([ConsoleColor]::Red) }
  if ($drift) { _Color ("DriftDetected  : True") ([ConsoleColor]::Yellow) }
  else { Write-UiLine ("DriftDetected  : False") }
  Write-UiLine ("Remediate      : " + $Summary.Remediate + " (IsAdmin=" + $Summary.IsAdmin + ")")
  Write-UiLine ("EnsureChannel  : " + $Summary.EnsureChannel + " (SizeMiB=" + $ChannelSizeMiB + ")")
  Write-UiLine ("ConfigFile     : " + ($(if($Summary.ConfigFile){$Summary.ConfigFile}else{'n/a'})))
  Write-UiLine ("DesiredSha256  : " + ($(if($Summary.DesiredSha256){$Summary.DesiredSha256}else{'n/a'})))
  Write-UiLine ("PrevSha256     : " + ($(if($Summary.PrevDesiredSha256){$Summary.PrevDesiredSha256}else{'n/a'})))
  Write-UiLine ("Service        : " + ($(if($Summary.SysmonService){$Summary.SysmonService}else{'n/a'})))
  Write-UiLine ("Exe            : " + ($(if($Summary.SysmonExe){$Summary.SysmonExe}else{'n/a'})))
  Write-UiLine ("EngineVersion  : " + ($(if($Summary.EngineVersion){$Summary.EngineVersion}else{'n/a'})))
  Write-UiLine ("DumpSha256     : " + ($(if($Summary.CurrentDumpSha256){$Summary.CurrentDumpSha256}else{'n/a'})))
  Write-UiLine ("StateWritten   : " + $Summary.StateWritten)
  if ($Summary.Actions -and $Summary.Actions.Count -gt 0) {
    Write-UiLine ""
    _Color "Actions:" ([ConsoleColor]::Green)
    foreach ($a in $Summary.Actions) { Write-UiLine ("  - " + $a) }
  }
  if ($Summary.Warnings -and $Summary.Warnings.Count -gt 0) {
    Write-UiLine ""
    _Color "Warnings:" ([ConsoleColor]::Yellow)
    foreach ($w in $Summary.Warnings) { Write-UiLine ("  - " + $w) }
  }
  Write-UiLine $line
}
