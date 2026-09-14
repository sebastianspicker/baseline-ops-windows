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
    $comparison = Compare-VersionComponent $x.$k $y.$k
    if ($comparison -ne 0) { return $comparison }
  }
  return 0
}
function Compare-VersionComponent($x,$y) {
  if ($x -gt $y) { return 1 }
  if ($x -lt $y) { return -1 }
  return 0
}
function Resolve-SysmonExe {
  param([string]$Hint)
  if (-not [string]::IsNullOrWhiteSpace($Hint)) {
    return Resolve-ExplicitSysmonExe $Hint
  }
  $servicePath = Resolve-SysmonServiceExe
  if ($servicePath) { return $servicePath }
  return Find-SysmonExeUnderRoots (Get-SysmonDiscoveryRoots)
}
function Resolve-ExplicitSysmonExe([string]$Hint) {
  if (-not (Test-Path -LiteralPath $Hint -PathType Leaf)) { return $null }
  if (-not (Test-TrustedSysmonExecutable -Path $Hint)) { return $null }
  return (Get-Item -LiteralPath $Hint -Force -ErrorAction Stop).FullName
}
function Resolve-SysmonServiceExe {
  foreach ($serviceName in 'Sysmon64','Sysmon') {
    try {
      $service = Get-ItemProperty -Path ("HKLM:\SYSTEM\CurrentControlSet\Services\" + $serviceName) -ErrorAction Stop
      $resolved = Resolve-SysmonServiceImagePath $service
      if ($resolved) { return $resolved }
    } catch { Write-Verbose ("Sysmon service image path probe failed for '{0}': {1}" -f $serviceName,$_.Exception.Message) }
  }
  return $null
}
function Resolve-SysmonServiceImagePath($Service) {
  if (-not $Service) { return $null }
  if (-not $Service.ImagePath) { return $null }
  $imagePath = [Environment]::ExpandEnvironmentVariables([string]$Service.ImagePath)
  $nullRef = $null
  $token = [Management.Automation.PSParser]::Tokenize($imagePath,[ref]$nullRef) |
    Where-Object { $_.Type -in @('Command','CommandArgument') } | Select-Object -First 1
  if ($token) {
    $tokenPath = $token.Content.Trim('"')
    if (Test-Path -LiteralPath $tokenPath) { return $tokenPath }
  }
  $match = [regex]::Match($imagePath,'(?i)([a-z]:\\[^"]+?\.exe)')
  if (-not $match.Success) { return $null }
  if (Test-Path -LiteralPath $match.Groups[1].Value) { return $match.Groups[1].Value }
  return $null
}
function Get-SysmonDiscoveryRoots {
  return @(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows),
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
  ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
}
function Find-SysmonExeUnderRoots([string[]]$Roots) {
  foreach ($root in $Roots) {
    $canonicalRoot = [IO.Path]::GetFullPath($root).TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    foreach ($relativeCandidate in @('Sysmon64.exe','Sysmon.exe','Sysmon\Sysmon64.exe','Sysmon\Sysmon.exe')) {
      $candidate = [IO.Path]::GetFullPath((Join-Path $root $relativeCandidate))
      if (-not $candidate.StartsWith($canonicalRoot,[StringComparison]::OrdinalIgnoreCase)) { continue }
      if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
      if (Test-SysmonPathWithoutReparsePoint $candidate $canonicalRoot) { return $candidate }
    }
  }
  return $null
}
function Test-SysmonPathWithoutReparsePoint([string]$Candidate,[string]$CanonicalRoot) {
  $current = $CanonicalRoot
  foreach ($segment in @($Candidate.Substring($CanonicalRoot.Length) -split '[/\\]' | Where-Object { $_ })) {
    $current = Join-Path $current $segment
    if ((Get-Item -LiteralPath $current -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
  }
  return $true
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
  Assert-TrustedStateOwner $acl $Path $trustedSids
  if (-not $acl.AreAccessRulesProtected) { throw "Sysmon state path '$Path' must use a protected ACL." }
  Assert-TrustedStateAccessRules $acl $Path $trustedSids
}
function Get-TrustedStateWriteMask {
  return [Security.AccessControl.FileSystemRights]::WriteData -bor
    [Security.AccessControl.FileSystemRights]::AppendData -bor
    [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
    [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
    [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [Security.AccessControl.FileSystemRights]::Delete -bor
    [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [Security.AccessControl.FileSystemRights]::TakeOwnership
}
function Assert-TrustedStateOwner($Acl,[string]$Path,[string[]]$TrustedSids) {
  $ownerSid = ConvertTo-TrustedStateSidValue -IdentityReference $Acl.Owner
  if ($TrustedSids -notcontains $ownerSid) { throw "Sysmon state path '$Path' has an untrusted owner SID '$ownerSid'." }
}
function Assert-TrustedStateAccessRules($Acl,[string]$Path,[string[]]$TrustedSids) {
  $writeMask = Get-TrustedStateWriteMask
  foreach ($accessRule in @($acl.Access)) {
    if ($accessRule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
    if (($accessRule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
    if (([int64]$accessRule.FileSystemRights -band [int64]$writeMask) -eq 0) { continue }
    $sid = ConvertTo-TrustedStateSidValue -IdentityReference $accessRule.IdentityReference
    if ($TrustedSids -notcontains $sid) { throw "Sysmon state path '$Path' grants write access to untrusted SID '$sid'." }
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
  Assert-SysmonStateRootSchema $State
  Assert-SysmonStateObjectSchemas $State
  Assert-SysmonStateScalarSchemas $State
}
function Assert-SysmonStateRootSchema($State) {
  if ($State -isnot [pscustomobject]) { throw 'Sysmon updater state root must be an object.' }
  $allowedRoot = @('Version','Time','Host','Engine','Observed','Applied','Runtime')
  Assert-SysmonObjectFields $State $allowedRoot 'Sysmon updater state'
  Assert-SysmonStateVersion $State.Version
  foreach ($field in @('Time','Host')) { Assert-SysmonBoundedString $State.$field "Sysmon updater state $field" 512 }
}
function Assert-SysmonStateVersion($Version) {
  if ($Version -isnot [int] -and $Version -isnot [long]) { throw 'Sysmon updater state Version must be an integer.' }
  if ([int64]$Version -ne 2) { throw 'Sysmon updater state Version is unsupported.' }
}
function Assert-SysmonBoundedString($Value,[string]$Label,[int]$MaximumLength) {
  if ($Value -isnot [string] -or $Value.Length -gt $MaximumLength) { throw "$Label must be a bounded string." }
}
function Assert-SysmonObjectFields($Value,[string[]]$Fields,[string]$Label) {
  if (@($Value.PSObject.Properties.Name | Where-Object { $Fields -notcontains $_ }).Count -gt 0) { throw "$Label has missing or unsupported fields." }
  if (@($Value.PSObject.Properties.Name).Count -ne $Fields.Count) { throw "$Label has missing or unsupported fields." }
}
function Assert-SysmonStateObjectSchemas($State) {
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
    Assert-SysmonObjectFields $value $fields "Sysmon updater state $name"
  }
}
function Assert-SysmonStateScalarSchemas($State) {
  Assert-SysmonEngineScalars $State.Engine
  Assert-SysmonObservedScalars $State.Observed
  Assert-SysmonStateHashes $State
}
function Assert-SysmonEngineScalars($Engine) {
  foreach ($field in @('Version','ExePath','Service')) {
    $value = $Engine.$field
    if ($null -ne $value -and ($value -isnot [string] -or $value.Length -gt 4096)) { throw "Sysmon updater state Engine.$field has an invalid type or length." }
  }
}
function Assert-SysmonObservedScalars($Observed) {
  foreach ($field in @('Path','Source')) {
    $value = $Observed.$field
    if ($value -isnot [string] -or $value.Length -gt 4096) { throw "Sysmon updater state Observed.$field has an invalid type or length." }
  }
  if ($Observed.Valid -isnot [bool]) { throw 'Sysmon updater state Observed.Valid must be boolean.' }
}
function Assert-SysmonStateHashes($State) {
  foreach ($hash in @($State.Observed.DesiredSha256,$State.Applied.Sha256,$State.Runtime.CurrentDumpSha256)) {
    if ($null -ne $hash -and ($hash -isnot [string] -or $hash -notmatch '^[a-fA-F0-9]{64}$')) { throw 'Sysmon updater state SHA256 fields must be null or exactly 64 hexadecimal characters.' }
  }
}
function Load-JsonOrDefault {
  param(
    [string]$Path,
    [hashtable]$DefaultObject
  )
  $fallback = $(if ($DefaultObject) { $DefaultObject } else { @{} })
  if (-not $Path) { return $fallback }
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $fallback }
  try { return Read-ValidatedSysmonState $Path $fallback }
  catch { return $fallback }
}
function Read-ValidatedSysmonState([string]$Path,$Fallback) {
  Assert-TrustedStateAcl -Path $Path
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (-not (Test-RegularSysmonStateFile $item)) { return $Fallback }
  $raw = Get-BoundedUtf8FileContent -Path $item.FullName -MaximumBytes 65536
  if ([string]::IsNullOrWhiteSpace($raw)) { return $Fallback }
  $state = $raw | ConvertFrom-Json -ErrorAction Stop
  if ($null -eq $state) { return $Fallback }
  Assert-SysmonStateSchema -State $state
  return $state
}
function Test-RegularSysmonStateFile($Item) {
  return -not $Item.PSIsContainer -and -not ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint)
}
# Treats the update manifest as untrusted input and returns an explicit validity
# result rather than allowing partial manifest data to drive remediation.
