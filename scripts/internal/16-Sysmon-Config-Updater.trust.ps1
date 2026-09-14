#requires -version 5.1
<#
.SYNOPSIS
Protects Sysmon execution and persisted updater state.
.DESCRIPTION
Validates and stages the Sysmon executable, manages its event channel, and reads or writes trusted state.
#>
function Test-TrustedSysmonExecutable {
  param([Parameter(Mandatory)][string]$Path)
  try {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $false }
    if ($item.Name -inotmatch '^Sysmon(?:64)?\.exe$') { return $false }
    if (-not (Test-SysmonExecutablePath $item.FullName)) { return $false }
    if (-not (Test-SysmonExecutableSignature $item)) { return $false }
    return $true
  } catch { return $false }
}
function Test-SysmonExecutablePath([string]$Path) {
  $fullPath = [IO.Path]::GetFullPath($Path)
  $root = [IO.Path]::GetPathRoot($fullPath)
  $current = $root
  foreach ($segment in @($fullPath.Substring($root.Length) -split '[/\\]' | Where-Object { $_ })) {
    $current = Join-Path $current $segment
    if ((Get-Item -LiteralPath $current -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
  }
  return $true
}
function Test-SysmonExecutableSignature($Item) {
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return $true }
  $signature = Get-AuthenticodeSignature -LiteralPath $Item.FullName -ErrorAction Stop
  if ($signature.Status -ne 'Valid') { return $false }
  if (-not $signature.SignerCertificate) { return $false }
  if ($signature.SignerCertificate.Subject -notmatch '(?i)(?:^|,\s*)O=Microsoft Corporation(?:,|$)') { return $false }
  return [string]$Item.VersionInfo.OriginalFilename -match '(?i)^Sysmon(?:64)?\.exe$'
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
    $sourceBytes = Read-LockedSysmonExecutable $source
    $sourceHash = Get-BytesSha256 -Bytes $sourceBytes
    $stage = New-PrivateSysmonExecutableStage $Path $sourceBytes
    $stagePath = $stage.Path; $stageDirectory = $stage.Directory; $staged = $stage.Stream
    Assert-StagedSysmonExecutableHash $staged $sourceHash
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
function Read-LockedSysmonExecutable($Stream) {
  if ($Stream.Length -le 0 -or $Stream.Length -gt 256MB) { throw 'Sysmon executable has an unsupported size.' }
  $bytes = New-Object byte[] ([int]$Stream.Length)
  $offset = 0
  while ($offset -lt $bytes.Length) {
    $read = $Stream.Read($bytes,$offset,$bytes.Length - $offset)
    if ($read -le 0) { throw 'Sysmon executable changed while it was being read.' }
    $offset += $read
  }
  if ($Stream.ReadByte() -ne -1) { throw 'Sysmon executable changed while it was being read.' }
  return $bytes
}
function New-PrivateSysmonExecutableStage([string]$SourcePath,[byte[]]$Bytes) {
  for ($attempt = 0; $attempt -lt 10; $attempt++) {
    $directory = Join-Path ([IO.Path]::GetTempPath()) ('.sysmon-exe-' + [guid]::NewGuid().ToString('N'))
    $stream = $null
    try {
      [void][IO.Directory]::CreateDirectory($directory)
      if ((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'The staged Sysmon directory is a reparse point.' }
      $path = Join-Path $directory ([IO.Path]::GetFileName($SourcePath))
      $stream = [IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
      $stream.Write($Bytes,0,$Bytes.Length); $stream.Flush($true); $stream.Position = 0
      return [pscustomobject]@{ Path=$path; Directory=$directory; Stream=$stream }
    } catch [IO.IOException] {
      if ($stream) { $stream.Dispose() }
      Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
      if ($stream) { $stream.Dispose() }
      Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction SilentlyContinue
      throw
    }
  }
  throw 'Could not create a private staged Sysmon executable.'
}
function Assert-StagedSysmonExecutableHash($Stream,[string]$ExpectedHash) {
  $bytes = Read-LockedSysmonExecutable $Stream
  if ((Get-BytesSha256 -Bytes $bytes) -ne $ExpectedHash) { throw 'Staged Sysmon executable hash did not match the trusted source.' }
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
  $name = 'Microsoft-Windows-Sysmon/Operational'; $ok = $true
  $messages = [System.Collections.Generic.List[string]]::new()
  try {
    $glResult = Invoke-Wevtutil -Arguments @('gl', $name) -CaptureOutput
    $q = if ($glResult -and $glResult.Output) { $glResult.Output } else { '' }
    $queryText = @($q) -join "`n"
    $enableResult = Set-SysmonChannelEnabled $name ([bool]($queryText -match 'enabled:\s*true')) ([bool]$DoIt) $Cmdlet
    $ok = Merge-SysmonChannelResult $enableResult $messages $ok
    $sizeResult = Set-SysmonChannelSize $name $queryText $MiB ([bool]$DoIt) $Cmdlet
    $ok = Merge-SysmonChannelResult $sizeResult $messages $ok
  } catch { $ok = $false; [void]$messages.Add($_.Exception.Message) }
  return $ok, (@($messages) -join '; ')
}
function Merge-SysmonChannelResult($Result,$Messages,[bool]$CurrentOk) {
  if ($Result.Message) { [void]$Messages.Add($Result.Message) }
  return $CurrentOk -and $Result.Ok
}
function Set-SysmonChannelEnabled([string]$Name,[bool]$Enabled,[bool]$DoIt,$CommandContext) {
  if ($Enabled) { return [pscustomobject]@{ Ok=$true; Message=$null } }
  if (-not $DoIt) { return [pscustomobject]@{ Ok=$false; Message=$null } }
  if (-not $CommandContext.ShouldProcess($Name,'Enable Sysmon Operational event channel')) { return [pscustomobject]@{ Ok=$false; Message='enable skipped by ShouldProcess' } }
  if (Invoke-Wevtutil -Arguments @('sl',$Name,'/e:true')) { return [pscustomobject]@{ Ok=$true; Message='enabled' } }
  return [pscustomobject]@{ Ok=$false; Message='enable failed' }
}
function Set-SysmonChannelSize([string]$Name,[string]$CurrentText,[int]$MiB,[bool]$DoIt,$CommandContext) {
  if ($MiB -le 0) { return [pscustomobject]@{ Ok=$true; Message=$null } }
  $match = [regex]::Match($CurrentText,'maximum size:\s*(\d+)')
  $current = $(if ($match.Success) { [int64]$match.Groups[1].Value } else { 0 })
  $desired = [int64]$MiB * 1024 * 1024
  if ($current -ge $desired) { return [pscustomobject]@{ Ok=$true; Message=$null } }
  if (-not $DoIt) { return [pscustomobject]@{ Ok=$false; Message=$null } }
  if (-not $CommandContext.ShouldProcess($Name,"Resize Sysmon Operational event channel to $MiB MiB")) { return [pscustomobject]@{ Ok=$false; Message='resize skipped by ShouldProcess' } }
  if (Invoke-Wevtutil -Arguments @('sl',$Name,"/ms:$desired")) { return [pscustomobject]@{ Ok=$true; Message=("size=" + $MiB + 'MiB') } }
  return [pscustomobject]@{ Ok=$false; Message='resize failed' }
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
    Assert-ExistingSysmonStatePaths @($p,$p + '.lock')
    $stage = $null
    $lock = Open-TrustedStateFile -Path ($p + '.lock') -Mode OpenOrCreate -Share ([IO.FileShare]::None)
    try {
      Assert-TrustedStateAcl -Path ($p + '.lock')
      $stage = Write-StagedSysmonState $directory $json
      if (Test-Path -LiteralPath $p) { [IO.File]::Replace($stage, $p, $null) } else { [IO.File]::Move($stage, $p) }
      Assert-TrustedStateAcl -Path $p
    } finally { if ($lock) { $lock.Dispose() }; if ($stage -and (Test-Path -LiteralPath $stage)) { Remove-Item -LiteralPath $stage -Force -ErrorAction SilentlyContinue } }
    return $true
    } catch {
      Write-Verbose ("Sysmon state write failed for '{0}': {1}" -f $p,$_.Exception.Message)
      return $false
    }
}
function Assert-ExistingSysmonStatePaths([string[]]$Paths) {
  foreach ($path in $Paths) {
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Sysmon state file or lock path is unsafe.' }
    Assert-TrustedStateAcl -Path $item.FullName
  }
}
function Write-StagedSysmonState([string]$Directory,[string]$Json) {
  $path = Join-Path $Directory ('.state-' + [guid]::NewGuid().ToString('N') + '.json')
  $stream = Open-TrustedStateFile -Path $path -Mode CreateNew -Share ([IO.FileShare]::None)
  try {
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Json)
    $stream.Write($bytes,0,$bytes.Length)
    $stream.Flush($true)
  } finally { $stream.Dispose() }
  Assert-TrustedStateAcl -Path $path
  return $path
}
function Get-SysmonCurrentConfigSha256 {
  param([string]$Exe)
  # Sysmon: "-c" without file dumps current configuration.
  if (-not $Exe -or -not (Test-Path -LiteralPath $Exe)) { return $null }
  try {
    $native = Invoke-StagedSysmonCommand -Exe $Exe -Arguments @('-c')
    if (-not (Test-SysmonNativeApplySuccess $native)) { return $null }
    $txt = [string]$native.Output
    if ([string]::IsNullOrWhiteSpace($txt)) { return $null }
    $norm  = ($txt -replace "`r`n","`n").Trim()
    $bytes = [Text.Encoding]::UTF8.GetBytes($norm)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
  } catch {
    return $null
  }
}
