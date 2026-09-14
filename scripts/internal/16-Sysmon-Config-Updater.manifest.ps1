#requires -version 5.1
<#
.SYNOPSIS
Validates Sysmon manifest and configuration inputs.
.DESCRIPTION
Applies the closed manifest schema, deterministic configuration selection, XML validation, and locked configuration staging.
#>
function Test-ManifestPolicy {
  param([string]$Path,[string]$SourceDirectory)
  $result = @{ Valid = $true; Manifest = $null; Reason = $null }
  if (-not $Path) { return $result }
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return New-InvalidManifestResult 'Manifest file does not exist.' }
  try {
    $manifest = Read-SysmonManifest $Path
    Assert-SysmonManifestPropertyNames $manifest
    Assert-SysmonManifestMinimumEngine $manifest
    Assert-SysmonManifestAllowedHashes $manifest
    Assert-SysmonManifestConfig $manifest $SourceDirectory
    $result.Manifest = $manifest
  } catch { return New-InvalidManifestResult $_.Exception.Message }
  return $result
}
function New-InvalidManifestResult([string]$Reason) { return @{ Valid=$false; Manifest=$null; Reason=$Reason } }
function Read-SysmonManifest([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Manifest must be a regular non-reparse file.' }
  $raw = Get-BoundedUtf8FileContent -Path $item.FullName -MaximumBytes 1048576
  if ([string]::IsNullOrWhiteSpace($raw)) { throw 'Manifest is empty.' }
  $manifest = $raw | ConvertFrom-Json -ErrorAction Stop
  if (-not (Test-SysmonManifestObject $manifest)) { throw 'Manifest root must be an object.' }
  return $manifest
}
function Test-SysmonManifestObject($Value) {
  if ($null -eq $Value) { return $false }
  if ($Value -is [string]) { return $false }
  if ($Value -is [ValueType]) { return $false }
  return $Value -isnot [Collections.IEnumerable]
}
function Assert-SysmonManifestPropertyNames($Manifest) {
  $seen = @{}
  foreach ($property in $Manifest.PSObject.Properties) {
    $normalized = $property.Name.ToLowerInvariant()
    if ($seen.ContainsKey($normalized)) { throw ("Manifest contains duplicate property '{0}' (property names are case-insensitive)." -f $property.Name) }
    $seen[$normalized] = $true
    if ($property.Name -inotmatch '^(MinEngine|AllowedHashes|Config)$') { throw ("Manifest contains unsupported property '{0}'." -f $property.Name) }
  }
}
function Assert-SysmonManifestMinimumEngine($Manifest) {
  if (-not $Manifest.PSObject.Properties['MinEngine'] -or $null -eq $Manifest.MinEngine) { return }
  if ($Manifest.MinEngine -isnot [string] -or -not (Parse-Version ([string]$Manifest.MinEngine))) { throw 'Manifest MinEngine must be a version string.' }
}
function Assert-SysmonManifestAllowedHashes($Manifest) {
  if (-not $Manifest.PSObject.Properties['AllowedHashes']) { return }
  if (-not (Test-SysmonHashArray $Manifest.AllowedHashes)) { throw 'Manifest AllowedHashes must be an array of SHA256 hashes.' }
  foreach ($hash in @($Manifest.AllowedHashes)) {
    if (-not (Test-SysmonSha256 $hash)) { throw 'Manifest AllowedHashes must contain SHA256 hashes.' }
  }
}
function Test-SysmonHashArray($Value) {
  if ($null -eq $Value) { return $false }
  if ($Value -is [string]) { return $false }
  if ($Value -isnot [Collections.IEnumerable]) { return $false }
  return @($Value).Count -gt 0
}
function Test-SysmonSha256($Value) { return $Value -is [string] -and $Value -match '^[a-fA-F0-9]{64}$' }
function Assert-SysmonManifestConfig($Manifest,[string]$SourceDirectory) {
  $configProperty = $Manifest.PSObject.Properties['Config']
  if (-not $configProperty) { return }
  $config = $configProperty.Value
  if ($null -eq $config) { return }
  if (-not (Test-SysmonManifestObject $config)) { throw 'Manifest Config must be an object.' }
  Assert-SysmonManifestConfigProperties $config
  $fileProperty = $config.PSObject.Properties['File']
  if (-not $fileProperty) { return }
  if ($null -eq $fileProperty.Value) { return }
  Assert-SysmonManifestConfigFile $fileProperty.Value $SourceDirectory
}
function Assert-SysmonManifestConfigProperties($Config) {
  foreach ($property in $Config.PSObject.Properties) {
    if ($property.Name -inotmatch '^File$') { throw ("Manifest Config contains unsupported property '{0}'." -f $property.Name) }
  }
}
function Assert-SysmonManifestConfigFile($File,[string]$SourceDirectory) {
  Assert-SysmonManifestFileName $File
  if (-not (Test-SysmonSourceDirectory $SourceDirectory)) { throw 'Manifest Config.File requires an existing SourceDir.' }
  $sourceRoot = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $SourceDirectory -ErrorAction Stop).Path)
  $candidate = [IO.Path]::GetFullPath((Join-Path $sourceRoot $File))
  $rootWithSeparator = $sourceRoot.TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  if (-not (Test-SysmonConfigCandidate $File $candidate $rootWithSeparator)) { throw 'Manifest Config.File must be a basename or a path beneath SourceDir.' }
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw 'Manifest Config.File does not identify an existing file beneath SourceDir.' }
  Assert-SysmonConfigPathWithoutReparsePoint $sourceRoot $rootWithSeparator $candidate
}
function Assert-SysmonManifestFileName($File) {
  if ($File -isnot [string]) { throw 'Manifest Config.File must be a non-empty string.' }
  if ([string]::IsNullOrWhiteSpace($File)) { throw 'Manifest Config.File must be a non-empty string.' }
}
function Test-SysmonSourceDirectory([string]$Path) {
  if (-not $Path) { return $false }
  return Test-Path -LiteralPath $Path -PathType Container
}
function Test-SysmonConfigCandidate([string]$File,[string]$Candidate,[string]$RootWithSeparator) {
  if ([IO.Path]::IsPathRooted($File)) { return $false }
  return $Candidate.StartsWith($RootWithSeparator,[StringComparison]::OrdinalIgnoreCase)
}
function Assert-SysmonConfigPathWithoutReparsePoint([string]$SourceRoot,[string]$RootWithSeparator,[string]$Candidate) {
  $current = $SourceRoot
  foreach ($segment in @($Candidate.Substring($RootWithSeparator.Length) -split '[/\\]' | Where-Object { $_ })) {
    $current = Join-Path $current $segment
    if ((Get-Item -LiteralPath $current -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Manifest Config.File must not traverse a reparse point.' }
  }
}
function Select-ConfigFile([string]$Path,[string]$Dir,[string]$NameHint,[object]$Manifest){
  if ($Path -and (Test-Path -LiteralPath $Path)) { return (Get-Item -LiteralPath $Path) }
  $manifestFile = Select-SysmonManifestConfigFile $Path $Dir $Manifest
  if ($manifestFile) { return $manifestFile }
  return Select-SysmonDirectoryConfigFile $Dir $NameHint
}
function Select-SysmonManifestConfigFile([string]$Path,[string]$Dir,$Manifest) {
  $file = Get-SysmonManifestFile $Manifest
  if (-not $file) { return $null }
  $candidate = Get-ExistingSysmonConfigCandidate $Dir $file
  if ($candidate) { return $candidate }
  if ($Path) { return Get-ExistingSysmonConfigCandidate (Split-Path -Parent $Path) $file }
  return $null
}
function Get-SysmonManifestFile($Manifest) {
  if (-not $Manifest) { return $null }
  $config = $Manifest.PSObject.Properties['Config']
  if (-not $config -or -not $config.Value) { return $null }
  $file = $config.Value.PSObject.Properties['File']
  if (-not $file) { return $null }
  return [string]$file.Value
}
function Get-ExistingSysmonConfigCandidate([string]$Directory,[string]$File) {
  if (-not $Directory) { return $null }
  $candidate = Join-Path $Directory $File
  if (Test-Path -LiteralPath $candidate) { return Get-Item -LiteralPath $candidate }
  return $null
}
function Select-SysmonDirectoryConfigFile([string]$Dir,[string]$NameHint) {
  if (-not (Test-SysmonSourceDirectory $Dir)) { return $null }
  $all = @(Get-ChildItem -LiteralPath $Dir -Filter '*.xml' -File -ErrorAction SilentlyContinue)
  if ($NameHint) { $all = @($all | Where-Object { $_.Name.IndexOf($NameHint,[StringComparison]::OrdinalIgnoreCase) -ge 0 }) }
  if ($all.Count -eq 0) { return $null }
  if ($NameHint) { Assert-SysmonHintSelectsOne $all }
  $ranked = $all | ForEach-Object { Get-SysmonConfigRank $_ }
  return ($ranked | Sort-Object -Property @{Expression='Score';Descending=$true},@{Expression='Time';Descending=$true} | Select-Object -First 1).File
}
function Assert-SysmonHintSelectsOne($Files) {
  if ($Files.Count -ne 1) { throw "ConfigNameHint must select exactly one XML configuration; matched $($Files.Count)." }
}
function Get-SysmonConfigRank($File) {
  $match = [regex]::Match($File.Name,'v(\d+\.\d+(\.\d+)?)')
  $score = $(if ($match.Success) { [double]($match.Groups[1].Value -replace '\.','') } else { 0 })
  return [pscustomobject]@{ File=$File; Score=$score; Time=$File.LastWriteTimeUtc }
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
    return Test-SysmonXmlDocument $x
  } catch {
    return $false, $_.Exception.Message
  } finally {
    if ($null -ne $reader) { $reader.Dispose() }
    if ($null -ne $stream) { $stream.Dispose() }
  }
}
function Test-SysmonXmlDocument($Document) {
  if (-not $Document) { return $false,'empty xml' }
  $root = $Document.DocumentElement
  if (-not $root) { return $false,'no root element' }
  if ($root.Name -notin @('Sysmon','sysmon')) { return $false,('unexpected root: ' + $root.Name) }
  $schemaVersion = $root.GetAttribute('schemaversion')
  if ($schemaVersion) { return $true,('schema=' + $schemaVersion) }
  return $true,'schema=n/a'
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
