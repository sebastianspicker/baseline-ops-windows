#requires -version 5.1
<#
.SYNOPSIS
Internal state, event-query, and remediation helpers for the Sysmon sensor.

.DESCRIPTION
Validates persisted sensor state, performs bounded event queries, classifies
rule drift, and launches remediation through a locked execution closure. The
entry script establishes modules and strict mode before loading these helpers.
#>

function Test-AllConditions {
  param([scriptblock[]]$Conditions)
  foreach ($condition in $Conditions) {
    if (-not (. $condition)) { return $false }
  }
  return $true
}
function Test-AnyCondition {
  param([scriptblock[]]$Conditions)
  foreach ($condition in $Conditions) {
    if (. $condition) { return $true }
  }
  return $false
}
function Get-StatusColor {
  param([string]$Status)
  switch ($Status) {
    'OK'                 { 'Green'; break }
    'ANOMALIES_DETECTED' { 'Yellow'; break }
    'CHANNEL_UNAVAILABLE'{ 'Red'; break }
    'ERROR'              { 'Red'; break }
    default              { 'Yellow'; break }
  }
}
function Get-RuleStatusColor {
  param([string]$Status)
  switch ($Status) {
    'OK'         { 'Green'; break }
    'HARDZERO'   { 'Red'; break }
    'LOW'        { 'Yellow'; break }
    'DRIFT_DOWN' { 'Yellow'; break }
    'SURGE'      { 'Yellow'; break }
    default      { 'Yellow'; break }
  }
}
# -----------------------------
# Utility: File IO (safe)
# -----------------------------
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
# Rejects sensor state writable by untrusted identities so baseline values
# cannot be manipulated to hide event-rate drift.
function Assert-TrustedStateAcl {
  param([Parameter(Mandatory)][string]$Path)
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return }
  $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  $trustedSids = @('S-1-5-18','S-1-5-32-544')
  $ownerSid = ConvertTo-TrustedStateSidValue -IdentityReference $acl.Owner
  if ($trustedSids -notcontains $ownerSid) { throw "Sysmon state path '$Path' has an untrusted owner SID '$ownerSid'." }
  if (-not $acl.AreAccessRulesProtected) { throw "Sysmon state path '$Path' must use a protected ACL." }
  $writeMask = [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor [Security.AccessControl.FileSystemRights]::WriteAttributes -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
  foreach ($accessRule in @($acl.Access)) {
    Assert-TrustedStateAccessRule -AccessRule $accessRule -TrustedSids $trustedSids -WriteMask $writeMask -Path $Path
  }
}
function Assert-TrustedStateAccessRule {
  param($AccessRule, [string[]]$TrustedSids, $WriteMask, [string]$Path)
  if ($AccessRule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { return }
  if (($AccessRule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { return }
  if (([int64]$AccessRule.FileSystemRights -band [int64]$WriteMask) -eq 0) { return }
  $sid = ConvertTo-TrustedStateSidValue -IdentityReference $AccessRule.IdentityReference
  if ($TrustedSids -notcontains $sid) { throw "Sysmon state path '$Path' grants write access to untrusted SID '$sid'." }
}
function New-TrustedStateAcl {
  param([switch]$Directory)
  $administrators = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544'); $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
  if ($Directory) { $acl = New-Object Security.AccessControl.DirectorySecurity; $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit }
  else { $acl = New-Object Security.AccessControl.FileSecurity; $inheritance = [Security.AccessControl.InheritanceFlags]::None }
  $acl.SetOwner($administrators); $acl.SetAccessRuleProtection($true, $false)
  foreach ($sid in @($administrators,$system)) { $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid,[Security.AccessControl.FileSystemRights]::FullControl,$inheritance,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow); [void]$acl.AddAccessRule($rule) }
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
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][IO.FileMode]$Mode,[Parameter(Mandatory)][IO.FileShare]$Share)
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return [IO.File]::Open($Path,$Mode,[IO.FileAccess]::ReadWrite,$Share) }
  $security = New-TrustedStateAcl
  $rights = [Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Write
  $fileInfo = New-Object IO.FileInfo($Path)
  if ($PSVersionTable.PSEdition -eq 'Desktop') { return $fileInfo.Create($Mode,$rights,$Share,4096,[IO.FileOptions]::WriteThrough,$security) }
  return [IO.FileSystemAclExtensions]::Create($fileInfo,$Mode,$rights,$Share,4096,[IO.FileOptions]::WriteThrough,$security)
}
function Get-SysmonStatePath {
  param([string]$RequestedPath,[Parameter(Mandatory)][string]$FileName)
  $root = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'BaselineOpsForWindows\Sysmon'
  $expected = Join-Path $root $FileName
  if ($RequestedPath -and -not [string]::Equals([IO.Path]::GetFullPath($RequestedPath), [IO.Path]::GetFullPath($expected), [StringComparison]::OrdinalIgnoreCase)) { throw 'StatePath is fixed to the admin-owned CommonApplicationData Sysmon state directory.' }
  foreach ($part in @((Split-Path -Parent $root),$root)) {
    if (Test-Path -LiteralPath $part) { $item = Get-Item -LiteralPath $part -Force -ErrorAction Stop; if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Sysmon state path must not contain reparse points.' }; Assert-TrustedStateAcl -Path $item.FullName }
  }
  return $expected
}
function Initialize-SysmonStateDirectory([string]$directory) {
  $commonData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  if ([string]::IsNullOrWhiteSpace($commonData) -or -not (Test-PathUnderRoot -Path $directory -Root $commonData)) { throw 'Sysmon state directory is outside CommonApplicationData.' }
  $current = [IO.Path]::GetFullPath($commonData)
  $relative = [IO.Path]::GetFullPath($directory).Substring($current.TrimEnd([IO.Path]::DirectorySeparatorChar).Length).TrimStart([IO.Path]::DirectorySeparatorChar)
  foreach ($segment in @($relative -split '[/\\]' | Where-Object { $_ })) { $current = Join-Path $current $segment; if (Test-Path -LiteralPath $current) { $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop; if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Sysmon state directory contains an unsafe path component.' }; Assert-TrustedStateAcl -Path $item.FullName } else { [void](New-TrustedStateDirectory -Path $current) }; Assert-TrustedStateAcl -Path $current }
}
# Enforces a closed, bounded state schema before persisted baseline data is used
# for anomaly calculations.
function Assert-SysmonSensorStateSchemaSection01 {
  param([hashtable]$RunState)
$fields = @('Version','HostName','Timestamp','WindowHours','Alpha','Baseline','ConfigChanged','CatalogSource')
  if ($RunState.State -isnot [pscustomobject] -or @($RunState.State.PSObject.Properties.Name).Count -ne $fields.Count -or @($RunState.State.PSObject.Properties.Name | Where-Object { $fields -notcontains $_ }).Count -gt 0) { throw 'Sysmon sensor state has missing or unsupported fields.' }
}

function Assert-SysmonSensorStateSchemaSection02 {
  param([hashtable]$RunState)
if (($RunState.State.Version -isnot [int] -and $RunState.State.Version -isnot [long]) -or [int64]$RunState.State.Version -ne 1) { throw 'Sysmon sensor state Version is unsupported.' }
}

function Assert-SysmonSensorStateSchemaSection03 {
  param([hashtable]$RunState)
if ($RunState.State.HostName -isnot [string] -or $RunState.State.HostName.Length -gt 256 -or $RunState.State.Timestamp -isnot [string] -or $RunState.State.Timestamp.Length -gt 64 -or $RunState.State.CatalogSource -isnot [string] -or $RunState.State.CatalogSource.Length -gt 4096) { throw 'Sysmon sensor state contains an invalid bounded string.' }
}

function Assert-SysmonSensorStateSchemaSection04 {
  param([hashtable]$RunState)
if (($RunState.State.WindowHours -isnot [int] -and $RunState.State.WindowHours -isnot [long]) -or [int64]$RunState.State.WindowHours -lt 1 -or [int64]$RunState.State.WindowHours -gt 168) { throw 'Sysmon sensor state WindowHours is invalid.' }
}

function Assert-SysmonSensorStateSchemaSection05 {
  param([hashtable]$RunState)
if (((Test-AllConditions -Conditions @({ (Test-AllConditions -Conditions @({ $RunState.State.Alpha -isnot [double] }, { $RunState.State.Alpha -isnot [decimal] })) }, { $RunState.State.Alpha -isnot [int] })) -and $RunState.State.Alpha -isnot [long]) -or [double]::IsNaN([double]$RunState.State.Alpha) -or [double]::IsInfinity([double]$RunState.State.Alpha) -or [double]$RunState.State.Alpha -lt 0.01 -or [double]$RunState.State.Alpha -gt 1.0) { throw 'Sysmon sensor state Alpha is invalid.' }
}

function Assert-SysmonSensorStateSchemaSection06 {
  param([hashtable]$RunState)
if ($RunState.State.ConfigChanged -isnot [bool] -or $RunState.State.Baseline -isnot [pscustomobject] -or @($RunState.State.Baseline.PSObject.Properties).Count -gt 128) { throw 'Sysmon sensor state baseline or ConfigChanged field is invalid.' }
}

function Test-SysmonBaselineEntry {
  param($Entry)
  if ($Entry.Name -notmatch '^[1-9][0-9]{0,4}$') { return $false }
  if ([int]$Entry.Name -gt 65535) { return $false }
  $supportedTypes = @([double], [decimal], [int], [long])
  if ($supportedTypes -notcontains $Entry.Value.GetType()) { return $false }
  $value = [double]$Entry.Value
  if ($value -lt 0) { return $false }
  if ($value -gt 1000000000) { return $false }
  if ([double]::IsNaN($value)) { return $false }
  return (-not [double]::IsInfinity($value))
}
function Assert-SysmonSensorStateSchemaSection07 {
  param([hashtable]$RunState)
  foreach ($entry in @($RunState.State.Baseline.PSObject.Properties)) {
    if (-not (Test-SysmonBaselineEntry -Entry $entry)) { throw 'Sysmon sensor state Baseline contains an invalid key or value.' }
  }
}

function Assert-SysmonSensorStateSchema {
  param([Parameter(Mandatory)]$State, [hashtable]$RunState)
  $RunState.State = $State
    . Assert-SysmonSensorStateSchemaSection01 -RunState $RunState
    . Assert-SysmonSensorStateSchemaSection02 -RunState $RunState
    . Assert-SysmonSensorStateSchemaSection03 -RunState $RunState
    . Assert-SysmonSensorStateSchemaSection04 -RunState $RunState
    . Assert-SysmonSensorStateSchemaSection05 -RunState $RunState
    . Assert-SysmonSensorStateSchemaSection06 -RunState $RunState
    . Assert-SysmonSensorStateSchemaSection07 -RunState $RunState
}
# Returns only trusted, schema-valid state; corrupt or untrusted files are
# ignored so the sensor can rebuild a baseline without consuming forged data.
function Read-ValidatedSysmonState {
  param([Parameter(Mandatory)][string]$Path, [hashtable]$RunState)
  try { if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }; Assert-TrustedStateAcl -Path $Path; $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop; if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Sysmon state is not a regular file.' }; $raw = Get-BoundedUtf8FileContent -Path $item.FullName -MaximumBytes 65536; $RunState.state = $raw | ConvertFrom-Json -ErrorAction Stop; Assert-SysmonSensorStateSchema -State $RunState.state -RunState $RunState; return $RunState.state } catch { Write-Verbose "Ignoring invalid or untrusted Sysmon sensor state: $($_.Exception.Message)"; return $null }
}
function Write-SysmonStateSection01 {
  param([hashtable]$RunState)
Assert-SysmonSensorStateSchema -State $RunState.InputObject -RunState $RunState
  $directory = Split-Path -Parent $RunState.Path; Initialize-SysmonStateDirectory -directory $directory
  foreach ($protectedPath in @($RunState.Path,$RunState.Path + '.lock')) { if (Test-Path -LiteralPath $protectedPath) { $item = Get-Item -LiteralPath $protectedPath -Force -ErrorAction Stop; if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Sysmon state file or lock path is unsafe.' }; Assert-TrustedStateAcl -Path $item.FullName } }
  $RunState.lock = Open-TrustedStateFile -Path ($RunState.Path + '.lock') -Mode OpenOrCreate -Share ([IO.FileShare]::None); $RunState.stage = $null
}

function Write-SysmonStateSection02 {
  param([hashtable]$RunState)
try { Assert-TrustedStateAcl -Path ($RunState.Path + '.lock'); $RunState.stage = Join-Path $directory ('.state-' + [guid]::NewGuid().ToString('N') + '.json'); $json = $RunState.InputObject | ConvertTo-Json -Depth 10; $stageStream = Open-TrustedStateFile -Path $RunState.stage -Mode CreateNew -Share ([IO.FileShare]::None); try { $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json); $stageStream.Write($bytes,0,$bytes.Length); $stageStream.Flush($true) } finally { $stageStream.Dispose() }; Assert-TrustedStateAcl -Path $RunState.stage; if (Test-Path -LiteralPath $RunState.Path) { [IO.File]::Replace($RunState.stage,$RunState.Path,$null) } else { [IO.File]::Move($RunState.stage,$RunState.Path) }; Assert-TrustedStateAcl -Path $RunState.Path } finally { $RunState.lock.Dispose(); if ($RunState.stage -and (Test-Path -LiteralPath $RunState.stage)) { Remove-Item -LiteralPath $RunState.stage -Force -ErrorAction SilentlyContinue } }
}

function Write-SysmonState {
  param([Parameter(Mandatory)]$InputObject,[Parameter(Mandatory)][string]$Path, [hashtable]$RunState)
  $RunState.InputObject = $InputObject
  $RunState.Path = $Path
    . Write-SysmonStateSection01 -RunState $RunState
    . Write-SysmonStateSection02 -RunState $RunState
}
# Read-JsonFile replaced by Read-JsonFileSafe from lib/JsonCatalog.psm1
# Write-JsonFile: replaced by canonical Save-Json from lib/Serialization.psm1
# -----------------------------
# Catalog defaults
# -----------------------------
function Get-DefaultCatalog {
  param(
    [int]$DefaultWindowHours,
    [double]$DefaultAlpha,
    [double]$DefaultRatioFloor,
    [double]$DefaultRatioUpper,
    [int]$DefaultMinBaselineToCompare,
    [switch]$WithBuiltInRules
  )
  $rules = @()
  if ($WithBuiltInRules) {
    $rules = @(
      [pscustomobject]@{ Id = 1;  Name = 'Process Create';  Critical = $true;  MinPerWindow = 1;    MessageRegex = $null; Disabled = $false },
      [pscustomobject]@{ Id = 3;  Name = 'Network Connect'; Critical = $false; MinPerWindow = $null; MessageRegex = $null; Disabled = $false },
      [pscustomobject]@{ Id = 11; Name = 'File Create';     Critical = $false; MinPerWindow = $null; MessageRegex = $null; Disabled = $false },
      [pscustomobject]@{ Id = 16; Name = 'Config Change';   Critical = $false; MinPerWindow = $null; MessageRegex = $null; Disabled = $false },
      [pscustomobject]@{ Id = 22; Name = 'DNS Query';       Critical = $false; MinPerWindow = $null; MessageRegex = $null; Disabled = $false }
    )
  }
  [pscustomobject]@{
    WindowHours = $DefaultWindowHours
    Alpha = $DefaultAlpha
    RatioFloor = $DefaultRatioFloor
    RatioUpper = $DefaultRatioUpper
    MinBaselineToCompare = $DefaultMinBaselineToCompare
    Rules = $rules
  }
}
function Test-CatalogPropertySet {
  param(
    [Parameter(Mandatory)][pscustomobject]$Object,
    [Parameter(Mandatory)][string[]]$Allowed,
    [Parameter(Mandatory)][string]$Context
  )
  $seen = @{}
  foreach ($property in @($Object.PSObject.Properties)) {
    if (-not ($Allowed -contains $property.Name)) { throw "$Context contains unsupported property '$($property.Name)'." }
    $key = $property.Name.ToUpperInvariant()
    if ($seen.ContainsKey($key)) { throw "$Context contains duplicate property '$($property.Name)'." }
    $seen[$key] = $true
  }
}
function Test-CatalogInteger {
  param([Parameter(Mandatory)]$Value,[Parameter(Mandatory)][string]$Name,[int]$Minimum,[int]$Maximum)
  if ($Value -isnot [long] -and $Value -isnot [int]) { throw "$Name must be an integer." }
  $number = [int64]$Value
  if ($number -lt $Minimum -or $number -gt $Maximum) { throw "$Name must be between $Minimum and $Maximum." }
  return [int]$number
}
function Test-CatalogNumber {
  param([Parameter(Mandatory)]$Value,[Parameter(Mandatory)][string]$Name,[double]$Minimum,[double]$Maximum)
  if ((Test-AllConditions -Conditions @({ $Value -isnot [long] }, { $Value -isnot [int] })) -and $Value -isnot [double] -and $Value -isnot [decimal]) { throw "$Name must be numeric." }
  $number = [double]$Value
  if ((Test-AnyCondition -Conditions @({ [double]::IsNaN($number) }, { [double]::IsInfinity($number) })) -or $number -lt $Minimum -or $number -gt $Maximum) { throw "$Name must be between $Minimum and $Maximum." }
  return $number
}
function ConvertTo-ValidatedCatalogStage01 {
  param([hashtable]$RunState)
if ($rule -isnot [pscustomobject]) { throw 'Each catalog rule must be a JSON object.' }
    Test-CatalogPropertySet -Object $rule -Allowed @('Id','Name','Critical','MinPerWindow','MessageRegex','Disabled') -Context 'Catalog rule'
    if ($rule.PSObject.Properties.Name -notcontains 'Id') { throw 'Each catalog rule must contain Id.' }
    $ruleId = Test-CatalogInteger -Value $rule.Id -Name 'Catalog rule Id' -Minimum 1 -Maximum 65535
    if ($RunState.seenRuleIds.ContainsKey($ruleId)) { throw "Catalog contains duplicate rule Id $ruleId." }
    $RunState.seenRuleIds[$ruleId] = $true
}

function ConvertTo-ValidatedCatalogStage02 {
if ($rule.PSObject.Properties.Name -contains 'Name' -and ((Test-AnyCondition -Conditions @({ $rule.Name -isnot [string] }, { [string]::IsNullOrWhiteSpace($rule.Name) })) -or $rule.Name.Length -gt 128)) { throw 'Catalog rule Name must be a non-empty string no longer than 128 characters.' }
    foreach ($booleanName in @('Critical','Disabled')) {
      if ((Test-AllConditions -Conditions @({ $rule.PSObject.Properties.Name -contains $booleanName }, { $rule.$booleanName -isnot [bool] }))) { throw "Catalog rule $booleanName must be boolean." }
    }
}

function ConvertTo-ValidatedCatalogStage03 {
if ((Test-AllConditions -Conditions @({ $rule.PSObject.Properties.Name -contains 'MinPerWindow' }, { $null -ne $rule.MinPerWindow }))) { [void](Test-CatalogInteger -Value $rule.MinPerWindow -Name 'Catalog rule MinPerWindow' -Minimum 0 -Maximum 1000000) }
    if ($rule.PSObject.Properties.Name -contains 'MessageRegex') {
      if ($null -ne $rule.MessageRegex) {
        if ((Test-AnyCondition -Conditions @({ $rule.MessageRegex -isnot [string] }, { $rule.MessageRegex.Length -gt 512 }))) { throw 'Catalog rule MessageRegex must be null or a string no longer than 512 characters.' }
        try { [void][regex]::new($rule.MessageRegex, [System.Text.RegularExpressions.RegexOptions]::CultureInvariant, [TimeSpan]::FromSeconds(1)) } catch { throw "Catalog rule MessageRegex is invalid: $($_.Exception.Message)" }
      }
    }
}

function Assert-SysmonCatalogShape {
  param($Catalog)
  if ($Catalog -isnot [pscustomobject]) { throw 'Catalog must be a JSON object.' }
  Test-CatalogPropertySet -Object $Catalog -Allowed @('WindowHours','Alpha','RatioFloor','RatioUpper','MinBaselineToCompare','Rules') -Context 'Catalog'
  if ($Catalog.PSObject.Properties.Name -notcontains 'Rules') { throw 'Catalog must contain Rules.' }
  if ($Catalog.Rules -isnot [System.Array]) { throw 'Catalog.Rules must be an array.' }
  if ((Test-AnyCondition -Conditions @({ $Catalog.Rules.Count -lt 1 }, { $Catalog.Rules.Count -gt 128 }))) { throw 'Catalog.Rules must contain between 1 and 128 rules.' }
}
function Assert-SysmonCatalogSetting {
  param($Catalog, [string]$Property)
  switch ($Property) {
    'WindowHours' { [void](Test-CatalogInteger -Value $Catalog.$Property -Name "Catalog.$Property" -Minimum 1 -Maximum 168) }
    'MinBaselineToCompare' { [void](Test-CatalogInteger -Value $Catalog.$Property -Name "Catalog.$Property" -Minimum 0 -Maximum 1000000) }
    'Alpha' { [void](Test-CatalogNumber -Value $Catalog.$Property -Name "Catalog.$Property" -Minimum 0.01 -Maximum 1.0) }
    'RatioFloor' { [void](Test-CatalogNumber -Value $Catalog.$Property -Name "Catalog.$Property" -Minimum 0.0 -Maximum 1.0) }
    'RatioUpper' { [void](Test-CatalogNumber -Value $Catalog.$Property -Name "Catalog.$Property" -Minimum 1.0 -Maximum 1000.0) }
  }
}
function ConvertTo-ValidatedCatalog {
  param([Parameter(Mandatory)]$Catalog, [hashtable]$RunState)
  Assert-SysmonCatalogShape -Catalog $Catalog
  foreach ($property in @('WindowHours','Alpha','RatioFloor','RatioUpper','MinBaselineToCompare')) {
    if ($Catalog.PSObject.Properties.Name -contains $property) {
      Assert-SysmonCatalogSetting -Catalog $Catalog -Property $property
    }
  }
  $RunState.seenRuleIds = @{}
  foreach ($rule in @($Catalog.Rules)) {
    . ConvertTo-ValidatedCatalogStage01 -RunState $RunState
. ConvertTo-ValidatedCatalogStage02
. ConvertTo-ValidatedCatalogStage03
  }
  return $Catalog
}
function Get-ExplicitCatalog {
  param([Parameter(Mandatory)][string]$Path, [hashtable]$RunState)
  try {
    $catalogItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($catalogItem.PSIsContainer -or $catalogItem.Length -gt 262144) { throw 'CatalogPath must be a JSON file no larger than 256 KiB.' }
  } catch {
    throw "CatalogPath could not be safely inspected: $($_.Exception.Message)"
  }
  $read = Read-JsonFileWithStatus -Path $Path
  if (-not $read.Meta.Loaded) { throw "CatalogPath $($read.Meta.Status): $($read.Meta.Error)" }
  return (ConvertTo-ValidatedCatalog -Catalog $read.Data -RunState $RunState)
}
function Write-CatalogFailureResult {
  param([Parameter(Mandatory)][string]$Message)
  $finding = [pscustomobject]@{ Code = 'SYS-CatalogInvalid'; Severity = 'High'; Message = $Message }
  $summary = [pscustomobject]@{ Status = 'ERROR'; CatalogPath = $CatalogPath; Error = $Message }
  $result = Get-V2ResultObject -ScriptName '17-Sysmon-Rule-Drift-Sensor.ps1' -Mode $Mode -Result 'FAIL' -Findings @($finding) -Summary $summary -Metadata @{ CatalogPathProvided = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result 'FAIL')
}
# -----------------------------
# Event Log (audit)
# -----------------------------
function Limit-EventMessage {
  param([Parameter(Mandatory)][string]$Message)
  if ($Message.Length -le $script:MaxEventMessageLength) { return $Message }
  return ($Message.Substring(0, $script:MaxEventMessageLength) + "`r`n[TRUNCATED]")
}
function Write-AuditEvent {
  param(
    [int]$EventId,
    [string]$Message,
    [ValidateSet('Information','Warning','Error')]
    [string]$Level
  )
  $msg = Limit-EventMessage -Message $Message
  if (-not (Write-HealthEvent -LogName $script:EventLogName -Source $script:EventSourceName -Id $EventId -Level $Level -Message $msg)) {
    # Console fallback, do not emit pipeline output.
    Write-UiLine ("[{0}][{1}] {2}" -f $Level,$EventId,$msg)
  }
}
# -----------------------------
# Sysmon channel probe
# -----------------------------
# -----------------------------
# Counting
# -----------------------------
# Runs Get-WinEvent in a disposable pipeline with count and time limits because
# a busy or damaged event channel must not block the monitoring run indefinitely.
# -----------------------------
# Remediation
# -----------------------------
# HARDZERO remediation launches another PowerShell script, so normalize the path
# to a real file inside this repo's scripts directory before any signature check
# or process launch. This prevents catalog/profile input from selecting an
# arbitrary local script through traversal or reparse points.
# Enumerates the fixed code closure required by remediation; explicit membership
# prevents arbitrary files added to lib/ or scripts/ from becoming executable.
# Verifies every closure member is a trusted regular file before the caller
# acquires handles that keep those exact files immutable during launch.
# Launches only the trusted updater closure in Windows PowerShell and reports a
# structured outcome; the sensor never remediates inline in its own process.
# -----------------------------
# Result objects (pipeline)
# -----------------------------
# -----------------------------
# Console summary (no pipeline pollution)
# -----------------------------

. (Join-Path $PSScriptRoot '17-Sysmon-Rule-Drift-Sensor.runtime.ps1')
