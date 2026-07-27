<#
.SYNOPSIS
Internal collection and trust-boundary helpers for support bundles.

.DESCRIPTION
Creates restricted output locations, resolves evidence paths, and invokes
bounded system-report collectors. Centralizing these checks ensures every
bundle artifact is written beneath the same trusted, administrator-only root.
#>
Import-Module (Join-Path $PSScriptRoot '../../lib/Validation.psm1')

function SB_IsWindowsPlatform {
  [CmdletBinding()]
  param()

  if ($PSVersionTable.PSEdition -eq 'Core') { return [bool]$IsWindows }
  return $true
}

function SB_GetDefaultTrustedOutputRoot {
  [CmdletBinding()]
  param()

  $commonData = if (SB_IsWindowsPlatform) {
    [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  } else {
    # Test hosts may exercise the Windows-only script with a scoped ProgramData.
    $env:ProgramData
  }
  if ([string]::IsNullOrWhiteSpace($commonData)) {
    throw 'The system CommonApplicationData directory could not be resolved.'
  }

  return [System.IO.Path]::GetFullPath(
    (Join-Path (Join-Path $commonData 'BaselineOpsForWindows') 'SupportBundles')
  )
}

function SB_SetRestrictedDirectoryAcl {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  if (-not (SB_IsWindowsPlatform)) { return }

  $administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $localSystem = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
  $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  $propagation = [System.Security.AccessControl.PropagationFlags]::None
  $fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
  $allow = [System.Security.AccessControl.AccessControlType]::Allow
  $acl = New-Object System.Security.AccessControl.DirectorySecurity
  $acl.SetOwner($administrators)
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($sid in @($administrators, $localSystem)) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
      $sid, $fullControl, $inheritance, $propagation, $allow
    )
    [void]$acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop

  $verified = Get-Acl -LiteralPath $Path -ErrorAction Stop
  if (-not $verified.AreAccessRulesProtected) {
    throw "Trusted output ACL inheritance remains enabled: $Path"
  }
  $allowedSids = @($administrators.Value, $localSystem.Value)
  $rules = @($verified.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
  if ($rules.Count -ne 2) { throw "Trusted output ACL contains unexpected explicit rules: $Path" }
  foreach ($rule in $rules) {
    if (
      $allowedSids -notcontains $rule.IdentityReference.Value -or
      $rule.AccessControlType -ne $allow -or
      ($rule.FileSystemRights -band $fullControl) -ne $fullControl
    ) {
      throw "Trusted output ACL grants unexpected access: $Path"
    }
  }
}

function SB_WriteLog {
  param(
    [AllowNull()]
    [AllowEmptyString()]
    [string]$Message,

    [ValidateSet('INFO','WARN','ERROR','OK')]
    [string]$Level = 'INFO'
  )

  # Never throw on empty log lines.
  if ([string]::IsNullOrEmpty($Message)) { return }

  $prefix = "[{0}] " -f $Level
  switch ($Level) {
    'INFO'  { Write-UiLine -Message ($prefix + $Message) -ForegroundColor Gray -UseInformationStream:$script:UseInformationStream }
    'OK'    { Write-UiLine -Message ($prefix + $Message) -ForegroundColor Green -UseInformationStream:$script:UseInformationStream }
    'WARN'  { Write-UiLine -Message ($prefix + $Message) -ForegroundColor Yellow -UseInformationStream:$script:UseInformationStream }
    'ERROR' { Write-UiLine -Message ($prefix + $Message) -ForegroundColor Red -UseInformationStream:$script:UseInformationStream }
  }
}

function SB_WriteSection {
  param([Parameter(Mandatory)][string]$Title)

  $line = ('-' * 72)
  Write-UiLine -Message ("[INFO] {0}" -f $line) -ForegroundColor DarkGray -UseInformationStream:$script:UseInformationStream
  Write-UiLine -Message ("[INFO] {0}" -f $Title) -ForegroundColor Cyan -UseInformationStream:$script:UseInformationStream
  Write-UiLine -Message ("[INFO] {0}" -f $line) -ForegroundColor DarkGray -UseInformationStream:$script:UseInformationStream
}

function SB_WriteHealthEvent {
  param(
    [int]$Id,
    [string]$Msg,
    [ValidateSet('Information','Warning','Error')]
    [string]$Level = 'Information'
  )

  if (-not (Write-HealthEvent -LogName Application -Source $EventSource -Level $Level -Id $Id -Message $Msg)) {
    SB_WriteLog -Level $(if ($Level -eq 'Error') { 'ERROR' } elseif ($Level -eq 'Warning') { 'WARN' } else { 'INFO' }) -Message $Msg
  }
}

# -------------------- Basic helpers --------------------
function SB_SaveTextFile {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Text
  )
  [void](Ensure-Directory -Path (Split-Path -Parent $Path))
  $Text | Out-File -FilePath $Path -Encoding utf8
}

function SB_SaveJsonFile {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)]$Object
  )
  [void](Ensure-Directory -Path (Split-Path -Parent $Path))
  ($Object | ConvertTo-Json -Depth 40) | Out-File -FilePath $Path -Encoding utf8
}

# -------------------- Structured records --------------------
function SB_NewRecord {
  param(
    [Parameter(Mandatory)][string]$Name,
    [bool]$Ok,
    [string]$ArtifactPath,
    [string]$Note,
    [Alias('Error')]
    [string]$ErrorText
  )

  [pscustomobject]@{
    Name         = $Name
    Ok           = [bool]$Ok
    ArtifactPath = $ArtifactPath
    Note         = $Note
    Error        = $ErrorText
    Time         = (Get-Date).ToString('s')
  }
}

function SB_NewSummary {
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][bool]$IsAdminNow,
    [Parameter(Mandatory)][int]$DaysBack,
    [Parameter(Mandatory)][bool]$IncludeSec,
    [Parameter(Mandatory)][bool]$IncludeDef,
    [string]$ConfigPath,
    [string]$ProofDir,
    [string]$ReasonText
  )

  [pscustomobject]@{
    Hostname    = $ComputerName
    Time        = (Get-Date).ToString('s')
    User        = $env:USERNAME
    Admin       = $IsAdminNow
    DaysBack    = $DaysBack
    IncludeSec  = $IncludeSec
    IncludeDef  = $IncludeDef
    ConfigPath  = $ConfigPath
    ProofDir    = $ProofDir
    Reason      = $ReasonText
    ZipPath     = $null
    WorkDir     = $null
    Records     = @()
  }
}

function SB_AddRecord {
  param(
    [Parameter(Mandatory)][object]$Summary,
    [Parameter(Mandatory)][pscustomobject]$Record
  )

  if (-not $Summary) { return }
  if (@($Summary.PSObject.Properties.Name) -notcontains 'Records') { return }

  if ($Summary.Records -isnot [object[]]) {
    $Summary.Records = @($Summary.Records)
  }

  $Summary.Records += $Record
}

function SB_TryStep {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][scriptblock]$Code
  )

  try {
    $r = & $Code
    if ($r -is [pscustomobject]) { return $r }
    return (SB_NewRecord -Name $Name -Ok $true -ArtifactPath $null -Note $null -Error $null)
  } catch {
    return (SB_NewRecord -Name $Name -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}

# -------------------- Summary printing (console-only) --------------------
function SB_ShowSummary {
  param([Parameter(Mandatory)][object]$Summary)

  if (-not $Summary) {
    SB_WriteLog -Level 'ERROR' -Message 'Summary is null (unexpected).'
    return
  }

  if (@($Summary.PSObject.Properties.Name) -notcontains 'Records') {
    SB_WriteLog -Level 'ERROR' -Message ("Summary missing Records. Type={0}" -f $Summary.GetType().FullName)
    return
  }

  $records = @()
  try { $records = @($Summary.Records) } catch { $records = @() }

  $errors = @($records | Where-Object { -not $_.Ok })
  $ok     = @($records | Where-Object { $_.Ok })

  SB_WriteSection -Title 'SupportBundle summary'
  SB_WriteLog -Message ("Host            : {0}" -f $Summary.Hostname) -Level 'INFO'
  SB_WriteLog -Message ("Time            : {0}" -f $Summary.Time) -Level 'INFO'
  SB_WriteLog -Message ("User            : {0}" -f $Summary.User) -Level 'INFO'
  SB_WriteLog -Message ("Admin           : {0}" -f $Summary.Admin) -Level $(if ($Summary.Admin) { 'OK' } else { 'WARN' })
  SB_WriteLog -Message ("DaysBack        : {0}" -f $Summary.DaysBack) -Level 'INFO'
  SB_WriteLog -Message ("IncludeSecurity : {0}" -f $Summary.IncludeSec) -Level 'INFO'
  SB_WriteLog -Message ("IncludeDefender : {0}" -f $Summary.IncludeDef) -Level 'INFO'
  if (-not [string]::IsNullOrWhiteSpace($Summary.Reason)) {
    SB_WriteLog -Message ("Reason          : {0}" -f $Summary.Reason) -Level 'INFO'
  }

  SB_WriteLog -Message ("WorkDir         : {0}" -f $(if (-not [string]::IsNullOrWhiteSpace($Summary.WorkDir)) { $Summary.WorkDir } else { '(not created)' })) -Level 'INFO'
  SB_WriteLog -Message ("Zip             : {0}" -f $(if (-not [string]::IsNullOrWhiteSpace($Summary.ZipPath)) { $Summary.ZipPath } else { '(not created)' })) -Level 'INFO'

  if (-not $script:UseInformationStream) {
    Write-UiLine -Message '' -ForegroundColor Gray
  }
  SB_WriteLog -Message ("Records         : {0}" -f $records.Count) -Level 'INFO'
  SB_WriteLog -Message ("Successful      : {0}" -f $ok.Count) -Level 'OK'

  if ($errors.Count -gt 0) {
    SB_WriteLog -Message ("Errors          : {0}" -f $errors.Count) -Level 'ERROR'
    foreach ($e in ($errors | Select-Object -First 25)) {
      $msg = if (-not [string]::IsNullOrEmpty($e.Error)) { $e.Error } else { 'Unknown error' }
      SB_WriteLog -Level 'ERROR' -Message ("  ! {0} :: {1}" -f $e.Name, $msg)
    }
    if ($errors.Count -gt 25) {
      SB_WriteLog -Level 'WARN' -Message ("  ... ({0} more errors)" -f ($errors.Count - 25))
    }
  } else {
    SB_WriteLog -Message "Errors          : 0" -Level 'OK'
  }
}

# -------------------- Config --------------------
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

function SB_LoadJsonConfig {
  param(
    [string]$Path,
    [Parameter(Mandatory)][pscustomobject]$DefaultConfig,
    [switch]$AllowDefaults
  )

  try {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
      if ($AllowDefaults) {
        return [pscustomobject]@{ Ok = $true; Config = $DefaultConfig; UsedDefault = $true; Error = $null }
      }
      throw "Config file was not found or is not a regular file: $Path"
    }

    $configItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($configItem.PSIsContainer -or ($configItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
      throw "Config file must be a regular non-reparse file: $Path"
    }
    $raw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
    if ([string]::IsNullOrWhiteSpace($raw)) { throw 'Config file must not be empty.' }

    $cfg = $raw | ConvertFrom-Json
    if ($null -eq $cfg -or $cfg -is [string] -or $cfg -is [System.ValueType] -or $cfg -is [System.Collections.IEnumerable]) {
      throw 'Config root must be an object.'
    }

    $rootNames = @($cfg.PSObject.Properties | ForEach-Object Name)
    foreach ($name in $rootNames) {
      if ($name -notin @('Paths', 'ProofOutFiles')) { throw "Config contains unsupported property '$name'." }
    }
    if ($rootNames -notcontains 'Paths' -or $rootNames -notcontains 'ProofOutFiles') {
      throw 'Config must contain Paths and ProofOutFiles objects.'
    }
    foreach ($sectionName in @('Paths', 'ProofOutFiles')) {
      $section = $cfg.$sectionName
      if ($null -eq $section -or $section -is [string] -or $section -is [System.ValueType] -or $section -is [System.Collections.IEnumerable]) {
        throw "Config.$sectionName must be an object."
      }
    }

    $pathNames = @($cfg.Paths.PSObject.Properties | ForEach-Object Name)
    if ($pathNames.Count -ne 1 -or $pathNames -notcontains 'ProofDir' -or $cfg.Paths.ProofDir -isnot [string] -or [string]::IsNullOrWhiteSpace($cfg.Paths.ProofDir)) {
      throw 'Config.Paths must contain only a non-empty string ProofDir.'
    }

    $expectedNames = @('SysmonState', 'SysmonDriftState', 'SoftwareInventory', 'FirewallAudit', 'HardwareAudit')
    $proofNames = @($cfg.ProofOutFiles.PSObject.Properties | ForEach-Object Name)
    foreach ($name in $proofNames) {
      if ($name -notin $expectedNames) { throw "Config.ProofOutFiles contains unsupported property '$name'." }
      $value = $cfg.ProofOutFiles.$name
      if ($null -ne $value -and $value -isnot [string]) { throw "Config.ProofOutFiles.$name must be a string or null." }
    }
    foreach ($name in $expectedNames) {
      if ($proofNames -notcontains $name) { $cfg.ProofOutFiles | Add-Member -NotePropertyName $name -NotePropertyValue $null }
    }

    return [pscustomobject]@{ Ok = $true; Config = $cfg; UsedDefault = $false; Error = $null }
  } catch {
    if ($AllowDefaults) {
      return [pscustomobject]@{ Ok = $true; Config = $DefaultConfig; UsedDefault = $true; Error = $_.Exception.Message }
    }
    return [pscustomobject]@{ Ok = $false; Config = $null; UsedDefault = $false; Error = $_.Exception.Message }
  }
}

# Restricts bundle output to the fixed CommonApplicationData root and hardens
# each created component before any diagnostic artifact is written.
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
    if (Test-Path -LiteralPath $current) {
      $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
      if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Trusted output root component must be a non-reparse directory: $current"
      }
    } else {
      New-Item -ItemType Directory -Path ([System.Management.Automation.WildcardPattern]::Escape($current)) -ErrorAction Stop | Out-Null
    }
    SB_SetRestrictedDirectoryAcl -Path $current
  }

  $resolved = (Resolve-Path -LiteralPath $fullPath -ErrorAction Stop).Path
  if (Test-PathContainsReparsePoint -Path $resolved -Root $commonData) { throw "Trusted output root traverses a reparse point: $resolved" }
  return $resolved
}

# Creates or validates one bundle subdirectory without permitting reparse-point
# traversal or a path that escapes the already trusted output root.
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
  if (Test-Path -LiteralPath $fullPath) {
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
      throw "Support-bundle path must be a non-reparse directory: $fullPath"
    }
  } else {
    New-Item -ItemType Directory -Path ([System.Management.Automation.WildcardPattern]::Escape($fullPath)) -ErrorAction Stop | Out-Null
  }
  $resolved = (Resolve-Path -LiteralPath $fullPath -ErrorAction Stop).Path
  if (Test-PathContainsReparsePoint -Path $resolved -Root $root) {
    throw "Support-bundle directory traverses a reparse point: $resolved"
  }
  SB_SetRestrictedDirectoryAcl -Path $resolved
  return $resolved
}

# Accepts only the expected proof filename beneath the trusted root, preventing
# configuration from redirecting privileged collectors to arbitrary files.
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
  $candidate = if ([System.IO.Path]::IsPathRooted($ConfiguredPath)) { [System.IO.Path]::GetFullPath($ConfiguredPath) } else { [System.IO.Path]::GetFullPath((Join-Path $root $ConfiguredPath)) }
  $expected = [System.IO.Path]::GetFullPath((Join-Path $root $ExpectedFileName))
  if (-not $candidate.Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Config.ProofOutFiles.$PropertyName must identify only $ExpectedFileName beneath the trusted proof root."
  }
  if (Test-Path -LiteralPath $candidate) {
    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { throw "Config.ProofOutFiles.$PropertyName must identify a regular non-reparse file." }
    $resolved = (Resolve-Path -LiteralPath $candidate -ErrorAction Stop).Path
    if (-not (Test-PathUnderRoot -Path $resolved -Root $root) -or (Test-PathContainsReparsePoint -Path $resolved -Root $root)) { throw "Config.ProofOutFiles.$PropertyName is outside the trusted proof root or traverses a reparse point." }
    return $resolved
  }
  return $candidate
}

# -------------------- Registry trigger (StrictMode-safe) --------------------
function SB_TryGetRegValue {
  param(
    [Parameter(Mandatory)][string]$KeyPath,
    [Parameter(Mandatory)][string]$Name
  )
  try { return (Get-ItemPropertyValue -Path $KeyPath -Name $Name -ErrorAction Stop) }
  catch { return $null }
}

function SB_GetRegistryTrigger {
  param([Parameter(Mandatory)][string]$KeyPath)

  try {
    if (-not (Test-Path -Path $KeyPath)) {
      return [pscustomobject]@{ Ok=$false; Error="Path not found: $KeyPath" }
    }

    return [pscustomobject]@{
      Ok                     = $true
      Error                  = $null
      Request                = SB_TryGetRegValue -KeyPath $KeyPath -Name 'Request'
      Days                   = SB_TryGetRegValue -KeyPath $KeyPath -Name 'Days'
      IncludeSecurity        = SB_TryGetRegValue -KeyPath $KeyPath -Name 'IncludeSecurity'
      IncludeDefenderSupport = SB_TryGetRegValue -KeyPath $KeyPath -Name 'IncludeDefenderSupport'
      Reason                 = SB_TryGetRegValue -KeyPath $KeyPath -Name 'Reason'
    }
  } catch {
    return [pscustomobject]@{ Ok=$false; Error=$_.Exception.Message }
  }
}
# -------------------- Event logs --------------------
function SB_TestEventLogExists {
  param([Parameter(Mandatory)][string]$LogName)
  try {
    $native = Invoke-NativeCommand -Command 'wevtutil.exe' -Arguments @('gl', $LogName) -CaptureOutput -Quiet -TimeoutSeconds 30 -MaxOutputBytes 65536
    return ($null -ne $native -and $native.Success -and -not $native.TimedOut -and -not $native.OutputTruncated -and -not $native.StderrTruncated)
  } catch { return $false }
}

function SB_ExportEventLogEvtx {
  param(
    [Parameter(Mandatory)][string]$LogName,
    [Parameter(Mandatory)][string]$OutFile,
    [ValidateRange(1,365)]
    [int]$DaysBack = 7
  )

  [void](Ensure-Directory -Path (Split-Path -Parent $OutFile))

  $ms    = [int64]($DaysBack * 24 * 60 * 60 * 1000)
  $xpath = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"

  try {
    $wevtArgs = @('epl', $LogName, $OutFile, "/q:$xpath", '/ow:true')
    $native = Invoke-NativeCommand -Command 'wevtutil.exe' -Arguments $wevtArgs -ThrowOnError -CaptureOutput -TimeoutSeconds 120 -MaxOutputBytes 2097152
    if ($native.TimedOut -or $native.OutputTruncated -or $native.StderrTruncated) { throw 'wevtutil export timed out or produced truncated output.' }
    return (SB_NewRecord -Name ("EVTX:{0}" -f $LogName) -Ok $true -ArtifactPath $OutFile -Note $null -Error $null)
  } catch {
    return (SB_NewRecord -Name ("EVTX:{0}" -f $LogName) -Ok $false -ArtifactPath $OutFile -Note $null -Error $_.Exception.Message)
  }
}

function SB_ExportEventLogFallback {
  param(
    [Parameter(Mandatory)][string]$LogName,
    [Parameter(Mandatory)][string]$OutFileBase,
    [ValidateRange(1,365)]
    [int]$DaysBack = 7,
    [ValidateRange(1,100000)]
    [int]$MaxEvents = 10000
  )

  $ms    = [int64]($DaysBack * 24 * 60 * 60 * 1000)
  $xpath = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"

  try {
    # Get-WinEvent otherwise materializes every matching event before either
    # report is written.  Keep the fallback bounded as it is used precisely
    # when the native EVTX export path was unavailable.
    $events = @(Get-WinEvent -LogName $LogName -FilterXPath $xpath -MaxEvents $MaxEvents -ErrorAction Stop)

    $csv = $OutFileBase + '.csv'
    $txt = $OutFileBase + '.txt'
    [void](Ensure-Directory -Path (Split-Path -Parent $csv))

    $events |
      Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, LogName, Message |
      Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8

    ($events | Select-Object -First ([Math]::Min(200, $MaxEvents)) | Format-List * | Out-String -Width 4000) |
      Out-File -FilePath $txt -Encoding utf8

    return (SB_NewRecord -Name ("Fallback:{0}" -f $LogName) -Ok $true -ArtifactPath $csv -Note 'Fallback CSV/TXT created' -Error $null)
  } catch {
    return (SB_NewRecord -Name ("Fallback:{0}" -f $LogName) -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}

# -------------------- Proofs --------------------
function SB_CopyIfExists {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$DestDir
  )

  try {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
      return (SB_NewRecord -Name 'CopyProof' -Ok $true -ArtifactPath $null -Note ("Skip (not found): {0}" -f $Path) -Error $null)
    }

    [void](Ensure-Directory -Path $DestDir)
    Copy-Item -LiteralPath $Path -Destination $DestDir -Force -ErrorAction Stop
    return (SB_NewRecord -Name 'CopyProof' -Ok $true -ArtifactPath $DestDir -Note ("Copied: {0}" -f (Split-Path -Leaf $Path)) -Error $null)
  } catch {
    return (SB_NewRecord -Name 'CopyProof' -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}

# -------------------- Reports --------------------
function SB_ExportTextCommand {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Command,
    [Parameter(Mandatory)][string[]]$Arguments,
    [Parameter(Mandatory)][string]$OutDir
  )

  try {
    [void](Ensure-Directory -Path $OutDir)
    $path = Join-Path $OutDir ($Name + '.txt')
    $native = Invoke-NativeCommand -Command $Command -Arguments $Arguments -CaptureOutput -Quiet -TimeoutSeconds 60 -MaxOutputBytes 1048576
    if ($null -eq $native -or -not $native.Success -or $native.TimedOut -or $native.OutputTruncated -or $native.StderrTruncated) { throw "$Name timed out, failed, or produced truncated output." }
    $text = $native.Output
    SB_SaveTextFile -Path $path -Text $text
    return (SB_NewRecord -Name ("Report:{0}" -f $Name) -Ok $true -ArtifactPath $path -Note $null -Error $null)
  } catch {
    return (SB_NewRecord -Name ("Report:{0}" -f $Name) -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}

# Runs the bounded core diagnostic set and emits an index so partial collector
# failures remain visible instead of making the bundle appear complete.
function SB_ExportSystemReports {
  param([Parameter(Mandatory)][string]$OutDir)

  $list = @()

  $list += (SB_ExportTextCommand -Name 'systeminfo'          -OutDir $OutDir -Command 'systeminfo.exe' -Arguments @())
  $list += (SB_ExportTextCommand -Name 'ipconfig_all'        -OutDir $OutDir -Command 'ipconfig.exe' -Arguments @('/all'))
  $list += (SB_ExportTextCommand -Name 'route_print'         -OutDir $OutDir -Command 'route.exe' -Arguments @('print'))
  $list += (SB_ExportTextCommand -Name 'netsh_winhttp_proxy' -OutDir $OutDir -Command 'netsh.exe' -Arguments @('winhttp','show','proxy'))
  $list += (SB_ExportTextCommand -Name 'whoami_all'          -OutDir $OutDir -Command 'whoami.exe' -Arguments @('/all'))

  $list += (SB_TryStep -Name 'Report:hotfixes' -Code {
    [void](Ensure-Directory -Path $OutDir)
    $path = Join-Path $OutDir 'hotfixes.json'
    $hotfix = Get-HotFix | Select-Object HotFixID, InstalledOn, Description, InstalledBy
    SB_SaveJsonFile -Path $path -Object $hotfix
    SB_NewRecord -Name 'Report:hotfixes' -Ok $true -ArtifactPath $path -Note $null -Error $null
  })

  $idx = Join-Path $OutDir 'ReportsIndex.json'
  SB_SaveJsonFile -Path $idx -Object $list
  $list += (SB_NewRecord -Name 'Report:index' -Ok $true -ArtifactPath $idx -Note $null -Error $null)

  return $list
}

# -------------------- KB feed --------------------
function SB_ExportKbStatus {
  param(
    [Parameter(Mandatory)][string]$KbFeedPath,
    [Parameter(Mandatory)][string]$OutFile
  )

  if (-not (Test-Path -LiteralPath $KbFeedPath)) {
    return (SB_NewRecord -Name 'KBFeed' -Ok $true -ArtifactPath $null -Note ("KB feed not found (skip): {0}" -f $KbFeedPath) -Error $null)
  }

  try {
    $kbfeed = Get-BoundedUtf8FileContent -Path $KbFeedPath -MaximumBytes 16777216 | ConvertFrom-Json
    $installedKB = @(Get-HotFix | Select-Object -ExpandProperty HotFixID)

    $missingCritical = @()
    $missingZeroDay  = @()

    if ($kbfeed -and $kbfeed.KBs) {
      foreach ($kb in $kbfeed.KBs) {
        if ($installedKB -notcontains $kb.KB) {
          if ($kb.IsZeroDay -eq $true) { $missingZeroDay += $kb } else { $missingCritical += $kb }
        }
      }
    }

    $kbStatus = [pscustomobject]@{
      CriticalFeedPath   = $KbFeedPath
      Time               = (Get-Date).ToString('s')
      InstalledHotFixIDs = $installedKB
      MissingCritical    = $missingCritical
      MissingZeroDay     = $missingZeroDay
      Summary            = "MissingCritical=$($missingCritical.Count), ZeroDay=$($missingZeroDay.Count)"
      MethodNote         = 'InstalledHotFixIDs from Get-HotFix; may not reflect full LCU/SSU state.'
    }

    SB_SaveJsonFile -Path $OutFile -Object $kbStatus

    $note = $null
    if ($missingZeroDay.Count -gt 0) {
      $note = "Missing Zero-Day KB(s): " + (($missingZeroDay | ForEach-Object { $_.KB }) -join ', ')
    } elseif ($missingCritical.Count -gt 0) {
      $note = "Missing critical KB(s): " + (($missingCritical | ForEach-Object { $_.KB }) -join ', ')
    }

    return (SB_NewRecord -Name 'KBFeed' -Ok $true -ArtifactPath $OutFile -Note $note -Error $null)
  } catch {
    return (SB_NewRecord -Name 'KBFeed' -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}

# -------------------- Defender --------------------
function SB_ExportDefenderStatus {
  param([Parameter(Mandatory)][string]$OutDir)

  $list = @()
  [void](Ensure-Directory -Path $OutDir)

  $list += (SB_TryStep -Name 'Defender:status' -Code {
    $cmd = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
    if (-not $cmd) { throw 'Get-MpComputerStatus not available.' }
    $path = Join-Path $OutDir 'DefenderStatus.json'
    SB_SaveJsonFile -Path $path -Object (Get-MpComputerStatus)
    SB_NewRecord -Name 'Defender:status' -Ok $true -ArtifactPath $path -Note $null -Error $null
  })

  $list += (SB_TryStep -Name 'Defender:preference' -Code {
    $cmd = Get-Command Get-MpPreference -ErrorAction SilentlyContinue
    if (-not $cmd) { throw 'Get-MpPreference not available.' }
    $path = Join-Path $OutDir 'DefenderPreference.json'
    SB_SaveJsonFile -Path $path -Object (Get-MpPreference)
    SB_NewRecord -Name 'Defender:preference' -Ok $true -ArtifactPath $path -Note $null -Error $null
  })

  $idx = Join-Path $OutDir 'DefenderIndex.json'
  SB_SaveJsonFile -Path $idx -Object $list
  $list += (SB_NewRecord -Name 'Defender:index' -Ok $true -ArtifactPath $idx -Note $null -Error $null)

  return $list
}

function SB_ResolveMpCmdRun {
  $candidates = @()

  $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
  if (-not [string]::IsNullOrWhiteSpace($programFiles)) {
    $pfCandidate = Join-Path $programFiles 'Windows Defender\MpCmdRun.exe'
    if (Test-Path -LiteralPath $pfCandidate -PathType Leaf) { $candidates += $pfCandidate }
  }

  $commonData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  $platformRoot = if ([string]::IsNullOrWhiteSpace($commonData)) { $null } else { Join-Path $commonData 'Microsoft\Windows Defender\Platform' }
  if (-not [string]::IsNullOrWhiteSpace($platformRoot) -and (Test-Path -LiteralPath $platformRoot -PathType Container)) {
    $latest = Get-ChildItem -LiteralPath $platformRoot -Directory -ErrorAction SilentlyContinue |
      Sort-Object Name -Descending |
      Select-Object -First 1
    if ($latest) {
      $platCandidate = Join-Path $latest.FullName 'MpCmdRun.exe'
      if (Test-Path -LiteralPath $platCandidate) { $candidates += $platCandidate }
    }
  }

  if ($candidates.Count -gt 0) { return $candidates[0] }
  return $null
}

# Invokes Microsoft's support collector with bounded output, then copies the
# resulting CAB into the protected bundle rather than exposing its system path.
function SB_NewDefenderSupportCab {
  param([Parameter(Mandatory)][string]$OutDir)

  [void](Ensure-Directory -Path $OutDir)

  $mpCmdRun   = SB_ResolveMpCmdRun
  $commonData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  if ([string]::IsNullOrWhiteSpace($commonData)) { throw 'CommonApplicationData could not be resolved.' }
  $cabDefault = Join-Path $commonData 'Microsoft\Windows Defender\Support\MpSupportFiles.cab'
  $cabOut     = Join-Path $OutDir ("MpSupportFiles-{0}.cab" -f (Get-Date).ToString('yyyyMMdd-HHmmss'))

  try {
    if (-not $mpCmdRun) { throw 'MpCmdRun.exe not found.' }

    $native = Invoke-NativeCommand -Command $mpCmdRun -Arguments @('-GetFiles') -CaptureOutput -Quiet -TimeoutSeconds 600 -MaxOutputBytes 1048576
    if ($null -eq $native -or -not $native.Success -or $native.TimedOut -or $native.OutputTruncated -or $native.StderrTruncated) { throw 'MpCmdRun -GetFiles timed out, failed, or produced truncated output.' }

    if (-not (Test-Path -LiteralPath $cabDefault)) { throw "CAB not found at expected path: $cabDefault" }
    Copy-Item -LiteralPath $cabDefault -Destination $cabOut -Force

    return (SB_NewRecord -Name 'Defender:supportCab' -Ok $true -ArtifactPath $cabOut -Note $null -Error $null)
  } catch {
    return (SB_NewRecord -Name 'Defender:supportCab' -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}
