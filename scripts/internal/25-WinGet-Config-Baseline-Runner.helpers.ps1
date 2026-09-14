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
    return Initialize-PortableWinGetStagingRoot -StagingRoot $StagingRoot
  }
  if ([string]::IsNullOrWhiteSpace($commonApplicationData)) {
    throw 'CommonApplicationData could not be resolved for WinGet staging.'
  }

  $fixedRoot = Join-Path $commonApplicationData 'BaselineOpsForWindows\WinGetConfigStaging'
  if ((Test-AllConditions -Conditions @({ -not [string]::IsNullOrWhiteSpace($StagingRoot) }, { -not [System.IO.Path]::GetFullPath($StagingRoot).Equals([System.IO.Path]::GetFullPath($fixedRoot), [System.StringComparison]::OrdinalIgnoreCase) }))) {
    throw 'WinGet staging root is fixed under CommonApplicationData.'
  }

  $fullRoot = [System.IO.Path]::GetFullPath($fixedRoot)
  if (Test-Path -LiteralPath $fullRoot) { return Get-ExistingWinGetStagingRoot -Path $fullRoot }
  return New-MissingWinGetStagingRoot -Path $fullRoot
}
function Initialize-PortableWinGetStagingRoot {
  param([AllowEmptyString()][string]$StagingRoot)
  if ([string]::IsNullOrWhiteSpace($StagingRoot)) { throw 'A staging root is required for non-Windows helper tests.' }
  $portableRoot = [System.IO.Path]::GetFullPath($StagingRoot)
  [System.IO.Directory]::CreateDirectory($portableRoot) | Out-Null
  return $portableRoot
}
function Get-ExistingWinGetStagingRoot {
  param([string]$Path)
  $rootItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
    throw 'WinGet staging root is not a regular directory.'
  }
  Assert-TrustedWindowsPathAcl -Path $rootItem.FullName -CheckAncestors | Out-Null
  return $rootItem.FullName
}
function New-MissingWinGetStagingRoot {
  param([string]$Path)
  $missing = New-Object System.Collections.Generic.List[string]
  $current = $Path
  while (-not (Test-Path -LiteralPath $current)) {
    [void]$missing.Add($current)
    $parent = Split-Path -Path $current -Parent
    if ((Test-AnyCondition -Conditions @({ [string]::IsNullOrWhiteSpace($parent) }, { $parent -eq $current }))) {
      throw 'WinGet staging root has no existing trusted ancestor.'
    }
    $current = $parent
  }

  $existing = Get-Item -LiteralPath $current -Force -ErrorAction Stop
  if ((Test-AnyCondition -Conditions @({ -not $existing.PSIsContainer }, { ($existing.Attributes -band [System.IO.FileAttributes]::ReparsePoint) }))) {
    throw 'WinGet staging root ancestor is not a regular directory.'
  }

  # A generic ancestor such as C:\ProgramData may legitimately allow users to
  # create children. Validate it with ancestor replacement rights only by
  # checking from each atomically created protected child.
  for ($i = $missing.Count - 1; $i -ge 0; $i--) {
    New-WinGetAdminOnlyDirectory -Path $missing[$i]
    Assert-TrustedWindowsPathAcl -Path $missing[$i] -CheckAncestors | Out-Null
  }
  Assert-TrustedWindowsPathAcl -Path $Path -CheckAncestors | Out-Null
  return $Path
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
    $item = Get-ValidatedWinGetConfigurationItem -SourcePath $SourcePath
    $extension = [System.IO.Path]::GetExtension($item.Name).ToLowerInvariant()

    # Deny writers and replacement while copying the exact source bytes into
    # the protected staging directory.
    $sourceStream = [System.IO.File]::Open($item.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    if ((Test-AnyCondition -Conditions @({ $sourceStream.Length -eq 0 }, { $sourceStream.Length -gt $MaximumBytes }))) {
      throw "WinGet configuration must contain 1..$MaximumBytes bytes."
    }
    $bytes = Read-WinGetConfigurationBytes -Stream $sourceStream

    $root = Initialize-WinGetStagingRoot -StagingRoot $StagingRoot
    $workDirectory = New-WinGetWorkDirectory -Root $root
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

    $contentHash = Get-WinGetConfigurationHash -Bytes $bytes

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
    if ((Test-AllConditions -Conditions @({ $workDirectory }, { (Test-Path -LiteralPath $workDirectory -PathType Container) }))) {
      Remove-Item -LiteralPath $workDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
    throw
  } finally {
    if ($null -ne $sourceStream) { $sourceStream.Dispose() }
  }
}
function New-WinGetWorkDirectory {
  param([string]$Root)
  $directory = Join-Path $Root ('run-' + [guid]::NewGuid().ToString('N'))
  New-WinGetAdminOnlyDirectory -Path $directory
  Assert-TrustedWindowsPathAcl -Path $directory -CheckAncestors | Out-Null
  return $directory
}
function Get-ValidatedWinGetConfigurationItem {
  param([string]$SourcePath)
  $providerPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SourcePath)
  $item = Get-Item -LiteralPath $providerPath -Force -ErrorAction Stop
  if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
    throw 'WinGet configuration must be a regular file, not a directory or reparse point.'
  }
  $extension = [System.IO.Path]::GetExtension($item.Name).ToLowerInvariant()
  if ($extension -notin @('.yaml', '.yml', '.json')) { throw 'WinGet configuration must use a .yaml, .yml, or .json extension.' }
  $volumeRoot = [System.IO.Path]::GetPathRoot($item.FullName)
  if (Test-PathContainsReparsePoint -Path $item.FullName -Root $volumeRoot) { throw 'WinGet configuration path contains a reparse point.' }
  return $item
}
function Read-WinGetConfigurationBytes {
  param([System.IO.Stream]$Stream)
  $bytes = New-Object byte[] ([int]$Stream.Length)
  $offset = 0
  while ($offset -lt $bytes.Length) {
    $read = $Stream.Read($bytes, $offset, $bytes.Length - $offset)
    if ($read -le 0) { throw 'WinGet configuration changed or ended while being staged.' }
    $offset += $read
  }
  return $bytes
}
function Get-WinGetConfigurationHash {
  param([byte[]]$Bytes)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try { return ([System.BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '') }
  finally { $sha.Dispose() }
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


function To-BoolOrDefault {
  param($Value, [Parameter(Mandatory = $true)][bool]$Default)

  if ($null -eq $Value) { return $Default }
  if ($Value -is [bool]) { return [bool]$Value }

  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $Default }

  $normalized = $s.Trim().ToLowerInvariant()
  if (@('true','1') -contains $normalized) { return $true }
  if (@('false','0') -contains $normalized) { return $false }
  return $Default
}

function Get-SummaryObject {
  param([Parameter(Mandatory)]$Data)

  [pscustomobject]@{
    ComputerName         = $env:COMPUTERNAME
    ConfigPath           = $Data.ConfigPathResolved
    TestOnly             = $Data.TestOnlyEffective
    AcceptAgreements     = $Data.AcceptAgreementsEffective
    DisableInteractivity = $Data.DisableInteractivityEffective
    FailFast             = $Data.FailFastEffective
    PassThru             = $Data.PassThruEffective
    QuietConsole         = $Data.QuietConsoleEffective
    SummaryJsonPath      = (To-StringOrNull $Data.SummaryJsonPathEffective)
    LogPath              = $Data.LogPathEffective
    ExtraArgs            = @($Data.ExtraArgsEffective)
    Timestamp            = Get-Date
    Results              = @($Data.Results.ToArray())
    FinalExitCode        = $Data.FinalExitCode
    ErrorMessage         = (To-StringOrNull $Data.ErrorMessage)
  }
}

function Invoke-WinGetConsoleSummary {
  param([Parameter(Mandatory = $true)][pscustomobject]$Summary)

  if ($Summary.QuietConsole) { return }

  $fields = [ordered]@{
    TestOnly             = [string]$Summary.TestOnly
    AcceptAgreements     = [string]$Summary.AcceptAgreements
    DisableInteractivity = [string]$Summary.DisableInteractivity
    FailFast             = [string]$Summary.FailFast
    FinalExitCode        = [string]$Summary.FinalExitCode
  }
  if ($Summary.ErrorMessage) { $fields['ErrorMessage'] = $Summary.ErrorMessage }

  $findingsAL = Get-WinGetConsoleFindings
  Write-ConsoleSummary -Summary $Summary -Findings $findingsAL -CustomFields $fields
  Write-WinGetPhaseSummary -Summary $Summary
}
function Get-WinGetConsoleFindings {
  $findings = [System.Collections.ArrayList]::new()
  $findingsVar = Get-Variable -Name Findings -Scope Script -ErrorAction SilentlyContinue
  if ($findingsVar -and $findingsVar.Value) {
    foreach ($finding in @($findingsVar.Value.ToArray())) { [void]$findings.Add($finding) }
  }
  return $findings
}
function Write-WinGetPhaseSummary {
  param($Summary)
  if ((Test-AllConditions -Conditions @({ $Summary.Results }, { $Summary.Results.Count -gt 0 }))) {
    Write-UiLine ''
    Write-UiLine -Message 'Phases' -Style 'Header'
    foreach ($r in $Summary.Results) {
      $line = ("- {0,-8} ExitCode={1,-5} DurationS={2,-8}" -f $r.Phase, $r.ExitCode, $r.DurationS)
      if ($r.ExitCode -eq 0) {
        Write-UiLine -Message $line -Style 'Success'
      } else {
        Write-UiLine -Message $line -Style 'Error'
      }
    }
  } else {
    Write-UiLine ''
    Write-UiLine -Message 'Phases' -Style 'Header'
    Write-Warn "- (no phases executed)"
  }
}

function Write-UserFriendlyFailure {
  param([Parameter(Mandatory)]$Data)

  if (-not $Data.QuietConsoleEffective) {
    Write-UiLine -Message ("ERROR: {0}" -f $Data.Message) -Style 'Error'
    Write-UiLine "Hint: Provide a configuration file with -ConfigPath, or set 'ConfigPath' in the summary JSON passed with -SummaryJsonPath." -Style 'Warning'
  }

  $safeResults = $Data.Results
  if (-not $safeResults) { $safeResults = New-Object System.Collections.Generic.List[object] }

  $summaryData = $Data.PSObject.Copy()
  $summaryData.Results = $safeResults
  $summaryData.ErrorMessage = $Data.Message
  $summary = Get-SummaryObject -Data $summaryData
  $resultToken = if ($Data.ExitCode -eq 2) { 'WARN' } else { 'FAIL' }
  if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
  Add-Finding -FindingList $script:Findings -Code 'WINGET-PreflightFailed' -Severity 'Medium' -Message $Data.Message
  return [pscustomobject]@{ Summary = $summary; Token = $resultToken }
}
