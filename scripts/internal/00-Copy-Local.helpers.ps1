#requires -version 5.1
<#
.SYNOPSIS
Internal transactional deployment helpers for 00-Copy-Local.ps1.

.DESCRIPTION
Provides isolated Git execution, environment sanitization, swap recovery, and
cleanup primitives. The entry script loads this file through a validated,
deny-write/delete handle so deployment recovery cannot be redirected mid-run.
#>

# Runs Git with hooks, credentials, prompts, and unsafe protocols disabled so
# repository content cannot widen the deployment process's trust boundary.
function Invoke-GitCommand {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string[]]$GitArgs, [switch]$AllowFailure)
  $safeArguments = @(
    '-c', "core.hooksPath=$hooksPath", '-c', 'core.fsmonitor=false', '-c', 'credential.helper=',
    '-c', 'protocol.ext.allow=never', '-c', 'protocol.file.allow=never'
  ) + $GitArgs
  $result = Invoke-NativeCommand -Command $script:GitExecutablePath -Arguments $safeArguments -CaptureOutput -Quiet `
    -TimeoutSeconds 300 -MaxOutputBytes 1048576
  if ($null -eq $result) { throw 'git did not return a result.' }
  if ($result.TimedOut -or $result.OutputTruncated -or $result.StderrTruncated) {
    throw 'git did not complete with complete output; refusing to use an incomplete result.'
  }
  if (-not $result.Success -and -not $AllowFailure) { throw ("git failed with exit code {0}." -f $result.ExitCode) }
  return $result
}

function Test-CopyLocalBlockedGitEnvironmentName {
  [CmdletBinding()]
  [OutputType([bool])]
  param([Parameter(Mandatory)][string]$Name)
  return ($Name -match '^(?i:(?:GIT|GCM)_)' -or $Name -match '^(?i:(?:HTTP|HTTPS|ALL|NO|FTP)_PROXY)$' -or
    $Name -match '^(?i:SSH_ASKPASS(?:_REQUIRE)?)$' -or
    $Name -match '^(?i:(?:CURL_CA_BUNDLE|CURL_SSL_BACKEND|SSL_CERT_FILE|SSL_CERT_DIR))$')
}

# Defines the complete Git environment used during deployment rather than
# inheriting machine-specific proxy, credential, or configuration behavior.
function Get-CopyLocalSafeGitEnvironment {
  [CmdletBinding()]
  [OutputType([System.Collections.IDictionary])]
  param()
  return [ordered]@{
    GIT_CONFIG_NOSYSTEM = '1'; GIT_CONFIG_GLOBAL = if ($env:OS -eq 'Windows_NT') { 'NUL' } else { '/dev/null' }
    GIT_CONFIG_COUNT = '0'; GIT_ALLOW_PROTOCOL = 'https'; GIT_PROTOCOL_FROM_USER = '0'
    GIT_TERMINAL_PROMPT = '0'; GCM_INTERACTIVE = 'Never'
  }
}

# Temporarily replaces Git-related environment state and records the original
# values so the caller can restore the hosting process exactly.
function Enable-CopyLocalSafeGitEnvironment {
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Snapshot)
  foreach ($item in @(Get-ChildItem -Path Env:)) {
    if (Test-CopyLocalBlockedGitEnvironmentName -Name ([string]$item.Name)) {
      [void]$Snapshot.Add([pscustomobject]@{ Name = [string]$item.Name; Value = [string]$item.Value })
      Remove-Item -LiteralPath ("Env:{0}" -f $item.Name) -ErrorAction Stop
    }
  }
  foreach ($entry in (Get-CopyLocalSafeGitEnvironment).GetEnumerator()) {
    Set-Item -LiteralPath ("Env:{0}" -f $entry.Key) -Value ([string]$entry.Value) -ErrorAction Stop
  }
}

function Restore-CopyLocalGitEnvironment {
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Snapshot)
  foreach ($item in @(Get-ChildItem -Path Env:)) {
    if (Test-CopyLocalBlockedGitEnvironmentName -Name ([string]$item.Name)) {
      Remove-Item -LiteralPath ("Env:{0}" -f $item.Name) -ErrorAction SilentlyContinue
    }
  }
  foreach ($item in $Snapshot) {
    Set-Item -LiteralPath ("Env:{0}" -f $item.Name) -Value ([string]$item.Value) -ErrorAction SilentlyContinue
  }
}

function Get-FullPath {
  [CmdletBinding()]
  [OutputType([string])]
  param([Parameter(Mandatory)][string]$Path)
  try { return [IO.Path]::GetFullPath($Path) } catch { return $Path }
}

function Test-RepoPathOverlapsDeploymentTarget {
  [CmdletBinding()]
  [OutputType([bool])]
  param([Parameter(Mandatory)][string]$RepoPath, [Parameter(Mandatory)][string]$DestinationRoot)
  $repoFull = Get-FullPath -Path $RepoPath
  foreach ($name in @('scripts', 'lib')) {
    if (Test-PathUnderRoot -Path $repoFull -Root (Join-Path $DestinationRoot $name)) { return $true }
  }
  return $false
}

function Remove-CopyLocalCommittedBackup {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'None')]
  [OutputType([object[]])]
  param([Parameter(Mandatory)][System.Collections.IEnumerable]$Swaps)
  $residue = New-Object System.Collections.Generic.List[object]
  foreach ($swap in $Swaps) {
    if (-not $swap.HadExisting -or -not (Test-Path -LiteralPath $swap.Backup)) { continue }
    try {
      if ($PSCmdlet.ShouldProcess($swap.Backup, 'Remove committed previous-version backup')) {
        Remove-Item -LiteralPath $swap.Backup -Recurse -Force -ErrorAction Stop
      }
    } catch {
      [void]$residue.Add([pscustomobject]@{
          Path = [string]$swap.Backup
          Error = [string]$_.Exception.Message
        })
    }
  }
  return $residue.ToArray()
}

# Rolls back completed directory swaps in reverse order; reverse traversal
# preserves the last known-good deployment when a later commit step fails.
function Restore-CopyLocalDeploymentSwaps {
  [CmdletBinding()]
  [OutputType([object[]])]
  param([Parameter(Mandatory)][System.Collections.IList]$Swaps)

  $residue = New-Object System.Collections.Generic.List[object]
  for ($swapIndex = $Swaps.Count - 1; $swapIndex -ge 0; $swapIndex--) {
    $swap = $Swaps[$swapIndex]
    $errors = New-Object System.Collections.Generic.List[string]
    $restoredOriginal = -not $swap.HadExisting

    if ($swap.Installed -and (Test-Path -LiteralPath $swap.Target)) {
      try {
        Remove-Item -LiteralPath $swap.Target -Recurse -Force -ErrorAction Stop
      } catch {
        [void]$errors.Add(("Remove installed target '{0}' failed: {1}" -f $swap.Target, $_.Exception.Message))
      }
    }

    if ($swap.HadExisting) {
      if (Test-Path -LiteralPath $swap.Target) {
        [void]$errors.Add(("Original target '{0}' could not be restored because the replacement target remains." -f $swap.Target))
      } elseif (Test-Path -LiteralPath $swap.Backup) {
        try {
          Move-Item -LiteralPath $swap.Backup -Destination $swap.Target -ErrorAction Stop
          $restoredOriginal = $true
        } catch {
          [void]$errors.Add(("Restore backup '{0}' to '{1}' failed: {2}" -f $swap.Backup, $swap.Target, $_.Exception.Message))
        }
      } else {
        [void]$errors.Add(("Original backup '{0}' is missing; target '{1}' cannot be restored." -f $swap.Backup, $swap.Target))
      }
    }

    $targetExists = Test-Path -LiteralPath $swap.Target
    $backupExists = Test-Path -LiteralPath $swap.Backup
    $invariantSatisfied = if ($swap.HadExisting) {
      $restoredOriginal -and $targetExists -and -not $backupExists
    } else {
      -not $targetExists
    }
    if (-not $invariantSatisfied) {
      $expected = if ($swap.HadExisting) { 'the original target restored from its backup' } else { 'the installed target absent' }
      [void]$errors.Add(("Rollback invariant failed for target '{0}': expected {1}." -f $swap.Target, $expected))
    }
    if ($errors.Count -gt 0) {
      [void]$residue.Add([pscustomobject]@{
          Target = $swap.Target
          Backup = $swap.Backup
          HadExisting = [bool]$swap.HadExisting
          TargetExists = [bool]$targetExists
          BackupExists = [bool]$backupExists
          InvariantSatisfied = [bool]$invariantSatisfied
          Errors = @($errors)
        })
    }
  }
  return $residue.ToArray()
}
