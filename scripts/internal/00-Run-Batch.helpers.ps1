#requires -version 5.1
<#
.SYNOPSIS
Private runtime helpers for 00-Run-Batch.ps1.

.DESCRIPTION
Provides the post-trust batch orchestration path. The public entrypoint retains
all privileged bootstrap, ownership, ACL, and reparse-point validation.
#>

function Get-BatchAvailableScripts {
  [CmdletBinding()]
  [OutputType([string[]])]
  param([Parameter(Mandatory)][string]$ScriptsDirectory)

  return @(Get-ChildItem -LiteralPath $ScriptsDirectory -Filter '*.ps1' -File |
      Where-Object { $_.Name -match '^\d{2}-' -and $_.Name -notmatch '^00-' } |
      Select-Object -ExpandProperty Name)
}

function New-BatchProfileInvocationParameters {
  [CmdletBinding()]
  [OutputType([hashtable])]
  param([Parameter(Mandatory)][string]$ProfilePath)

  $parameters = @{ ProfilePath = $ProfilePath; Mode = $Mode; RootPath = $RootPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; Strict = $Strict; RequireSigned = $RequireSigned }
  if ($PassThru) { $parameters.PassThru = $true }
  if ($WhatIfPreference) { $parameters.WhatIf = $true }
  if ($PSBoundParameters.ContainsKey('Confirm')) { $parameters.Confirm = [bool]$PSBoundParameters['Confirm'] }
  return $parameters
}

function Clear-BatchProfileWorkspace {
  [CmdletBinding()]
  param([AllowNull()][System.IO.FileStream]$LockStream, [string]$Directory)

  if ($null -ne $LockStream) { $LockStream.Dispose() }
  if (-not [string]::IsNullOrWhiteSpace($Directory) -and (Test-Path -LiteralPath $Directory)) {
    Remove-Item -LiteralPath $Directory -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Invoke-BatchProfileRunner {
  [CmdletBinding()]
  [OutputType([object])]
  param([Parameter(Mandatory)]$BatchProfile)

  $directory = $null; $profilePath = $null; $lockStream = $null
  try {
    $directory = New-BatchProfileWorkspace
    $profilePath = Join-Path $directory 'profile.json'
    $BatchProfile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8
    if ($isElevatedWindows) { Set-BatchAdminSystemAcl -Path $profilePath; Assert-RunBatchTrustedWindowsAcl -Path $profilePath }
    $lockStream = New-Object System.IO.FileStream($profilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $invocationParameters = New-BatchProfileInvocationParameters -ProfilePath $profilePath
    & $runProfilePath @invocationParameters
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Error = $null }
  } catch {
    return [pscustomobject]@{ ExitCode = $null; Error = $_.Exception.Message }
  } finally {
    Clear-BatchProfileWorkspace -LockStream $lockStream -Directory $directory
  }
}

function Invoke-RunBatch {
  [CmdletBinding()]
  param()

  if (-not (Test-Path -LiteralPath $runProfilePath -PathType Leaf)) {
    Write-BatchTerminalResult -Result FAIL -Code 'Batch-MissingProfileRunner' -Message "Missing Run-Profile script: $runProfilePath"
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  $scriptsDirectory = [System.IO.Path]::Combine($RootPath, 'scripts')
  if (-not (Test-Path -LiteralPath $scriptsDirectory -PathType Container)) {
    Write-BatchTerminalResult -Result FAIL -Code 'Batch-MissingScriptsDirectory' -Message "Scripts directory not found: $scriptsDirectory"
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  $selected = @(Get-BatchSelectedScripts -Category $Category -ScriptNames (Get-BatchAvailableScripts -ScriptsDirectory $scriptsDirectory))
  if ($selected.Count -eq 0) {
    Write-BatchTerminalResult -Result FAIL -Code 'Batch-NoScriptsSelected' -Message "No scripts found for category '$Category'."
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  $batchProfile = New-BatchProfileDocument -Category $Category -Mode $Mode -Strict ([bool]$Strict) -RequireSigned ([bool]$RequireSigned) -ContinueOnError ([bool]$ContinueOnError) -SelectedScripts $selected
  if (-not $PSCmdlet.ShouldProcess("batch-$($Category.ToLowerInvariant())", "Execute $($selected.Count) scripts via profile")) {
    Write-BatchTerminalResult -Result WARN -Code 'Batch-ExecutionSkipped' -Message 'Batch execution was skipped by WhatIf or confirmation.' -SelectedScripts $selected
    exit (Get-V2ExitCode -Result 'WARN')
  }
  $execution = Invoke-BatchProfileRunner -BatchProfile $batchProfile
  if (-not [string]::IsNullOrWhiteSpace([string]$execution.Error)) {
    Write-BatchTerminalResult -Result FAIL -Code 'Batch-ProfileInvocationFailed' -Message $execution.Error -SelectedScripts $selected
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  if ($null -ne $execution.ExitCode) { exit [int]$execution.ExitCode }
  exit (Get-V2ExitCode -Result 'OK')
}
