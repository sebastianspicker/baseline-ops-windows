#requires -Version 5.1
<#
.SYNOPSIS
Alpha Windows Forms operator console for scripts and profiles.

.DESCRIPTION
Runs the existing local and profile runners through a versioned JSON manifest
and a child PowerShell process. The runner and profile contracts remain the
authority for paths, execution mode, integrity policy, and exit status.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
  Write-Error 'Launcher-GUI requires Windows.'
  exit 1
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Import-Module (Join-Path $PSScriptRoot 'Launcher.Core.psm1') -Force

[System.Windows.Forms.Application]::EnableVisualStyles()

$repoRoot = Split-Path -Parent $PSScriptRoot
$script:DefaultRoot = if (Test-Path -LiteralPath (Join-Path $repoRoot 'scripts') -PathType Container) { $repoRoot } else { 'C:\install\mdm\ps1' }
$script:IsElevated = $false
try {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  $script:IsElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
  Write-Verbose ("Elevation detection failed: {0}" -f $_.Exception.Message)
}

$script:CurrentProcess = $null
$script:CurrentProcessJob = $null
$script:CurrentOperation = $null
$script:RunStarted = $null
$script:StopRequested = $false
$script:CloseAfterStop = $false
$script:ManifestPath = $null
$script:FullLogPath = $null
$script:OutputCollector = $null
$script:OutputDrainTasks = @()
$script:TrustedClosure = $null
$script:OutputQueue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
$script:VisibleLines = New-Object System.Collections.ArrayList
$script:ScriptCatalog = @()
$script:DiscoveryTask = $null
$script:DiscoveryRoot = $null
$script:ProfileSummary = $null
$script:State = 'Ready'
$script:MaxPendingLines = 5000
$script:MaxVisibleLines = 10000
$script:MaxLogBytes = 25MB

<#
.SYNOPSIS
Creates an autosized accessible label.
.DESCRIPTION
Keeps repeated WinForms label defaults consistent across the launcher.
#>
function Get-LabelControl {
  param([string]$Text, [string]$AccessibleName)
  $control = New-Object System.Windows.Forms.Label
  $control.Text = $Text
  $control.AutoSize = $true
  if ($AccessibleName) { $control.AccessibleName = $AccessibleName }
  return $control
}

<#
.SYNOPSIS
Creates an accessible button with the launcher sizing defaults.
.DESCRIPTION
Centralizes minimum target size and padding for consistent keyboard and pointer use.
#>
function Get-ButtonControl {
  param([string]$Text, [string]$AccessibleName)
  $control = New-Object System.Windows.Forms.Button
  $control.Text = $Text
  $control.AutoSize = $true
  $control.MinimumSize = New-Object System.Drawing.Size(0, 32)
  $control.Padding = New-Object System.Windows.Forms.Padding(8, 2, 8, 2)
  if ($AccessibleName) { $control.AccessibleName = $AccessibleName }
  return $control
}

<#
.SYNOPSIS
Adds a control to a table-layout cell.
.DESCRIPTION
Applies optional column spanning through one layout helper.
#>
function Add-TableControl {
  param($Table, $Control, [int]$Column, [int]$Row, [int]$ColumnSpan = 1)
  $Table.Controls.Add($Control, $Column, $Row)
  if ($ColumnSpan -gt 1) { $Table.SetColumnSpan($Control, $ColumnSpan) }
}

<#
.SYNOPSIS
Transitions the launcher UI to a named operational state.
.DESCRIPTION
Updates status text and control availability together so validation, execution,
and stopping cannot leave conflicting actions enabled.
#>
function Write-LauncherState {
  param([ValidateSet('Ready', 'Validating', 'Running', 'Stopping', 'Completed', 'Warning', 'Failed', 'Stopped')][string]$State, [string]$Detail)
  $script:State = $State
  $statusLabel.Text = if ([string]::IsNullOrWhiteSpace($Detail)) { $State } else { "$State - $Detail" }
  $statusLabel.AccessibleName = "Launcher status: $($statusLabel.Text)"
  $active = $State -in @('Validating', 'Running', 'Stopping')
  foreach ($control in @($txtRoot, $btnBrowseRoot, $btnRefresh, $tabs, $txtFilter, $gridScripts, $txtArgs, $txtProfile, $btnBrowseProfile, $btnValidateProfile, $rbAudit, $rbRemediate, $chkStrict, $chkRequireSigned, $txtExpectedHash, $cmbHashAlgorithm)) {
    $control.Enabled = -not $active
  }
  $txtExpectedHash.Enabled = (-not $active) -and ($tabs.SelectedTab -eq $tabScript)
  if (-not $script:IsElevated) { $rbRemediate.Enabled = $false }
  $btnRun.Enabled = -not $active
  $btnStop.Enabled = $State -in @('Validating', 'Running')
  if ($State -eq 'Stopping') { $btnStop.Enabled = $false }
}

<#
.SYNOPSIS
Queues one launcher output line.
.DESCRIPTION
Routes output through the bounded collector when active and through the bounded
pending queue before a run artifact exists.
#>
function Add-LauncherLine {
  param([AllowEmptyString()][string]$Line)
  if ($null -eq $Line) { return }
  if ($null -ne $script:OutputCollector) { $script:OutputCollector.AddLine($Line) } else { Add-LauncherPendingLine -Queue $script:OutputQueue -Line $Line -Maximum $script:MaxPendingLines }
}

<#
.SYNOPSIS
Releases the current run's manifest, output collector, and trust locks.
.DESCRIPTION
Closes immutable execution handles before removing temporary artifacts.
#>
function Close-RunArtifact {
  if ($null -ne $script:TrustedClosure) {
    Exit-LauncherTrustedClosure -Closure $script:TrustedClosure
    $script:TrustedClosure = $null
  }
  if ($null -ne $script:OutputCollector) {
    try { $script:OutputCollector.Dispose() } catch { Write-Verbose ("Full log disposal failed: {0}" -f $_.Exception.Message) }
    $script:OutputCollector = $null
  }
  if ($script:ManifestPath -and (Test-Path -LiteralPath $script:ManifestPath)) {
    Remove-Item -LiteralPath $script:ManifestPath -Force -ErrorAction SilentlyContinue
  }
  $script:ManifestPath = $null
}

<#
.SYNOPSIS
Creates fresh bounded output state for a launcher run.
.DESCRIPTION
Removes the previous transient log and assigns a unique log path so evidence
from separate operations cannot be mixed.
#>
function Initialize-RunArtifact {
  $previousLogPath = $script:FullLogPath
  Close-RunArtifact
  if ($previousLogPath -and (Test-Path -LiteralPath $previousLogPath)) {
    Remove-Item -LiteralPath $previousLogPath -Force -ErrorAction SilentlyContinue
  }
  $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'baselineops-windows-launcher'
  New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null
  $id = [guid]::NewGuid().ToString('N')
  $script:ManifestPath = $null
  $script:FullLogPath = Join-Path $tempRoot "$id.log"
  $script:OutputCollector = New-Object LauncherOutputCollector($script:FullLogPath, $script:MaxLogBytes, $script:MaxPendingLines)
  $script:OutputQueue = $script:OutputCollector.Pending
}

<#
.SYNOPSIS
Returns the operator-selected execution mode.
.DESCRIPTION
Maps the radio-button state to the manifest's Audit or Remediate token.
#>
function Get-EffectiveMode {
  if ($rbRemediate.Checked) { return 'Remediate' }
  return 'Audit'
}

<#
.SYNOPSIS
Returns the selected script name or profile path.
.DESCRIPTION
Keeps tab-specific target selection out of manifest construction.
#>
function Get-SelectedTarget {
  if ($tabs.SelectedTab -eq $tabScript) {
    if ($gridScripts.SelectedRows.Count -eq 0) { return $null }
    return [string]$gridScripts.SelectedRows[0].Cells['Name'].Value
  }
  return $txtProfile.Text.Trim()
}

<#
.SYNOPSIS
Records the operator-visible inputs for a run.
.DESCRIPTION
Writes enough context to interpret exported logs without recording secret values.
#>
function Write-RunHeader {
  param([string]$Operation, [string]$Target, [string]$Mode, [string[]]$Arguments)
  Add-LauncherLine ('=' * 72)
  Add-LauncherLine ("Timestamp: {0}" -f (Get-Date).ToString('o'))
  Add-LauncherLine ("Computer: {0}" -f $env:COMPUTERNAME)
  Add-LauncherLine ("Elevated: {0}" -f $script:IsElevated)
  Add-LauncherLine ("Operation: {0}" -f $Operation)
  Add-LauncherLine ("Target: {0}" -f $Target)
  Add-LauncherLine ("Mode: {0}" -f $Mode)
  Add-LauncherLine ("Arguments: {0}" -f ($(if ($Arguments.Count -eq 0) { '(none)' } else { $Arguments -join ' ' })))
  Add-LauncherLine ("Strict: {0}; Require valid signature: {1}; Expected hash supplied: {2}; Hash algorithm: {3}" -f $chkStrict.Checked, $chkRequireSigned.Checked, (-not [string]::IsNullOrWhiteSpace($txtExpectedHash.Text)), $cmbHashAlgorithm.SelectedItem)
  Add-LauncherLine 'Exported logs may contain sensitive endpoint evidence.'
  Add-LauncherLine ('=' * 72)
}

<#
.SYNOPSIS
Starts the isolated launcher worker for validation or execution.
.DESCRIPTION
Validates and locks the execution closure, passes a bounded manifest through the
environment, and assigns the worker to a job object before allowing it to run.
#>
function Invoke-LauncherProcess {
  param($Manifest, [ValidateSet('validation', 'run')][string]$Purpose)

  $manifestJson = $Manifest | ConvertTo-Json -Depth 10 -Compress
  $manifestBytes = [System.Text.Encoding]::UTF8.GetBytes($manifestJson)
  if ($manifestBytes.Length -gt 16384) { throw 'Launcher manifest exceeds the 16 KiB inherited-data limit.' }
  $manifestBase64 = [Convert]::ToBase64String($manifestBytes)
  $workerPath = Join-Path $PSScriptRoot 'Launcher-Worker.ps1'
  $selectedExecutionPath = if ($Manifest.operation -eq 'run-script') {
    Join-Path (Join-Path ([string]$Manifest.root) 'scripts') ([string]$Manifest.target)
  } else {
    [string]$Manifest.target
  }
  $script:TrustedClosure = Enter-LauncherTrustedClosure -RootPath ([string]$Manifest.root) -AdditionalPaths @(
    $PSCommandPath,
    $workerPath,
    (Join-Path $PSScriptRoot 'Launcher.Core.psm1'),
    (Join-Path $PSScriptRoot '../lib/Validation.psm1'),
    $(if ($Manifest.operation -in @('validate-profile', 'run-profile')) { [string]$Manifest.target })
  ) -Operation ([string]$Manifest.operation) -SelectedExecutionPath $selectedExecutionPath
  $executable = (Get-Process -Id $PID).Path
  $startInfo = New-Object System.Diagnostics.ProcessStartInfo
  $startInfo.FileName = $executable
  $quotedWorker = '"' + $workerPath.Replace('"', '""') + '"'
  $startInfo.Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $quotedWorker"
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $startInfo.EnvironmentVariables['BASELINEOPS_LAUNCHER_MANIFEST_B64'] = $manifestBase64
  $startGateName = 'Local\BaselineOpsLauncherStart-{0}' -f [guid]::NewGuid().ToString('N')
  $startGate = New-Object System.Threading.EventWaitHandle(
    $false,
    [System.Threading.EventResetMode]::ManualReset,
    $startGateName
  )
  $startInfo.EnvironmentVariables['BASELINEOPS_LAUNCHER_START_GATE'] = $startGateName

  $process = New-Object System.Diagnostics.Process
  $process.StartInfo = $startInfo
  $process.EnableRaisingEvents = $true
  try {
    if (-not $process.Start()) { throw 'PowerShell worker process did not start.' }
  } catch {
    $startGate.Dispose()
    $process.Dispose()
    Exit-LauncherTrustedClosure -Closure $script:TrustedClosure
    $script:TrustedClosure = $null
    throw
  }
  $processJob = $null
  try {
    $processJob = New-LauncherProcessJob
    if ($null -eq $processJob) {
      throw 'The Windows Job Object required for process-tree control is unavailable.'
    }
    Add-LauncherProcessToJob -Job $processJob -Process $process
    $script:OutputDrainTasks = [System.Threading.Tasks.Task[]]@(
      $script:OutputCollector.DrainOutputAsync($process.StandardOutput),
      $script:OutputCollector.DrainErrorAsync($process.StandardError)
    )
    [void]$startGate.Set()
  } catch {
    $startError = $_.Exception.Message
    [void](Stop-LauncherProcessTree -Process $process -Job $processJob -WaitMilliseconds 5000)
    $process.Dispose()
    Exit-LauncherTrustedClosure -Closure $script:TrustedClosure
    $script:TrustedClosure = $null
    throw "Worker process-tree initialization failed: $startError"
  } finally {
    $startGate.Dispose()
  }
  $script:CurrentProcess = $process
  $script:CurrentProcessJob = $processJob
  $script:CurrentOperation = $Purpose
  $script:RunStarted = Get-Date
  $script:StopRequested = $false
  if ($Purpose -eq 'validation') { Write-LauncherState -State Validating -Detail 'Validating profile…' } else { Write-LauncherState -State Running -Detail 'Worker started' }
}

<#
.SYNOPSIS
Finalizes an exited launcher worker.
.DESCRIPTION
Drains output, releases trust and process-tree resources, and maps the worker
exit code into an operator-visible terminal state.
#>
function Complete-LauncherProcess {
  if ($null -eq $script:CurrentProcess) { return }
  $process = $script:CurrentProcess
  $purpose = $script:CurrentOperation
  try {
    if (-not $process.WaitForExit(1000)) {
      throw 'Worker was reported as exited but did not reach a terminal process state within 1 second.'
    }
    $exitCode = $process.ExitCode
  } catch {
    $exitCode = 1
    Add-LauncherLine "ERROR: Could not read worker exit status: $($_.Exception.Message)"
  }

  if ($null -ne $script:CurrentProcessJob) {
    try { $script:CurrentProcessJob.Dispose() } catch { Add-LauncherLine "ERROR: Worker process-tree cleanup failed: $($_.Exception.Message)" }
    $script:CurrentProcessJob = $null
  }
  if ($null -ne $script:TrustedClosure) {
    Exit-LauncherTrustedClosure -Closure $script:TrustedClosure
    $script:TrustedClosure = $null
  }
  if (@($script:OutputDrainTasks).Count -gt 0) {
    try {
      if (-not [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]$script:OutputDrainTasks, 5000)) {
        Add-LauncherLine 'ERROR: Worker output streams did not drain within 5 seconds.'
      }
    } catch {
      Add-LauncherLine "ERROR: Worker output stream drain failed: $($_.Exception.Message)"
    }
    $script:OutputDrainTasks = @()
  }

  $elapsed = if ($null -ne $script:RunStarted) { (Get-Date) - $script:RunStarted } else { [timespan]::Zero }
  $elapsedText = $elapsed.ToString('hh\:mm\:ss')
  if ($purpose -eq 'validation') {
    if ($script:StopRequested) {
      Add-LauncherLine '[STOPPED] Profile validation was stopped.'
      Write-LauncherState -State Stopped -Detail 'Profile validation stopped'
    } elseif ($exitCode -in @(0, 2)) {
      try {
        $script:ProfileSummary = Get-LauncherProfileSummary -ProfilePath $txtProfile.Text.Trim()
        Write-ProfileSummary
        $validationText = if ($exitCode -eq 2) { 'Profile valid with warnings' } else { 'Profile valid' }
        Write-LauncherState -State Ready -Detail $validationText
      } catch {
        $errorProvider.SetError($txtProfile, $_.Exception.Message)
        Write-LauncherState -State Failed -Detail 'Profile summary could not be loaded'
      }
    } else {
      $errorProvider.SetError($txtProfile, 'Profile validation failed. Review the output pane.')
      Write-LauncherState -State Failed -Detail 'Profile validation failed'
    }
  } else {
    $terminal = Get-LauncherTerminalState -ExitCode $exitCode -Stopped:$script:StopRequested
    switch ($terminal) {
      'Completed' { Add-LauncherLine "[OK] Completed in $elapsedText"; Write-LauncherState -State Completed -Detail "Exit 0; $elapsedText" }
      'Warning' { Add-LauncherLine "[WARN] Completed with warnings in $elapsedText"; Write-LauncherState -State Warning -Detail "Exit 2; review findings" }
      'Stopped' { Add-LauncherLine '[STOPPED] Changes may be partial; rerun Audit to establish final state.'; Write-LauncherState -State Stopped -Detail 'Changes may be partial; rerun Audit' }
      default { Add-LauncherLine "[FAIL] Worker exited $exitCode after $elapsedText"; Write-LauncherState -State Failed -Detail "Exit $exitCode; review output and retry" }
    }
  }

  Close-RunArtifact
  try { $process.Dispose() } catch { Write-Verbose ("Worker process disposal failed: {0}" -f $_.Exception.Message) }
  $script:CurrentProcess = $null
  $script:CurrentOperation = $null
  if ($script:CloseAfterStop) { $form.Close() }
}

<#
.SYNOPSIS
Requests bounded termination of the active worker process tree.
.DESCRIPTION
Uses the job-object boundary and restores the running state if termination
cannot be confirmed within the timeout.
#>
function Request-LauncherProcessStop {
  [CmdletBinding()]
  [OutputType([bool])]
  param([Parameter(Mandatory)][string]$Detail)

  if ($null -eq $script:CurrentProcess) { return $true }
  $previousState = $script:State
  $script:StopRequested = $true
  Write-LauncherState -State Stopping -Detail $Detail
  $stopped = Stop-LauncherProcessTree `
    -Process $script:CurrentProcess `
    -Job $script:CurrentProcessJob `
    -WaitMilliseconds 5000
  $script:CurrentProcessJob = $null
  if ($stopped) { return $true }

  $script:StopRequested = $false
  Add-LauncherLine 'ERROR: The worker process tree did not terminate within 5 seconds.'
  if ($previousState -eq 'Validating') {
    Write-LauncherState -State Validating -Detail 'Stop failed; validation is still running'
  } else {
    Write-LauncherState -State Running -Detail 'Stop failed; worker may still be running'
  }
  return $false
}

<#
.SYNOPSIS
Starts asynchronous discovery of numbered operational scripts.
.DESCRIPTION
Validates the selected kit root before background discovery so the UI never
presents scripts from an incomplete or unrelated directory.
#>
function Get-ScriptCatalogView {
  $errorProvider.SetError($txtRoot, '')
  $gridScripts.Rows.Clear()
  $rootPath = $txtRoot.Text.Trim()
  if (-not (Test-LauncherKitRoot -RootPath $rootPath)) {
    $script:ScriptCatalog = @()
    $lblEnvironment.Text = 'Kit invalid: expected scripts\00-Run-Local.ps1 and 00-Run-Profile.ps1.'
    $errorProvider.SetError($txtRoot, 'Select a kit root containing the required runner scripts.')
    return
  }
  if ($null -ne $script:DiscoveryTask -and -not $script:DiscoveryTask.IsCompleted) {
    $lblEnvironment.Text = 'Script discovery is already in progress…'
    return
  }

  $lblEnvironment.Text = 'Discovering numbered scripts…'
  $lblScriptState.Text = 'Loading script catalog…'
  $btnRefresh.Enabled = $false
  $script:DiscoveryRoot = $rootPath
  $script:DiscoveryTask = [LauncherCatalogDiscovery]::BeginDiscover($rootPath)
}

<#
.SYNOPSIS
Applies a completed catalog-discovery result to the UI.
.DESCRIPTION
Discards stale results when the selected root changed while discovery ran.
#>
function Complete-ScriptCatalogDiscovery {
  $task = $script:DiscoveryTask
  $requestedRoot = $script:DiscoveryRoot
  $script:DiscoveryTask = $null
  $script:DiscoveryRoot = $null
  if ($script:State -notin @('Validating', 'Running', 'Stopping')) { $btnRefresh.Enabled = $true }

  if (-not [string]::Equals($requestedRoot, $txtRoot.Text.Trim(), [StringComparison]::OrdinalIgnoreCase)) {
    Get-ScriptCatalogView
    return
  }
  if ($task.IsFaulted) {
    $message = $task.Exception.GetBaseException().Message
    $script:ScriptCatalog = @()
    $errorProvider.SetError($txtRoot, $message)
    $lblEnvironment.Text = 'Script discovery failed.'
    $lblScriptState.Text = 'The script catalog could not be loaded.'
    return
  }

  $script:ScriptCatalog = @($task.Result)
  Show-FilteredScript
  $elevationText = if ($script:IsElevated) { 'Administrator' } else { 'Standard user; remediation unavailable' }
  $lblEnvironment.Text = "$($script:ScriptCatalog.Count) scripts available · $elevationText · $env:COMPUTERNAME"
}

<#
.SYNOPSIS
Renders the catalog rows matching the current filter.
.DESCRIPTION
Preserves selection where possible and reports empty-catalog and empty-filter states.
#>
function Show-FilteredScript {
  $selectedName = if ($gridScripts.SelectedRows.Count -gt 0) { [string]$gridScripts.SelectedRows[0].Cells['Name'].Value } else { '' }
  $filter = $txtFilter.Text.Trim()
  $gridScripts.Rows.Clear()
  foreach ($item in $script:ScriptCatalog) {
    $searchText = "$($item.Number) $($item.Name) $($item.Task) $($item.Synopsis)"
    if ($filter -and $searchText.IndexOf($filter, [StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
    $index = $gridScripts.Rows.Add($item.Number, $item.Task, $item.SupportedModes, $item.Name, $item.Synopsis)
    if ($item.Name -eq $selectedName) { $gridScripts.Rows[$index].Selected = $true }
  }
  $lblScriptState.Text = if ($script:ScriptCatalog.Count -eq 0) { 'No numbered operational scripts found.' } elseif ($gridScripts.Rows.Count -eq 0) { 'No scripts match the filter.' } else { "$($gridScripts.Rows.Count) matching script(s)." }
}

<#
.SYNOPSIS
Displays purpose and supported modes for the selected script.
.DESCRIPTION
Gives the operator context before arguments or remediation mode are chosen.
#>
function Write-ScriptDetail {
  if ($gridScripts.SelectedRows.Count -eq 0) { $lblScriptDetails.Text = 'Select a script to review its purpose and supported modes.'; return }
  $row = $gridScripts.SelectedRows[0]
  $lblScriptDetails.Text = "Task: $($row.Cells['Name'].Value)`r`n$($row.Cells['Synopsis'].Value)`r`nSupported modes: $($row.Cells['Modes'].Value)"
}

<#
.SYNOPSIS
Displays the validated profile contract and ordered steps.
.DESCRIPTION
Uses only the parsed summary produced after validation, not raw profile fields.
#>
function Write-ProfileSummary {
  $gridProfileSteps.Rows.Clear()
  if ($null -eq $script:ProfileSummary) {
    $lblProfileSummary.Text = 'Choose a profile, then validate it before running.'
    return
  }
  $s = $script:ProfileSummary
  $integrity = "Strict: $($s.Strict); Require signature: $($s.RequireSigned)"
  $lblProfileSummary.Text = "$($s.ProfileName) · version $($s.Version) · default $($s.DefaultMode) · $($s.StepCount) step(s)`r`n$integrity"
  foreach ($step in $s.Steps) { [void]$gridProfileSteps.Rows.Add($step.Script, $step.DependsOn) }
}

<#
.SYNOPSIS
Validates all operator inputs required for the selected run.
.DESCRIPTION
Fails before manifest creation when the root, target, mode, arguments, profile,
or hash controls violate launcher policy.
#>
function Test-LauncherInput {
  $errorProvider.Clear()
  if (-not (Test-LauncherKitRoot -RootPath $txtRoot.Text.Trim())) {
    $errorProvider.SetError($txtRoot, 'Select a valid kit root.')
    $txtRoot.Focus()
    return $false
  }
  if ($tabs.SelectedTab -eq $tabScript -and $gridScripts.SelectedRows.Count -eq 0) {
    $errorProvider.SetError($gridScripts, 'Select a script.')
    $gridScripts.Focus()
    return $false
  }
  if ($tabs.SelectedTab -eq $tabScript -and $rbRemediate.Checked -and [string]$gridScripts.SelectedRows[0].Cells['Modes'].Value -notmatch 'Remediate') {
    $errorProvider.SetError($gridScripts, 'The selected script does not advertise remediation support.')
    $gridScripts.Focus()
    return $false
  }
  if ($tabs.SelectedTab -eq $tabProfile) {
    if (-not (Test-Path -LiteralPath $txtProfile.Text.Trim() -PathType Leaf)) {
      $errorProvider.SetError($txtProfile, 'Select an existing profile JSON file.')
      $txtProfile.Focus()
      return $false
    }
    if ($null -eq $script:ProfileSummary) {
      $errorProvider.SetError($txtProfile, 'Validate the selected profile before running.')
      $btnValidateProfile.Focus()
      return $false
    }
  }
  if ($rbRemediate.Checked -and -not $script:IsElevated) {
    $errorProvider.SetError($rbRemediate, 'Remediation requires an elevated launcher.')
    $rbAudit.Checked = $true
    return $false
  }
  try {
    $tokens = @(ConvertFrom-LauncherArgumentString -Text $txtArgs.Text)
    Assert-LauncherArgumentsAllowed -ArgumentTokens $tokens | Out-Null
  } catch {
    $errorProvider.SetError($txtArgs, $_.Exception.Message)
    $txtArgs.Focus()
    return $false
  }
  if (-not [string]::IsNullOrWhiteSpace($txtExpectedHash.Text) -and $tabs.SelectedTab -eq $tabProfile) {
    $errorProvider.SetError($txtExpectedHash, 'Expected hash applies to single-script runs. Profile hashes remain profile-owned.')
    $txtExpectedHash.Focus()
    return $false
  }
  return $true
}

<#
.SYNOPSIS
Builds and launches the operation selected in the UI.
.DESCRIPTION
Requires explicit remediation confirmation, creates a validated manifest, and
starts the worker without executing endpoint changes in the GUI process.
#>
function Invoke-SelectedRun {
  if (-not (Test-LauncherInput)) { return }
  $mode = Get-EffectiveMode
  $operation = if ($tabs.SelectedTab -eq $tabScript) { 'run-script' } else { 'run-profile' }
  $target = Get-SelectedTarget
  $arguments = if ($operation -eq 'run-script') { @(ConvertFrom-LauncherArgumentString -Text $txtArgs.Text) } else { @() }
  $approved = $false

  if ($mode -eq 'Remediate') {
    $message = @"
Review remediation

Target: $target
Computer: $env:COMPUTERNAME
Mode: Remediate
Arguments: $(if ($arguments.Count) { $arguments -join ' ' } else { '(none)' })
Strict: $($chkStrict.Checked)
Require valid signature: $($chkRequireSigned.Checked)

Remediation may make irreversible endpoint changes. Completed changes are not rolled back if you stop the run. Run Audit first when possible.

Run remediation now?
"@
    $choice = [System.Windows.Forms.MessageBox]::Show($form, $message, 'Review and run remediation', 'YesNo', 'Warning', 'Button2')
    if ($choice -ne [System.Windows.Forms.DialogResult]::Yes) { $btnRun.Focus(); return }
    $approved = $true
  }

  try {
    $manifest = ConvertTo-LauncherManifest -Operation $operation -Root $txtRoot.Text.Trim() -Target $target -Mode $mode -ArgumentTokens $arguments -Strict:$chkStrict.Checked -RequireSigned:$chkRequireSigned.Checked -ExpectedHash $txtExpectedHash.Text.Trim() -HashAlgorithm ([string]$cmbHashAlgorithm.SelectedItem) -RemediationApproved:$approved
    Initialize-RunArtifact
    Write-RunHeader -Operation $operation -Target $target -Mode $mode -Arguments $arguments
    Invoke-LauncherProcess -Manifest $manifest -Purpose run
  } catch {
    Add-LauncherLine "ERROR: Could not start run: $($_.Exception.Message)"
    Write-LauncherState -State Failed -Detail 'Could not start worker'
    Close-RunArtifact
  }
}

# Window and root layout
$form = New-Object System.Windows.Forms.Form
$form.Text = 'BaselineOps for Windows - Operator Console (Alpha)'
$form.StartPosition = 'CenterScreen'
$form.Size = New-Object System.Drawing.Size(1080, 760)
$form.MinimumSize = New-Object System.Drawing.Size(900, 600)
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$form.BackColor = [System.Drawing.SystemColors]::Control
$form.AccessibleName = 'BaselineOps for Windows operator console'

$errorProvider = New-Object System.Windows.Forms.ErrorProvider
$errorProvider.ContainerControl = $form
$errorProvider.BlinkStyle = [System.Windows.Forms.ErrorBlinkStyle]::NeverBlink

$rootLayout = New-Object System.Windows.Forms.TableLayoutPanel
$rootLayout.Dock = 'Fill'
$rootLayout.Padding = New-Object System.Windows.Forms.Padding(12)
$rootLayout.ColumnCount = 1
$rootLayout.RowCount = 3
[void]$rootLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
[void]$rootLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
[void]$rootLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
$form.Controls.Add($rootLayout)

# Environment row
$environmentGroup = New-Object System.Windows.Forms.GroupBox
$environmentGroup.Text = 'Environment'
$environmentGroup.AutoSize = $true
$environmentGroup.Dock = 'Fill'
$environmentLayout = New-Object System.Windows.Forms.TableLayoutPanel
$environmentLayout.Dock = 'Fill'
$environmentLayout.AutoSize = $true
$environmentLayout.ColumnCount = 4
$environmentLayout.Padding = New-Object System.Windows.Forms.Padding(8)
[void]$environmentLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
[void]$environmentLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
[void]$environmentLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
[void]$environmentLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
$environmentGroup.Controls.Add($environmentLayout)
$lblRoot = Get-LabelControl -Text '&Kit location:' -AccessibleName 'Kit location label'
$txtRoot = New-Object System.Windows.Forms.TextBox
$txtRoot.Text = $script:DefaultRoot
$txtRoot.Dock = 'Fill'
$txtRoot.AccessibleName = 'Kit location'
$txtRoot.AccessibleDescription = 'Folder containing the scripts directory and launcher runners.'
$lblRoot.Add_Click({ $txtRoot.Focus() })
$btnBrowseRoot = Get-ButtonControl -Text '&Browse kit…' -AccessibleName 'Browse for kit location'
$btnRefresh = Get-ButtonControl -Text '&Refresh' -AccessibleName 'Refresh kit and script catalog'
$lblEnvironment = Get-LabelControl -Text 'Not validated.' -AccessibleName 'Environment validation status'
$lblEnvironment.Dock = 'Fill'
Add-TableControl $environmentLayout $lblRoot 0 0
Add-TableControl $environmentLayout $txtRoot 1 0
Add-TableControl $environmentLayout $btnBrowseRoot 2 0
Add-TableControl $environmentLayout $btnRefresh 3 0
Add-TableControl $environmentLayout $lblEnvironment 1 1 3
$rootLayout.Controls.Add($environmentGroup, 0, 0)

# Main split: task configuration above, output below
$split = New-Object System.Windows.Forms.SplitContainer
$split.Dock = 'Fill'
$split.Orientation = 'Horizontal'
$split.SplitterDistance = 360
$split.Panel1MinSize = 220
$split.Panel2MinSize = 150
$rootLayout.Controls.Add($split, 0, 1)

$configurationLayout = New-Object System.Windows.Forms.TableLayoutPanel
$configurationLayout.Dock = 'Fill'
$configurationLayout.RowCount = 2
$configurationLayout.ColumnCount = 1
[void]$configurationLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
[void]$configurationLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
$split.Panel1.Controls.Add($configurationLayout)

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$tabs.AccessibleName = 'Task type'
$tabScript = New-Object System.Windows.Forms.TabPage
$tabScript.Text = 'Run script'
$tabProfile = New-Object System.Windows.Forms.TabPage
$tabProfile.Text = 'Run profile'
[void]$tabs.TabPages.Add($tabScript)
[void]$tabs.TabPages.Add($tabProfile)
$configurationLayout.Controls.Add($tabs, 0, 0)

# Script tab
$scriptLayout = New-Object System.Windows.Forms.TableLayoutPanel
$scriptLayout.Dock = 'Fill'
$scriptLayout.Padding = New-Object System.Windows.Forms.Padding(8)
$scriptLayout.ColumnCount = 2
$scriptLayout.RowCount = 5
[void]$scriptLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
[void]$scriptLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
[void]$scriptLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
[void]$scriptLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
[void]$scriptLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
[void]$scriptLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
[void]$scriptLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
$tabScript.Controls.Add($scriptLayout)
$lblFilter = Get-LabelControl -Text '&Filter:' -AccessibleName 'Script filter label'
$txtFilter = New-Object System.Windows.Forms.TextBox
$txtFilter.Dock = 'Fill'
$txtFilter.AccessibleName = 'Script filter'
$txtFilter.AccessibleDescription = 'Filter by script number, name, task, or synopsis.'
Add-TableControl $scriptLayout $lblFilter 0 0
Add-TableControl $scriptLayout $txtFilter 1 0
$gridScripts = New-Object System.Windows.Forms.DataGridView
$gridScripts.Dock = 'Fill'
$gridScripts.ReadOnly = $true
$gridScripts.AllowUserToAddRows = $false
$gridScripts.AllowUserToDeleteRows = $false
$gridScripts.AllowUserToResizeRows = $false
$gridScripts.AutoGenerateColumns = $false
$gridScripts.AutoSizeColumnsMode = 'Fill'
$gridScripts.SelectionMode = 'FullRowSelect'
$gridScripts.MultiSelect = $false
$gridScripts.RowHeadersVisible = $false
$gridScripts.AccessibleName = 'Operational scripts'
[void]$gridScripts.Columns.Add('Number', 'No.')
[void]$gridScripts.Columns.Add('Task', 'Task')
[void]$gridScripts.Columns.Add('Modes', 'Supported modes')
$nameColumn = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$nameColumn.Name = 'Name'; $nameColumn.HeaderText = 'File'; $nameColumn.Visible = $false
[void]$gridScripts.Columns.Add($nameColumn)
$synopsisColumn = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$synopsisColumn.Name = 'Synopsis'; $synopsisColumn.HeaderText = 'Synopsis'; $synopsisColumn.Visible = $false
[void]$gridScripts.Columns.Add($synopsisColumn)
Add-TableControl $scriptLayout $gridScripts 0 1 2
$lblScriptState = Get-LabelControl -Text 'Refresh the kit to discover scripts.' -AccessibleName 'Script list status'
Add-TableControl $scriptLayout $lblScriptState 0 2 2
$lblScriptDetails = Get-LabelControl -Text 'Select a script to review its purpose and supported modes.' -AccessibleName 'Selected script details'
$lblScriptDetails.MaximumSize = New-Object System.Drawing.Size(900, 0)
Add-TableControl $scriptLayout $lblScriptDetails 0 3 2
$lblArgs = Get-LabelControl -Text '&Advanced arguments:' -AccessibleName 'Advanced arguments label'
$txtArgs = New-Object System.Windows.Forms.TextBox
$txtArgs.Dock = 'Fill'
$txtArgs.AccessibleName = 'Advanced script arguments'
$txtArgs.AccessibleDescription = 'Script-specific tokens only. Launcher-owned mode, paths, output, confirmation, and integrity arguments are rejected.'
Add-TableControl $scriptLayout $lblArgs 0 4
Add-TableControl $scriptLayout $txtArgs 1 4

# Profile tab
$profileLayout = New-Object System.Windows.Forms.TableLayoutPanel
$profileLayout.Dock = 'Fill'
$profileLayout.Padding = New-Object System.Windows.Forms.Padding(8)
$profileLayout.ColumnCount = 3
$profileLayout.RowCount = 4
[void]$profileLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
[void]$profileLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
[void]$profileLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
[void]$profileLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
[void]$profileLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
[void]$profileLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
[void]$profileLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
$tabProfile.Controls.Add($profileLayout)
$lblProfile = Get-LabelControl -Text '&Profile JSON:' -AccessibleName 'Profile path label'
$txtProfile = New-Object System.Windows.Forms.TextBox
$txtProfile.Dock = 'Fill'
$txtProfile.AccessibleName = 'Profile JSON path'
$btnBrowseProfile = Get-ButtonControl -Text 'Browse &profile…' -AccessibleName 'Browse for profile JSON'
$btnValidateProfile = Get-ButtonControl -Text '&Validate profile' -AccessibleName 'Validate selected profile'
Add-TableControl $profileLayout $lblProfile 0 0
Add-TableControl $profileLayout $txtProfile 1 0
Add-TableControl $profileLayout $btnBrowseProfile 2 0
$lblProfileSummary = Get-LabelControl -Text 'Choose a profile, then validate it before running.' -AccessibleName 'Profile validation summary'
Add-TableControl $profileLayout $lblProfileSummary 0 1 3
$gridProfileSteps = New-Object System.Windows.Forms.DataGridView
$gridProfileSteps.Dock = 'Fill'
$gridProfileSteps.ReadOnly = $true
$gridProfileSteps.AllowUserToAddRows = $false
$gridProfileSteps.AllowUserToDeleteRows = $false
$gridProfileSteps.RowHeadersVisible = $false
$gridProfileSteps.AutoSizeColumnsMode = 'Fill'
$gridProfileSteps.SelectionMode = 'FullRowSelect'
$gridProfileSteps.AccessibleName = 'Profile steps and dependencies'
[void]$gridProfileSteps.Columns.Add('Script', 'Step script')
[void]$gridProfileSteps.Columns.Add('DependsOn', 'Depends on')
Add-TableControl $profileLayout $gridProfileSteps 0 2 3
Add-TableControl $profileLayout $btnValidateProfile 2 3

# Execution policy and actions
$executionGroup = New-Object System.Windows.Forms.GroupBox
$executionGroup.Text = 'Execution policy'
$executionGroup.AutoSize = $true
$executionGroup.Dock = 'Fill'
$executionLayout = New-Object System.Windows.Forms.FlowLayoutPanel
$executionLayout.Dock = 'Fill'
$executionLayout.AutoSize = $true
$executionLayout.WrapContents = $true
$executionLayout.Padding = New-Object System.Windows.Forms.Padding(8)
$executionGroup.Controls.Add($executionLayout)
$rbAudit = New-Object System.Windows.Forms.RadioButton
$rbAudit.Text = '&Audit'; $rbAudit.Checked = $true; $rbAudit.AutoSize = $true; $rbAudit.AccessibleDescription = 'Read-only execution mode.'
$rbRemediate = New-Object System.Windows.Forms.RadioButton
$rbRemediate.Text = '&Remediate'; $rbRemediate.AutoSize = $true; $rbRemediate.Enabled = $script:IsElevated; $rbRemediate.AccessibleDescription = 'Applies endpoint changes after explicit review.'
$chkStrict = New-Object System.Windows.Forms.CheckBox
$chkStrict.Text = '&Strict'; $chkStrict.AutoSize = $true
$chkRequireSigned = New-Object System.Windows.Forms.CheckBox
$chkRequireSigned.Text = 'Require valid &signature'; $chkRequireSigned.AutoSize = $true; $chkRequireSigned.Checked = $script:IsElevated
$chkRequireSigned.AccessibleDescription = 'Defaults on for elevated sessions. Signature validation supplements the required protected-path ACL checks.'
$lblHash = Get-LabelControl -Text 'Expected &hash:' -AccessibleName 'Expected hash label'
$txtExpectedHash = New-Object System.Windows.Forms.TextBox
$txtExpectedHash.Width = 190; $txtExpectedHash.AccessibleName = 'Expected script hash'
$cmbHashAlgorithm = New-Object System.Windows.Forms.ComboBox
$cmbHashAlgorithm.DropDownStyle = 'DropDownList'; $cmbHashAlgorithm.Width = 80; $cmbHashAlgorithm.AccessibleName = 'Hash algorithm'
[void]$cmbHashAlgorithm.Items.AddRange(@('SHA256', 'SHA384', 'SHA512')); $cmbHashAlgorithm.SelectedIndex = 0
$btnRun = Get-ButtonControl -Text '&Run audit' -AccessibleName 'Run audit'
$btnStop = Get-ButtonControl -Text 'S&top run' -AccessibleName 'Stop active run'; $btnStop.Enabled = $false
foreach ($control in @($rbAudit, $rbRemediate, $chkStrict, $chkRequireSigned, $lblHash, $txtExpectedHash, $cmbHashAlgorithm, $btnRun, $btnStop)) { [void]$executionLayout.Controls.Add($control) }
$configurationLayout.Controls.Add($executionGroup, 0, 1)

# Results pane
$resultsLayout = New-Object System.Windows.Forms.TableLayoutPanel
$resultsLayout.Dock = 'Fill'
$resultsLayout.ColumnCount = 1
$resultsLayout.RowCount = 2
[void]$resultsLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
[void]$resultsLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
$split.Panel2.Controls.Add($resultsLayout)
$resultsActions = New-Object System.Windows.Forms.FlowLayoutPanel
$resultsActions.Dock = 'Fill'; $resultsActions.AutoSize = $true
$lblOutput = Get-LabelControl -Text '&Results' -AccessibleName 'Results pane label'
$btnClear = Get-ButtonControl -Text '&Clear view' -AccessibleName 'Clear visible output'
$btnSave = Get-ButtonControl -Text '&Save captured output' -AccessibleName 'Save captured temporary output log'
foreach ($control in @($lblOutput, $btnClear, $btnSave)) { [void]$resultsActions.Controls.Add($control) }
$txtOutput = New-Object System.Windows.Forms.TextBox
$txtOutput.Dock = 'Fill'; $txtOutput.Multiline = $true; $txtOutput.ReadOnly = $true
$txtOutput.ScrollBars = 'Both'; $txtOutput.WordWrap = $false
$txtOutput.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtOutput.BackColor = [System.Drawing.SystemColors]::Window
$txtOutput.ForeColor = [System.Drawing.SystemColors]::WindowText
$txtOutput.AccessibleName = 'Execution results'
$txtOutput.AccessibleDescription = 'Live bounded view of launcher and runner output.'
$resultsLayout.Controls.Add($resultsActions, 0, 0)
$resultsLayout.Controls.Add($txtOutput, 0, 1)

$statusStrip = New-Object System.Windows.Forms.StatusStrip
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Text = 'Ready'; $statusLabel.Spring = $true; $statusLabel.TextAlign = 'MiddleLeft'
[void]$statusStrip.Items.Add($statusLabel)
$rootLayout.Controls.Add($statusStrip, 0, 2)
$form.AcceptButton = $btnRun

# Timers and events
$outputTimer = New-Object System.Windows.Forms.Timer
$outputTimer.Interval = 100
$outputTimer.Add_Tick({
    $batch = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt 250; $i++) {
      $line = $null
      $hasLine = if ($null -ne $script:OutputCollector) {
        $script:OutputCollector.TryDequeue([ref]$line)
      } else {
        $script:OutputQueue.TryDequeue([ref]$line)
      }
      if (-not $hasLine) { break }
      [void]$batch.Add($line)
      [void]$script:VisibleLines.Add($line)
    }
    if ($batch.Count -gt 0) {
      while ($script:VisibleLines.Count -gt $script:MaxVisibleLines) { $script:VisibleLines.RemoveAt(0) }
      $txtOutput.Lines = @($script:VisibleLines)
      $txtOutput.SelectionStart = $txtOutput.TextLength
      $txtOutput.ScrollToCaret()
    }
    if ($script:State -in @('Running', 'Stopping', 'Validating') -and $null -ne $script:RunStarted) {
      $statusLabel.Text = "$($script:State) - $(((Get-Date) - $script:RunStarted).ToString('hh\:mm\:ss')) elapsed"
    }
    if ($null -ne $script:CurrentProcess -and $script:CurrentProcess.HasExited) {
      Complete-LauncherProcess
    }
    if ($null -ne $script:DiscoveryTask -and $script:DiscoveryTask.IsCompleted) {
      Complete-ScriptCatalogDiscovery
    }
  })
$outputTimer.Start()

$btnBrowseRoot.Add_Click({
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = 'Select the kit folder containing scripts'
    $dialog.SelectedPath = $txtRoot.Text.Trim()
    if ($dialog.ShowDialog($form) -eq 'OK') { $txtRoot.Text = $dialog.SelectedPath; Get-ScriptCatalogView }
    $dialog.Dispose()
  })
$btnRefresh.Add_Click({ Get-ScriptCatalogView })
$txtRoot.Add_Validated({ Get-ScriptCatalogView })
$txtFilter.Add_TextChanged({ Show-FilteredScript })
$gridScripts.Add_SelectionChanged({ Write-ScriptDetail })
$btnBrowseProfile.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = 'JSON profiles (*.json)|*.json|All files (*.*)|*.*'
    $dialog.Title = 'Select execution profile'
    if ($dialog.ShowDialog($form) -eq 'OK') { $txtProfile.Text = $dialog.FileName; $script:ProfileSummary = $null; Write-ProfileSummary }
    $dialog.Dispose()
  })
$txtProfile.Add_TextChanged({ $script:ProfileSummary = $null; Write-ProfileSummary; $errorProvider.SetError($txtProfile, '') })
$btnValidateProfile.Add_Click({
    $errorProvider.SetError($txtProfile, '')
    if (-not (Test-LauncherKitRoot -RootPath $txtRoot.Text.Trim())) { $errorProvider.SetError($txtRoot, 'Select a valid kit root before validating a profile.'); $txtRoot.Focus(); return }
    if (-not (Test-Path -LiteralPath $txtProfile.Text.Trim() -PathType Leaf)) { $errorProvider.SetError($txtProfile, 'Select an existing profile JSON file.'); $txtProfile.Focus(); return }
    try {
      $manifest = ConvertTo-LauncherManifest -Operation validate-profile -Root $txtRoot.Text.Trim() -Target $txtProfile.Text.Trim()
      Initialize-RunArtifact
      Add-LauncherLine "[VALIDATE] $($txtProfile.Text.Trim())"
      Invoke-LauncherProcess -Manifest $manifest -Purpose validation
    } catch { $errorProvider.SetError($txtProfile, $_.Exception.Message); Write-LauncherState Failed 'Could not start validation' }
  })
$tabs.Add_SelectedIndexChanged({
    $btnRun.Text = if ($rbRemediate.Checked) { 'Review and run remediation…' } else { '&Run audit' }
    $txtExpectedHash.Enabled = ($tabs.SelectedTab -eq $tabScript) -and ($script:State -notin @('Running', 'Stopping', 'Validating'))
  })
$rbAudit.Add_CheckedChanged({ if ($rbAudit.Checked) { $btnRun.Text = '&Run audit'; $btnRun.AccessibleName = 'Run audit' } })
$rbRemediate.Add_CheckedChanged({ if ($rbRemediate.Checked) { $btnRun.Text = 'Review and run remediation…'; $btnRun.AccessibleName = 'Review and run remediation' } })
$btnRun.Add_Click({ Invoke-SelectedRun })
$btnStop.Add_Click({
    if ($null -eq $script:CurrentProcess) { return }
    $message = if ((Get-EffectiveMode) -eq 'Remediate') { 'Stop this remediation run? Completed changes are not rolled back. Rerun Audit afterward to establish final state.' } else { 'Stop this audit run?' }
    if ([System.Windows.Forms.MessageBox]::Show($form, $message, 'Stop active run', 'YesNo', 'Warning', 'Button2') -ne 'Yes') { return }
    [void](Request-LauncherProcessStop -Detail 'Waiting for process-tree termination…')
  })
$btnClear.Add_Click({ $script:VisibleLines.Clear(); $txtOutput.Clear() })
$btnSave.Add_Click({
    if ([string]::IsNullOrWhiteSpace($script:FullLogPath) -or -not (Test-Path -LiteralPath $script:FullLogPath -PathType Leaf)) {
      [System.Windows.Forms.MessageBox]::Show($form, 'No captured output log is available yet.', 'Save captured output', 'OK', 'Information') | Out-Null
      return
    }
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Filter = 'Log files (*.log)|*.log|Text files (*.txt)|*.txt|All files (*.*)|*.*'
    $dialog.FileName = "baselineops-windows-launcher-$(Get-Date -Format yyyyMMdd-HHmmss).log"
    if ($dialog.ShowDialog($form) -eq 'OK') {
      try {
        if ($null -ne $script:OutputCollector) { $script:OutputCollector.Flush() }
        Copy-Item -LiteralPath $script:FullLogPath -Destination $dialog.FileName -Force
        [System.Windows.Forms.MessageBox]::Show($form, "Captured output saved to:`r`n$($dialog.FileName)`r`n`r`nThe log is capped at 25 MiB and may contain sensitive endpoint evidence. Review it before sharing.", 'Save captured output', 'OK', 'Information') | Out-Null
      } catch {
        $errorProvider.SetError($btnSave, "Could not save output: $($_.Exception.Message)")
        $btnSave.Focus()
      }
    }
    $dialog.Dispose()
  })
$form.Add_FormClosing({
    param($closingForm, $closingEvent)
    [void]$closingForm
    if ($null -ne $script:CurrentProcess -and -not $script:CloseAfterStop) {
      $choice = [System.Windows.Forms.MessageBox]::Show($form, 'Stop the active run and close after the worker reaches a terminal state? Select No to keep the launcher open.', 'Active run', 'YesNo', 'Warning', 'Button2')
      $closingEvent.Cancel = $true
      if ($choice -eq 'Yes') {
        $script:CloseAfterStop = $true
        if (-not (Request-LauncherProcessStop -Detail 'Stopping process tree before close…')) {
          $script:CloseAfterStop = $false
        }
      }
    }
  })
$form.Add_FormClosed({
    $outputTimer.Stop(); $outputTimer.Dispose()
    Close-RunArtifact
    if ($script:FullLogPath -and (Test-Path -LiteralPath $script:FullLogPath)) { Remove-Item -LiteralPath $script:FullLogPath -Force -ErrorAction SilentlyContinue }
  })
$form.Add_Load({ Get-ScriptCatalogView; Write-LauncherState -State Ready -Detail 'Audit is selected' })

[void]$form.ShowDialog()
