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

  $manifestBase64 = ConvertTo-LauncherManifestBase64 -Manifest $Manifest
  $workerPath = Join-Path $PSScriptRoot 'Launcher-Worker.ps1'
  $script:TrustedClosure = Open-LauncherGuiTrustedClosure -Manifest $Manifest -WorkerPath $workerPath
  $started = Start-LauncherWorkerProcess -WorkerPath $workerPath -ManifestBase64 $manifestBase64
  $process = $started.Process; $processJob = $null
  try { $processJob = Initialize-LauncherWorkerProcess -Process $process -StartGate $started.StartGate }
  catch {
    $message = $_.Exception.Message; [void](Stop-LauncherProcessTree -Process $process -Job $processJob -WaitMilliseconds 5000); $process.Dispose(); Exit-LauncherTrustedClosure -Closure $script:TrustedClosure; $script:TrustedClosure = $null; throw "Worker process-tree initialization failed: $message"
  } finally { $started.StartGate.Dispose() }
  $script:CurrentProcess = $process
  $script:CurrentProcessJob = $processJob
  $script:CurrentOperation = $Purpose
  $script:RunStarted = Get-Date
  $script:StopRequested = $false
  if ($Purpose -eq 'validation') { Write-LauncherState -State Validating -Detail 'Validating profile…' } else { Write-LauncherState -State Running -Detail 'Worker started' }
}

function ConvertTo-LauncherManifestBase64 {
  param($Manifest)
  $bytes = [System.Text.Encoding]::UTF8.GetBytes(($Manifest | ConvertTo-Json -Depth 10 -Compress))
  if ($bytes.Length -gt 16384) { throw 'Launcher manifest exceeds the 16 KiB inherited-data limit.' }
  return [Convert]::ToBase64String($bytes)
}

function Open-LauncherGuiTrustedClosure {
  param($Manifest, [string]$WorkerPath)
  $selected = if ($Manifest.operation -eq 'run-script') { Join-Path (Join-Path ([string]$Manifest.root) 'scripts') ([string]$Manifest.target) } else { [string]$Manifest.target }
  $launcherFiles = @(
    $PSCommandPath,
    $WorkerPath,
    (Join-Path $PSScriptRoot 'Launcher-GUI.ps1'),
    (Join-Path $PSScriptRoot 'Launcher-GUI.App.psm1'),
    (Join-Path $PSScriptRoot 'Launcher-GUI.Catalog.ps1'),
    (Join-Path $PSScriptRoot 'Launcher-GUI.View.ps1'),
    (Join-Path $PSScriptRoot 'Launcher.Core.psm1'),
    (Join-Path $PSScriptRoot '../lib/Validation.psm1')
  )
  if ($Manifest.operation -in @('validate-profile', 'run-profile')) { $launcherFiles += [string]$Manifest.target }
  return Enter-LauncherTrustedClosure -RootPath ([string]$Manifest.root) -AdditionalPaths $launcherFiles -Operation ([string]$Manifest.operation) -SelectedExecutionPath $selected
}

function Start-LauncherWorkerProcess {
  param([string]$WorkerPath, [string]$ManifestBase64)
  $gateName = 'Local\BaselineOpsLauncherStart-{0}' -f [guid]::NewGuid().ToString('N')
  $gate = New-Object System.Threading.EventWaitHandle($false, [System.Threading.EventResetMode]::ManualReset, $gateName)
  $info = New-Object System.Diagnostics.ProcessStartInfo
  $info.FileName = (Get-Process -Id $PID).Path; $info.Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$($WorkerPath.Replace('"', '""'))`""
  $info.UseShellExecute = $false; $info.CreateNoWindow = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
  $info.EnvironmentVariables['BASELINEOPS_LAUNCHER_MANIFEST_B64'] = $ManifestBase64; $info.EnvironmentVariables['BASELINEOPS_LAUNCHER_START_GATE'] = $gateName
  $process = New-Object System.Diagnostics.Process; $process.StartInfo = $info; $process.EnableRaisingEvents = $true
  try { if (-not $process.Start()) { throw 'PowerShell worker process did not start.' } }
  catch { $gate.Dispose(); $process.Dispose(); Exit-LauncherTrustedClosure -Closure $script:TrustedClosure; $script:TrustedClosure = $null; throw }
  return [pscustomobject]@{ Process = $process; StartGate = $gate }
}

function Initialize-LauncherWorkerProcess {
  param([System.Diagnostics.Process]$Process, $StartGate)
  $job = New-LauncherProcessJob
  if ($null -eq $job) { throw 'The Windows Job Object required for process-tree control is unavailable.' }
  Add-LauncherProcessToJob -Job $job -Process $Process
  $script:OutputDrainTasks = [System.Threading.Tasks.Task[]]@($script:OutputCollector.DrainOutputAsync($Process.StandardOutput), $script:OutputCollector.DrainErrorAsync($Process.StandardError))
  [void]$StartGate.Set(); return $job
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
  $exitCode = Get-LauncherWorkerExitCode -Process $process
  Close-LauncherWorkerResources
  $elapsedText = Get-LauncherElapsedText
  if ($purpose -eq 'validation') { Complete-LauncherValidation -ExitCode $exitCode }
  else { Complete-LauncherRun -ExitCode $exitCode -ElapsedText $elapsedText }
  if ($null -ne $script:OutputCollector) {
    try { $script:OutputCollector.Complete() }
    catch { Add-LauncherLine "ERROR: Final output log flush failed: $($_.Exception.Message)" }
  }
  Close-RunArtifact
  try { $process.Dispose() } catch { Write-Verbose ("Worker process disposal failed: {0}" -f $_.Exception.Message) }
  $script:CurrentProcess = $null
  $script:CurrentOperation = $null
  if ($script:CloseAfterStop) { $form.Close() }
}

function Get-LauncherWorkerExitCode {
  param([System.Diagnostics.Process]$Process)
  try { if (-not $Process.WaitForExit(1000)) { throw 'Worker was reported as exited but did not reach a terminal process state within 1 second.' }; return $Process.ExitCode }
  catch { Add-LauncherLine "ERROR: Could not read worker exit status: $($_.Exception.Message)"; return 1 }
}

function Close-LauncherWorkerResources {
  if ($null -ne $script:CurrentProcessJob) { try { $script:CurrentProcessJob.Dispose() } catch { Add-LauncherLine "ERROR: Worker process-tree cleanup failed: $($_.Exception.Message)" }; $script:CurrentProcessJob = $null }
  if ($null -ne $script:TrustedClosure) { Exit-LauncherTrustedClosure -Closure $script:TrustedClosure; $script:TrustedClosure = $null }
  if (@($script:OutputDrainTasks).Count -eq 0) { return }
  try { if (-not [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]$script:OutputDrainTasks, 5000)) { Add-LauncherLine 'ERROR: Worker output streams did not drain within 5 seconds.' } }
  catch { Add-LauncherLine "ERROR: Worker output stream drain failed: $($_.Exception.Message)" }
  $script:OutputDrainTasks = @()
}

function Get-LauncherElapsedText { if ($null -eq $script:RunStarted) { return [timespan]::Zero.ToString('hh\:mm\:ss') }; return ((Get-Date) - $script:RunStarted).ToString('hh\:mm\:ss') }

function Complete-LauncherValidation {
  param([int]$ExitCode)
  if ($script:StopRequested) { Add-LauncherLine '[STOPPED] Profile validation was stopped.'; Write-LauncherState -State Stopped -Detail 'Profile validation stopped'; return }
  if ($ExitCode -notin @(0, 2)) { $errorProvider.SetError($txtProfile, 'Profile validation failed. Review the output pane.'); Write-LauncherState -State Failed -Detail 'Profile validation failed'; return }
  try { $script:ProfileSummary = Get-LauncherProfileSummary -ProfilePath $txtProfile.Text.Trim(); Write-ProfileSummary; Write-LauncherState -State Ready -Detail $(if ($ExitCode -eq 2) { 'Profile valid with warnings' } else { 'Profile valid' }) }
  catch { $errorProvider.SetError($txtProfile, $_.Exception.Message); Write-LauncherState -State Failed -Detail 'Profile summary could not be loaded' }
}

function Complete-LauncherRun {
  param([int]$ExitCode, [string]$ElapsedText)
  switch (Get-LauncherTerminalState -ExitCode $ExitCode -Stopped:$script:StopRequested) {
    'Completed' { Add-LauncherLine "[OK] Completed in $ElapsedText"; Write-LauncherState -State Completed -Detail "Exit 0; $ElapsedText" }
    'Warning' { Add-LauncherLine "[WARN] Completed with warnings in $ElapsedText"; Write-LauncherState -State Warning -Detail 'Exit 2; review findings' }
    'Stopped' { Add-LauncherLine '[STOPPED] Changes may be partial; rerun Audit to establish final state.'; Write-LauncherState -State Stopped -Detail 'Changes may be partial; rerun Audit' }
    default { Add-LauncherLine "[FAIL] Worker exited $ExitCode after $ElapsedText"; Write-LauncherState -State Failed -Detail "Exit $ExitCode; review output and retry" }
  }
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
