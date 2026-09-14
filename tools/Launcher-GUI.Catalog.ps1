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
  $lblScriptState.Text = Get-LauncherFilterStatus
}

function Get-LauncherFilterStatus {
  if ($script:ScriptCatalog.Count -eq 0) { return 'No numbered operational scripts found.' }
  if ($gridScripts.Rows.Count -eq 0) { return 'No scripts match the filter.' }
  return "$($gridScripts.Rows.Count) matching script(s)."
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
  if (-not (Test-LauncherRootInput)) { return $false }
  if (-not (Test-LauncherTargetInput)) { return $false }
  if (-not (Test-LauncherProfileInput)) { return $false }
  if (-not (Test-LauncherModeInput)) { return $false }
  if (-not (Test-LauncherArgumentsInput)) { return $false }
  if (-not (Test-LauncherHashInput)) { return $false }
  return $true
}

function Test-LauncherRootInput {
  if (Test-LauncherKitRoot -RootPath $txtRoot.Text.Trim()) { return $true }
  $errorProvider.SetError($txtRoot, 'Select a valid kit root.'); $txtRoot.Focus(); return $false
}

function Test-LauncherTargetInput {
  if ($tabs.SelectedTab -ne $tabScript) { return $true }
  if ($gridScripts.SelectedRows.Count -eq 0) { $errorProvider.SetError($gridScripts, 'Select a script.'); $gridScripts.Focus(); return $false }
  if (-not $rbRemediate.Checked -or [string]$gridScripts.SelectedRows[0].Cells['Modes'].Value -match 'Remediate') { return $true }
  $errorProvider.SetError($gridScripts, 'The selected script does not advertise remediation support.'); $gridScripts.Focus(); return $false
}

function Test-LauncherProfileInput {
  if ($tabs.SelectedTab -ne $tabProfile) { return $true }
  if (-not (Test-Path -LiteralPath $txtProfile.Text.Trim() -PathType Leaf)) { $errorProvider.SetError($txtProfile, 'Select an existing profile JSON file.'); $txtProfile.Focus(); return $false }
  if ($null -ne $script:ProfileSummary) { return $true }
  $errorProvider.SetError($txtProfile, 'Validate the selected profile before running.'); $btnValidateProfile.Focus(); return $false
}

function Test-LauncherModeInput {
  if (-not $rbRemediate.Checked -or $script:IsElevated) { return $true }
  $errorProvider.SetError($rbRemediate, 'Remediation requires an elevated launcher.'); $rbAudit.Checked = $true; return $false
}

function Test-LauncherArgumentsInput {
  try { Assert-LauncherArgumentsAllowed -ArgumentTokens @(ConvertFrom-LauncherArgumentString -Text $txtArgs.Text) | Out-Null; return $true }
  catch { $errorProvider.SetError($txtArgs, $_.Exception.Message); $txtArgs.Focus(); return $false }
}

function Test-LauncherHashInput {
  if ([string]::IsNullOrWhiteSpace($txtExpectedHash.Text) -or $tabs.SelectedTab -ne $tabProfile) { return $true }
  $errorProvider.SetError($txtExpectedHash, 'Expected hash applies to single-script runs. Profile hashes remain profile-owned.'); $txtExpectedHash.Focus(); return $false
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
  $approved = Confirm-LauncherRemediation -Mode $mode -Target $target -Arguments $arguments
  if ($mode -eq 'Remediate' -and -not $approved) { return }

  try {
    $manifestOptions = @{ ExpectedHash = $txtExpectedHash.Text.Trim(); HashAlgorithm = [string]$cmbHashAlgorithm.SelectedItem; RemediationApproved = $approved }
    $manifest = ConvertTo-LauncherManifest -Operation $operation -Root $txtRoot.Text.Trim() -Target $target -Mode $mode -ArgumentTokens $arguments -Strict:$chkStrict.Checked -RequireSigned:$chkRequireSigned.Checked -Options $manifestOptions
    Initialize-RunArtifact
    Write-RunHeader -Operation $operation -Target $target -Mode $mode -Arguments $arguments
    Invoke-LauncherProcess -Manifest $manifest -Purpose run
  } catch {
    Add-LauncherLine "ERROR: Could not start run: $($_.Exception.Message)"
    Write-LauncherState -State Failed -Detail 'Could not start worker'
    Close-RunArtifact
  }
}

function Confirm-LauncherRemediation {
  param([string]$Mode, [string]$Target, [string[]]$Arguments)
  if ($Mode -ne 'Remediate') { return $false }
  $argumentText = if ($Arguments.Count) { $Arguments -join ' ' } else { '(none)' }
  $message = "Review remediation`r`n`r`nTarget: $Target`r`nComputer: $env:COMPUTERNAME`r`nMode: Remediate`r`nArguments: $argumentText`r`nStrict: $($chkStrict.Checked)`r`nRequire valid signature: $($chkRequireSigned.Checked)`r`n`r`nRemediation may make irreversible endpoint changes. Completed changes are not rolled back if you stop the run. Run Audit first when possible.`r`n`r`nRun remediation now?"
  if ([System.Windows.Forms.MessageBox]::Show($form, $message, 'Review and run remediation', 'YesNo', 'Warning', 'Button2') -eq [System.Windows.Forms.DialogResult]::Yes) { return $true }
  $btnRun.Focus(); return $false
}
