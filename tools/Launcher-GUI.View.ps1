<#
.SYNOPSIS
Builds and displays the launcher window.

.DESCRIPTION
Creates the operator controls and binds their lifecycle to the trusted worker
process functions loaded by the launcher runtime component.
#>
function Start-LauncherGui {
function New-LauncherShell {
# Window and root layout
$script:form = New-Object System.Windows.Forms.Form
$script:form.Text = 'BaselineOps for Windows - Operator Console (Alpha)'
$script:form.StartPosition = 'CenterScreen'
$script:form.Size = New-Object System.Drawing.Size(1080, 760)
$script:form.MinimumSize = New-Object System.Drawing.Size(900, 600)
$script:form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
$script:form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$script:form.BackColor = [System.Drawing.SystemColors]::Control
$script:form.AccessibleName = 'BaselineOps for Windows operator console'

$script:errorProvider = New-Object System.Windows.Forms.ErrorProvider
$script:errorProvider.ContainerControl = $script:form
$script:errorProvider.BlinkStyle = [System.Windows.Forms.ErrorBlinkStyle]::NeverBlink

$script:rootLayout = New-Object System.Windows.Forms.TableLayoutPanel
$script:rootLayout.Dock = 'Fill'
$script:rootLayout.Padding = New-Object System.Windows.Forms.Padding(12)
$script:rootLayout.ColumnCount = 1
$script:rootLayout.RowCount = 3
[void]$script:rootLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
[void]$script:rootLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
[void]$script:rootLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
$script:form.Controls.Add($script:rootLayout)
}

function New-LauncherEnvironment {
# Environment row
$script:environmentGroup = New-Object System.Windows.Forms.GroupBox
$script:environmentGroup.Text = 'Environment'
$script:environmentGroup.AutoSize = $true
$script:environmentGroup.Dock = 'Fill'
$script:environmentLayout = New-Object System.Windows.Forms.TableLayoutPanel
$script:environmentLayout.Dock = 'Fill'
$script:environmentLayout.AutoSize = $true
$script:environmentLayout.ColumnCount = 4
$script:environmentLayout.Padding = New-Object System.Windows.Forms.Padding(8)
[void]$script:environmentLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
[void]$script:environmentLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
[void]$script:environmentLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
[void]$script:environmentLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
$script:environmentGroup.Controls.Add($script:environmentLayout)
$script:lblRoot = Get-LabelControl -Text '&Kit location:' -AccessibleName 'Kit location label'
$script:txtRoot = New-Object System.Windows.Forms.TextBox
$script:txtRoot.Text = $script:DefaultRoot
$script:txtRoot.Dock = 'Fill'
$script:txtRoot.AccessibleName = 'Kit location'
$script:txtRoot.AccessibleDescription = 'Folder containing the scripts directory and launcher runners.'
$script:lblRoot.Add_Click({ $script:txtRoot.Focus() })
$script:btnBrowseRoot = Get-ButtonControl -Text '&Browse kit…' -AccessibleName 'Browse for kit location'
$script:btnRefresh = Get-ButtonControl -Text '&Refresh' -AccessibleName 'Refresh kit and script catalog'
$script:lblEnvironment = Get-LabelControl -Text 'Not validated.' -AccessibleName 'Environment validation status'
$script:lblEnvironment.Dock = 'Fill'
Add-TableControl $script:environmentLayout $script:lblRoot 0 0
Add-TableControl $script:environmentLayout $script:txtRoot 1 0
Add-TableControl $script:environmentLayout $script:btnBrowseRoot 2 0
Add-TableControl $script:environmentLayout $script:btnRefresh 3 0
Add-TableControl $script:environmentLayout $script:lblEnvironment 1 1 3
$script:rootLayout.Controls.Add($script:environmentGroup, 0, 0)
}

function New-LauncherConfiguration {
# Main split: task configuration above, output below
$script:split = New-Object System.Windows.Forms.SplitContainer
$script:split.Dock = 'Fill'
$script:split.Orientation = 'Horizontal'
$script:split.SplitterDistance = 360
$script:split.Panel1MinSize = 220
$script:split.Panel2MinSize = 150
$script:rootLayout.Controls.Add($script:split, 0, 1)

$script:configurationLayout = New-Object System.Windows.Forms.TableLayoutPanel
$script:configurationLayout.Dock = 'Fill'
$script:configurationLayout.RowCount = 2
$script:configurationLayout.ColumnCount = 1
[void]$script:configurationLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
[void]$script:configurationLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
$script:split.Panel1.Controls.Add($script:configurationLayout)

$script:tabs = New-Object System.Windows.Forms.TabControl
$script:tabs.Dock = 'Fill'
$script:tabs.AccessibleName = 'Task type'
$script:tabScript = New-Object System.Windows.Forms.TabPage
$script:tabScript.Text = 'Run script'
$script:tabProfile = New-Object System.Windows.Forms.TabPage
$script:tabProfile.Text = 'Run profile'
[void]$script:tabs.TabPages.Add($script:tabScript)
[void]$script:tabs.TabPages.Add($script:tabProfile)
$script:configurationLayout.Controls.Add($script:tabs, 0, 0)
}

function New-LauncherScriptTab {
# Script tab
$script:scriptLayout = New-Object System.Windows.Forms.TableLayoutPanel
$script:scriptLayout.Dock = 'Fill'
$script:scriptLayout.Padding = New-Object System.Windows.Forms.Padding(8)
$script:scriptLayout.ColumnCount = 2
$script:scriptLayout.RowCount = 5
[void]$script:scriptLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
[void]$script:scriptLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
[void]$script:scriptLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
[void]$script:scriptLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
[void]$script:scriptLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
[void]$script:scriptLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
[void]$script:scriptLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
$script:tabScript.Controls.Add($script:scriptLayout)
$script:lblFilter = Get-LabelControl -Text '&Filter:' -AccessibleName 'Script filter label'
$script:txtFilter = New-Object System.Windows.Forms.TextBox
$script:txtFilter.Dock = 'Fill'
$script:txtFilter.AccessibleName = 'Script filter'
$script:txtFilter.AccessibleDescription = 'Filter by script number, name, task, or synopsis.'
Add-TableControl $script:scriptLayout $script:lblFilter 0 0
Add-TableControl $script:scriptLayout $script:txtFilter 1 0
}

function New-LauncherScriptGrid {
$script:gridScripts = New-Object System.Windows.Forms.DataGridView
$script:gridScripts.Dock = 'Fill'
$script:gridScripts.ReadOnly = $true
$script:gridScripts.AllowUserToAddRows = $false
$script:gridScripts.AllowUserToDeleteRows = $false
$script:gridScripts.AllowUserToResizeRows = $false
$script:gridScripts.AutoGenerateColumns = $false
$script:gridScripts.AutoSizeColumnsMode = 'Fill'
$script:gridScripts.SelectionMode = 'FullRowSelect'
$script:gridScripts.MultiSelect = $false
$script:gridScripts.RowHeadersVisible = $false
$script:gridScripts.AccessibleName = 'Operational scripts'
[void]$script:gridScripts.Columns.Add('Number', 'No.')
[void]$script:gridScripts.Columns.Add('Task', 'Task')
[void]$script:gridScripts.Columns.Add('Modes', 'Supported modes')
$script:nameColumn = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$script:nameColumn.Name = 'Name'; $script:nameColumn.HeaderText = 'File'; $script:nameColumn.Visible = $false
[void]$script:gridScripts.Columns.Add($script:nameColumn)
$script:synopsisColumn = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$script:synopsisColumn.Name = 'Synopsis'; $script:synopsisColumn.HeaderText = 'Synopsis'; $script:synopsisColumn.Visible = $false
[void]$script:gridScripts.Columns.Add($script:synopsisColumn)
Add-TableControl $script:scriptLayout $script:gridScripts 0 1 2
$script:lblScriptState = Get-LabelControl -Text 'Refresh the kit to discover scripts.' -AccessibleName 'Script list status'
Add-TableControl $script:scriptLayout $script:lblScriptState 0 2 2
$script:lblScriptDetails = Get-LabelControl -Text 'Select a script to review its purpose and supported modes.' -AccessibleName 'Selected script details'
$script:lblScriptDetails.MaximumSize = New-Object System.Drawing.Size(900, 0)
Add-TableControl $script:scriptLayout $script:lblScriptDetails 0 3 2
$script:lblArgs = Get-LabelControl -Text '&Advanced arguments:' -AccessibleName 'Advanced arguments label'
$script:txtArgs = New-Object System.Windows.Forms.TextBox
$script:txtArgs.Dock = 'Fill'
$script:txtArgs.AccessibleName = 'Advanced script arguments'
$script:txtArgs.AccessibleDescription = 'Script-specific tokens only. Launcher-owned mode, paths, output, confirmation, and integrity arguments are rejected.'
Add-TableControl $script:scriptLayout $script:lblArgs 0 4
Add-TableControl $script:scriptLayout $script:txtArgs 1 4
}

function New-LauncherProfileTab {
# Profile tab
$script:profileLayout = New-Object System.Windows.Forms.TableLayoutPanel
$script:profileLayout.Dock = 'Fill'
$script:profileLayout.Padding = New-Object System.Windows.Forms.Padding(8)
$script:profileLayout.ColumnCount = 3
$script:profileLayout.RowCount = 4
[void]$script:profileLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
[void]$script:profileLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
[void]$script:profileLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
[void]$script:profileLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
[void]$script:profileLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
[void]$script:profileLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
[void]$script:profileLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
$script:tabProfile.Controls.Add($script:profileLayout)
$script:lblProfile = Get-LabelControl -Text '&Profile JSON:' -AccessibleName 'Profile path label'
$script:txtProfile = New-Object System.Windows.Forms.TextBox
$script:txtProfile.Dock = 'Fill'
$script:txtProfile.AccessibleName = 'Profile JSON path'
$script:btnBrowseProfile = Get-ButtonControl -Text 'Browse &profile…' -AccessibleName 'Browse for profile JSON'
$script:btnValidateProfile = Get-ButtonControl -Text '&Validate profile' -AccessibleName 'Validate selected profile'
Add-TableControl $script:profileLayout $script:lblProfile 0 0
Add-TableControl $script:profileLayout $script:txtProfile 1 0
Add-TableControl $script:profileLayout $script:btnBrowseProfile 2 0
$script:lblProfileSummary = Get-LabelControl -Text 'Choose a profile, then validate it before running.' -AccessibleName 'Profile validation summary'
Add-TableControl $script:profileLayout $script:lblProfileSummary 0 1 3
$script:gridProfileSteps = New-Object System.Windows.Forms.DataGridView
$script:gridProfileSteps.Dock = 'Fill'
$script:gridProfileSteps.ReadOnly = $true
$script:gridProfileSteps.AllowUserToAddRows = $false
$script:gridProfileSteps.AllowUserToDeleteRows = $false
$script:gridProfileSteps.RowHeadersVisible = $false
$script:gridProfileSteps.AutoSizeColumnsMode = 'Fill'
$script:gridProfileSteps.SelectionMode = 'FullRowSelect'
$script:gridProfileSteps.AccessibleName = 'Profile steps and dependencies'
[void]$script:gridProfileSteps.Columns.Add('Script', 'Step script')
[void]$script:gridProfileSteps.Columns.Add('DependsOn', 'Depends on')
Add-TableControl $script:profileLayout $script:gridProfileSteps 0 2 3
Add-TableControl $script:profileLayout $script:btnValidateProfile 2 3
}

function New-LauncherExecutionControls {
# Execution policy and actions
$script:executionGroup = New-Object System.Windows.Forms.GroupBox
$script:executionGroup.Text = 'Execution policy'
$script:executionGroup.AutoSize = $true
$script:executionGroup.Dock = 'Fill'
$script:executionLayout = New-Object System.Windows.Forms.FlowLayoutPanel
$script:executionLayout.Dock = 'Fill'
$script:executionLayout.AutoSize = $true
$script:executionLayout.WrapContents = $true
$script:executionLayout.Padding = New-Object System.Windows.Forms.Padding(8)
$script:executionGroup.Controls.Add($script:executionLayout)
$script:rbAudit = New-Object System.Windows.Forms.RadioButton
$script:rbAudit.Text = '&Audit'; $script:rbAudit.Checked = $true; $script:rbAudit.AutoSize = $true; $script:rbAudit.AccessibleDescription = 'Read-only execution mode.'
$script:rbRemediate = New-Object System.Windows.Forms.RadioButton
$script:rbRemediate.Text = '&Remediate'; $script:rbRemediate.AutoSize = $true; $script:rbRemediate.Enabled = $script:IsElevated; $script:rbRemediate.AccessibleDescription = 'Applies endpoint changes after explicit review.'
$script:chkStrict = New-Object System.Windows.Forms.CheckBox
$script:chkStrict.Text = '&Strict'; $script:chkStrict.AutoSize = $true
$script:chkRequireSigned = New-Object System.Windows.Forms.CheckBox
$script:chkRequireSigned.Text = 'Require valid &signature'; $script:chkRequireSigned.AutoSize = $true; $script:chkRequireSigned.Checked = $script:IsElevated
$script:chkRequireSigned.AccessibleDescription = 'Defaults on for elevated sessions. Signature validation supplements the required protected-path ACL checks.'
$script:lblHash = Get-LabelControl -Text 'Expected &hash:' -AccessibleName 'Expected hash label'
$script:txtExpectedHash = New-Object System.Windows.Forms.TextBox
$script:txtExpectedHash.Width = 190; $script:txtExpectedHash.AccessibleName = 'Expected script hash'
$script:cmbHashAlgorithm = New-Object System.Windows.Forms.ComboBox
$script:cmbHashAlgorithm.DropDownStyle = 'DropDownList'; $script:cmbHashAlgorithm.Width = 80; $script:cmbHashAlgorithm.AccessibleName = 'Hash algorithm'
[void]$script:cmbHashAlgorithm.Items.AddRange(@('SHA256', 'SHA384', 'SHA512')); $script:cmbHashAlgorithm.SelectedIndex = 0
$script:btnRun = Get-ButtonControl -Text '&Run audit' -AccessibleName 'Run audit'
$script:btnStop = Get-ButtonControl -Text 'S&top run' -AccessibleName 'Stop active run'; $script:btnStop.Enabled = $false
foreach ($control in @($script:rbAudit, $script:rbRemediate, $script:chkStrict, $script:chkRequireSigned, $script:lblHash, $script:txtExpectedHash, $script:cmbHashAlgorithm, $script:btnRun, $script:btnStop)) { [void]$script:executionLayout.Controls.Add($control) }
$script:configurationLayout.Controls.Add($script:executionGroup, 0, 1)
}

function New-LauncherResultsPane {
# Results pane
$script:resultsLayout = New-Object System.Windows.Forms.TableLayoutPanel
$script:resultsLayout.Dock = 'Fill'
$script:resultsLayout.ColumnCount = 1
$script:resultsLayout.RowCount = 2
[void]$script:resultsLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
[void]$script:resultsLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
$script:split.Panel2.Controls.Add($script:resultsLayout)
$script:resultsActions = New-Object System.Windows.Forms.FlowLayoutPanel
$script:resultsActions.Dock = 'Fill'; $script:resultsActions.AutoSize = $true
$script:lblOutput = Get-LabelControl -Text '&Results' -AccessibleName 'Results pane label'
$script:btnClear = Get-ButtonControl -Text '&Clear view' -AccessibleName 'Clear visible output'
$script:btnSave = Get-ButtonControl -Text '&Save captured output' -AccessibleName 'Save captured temporary output log'
foreach ($control in @($script:lblOutput, $script:btnClear, $script:btnSave)) { [void]$script:resultsActions.Controls.Add($control) }
$script:txtOutput = New-Object System.Windows.Forms.TextBox
$script:txtOutput.Dock = 'Fill'; $script:txtOutput.Multiline = $true; $script:txtOutput.ReadOnly = $true
$script:txtOutput.ScrollBars = 'Both'; $script:txtOutput.WordWrap = $false
$script:txtOutput.Font = New-Object System.Drawing.Font('Consolas', 9)
$script:txtOutput.BackColor = [System.Drawing.SystemColors]::Window
$script:txtOutput.ForeColor = [System.Drawing.SystemColors]::WindowText
$script:txtOutput.AccessibleName = 'Execution results'
$script:txtOutput.AccessibleDescription = 'Live bounded view of launcher and runner output.'
$script:resultsLayout.Controls.Add($script:resultsActions, 0, 0)
$script:resultsLayout.Controls.Add($script:txtOutput, 0, 1)

$script:statusStrip = New-Object System.Windows.Forms.StatusStrip
$script:statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$script:statusLabel.Text = 'Ready'; $script:statusLabel.Spring = $true; $script:statusLabel.TextAlign = 'MiddleLeft'
[void]$script:statusStrip.Items.Add($script:statusLabel)
$script:rootLayout.Controls.Add($script:statusStrip, 0, 2)
$script:form.AcceptButton = $script:btnRun
}

function Remove-LauncherVisibleLineExcess {
  $excess = $script:VisibleLines.Count - $script:MaxVisibleLines
  if ($excess -le 0) { return }

  $removeLength = 0
  for ($index = 0; $index -lt $excess; $index++) {
    $removeLength += ([string]$script:VisibleLines[$index]).Length + [Environment]::NewLine.Length
  }
  $script:VisibleLines.RemoveRange(0, $excess)
  $script:txtOutput.Select(0, $removeLength)
  $script:txtOutput.SelectedText = ''
}

function Update-LauncherVisibleOutput {
  $batch = New-Object System.Collections.ArrayList
  for ($i = 0; $i -lt 250; $i++) {
    $line = $null
    $hasLine = if ($null -ne $script:OutputCollector) { $script:OutputCollector.TryDequeue([ref]$line) } else { $script:OutputQueue.TryDequeue([ref]$line) }
    if (-not $hasLine) { break }
    [void]$batch.Add($line)
  }
  if ($batch.Count -gt 0) {
    $separator = if ($script:VisibleLines.Count -gt 0) { [Environment]::NewLine } else { '' }
    $script:VisibleLines.AddRange($batch)
    $script:txtOutput.AppendText($separator + (($batch | ForEach-Object { [string]$_ }) -join [Environment]::NewLine))
    Remove-LauncherVisibleLineExcess
    $script:txtOutput.SelectionStart = $script:txtOutput.TextLength
    $script:txtOutput.ScrollToCaret()
  }
}

function Update-LauncherElapsedStatus {
  if ($script:State -in @('Running', 'Stopping', 'Validating') -and $null -ne $script:RunStarted) {
    $script:statusLabel.Text = "$($script:State) - $(((Get-Date) - $script:RunStarted).ToString('hh\:mm\:ss')) elapsed"
  }
}

function Complete-LauncherReadyWork {
  if ($null -ne $script:CurrentProcess -and $script:CurrentProcess.HasExited) { Complete-LauncherProcess }
  if ($null -ne $script:DiscoveryTask -and $script:DiscoveryTask.IsCompleted) { Complete-ScriptCatalogDiscovery }
}

function Invoke-LauncherOutputTick {
  Update-LauncherVisibleOutput
  Update-LauncherElapsedStatus
  Complete-LauncherReadyWork
}

function Start-LauncherOutputTimer {
# Timers and events
$script:outputTimer = New-Object System.Windows.Forms.Timer
$script:outputTimer.Interval = 100
$script:outputTimer.Add_Tick({ Invoke-LauncherOutputTick })
$script:outputTimer.Start()
}

function Register-LauncherInputEvents {
$script:btnBrowseRoot.Add_Click({
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = 'Select the kit folder containing scripts'
    $dialog.SelectedPath = $script:txtRoot.Text.Trim()
    if ($dialog.ShowDialog($script:form) -eq 'OK') { $script:txtRoot.Text = $dialog.SelectedPath; Get-ScriptCatalogView }
    $dialog.Dispose()
  })
$script:btnRefresh.Add_Click({ Get-ScriptCatalogView })
$script:txtRoot.Add_Validated({ Get-ScriptCatalogView })
$script:txtFilter.Add_TextChanged({ Show-FilteredScript })
$script:gridScripts.Add_SelectionChanged({ Write-ScriptDetail })
$script:btnBrowseProfile.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = 'JSON profiles (*.json)|*.json|All files (*.*)|*.*'
    $dialog.Title = 'Select execution profile'
    if ($dialog.ShowDialog($script:form) -eq 'OK') { $script:txtProfile.Text = $dialog.FileName; $script:ProfileSummary = $null; Write-ProfileSummary }
    $dialog.Dispose()
  })
$script:txtProfile.Add_TextChanged({ $script:ProfileSummary = $null; Write-ProfileSummary; $script:errorProvider.SetError($script:txtProfile, '') })
}

function Register-LauncherValidationEvents {
$script:btnValidateProfile.Add_Click({
    $script:errorProvider.SetError($script:txtProfile, '')
    if (-not (Test-LauncherKitRoot -RootPath $script:txtRoot.Text.Trim())) { $script:errorProvider.SetError($script:txtRoot, 'Select a valid kit root before validating a profile.'); $script:txtRoot.Focus(); return }
    if (-not (Test-Path -LiteralPath $script:txtProfile.Text.Trim() -PathType Leaf)) { $script:errorProvider.SetError($script:txtProfile, 'Select an existing profile JSON file.'); $script:txtProfile.Focus(); return }
    try {
      $manifest = ConvertTo-LauncherManifest -Operation validate-profile -Root $script:txtRoot.Text.Trim() -Target $script:txtProfile.Text.Trim()
      Initialize-RunArtifact
      Add-LauncherLine "[VALIDATE] $($script:txtProfile.Text.Trim())"
      Invoke-LauncherProcess -Manifest $manifest -Purpose validation
    } catch { $script:errorProvider.SetError($script:txtProfile, $_.Exception.Message); Write-LauncherState Failed 'Could not start validation' }
  })
}

function Update-LauncherTabControls {
  $script:btnRun.Text = if ($script:rbRemediate.Checked) { 'Review and run remediation…' } else { '&Run audit' }
  $script:txtExpectedHash.Enabled = ($script:tabs.SelectedTab -eq $script:tabScript) -and ($script:State -notin @('Running', 'Stopping', 'Validating'))
}

function Set-LauncherAuditButton {
  if ($script:rbAudit.Checked) { $script:btnRun.Text = '&Run audit'; $script:btnRun.AccessibleName = 'Run audit' }
}

function Set-LauncherRemediationButton {
  if ($script:rbRemediate.Checked) { $script:btnRun.Text = 'Review and run remediation…'; $script:btnRun.AccessibleName = 'Review and run remediation' }
}

function Request-LauncherStopFromUi {
  if ($null -eq $script:CurrentProcess) { return }
  $message = if ((Get-EffectiveMode) -eq 'Remediate') { 'Stop this remediation run? Completed changes are not rolled back. Rerun Audit afterward to establish final state.' } else { 'Stop this audit run?' }
  if ([System.Windows.Forms.MessageBox]::Show($script:form, $message, 'Stop active run', 'YesNo', 'Warning', 'Button2') -eq 'Yes') { [void](Request-LauncherProcessStop -Detail 'Waiting for process-tree termination…') }
}

function Register-LauncherRunEvents {
$script:tabs.Add_SelectedIndexChanged({ Update-LauncherTabControls })
$script:rbAudit.Add_CheckedChanged({ Set-LauncherAuditButton })
$script:rbRemediate.Add_CheckedChanged({ Set-LauncherRemediationButton })
$script:btnRun.Add_Click({ Invoke-SelectedRun })
$script:btnStop.Add_Click({ Request-LauncherStopFromUi })
$script:btnClear.Add_Click({ $script:VisibleLines.Clear(); $script:txtOutput.Clear() })
}

function Register-LauncherSaveEvents {
$script:btnSave.Add_Click({
    if ([string]::IsNullOrWhiteSpace($script:FullLogPath) -or -not (Test-Path -LiteralPath $script:FullLogPath -PathType Leaf)) {
      [System.Windows.Forms.MessageBox]::Show($script:form, 'No captured output log is available yet.', 'Save captured output', 'OK', 'Information') | Out-Null
      return
    }
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Filter = 'Log files (*.log)|*.log|Text files (*.txt)|*.txt|All files (*.*)|*.*'
    $dialog.FileName = "baselineops-windows-launcher-$(Get-Date -Format yyyyMMdd-HHmmss).log"
    if ($dialog.ShowDialog($script:form) -eq 'OK') {
      try {
        if ($null -ne $script:OutputCollector) { $script:OutputCollector.Flush() }
        Copy-Item -LiteralPath $script:FullLogPath -Destination $dialog.FileName -Force
        [System.Windows.Forms.MessageBox]::Show($script:form, "Captured output saved to:`r`n$($dialog.FileName)`r`n`r`nThe log is capped at 25 MiB and may contain sensitive endpoint evidence. Review it before sharing.", 'Save captured output', 'OK', 'Information') | Out-Null
      } catch {
        $script:errorProvider.SetError($script:btnSave, "Could not save output: $($_.Exception.Message)")
        $script:btnSave.Focus()
      }
    }
    $dialog.Dispose()
  })
}

function Register-LauncherLifecycleEvents {
$script:form.Add_FormClosing({
    param($closingForm, $closingEvent)
    [void]$closingForm
    if ($null -ne $script:CurrentProcess -and -not $script:CloseAfterStop) {
      $choice = [System.Windows.Forms.MessageBox]::Show($script:form, 'Stop the active run and close after the worker reaches a terminal state? Select No to keep the launcher open.', 'Active run', 'YesNo', 'Warning', 'Button2')
      $closingEvent.Cancel = $true
      if ($choice -eq 'Yes') {
        $script:CloseAfterStop = $true
        if (-not (Request-LauncherProcessStop -Detail 'Stopping process tree before close…')) {
          $script:CloseAfterStop = $false
        }
      }
    }
  })
$script:form.Add_FormClosed({
    $script:outputTimer.Stop(); $script:outputTimer.Dispose()
    Close-RunArtifact
    if ($script:FullLogPath -and (Test-Path -LiteralPath $script:FullLogPath)) { Remove-Item -LiteralPath $script:FullLogPath -Force -ErrorAction SilentlyContinue }
  })
$script:form.Add_Load({ Get-ScriptCatalogView; Write-LauncherState -State Ready -Detail 'Audit is selected' })
}

  New-LauncherShell
  New-LauncherEnvironment
  New-LauncherConfiguration
  New-LauncherScriptTab
  New-LauncherScriptGrid
  New-LauncherProfileTab
  New-LauncherExecutionControls
  New-LauncherResultsPane
  Start-LauncherOutputTimer
  Register-LauncherInputEvents
  Register-LauncherValidationEvents
  Register-LauncherRunEvents
  Register-LauncherSaveEvents
  Register-LauncherLifecycleEvents
  [void]$script:form.ShowDialog()
}
