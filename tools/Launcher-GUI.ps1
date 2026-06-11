#requires -Version 5.1
<#
.SYNOPSIS
GUI launcher for MDM Security Hardening scripts and profiles.

.DESCRIPTION
Windows Forms launcher to:
- run a single script via 00-Run-Local.ps1
- run a profile via 00-Run-Profile.ps1
- stream output live
- save output logs
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
  Write-Error 'Launcher-GUI requires Windows.'
  exit 1
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:DefaultRoot = 'C:\install\mdm\ps1'
$guiDir = $PSScriptRoot
$parent = Split-Path -Parent $guiDir
if ((Split-Path -Leaf $guiDir) -eq 'tools' -and (Test-Path -LiteralPath (Join-Path $parent 'scripts') -PathType Container)) {
  $script:DefaultRoot = $parent
}

$executionModulePath = Join-Path $parent 'lib\Execution.psm1'
if (Test-Path -LiteralPath $executionModulePath -PathType Leaf) {
  Import-Module $executionModulePath -Force
}

function Parse-ArgumentString {
  param([string]$ArgString)
  if ([string]::IsNullOrWhiteSpace($ArgString)) { return @() }

  $tokens = [System.Collections.ArrayList]::new()
  $current = [System.Text.StringBuilder]::new()
  $inQuotes = $false
  $chars = $ArgString.ToCharArray()

  for ($i = 0; $i -lt $chars.Length; $i++) {
    $c = $chars[$i]
    if ($c -eq '"') {
      if ($inQuotes) {
        [void]$tokens.Add($current.ToString())
        $current = [System.Text.StringBuilder]::new()
        $inQuotes = $false
      } else {
        $inQuotes = $true
      }
      continue
    }

    if (-not $inQuotes -and ($c -eq ' ' -or $c -eq "`t")) {
      $s = $current.ToString().Trim()
      if ($s) { [void]$tokens.Add($s) }
      $current = [System.Text.StringBuilder]::new()
      continue
    }

    [void]$current.Append($c)
  }

  $tail = $current.ToString().Trim()
  if ($tail) { [void]$tokens.Add($tail) }
  return @($tokens)
}

function Get-ScriptListItems {
  param([string]$RootPath)

  if ([string]::IsNullOrWhiteSpace($RootPath) -or $RootPath -match '\.\.') { return @() }
  $scriptsDir = Join-Path $RootPath 'scripts'
  if (-not (Test-Path -LiteralPath $scriptsDir -PathType Container)) { return @() }

  $files = Get-ChildItem -LiteralPath $scriptsDir -Filter '*.ps1' -File |
    Where-Object { $_.Name -match '^\d{2}-' }

  $list = [System.Collections.ArrayList]::new()
  foreach ($f in ($files | Sort-Object Name)) {
    if ($f.BaseName -match '^(\d+)-') {
      $num = $Matches[1]
      [void]$list.Add([pscustomobject]@{
          Number = $num
          Name = $f.Name
          Display = $f.Name
        })
    }
  }
  return @($list)
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'MDM Security Hardening - Launcher v2'
$form.Size = New-Object System.Drawing.Size(900, 740)
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = New-Object System.Drawing.Size(780, 600)

# --- Root path ---
$lblRoot = New-Object System.Windows.Forms.Label
$lblRoot.Text = 'Root path:'
$lblRoot.Location = New-Object System.Drawing.Point(12, 12)
$lblRoot.AutoSize = $true
$form.Controls.Add($lblRoot)

$txtRoot = New-Object System.Windows.Forms.TextBox
$txtRoot.Text = $script:DefaultRoot
$txtRoot.Location = New-Object System.Drawing.Point(12, 30)
$txtRoot.Size = New-Object System.Drawing.Size(700, 23)
$txtRoot.Anchor = 'Top,Left,Right'
$form.Controls.Add($txtRoot)

$btnBrowseRoot = New-Object System.Windows.Forms.Button
$btnBrowseRoot.Text = 'Browse...'
$btnBrowseRoot.Location = New-Object System.Drawing.Point(720, 28)
$btnBrowseRoot.Size = New-Object System.Drawing.Size(80, 26)
$btnBrowseRoot.Anchor = 'Top,Right'
$form.Controls.Add($btnBrowseRoot)

# --- Script selection ---
$lblScripts = New-Object System.Windows.Forms.Label
$lblScripts.Text = 'Select script:'
$lblScripts.Location = New-Object System.Drawing.Point(12, 62)
$lblScripts.AutoSize = $true
$form.Controls.Add($lblScripts)

$listScripts = New-Object System.Windows.Forms.ListBox
$listScripts.Location = New-Object System.Drawing.Point(12, 80)
$listScripts.Size = New-Object System.Drawing.Size(788, 170)
$listScripts.Anchor = 'Top,Left,Right'
$listScripts.DisplayMember = 'Display'
$form.Controls.Add($listScripts)

# --- Execution controls GroupBox ---
$grpExecution = New-Object System.Windows.Forms.GroupBox
$grpExecution.Text = 'Execution'
$grpExecution.Location = New-Object System.Drawing.Point(8, 254)
$grpExecution.Size = New-Object System.Drawing.Size(868, 100)
$grpExecution.Anchor = 'Top,Left,Right'
$form.Controls.Add($grpExecution)

$lblMode = New-Object System.Windows.Forms.Label
$lblMode.Text = 'MODE:'
$lblMode.Location = New-Object System.Drawing.Point(8, 20)
$lblMode.AutoSize = $true
$lblMode.Font = New-Object System.Drawing.Font($form.Font.FontFamily, $form.Font.Size, [System.Drawing.FontStyle]::Bold)
$grpExecution.Controls.Add($lblMode)

$cmbMode = New-Object System.Windows.Forms.ComboBox
$cmbMode.Location = New-Object System.Drawing.Point(8, 38)
$cmbMode.Size = New-Object System.Drawing.Size(160, 23)
$cmbMode.DropDownStyle = 'DropDownList'
[void]$cmbMode.Items.Add('Audit')
[void]$cmbMode.Items.Add('Remediate')
$cmbMode.SelectedIndex = 0
$grpExecution.Controls.Add($cmbMode)

$lblModeHint = New-Object System.Windows.Forms.Label
$lblModeHint.Text = 'Audit = read-only   |   Remediate = applies changes (use with care)'
$lblModeHint.Location = New-Object System.Drawing.Point(8, 66)
$lblModeHint.AutoSize = $true
$lblModeHint.ForeColor = [System.Drawing.Color]::Gray
$grpExecution.Controls.Add($lblModeHint)

$lblArgs = New-Object System.Windows.Forms.Label
$lblArgs.Text = 'Extra arguments:'
$lblArgs.Location = New-Object System.Drawing.Point(190, 20)
$lblArgs.AutoSize = $true
$grpExecution.Controls.Add($lblArgs)

$txtArgs = New-Object System.Windows.Forms.TextBox
$txtArgs.Location = New-Object System.Drawing.Point(190, 38)
$txtArgs.Size = New-Object System.Drawing.Size(446, 23)
$txtArgs.Anchor = 'Top,Left,Right'
$grpExecution.Controls.Add($txtArgs)

$lblProfile = New-Object System.Windows.Forms.Label
$lblProfile.Text = 'Profile JSON:'
$lblProfile.Location = New-Object System.Drawing.Point(650, 20)
$lblProfile.AutoSize = $true
$lblProfile.Anchor = 'Top,Right'
$grpExecution.Controls.Add($lblProfile)

$txtProfile = New-Object System.Windows.Forms.TextBox
$txtProfile.Location = New-Object System.Drawing.Point(650, 38)
$txtProfile.Size = New-Object System.Drawing.Size(126, 23)
$txtProfile.Anchor = 'Top,Right'
$grpExecution.Controls.Add($txtProfile)

$btnBrowseProfile = New-Object System.Windows.Forms.Button
$btnBrowseProfile.Text = '...'
$btnBrowseProfile.Location = New-Object System.Drawing.Point(780, 36)
$btnBrowseProfile.Size = New-Object System.Drawing.Size(32, 26)
$btnBrowseProfile.Anchor = 'Top,Right'
$grpExecution.Controls.Add($btnBrowseProfile)

# --- Action buttons row ---
$btnRunScript = New-Object System.Windows.Forms.Button
$btnRunScript.Text = 'Run Script'
$btnRunScript.Location = New-Object System.Drawing.Point(12, 362)
$btnRunScript.Size = New-Object System.Drawing.Size(110, 32)
$btnRunScript.Font = New-Object System.Drawing.Font($form.Font.FontFamily, $form.Font.Size, [System.Drawing.FontStyle]::Bold)
$btnRunScript.BackColor = [System.Drawing.Color]::FromArgb(230, 245, 230)
$form.Controls.Add($btnRunScript)

$btnRunProfile = New-Object System.Windows.Forms.Button
$btnRunProfile.Text = 'Run Profile'
$btnRunProfile.Location = New-Object System.Drawing.Point(128, 362)
$btnRunProfile.Size = New-Object System.Drawing.Size(110, 32)
$form.Controls.Add($btnRunProfile)

$btnClear = New-Object System.Windows.Forms.Button
$btnClear.Text = 'Clear'
$btnClear.Location = New-Object System.Drawing.Point(244, 362)
$btnClear.Size = New-Object System.Drawing.Size(80, 32)
$form.Controls.Add($btnClear)

$btnSave = New-Object System.Windows.Forms.Button
$btnSave.Text = 'Save Output'
$btnSave.Location = New-Object System.Drawing.Point(330, 362)
$btnSave.Size = New-Object System.Drawing.Size(110, 32)
$form.Controls.Add($btnSave)

# --- Output area ---
$lblOutput = New-Object System.Windows.Forms.Label
$lblOutput.Text = 'Output:'
$lblOutput.Location = New-Object System.Drawing.Point(12, 402)
$lblOutput.AutoSize = $true
$form.Controls.Add($lblOutput)

$txtOutput = New-Object System.Windows.Forms.TextBox
$txtOutput.Multiline = $true
$txtOutput.ReadOnly = $true
$txtOutput.ScrollBars = 'Both'
$txtOutput.WordWrap = $false
$txtOutput.Location = New-Object System.Drawing.Point(12, 420)
$txtOutput.Size = New-Object System.Drawing.Size(860, 250)
$txtOutput.Anchor = 'Top,Bottom,Left,Right'
$txtOutput.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtOutput.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 30)
$txtOutput.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
$form.Controls.Add($txtOutput)

# --- Status bar ---
$statusBar = New-Object System.Windows.Forms.StatusStrip
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Text = 'Ready'
$statusLabel.Spring = $true
$statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
[void]$statusBar.Items.Add($statusLabel)
$form.Controls.Add($statusBar)

# Mode change highlights Remediate in red as a safety cue
$cmbMode.Add_SelectedIndexChanged({
  if ($cmbMode.SelectedItem -eq 'Remediate') {
    $cmbMode.BackColor = [System.Drawing.Color]::FromArgb(255, 230, 230)
  } else {
    $cmbMode.BackColor = [System.Drawing.SystemColors]::Window
  }
})

function Refresh-ScriptList {
  $root = $txtRoot.Text.Trim()
  $listScripts.Items.Clear()
  foreach ($item in (Get-ScriptListItems -RootPath $root)) {
    [void]$listScripts.Items.Add($item)
  }
}

function Invoke-BackgroundRun {
  param(
    [scriptblock]$ScriptBlock,
    [object[]]$ScriptArguments
  )

  $btnRunScript.Enabled = $false
  $btnRunProfile.Enabled = $false

  $runspace = [runspacefactory]::CreateRunspace()
  $runspace.Open()
  $pwsh = [powershell]::Create().AddScript($ScriptBlock)
  foreach ($arg in $ScriptArguments) { [void]$pwsh.AddArgument($arg) }
  $pwsh.Runspace = $runspace
  $asyncResult = $pwsh.BeginInvoke()
  $cleanupState = [pscustomobject]@{
    PowerShell = $pwsh
    Runspace = $runspace
    AsyncResult = $asyncResult
  }
  [void][System.Threading.ThreadPool]::QueueUserWorkItem([System.Threading.WaitCallback]{
      param($state)
      try {
        [void]$state.PowerShell.EndInvoke($state.AsyncResult)
      } catch {
        Write-Verbose ("Background run failed: {0}" -f $_.Exception.Message)
      } finally {
        try { $state.PowerShell.Dispose() } catch {
          Write-Verbose ("PowerShell instance disposal failed: {0}" -f $_.Exception.Message)
        }
        try { $state.Runspace.Dispose() } catch {
          Write-Verbose ("Runspace disposal failed: {0}" -f $_.Exception.Message)
        }
      }
    }, $cleanupState)
}

$btnBrowseRoot.Add_Click({
  $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
  $dlg.Description = 'Select kit root (contains scripts\\)'
  $dlg.SelectedPath = $txtRoot.Text.Trim()
  if ($dlg.ShowDialog() -eq 'OK') {
    $txtRoot.Text = $dlg.SelectedPath
    Refresh-ScriptList
  }
})

$btnBrowseProfile.Add_Click({
  $dlg = New-Object System.Windows.Forms.OpenFileDialog
  $dlg.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
  if ($dlg.ShowDialog() -eq 'OK') {
    $txtProfile.Text = $dlg.FileName
  }
})

$btnClear.Add_Click({ $txtOutput.Clear() })

$btnSave.Add_Click({
  $dlg = New-Object System.Windows.Forms.SaveFileDialog
  $dlg.Filter = 'Log files (*.log)|*.log|Text files (*.txt)|*.txt|All files (*.*)|*.*'
  $dlg.FileName = "launcher-output-$(Get-Date -Format yyyyMMdd-HHmmss).log"
  if ($dlg.ShowDialog() -eq 'OK') {
    Set-Content -LiteralPath $dlg.FileName -Value $txtOutput.Text -Encoding UTF8
    [System.Windows.Forms.MessageBox]::Show("Saved: $($dlg.FileName)", 'Launcher', 'OK', 'Information') | Out-Null
  }
})

$btnRunScript.Add_Click({
  $root = $txtRoot.Text.Trim()
  if ([string]::IsNullOrWhiteSpace($root) -or $root -match '\.\.') {
    [System.Windows.Forms.MessageBox]::Show('Root path is invalid.', 'Launcher', 'OK', 'Warning') | Out-Null
    return
  }

  $selected = $listScripts.SelectedItem
  if (-not $selected) {
    [System.Windows.Forms.MessageBox]::Show('Select a script first.', 'Launcher', 'OK', 'Warning') | Out-Null
    return
  }

  $runLocal = Join-Path (Join-Path $root 'scripts') '00-Run-Local.ps1'
  if (-not (Test-Path -LiteralPath $runLocal -PathType Leaf)) {
    [System.Windows.Forms.MessageBox]::Show("Missing 00-Run-Local.ps1 in $root\\scripts", 'Launcher', 'OK', 'Warning') | Out-Null
    return
  }

  $mode = [string]$cmbMode.SelectedItem
  $scriptArgs = Parse-ArgumentString -ArgString $txtArgs.Text
  if ($mode -eq 'Remediate' -and -not ($scriptArgs | Where-Object { $_ -ieq '-Mode' -or $_ -imatch '^-Mode:' })) {
    $scriptArgs += @('-Mode', 'Remediate')
  }

  $statusLabel.Text = "Running: $($selected.Name) [$mode]..."
  $txtOutput.AppendText("[RUN] Script: $($selected.Name)  Mode: $mode  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n")
  $sb = {
    param($RunLocalPath, $ScriptName, $RootPath, $ScriptArgs, $OutputControl, $RunScriptButton, $RunProfileButton, $StatusLbl)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
      & $RunLocalPath -ScriptName $ScriptName -RootPath $RootPath -ScriptArgs $ScriptArgs 2>&1 | ForEach-Object {
        $line = [string]$_
        [void]$OutputControl.Invoke([Action]{ $OutputControl.AppendText("$line`r`n") })
      }
      $elapsed = $sw.Elapsed.ToString('hh\:mm\:ss')
      [void]$OutputControl.Invoke([Action]{ $OutputControl.AppendText("[DONE] Completed in $elapsed`r`n`r`n") })
      [void]$StatusLbl.GetCurrentParent().Invoke([Action]{ $StatusLbl.Text = "Completed: $ScriptName ($elapsed)" })
    } catch {
      $line = "ERROR: $($_.Exception.Message)"
      [void]$OutputControl.Invoke([Action]{ $OutputControl.AppendText("$line`r`n") })
      [void]$StatusLbl.GetCurrentParent().Invoke([Action]{ $StatusLbl.Text = "Error: $ScriptName" })
    } finally {
      [void]$RunScriptButton.Invoke([Action]{ $RunScriptButton.Enabled = $true })
      [void]$RunProfileButton.Invoke([Action]{ $RunProfileButton.Enabled = $true })
    }
  }

  Invoke-BackgroundRun -ScriptBlock $sb -ScriptArguments @($runLocal, $selected.Name, $root, $scriptArgs, $txtOutput, $btnRunScript, $btnRunProfile, $statusLabel)
})

$btnRunProfile.Add_Click({
  $root = $txtRoot.Text.Trim()
  $profilePathText = $txtProfile.Text.Trim()

  if ([string]::IsNullOrWhiteSpace($root) -or $root -match '\.\.') {
    [System.Windows.Forms.MessageBox]::Show('Root path is invalid.', 'Launcher', 'OK', 'Warning') | Out-Null
    return
  }
  if ([string]::IsNullOrWhiteSpace($profilePathText) -or -not (Test-Path -LiteralPath $profilePathText -PathType Leaf)) {
    [System.Windows.Forms.MessageBox]::Show('Select a valid profile JSON file.', 'Launcher', 'OK', 'Warning') | Out-Null
    return
  }

  $runProfile = Join-Path (Join-Path $root 'scripts') '00-Run-Profile.ps1'
  if (-not (Test-Path -LiteralPath $runProfile -PathType Leaf)) {
    [System.Windows.Forms.MessageBox]::Show("Missing 00-Run-Profile.ps1 in $root\\scripts", 'Launcher', 'OK', 'Warning') | Out-Null
    return
  }

  $mode = [string]$cmbMode.SelectedItem
  $extra = Parse-ArgumentString -ArgString $txtArgs.Text
  $parsedExtra = if (Get-Command -Name Convert-ArgumentTokens -ErrorAction SilentlyContinue) {
    Convert-ArgumentTokens -Arguments $extra
  } else {
    [pscustomobject]@{ Named = @{}; Positional = @($extra) }
  }

  $profileBaseName = [System.IO.Path]::GetFileName($profilePathText)
  $statusLabel.Text = "Running profile: $profileBaseName [$mode]..."
  $txtOutput.AppendText("[RUN] Profile: $profilePathText  Mode: $mode  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n")
  $sb = {
    param($RunProfilePath, $ProfilePath, $RootPath, $Mode, $NamedExtraArgs, $PositionalExtraArgs, $OutputControl, $RunScriptButton, $RunProfileButton, $StatusLbl)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
      $params = @{
        ProfilePath = $ProfilePath
        RootPath    = $RootPath
        Mode        = $Mode
      }

      & $RunProfilePath @params @NamedExtraArgs @PositionalExtraArgs 2>&1 | ForEach-Object {
        $line = [string]$_
        [void]$OutputControl.Invoke([Action]{ $OutputControl.AppendText("$line`r`n") })
      }
      $elapsed = $sw.Elapsed.ToString('hh\:mm\:ss')
      $pName = [System.IO.Path]::GetFileName($ProfilePath)
      [void]$OutputControl.Invoke([Action]{ $OutputControl.AppendText("[DONE] Profile completed in $elapsed`r`n`r`n") })
      [void]$StatusLbl.GetCurrentParent().Invoke([Action]{ $StatusLbl.Text = "Completed: $pName ($elapsed)" })
    } catch {
      $line = "ERROR: $($_.Exception.Message)"
      [void]$OutputControl.Invoke([Action]{ $OutputControl.AppendText("$line`r`n") })
      [void]$StatusLbl.GetCurrentParent().Invoke([Action]{ $StatusLbl.Text = "Error: profile run failed" })
    } finally {
      [void]$RunScriptButton.Invoke([Action]{ $RunScriptButton.Enabled = $true })
      [void]$RunProfileButton.Invoke([Action]{ $RunProfileButton.Enabled = $true })
    }
  }

  Invoke-BackgroundRun -ScriptBlock $sb -ScriptArguments @($runProfile, $profilePathText, $root, $mode, $parsedExtra.Named, @($parsedExtra.Positional), $txtOutput, $btnRunScript, $btnRunProfile, $statusLabel)
})

$txtRoot.Add_TextChanged({ Refresh-ScriptList })
$form.Add_Load({ Refresh-ScriptList })

[void]$form.ShowDialog()
