#requires -Version 5.1
<#
.SYNOPSIS
Regression coverage for bounded launcher output rendering.
.DESCRIPTION
Exercises the platform-neutral state changes around the WinForms output view,
including append-only batches, exact oldest-line removal, suffix, and scrolling.
#>

BeforeAll {
  if (-not ('LauncherTextBoxProbe' -as [type])) {
    Add-Type -TypeDefinition @'
using System;

public sealed class LauncherTextBoxProbe
{
    private int selectionStart;
    private int selectionLength;
    public string Text = String.Empty;
    public int AppendCallCount;
    public int ReplacementCount;
    public int ScrollCallCount;
    public int TextLength { get { return this.Text.Length; } }
    public int SelectionStart { get { return this.selectionStart; } set { this.selectionStart = value; } }
    public string SelectedText
    {
        get { return String.Empty; }
        set
        {
            this.Text = this.Text.Remove(this.selectionStart, this.selectionLength).Insert(this.selectionStart, value ?? String.Empty);
            this.selectionLength = 0;
            this.ReplacementCount++;
        }
    }
    public void AppendText(string value) { this.Text += value; this.AppendCallCount++; }
    public void Select(int start, int length) { this.selectionStart = start; this.selectionLength = length; }
    public void ScrollToCaret() { this.ScrollCallCount++; }
}
'@
  }

  $viewPath = Join-Path $PSScriptRoot '../../tools/Launcher-GUI.View.ps1'
  $tokens = $null
  $parseErrors = $null
  $ast = [Management.Automation.Language.Parser]::ParseFile($viewPath, [ref]$tokens, [ref]$parseErrors)
  $parseErrors.Count | Should -Be 0
  $functionAsts = @($ast.FindAll({
      param($node)
      $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -in @('Remove-LauncherVisibleLineExcess', 'Update-LauncherVisibleOutput')
    }, $true))
  $moduleText = (($functionAsts | ForEach-Object Extent | ForEach-Object Text) -join [Environment]::NewLine) + @'
function Invoke-LauncherVisibleOutputTest {
  param($Queue, $VisibleLines, $TextOutput, [int]$Maximum)
  $script:OutputCollector = $null
  $script:OutputQueue = $Queue
  $script:VisibleLines = $VisibleLines
  $script:txtOutput = $TextOutput
  $script:MaxVisibleLines = $Maximum
  Update-LauncherVisibleOutput
}
Export-ModuleMember -Function Invoke-LauncherVisibleOutputTest
'@
  $script:LauncherViewTestModule = New-Module -Name LauncherViewContract -ScriptBlock ([scriptblock]::Create($moduleText))
  Import-Module $script:LauncherViewTestModule -Force

function Test-LauncherAppendBatch {
  $queue = New-Object 'Collections.Concurrent.ConcurrentQueue[string]'
  @('alpha', 'beta', 'gamma') | ForEach-Object { $queue.Enqueue($_) }
  $visible = New-Object Collections.ArrayList
  $textOutput = New-Object LauncherTextBoxProbe
  Invoke-LauncherVisibleOutputTest -Queue $queue -VisibleLines $visible -TextOutput $textOutput -Maximum 10000
  $textOutput.Text | Should -BeExactly (@('alpha', 'beta', 'gamma') -join [Environment]::NewLine)
  $textOutput.AppendCallCount | Should -Be 1
  $textOutput.ReplacementCount | Should -Be 0
  $textOutput.SelectionStart | Should -Be $textOutput.TextLength
  $textOutput.ScrollCallCount | Should -Be 1
}

function Test-LauncherVisibleRetention {
  $queue = New-Object 'Collections.Concurrent.ConcurrentQueue[string]'
  0..24 | ForEach-Object { $queue.Enqueue(('new-{0:D2}' -f $_)) }
  $visible = New-Object Collections.ArrayList
  0..9989 | ForEach-Object { [void]$visible.Add(('seed-{0:D4}' -f $_)) }
  $textOutput = New-Object LauncherTextBoxProbe
  $textOutput.Text = (@($visible) -join [Environment]::NewLine)
  Invoke-LauncherVisibleOutputTest -Queue $queue -VisibleLines $visible -TextOutput $textOutput -Maximum 10000
  $visible.Count | Should -Be 10000
  $visible[0] | Should -BeExactly 'seed-0015'
  $visible[$visible.Count - 1] | Should -BeExactly 'new-24'
  $textOutput.Text | Should -BeExactly (@($visible) -join [Environment]::NewLine)
  $textOutput.AppendCallCount | Should -Be 1
  $textOutput.ReplacementCount | Should -Be 1
  $textOutput.SelectionStart | Should -Be $textOutput.TextLength
  $textOutput.ScrollCallCount | Should -Be 1
}
}

AfterAll {
  Remove-Module LauncherViewContract -Force -ErrorAction SilentlyContinue
}

Describe 'launcher visible output rendering' {
  It 'appends one new batch and preserves the displayed suffix and scroll position' {
    Test-LauncherAppendBatch
  }

  It 'removes the exact oldest excess in one operation above 10000 lines' {
    Test-LauncherVisibleRetention
  }
}
