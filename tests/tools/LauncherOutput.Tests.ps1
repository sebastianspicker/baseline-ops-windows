#requires -Version 5.1
<#
.SYNOPSIS
Regression coverage for launcher output batching and lifecycle behavior.
.DESCRIPTION
Verifies ordered bounded retention, timed and size-triggered persistence,
truncation, write-failure handling, terminal stream drain, and disposal races.
#>

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../tools/Launcher.Core.psm1') -Force

  if (-not ('LauncherCollectorRaceProbe' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

public static class LauncherCollectorRaceProbe
{
    public static Task[] Start(object collector, int workers, int linesPerWorker)
    {
        MethodInfo addLine = collector.GetType().GetMethod("AddLine");
        MethodInfo dispose = collector.GetType().GetMethod("Dispose");
        MethodInfo flushFromTimer = collector.GetType().GetMethod("FlushFromTimer", BindingFlags.Instance | BindingFlags.NonPublic);
        List<Task> tasks = new List<Task>();
        for (int worker = 0; worker < workers; worker++)
        {
            int capturedWorker = worker;
            tasks.Add(Task.Run(() =>
            {
                for (int line = 0; line < linesPerWorker; line++)
                    addLine.Invoke(collector, new object[] { String.Format("worker-{0:D2}-line-{1:D4}", capturedWorker, line) });
            }));
        }
        tasks.Add(Task.Run(() =>
        {
            Thread.Sleep(2);
            dispose.Invoke(collector, null);
        }));
        tasks.Add(Task.Run(() => flushFromTimer.Invoke(collector, new object[] { null })));
        return tasks.ToArray();
    }
}
'@
  }

function Test-LauncherOrderedRetention {
  $path = Join-Path $TestDrive 'ordered.log'
  $collector = New-Object LauncherOutputCollector($path, 1MB, 3)
  0..9 | ForEach-Object { $collector.AddLine("line-$_") }
  $collector.Flush()
  $pending = @()
  $line = $null
  while ($collector.TryDequeue([ref]$line)) { $pending += $line }
  $collector.Dispose()
  [IO.File]::ReadAllLines($path) | Should -Be (0..9 | ForEach-Object { "line-$_" })
  $pending | Should -Be @('line-7', 'line-8', 'line-9')
}

function Test-LauncherTimerDeadline {
  $path = Join-Path $TestDrive 'deadline.log'
  $collector = New-Object LauncherOutputCollector($path, 1MB, 10)
  $stopwatch = [Diagnostics.Stopwatch]::StartNew()
  $collector.AddLine('deadline-line')
  while ($stopwatch.ElapsedMilliseconds -lt 1000 -and [IO.File]::ReadAllText($path) -notmatch 'deadline-line') {
    Start-Sleep -Milliseconds 10
  }
  $stopwatch.Stop()
  $collector.Dispose()
  [IO.File]::ReadAllText($path) | Should -Match 'deadline-line'
  $stopwatch.ElapsedMilliseconds | Should -BeLessThan 1000
}

function Test-LauncherSizeThreshold {
  $path = Join-Path $TestDrive 'threshold.log'
  $collector = New-Object LauncherOutputCollector($path, 1MB, 10)
  $collector.AddLine(('x' * 70000))
  $collector.FlushOperationCount | Should -BeGreaterThan 0
  [IO.File]::ReadAllText($path).Length | Should -BeGreaterThan 65536
  $collector.Dispose()
}

function Test-LauncherTruncation {
  $path = Join-Path $TestDrive 'truncated.log'
  $collector = New-Object LauncherOutputCollector($path, 16, 10)
  $collector.AddLine('first')
  $collector.AddLine(('x' * 100))
  $collector.AddLine('after-limit')
  $collector.Complete()
  [IO.File]::ReadAllLines($path) | Should -Be @('first', '[OUTPUT TRUNCATED: temporary full log reached 25 MiB]')
  $collector.IsTruncated | Should -BeTrue
  $collector.PendingCount | Should -Be 3
  $collector.Dispose()
}

function Test-LauncherWriteFailure {
  $path = Join-Path $TestDrive 'failed.log'
  $collector = New-Object LauncherOutputCollector($path, 1MB, 10)
  $writerField = [LauncherOutputCollector].GetField('writer', [Reflection.BindingFlags]'Instance,NonPublic')
  $writerField.GetValue($collector).Dispose()
  { $collector.AddLine('still-visible') } | Should -Not -Throw
  $collector.LogWriteFailed | Should -BeTrue
  $collector.PendingCount | Should -Be 1
  { $collector.Flush() } | Should -Throw '*earlier write failed*'
  { $collector.Dispose() } | Should -Not -Throw
}

function Test-LauncherTerminalDrain {
  $path = Join-Path $TestDrive 'drain.log'
  $collector = New-Object LauncherOutputCollector($path, 1MB, 10)
  $bytes = [Text.Encoding]::UTF8.GetBytes("first`r`nsecond`nterminal")
  $stream = New-Object IO.MemoryStream(, $bytes)
  $reader = New-Object IO.StreamReader($stream)
  $task = $collector.DrainOutputAsync($reader)
  $task.Wait(2000) | Should -BeTrue
  $collector.Complete()
  [IO.File]::ReadAllLines($path) | Should -Be @('first', 'second', 'terminal')
  $flushes = $collector.FlushOperationCount
  Start-Sleep -Milliseconds 400
  $collector.FlushOperationCount | Should -Be $flushes
  $reader.Dispose()
  $collector.Dispose()
}

function Test-LauncherPostCompletionOrdering {
  $path = Join-Path $TestDrive 'post-completion.log'
  $collector = New-Object LauncherOutputCollector($path, 1MB, 10)
  $collector.AddLine('before-completion')
  $collector.Complete()
  $collector.AddLine('late-terminal-line')
  [IO.File]::ReadAllLines($path) | Should -Be @('before-completion', 'late-terminal-line')
  $collector.Dispose()
}

function Test-LauncherBoundedDrainFrame {
  $path = Join-Path $TestDrive 'bounded-drain.log'
  $collector = New-Object LauncherOutputCollector($path, 1MB, 10)
  $bytes = [Text.Encoding]::UTF8.GetBytes(('x' * 9000))
  $stream = New-Object IO.MemoryStream(, $bytes)
  $reader = New-Object IO.StreamReader($stream)
  $collector.DrainOutputAsync($reader).Wait(2000) | Should -BeTrue
  $collector.Complete()
  $lines = [IO.File]::ReadAllLines($path)
  $lines.Count | Should -Be 3
  ($lines | Measure-Object Length -Maximum).Maximum | Should -BeLessOrEqual 4096
  ($lines -join '').Length | Should -Be 9000
  $reader.Dispose()
  $collector.Dispose()
}

function Test-LauncherDisposalRace {
  $path = Join-Path $TestDrive 'race.log'
  $collector = New-Object LauncherOutputCollector($path, 10MB, 128)
  $tasks = [LauncherCollectorRaceProbe]::Start($collector, 6, 500)
  [Threading.Tasks.Task]::WaitAll($tasks, 5000) | Should -BeTrue
  $collector.IsDisposed | Should -BeTrue
  $collector.PendingCount | Should -BeLessOrEqual 128
  @($tasks | Where-Object IsFaulted).Count | Should -Be 0
}
}

Describe 'LauncherOutputCollector batching and lifecycle' {
  It 'keeps persisted and pending lines ordered while retaining only the newest pending bound' {
    Test-LauncherOrderedRetention
  }

  It 'flushes a pending line within the 250 millisecond timer deadline' {
    Test-LauncherTimerDeadline
  }

  It 'flushes immediately when an unflushed batch reaches 64 KiB' {
    Test-LauncherSizeThreshold
  }

  It 'writes one truncation marker while continuing bounded pending capture' {
    Test-LauncherTruncation
  }

  It 'records a write failure without throwing from producers or disposal' {
    Test-LauncherWriteFailure
  }

  It 'drains the terminal unterminated line before explicit completion' {
    Test-LauncherTerminalDrain
  }

  It 'flushes late terminal lines synchronously after completion in order' {
    Test-LauncherPostCompletionOrdering
  }

  It 'bounds newline-free stream frames while preserving all characters' {
    Test-LauncherBoundedDrainFrame
  }

  It 'handles producer and timer disposal races without unbounded pending output' {
    Test-LauncherDisposalRace
  }
}
