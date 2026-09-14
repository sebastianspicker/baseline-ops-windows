#requires -version 5.1
<#
.SYNOPSIS
  Provides private artifact collection phases.
.DESCRIPTION
  Preserves protected evidence paths, bounded observations, trigger decisions, and artifact proof ordering within this capability.
#>

function Collect-ArtifactProcesses {
  param($RunState)
  # Processes
  $RunState.pDir = Join-Path $RunState.work 'process'
  $pRes = Collect-Processes -outDir $RunState.pDir -cat $RunState.cat -hashAll:$RunState.HashAllProcesses
  $RunState.summary.Counts.Processes = Safe-ToInt $pRes.Counts.Count 0
  if ($pRes.Errors.Count -gt 0) {
    $pRes.Errors | ForEach-Object { [void]$RunState.errors.Add($_) }
  }


}

function Collect-ArtifactNetwork {
  param($RunState)
  # Network
  $nDir = Join-Path $RunState.work 'network'
  $nRes = Collect-Network -outDir $nDir
  $RunState.summary.Counts.Network = $nRes.Counts
  if ($nRes.Errors.Count -gt 0) {
    $nRes.Errors | ForEach-Object { [void]$RunState.errors.Add($_) }
  }
  if ($nRes.Notes.Count -gt 0) {
    $RunState.summary.Notes += @($nRes.Notes)
  }


}

function Collect-ArtifactTasks {
  param($RunState)
  # Tasks
  $tDir = Join-Path $RunState.work 'tasks'
  $tRes = Collect-Tasks -outDir $tDir -cat $RunState.cat
  $RunState.summary.Counts.Tasks = $tRes.Counts
  if ($tRes.Errors.Count -gt 0) {
    $tRes.Errors | ForEach-Object { [void]$RunState.errors.Add($_) }
  }
  if (Safe-ToInt $tRes.Counts.Suspicious 0 -gt 0) {
    $RunState.hasFindings = $true
  }


}

function Collect-ArtifactWmi {
  param($RunState)
  # WMI persistence
  $wDir = Join-Path $RunState.work 'wmi'
  $wRes = Collect-WmiPersistence -outDir $wDir
  $RunState.summary.Counts.WMI = $wRes.Counts
  if ($wRes.Errors.Count -gt 0) {
    $wRes.Errors | ForEach-Object { [void]$RunState.errors.Add($_) }
  }

  $wmiTotal = (Safe-ToInt $wRes.Counts.Filters 0) + (Safe-ToInt $wRes.Counts.Bindings 0) + (Safe-ToInt $wRes.Counts.Cmd 0) + (Safe-ToInt $wRes.Counts.ActiveScript 0) + (Safe-ToInt $wRes.Counts.NTEventLog 0) + (Safe-ToInt $wRes.Counts.LogFile 0)
  if ($wmiTotal -gt 0) {
    $RunState.hasFindings = $true
  }


}

function Collect-ArtifactAutoruns {
  param($RunState)
  # Autoruns
  $aDir = Join-Path $RunState.work 'autoruns'
  $aRes = Export-Autoruns -outDir $aDir
  $RunState.summary.Counts.Autoruns = $aRes.Counts
  if ($aRes.Errors.Count -gt 0) {
    $aRes.Errors | ForEach-Object { [void]$RunState.errors.Add($_) }
  }


}

function Collect-ArtifactSamples {
  param($RunState)
  $RunState.sDir = Join-Path $RunState.work 'samples'
  [void](Ensure-Directory $RunState.sDir)

  $RunState.maxFileMB = Safe-ToInt $RunState.tr.MaxFileMB (Safe-ToInt $RunState.cat.Samples.MaxFileSizeMB 20)
  $RunState.maxTotalMB = Safe-ToInt $RunState.tr.MaxTotalMB (Safe-ToInt $RunState.cat.Samples.MaxTotalMB 100)
  $RunState.totalBytes = [ref]([int64]0)

  $procCsv = Join-Path $RunState.pDir 'processes.csv'
  if (Test-Path -LiteralPath $procCsv) {
    $procList = Import-Csv -Path $procCsv
    foreach ($row in $procList) {
      Add-ArtifactSample -RunState $RunState -Row $row
    }
  }
  else {
    [void]$RunState.errors.Add("samples: processes.csv missing")
  }

  $copiedCount = @($RunState.summary.Samples | Where-Object { $_.Copied }).Count
  $RunState.summary.Counts.Samples = @{
    Copied = $copiedCount
    MaxFileMB = $RunState.maxFileMB
    MaxTotalMB = $RunState.maxTotalMB
  }
  if ($copiedCount -gt 0) {
    $RunState.hasFindings = $true
  }

}

function Add-ArtifactSample {
  param($RunState, $Row)
  $path = [string]$row.Path
  if (-not $path) {
    return
  }
  if (-not (Test-Path -LiteralPath $path)) {
    return
  }

  $pick = Test-ArtifactRegexMatch -Value $path -RegexList @($RunState.cat.Samples.__PathIncludeRegex)
  if (-not $pick) {
    return
  }

  if (Safe-ToBool $RunState.cat.Samples.OnlyUnsignedOrUnknown $true) {
    if ($row.Signed -eq 'True') {
      return
    }
  }

  $okc, $dstOrWhy = Copy-ToEvidence -SourcePath $path -EvidenceBaseDir $RunState.sDir -MaxFileSizeMB $RunState.maxFileMB -MaxTotalMB $RunState.maxTotalMB -RunningTotalBytes $RunState.totalBytes
  $sha = $null
  if ($okc) {
    $sha = Get-FileSha256 -Path $dstOrWhy
    [void](Add-Finding -FindingList $script:Findings -Code 'Grabber-SampleCollected' -Severity 'Low' -Message "Suspicious sample collected: $path" -Extra @{ Path = $path
        Sha256 = $sha
        Evidence = $dstOrWhy
      })
  }

  $RunState.summary.Samples += [pscustomobject]@{
    Source = $path
    Copied = [bool]$okc
    Info = $dstOrWhy
    Sha256 = $sha
  }
}
