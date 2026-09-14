#requires -version 5.1
<#
.SYNOPSIS
  Provides private artifact collection phases.
.DESCRIPTION
  Preserves protected evidence paths, bounded observations, trigger decisions, and artifact proof ordering within this capability.
#>


function Print-ConsoleSummary {
  param(
    [hashtable]$Summary,
    [System.Collections.Generic.List[string]]$Errors,
    [bool]$Findings,
    [string]$CatalogLoadNote,
    [string]$ScriptVersion
  )

  Write-UiHeader -Title ("IR Grabber Summary (v{0})" -f $ScriptVersion) -Subtitle ("Host: {0} | Time: {1}" -f $Summary.Host, $Summary.Time)

  if ($CatalogLoadNote) {
    Write-UiStatus -Label 'Config' -State 'INFO' -Text $CatalogLoadNote
  }

  Write-KeyValue -Key 'WorkDir' -Value ([string]$Summary.Output.WorkDir)
  Write-KeyValue -Key 'Zip'     -Value ([string]$Summary.Output.Zip)

  Write-UiLine
  Write-UiLine "Counts:" -ForegroundColor Gray

  Write-ArtifactProcessCounts -Summary $Summary
  Write-ArtifactNetworkCounts -Summary $Summary
  Write-ArtifactTaskCounts -Summary $Summary
  Write-ArtifactWmiCounts -Summary $Summary
  Write-ArtifactAutorunCounts -Summary $Summary
  Write-ArtifactSampleCounts -Summary $Summary

  Write-UiLine

  if ($Errors -and $Errors.Count -gt 0) {
    Write-UiStatus -Label 'Errors' -State 'WARN' -Text ("{0} error(s) occurred" -f $Errors.Count)
    foreach ($e in @($Errors)) {
      Write-UiLine ("  - {0}" -f $e) -ForegroundColor Yellow
    }
  }
  else {
    Write-UiStatus -Label 'Errors' -State 'OK' -Text "None"
  }

  if ($Findings) {
    Write-UiStatus -Label 'Findings' -State 'WARN' -Text "YES (review outputs)"
  }
  else {
    Write-UiStatus -Label 'Findings' -State 'OK' -Text "NO"
  }

  Write-UiLine
}
function Write-ArtifactProcessCounts {
  param($Summary)
  try {
    Write-UiLine ("  Processes : {0}" -f (Safe-ToInt $Summary.Counts.Processes 0)) -ForegroundColor White
  }
  catch {
    Write-Verbose ("Console process-count summary failed: {0}" -f $_.Exception.Message)
  }

}

function Write-ArtifactNetworkCounts {
  param($Summary)
  try {
    $tcp = Safe-ToInt $Summary.Counts.Network.Tcp 0
    $lst = Safe-ToInt $Summary.Counts.Network.Listeners 0
    $udp = Safe-ToInt $Summary.Counts.Network.Udp 0
    Write-UiLine ("  Network   : TCP={0} Listeners={1} UDP={2}" -f $tcp, $lst, $udp) -ForegroundColor White
  }
  catch {
    Write-Verbose ("Console network-count summary failed: {0}" -f $_.Exception.Message)
  }

}

function Write-ArtifactTaskCounts {
  param($Summary)
  try {
    $tot = Safe-ToInt $Summary.Counts.Tasks.Total 0
    $sus = Safe-ToInt $Summary.Counts.Tasks.Suspicious 0
    $xml = Safe-ToInt $Summary.Counts.Tasks.XmlExported 0

    $c = 'White'
    if ($sus -gt 0) {
      $c = 'Yellow'
    }
    Write-UiLine ("  Tasks     : Total={0} Suspicious={1} XmlExported={2}" -f $tot, $sus, $xml) -ForegroundColor $c
  }
  catch {
    Write-Verbose ("Console task-count summary failed: {0}" -f $_.Exception.Message)
  }

}

function Write-ArtifactWmiCounts {
  param($Summary)
  try {
    $f = Safe-ToInt $Summary.Counts.WMI.Filters 0
    $b = Safe-ToInt $Summary.Counts.WMI.Bindings 0
    $c1 = Safe-ToInt $Summary.Counts.WMI.Cmd 0
    $a = Safe-ToInt $Summary.Counts.WMI.ActiveScript 0
    $e = Safe-ToInt $Summary.Counts.WMI.NTEventLog 0
    $l = Safe-ToInt $Summary.Counts.WMI.LogFile 0

    $wTotal = $f + $b + $c1 + $a + $e + $l
    $col = 'White'
    if ($wTotal -gt 0) {
      $col = 'Yellow'
    }

    Write-UiLine ("  WMI       : Filters={0} Bindings={1} Cmd={2} ActiveScript={3} NTEventLog={4} LogFile={5}" -f $f, $b, $c1, $a, $e, $l) -ForegroundColor $col
  }
  catch {
    Write-Verbose ("Console WMI-count summary failed: {0}" -f $_.Exception.Message)
  }

}

function Write-ArtifactAutorunCounts {
  param($Summary)
  try {
    Write-UiLine ("  Autoruns  : Items={0}" -f (Safe-ToInt $Summary.Counts.Autoruns.Items 0)) -ForegroundColor White
  }
  catch {
    Write-Verbose ("Console autorun-count summary failed: {0}" -f $_.Exception.Message)
  }

}

function Write-ArtifactSampleCounts {
  param($Summary)
  try {
    if ($Summary.Counts.ContainsKey('Samples')) {
      $cop = Safe-ToInt $Summary.Counts.Samples.Copied 0
      $m1 = Safe-ToInt $Summary.Counts.Samples.MaxFileMB 0
      $m2 = Safe-ToInt $Summary.Counts.Samples.MaxTotalMB 0

      $col = 'White'
      if ($cop -gt 0) {
        $col = 'Yellow'
      }

      Write-UiLine ("  Samples   : Copied={0} (MaxFileMB={1}, MaxTotalMB={2})" -f $cop, $m1, $m2) -ForegroundColor $col
    }
  }
  catch {
    Write-Verbose ("Console sample-count summary failed: {0}" -f $_.Exception.Message)
  }

}
