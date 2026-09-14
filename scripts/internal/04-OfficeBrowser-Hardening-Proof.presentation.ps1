#requires -version 5.1
<#
.SYNOPSIS
  Provides private Office and browser hardening phases.
.DESCRIPTION
  Preserves capability-local policy, confirmation, error, and proof semantics for the public entry point.
#>

function Write-ConsoleSummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object[]]$AllItems,
    [Parameter(Mandatory)][object]$CatalogInfo,
    [Parameter(Mandatory)][string]$ProofPath,
    [Parameter(Mandatory)][bool]$IsAdmin,
    [Parameter(Mandatory)][bool]$Remediate,
    [Parameter(Mandatory)][bool]$Strict,
    [Parameter(Mandatory)][string[]]$Notes
  )

  $safe = @($AllItems | ForEach-Object { Ensure-ProofItemLike $_ })

  $officeItems = @($safe | Where-Object { $_.Product -eq 'Office' })
  $edgeItems = @($safe | Where-Object { $_.Product -eq 'Edge' })
  $firefoxItems = @($safe | Where-Object { $_.Product -eq 'Firefox' })

  $sum = @(
    Get-ResultSummary -Section 'Office'  -Items $officeItems
    Get-ResultSummary -Section 'Edge'    -Items $edgeItems
    Get-ResultSummary -Section 'Firefox' -Items $firefoxItems
  )

  Write-OfficeBrowserSummaryHeader -CatalogInfo $CatalogInfo -IsAdmin:$IsAdmin -Remediate:$Remediate -Strict:$Strict

  foreach ($row in $sum) {
    $statusText = if ($row.Ok) {
      "OK"
    }
    else {
      "DRIFT"
    }
    $statusColor = if ($row.Ok) {
      'Green'
    }
    else {
      'Red'
    }

    Write-UiLine ("[{0}]" -f $row.Section) -ForegroundColor White -NoNewline
    Write-UiLine (" {0,-5} " -f $statusText) -ForegroundColor $statusColor -NoNewline
    Write-UiLine ("Total={0}  NonCompliant={1}  Changed={2}" -f $row.Total, $row.NonCompliant, $row.Changed) -ForegroundColor Gray
  }

  Write-OfficeBrowserDriftSample -Items $safe

  Write-OfficeBrowserSummaryNotes -Notes $Notes

  Write-UiLine ""
  Write-UiLine ("Proof JSON written to: {0}" -f $ProofPath) -ForegroundColor Cyan
  Write-UiLine ""

  Write-OfficeBrowserTotals -Items $safe -Strict:$Strict

}

function Write-OfficeBrowserDriftSample {
  param($Items)
  $driftSample = @($Items | Where-Object { (Bool-Prop $_ 'Compliant' $true) -eq $false } | Select-Object -First 10)
  if ($driftSample.Count -gt 0) {
    Write-UiLine ""
    Write-UiLine "Drift sample (first 10 items)" -ForegroundColor Yellow
    Write-UiLine "---------------------------------------------" -Style 'Warning'
    foreach ($d in $driftSample) {
      Write-UiLine ("- [{0}/{1}] {2} :: {3}\{4} (Expected={5} Actual={6})" -f $d.Product, $d.Area, $d.Policy, $d.Target, $d.Name, $d.Expected, $d.Actual) -ForegroundColor Yellow
    }
  }

}

function Write-OfficeBrowserTotals {
  param($Items, [bool]$Strict)
  $total = $Items.Count
  $nonCompliant = @($Items | Where-Object { (Bool-Prop $_ 'Compliant' $true) -eq $false }).Count
  $changed = @($Items | Where-Object { (Bool-Prop $_ 'Changed' $false) -eq $true }).Count

  $overallOk = ($nonCompliant -eq 0)
  $finalColor = if ($overallOk -and -not $Strict) {
    'Green'
  }
  else {
    'Red'
  }
  $finalText = if ($overallOk -and -not $Strict) {
    'HARDENING OK'
  }
  else {
    'DRIFT DETECTED'
  }

  Write-UiLine "==================================================" -Style 'Header'
  Write-UiLine (" Final result : {0}" -f $finalText) -ForegroundColor $finalColor
  Write-UiLine (" Items        : Total={0}  NonCompliant={1}  Changed={2}" -f $total, $nonCompliant, $changed) -ForegroundColor Gray
  Write-UiLine "==================================================" -Style 'Header'

  Write-Information ("Summary: FinalResult={0}; Total={1}; NonCompliant={2}; Changed={3}" -f $finalText, $total, $nonCompliant, $changed)
}

function Write-OfficeBrowserSummaryHeader {
  param($CatalogInfo, [bool]$IsAdmin, [bool]$Remediate, [bool]$Strict)
  Write-UiLine ""
  Write-UiLine "==================================================" -Style 'Header'
  Write-UiLine " Office / Browser Hardening Summary" -Style 'Accent'
  Write-UiLine "==================================================" -Style 'Header'
  Write-UiLine ("Catalog source : {0}" -f $CatalogInfo.LoadedFrom) -ForegroundColor Gray
  Write-UiLine ("Mode           : Remediate={0}  Strict={1}  IsAdmin={2}" -f $Remediate, $Strict, $IsAdmin) -ForegroundColor Gray
  Write-UiLine ""

}

function Write-OfficeBrowserSummaryNotes {
  param([string[]]$Notes)
  if ($Notes -and $Notes.Count -gt 0) {
    Write-UiLine ""
    Write-UiLine "Notes" -ForegroundColor White
    Write-UiLine "-----" -ForegroundColor White
    foreach ($n in $Notes) {
      Write-UiLine ("- " + $n) -ForegroundColor DarkGray
    }
  }

}
