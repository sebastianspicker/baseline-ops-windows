#requires -version 5.1
<#
.SYNOPSIS
  Provides private Office and browser hardening phases.
.DESCRIPTION
  Preserves capability-local policy, confirmation, error, and proof semantics for the public entry point.
#>

function Initialize-OfficeBrowserProofRun {
  param($RunState)
  if (-not (Ensure-EventSource -Source $RunState.EventSource -Log $RunState.EventLog)) {
    Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
  }

  $RunState.isAdmin = Test-IsAdmin
  $RunState.globalNotes = New-Object System.Collections.Generic.List[string]
  $RunState.proofPath = $RunState.DefaultProofPath
  $RunState.overallOk = $true

  $RunState.catalogInfo = Load-Catalog -CatalogPath $RunState.CatalogPath -ConfigPath $RunState.ConfigPath -DefaultCatalogJson $RunState.DefaultCatalogJson
  foreach ($n in $RunState.catalogInfo.Notes) {
    $RunState.globalNotes.Add($n) | Out-Null
  }

  if (-not $RunState.isAdmin) {
    $RunState.globalNotes.Add("Not elevated: HKLM (Edge) and Program Files (Firefox) writes may fail.") | Out-Null
  }

  $RunState.cat = $RunState.catalogInfo.Catalog
  $proofOverride = Get-TextOrNull $RunState.cat.Proof.OutFile
  if ($proofOverride) {
    $RunState.proofPath = $proofOverride
  }

  $RunState.allItems = New-Object System.Collections.Generic.List[object]

}

function Complete-OfficeBrowserProof {
  param($RunState)
  $RunState.allSafe = @($RunState.allItems | ForEach-Object { Ensure-ProofItemLike $_ })

  $RunState.nonCompliant = @($RunState.allSafe | Where-Object { (Bool-Prop $_ 'Compliant' $true) -eq $false })
  if ($RunState.nonCompliant.Count -gt 0) {
    $RunState.overallOk = $false
  }

  $RunState.changedCount = @($RunState.allSafe | Where-Object { (Bool-Prop $_ 'Changed' $false) -eq $true }).Count

  $RunState.proof = [ordered]@{
    Time = (Get-Date).ToString("s")
    Hostname = $env:COMPUTERNAME
    Strict = [bool]$RunState.Strict
    Remediate = [bool]$RunState.Remediate
    IsAdmin = [bool]$RunState.isAdmin
    Catalog = [ordered]@{ LoadedFrom = $RunState.catalogInfo.LoadedFrom }
    Notes = @($RunState.globalNotes)
    Summary = [ordered]@{
      TotalItems = $RunState.allSafe.Count
      NonCompliant = $RunState.nonCompliant.Count
      Changed = $RunState.changedCount
    }
    Items = @($RunState.allSafe)
  }

}

function Save-OfficeBrowserProof {
  param($RunState)
  try {
    Save-Json -InputObject $RunState.proof -Path $RunState.proofPath -NoBom
  }
  catch {
    $RunState.overallOk = $false
    $RunState.globalNotes.Add("Failed to write proof JSON: $($_.Exception.Message)") | Out-Null
  }

}

function Write-OfficeBrowserHealthEvent {
  param($RunState)
  try {
    $eventId = 4940
    $level = 'Information'
    if (-not $RunState.overallOk -or $RunState.Strict) {
      $eventId = 4950
      $level = 'Warning'
    }

    $msg = @(
      ("Office/Browser hardening: Ok={0} Strict={1} Remediate={2}" -f $RunState.overallOk, [bool]$RunState.Strict, [bool]$RunState.Remediate),
      ("TotalItems={0} NonCompliant={1} Changed={2}" -f $RunState.proof.Summary.TotalItems, $RunState.proof.Summary.NonCompliant, $RunState.proof.Summary.Changed),
      ("Proof JSON: {0}" -f $RunState.proofPath)
    ) -join "`r`n"

    Write-HealthEvent -Id $eventId -Msg $msg -Level $level -Source $RunState.EventSource -Log $RunState.EventLog
  }
  catch {
    Write-Verbose ("Office/browser health event write failed: {0}" -f $_.Exception.Message)
  }

}

function Add-OfficeBrowserFindings {
  param($RunState)
  foreach ($nc in @($RunState.nonCompliant)) {
    $prod = if ($nc.PSObject.Properties['Product']) {
      $nc.Product
    }
    else {
      'Unknown'
    }
    $area = if ($nc.PSObject.Properties['Area']) {
      $nc.Area
    }
    else {
      ''
    }
    $name = if ($nc.PSObject.Properties['Name']) {
      $nc.Name
    }
    else {
      ''
    }
    $msg = if ($nc.PSObject.Properties['Message']) {
      $nc.Message
    }
    else {
      ("{0}/{1}/{2} not compliant" -f $prod, $area, $name)
    }
    $code = "OB-{0}" -f ($prod -replace '\s', '')
    Add-Finding -FindingList $script:Findings -Code $code -Severity 'Medium' -Message $msg `
      -Extra @{ Product = $prod
      Area = $area
      Name = $name
    }
  }

}

function Invoke-OfficeBrowserProof {
  param($RunState)
  Initialize-OfficeBrowserProofRun -RunState $RunState
  try {
    foreach ($i in (Ensure-Office  -OfficeCfg  $RunState.cat.Office  -Remediate:$RunState.Remediate)) {
      $RunState.allItems.Add($i) | Out-Null
    }
    foreach ($i in (Ensure-Edge    -EdgeCfg    $RunState.cat.Edge    -Remediate:$RunState.Remediate)) {
      $RunState.allItems.Add($i) | Out-Null
    }
    foreach ($i in (Ensure-Firefox -FirefoxCfg $RunState.cat.Firefox -Remediate:$RunState.Remediate)) {
      $RunState.allItems.Add($i) | Out-Null
    }
  }
  catch {
    $RunState.overallOk = $false
    $RunState.globalNotes.Add("Unhandled error during evaluation: $($_.Exception.Message)") | Out-Null
  }

  Complete-OfficeBrowserProof -RunState $RunState

  Save-OfficeBrowserProof -RunState $RunState

  Write-OfficeBrowserHealthEvent -RunState $RunState

  Write-ConsoleSummary -AllItems @($RunState.allSafe) -CatalogInfo $RunState.catalogInfo -ProofPath $RunState.proofPath -IsAdmin $RunState.isAdmin -Remediate ([bool]$RunState.Remediate) -Strict ([bool]$RunState.Strict) -Notes @($RunState.globalNotes)

  Add-OfficeBrowserFindings -RunState $RunState
}

function New-OfficeBrowserRunState {
  param([hashtable]$Inputs)
  $state = @{
    EventSource = $null
    EventLog = $null
    DefaultProofPath = $null
    DefaultCatalogJson = $null
    isAdmin = $null
    globalNotes = $null
    proofPath = $null
    overallOk = $null
    catalogInfo = $null
    cat = $null
    allItems = $null
    allSafe = $null
    nonCompliant = $null
    changedCount = $null
    proof = $null
    CatalogPath = $null
    ConfigPath = $null
    Remediate = $null
    Strict = $null
  }
  foreach ($key in $Inputs.Keys) {
    $state[$key] = $Inputs[$key]
  }
  $state.EventSource = 'OfficeBrowser-Hardening'
  $state.EventLog = 'Application'
  $state.DefaultProofPath = Join-Path ([System.IO.Path]::GetTempPath()) 'OfficeBrowser-Hardening-Proof.json'
  $state.DefaultCatalogJson = Get-DefaultOfficeBrowserCatalog
  return $state
}
