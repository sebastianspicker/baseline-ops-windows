#requires -version 5.1
<#
.SYNOPSIS
Runs the Windows Update for Business proofing phases.
.DESCRIPTION
Uses an explicit run state for source selection, policy evaluation, evidence persistence, and terminal presentation.
#>

function New-WufbRunState {
  param([bool]$Remediate, [bool]$Strict)
  $proofPath = Join-Path (Get-WufbTrustedDataRoot) 'WUfB-Proofing\proof.json'
  return [pscustomobject]@{
    Ok = $true; EventLogStatus = 'Not attempted'; Changes = [System.Collections.Generic.List[string]]::new()
    Drifts = [System.Collections.Generic.List[string]]::new(); Notes = [System.Collections.Generic.List[string]]::new()
    Operations = [System.Collections.Generic.List[object]]::new(); ProofWrittenPath = $null; OutFile = $proofPath
    Proof = [ordered]@{
      Time = (Get-Date).ToString('s'); Hostname = $env:COMPUTERNAME; OS = (Get-OsEvidence); Catalog = @{}; Settings = @{}
      Evidence = @{}; Actions = @(); Drift = @(); Notes = @()
      Result = @{ Ok = $true; HasDrift = $false; Remediate = $Remediate; Strict = $Strict; Elevated = $false }
    }
    HasDrift = $false; ResultLabel = 'OK'; Summary = $null
  }
}

function Set-WufbUpdateSource {
  param($RunState, $Catalog, [bool]$Remediate, [string]$WindowsUpdatePath, [string]$AuPath)
  if ([string]$Catalog.UpdateSource -ne 'WSUS') {
    Add-Result (Set-WufbDword -Path $AuPath -Name UseWUServer -Value 0 -Remediate:$Remediate) $RunState
    Add-Result (Remove-REGValue -Path $WindowsUpdatePath -Name WUServer -Remediate:$Remediate) $RunState
    Add-Result (Remove-REGValue -Path $WindowsUpdatePath -Name WUStatusServer -Remediate:$Remediate) $RunState
    return
  }

  Add-Result (Set-WufbDword -Path $AuPath -Name UseWUServer -Value 1 -Remediate:$Remediate) $RunState
  foreach ($name in @('WUServer','WUStatusServer')) {
    $value = [string]$Catalog.WSUS.$name
    if ([string]::IsNullOrWhiteSpace($value)) {
      $RunState.Notes.Add("UpdateSource=WSUS but WSUS.$name is empty.") | Out-Null
      $RunState.Ok = $false
    }
    else { Add-Result (Set-REGSZ -Path $WindowsUpdatePath -Name $name -Value $value -Remediate:$Remediate) $RunState }
  }
}

function Get-WufbConfiguredDay {
  param($Value, [int]$Default, [int]$Maximum, [string]$Name, [System.Collections.Generic.List[string]]$Notes)
  try { $day = $(if ($null -eq $Value) { $Default } else { [int]$Value }) }
  catch { $Notes.Add("$Name invalid. Using default $Default.") | Out-Null; return $Default }
  if ($day -lt 0 -or $day -gt $Maximum) {
    $Notes.Add("$Name out of range (0-$Maximum). Using default $Default.") | Out-Null
    return $Default
  }
  return $day
}

function Get-WufbDeferralDays {
  param($Catalog, [System.Collections.Generic.List[string]]$Notes)
  return [pscustomobject]@{
    Feature = Get-WufbConfiguredDay -Value $Catalog.Deferrals.FeatureDays -Default 30 -Maximum 365 -Name 'Deferrals.FeatureDays' -Notes $Notes
    Quality = Get-WufbConfiguredDay -Value $Catalog.Deferrals.QualityDays -Default 7 -Maximum 35 -Name 'Deferrals.QualityDays' -Notes $Notes
  }
}

function Set-WufbDeferrals {
  param($RunState, $Catalog, [bool]$Remediate, [string]$WindowsUpdatePath)
  $days = Get-WufbDeferralDays -Catalog $Catalog -Notes $RunState.Notes
  foreach ($setting in @(
      @{ Name = 'DeferFeatureUpdates'; Value = 1 }, @{ Name = 'DeferFeatureUpdatesPeriodInDays'; Value = $days.Feature },
      @{ Name = 'DeferQualityUpdates'; Value = 1 }, @{ Name = 'DeferQualityUpdatesPeriodInDays'; Value = $days.Quality }
    )) {
    Add-Result (Set-WufbDword -Path $WindowsUpdatePath -Name $setting.Name -Value $setting.Value -Remediate:$Remediate) $RunState
  }
}

function Set-WufbTargetRelease {
  param($RunState, $Catalog, [bool]$Remediate, [string]$WindowsUpdatePath)
  $enabled = $false
  try { $enabled = [bool]$Catalog.TargetRelease.Enable } catch { $enabled = $false }
  $product = [string]$Catalog.TargetRelease.ProductVersion
  $release = [string]$Catalog.TargetRelease.TargetReleaseVersionInfo
  if ($enabled -and ([string]::IsNullOrWhiteSpace($product) -or [string]::IsNullOrWhiteSpace($release))) {
    $RunState.Notes.Add('TargetRelease enabled but missing ProductVersion/TargetReleaseVersionInfo. Disabling pinning.') | Out-Null
    $enabled = $false
  }
  if ($enabled) {
    Add-Result (Set-WufbDword -Path $WindowsUpdatePath -Name TargetReleaseVersion -Value 1 -Remediate:$Remediate) $RunState
    Add-Result (Set-REGSZ -Path $WindowsUpdatePath -Name ProductVersion -Value $product -Remediate:$Remediate) $RunState
    Add-Result (Set-REGSZ -Path $WindowsUpdatePath -Name TargetReleaseVersionInfo -Value $release -Remediate:$Remediate) $RunState
    return
  }
  Add-Result (Set-WufbDword -Path $WindowsUpdatePath -Name TargetReleaseVersion -Value 0 -Remediate:$Remediate) $RunState
  Add-Result (Remove-REGValue -Path $WindowsUpdatePath -Name ProductVersion -Remediate:$Remediate) $RunState
  Add-Result (Remove-REGValue -Path $WindowsUpdatePath -Name TargetReleaseVersionInfo -Remediate:$Remediate) $RunState
}

function Set-WufbOptionalPolicies {
  param($RunState, $Catalog, [bool]$Remediate, [string]$DeliveryOptimizationPath)
  if ($null -ne $Catalog.DeliveryOptimization -and $null -ne $Catalog.DeliveryOptimization.DownloadMode) {
    try { Add-Result (Set-WufbDword -Path $DeliveryOptimizationPath -Name DODownloadMode -Value ([int]$Catalog.DeliveryOptimization.DownloadMode) -Remediate:$Remediate) $RunState }
    catch { $RunState.Notes.Add('DeliveryOptimization.DownloadMode invalid. Skipped.') | Out-Null }
  }
  if ($null -ne $Catalog.ActiveHours -and $Catalog.ActiveHours.Enable -eq $true) {
    $RunState.Proof.Settings.ActiveHours = @{ Start = [int]$Catalog.ActiveHours.Start; End = [int]$Catalog.ActiveHours.End }
  }
}

function Set-WufbEvidence {
  param($RunState, [string]$WindowsUpdatePath, [string]$AuPath, [string]$DeliveryOptimizationPath)
  $RunState.Proof.Evidence.Registry = @{
    WindowsUpdatePolicyPath = $WindowsUpdatePath; AUPath = $AuPath; DeliveryOptimizationPath = $DeliveryOptimizationPath
    UseWUServer = Get-REG -Path $AuPath -Name UseWUServer; WUServer = Get-REG -Path $WindowsUpdatePath -Name WUServer
    WUStatusServer = Get-REG -Path $WindowsUpdatePath -Name WUStatusServer
    DeferFeatureUpdatesPeriodInDays = Get-REG -Path $WindowsUpdatePath -Name DeferFeatureUpdatesPeriodInDays
    DeferQualityUpdatesPeriodInDays = Get-REG -Path $WindowsUpdatePath -Name DeferQualityUpdatesPeriodInDays
    TargetReleaseVersion = Get-REG -Path $WindowsUpdatePath -Name TargetReleaseVersion
    ProductVersion = Get-REG -Path $WindowsUpdatePath -Name ProductVersion
    TargetReleaseVersionInfo = Get-REG -Path $WindowsUpdatePath -Name TargetReleaseVersionInfo
    DODownloadMode = Get-REG -Path $DeliveryOptimizationPath -Name DODownloadMode
  }
}

function Save-WufbProofAndEvent {
  param($RunState, [bool]$Strict)
  $RunState.HasDrift = ($RunState.Drifts.Count -gt 0)
  $RunState.Proof.Result.HasDrift = $RunState.HasDrift
  $RunState.Proof.Result.Ok = $RunState.Ok
  $RunState.Proof.Actions = @($RunState.Changes.ToArray())
  $RunState.Proof.Drift = @($RunState.Drifts.ToArray())
  $RunState.Proof.Notes = @($RunState.Notes.ToArray())
  Save-Json -InputObject $RunState.Proof -Path $RunState.OutFile -Depth 12 -NoBom
  $RunState.ProofWrittenPath = $RunState.OutFile
  $RunState.Changes.Add("Proof JSON: $($RunState.ProofWrittenPath)") | Out-Null
  $eventId = 4980; $level = 'Information'
  if (-not $RunState.Ok) { $eventId = 4990; $level = 'Error' }
  elseif ($Strict -and $RunState.HasDrift) { $eventId = 4990; $level = 'Warning' }
  $written = Write-HealthEvent -Id $eventId -Msg "WUfB proof done. Changes=$($RunState.Changes.Count) Drift=$($RunState.Drifts.Count) Notes=$($RunState.Notes.Count)" -Level $level
  $RunState.EventLogStatus = $(if ($written) { 'Written' } else { 'Not written (source/rights)' })
}

function Invoke-WufbEvaluation {
  param($RunState, [string]$CatalogPath, [string]$ConfigPath, [bool]$Remediate, [bool]$Strict)
  if (-not (Ensure-EventSource)) { Write-Warning 'EventSource could not be registered. EventLog tracing will be unavailable.'; $RunState.Notes.Add('Event source not ensured. EventLog write may fail.') | Out-Null }
  $isAdmin = Test-IsAdmin
  $RunState.Proof.Result.Elevated = $isAdmin
  if (-not $isAdmin) { $RunState.Notes.Add('Not elevated. Remediation may fail.') | Out-Null; if ($Remediate) { $RunState.Ok = $false } }
  $catalog = Load-Catalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath -Notes $RunState.Notes
  $RunState.Proof.Catalog = $catalog
  try { $candidateOut = [string]$catalog.Proof.OutFile } catch { $candidateOut = $null }
  $RunState.OutFile = Get-SafeProofPath -Candidate $candidateOut
  $wuPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
  $auPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
  $doPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
  Set-WufbUpdateSource $RunState $catalog $Remediate $wuPath $auPath
  Set-WufbDeferrals $RunState $catalog $Remediate $wuPath
  Set-WufbTargetRelease $RunState $catalog $Remediate $wuPath
  Set-WufbOptionalPolicies $RunState $catalog $Remediate $doPath
  Set-WufbEvidence $RunState $wuPath $auPath $doPath
  Save-WufbProofAndEvent $RunState $Strict
}

function Complete-WufbRun {
  param($RunState, [bool]$Remediate, [bool]$Strict)
  $RunState.HasDrift = ($RunState.Drifts.Count -gt 0)
  $RunState.ResultLabel = 'OK'
  if (-not $RunState.Ok) { $RunState.ResultLabel = 'ERROR' }
  elseif ($Strict -and $RunState.HasDrift) { $RunState.ResultLabel = 'WARNING' }
  elseif (-not $Remediate -and $RunState.HasDrift) { $RunState.ResultLabel = 'DRIFT' }
  $proofPath = $(if ($RunState.ProofWrittenPath) { $RunState.ProofWrittenPath } else { $RunState.OutFile })
  $RunState.Summary = [pscustomobject]@{
    Result = $RunState.ResultLabel; Elevated = $RunState.Proof.Result.Elevated; Remediate = $Remediate; Strict = $Strict
    ChangesCount = $RunState.Changes.Count; DriftCount = $RunState.Drifts.Count; NotesCount = $RunState.Notes.Count
    EventLogStatus = $RunState.EventLogStatus; ProofPath = $proofPath; ComputerName = $env:COMPUTERNAME
  }
  Write-ConsoleSummary -Summary $RunState.Summary -Findings ([System.Collections.ArrayList]::new()) -CustomFields ([ordered]@{
      Result = $RunState.Summary.Result; Elevated = $RunState.Summary.Elevated; Remediate = $RunState.Summary.Remediate; Strict = $RunState.Summary.Strict
      Changes = $RunState.Summary.ChangesCount; Drift = $RunState.Summary.DriftCount; Notes = $RunState.Summary.NotesCount
      EventLog = $RunState.Summary.EventLogStatus; 'Proof JSON' = $RunState.Summary.ProofPath
    })
  Write-WufbDetailLists -RunState $RunState
}

function Write-WufbDetailLists {
  param($RunState)
  foreach ($group in @(
      @{ Name = 'Changes'; Color = [ConsoleColor]::Green; Items = $RunState.Changes.ToArray() },
      @{ Name = 'Drift'; Color = [ConsoleColor]::Yellow; Items = $RunState.Drifts.ToArray() },
      @{ Name = 'Notes'; Color = [ConsoleColor]::Cyan; Items = $RunState.Notes.ToArray() }
    )) {
    if ($group.Items.Count -eq 0) { continue }
    Write-UiLine ''; Write-UiLine ($group.Name + ':') -ForegroundColor $group.Color
    foreach ($item in $group.Items) { Write-UiLine ('- {0}' -f $item) -ForegroundColor ([ConsoleColor]::Gray) }
  }
}

function Add-WufbFindings {
  param($RunState)
  foreach ($drift in $RunState.Drifts) {
    $code = 'WUFB-Drift'; $severity = 'Medium'
    if ($drift -match 'WSUS') { $code = 'WUFB-WsusDrift' }
    if ($drift -match 'Deferral') { $code = 'WUFB-DeferralDrift' }
    if ($drift -match 'TargetRelease') { $code = 'WUFB-TargetReleaseDrift' }
    if ($drift -match 'DeliveryOpt') { $code = 'WUFB-DeliveryOptDrift' }
    if ($drift -match 'Failed') { $severity = 'High' }
    Add-Finding -FindingList $script:Findings -Code $code -Severity $severity -Message $drift
  }
}

function Invoke-WufbRun {
  param($RunState, [string]$CatalogPath, [string]$ConfigPath, [bool]$Remediate, [bool]$Strict)
  try { Invoke-WufbEvaluation $RunState $CatalogPath $ConfigPath $Remediate $Strict }
  catch {
    $RunState.Ok = $false; $RunState.Notes.Add((Get-FirstErrorNote -ErrorRecord $_)) | Out-Null; $RunState.EventLogStatus = 'Not written (error)'
    try { $fallback = Join-Path (Get-WufbTrustedDataRoot) 'WUfB-Proofing\proof-error.json'; Save-Json $RunState.Proof $fallback -Depth 12 -NoBom; $RunState.ProofWrittenPath = $fallback }
    catch { Write-Verbose ('Fallback WUfB proof save failed: {0}' -f $_.Exception.Message) }
  }
  finally { Complete-WufbRun $RunState $Remediate $Strict }
  Add-WufbFindings $RunState
}

function Initialize-WufbEntry {
  param($V2Context)
  if ($V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
  $script:NoColor = [bool]$V2Context.NoColor
  $ErrorActionPreference = 'Stop'
  return [bool]$V2Context.Remediate
}

function New-WufbUnsupportedSummary {
  param([string]$Mode)
  return [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Timestamp = Get-Date; Mode = $Mode; Supported = $false; Notes = @('Skipped: this script is only supported on Windows hosts.') }
}

function Write-WufbStart {
  param([bool]$Remediate)
  $modeText = $(if ($Remediate) { 'Remediate' } else { 'Audit' })
  Write-DecorativeRule -Title ("WUfB Proofing - {0}" -f $env:COMPUTERNAME) -Color Header
  Write-KeyValue -Key Start -Value (Get-Date).ToString()
  Write-KeyValue -Key Mode -Value $modeText
  Write-UiLine ''
}

function Get-WufbResultToken {
  param($RunState)
  if (-not $RunState.Ok) { return 'FAIL' }
  if ($RunState.HasDrift) { return 'WARN' }
  return 'OK'
}

function New-WufbV2Summary {
  param($RunState)
  return [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Ok = $RunState.Ok; HasDrift = $RunState.HasDrift; Timestamp = Get-Date }
}
