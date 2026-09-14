#requires -version 5.1
<#
.SYNOPSIS
Runs Update Health and servicing stack proof phases.
.DESCRIPTION
Uses explicit state to retain evidence, findings, actions, notes, proof output, and terminal summary across named phases.
#>

function Initialize-UpdateHealthEntry {
  param($V2Context)
  if ($V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
  $script:NoColor = [bool]$V2Context.NoColor
  $ErrorActionPreference = 'Stop'
  return [bool]$V2Context.Remediate
}

function New-UpdateHealthUnsupportedSummary {
  param([string]$Mode)
  return [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Timestamp = Get-Date; Mode = $Mode; Supported = $false; Notes = @('Skipped: this script is only supported on Windows hosts.') }
}

function New-UpdateHealthRunState {
  param([string]$DefaultProofPath)
  $stopwatch = New-Object System.Diagnostics.Stopwatch
  $stopwatch.Start()
  return [pscustomobject]@{
    Stopwatch = $stopwatch; Admin = Test-IsAdmin; EventSourceOk = $true
    Findings = [System.Collections.ArrayList]::new(); Actions = [System.Collections.ArrayList]::new(); Notes = [System.Collections.ArrayList]::new()
    OutFile = $DefaultProofPath; Catalog = $null; CatalogInfo = $null; Evidence = [ordered]@{}
    EffectiveFindings = [System.Collections.ArrayList]::new(); SummaryStatus = 'OK'; CatalogSource = 'Default'; Proof = $null
  }
}

function Add-UpdateHealthVersionFinding {
  param($RunState, [string]$Area, [string]$Have, [string]$Minimum, [string]$Source, [bool]$Required)
  if (-not $Minimum) { return }
  if (-not $Have) {
    if ($Required) { Add-ArrayList $RunState.Findings (Get-LegacyFinding -Area $Area -Severity Warning -Message ("Version unknown; cannot compare to Min {0}." -f $Minimum)) }
    return
  }
  $comparison = Compare-Version $Have $Minimum
  if ($null -eq $comparison) { Add-ArrayList $RunState.Findings (Get-LegacyFinding -Area $Area -Severity Warning -Message ("Version compare failed ({0}='{1}' vs Min='{2}')." -f $Source,$Have,$Minimum)); return }
  if ($comparison -lt 0) { Add-ArrayList $RunState.Findings (Get-LegacyFinding -Area $Area -Severity Warning -Message ("{0} {1} < Min {2}." -f $Source,$Have,$Minimum)) }
}

function Get-UpdateHealthInstallPolicy {
  param($Policy)
  $required = $true
  $minimum = $null
  if ($Policy) {
    if ($null -ne $Policy.Require) { $required = [bool]$Policy.Require }
    if ($Policy.MinVersion) { $minimum = [string]$Policy.MinVersion }
  }
  return [pscustomobject]@{ Required = $required; Minimum = $minimum }
}

function Get-UpdateHealthAllowedStarts {
  param($Policy)
  $allowed = @('Automatic','AutomaticDelayedStart')
  if (-not $Policy -or -not $Policy.ServiceStartAllowed) { return $allowed }
  try { $allowed = @($Policy.ServiceStartAllowed) }
  catch { Write-Verbose ('Update Health Tools ServiceStartAllowed read failed: {0}' -f $_.Exception.Message) }
  if (-not $allowed -or $allowed.Count -eq 0) { return @('Automatic','AutomaticDelayedStart') }
  return $allowed
}

function Test-UpdateHealthInstallation {
  param($RunState)
  $info = Get-UHT-Info
  $RunState.Evidence.UpdateHealthTools = $info
  $policy = Get-UpdateHealthToolsPolicy -Catalog $RunState.Catalog
  $installPolicy = Get-UpdateHealthInstallPolicy -Policy $policy
  if ($installPolicy.Required -and -not $info.Installed) { Add-ArrayList $RunState.Findings (Get-LegacyFinding -Area UHT -Severity Error -Message 'Not installed.') }
  $have = $info.DisplayVersion; $source = 'DisplayVersion'
  if ([string]::IsNullOrWhiteSpace($have)) { $have = $info.FileVersion; $source = 'FileVersion' }
  Add-UpdateHealthVersionFinding -RunState $RunState -Area UHT -Have $have -Minimum $installPolicy.Minimum -Source $source -Required $installPolicy.Required
}

function Get-UpdateHealthServicePolicy {
  param($Catalog)
  $section = Get-UpdateHealthToolsPolicy -Catalog $Catalog
  $allowed = Get-UpdateHealthAllowedStarts -Policy $section
  $desiredState = $(if ($section -and $section.ServiceDesiredState) { Get-SafeString $section.ServiceDesiredState Running } else { 'Running' })
  return [pscustomobject]@{ Allowed = $allowed; DesiredState = $desiredState }
}

function Test-UpdateHealthStartType {
  param($RunState, $Info, $Policy, [bool]$Remediate)
  $actual = $Info.Service.StartType
  if (-not $actual -or $actual -eq 'N/A' -or $Policy.Allowed -contains $actual) { return $false }
  Add-ArrayList $RunState.Findings (Get-LegacyFinding -Area UHT -Severity Warning -Message ("uhssvc StartType '{0}' not allowed ({1})." -f $actual,($Policy.Allowed -join ', ')))
  if ($Remediate) { Add-UpdateHealthServiceFix -RunState $RunState -Start $Policy.Allowed[0] -State $Policy.DesiredState }
  return $true
}

function Test-UpdateHealthStatus {
  param($RunState, $Info, $Policy, [bool]$Remediate)
  $actualState = $Info.Service.Status
  if (-not $actualState -or $actualState -eq 'N/A' -or $actualState -eq $Policy.DesiredState) { return }
  Add-ArrayList $RunState.Findings (Get-LegacyFinding -Area UHT -Severity Warning -Message ("uhssvc Status '{0}' expected '{1}'." -f $actualState,$Policy.DesiredState))
  $actualStart = $Info.Service.StartType
  $start = $(if ($actualStart -and $Policy.Allowed -contains $actualStart) { $actualStart } else { $Policy.Allowed[0] })
  if ($Remediate) { Add-UpdateHealthServiceFix -RunState $RunState -Start $start -State $Policy.DesiredState }
}

function Repair-UpdateHealthService {
  param($RunState, $Info, $Policy, [bool]$Remediate)
  $startDrift = Test-UpdateHealthStartType -RunState $RunState -Info $Info -Policy $Policy -Remediate $Remediate
  if (-not $startDrift) { Test-UpdateHealthStatus -RunState $RunState -Info $Info -Policy $Policy -Remediate $Remediate }
}

function Add-UpdateHealthServiceFix {
  param($RunState, [string]$Start, [string]$State)
  $fix = Ensure-ServiceState -Name uhssvc -Start $Start -State $State -Remediate
  Add-ArrayListMany $RunState.Findings $fix.Drift
  Add-ArrayListMany $RunState.Actions $fix.Actions
}

function Test-UpdateHealthTasks {
  param($RunState, [bool]$Remediate)
  $policy = Get-UpdateHealthToolsPolicy -Catalog $RunState.Catalog
  $ensure = $(if ($policy -and $null -ne $policy.EnsureTasksEnabled) { [bool]$policy.EnsureTasksEnabled } else { $true })
  if (-not $ensure) { return }
  $folder = $(if ($policy -and $policy.TaskFolder) { [string]$policy.TaskFolder } else { '\Microsoft\UpdateHealthService\' })
  $RunState.Evidence.UpdateHealthTools.Tasks = Get-TaskInfoUnder $folder
  $fix = Ensure-TasksEnabled -Folder $folder -Remediate:$Remediate
  Add-ArrayListMany $RunState.Findings $fix.Drift
  Add-ArrayListMany $RunState.Actions $fix.Actions
}

function Test-UpdateHealthServiceAndTasks {
  param($RunState, [bool]$Remediate)
  if (-not $RunState.Evidence.UpdateHealthTools.Installed) { return }
  $policy = Get-UpdateHealthServicePolicy -Catalog $RunState.Catalog
  Repair-UpdateHealthService -RunState $RunState -Info $RunState.Evidence.UpdateHealthTools -Policy $policy -Remediate $Remediate
  Test-UpdateHealthTasks -RunState $RunState -Remediate $Remediate
}

function Test-ServicingStackVersion {
  param($RunState)
  $info = Get-SSU-Info
  $RunState.Evidence.ServicingStack = $info
  $policy = Get-ServicingStackPolicy -Catalog $RunState.Catalog
  $minimum = $(if ($policy -and $policy.MinVersion) { [string]$policy.MinVersion } else { $null })
  if (-not $minimum) { return }
  if (-not $info.Version) { Add-ArrayList $RunState.Findings (Get-LegacyFinding -Area SSU -Severity Warning -Message ("Version unknown; cannot compare to Min {0}." -f $minimum)); return }
  $comparison = Compare-Version $info.Version $minimum
  if ($null -eq $comparison) { Add-ArrayList $RunState.Findings (Get-LegacyFinding -Area SSU -Severity Warning -Message ("Version compare failed (Have='{0}' vs Min='{1}', Source={2})." -f $info.Version,$minimum,$info.Source)); return }
  if ($comparison -lt 0) { Add-ArrayList $RunState.Findings (Get-LegacyFinding -Area SSU -Severity Warning -Message ("{0} < Min {1} (Source={2})." -f $info.Version,$minimum,$info.Source)) }
}

function Invoke-UpdateHealthEvaluation {
  param($RunState, $DefaultCatalog, [string]$CatalogPath, [string]$ConfigPath, [bool]$Remediate)
  if (-not $RunState.Admin) { Add-ArrayList $RunState.Notes (Get-LegacyFinding -Area Runtime -Severity Info -Message 'Not elevated; remediation/event logging may fail.') }
  $loaded = Load-Catalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath -FallbackCatalog $DefaultCatalog
  $RunState.Catalog = $loaded.Catalog; $RunState.CatalogInfo = $loaded.Meta
  if (-not $loaded.Meta.CatalogLoaded -and $loaded.Meta.Errors -and $loaded.Meta.Errors.Count -gt 0) {
    foreach ($errorMessage in $loaded.Meta.Errors) { Add-ArrayList $RunState.Notes (Get-LegacyFinding -Area Catalog -Severity Info -Message $errorMessage) }
  }
  Test-UpdateHealthInstallation $RunState
  Test-UpdateHealthServiceAndTasks $RunState $Remediate
  Test-ServicingStackVersion $RunState
  $RunState.Evidence.WUCoreServices = Get-WU-CoreServices
  $RunState.OutFile = Get-UpdateHealthProofPath -Catalog $RunState.Catalog -DefaultPath $RunState.OutFile
}

function Initialize-UpdateHealthProof {
  param($RunState, [string]$CatalogPath, [string]$ConfigPath, [bool]$Remediate, [bool]$Strict)
  Add-ArrayListMany $RunState.EffectiveFindings $RunState.Findings
  if ($Strict) { Add-ArrayListMany $RunState.EffectiveFindings $RunState.Notes }
  foreach ($finding in $RunState.EffectiveFindings) { Add-FindingToCanonical -LegacyFinding $finding }
  $RunState.Proof = [pscustomobject]@{
    Time = (Get-Date).ToString('s'); Hostname = $env:COMPUTERNAME; User = [pscustomobject]@{ Name = $env:USERNAME; IsAdmin = $RunState.Admin }
    Settings = [pscustomobject]@{ CatalogPath = Get-SafeString $CatalogPath ''; ConfigPath = Get-SafeString $ConfigPath ''; Remediate = $Remediate; Strict = $Strict; EventSource = $script:EventSource; EventLog = $script:EventLog; FallbackLog = $script:FallbackLog }
    CatalogMeta = $RunState.CatalogInfo; Evidence = $RunState.Evidence; Actions = @($RunState.Actions); Findings = @($RunState.EffectiveFindings); Notes = @($RunState.Notes)
  }
}

function Save-UpdateHealthProof {
  param($RunState)
  try { Save-Json -InputObject $RunState.Proof -Path $RunState.OutFile -Depth 12; Add-ArrayList $RunState.Actions (Get-LegacyAction -Target $RunState.OutFile -Operation WriteJson -Result Success -Message 'Proof written') }
  catch { Write-FallbackLogLine ("JSON write failed ({0}): {1}" -f $RunState.OutFile,$_.Exception.Message); Add-ArrayList $RunState.Notes (Get-LegacyFinding -Area Proof -Severity Info -Message 'Failed to write JSON proof file.') }
}

function Write-UpdateHealthEvent {
  param($RunState, [bool]$Remediate, [bool]$Strict)
  if (-not $RunState.EventSourceOk) { return }
  $hasFinding = ($RunState.EffectiveFindings.Count -gt 0)
  $eventId = $(if ($hasFinding) { 5010 } else { 5000 }); $level = $(if ($hasFinding) { 'Warning' } else { 'Information' })
  $RunState.CatalogSource = $(if ($RunState.CatalogInfo -and $RunState.CatalogInfo.CatalogSource) { [string]$RunState.CatalogInfo.CatalogSource } else { 'Default' })
  $top = @($RunState.EffectiveFindings | Select-Object -First 8 | ForEach-Object { '[{0}] {1}' -f $_.Area,$_.Message })
  $message = @(
    ('CatalogSource={0}; Remediate={1}; Strict={2}; Admin={3}; JSON={4}' -f $RunState.CatalogSource,$Remediate,$Strict,$RunState.Admin,$RunState.OutFile)
    ('Actions={0}; Findings={1}' -f $RunState.Actions.Count,$RunState.EffectiveFindings.Count); ('Top={0}' -f ($top -join ' | '))
  ) -join "`r`n"
  [void](Write-HealthEvent -Id $eventId -Msg $message -Level $level)
}

function Write-UpdateHealthNotes {
  param($Items)
  if ($Items.Count -eq 0) { return }
  Write-UiLine ''; Write-UiLine -Text Notes -Style Header
  foreach ($item in $Items) {
    $style = 'Info'
    if ($item.Severity -eq 'Error') { $style = 'Err' }
    elseif ($item.Severity -eq 'Warning') { $style = 'Warn' }
    Write-UiLine -Text ('- {0} [{1}] {2}' -f $item.Time,$item.Area,$item.Message) -Style $style
  }
}

function Write-UpdateHealthActions {
  param($Items)
  if ($Items.Count -eq 0) { return }
  Write-UiLine ''; Write-UiLine -Text Actions -Style Header
  foreach ($item in $Items) {
    $style = $(if ($item.Result -ne 'Success') { 'Err' } else { 'Ok' })
    Write-UiLine -Text ('- {0} {1} {2}: {3} ({4})' -f $item.Time,$item.Target,$item.Operation,$item.Message,$item.Result) -Style $style
  }
}

function Write-UpdateHealthFindings {
  param($Items)
  if ($Items.Count -eq 0) { Write-UiLine ''; Write-UiLine -Text 'No findings.' -Style Ok; return }
  Write-UiLine ''; Write-UiLine -Text Findings -Style Header
  foreach ($item in $Items) {
    $style = 'Info'
    if ($item.Severity -eq 'Error') { $style = 'Err' }
    elseif ($item.Severity -eq 'Warning') { $style = 'Warn' }
    Write-UiLine -Text ('- {0} [{1}] {2} ({3})' -f $item.Time,$item.Area,$item.Message,$item.Severity) -Style $style
  }
}

function Get-UpdateHealthSummaryStyles {
  param([string]$Status, [bool]$Admin)
  return [pscustomobject]@{ Status = $(if ($Status -eq 'OK') { 'Ok' } else { 'Warn' }); Admin = $(if ($Admin) { 'Ok' } else { 'Warn' }) }
}

function Write-UpdateHealthSummary {
  param($RunState, [bool]$Remediate, [bool]$Strict)
  $RunState.CatalogSource = $(if ($RunState.CatalogInfo -and $RunState.CatalogInfo.CatalogSource) { [string]$RunState.CatalogInfo.CatalogSource } else { 'Default' })
  $RunState.SummaryStatus = $(if ($RunState.EffectiveFindings.Count -gt 0) { 'WARNING' } else { 'OK' })
  $styles = Get-UpdateHealthSummaryStyles -Status $RunState.SummaryStatus -Admin $RunState.Admin
  Write-UiLine ''; Write-UiLine -Text '=== UpdateHealth/SSU Proof Summary ===' -Style Header
  foreach ($pair in @(
      @{ K='Status';V=$RunState.SummaryStatus;S=$styles.Status },@{ K='Remediate';V=[string]$Remediate;S='Dim' },@{ K='Strict';V=[string]$Strict;S='Dim' },
      @{ K='Admin';V=[string]$RunState.Admin;S=$styles.Admin },@{ K='Catalog';V=$RunState.CatalogSource;S='Dim' },@{ K='JSON';V=$RunState.OutFile;S='Dim' },
      @{ K='EventLog';V=("{0}/{1}" -f $script:EventLog,$script:EventSource);S='Dim' },@{ K='Duration';V=("{0} ms" -f $RunState.Stopwatch.ElapsedMilliseconds);S='Dim' }
    )) { Write-KeyValue -Key $pair.K -Value $pair.V -Style $pair.S }
  Write-UpdateHealthNotes $RunState.Notes
  Write-UpdateHealthActions $RunState.Actions
  Write-UpdateHealthFindings $RunState.EffectiveFindings
}

function Invoke-UpdateHealthRun {
  param($RunState, $DefaultCatalog, [string]$CatalogPath, [string]$ConfigPath, [bool]$Remediate, [bool]$Strict)
  if (-not (Ensure-EventSource)) { $RunState.EventSourceOk = $false; Write-Warning 'EventSource could not be registered. EventLog tracing will be unavailable.' }
  try { Invoke-UpdateHealthEvaluation $RunState $DefaultCatalog $CatalogPath $ConfigPath $Remediate }
  catch { Add-ArrayList $RunState.Notes (Get-LegacyFinding -Area Runtime -Severity Error -Message ("Fatal error: {0}" -f $_.Exception.Message)) }
  Initialize-UpdateHealthProof $RunState $CatalogPath $ConfigPath $Remediate $Strict
  Save-UpdateHealthProof $RunState
  Write-UpdateHealthEvent $RunState $Remediate $Strict
  $RunState.Stopwatch.Stop()
  Write-UpdateHealthSummary $RunState $Remediate $Strict
}

function Get-UpdateHealthResultToken {
  param($RunState)
  if ($RunState.SummaryStatus -eq 'FAIL') { return 'FAIL' }
  if ($RunState.SummaryStatus -eq 'WARN' -or $RunState.EffectiveFindings.Count -gt 0) { return 'WARN' }
  return 'OK'
}

function New-UpdateHealthV2Summary {
  param($RunState, [bool]$Remediate, [bool]$Strict)
  return [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Status = $RunState.SummaryStatus; Remediate = $Remediate; Strict = $Strict; DurationMs = $RunState.Stopwatch.ElapsedMilliseconds; Timestamp = Get-Date }
}

function Get-UpdateHealthToolsPolicy {
  param($Catalog)
  if ($Catalog -and $Catalog.PSObject.Properties['UpdateHealthTools']) { return $Catalog.UpdateHealthTools }
  return $null
}

function Get-ServicingStackPolicy {
  param($Catalog)
  if ($Catalog -and $Catalog.PSObject.Properties['ServicingStack']) { return $Catalog.ServicingStack }
  return $null
}

function Get-UpdateHealthProofPath {
  param($Catalog, [string]$DefaultPath)
  if ($Catalog -and $Catalog.PSObject.Properties['Proof'] -and $Catalog.Proof -and $Catalog.Proof.OutFile) { return [string]$Catalog.Proof.OutFile }
  return $DefaultPath
}
