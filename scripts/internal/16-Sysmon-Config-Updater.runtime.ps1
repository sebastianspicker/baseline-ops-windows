#requires -version 5.1
<#
.SYNOPSIS
Runs the Sysmon configuration updater phases.
.DESCRIPTION
Coordinates policy validation, drift observation, guarded remediation, state persistence, event reporting, and console presentation through explicit state.
#>

function New-SysmonUpdaterState {
  param($Options)
  $summary = [ordered]@{
    Ok=$false; Remediate=$Options.Remediate; EnsureChannel=$Options.EnsureChannel; IsAdmin=$false
    ConfigFile=$null; DesiredSha256=$null; PrevDesiredSha256=$null; SysmonService=$null; SysmonExe=$null
    EngineVersion=$null; MinEngineRequired=$null; CurrentDumpSha256=$null; DriftDetected=$false
    InstalledNow=$false; Actions=@(); Warnings=@(); StateWritten=$false; StatePath=$Options.StatePath
    PolicyBlocked=$false; ObservedDesiredSha256=$null; LastAppliedSha256=$null
  }
  return [pscustomobject]@{
    Ok=$true; NeedUpdate=$false; Installed=$false
    Lines=[Collections.Generic.List[string]]::new(); Actions=[Collections.Generic.List[string]]::new(); Warnings=[Collections.Generic.List[string]]::new()
    PolicyBlocked=$false; FatalError=$null; ExplicitExeHint=(-not [string]::IsNullOrWhiteSpace($Options.SysmonExePath))
    Summary=$summary; IsAdmin=$false; PreviewOnly=$false; Manifest=$null; MinEngineVersion=$null; AllowHashes=@()
    ConfigFile=$null; ConfigPath=$null; ConfigSnapshot=$null; ConfigHash=$null; ConfigValid=$false
    Exe=$null; ServiceName=$null; Engine=$null; PersistedState=$null; LastAppliedHash=$null; CurrentDumpSha256=$null
  }
}

function Initialize-SysmonUpdaterEntry {
  param($BoundParameters,[string]$Mode,[string]$OutputFormat,[string]$OutputPath,[bool]$PassThru,[bool]$Strict,[bool]$Quiet,[bool]$NoColor)
  $context = Initialize-V2Context -ScriptName '16-Sysmon-Config-Updater.ps1' -BoundParameters $BoundParameters -Values @{
    Mode=$Mode; ConfigPath=(Get-SysmonBoundValue $BoundParameters ConfigPath $null); OutputFormat=$OutputFormat; OutputPath=$OutputPath; PassThru=$PassThru
    Strict=$Strict; Quiet=$Quiet; NoColor=$NoColor; DeriveRemediate=$true
  }
  if ($context.Quiet) { $script:InformationPreference='SilentlyContinue'; $script:VerbosePreference='SilentlyContinue' }
  $script:NoColor = [bool]$context.NoColor
  $script:ErrorActionPreference = 'Stop'
  return $context
}

function Get-SysmonBoundValue($BoundParameters,[string]$Name,$Default) {
  if ($BoundParameters.ContainsKey($Name)) { return $BoundParameters[$Name] }
  return $Default
}

function New-SysmonUpdaterOptions {
  param($BoundParameters,[string]$RequestedStatePath,$V2Context)
  $statePath = Get-SysmonStatePath -RequestedPath $RequestedStatePath -FileName 'config-updater-state.json'
  return [pscustomobject]@{
    ConfigPath=(Get-SysmonBoundValue $BoundParameters ConfigPath $null); SourceDir=(Get-SysmonBoundValue $BoundParameters SourceDir $null)
    ManifestPath=(Get-SysmonBoundValue $BoundParameters ManifestPath $null); SysmonExePath=(Get-SysmonBoundValue $BoundParameters SysmonExePath $null)
    EnsureChannel=[bool](Get-SysmonBoundValue $BoundParameters EnsureChannel $false); ChannelSizeMiB=[int](Get-SysmonBoundValue $BoundParameters ChannelSizeMiB 256); StatePath=$statePath
    ConfigPathFallback=(Get-SysmonBoundValue $BoundParameters ConfigPathFallback $null); MinEngine=(Get-SysmonBoundValue $BoundParameters MinEngine $null)
    ConfigNameHint=(Get-SysmonBoundValue $BoundParameters ConfigNameHint $null); NoConsoleSummary=[bool](Get-SysmonBoundValue $BoundParameters NoConsoleSummary $false)
    SanitizeConsoleOutput=[bool](Get-SysmonBoundValue $BoundParameters SanitizeConsoleOutput $false); NoColor=[bool]$V2Context.NoColor; Remediate=[bool]$V2Context.Remediate
  }
}

function New-SysmonUnsupportedSummary([string]$Mode) {
  return [pscustomobject]@{ ComputerName=$env:COMPUTERNAME; Timestamp=Get-Date; Mode=$Mode; Supported=$false; Notes=@('Skipped: this script is only supported on Windows hosts.') }
}

function Initialize-SysmonManifestPolicy {
  param($State,$Options)
  $State.Manifest = @{ MinEngine=$null; AllowedHashes=@(); Config=@{ File=$null } }
  if ($Options.ManifestPath) {
    $check = Test-ManifestPolicy -Path $Options.ManifestPath -SourceDirectory $Options.SourceDir
    if ($check.Valid) { $State.Manifest = $check.Manifest }
    else { Block-SysmonPolicy $State ('Manifest validation failed: ' + $check.Reason) }
  }
  Set-SysmonMinimumEnginePolicy $State $Options.MinEngine
  Set-SysmonAllowedHashPolicy $State
}
function Set-SysmonMinimumEnginePolicy($State,[string]$RequestedMinimum) {
  $minimum = $RequestedMinimum
  if (-not $minimum) { $minimum = Get-SysmonManifestMinimumEngine $State.Manifest }
  $State.Summary.MinEngineRequired = $minimum
  if ($minimum) { $State.MinEngineVersion = Parse-Version $minimum }
  if ($minimum -and -not $State.MinEngineVersion) { Block-SysmonPolicy $State 'MinEngine must be a version string.' }
}
function Get-SysmonManifestMinimumEngine($Manifest) {
  if (-not $Manifest) { return $null }
  $property = $Manifest.PSObject.Properties['MinEngine']
  if ($property) { return [string]$property.Value }
  return $null
}
function Set-SysmonAllowedHashPolicy($State) {
  if ($State.Manifest -and $State.Manifest.PSObject.Properties['AllowedHashes'] -and $State.Manifest.AllowedHashes) {
    $State.AllowHashes = @($State.Manifest.AllowedHashes | ForEach-Object { $_.ToString().ToLowerInvariant() })
  }
}

function Block-SysmonPolicy {
  param($State,[string]$Message)
  $State.PolicyBlocked = $true
  $State.Ok = $false
  [void]$State.Warnings.Add($Message)
}

function Select-SysmonUpdaterConfig {
  param($State,$Options)
  $State.ConfigFile = Select-ConfigFile -Path $Options.ConfigPath -Dir $Options.SourceDir -NameHint $Options.ConfigNameHint -Manifest $State.Manifest
  if (-not $State.ConfigFile) { $State.ConfigFile = Get-SysmonFallbackConfig $Options.ConfigPathFallback }
  if (-not $State.ConfigFile) { throw 'No config file found. Use -ConfigPath, -SourceDir or -ManifestPath.' }
  $State.ConfigPath = $State.ConfigFile.FullName
  $State.Summary.ConfigFile = $State.ConfigFile.Name
  $State.ConfigSnapshot = Get-ConfigSnapshot -Path $State.ConfigPath
  $State.ConfigHash = $State.ConfigSnapshot.Sha256
  $State.Summary.DesiredSha256 = $State.ConfigHash
  $State.Summary.ObservedDesiredSha256 = $State.ConfigHash
  $validation = Validate-ConfigXml $State.ConfigSnapshot.Bytes
  $State.ConfigValid = [bool]$validation[0]
  if (-not $State.ConfigValid) { throw ('Config XML invalid: ' + [string]$validation[1]) }
  [void]$State.Lines.Add(('Config: ' + $State.ConfigFile.Name + ' (SHA256=' + $State.ConfigHash + '; ' + [string]$validation[1] + ')'))
  if ($State.AllowHashes.Count -gt 0 -and $State.AllowHashes -notcontains $State.ConfigHash) { Block-SysmonPolicy $State 'Config SHA256 not in allowlist.' }
}
function Get-SysmonFallbackConfig([string]$Path) {
  if (-not $Path) { return $null }
  if (Test-Path -LiteralPath $Path) { return Get-Item -LiteralPath $Path }
  return $null
}

function Test-SysmonExecutablePolicy {
  param($State,$Options)
  if ($State.PolicyBlocked) { $State.Summary.PolicyBlocked = $true; return }
  $State.Exe = Resolve-SysmonExe -Hint $Options.SysmonExePath
  $State.ServiceName = Get-SysmonServiceName
  $State.Engine = Get-SysmonEngineVersion -Exe $State.Exe
  Update-SysmonEngineSummary $State
  Add-SysmonDetectionLine $State
  if ($State.ExplicitExeHint -and -not $State.Exe) { Block-SysmonPolicy $State 'Explicit SysmonExePath did not pass trusted executable validation; service discovery fallback was refused.' }
  if ($State.Exe -and -not (Test-TrustedSysmonExecutable -Path $State.Exe)) { Block-SysmonPolicy $State 'Sysmon executable did not pass trusted executable validation; process execution was blocked.' }
  Test-SysmonMinimumEngine $State
  $State.Summary.PolicyBlocked = $State.PolicyBlocked
}

function Update-SysmonEngineSummary($State) {
  $State.Summary.SysmonExe = $State.Exe
  $State.Summary.SysmonService = $State.ServiceName
  if ($State.Engine) { $State.Summary.EngineVersion = $State.Engine.Raw }
}

function Add-SysmonDetectionLine($State) {
  $exeLabel = $(if ($State.Exe) { $State.Exe } else { 'n/a' })
  if ($State.ServiceName) {
    $engineLabel = $(if ($State.Engine) { $State.Engine.Raw } else { 'n/a' })
    [void]$State.Lines.Add("Sysmon: Service=$($State.ServiceName), Exe='$exeLabel', Engine=$engineLabel")
  } else { [void]$State.Lines.Add("Sysmon: Service not installed (Exe=$exeLabel)") }
}

function Test-SysmonMinimumEngine($State) {
  if (-not $State.MinEngineVersion) { return }
  if (-not $State.Engine) { Block-SysmonPolicy $State ('Cannot determine engine version; minimum required=' + $State.MinEngineVersion.Raw); return }
  if ((Cmp-Ver $State.Engine $State.MinEngineVersion) -lt 0) { Block-SysmonPolicy $State ('Engine below minimum: Installed=' + $State.Engine.Raw + ' Required=' + $State.MinEngineVersion.Raw) }
}

function Read-SysmonUpdaterState {
  param($State,$Options)
  $default = @{ Version=2; Observed=@{ DesiredSha256=$null }; Applied=@{ Sha256=$null }; Runtime=@{ CurrentDumpSha256=$null } }
  $State.PersistedState = Load-JsonOrDefault -Path $Options.StatePath -DefaultObject $default
  $persisted = $State.PersistedState
  $State.LastAppliedHash = Get-SysmonLastAppliedHash $persisted
  if (-not $State.LastAppliedHash -and (Test-LegacySysmonState $persisted)) { [void]$State.Warnings.Add('Legacy state did not distinguish observed from successfully applied configuration; forcing one safe reapply.') }
  $State.Summary.PrevDesiredSha256 = $State.LastAppliedHash
  $State.Summary.LastAppliedSha256 = $State.LastAppliedHash
  if ($State.LastAppliedHash -ne $State.ConfigHash) { $State.NeedUpdate = $true }
}
function Get-SysmonLastAppliedHash($State) {
  if (-not $State) { return $null }
  $applied = $State.PSObject.Properties['Applied']
  if (-not $applied -or -not $applied.Value) { return $null }
  $hash = $applied.Value.PSObject.Properties['Sha256']
  if ($hash) { return [string]$hash.Value }
  return $null
}
function Test-LegacySysmonState($State) {
  if (-not $State) { return $false }
  $config = $State.PSObject.Properties['Config']
  if (-not $config -or -not $config.Value) { return $false }
  $hash = $config.Value.PSObject.Properties['Sha256']
  return [bool]($hash -and $hash.Value)
}

function Test-SysmonRuntimeDrift {
  param($State)
  if (-not (Test-SysmonRuntimeProbeAllowed $State)) { return }
  if ($State.ExplicitExeHint) { [void]$State.Warnings.Add('Runtime config dump skipped for explicitly supplied SysmonExePath.'); return }
  if ($State.PreviewOnly) { [void]$State.Warnings.Add('Runtime config dump skipped in WhatIf mode.'); return }
  $State.CurrentDumpSha256 = Get-SysmonCurrentConfigSha256 -Exe $State.Exe
  $State.Summary.CurrentDumpSha256 = $State.CurrentDumpSha256
  if (-not $State.CurrentDumpSha256) { [void]$State.Warnings.Add('Could not compute runtime config dump hash.'); return }
  $previous = Get-SysmonPreviousDumpHash $State.PersistedState
  if ($previous -and $previous -ne $State.CurrentDumpSha256) {
    $State.NeedUpdate = $true
    [void]$State.Warnings.Add('Runtime drift: current dump hash differs from last recorded.')
  }
}
function Test-SysmonRuntimeProbeAllowed($State) { return [bool]($State.ServiceName -and $State.Exe -and -not $State.PolicyBlocked) }
function Get-SysmonPreviousDumpHash($State) {
  if (-not $State) { return $null }
  $runtime = $State.PSObject.Properties['Runtime']
  if (-not $runtime -or -not $runtime.Value) { return $null }
  $hash = $runtime.Value.PSObject.Properties['CurrentDumpSha256']
  if ($hash) { return [string]$hash.Value }
  return $null
}

function Test-SysmonChannelPolicy {
  param($State,$Options,$CommandContext)
  if (-not $Options.EnsureChannel -or $State.PolicyBlocked) { return }
  $doIt = $Options.Remediate -and $State.IsAdmin
  $result = Ensure-SysmonChannel -DoIt:$doIt -MiB $Options.ChannelSizeMiB -Cmdlet $CommandContext
  if (-not [bool]$result[0]) { $State.Ok = $false; [void]$State.Warnings.Add('Channel not compliant: ' + [string]$result[1]); return }
  if ([string]$result[1]) { [void]$State.Actions.Add('Channel: ' + [string]$result[1]) }
}

function Test-SysmonRemediationExecutable {
  param($State,$Options)
  if (-not $Options.Remediate -or -not $State.IsAdmin -or $State.PolicyBlocked) { return }
  if (-not $State.Exe -or -not (Test-TrustedSysmonExecutable -Path $State.Exe)) {
    Block-SysmonPolicy $State 'Sysmon executable did not pass trusted executable validation.'
    $State.Summary.PolicyBlocked = $true
  }
}

function Invoke-SysmonRemediation {
  param($State,$Options,$CommandContext)
  if (-not $Options.Remediate -or -not $State.IsAdmin -or $State.PolicyBlocked) { return }
  if (-not $State.ServiceName) { Install-SysmonConfiguration $State $CommandContext }
  elseif ($State.NeedUpdate) { Update-SysmonConfiguration $State $CommandContext }
  Refresh-SysmonRuntimeState $State $Options
}

function Install-SysmonConfiguration {
  param($State,$CommandContext)
  if (-not $State.Exe) { $State.Ok = $false; throw 'Sysmon not installed and SysmonExePath not provided/found.' }
  $result = Invoke-SysmonConfigurationApply $State $CommandContext @('-accepteula','-i') 'Install Sysmon with staged configuration'
  if ($result.Success) {
    $State.Installed = $true; [void]$State.Actions.Add('Installed Sysmon'); Complete-SysmonConfigApply $State
  } elseif ($result.Skipped) {
    $State.Ok = $false; $State.NeedUpdate = $true; [void]$State.Warnings.Add('Install skipped by ShouldProcess.')
  } else { $State.Ok = $false; [void]$State.Warnings.Add('Install failed: ' + $result.Reason) }
}

function Update-SysmonConfiguration {
  param($State,$CommandContext)
  $result = Invoke-SysmonConfigurationApply $State $CommandContext @('-accepteula','-c') 'Update Sysmon with staged configuration'
  if ($result.Success) { [void]$State.Actions.Add('Applied config update'); Complete-SysmonConfigApply $State }
  elseif ($result.Skipped) { $State.Ok = $false; [void]$State.Warnings.Add('Update skipped by ShouldProcess.') }
  else { $State.Ok = $false; [void]$State.Warnings.Add('Update failed: ' + $result.Reason) }
}

function Invoke-SysmonConfigurationApply {
  param($State,$CommandContext,[string[]]$Arguments,[string]$Operation)
  if (-not $CommandContext.ShouldProcess($State.Exe,$Operation)) { return [pscustomobject]@{ Success=$false; Skipped=$true; Reason=$null } }
  $stage = $null
  try {
    $stage = New-StagedConfigFile -Bytes $State.ConfigSnapshot.Bytes
    Assert-SysmonConfigSnapshotHash $State
    $native = Invoke-StagedSysmonCommand -Exe $State.Exe -Arguments @($Arguments + $stage.Path)
    if (Test-SysmonNativeApplySuccess $native) { return [pscustomobject]@{ Success=$true; Skipped=$false; Reason=$null } }
    return [pscustomobject]@{ Success=$false; Skipped=$false; Reason=(Get-SysmonNativeFailureReason $native) }
  } catch { return [pscustomobject]@{ Success=$false; Skipped=$false; Reason=$_.Exception.Message } }
  finally { if ($stage) { $stage.Stream.Dispose(); Remove-Item -LiteralPath $stage.Path -Force -ErrorAction SilentlyContinue } }
}
function Assert-SysmonConfigSnapshotHash($State) {
  if ((Get-BytesSha256 -Bytes $State.ConfigSnapshot.Bytes) -ne $State.ConfigHash) { throw 'Config snapshot hash changed before apply.' }
}
function Test-SysmonNativeApplySuccess($Result) {
  if (-not $Result) { return $false }
  if (-not $Result.Success) { return $false }
  if ($Result.TimedOut) { return $false }
  if ($Result.OutputTruncated) { return $false }
  return -not $Result.StderrTruncated
}

function Get-SysmonNativeFailureReason($NativeResult) {
  if (-not $NativeResult) { return 'native command did not return a result' }
  if ($NativeResult.TimedOut) { return 'timed out' }
  if ($NativeResult.OutputTruncated -or $NativeResult.StderrTruncated) { return 'output was truncated' }
  return 'exitcode=' + $NativeResult.ExitCode
}

function Complete-SysmonConfigApply($State) {
  $State.NeedUpdate = $false
  $State.LastAppliedHash = $State.ConfigHash
  $State.Summary.LastAppliedSha256 = $State.LastAppliedHash
}

function Refresh-SysmonRuntimeState($State,$Options) {
  $State.Exe = Resolve-SysmonExe -Hint $Options.SysmonExePath
  $State.ServiceName = Get-SysmonServiceName
  $State.Engine = Get-SysmonEngineVersion -Exe $State.Exe
  if ($State.ServiceName -and $State.Exe -and -not $State.PreviewOnly -and -not $State.ExplicitExeHint) { $State.CurrentDumpSha256 = Get-SysmonCurrentConfigSha256 -Exe $State.Exe }
  $State.Summary.CurrentDumpSha256 = $State.CurrentDumpSha256
  Update-SysmonEngineSummary $State
}

function Save-SysmonUpdaterState {
  param($State,$Options)
  $source = Get-SysmonConfigSourceLabel $Options
  $engineVersion = $(if ($State.Engine) { $State.Engine.Raw } else { $null })
  $newState = @{
    Version=2; Time=(Get-Date).ToString('s'); Host=$env:COMPUTERNAME
    Engine=@{ Version=$engineVersion; ExePath=$State.Exe; Service=$State.ServiceName }
    Observed=@{ Path=$State.ConfigPath; DesiredSha256=$State.ConfigHash; Source=$source; Valid=$State.ConfigValid }
    Applied=@{ Sha256=$State.LastAppliedHash }; Runtime=@{ CurrentDumpSha256=$State.CurrentDumpSha256 }
  }
  $written = $false
  if (-not $State.PolicyBlocked -and $Options.StatePath) { $written = Write-State -p $Options.StatePath -obj $newState }
  $State.Summary.StateWritten = [bool]$written
  if ($written) { [void]$State.Actions.Add('State updated') }
  else { [void]$State.Warnings.Add('State not written (StatePath not set or write failed).') }
}

function Get-SysmonConfigSourceLabel($Options) {
  if ($Options.ManifestPath) { return 'manifest:[configured path]' }
  if ($Options.SourceDir) { return 'dir:[configured path]' }
  return 'file:[configured path]'
}

function Complete-SysmonUpdaterRun {
  param($State,$Options)
  $State.Summary.InstalledNow = $State.Installed
  Add-SysmonAuditDriftWarning $State $Options.Remediate
  $State.Summary.DriftDetected = $State.NeedUpdate
  if ($State.Warnings.Count -gt 0) { [void]$State.Lines.Add('Warnings: ' + (@($State.Warnings) -join ' | ')) }
  if ($State.Actions.Count -gt 0) { [void]$State.Lines.Add('Actions: ' + (@($State.Actions) -join '; ')) }
  $eventId = $(if ($State.Ok) { 4700 } else { 4710 })
  $level = $(if ($State.Ok) { 'Information' } else { 'Warning' })
  Write-HealthEvent $eventId (@($State.Lines) -join "`r`n") $level
  $State.Summary.Ok = $State.Ok
  $State.Summary.Actions = @($State.Actions)
  $State.Summary.Warnings = @($State.Warnings)
}
function Add-SysmonAuditDriftWarning($State,[bool]$Remediate) {
  if (-not $State.NeedUpdate -or $Remediate) { return }
  $State.Ok = $false
  $previous = $(if ($State.LastAppliedHash) { $State.LastAppliedHash } else { 'n/a' })
  [void]$State.Warnings.Add("Drift detected: desired SHA256=$($State.ConfigHash), last applied=$previous")
}

function Invoke-SysmonUpdaterPhases {
  param($State,$Options,$CommandContext)
  $State.IsAdmin = Test-IsAdmin
  $State.Summary.IsAdmin = $State.IsAdmin
  $State.PreviewOnly = $Options.Remediate -and [bool]$WhatIfPreference
  if ($Options.Remediate -and -not $State.IsAdmin) { $State.Ok = $false; [void]$State.Warnings.Add('Remediate requested but not elevated.') }
  Initialize-SysmonManifestPolicy $State $Options
  Select-SysmonUpdaterConfig $State $Options
  Test-SysmonExecutablePolicy $State $Options
  Read-SysmonUpdaterState $State $Options
  Test-SysmonRuntimeDrift $State
  Test-SysmonChannelPolicy $State $Options $CommandContext
  Test-SysmonRemediationExecutable $State $Options
  Invoke-SysmonRemediation $State $Options $CommandContext
  Save-SysmonUpdaterState $State $Options
  Complete-SysmonUpdaterRun $State $Options
}

function Invoke-SysmonUpdater {
  param($State,$Options,$CommandContext)
  if (-not (Ensure-EventSource)) { Write-Warning 'EventSource could not be registered. EventLog tracing will be unavailable.' }
  try { Invoke-SysmonUpdaterPhases $State $Options $CommandContext }
  catch {
    $State.FatalError = $_.Exception.Message
    $State.Ok = $false; $State.Summary.Ok = $false
    [void]$State.Warnings.Add('Fatal: ' + $State.FatalError)
    $State.Summary.Warnings = @($State.Warnings)
    Write-HealthEvent 4710 ('Sysmon Config Updater: error ' + $State.FatalError) Error
  } finally {
    if (-not $Options.NoConsoleSummary) {
      $pretty = Get-SysmonConsoleSummary $State.Summary $Options.SanitizeConsoleOutput
      Write-PrettySummary -Summary $pretty -ChannelSizeMiB $Options.ChannelSizeMiB -Sanitize:$false -NoColor:$Options.NoColor
    }
  }
}

function Get-SysmonConsoleSummary($Summary,[bool]$Sanitize) {
  if (-not $Sanitize) { return $Summary }
  $copy = @{}
  foreach ($key in $Summary.Keys) { $copy[$key] = ConvertTo-SanitizedSysmonValue $Summary[$key] }
  return $copy
}

function ConvertTo-SanitizedSysmonValue($Value) {
  if ($Value -is [string]) { return Sanitize-Text $Value }
  if ($Value -isnot [Collections.IEnumerable]) { return $Value }
  $items = [Collections.Generic.List[object]]::new()
  foreach ($item in $Value) { if ($item -is [string]) { [void]$items.Add((Sanitize-Text $item)) } else { [void]$items.Add($item) } }
  return $items.ToArray()
}

function Add-SysmonCanonicalFindings {
  param([string[]]$Warnings)
  foreach ($warning in @($Warnings)) {
    $classification = Get-SysmonFindingClassification $warning
    $null = Add-Finding -FindingList $script:Findings -Code $classification.Code -Severity $classification.Severity -Message $warning
  }
}

function Get-SysmonFindingClassification([string]$Warning) {
  $code = 'SYSMON-Warning'; $severity = 'Medium'
  foreach ($rule in @(
      @{ Pattern='allowlist';Code='SYSMON-AllowlistFail';Severity='High' }, @{ Pattern='Engine below';Code='SYSMON-EngineOld';Severity='High' },
      @{ Pattern='^Fatal:';Code='SYSMON-Fatal';Severity='High' }, @{ Pattern='Manifest validation failed|MinEngine must';Code='SYSMON-PolicyInvalid';Severity='High' },
      @{ Pattern='drift';Code='SYSMON-Drift';Severity='Medium' }, @{ Pattern='Install|Update';Code='SYSMON-ApplyFail';Severity='High' },
      @{ Pattern='Channel';Code='SYSMON-Channel';Severity='Low' },
      @{ Pattern='Channel not compliant: .*resize failed';Code='Sysmon-ChannelResizeFailed';Severity='Medium' },
      @{ Pattern='Channel not compliant: .*enable failed';Code='Sysmon-ChannelEnableFailed';Severity='Medium' },
      @{ Pattern='not elevated';Code='SYSMON-NoAdmin';Severity='Medium' }
    )) { if ($Warning -match $rule.Pattern) { $code=$rule.Code; $severity=$rule.Severity } }
  return [pscustomobject]@{ Code=$code; Severity=$severity }
}

function Get-SysmonUpdaterResultToken {
  param($State,[bool]$Strict)
  if ($State.FatalError -or $State.PolicyBlocked) { return 'FAIL' }
  $hasIssues = Test-SysmonRunHasIssues $State
  if ($Strict -and $hasIssues) { return 'FAIL' }
  if ($hasIssues) { return 'WARN' }
  return 'OK'
}
function Test-SysmonRunHasIssues($State) {
  if ($script:Findings.Count -gt 0) { return $true }
  return -not $State.Ok
}
