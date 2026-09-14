<#
.SYNOPSIS
Support bundle runtime helpers.

.DESCRIPTION
Coordinates capability-private trigger, archive, collection, and result behavior.
#>

function SB_EnsureEventSource {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param()
  if (-not (SB_IsWindowsPlatform)) {
    return (SB_NewRecord -Name 'EventSource' -Ok $true -ArtifactPath $null -Note 'Skipped on non-Windows test host' -Error $null)
  }

  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
      if (-not $PSCmdlet.ShouldProcess($EventSource, 'Register SupportBundle event source')) {
        return (SB_NewRecord -Name 'EventSource' -Ok $true -ArtifactPath $null -Note 'Skipped by ShouldProcess' -Error $null)
      }
      if (-not (Ensure-EventSource -LogName Application -Source $EventSource)) {
        throw 'Event source registration failed.'
      }
    }
    return (SB_NewRecord -Name 'EventSource' -Ok $true -ArtifactPath $null -Note 'Available' -Error $null)
  } catch {
    return (SB_NewRecord -Name 'EventSource' -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}

function SB_ResetRegistryTrigger {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param(
    [Parameter(Mandatory)][string]$KeyPath,
    [Parameter(Mandatory)][string]$ZipPath
  )

  if (-not (SB_IsWindowsPlatform)) {
    return (SB_NewRecord -Name 'RegistryReset' -Ok $true -ArtifactPath $null -Note 'Skipped on non-Windows test host' -Error $null)
  }

  try {
    if (-not $PSCmdlet.ShouldProcess($KeyPath, 'Reset support bundle trigger registry values')) {
      return (SB_NewRecord -Name 'RegistryReset' -Ok $true -ArtifactPath $null -Note 'Skipped by ShouldProcess' -Error $null)
    }
    New-Item -Path $KeyPath -Force | Out-Null
    New-ItemProperty -Path $KeyPath -Name 'Request'        -PropertyType DWord  -Value 0 -Force | Out-Null
    New-ItemProperty -Path $KeyPath -Name 'LastBundlePath' -PropertyType String -Value $ZipPath -Force | Out-Null
    New-ItemProperty -Path $KeyPath -Name 'LastBundleTime' -PropertyType String -Value ((Get-Date).ToString('s')) -Force | Out-Null
    return (SB_NewRecord -Name 'RegistryReset' -Ok $true -ArtifactPath $null -Note 'Registry updated' -Error $null)
  } catch {
    return (SB_NewRecord -Name 'RegistryReset' -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}

function SB_ResolveTrustedBundleArchive {
  param([string]$ZipPath, [string]$TrustedRoot)
  if (-not (Test-Path -LiteralPath $ZipPath -PathType Leaf)) { throw 'Archive was not created as a regular file.' }
  $item = Get-Item -LiteralPath $ZipPath -Force -ErrorAction Stop
  if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or $item.Length -le 0) {
    throw 'Archive must be a non-empty regular non-reparse file.'
  }
  $root = (Resolve-Path -LiteralPath $TrustedRoot -ErrorAction Stop).Path
  $resolved = (Resolve-Path -LiteralPath $ZipPath -ErrorAction Stop).Path
  if (-not (Test-PathUnderRoot -Path $resolved -Root $root) -or
      (Test-PathContainsReparsePoint -Path $resolved -Root $root)) {
    throw 'Archive is outside the trusted output root or traverses a reparse point.'
  }
  return $resolved
}

function SB_TestBundleArchive {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ZipPath,
    [Parameter(Mandatory)][string]$TrustedRoot
  )

  $archive = $null
  try {
    $resolved = SB_ResolveTrustedBundleArchive -ZipPath $ZipPath -TrustedRoot $TrustedRoot
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $archive = [System.IO.Compression.ZipFile]::OpenRead($resolved)
    if (-not (@($archive.Entries | Where-Object { $_.FullName -ieq 'Summary.json' }))) { throw 'Archive does not contain the expected Summary.json entry.' }
    return [pscustomobject]@{ Ok = $true; Path = $resolved; Error = $null }
  } catch {
    return [pscustomobject]@{ Ok = $false; Path = $null; Error = $_.Exception.Message }
  } finally {
    if ($null -ne $archive) { $archive.Dispose() }
  }
}

function Initialize-SupportBundleV2Context {
  param([hashtable]$BoundParameters)
  $script:__V2Context = Initialize-V2Context -ScriptName '09-SupportBundle.ps1' -BoundParameters $BoundParameters `
    -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
  if ($script:__V2Context.Quiet) { $script:InformationPreference = 'SilentlyContinue'; $script:VerbosePreference = 'SilentlyContinue' }
  $script:NoColor = [bool]$script:__V2Context.NoColor
  $script:ErrorActionPreference = 'Stop'
}

function New-SupportBundleUnsupportedResult {
  param([string]$ResultToken)
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp = Get-Date
    Mode = $Mode
    Supported = $false
    Notes = @('Skipped: this script is only supported on Windows hosts.')
  }
  return Get-V2ResultObject -ScriptName '09-SupportBundle.ps1' -Mode $Mode -Result $ResultToken `
    -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
}

function SB_NewRecordFinding {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Record
  )

  $recordName = [string]$Record.Name
  $severity = if ($recordName -eq 'Bundle:Zip') { 'High' } else { 'Medium' }
  [pscustomobject]@{
    Code         = 'SupportBundle-RecordFailed'
    Severity     = $severity
    Message      = "SupportBundle step failed: $recordName"
    RecordName   = $recordName
    Error        = [string]$Record.Error
    ArtifactPath = $Record.ArtifactPath
  }
}

function New-SupportBundleInputs {
  param($BoundParameters)
  $configExplicit = $BoundParameters.ContainsKey('ConfigPath')
  return @{
    Force = [bool]$Force
    Days = $Days
    IncludeSecurity = [bool]$IncludeSecurity
    IncludeDefenderSupport = [bool]$IncludeDefenderSupport
    Reason = $Reason
    ConfigPathExplicit = $configExplicit
    ConfigPath = if ($configExplicit) { $ConfigPath } else { Join-Path $PSScriptRoot 'support-bundle.json' }
    ProofDir = SB_GetDefaultTrustedOutputRoot
    KbFeedPath = Join-Path $PSScriptRoot 'kb-feed.json'
    FlagKey = 'HKLM:\SOFTWARE\BaselineOps\SupportBundle'
    BoundParameters = $BoundParameters
  }
}

function New-SupportBundleRunState {
  param([hashtable]$Inputs)
  $isAdmin = Test-IsAdmin
  $summary = SB_NewSummary -ComputerName $env:COMPUTERNAME -IsAdminNow $isAdmin -DaysBack $Inputs.Days `
    -IncludeSec $Inputs.IncludeSecurity -IncludeDef $Inputs.IncludeDefenderSupport `
    -ConfigPath $Inputs.ConfigPath -ProofDir $Inputs.ProofDir -ReasonText $Inputs.Reason
  return @{
    Inputs = $Inputs
    IsAdmin = $isAdmin
    ComputerName = $env:COMPUTERNAME
    Summary = $summary
    CollectRequested = $true
    TriggerIdle = $false
  }
}

function Add-SupportBundleTriggerFailure {
  param([hashtable]$RunState, [string]$Message, [string]$ErrorText)
  SB_WriteHealthEvent -Id 8110 -Msg $Message -Level Warning
  SB_WriteLog -Level WARN -Message $Message
  SB_AddRecord -Summary $RunState.Summary -Record (SB_NewRecord -Name Trigger -Ok $false `
    -ArtifactPath $null -Note $null -Error $ErrorText)
  $RunState.CollectRequested = $false
}

function Set-SupportBundleTriggerValues {
  param([hashtable]$RunState, $Trigger)
  $bound = $RunState.Inputs.BoundParameters
  if (-not $bound.ContainsKey('Days') -and $Trigger.Days) { $RunState.Inputs.Days = [int]$Trigger.Days }
  if (-not $bound.ContainsKey('Reason') -and $Trigger.Reason) { $RunState.Inputs.Reason = [string]$Trigger.Reason }
}

function Set-SupportBundleTriggerSwitches {
  param([hashtable]$RunState, $Trigger)
  $bound = $RunState.Inputs.BoundParameters
  if (-not $bound.ContainsKey('IncludeSecurity') -and $Trigger.IncludeSecurity -eq 1) { $RunState.Inputs.IncludeSecurity = $true }
  if (-not $bound.ContainsKey('IncludeDefenderSupport') -and $Trigger.IncludeDefenderSupport -eq 1) { $RunState.Inputs.IncludeDefenderSupport = $true }
}

function Set-SupportBundleTriggerInputs {
  param([hashtable]$RunState, $Trigger)
  Set-SupportBundleTriggerValues -RunState $RunState -Trigger $Trigger
  Set-SupportBundleTriggerSwitches -RunState $RunState -Trigger $Trigger
  $RunState.Summary.DaysBack = $RunState.Inputs.Days
  $RunState.Summary.IncludeSec = $RunState.Inputs.IncludeSecurity
  $RunState.Summary.IncludeDef = $RunState.Inputs.IncludeDefenderSupport
  $RunState.Summary.Reason = $RunState.Inputs.Reason
}

function Read-SupportBundleTrigger {
  param([hashtable]$RunState)
  if ($RunState.Inputs.Force) { return }
  $trigger = SB_GetRegistryTrigger -KeyPath $RunState.Inputs.FlagKey
  if (-not $trigger.Ok) {
    $message = "SupportBundle not started: Registry trigger missing/invalid ($($trigger.Error)). Use -Force to run anyway."
    Add-SupportBundleTriggerFailure -RunState $RunState -Message $message -ErrorText $trigger.Error
    return
  }
  [int]$requestValue = -1
  $requestValid = [int]::TryParse([string]$trigger.Request, [ref]$requestValue) -and $requestValue -in @(0, 1)
  if (-not $requestValid) {
    $message = "SupportBundle not started: Request flag is invalid (expected $($RunState.Inputs.FlagKey)/Request=0 or 1). Use -Force to run anyway."
    Add-SupportBundleTriggerFailure -RunState $RunState -Message $message -ErrorText 'Request flag must be 0 or 1'
    return
  }
  if ($requestValue -eq 0) {
    $message = "SupportBundle idle: $($RunState.Inputs.FlagKey)/Request=0; no collection was requested."
    SB_WriteLog -Level INFO -Message $message
    SB_AddRecord -Summary $RunState.Summary -Record (SB_NewRecord -Name Trigger -Ok $true -ArtifactPath $null `
      -Note 'Idle (Request=0); collection not requested' -Error $null)
    $RunState.TriggerIdle = $true
    $RunState.CollectRequested = $false
    return
  }
  Set-SupportBundleTriggerInputs -RunState $RunState -Trigger $trigger
}

function Disable-UnavailableSecurityCollection {
  param([hashtable]$RunState)
  if (-not $RunState.Inputs.IncludeSecurity -or $RunState.IsAdmin) { return }
  $message = 'IncludeSecurity requested without admin rights; skipping Security event log.'
  SB_WriteHealthEvent -Id 8110 -Msg $message -Level Warning
  SB_WriteLog -Level WARN -Message $message
  $RunState.Inputs.IncludeSecurity = $false
  $RunState.Summary.IncludeSec = $false
  SB_AddRecord -Summary $RunState.Summary -Record (SB_NewRecord -Name SecurityLog -Ok $true `
    -ArtifactPath $null -Note 'Skipped (not elevated)' -Error $null)
}

function Initialize-SupportBundleConfiguration {
  param([hashtable]$RunState)
  Disable-UnavailableSecurityCollection -RunState $RunState
  $defaults = SB_NewDefaultConfig -ProofDirDefault $RunState.Inputs.ProofDir
  $configLoad = SB_LoadJsonConfig -Path $RunState.Inputs.ConfigPath -DefaultConfig $defaults `
    -AllowDefaults:(-not $RunState.Inputs.ConfigPathExplicit)
  if (-not $configLoad.Ok) {
    SB_AddRecord -Summary $RunState.Summary -Record (SB_NewRecord -Name Config -Ok $false `
      -ArtifactPath $RunState.Inputs.ConfigPath -Note 'Explicit configuration rejected' -Error $configLoad.Error)
    throw "Support bundle configuration rejected: $($configLoad.Error)"
  }
  $RunState.Config = $configLoad.Config
  $RunState.ProofDir = SB_AssertTrustedOutputRoot -Path $RunState.Inputs.ProofDir
  $configuredProofDir = [System.IO.Path]::GetFullPath([string]$RunState.Config.Paths.ProofDir)
  if (-not $configuredProofDir.Equals($RunState.ProofDir, [System.StringComparison]::OrdinalIgnoreCase)) {
    SB_AddRecord -Summary $RunState.Summary -Record (SB_NewRecord -Name Config -Ok $false `
      -ArtifactPath $RunState.Inputs.ConfigPath -Note 'Unsafe proof root rejected' `
      -Error 'Config.Paths.ProofDir must equal the fixed trusted proof root.')
    throw 'Support bundle configuration rejected: unsafe proof root.'
  }
  $RunState.Summary.ConfigPath = $RunState.Inputs.ConfigPath
  $RunState.Summary.ProofDir = $RunState.ProofDir
  Add-SupportBundleConfigRecord -RunState $RunState -UsedDefault $configLoad.UsedDefault
  Initialize-SupportBundleDirectories -RunState $RunState
}

function Add-SupportBundleConfigRecord {
  param([hashtable]$RunState, [bool]$UsedDefault)
  if (-not $UsedDefault) {
    $record = SB_NewRecord -Name Config -Ok $true -ArtifactPath $RunState.Inputs.ConfigPath `
      -Note 'Config loaded and schema validated' -Error $null
  }
  else {
    $record = SB_NewRecord -Name Config -Ok $true -ArtifactPath $null `
      -Note "Implicit config unavailable or invalid; using defaults: $($RunState.Inputs.ConfigPath)" -Error $null
  }
  SB_AddRecord -Summary $RunState.Summary -Record $record
}

function Initialize-SupportBundleDirectories {
  param([hashtable]$RunState)
  $RunState.BundleDir = SB_AssertTrustedChildDirectory -Path (Join-Path $RunState.ProofDir support) `
    -TrustedRoot $RunState.ProofDir
  $RunState.RunId = '{0}-{1}' -f (Get-Date).ToString('yyyyMMdd-HHmmss'), [guid]::NewGuid().ToString('N')
  $RunState.WorkDir = SB_AssertTrustedChildDirectory -Path (Join-Path $RunState.BundleDir $RunState.RunId) `
    -TrustedRoot $RunState.ProofDir
  $RunState.ZipPath = Join-Path $RunState.BundleDir ("SupportBundle-{0}-{1}.zip" -f $RunState.ComputerName, $RunState.RunId)
  $RunState.Summary.WorkDir = $RunState.WorkDir
  $RunState.Summary.ZipPath = $null
}

function Copy-SupportBundleProofs {
  param([hashtable]$RunState)
  $destination = Join-Path $RunState.WorkDir proofs
  $candidates = @(
    @{ Name = 'SysmonState'; Expected = 'SysmonState.json' }
    @{ Name = 'SysmonDriftState'; Expected = 'SysmonDriftState.json' }
    @{ Name = 'SoftwareInventory'; Expected = 'SoftwareInventory.json' }
    @{ Name = 'FirewallAudit'; Expected = 'FirewallAudit.json' }
    @{ Name = 'HardwareAudit'; Expected = 'HardwareAudit.json' }
  )
  foreach ($proof in $candidates) {
    $configuredPath = [string]$RunState.Config.ProofOutFiles.($proof.Name)
    if ([string]::IsNullOrWhiteSpace($configuredPath)) { continue }
    $trustedPath = SB_ResolveTrustedProofFile -ConfiguredPath $configuredPath -TrustedRoot $RunState.ProofDir `
      -ExpectedFileName $proof.Expected -PropertyName $proof.Name
    SB_AddRecord -Summary $RunState.Summary -Record (SB_CopyIfExists -Path $trustedPath -DestDir $destination)
  }
}

function Export-SupportBundleEventLogs {
  param([hashtable]$RunState)
  $directory = Join-Path $RunState.WorkDir eventlogs
  [void](Ensure-Directory -Path $directory)
  $logs = @('Application', 'System', 'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-CodeIntegrity/Operational', 'Microsoft-Windows-AppLocker/EXE and DLL',
    'Microsoft-Windows-AppLocker/MSI and Script', 'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-WindowsUpdateClient/Operational')
  if ($RunState.Inputs.IncludeSecurity) { $logs += 'Security' }
  foreach ($log in $logs) { Export-SupportBundleEventLog -RunState $RunState -LogName $log -Directory $directory }
}

function Export-SupportBundleEventLog {
  param([hashtable]$RunState, [string]$LogName, [string]$Directory)
  if (-not (SB_TestEventLogExists -LogName $LogName)) {
    SB_AddRecord -Summary $RunState.Summary -Record (SB_NewRecord -Name "EVTX:$LogName" -Ok $true `
      -ArtifactPath $null -Note 'Event log not present (skip)' -Error $null)
    return
  }
  $safeName = Get-SafeFileName -Name $LogName
  $record = SB_ExportEventLogEvtx -LogName $LogName -OutFile (Join-Path $Directory "$safeName.evtx") `
    -DaysBack $RunState.Inputs.Days
  SB_AddRecord -Summary $RunState.Summary -Record $record
  if (-not $record.Ok) {
    SB_AddRecord -Summary $RunState.Summary -Record (SB_ExportEventLogFallback -LogName $LogName `
      -OutFileBase (Join-Path $Directory $safeName) -DaysBack $RunState.Inputs.Days)
  }
}

function Export-SupportBundleReports {
  param([hashtable]$RunState)
  SB_AddRecord -Summary $RunState.Summary -Record (SB_ExportKbStatus -KbFeedPath $RunState.Inputs.KbFeedPath `
    -OutFile (Join-Path $RunState.WorkDir 'KBStatus.json'))
  foreach ($record in @(SB_ExportSystemReports -OutDir (Join-Path $RunState.WorkDir reports))) {
    SB_AddRecord -Summary $RunState.Summary -Record $record
  }
  foreach ($record in @(SB_ExportDefenderStatus -OutDir (Join-Path $RunState.WorkDir defender))) {
    SB_AddRecord -Summary $RunState.Summary -Record $record
  }
  if ($RunState.Inputs.IncludeDefenderSupport) {
    SB_AddRecord -Summary $RunState.Summary -Record (SB_NewDefenderSupportCab `
      -OutDir (Join-Path $RunState.WorkDir 'defender-support'))
  }
}

function New-SupportBundleArchive {
  param([hashtable]$RunState)
  $summaryPath = Join-Path $RunState.WorkDir 'Summary.json'
  SB_SaveJsonFile -Path $summaryPath -Object $RunState.Summary
  SB_AddRecord -Summary $RunState.Summary -Record (SB_NewRecord -Name 'Bundle:SummaryJson' -Ok $true `
    -ArtifactPath $summaryPath -Note $null -Error $null)
  [void](Ensure-Directory -Path $RunState.BundleDir)
  if (Test-Path -LiteralPath $RunState.ZipPath) {
    Remove-Item -LiteralPath $RunState.ZipPath -Force -ErrorAction SilentlyContinue
  }
  try {
    Compress-Archive -Path (Join-Path $RunState.WorkDir '*') -DestinationPath $RunState.ZipPath -Force
    $validation = SB_TestBundleArchive -ZipPath $RunState.ZipPath -TrustedRoot $RunState.BundleDir
    if (-not $validation.Ok) { throw $validation.Error }
    $RunState.Summary.ZipPath = $validation.Path
    $record = SB_NewRecord -Name 'Bundle:Zip' -Ok $true -ArtifactPath $validation.Path `
      -Note 'Archive integrity validated' -Error $null
  }
  catch {
    $RunState.Summary.ZipPath = $null
    $record = SB_NewRecord -Name 'Bundle:Zip' -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message
  }
  SB_AddRecord -Summary $RunState.Summary -Record $record
}

function Save-SupportBundleSidecar {
  param([hashtable]$RunState)
  if (-not $RunState.Summary.ZipPath) {
    SB_AddRecord -Summary $RunState.Summary -Record (SB_NewRecord -Name 'Bundle:SidecarSummaryJson' -Ok $true `
      -ArtifactPath $null -Note 'Skipped because no validated archive exists' -Error $null)
    return
  }
  $path = $RunState.Summary.ZipPath + '.summary.json'
  try {
    SB_SaveJsonFile -Path $path -Object $RunState.Summary
    $record = SB_NewRecord -Name 'Bundle:SidecarSummaryJson' -Ok $true -ArtifactPath $path -Note $null -Error $null
  }
  catch {
    $record = SB_NewRecord -Name 'Bundle:SidecarSummaryJson' -Ok $false -ArtifactPath $path -Note $null -Error $_.Exception.Message
  }
  SB_AddRecord -Summary $RunState.Summary -Record $record
}

function Complete-SupportBundleCollection {
  param([hashtable]$RunState)
  Save-SupportBundleSidecar -RunState $RunState
  if ($RunState.Summary.ZipPath) {
    $record = SB_ResetRegistryTrigger -KeyPath $RunState.Inputs.FlagKey -ZipPath $RunState.Summary.ZipPath
  }
  else {
    $record = SB_NewRecord -Name RegistryReset -Ok $true -ArtifactPath $null `
      -Note 'Request left pending because no validated archive exists' -Error $null
  }
  SB_AddRecord -Summary $RunState.Summary -Record $record
  $hasErrors = @($RunState.Summary.Records | Where-Object { -not $_.Ok }).Count -gt 0
  if ($hasErrors) {
    SB_WriteHealthEvent -Id 8110 -Msg "SupportBundle finished with warnings/errors. ZIP: $($RunState.Summary.ZipPath)" -Level Warning
  }
  else {
    SB_WriteHealthEvent -Id 8100 -Msg "SupportBundle successfully created. ZIP: $($RunState.ZipPath)" -Level Information
  }
}

function Invoke-SupportBundleCollection {
  param([hashtable]$RunState)
  Initialize-SupportBundleConfiguration -RunState $RunState
  Copy-SupportBundleProofs -RunState $RunState
  Export-SupportBundleEventLogs -RunState $RunState
  Export-SupportBundleReports -RunState $RunState
  New-SupportBundleArchive -RunState $RunState
  Complete-SupportBundleCollection -RunState $RunState
}

function Add-SupportBundleUnhandledError {
  param([hashtable]$RunState, $ErrorRecord)
  $existing = @($RunState.Summary.Records | Where-Object { $_.Name -eq 'Config' -and -not $_.Ok })
  if ($existing.Count -eq 0) {
    SB_AddRecord -Summary $RunState.Summary -Record (SB_NewRecord -Name SupportBundle -Ok $false `
      -ArtifactPath $null -Note $null -Error $ErrorRecord.Exception.Message)
  }
}

function Invoke-SupportBundle {
  param([hashtable]$RunState)
  SB_WriteLog -Message ("SupportBundle starting (Days={0}, Force={1}, IncludeSecurity={2}, IncludeDefenderSupport={3})." -f `
      $RunState.Inputs.Days, $RunState.Inputs.Force, $RunState.Inputs.IncludeSecurity, $RunState.Inputs.IncludeDefenderSupport) -Level INFO
  SB_AddRecord -Summary $RunState.Summary -Record (SB_EnsureEventSource)
  try {
    Read-SupportBundleTrigger -RunState $RunState
    if ($RunState.CollectRequested) { Invoke-SupportBundleCollection -RunState $RunState }
  }
  catch { Add-SupportBundleUnhandledError -RunState $RunState -ErrorRecord $_ }
  finally {
    try { SB_ShowSummary -Summary $RunState.Summary }
    catch { Write-Verbose ("Support bundle summary display failed: {0}" -f $_.Exception.Message) }
  }
}

function Invoke-NewSupportBundleRun {
  param([hashtable]$BoundParameters)
  $inputs = New-SupportBundleInputs -BoundParameters $BoundParameters
  $runState = New-SupportBundleRunState -Inputs $inputs
  Invoke-SupportBundle -RunState $runState
  Complete-SupportBundleResult -RunState $runState
  return $runState
}

function Get-SupportBundleResultToken {
  param([bool]$TriggerIdle, [bool]$ZipCreated, [int]$FailedCount)
  if ($TriggerIdle) {
    if ($FailedCount -gt 0) { return 'WARN' }
    return 'OK'
  }
  if (-not $ZipCreated) { return 'FAIL' }
  if ($FailedCount -gt 0) { return 'WARN' }
  return 'OK'
}

function Complete-SupportBundleResult {
  param([hashtable]$RunState)
  $records = @($RunState.Summary.Records)
  $okRecords = @($records | Where-Object { $_.Ok })
  $failedRecords = @($records | Where-Object { -not $_.Ok })
  $zipRecords = @($records | Where-Object Name -eq 'Bundle:Zip')
  $zipRecord = if ($zipRecords.Count -gt 0) { $zipRecords[$zipRecords.Count - 1] } else { $null }
  $zipCreated = [bool]($zipRecord -and $zipRecord.Ok)
  $RunState.Summary | Add-Member -NotePropertyName RecordsOk -NotePropertyValue $okRecords.Count -Force
  $RunState.Summary | Add-Member -NotePropertyName RecordsFailed -NotePropertyValue $failedRecords.Count -Force
  $RunState.Summary | Add-Member -NotePropertyName ZipCreated -NotePropertyValue $zipCreated -Force
  $RunState.Summary | Add-Member -NotePropertyName CollectionRequested `
    -NotePropertyValue (-not $RunState.TriggerIdle -and $RunState.CollectRequested) -Force
  $RunState.Summary | Add-Member -NotePropertyName TriggerIdle -NotePropertyValue $RunState.TriggerIdle -Force
  $RunState.FailedRecords = $failedRecords
  $RunState.ResultToken = Get-SupportBundleResultToken -TriggerIdle $RunState.TriggerIdle `
    -ZipCreated $zipCreated -FailedCount $failedRecords.Count
}
