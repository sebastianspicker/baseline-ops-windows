#requires -version 5.1
<#
.SYNOPSIS
  Generates a timestamped support bundle (ZIP) that collects system diagnostics, selected Windows event logs, optional proof files, and optional Microsoft Defender information.

.DESCRIPTION
  This script is designed to create a single “support bundle” artifact for troubleshooting and incident triage.
  It builds a working directory under a configurable proof root, exports logs and reports into subfolders, writes a structured summary (JSON), and compresses everything into a ZIP file.

  The script supports two execution modes:
  - Triggered mode (default): runs only if a registry “Request” flag is set; this is intended for controlled/remote triggering.
  - Forced mode (-Force): bypasses the registry trigger and always runs.

  Configuration is optionally loaded from a JSON file.
  If the implicit JSON file is missing or invalid, the script continues with built-in defaults.
  An explicitly supplied invalid configuration fails closed.

  Output streams are separated by design:
  - Console: status, separators, and colored messages are written via Write-UiLine or Write-Information.
  - Pipeline: only structured objects are emitted, and only when -EmitObject is specified (enables clean Export-Csv/ConvertTo-Json/Where-Object usage).

.PARAMETER Force
  Bypasses the registry trigger and runs the bundle creation immediately.
  Use this for interactive troubleshooting or when the registry trigger mechanism is not used.

.PARAMETER Days
  Number of days to include when exporting event logs.
  The script attempts to export only events newer than the specified window.

.PARAMETER IncludeSecurity
  Includes the Security event log in the export list.
  This typically requires elevated execution; if not elevated, the script records a note and skips Security.

.PARAMETER IncludeDefenderSupport
  Collects additional Microsoft Defender diagnostics.
  This can include a Defender support CAB (if available) and Defender status/preference outputs.

.PARAMETER Reason
  Optional free-text reason for why the bundle was collected.
  The value is stored in the summary object and summary JSON for traceability.

.PARAMETER EmitObject
  When set, emits exactly one structured summary object to the pipeline at the end of the run.
  If not set (default), nothing is emitted to the pipeline (console-only run).

.PARAMETER UseInformationStream
  When set, writes console UI to the Information stream instead of using Write-UiLine.
  This can be useful if the calling environment wants to suppress/capture informational UI separately.


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER ConfigPath
  Path to JSON configuration file.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER PassThru
  Emit structured v2 result object to pipeline.

.PARAMETER Strict
  Treat warnings as failures.

.PARAMETER Quiet
  Suppress console output.

.PARAMETER NoColor
  Disable colored output.

.OUTPUTS
  By default, the script writes no objects to the pipeline.

  If -EmitObject is specified:
  - System.Management.Automation.PSCustomObject (Summary)
    Properties include:
    - Hostname, Time, User, Admin
    - DaysBack, IncludeSec, IncludeDef
    - ConfigPath, ProofDir, Reason
    - WorkDir, ZipPath
    - Records (array of step results with Name/Ok/ArtifactPath/Note/Error/Time)

.NOTES
  Registry trigger behavior:
  - When -Force is NOT used, the script reads
    HKLM:\SOFTWARE\BaselineOps\SupportBundle for a Request flag.
  - If Request is not set, the script exits early and still prints a console summary.
  - When a bundle is successfully created, the script attempts to reset the trigger flag and writes last bundle metadata.

  Bundle layout (high level):
  - <WorkDir>\eventlogs\        Exported .evtx and/or fallback .csv/.txt logs
  - <WorkDir>\reports\          Text and JSON reports (e.g., systeminfo, ipconfig, hotfix list)
  - <WorkDir>\proofs\           Copies of configured proof artifacts if paths exist
  - <WorkDir>\defender\         Defender status/preference (if available)
  - <WorkDir>\defender-support\ Defender support CAB (optional)
  - <WorkDir>\Summary.json      Structured summary saved inside the bundle

  Error handling:
  - Individual collection steps are recorded as success/failure records.
  - The script always attempts to print a final console summary (best effort), even if some steps fail.

.EXAMPLE
  # Default triggered execution (runs only if registry Request flag is set)
  .\09-SupportBundle.ps1

.EXAMPLE
  # Force execution (bypass registry trigger)
  .\09-SupportBundle.ps1 -Force

.EXAMPLE
  # Collect last 3 days of logs and include Security log (requires elevation)
  .\09-SupportBundle.ps1 -Force -Days 3 -IncludeSecurity

.EXAMPLE
  # Collect bundle including Defender diagnostics and emit a structured summary object
  $summary = .\09-SupportBundle.ps1 -Force -IncludeDefenderSupport -EmitObject
  $summary.Records | Where-Object { -not $_.Ok } | Export-Csv .\SupportBundleErrors.csv -NoTypeInformation

.EXAMPLE
  # Emit summary as JSON for automation pipelines
  .\09-SupportBundle.ps1 -Force -EmitObject | ConvertTo-Json -Depth 10

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [switch]$Force,

  [ValidateRange(1,365)]
  [int]$Days = 7,

  [switch]$IncludeSecurity,
  [switch]$IncludeDefenderSupport,

  [string]$Reason,

  # Interactive default: do not emit objects unless requested.
  [switch]$EmitObject,

  # Optional: write UI to information stream instead of host.
  [switch]$UseInformationStream

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [string]$ConfigPath,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
. (Join-Path $PSScriptRoot 'internal/09-SupportBundle.helpers.ps1')

Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '09-SupportBundle.ps1' -BoundParameters $PSBoundParameters `
  -Mode $Mode -ConfigPath $ConfigPath -OutputFormat $OutputFormat -OutputPath $OutputPath `
  -PassThru:$PassThru -Strict:$Strict -Quiet:$Quiet -NoColor:$NoColor
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '09-SupportBundle.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# -------------------- Defaults (anonymized) --------------------
$ConfigPathWasExplicit = $PSBoundParameters.ContainsKey('ConfigPath')
$DefaultConfigPath = if (-not $ConfigPathWasExplicit) { Join-Path $PSScriptRoot 'support-bundle.json' } else { $ConfigPath }
$DefaultProofDir   = SB_GetDefaultTrustedOutputRoot
$DefaultKbFeedPath = Join-Path $PSScriptRoot 'kb-feed.json'

# Registry trigger
$FlagKey     = 'HKLM:\SOFTWARE\BaselineOps\SupportBundle'
$EventSource = 'SupportBundle'

# -------------------- Event log (best effort) --------------------

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

function SB_TestBundleArchive {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ZipPath,
    [Parameter(Mandatory)][string]$TrustedRoot
  )

  $archive = $null
  try {
    if (-not (Test-Path -LiteralPath $ZipPath -PathType Leaf)) { throw 'Archive was not created as a regular file.' }
    $item = Get-Item -LiteralPath $ZipPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or $item.Length -le 0) { throw 'Archive must be a non-empty regular non-reparse file.' }
    $root = (Resolve-Path -LiteralPath $TrustedRoot -ErrorAction Stop).Path
    $resolved = (Resolve-Path -LiteralPath $ZipPath -ErrorAction Stop).Path
    if (-not (Test-PathUnderRoot -Path $resolved -Root $root) -or (Test-PathContainsReparsePoint -Path $resolved -Root $root)) { throw 'Archive is outside the trusted output root or traverses a reparse point.' }
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


# -------------------- Main --------------------
$IsAdminNow   = Test-IsAdmin
$ComputerName = $env:COMPUTERNAME

SB_WriteLog -Message ("SupportBundle starting (Days={0}, Force={1}, IncludeSecurity={2}, IncludeDefenderSupport={3})." -f $Days, $Force, $IncludeSecurity, $IncludeDefenderSupport) -Level 'INFO'

# Initialize summary early so finally always works.
$Summary = SB_NewSummary -ComputerName $ComputerName -IsAdminNow $IsAdminNow -DaysBack $Days `
  -IncludeSec ([bool]$IncludeSecurity) -IncludeDef ([bool]$IncludeDefenderSupport) `
  -ConfigPath $DefaultConfigPath -ProofDir $DefaultProofDir -ReasonText $Reason
SB_AddRecord -Summary $Summary -Record (SB_EnsureEventSource)

$collectRequested = $true
$triggerIdle = $false
try {
  if (-not $Force) {
    $t = SB_GetRegistryTrigger -KeyPath $FlagKey

    if (-not $t.Ok) {
      $m = "SupportBundle not started: Registry trigger missing/invalid ({0}). Use -Force to run anyway." -f $t.Error
      SB_WriteHealthEvent -Id 8110 -Msg $m -Level 'Warning'
      SB_WriteLog -Level 'WARN' -Message $m
      SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Trigger' -Ok $false -ArtifactPath $null -Note $null -Error $t.Error)
      $collectRequested = $false
    }

    else {
      [int]$requestValue = -1
      $requestValid = [int]::TryParse([string]$t.Request, [ref]$requestValue) -and $requestValue -in @(0, 1)
      if (-not $requestValid) {
        $m = "SupportBundle not started: Request flag is invalid (expected $FlagKey/Request=0 or 1). Use -Force to run anyway."
        SB_WriteHealthEvent -Id 8110 -Msg $m -Level 'Warning'
        SB_WriteLog -Level 'WARN' -Message $m
        SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Trigger' -Ok $false -ArtifactPath $null -Note $null -Error 'Request flag must be 0 or 1')
        $collectRequested = $false
      } elseif ($requestValue -eq 0) {
        $m = "SupportBundle idle: $FlagKey/Request=0; no collection was requested."
        SB_WriteLog -Level 'INFO' -Message $m
        SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Trigger' -Ok $true -ArtifactPath $null -Note 'Idle (Request=0); collection not requested' -Error $null)
        $triggerIdle = $true
        $collectRequested = $false
      }
    }

    if ($collectRequested) {
      if (-not $PSBoundParameters.ContainsKey('Days') -and $t.Days) { $Days = [int]$t.Days }
      if (-not $PSBoundParameters.ContainsKey('IncludeSecurity') -and $t.IncludeSecurity -eq 1) { $IncludeSecurity = $true }
      if (-not $PSBoundParameters.ContainsKey('IncludeDefenderSupport') -and $t.IncludeDefenderSupport -eq 1) { $IncludeDefenderSupport = $true }
      if (-not $PSBoundParameters.ContainsKey('Reason') -and $t.Reason) { $Reason = [string]$t.Reason }

      $Summary.DaysBack   = $Days
      $Summary.IncludeSec = [bool]$IncludeSecurity
      $Summary.IncludeDef = [bool]$IncludeDefenderSupport
      $Summary.Reason     = $Reason
    }
  }

  if ($collectRequested) {
  if ($IncludeSecurity -and -not $IsAdminNow) {
    $m = 'IncludeSecurity requested without admin rights; skipping Security event log.'
    SB_WriteHealthEvent -Id 8110 -Msg $m -Level 'Warning'
    SB_WriteLog -Level 'WARN' -Message $m
    $IncludeSecurity = $false
    $Summary.IncludeSec = $false
    SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'SecurityLog' -Ok $true -ArtifactPath $null -Note 'Skipped (not elevated)' -Error $null)
  }

  $DefaultConfig = SB_NewDefaultConfig -ProofDirDefault $DefaultProofDir
  $ConfigPath    = $DefaultConfigPath
  $configLoad    = SB_LoadJsonConfig -Path $ConfigPath -DefaultConfig $DefaultConfig -AllowDefaults:(-not $ConfigPathWasExplicit)
  if (-not $configLoad.Ok) {
    SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Config' -Ok $false -ArtifactPath $ConfigPath -Note 'Explicit configuration rejected' -Error $configLoad.Error)
    throw "Support bundle configuration rejected: $($configLoad.Error)"
  }
  $Config = $configLoad.Config
  $ProofDir = SB_AssertTrustedOutputRoot -Path $DefaultProofDir
  $configuredProofDir = [System.IO.Path]::GetFullPath([string]$Config.Paths.ProofDir)
  if (-not $configuredProofDir.Equals($ProofDir, [System.StringComparison]::OrdinalIgnoreCase)) {
    SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Config' -Ok $false -ArtifactPath $ConfigPath -Note 'Unsafe proof root rejected' -Error 'Config.Paths.ProofDir must equal the fixed trusted proof root.')
    throw 'Support bundle configuration rejected: unsafe proof root.'
  }

  $Summary.ConfigPath = $ConfigPath
  $Summary.ProofDir   = $ProofDir

  if (-not $configLoad.UsedDefault) {
    SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Config' -Ok $true -ArtifactPath $ConfigPath -Note 'Config loaded and schema validated' -Error $null)
  } else {
    SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Config' -Ok $true -ArtifactPath $null -Note "Implicit config unavailable or invalid; using defaults: $ConfigPath" -Error $null)
  }

  $bundleDir = SB_AssertTrustedChildDirectory -Path (Join-Path $ProofDir 'support') -TrustedRoot $ProofDir
  $runId     = "{0}-{1}" -f (Get-Date).ToString('yyyyMMdd-HHmmss'), [guid]::NewGuid().ToString('N')
  $workDir   = SB_AssertTrustedChildDirectory -Path (Join-Path $bundleDir $runId) -TrustedRoot $ProofDir
  $zipPath   = Join-Path $bundleDir ("SupportBundle-{0}-{1}.zip" -f $ComputerName, $runId)

  $Summary.WorkDir = $workDir
  $Summary.ZipPath = $null

  $proofDest = Join-Path $workDir 'proofs'
  $proofCandidates = @(
    @{ Name = 'SysmonState'; Expected = 'SysmonState.json' },
    @{ Name = 'SysmonDriftState'; Expected = 'SysmonDriftState.json' },
    @{ Name = 'SoftwareInventory'; Expected = 'SoftwareInventory.json' },
    @{ Name = 'FirewallAudit'; Expected = 'FirewallAudit.json' },
    @{ Name = 'HardwareAudit'; Expected = 'HardwareAudit.json' }
  )

  foreach ($proof in $proofCandidates) {
    $configuredPath = [string]$Config.ProofOutFiles.($proof.Name)
    if (-not [string]::IsNullOrWhiteSpace($configuredPath)) {
      $trustedPath = SB_ResolveTrustedProofFile -ConfiguredPath $configuredPath -TrustedRoot $ProofDir -ExpectedFileName $proof.Expected -PropertyName $proof.Name
      SB_AddRecord -Summary $Summary -Record (SB_CopyIfExists -Path $trustedPath -DestDir $proofDest)
    }
  }

  SB_AddRecord -Summary $Summary -Record (SB_ExportKbStatus -KbFeedPath $DefaultKbFeedPath -OutFile (Join-Path $workDir 'KBStatus.json'))

  $evDir = Join-Path $workDir 'eventlogs'
  [void](Ensure-Directory -Path $evDir)

  $logs = @(
    'Application',
    'System',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-CodeIntegrity/Operational',
    'Microsoft-Windows-AppLocker/EXE and DLL',
    'Microsoft-Windows-AppLocker/MSI and Script',
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-WindowsUpdateClient/Operational'
  )
  if ($IncludeSecurity) { $logs += 'Security' }

  foreach ($log in $logs) {
    if (-not (SB_TestEventLogExists -LogName $log)) {
      SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name ("EVTX:{0}" -f $log) -Ok $true -ArtifactPath $null -Note 'Event log not present (skip)' -Error $null)
      continue
    }

    $safe = Get-SafeFileName -Name $log
    $evtxOut = Join-Path $evDir ($safe + '.evtx')

    $r = SB_ExportEventLogEvtx -LogName $log -OutFile $evtxOut -DaysBack $Days
    SB_AddRecord -Summary $Summary -Record $r

    if (-not $r.Ok) {
      SB_AddRecord -Summary $Summary -Record (SB_ExportEventLogFallback -LogName $log -OutFileBase (Join-Path $evDir $safe) -DaysBack $Days)
    }
  }

  $repDir = Join-Path $workDir 'reports'
  $rep = SB_ExportSystemReports -OutDir $repDir
  foreach ($r in @($rep)) { SB_AddRecord -Summary $Summary -Record $r }

  $defDir = Join-Path $workDir 'defender'
  $def = SB_ExportDefenderStatus -OutDir $defDir
  foreach ($r in @($def)) { SB_AddRecord -Summary $Summary -Record $r }

  if ($IncludeDefenderSupport) {
    SB_AddRecord -Summary $Summary -Record (SB_NewDefenderSupportCab -OutDir (Join-Path $workDir 'defender-support'))
  }

  $summaryInBundle = Join-Path $workDir 'Summary.json'
  SB_SaveJsonFile -Path $summaryInBundle -Object $Summary
  SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Bundle:SummaryJson' -Ok $true -ArtifactPath $summaryInBundle -Note $null -Error $null)

  [void](Ensure-Directory -Path $bundleDir)
  if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue }
  try {
    Compress-Archive -Path (Join-Path $workDir '*') -DestinationPath $zipPath -Force
    $archiveValidation = SB_TestBundleArchive -ZipPath $zipPath -TrustedRoot $bundleDir
    if (-not $archiveValidation.Ok) { throw $archiveValidation.Error }
    $Summary.ZipPath = $archiveValidation.Path
    SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Bundle:Zip' -Ok $true -ArtifactPath $archiveValidation.Path -Note 'Archive integrity validated' -Error $null)
  } catch {
    $Summary.ZipPath = $null
    SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Bundle:Zip' -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }

  if ($Summary.ZipPath) {
    $sidecarSummaryPath = $Summary.ZipPath + '.summary.json'
    try {
      SB_SaveJsonFile -Path $sidecarSummaryPath -Object $Summary
      SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Bundle:SidecarSummaryJson' -Ok $true -ArtifactPath $sidecarSummaryPath -Note $null -Error $null)
    } catch {
      SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Bundle:SidecarSummaryJson' -Ok $false -ArtifactPath $sidecarSummaryPath -Note $null -Error $_.Exception.Message)
    }
  } else {
    SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Bundle:SidecarSummaryJson' -Ok $true -ArtifactPath $null -Note 'Skipped because no validated archive exists' -Error $null)
  }

  if ($Summary.ZipPath) {
    SB_AddRecord -Summary $Summary -Record (SB_ResetRegistryTrigger -KeyPath $FlagKey -ZipPath $Summary.ZipPath)
  } else {
    SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'RegistryReset' -Ok $true -ArtifactPath $null -Note 'Request left pending because no validated archive exists' -Error $null)
  }

  $hasErrors = @($Summary.Records | Where-Object { -not $_.Ok }).Count -gt 0
  if ($hasErrors) {
    SB_WriteHealthEvent -Id 8110 -Msg ("SupportBundle finished with warnings/errors. ZIP: {0}" -f $Summary.ZipPath) -Level 'Warning'
  } else {
    SB_WriteHealthEvent -Id 8100 -Msg ("SupportBundle successfully created. ZIP: {0}" -f $zipPath) -Level 'Information'
  }
  }
}
catch {
  if (-not (@($Summary.Records | Where-Object { $_.Name -eq 'Config' -and -not $_.Ok }))) {
    SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'SupportBundle' -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}
finally {
  # Must never throw: this is best-effort UI in finally.
  try { SB_ShowSummary -Summary $Summary } catch {
    Write-Verbose ("Support bundle summary display failed: {0}" -f $_.Exception.Message)
  }

}

# V2 output contract
$records = @($Summary.Records)
$recordsOk = @($records | Where-Object { $_.Ok })
$recordsFailed = @($records | Where-Object { -not $_.Ok })
$zipRecords = @($records | Where-Object { $_.Name -eq 'Bundle:Zip' })
$zipRecord = if ($zipRecords.Count -gt 0) { $zipRecords[$zipRecords.Count - 1] } else { $null }
$zipCreated = [bool]($zipRecord -and $zipRecord.Ok)

$Summary | Add-Member -NotePropertyName RecordsOk -NotePropertyValue $recordsOk.Count -Force
$Summary | Add-Member -NotePropertyName RecordsFailed -NotePropertyValue $recordsFailed.Count -Force
$Summary | Add-Member -NotePropertyName ZipCreated -NotePropertyValue $zipCreated -Force
$Summary | Add-Member -NotePropertyName CollectionRequested -NotePropertyValue (-not $triggerIdle -and $collectRequested) -Force
$Summary | Add-Member -NotePropertyName TriggerIdle -NotePropertyValue $triggerIdle -Force

$resultToken = if ($triggerIdle) {
  if ($recordsFailed.Count -gt 0) { 'WARN' } else { 'OK' }
} elseif (-not $zipCreated) { 'FAIL' } elseif ($recordsFailed.Count -gt 0) { 'WARN' } else { 'OK' }
$findings = @($recordsFailed | ForEach-Object { SB_NewRecordFinding -Record $_ })
$v2Result = Get-V2ResultObject -ScriptName '09-SupportBundle.ps1' -Mode $Mode -Result $resultToken -Findings $findings -Summary $Summary -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
