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
  If the JSON file is missing or invalid, the script continues with built-in defaults.

  Output streams are separated by design:
  - Console: human-friendly status, separators, and colored messages are written via Write-UiLine or Write-Information.
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
  - When -Force is NOT used, the script reads a registry key for a Request flag.
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
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force

Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
Initialize-V2Context -ScriptName '09-SupportBundle.ps1' -BoundParameters $PSBoundParameters
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
  $result = Get-V2ResultObject -ScriptName '09-SupportBundle.ps1' -Mode $Mode -Result 'WARN' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 2
}

# -------------------- Defaults (anonymized) --------------------
$DefaultConfigPath = if ([string]::IsNullOrWhiteSpace($ConfigPath)) { Join-Path $PSScriptRoot 'support-bundle.json' } else { $ConfigPath }
$DefaultProofDir   = Join-Path ([System.IO.Path]::GetTempPath()) 'win-mdm-support-bundles'
$DefaultKbFeedPath = Join-Path $PSScriptRoot 'kb-feed.json'

# Registry trigger (anonymized)
$FlagKey     = 'HKLM:\SOFTWARE\Company\Product\SupportBundle'
$EventSource = 'SupportBundle'

# -------------------- Console UI (no pipeline output) --------------------
. (Join-Path $PSScriptRoot 'internal/09-SupportBundle.helpers.ps1')

# -------------------- Event log (best effort) --------------------
function SB_IsWindowsPlatform {
  [CmdletBinding()]
  param()

  if ($PSVersionTable.PSEdition -eq 'Core') { return [bool]$IsWindows }
  return $true
}

function SB_EnsureEventSource {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param()
  if (-not (SB_IsWindowsPlatform)) {
    return (SB_NewRecord -Name 'EventSource' -Ok $true -ArtifactPath $null -Note 'Skipped on non-Windows test host' -Error $null)
  }

  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
      if ($PSCmdlet.ShouldProcess($EventSource, 'Register SupportBundle event source')) {
        New-EventLog -LogName Application -Source $EventSource -ErrorAction Stop | Out-Null
      } else {
        return (SB_NewRecord -Name 'EventSource' -Ok $true -ArtifactPath $null -Note 'Skipped by ShouldProcess' -Error $null)
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

try {
  if (-not $Force) {
    $t = SB_GetRegistryTrigger -KeyPath $FlagKey

    if (-not $t.Ok) {
      $m = "SupportBundle not started: Registry trigger missing/invalid ({0}). Use -Force to run anyway." -f $t.Error
      SB_WriteHealthEvent -Id 8110 -Msg $m -Level 'Warning'
      SB_WriteLog -Level 'WARN' -Message $m
      SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Trigger' -Ok $false -ArtifactPath $null -Note $null -Error $t.Error)
      return
    }

    if ($t.Request -ne 1) {
      $m = "SupportBundle not started: Request flag not set (expected: $FlagKey/Request=1). Use -Force to run anyway."
      SB_WriteHealthEvent -Id 8110 -Msg $m -Level 'Warning'
      SB_WriteLog -Level 'WARN' -Message $m
      SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Trigger' -Ok $false -ArtifactPath $null -Note $null -Error 'Request flag not set')
      return
    }

    if (-not $PSBoundParameters.ContainsKey('Days') -and $t.Days) { $Days = [int]$t.Days }
    if (-not $PSBoundParameters.ContainsKey('IncludeSecurity') -and $t.IncludeSecurity -eq 1) { $IncludeSecurity = $true }
    if (-not $PSBoundParameters.ContainsKey('IncludeDefenderSupport') -and $t.IncludeDefenderSupport -eq 1) { $IncludeDefenderSupport = $true }
    if (-not $PSBoundParameters.ContainsKey('Reason') -and $t.Reason) { $Reason = [string]$t.Reason }

    $Summary.DaysBack   = $Days
    $Summary.IncludeSec = [bool]$IncludeSecurity
    $Summary.IncludeDef = [bool]$IncludeDefenderSupport
    $Summary.Reason     = $Reason
  }

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
  $Config        = SB_LoadJsonConfig -Path $ConfigPath -DefaultConfig $DefaultConfig
  $ProofDir      = [string]$Config.Paths.ProofDir
  Assert-NoPathTraversal -Path $ProofDir -ParameterName 'Config.Paths.ProofDir'

  $Summary.ConfigPath = $ConfigPath
  $Summary.ProofDir   = $ProofDir

  if (-not [string]::IsNullOrWhiteSpace($ConfigPath) -and (Test-Path -LiteralPath $ConfigPath)) {
    SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Config' -Ok $true -ArtifactPath $ConfigPath -Note 'Config loaded' -Error $null)
  } else {
    SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Config' -Ok $true -ArtifactPath $null -Note "Config not found, using defaults: $ConfigPath" -Error $null)
  }

  $bundleDir = Join-Path $ProofDir 'support'
  $ts        = (Get-Date).ToString('yyyyMMdd-HHmmss')
  $workDir   = Join-Path $bundleDir $ts
  $zipPath   = Join-Path $bundleDir ("SupportBundle-{0}-{1}.zip" -f $ComputerName, $ts)

  [void](Ensure-Directory -Path $workDir)
  $Summary.WorkDir = $workDir
  $Summary.ZipPath = $zipPath

  $proofDest = Join-Path $workDir 'proofs'
  $proofCandidates = @(
    $Config.ProofOutFiles.SysmonState,
    $Config.ProofOutFiles.SysmonDriftState,
    $Config.ProofOutFiles.SoftwareInventory,
    $Config.ProofOutFiles.FirewallAudit,
    $Config.ProofOutFiles.HardwareAudit
  ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

  foreach ($p in $proofCandidates) {
    Assert-NoPathTraversal -Path $p -ParameterName 'Config.ProofOutFiles'
    SB_AddRecord -Summary $Summary -Record (SB_CopyIfExists -Path $p -DestDir $proofDest)
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
    SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Bundle:Zip' -Ok $true -ArtifactPath $zipPath -Note $null -Error $null)
  } catch {
    SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Bundle:Zip' -Ok $false -ArtifactPath $zipPath -Note $null -Error $_.Exception.Message)
  }

  $sidecarSummaryPath = $zipPath + '.summary.json'
  try {
    SB_SaveJsonFile -Path $sidecarSummaryPath -Object $Summary
    SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Bundle:SidecarSummaryJson' -Ok $true -ArtifactPath $sidecarSummaryPath -Note $null -Error $null)
  } catch {
    SB_AddRecord -Summary $Summary -Record (SB_NewRecord -Name 'Bundle:SidecarSummaryJson' -Ok $false -ArtifactPath $sidecarSummaryPath -Note $null -Error $_.Exception.Message)
  }

  SB_AddRecord -Summary $Summary -Record (SB_ResetRegistryTrigger -KeyPath $FlagKey -ZipPath $zipPath)

  $hasErrors = @($Summary.Records | Where-Object { -not $_.Ok }).Count -gt 0
  if ($hasErrors) {
    SB_WriteHealthEvent -Id 8110 -Msg ("SupportBundle finished with warnings/errors. ZIP: {0}" -f $zipPath) -Level 'Warning'
  } else {
    SB_WriteHealthEvent -Id 8100 -Msg ("SupportBundle successfully created. ZIP: {0}" -f $zipPath) -Level 'Information'
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
$zipRecord = @($records | Where-Object { $_.Name -eq 'Bundle:Zip' })[-1]
$zipCreated = [bool]($zipRecord -and $zipRecord.Ok)

$Summary | Add-Member -NotePropertyName RecordsOk -NotePropertyValue $recordsOk.Count -Force
$Summary | Add-Member -NotePropertyName RecordsFailed -NotePropertyValue $recordsFailed.Count -Force
$Summary | Add-Member -NotePropertyName ZipCreated -NotePropertyValue $zipCreated -Force

$resultToken = if (-not $zipCreated) { 'FAIL' } elseif ($recordsFailed.Count -gt 0) { 'WARN' } else { 'OK' }
$findings = @($recordsFailed | ForEach-Object { SB_NewRecordFinding -Record $_ })
$v2Result = Get-V2ResultObject -ScriptName '09-SupportBundle.ps1' -Mode $Mode -Result $resultToken -Findings $findings -Summary $Summary -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
if ($resultToken -eq 'FAIL') { exit 1 }
if ($resultToken -eq 'WARN') { exit 2 }
exit 0
