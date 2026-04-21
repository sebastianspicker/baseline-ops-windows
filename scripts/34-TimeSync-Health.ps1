#requires -version 5.1
<#
.SYNOPSIS
Audit Windows Time Service (w32time): service state, time source, sync health indicators, and configuration.

.DESCRIPTION
Collects service status and w32tm outputs (/query /source, /status /verbose, /configuration), evaluates health indicators,
creates structured findings, and optionally exports CSV + raw TXT dumps.

Best-practice goals (PowerShell 5.1, 2025):
- Pipeline output: structured objects only (Export-Csv / ConvertTo-Json / Where-Object safe).
- Console output: all formatting via Write-UiLine / Write-Information only (no formatting objects on the pipeline).
- StrictMode-safe counting patterns (.Count pitfalls). [web:92]

.PARAMETER ExportPath
Base path/filename for export. Example: C:\Temp\TimeHealth.csv -> _summary.csv/_findings.csv and _*.txt.

.PARAMETER AutoStartService
Attempts to start w32time if not running (may require admin rights).

.PARAMETER ConfigJsonPath
Optional JSON file path (e.g. PATH/TO/JSON\TimeSyncHealth.json). If missing/invalid, defaults apply.

.PARAMETER NoConsoleSummary
Suppresses pretty console summary (pipeline output still returned).


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
One object: Summary, Findings, Raw, ConfigUsed, ConfigMeta.
.EXAMPLE
  .\34-TimeSync-Health.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$ExportPath,
  [switch]$AutoStartService,
  [string]$ConfigJsonPath,
  [switch]$NoConsoleSummary

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
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
# v2-init
$null = $Mode, $ConfigPath, $OutputFormat, $OutputPath, $PassThru, $Strict, $Quiet, $NoColor
$script:__V2Context = @{
  Mode = $Mode
  ConfigPath = $ConfigPath
  OutputFormat = $OutputFormat
  OutputPath = $OutputPath
  PassThru = [bool]$PassThru
  Strict = [bool]$Strict
  Quiet = [bool]$Quiet
  NoColor = [bool]$NoColor
}
if ($PSBoundParameters.ContainsKey('Mode')) {
  if (Get-Variable -Name Remediate -ErrorAction SilentlyContinue) {
    Set-Variable -Name Remediate -Scope Script -Value ($Mode -eq 'Remediate')
  }
}
if ($Quiet) {
  $InformationPreference = 'SilentlyContinue'
  $VerbosePreference = 'SilentlyContinue'
}
if ($NoColor) {
  $script:NoColor = $true
}
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
  $result = New-V2ResultObject -ScriptName '34-TimeSync-Health.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

# ----------------------------
# Helpers
# ----------------------------

function Ensure-Exe {
  param([Parameter(Mandatory)][string]$Name)
  if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
    throw "Executable not found: $Name"
  }
}

function Invoke-NativeCommandSoft {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$FilePath,
    [Parameter(Mandatory)][string[]]$Arguments
  )

  $text = (& $FilePath @Arguments 2>&1 | Out-String).Trim()
  $exit = $LASTEXITCODE

  [pscustomobject]@{
    FilePath  = $FilePath
    Arguments = ($Arguments -join ' ')
    ExitCode  = $exit
    Text      = $text
  }
}

function Parse-W32tmField {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Text,
    [Parameter(Mandatory)][string]$FieldName
  )

  if (-not $Text) { return $null }
  $m = [regex]::Match($Text, "(?m)^\s*$([regex]::Escape($FieldName))\s*:\s*(.+?)\s*$")
  if ($m.Success) { return $m.Groups[1].Value.Trim() }
  $null
}

function Parse-SecondsValue {
  [CmdletBinding()]
  param([string]$ValueText)

  if (-not $ValueText) { return $null }
  $m = [regex]::Match($ValueText, '([-+]?\d+(?:\.\d+)?)\s*s', 'IgnoreCase')
  if ($m.Success) { return [double]$m.Groups[1].Value }
  $null
}

function Get-DefaultConfig {
  [pscustomobject]@{
    Thresholds = [pscustomobject]@{
      RootDispersionSecondsWarn = 5.0
      PhaseOffsetSecondsWarn    = 1.0
    }
    Behavior = [pscustomobject]@{
      TreatW32tmFailureAsHighFinding     = $true
      AlwaysRunW32tmEvenIfServiceStopped = $false
    }
    Console = [pscustomobject]@{
      UseWriteInformation = $false
    }
  }
}

function Load-Config {
  [CmdletBinding()]
  param([string]$Path)

  $result = [pscustomobject]@{
    Config     = (Get-DefaultConfig)
    LoadState  = 'DefaultUsed'  # DefaultUsed | Loaded
    LoadDetail = $null
  }

  if (-not $Path) {
    $result.LoadDetail = 'No JSON config path provided.'
    return $result
  }

  if (-not (Test-Path -LiteralPath $Path)) {
    $result.LoadDetail = 'JSON config not found at PATH/TO/JSON.'
    return $result
  }

  try {
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop
    $obj = $raw | ConvertFrom-Json -ErrorAction Stop
  } catch {
    $result.LoadDetail = 'JSON config could not be loaded/parsed; using defaults.'
    return $result
  }

  try {
    if ($null -ne $obj.Thresholds.RootDispersionSecondsWarn) {
      $result.Config.Thresholds.RootDispersionSecondsWarn = [double]$obj.Thresholds.RootDispersionSecondsWarn
    }
    if ($null -ne $obj.Thresholds.PhaseOffsetSecondsWarn) {
      $result.Config.Thresholds.PhaseOffsetSecondsWarn = [double]$obj.Thresholds.PhaseOffsetSecondsWarn
    }
    if ($null -ne $obj.Behavior.TreatW32tmFailureAsHighFinding) {
      $result.Config.Behavior.TreatW32tmFailureAsHighFinding = [bool]$obj.Behavior.TreatW32tmFailureAsHighFinding
    }
    if ($null -ne $obj.Behavior.AlwaysRunW32tmEvenIfServiceStopped) {
      $result.Config.Behavior.AlwaysRunW32tmEvenIfServiceStopped = [bool]$obj.Behavior.AlwaysRunW32tmEvenIfServiceStopped
    }
    if ($null -ne $obj.Console.UseWriteInformation) {
      $result.Config.Console.UseWriteInformation = [bool]$obj.Console.UseWriteInformation
    }
  } catch {
    $result.LoadDetail = 'JSON config contained invalid values; using defaults.'
    return $result
  }

  $result.LoadState  = 'Loaded'
  $result.LoadDetail = 'JSON config loaded successfully from PATH/TO/JSON.'
  return $result
}

function Get-CountSafe {
  param($Value)
  @($Value).Count
}

function Get-OutputFolderAndBase {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$ExportPath)

  $folder = Split-Path -Path $ExportPath -Parent
  if (-not $folder) { $folder = (Get-Location).Path }

  [pscustomobject]@{
    Folder = $folder
    Base   = [IO.Path]::GetFileNameWithoutExtension($ExportPath)
  }
}



# Write-ConsoleSummary imported from lib/Console.psm1

# ----------------------------
# Main
# ----------------------------

Ensure-Exe -Name 'w32tm.exe'

$script:Findings = New-FindingsList

$configLoad = Load-Config -Path $ConfigJsonPath
$ConfigUsed = $configLoad.Config

if ($configLoad.LoadState -eq 'Loaded') {
  Add-Finding -FindingList $script:Findings -Code 'CFG-Loaded' -Severity 'Low' -Message $configLoad.LoadDetail -Extra @{ Data = 'PATH/TO/JSON' }
} else {
  Add-Finding -FindingList $script:Findings -Code 'CFG-DefaultUsed' -Severity 'Low' -Message $configLoad.LoadDetail -Extra @{ Data = 'PATH/TO/JSON' }
}

$svc = Get-Service -Name 'w32time' -ErrorAction Stop
if ($svc.Status -ne 'Running') {
  Add-Finding -FindingList $script:Findings -Code 'TIME-ServiceNotRunning' -Severity 'High' -Message ("w32time service is {0}." -f $svc.Status)

  if ($AutoStartService) {
    try {
      if ($PSCmdlet.ShouldProcess('w32time', 'Start service')) {
        Start-Service -Name 'w32time' -ErrorAction Stop
        $svc = Get-Service -Name 'w32time' -ErrorAction Stop

        if ($svc.Status -eq 'Running') {
          Add-Finding -FindingList $script:Findings -Code 'TIME-ServiceAutoStarted' -Severity 'Low' -Message 'w32time service was started automatically (AutoStartService).'
        } else {
          Add-Finding -FindingList $script:Findings -Code 'TIME-ServiceStartFailed' -Severity 'High' -Message ("Start-Service executed but service is still {0}." -f $svc.Status)
        }
      }
    } catch {
      Add-Finding -FindingList $script:Findings -Code 'TIME-ServiceStartException' -Severity 'High' -Message ("Start-Service w32time failed: {0}" -f $_.Exception.Message)
    }
  }
}

$regParams    = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
$regNtpClient = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient'

$typeValue        = Get-RegValue -Path $regParams -Name 'Type'
$ntpServerValue   = Get-RegValue -Path $regParams -Name 'NtpServer'
$ntpClientEnabled = Get-RegValue -Path $regNtpClient -Name 'Enabled'

if ($typeValue -eq 'NoSync') {
  Add-Finding -FindingList $script:Findings -Code 'TIME-TypeNoSync' -Severity 'High' -Message 'Registry Type=NoSync: time service will not synchronize.'
}
if ($typeValue -eq 'NTP' -and -not $ntpServerValue) {
  Add-Finding -FindingList $script:Findings -Code 'TIME-TypeNtpButNoServer' -Severity 'Medium' -Message 'Registry Type=NTP but NtpServer is empty/unreadable.'
}
if ($null -ne $ntpClientEnabled -and [int]$ntpClientEnabled -eq 0) {
  Add-Finding -FindingList $script:Findings -Code 'TIME-NtpClientDisabled' -Severity 'High' -Message 'NtpClient provider is disabled (TimeProviders\\NtpClient\\Enabled=0).'
}

$srcText  = $null
$statText = $null
$cfgText  = $null

$shouldRunW32tm = ($svc.Status -eq 'Running') -or $ConfigUsed.Behavior.AlwaysRunW32tmEvenIfServiceStopped

if ($shouldRunW32tm) {
  $srcR  = Invoke-NativeCommandSoft -FilePath 'w32tm.exe' -Arguments @('/query','/source')
  $statR = Invoke-NativeCommandSoft -FilePath 'w32tm.exe' -Arguments @('/query','/status','/verbose')
  $cfgR  = Invoke-NativeCommandSoft -FilePath 'w32tm.exe' -Arguments @('/query','/configuration')

  $srcText  = $srcR.Text
  $statText = $statR.Text
  $cfgText  = $cfgR.Text

  foreach ($r in @($srcR, $statR, $cfgR)) {
    if ($r.ExitCode -ne 0) {
      $sev = if ($ConfigUsed.Behavior.TreatW32tmFailureAsHighFinding) { 'High' } else { 'Medium' }
      Add-Finding -FindingList $script:Findings -Code 'TIME-W32tmCommandFailed' -Severity $sev -Message ("w32tm failed: {0} {1} (ExitCode={2})." -f $r.FilePath, $r.Arguments, $r.ExitCode) -Extra @{ Data = $r.Text }
    }
  }

  if ($srcText -and ($srcText -match 'Free-running System Clock')) {
    Add-Finding -FindingList $script:Findings -Code 'TIME-FreeRunning' -Severity 'High' -Message 'Time source is "Free-running System Clock" (no NTP/domain sync).'
  }

  if ($statText -and ($statText -match '(?m)^\s*Leap Indicator\s*:\s*3\b')) {
    Add-Finding -FindingList $script:Findings -Code 'TIME-LeapUnsync' -Severity 'High' -Message 'Leap Indicator = 3 (not synchronized).'
  }

  $lastSyncError = Parse-W32tmField -Text $statText -FieldName 'Last Sync Error'
  if ($lastSyncError -and ($lastSyncError -notmatch '^\s*0\s*\(')) {
    Add-Finding -FindingList $script:Findings -Code 'TIME-LastSyncError' -Severity 'Medium' -Message ("Last Sync Error is non-zero: {0}" -f $lastSyncError)
  }

  $phaseOffsetText    = Parse-W32tmField -Text $statText -FieldName 'Phase Offset'
  $rootDispersionText = Parse-W32tmField -Text $statText -FieldName 'Root Dispersion'

  $phaseOffsetSec    = Parse-SecondsValue -ValueText $phaseOffsetText
  $rootDispersionSec = Parse-SecondsValue -ValueText $rootDispersionText

  if ($null -ne $rootDispersionSec -and $rootDispersionSec -ge $ConfigUsed.Thresholds.RootDispersionSecondsWarn) {
    Add-Finding -FindingList $script:Findings -Code 'TIME-RootDispersionHigh' -Severity 'Medium' -Message ("Root Dispersion is high ({0}s >= {1}s)." -f $rootDispersionSec, $ConfigUsed.Thresholds.RootDispersionSecondsWarn)
  }

  if ($null -ne $phaseOffsetSec -and ([math]::Abs($phaseOffsetSec) -ge $ConfigUsed.Thresholds.PhaseOffsetSecondsWarn)) {
    Add-Finding -FindingList $script:Findings -Code 'TIME-PhaseOffsetHigh' -Severity 'Medium' -Message ("Phase Offset is high ({0}s >= {1}s)." -f ([math]::Abs($phaseOffsetSec)), $ConfigUsed.Thresholds.PhaseOffsetSecondsWarn)
  }
} else {
  Add-Finding -FindingList $script:Findings -Code 'TIME-W32tmSkipped' -Severity 'Medium' -Message 'w32tm queries skipped because w32time is not running.'
}

$Findings = @($script:Findings.ToArray())
$findingsCount = Get-CountSafe $Findings

$result = [pscustomobject]@{
  Summary = [pscustomobject]@{
    ComputerName        = $env:COMPUTERNAME
    Timestamp           = Get-Date
    W32TimeServiceState = $svc.Status
    Type                = $typeValue
    NtpServer           = $ntpServerValue
    NtpClientEnabled    = $ntpClientEnabled
    Source              = $srcText
    FindingsCount       = $findingsCount
  }
  Findings   = $Findings
  Raw        = [pscustomobject]@{
    SourceText        = $srcText
    StatusVerboseText = $statText
    ConfigText        = $cfgText
  }
  ConfigUsed = $ConfigUsed
  ConfigMeta = [pscustomobject]@{
    LoadState  = $configLoad.LoadState
    LoadDetail = $configLoad.LoadDetail
  }
}

if ($ExportPath) {
  $out = Get-OutputFolderAndBase -ExportPath $ExportPath
  if (-not (Test-Path -LiteralPath $out.Folder)) {
    New-Item -Path $out.Folder -ItemType Directory -Force | Out-Null
  }

  $result.Summary  | Export-Csv -Path (Join-Path $out.Folder ($out.Base + "_summary.csv"))  -NoTypeInformation -Encoding UTF8
  $result.Findings | Export-Csv -Path (Join-Path $out.Folder ($out.Base + "_findings.csv")) -NoTypeInformation -Encoding UTF8

  if ($result.Raw.SourceText)        { Set-Content -Path (Join-Path $out.Folder ($out.Base + "_source.txt")) -Value $result.Raw.SourceText        -Encoding UTF8 }
  if ($result.Raw.StatusVerboseText) { Set-Content -Path (Join-Path $out.Folder ($out.Base + "_status.txt")) -Value $result.Raw.StatusVerboseText -Encoding UTF8 }
  if ($result.Raw.ConfigText)        { Set-Content -Path (Join-Path $out.Folder ($out.Base + "_config.txt")) -Value $result.Raw.ConfigText        -Encoding UTF8 }
}

if (-not $NoConsoleSummary) {
  $healthLabel = if (($Findings | Where-Object { $_.Severity -eq 'High' }).Count -gt 0) { 'ATTENTION REQUIRED' }
    elseif (($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count -gt 0) { 'WARNINGS' }
    else { 'OK' }

  $customFields = [ordered]@{
    'W32Time'    = [string]$result.Summary.W32TimeServiceState
    'Source'     = $(if ($result.Summary.Source) { $result.Summary.Source } else { '<n/a>' })
    'Type'       = $(if ($result.Summary.Type) { $result.Summary.Type } else { '<n/a>' })
    'NtpServer'  = $(if ($result.Summary.NtpServer) { $result.Summary.NtpServer } else { '<n/a>' })
    'ConfigLoad' = $result.ConfigMeta.LoadState
    'Health'     = $healthLabel
  }

  $findingsAL = [System.Collections.ArrayList]@($Findings)
  Write-ConsoleSummary -Summary $result.Summary -Findings $findingsAL `
    -Title 'TimeSync Health Summary' `
    -CustomFields $customFields
}

$resultToken = if ($Strict -and $findingsCount -gt 0) { 'FAIL' } elseif ($findingsCount -gt 0) { 'WARN' } else { 'OK' }
$v2Result = New-V2ResultObject -ScriptName '34-TimeSync-Health.ps1' -Mode $Mode -Result $resultToken -Findings $Findings -Summary $result.Summary -Metadata @{ Raw = $result.Raw; ConfigUsed = $result.ConfigUsed; ConfigMeta = $result.ConfigMeta }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
