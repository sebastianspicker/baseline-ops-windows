#requires -version 5.1
<#
.SYNOPSIS
WEF client readiness audit (Windows PowerShell 5.1).

.DESCRIPTION
Best-practice output model:
- Pipeline: structured objects only (safe for Export-Csv / ConvertTo-Json / Where-Object).
- Console: pretty human-readable output via Write-UiLine / Write-Information only.

Checks:
- WinRM service status and start mode.
- SubscriptionManager policy values from registry.
- Optional: wecutil qc output (mainly collector-side; stored as indicator).

Optional JSON config. If JSON is missing/invalid, built-in defaults are used.

.PARAMETER ExportPath
Optional base CSV path. Creates:
- <ExportPath>                 (summary)
- <ExportPath>-findings.csv
- <ExportPath>-indicators.csv

.PARAMETER IncludeWecutilCheck
If set, runs 'wecutil qc /q' and stores output in indicators.

.PARAMETER ConfigPath
Optional JSON config path (placeholder): PATH/TO/JSON/wef-audit.json

.PARAMETER PassThru
If set, emits Summary, Finding (each), Indicators as separate pipeline objects.
If not set, emits a single Result object (default).

.OUTPUTS
Default: one Result object with Summary/Findings/Indicators.
With -PassThru: Summary + Findings + Indicators (structured objects only).

.NOTES
PowerShell 5.1 compatible.
.EXAMPLE
  .\45-WEF-Client-Forwarding-Readiness-Audit.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$ExportPath,
  [switch]$IncludeWecutilCheck,
  [string]$ConfigPath,
  [switch]$PassThru

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
Initialize-V2Context -ScriptName '45-WEF-Client-Forwarding-Readiness-Audit.ps1' -BoundParameters $PSBoundParameters
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
  $result = Get-V2ResultObject -ScriptName '45-WEF-Client-Forwarding-Readiness-Audit.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

# ----------------------------
# Defaults (used if JSON is missing/invalid)
# ----------------------------
$Defaults = @{
  RegistrySubscriptionManagerKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
  ExportEncoding                 = 'UTF8'  # Windows PowerShell 5.1 typically writes UTF-8 with BOM via Export-Csv. [web:14]
  ExportDelimiter                = ','
  ExportIncludeTimestampInRows   = $true

  ConsoleSummary                 = $true
  ConsoleUseWriteInformation     = $false  # If true, relies on Information stream settings. [web:73][web:77]
  ConsoleColor                   = $true   # Only applies to Write-UiLine.
}

# Script state
$script:Findings = Get-FindingsList
$script:ConfigUsedDefaults = $true
$script:ConfigLoadError = $null
$script:Config = $null

function Ensure-ExportDirectory {
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path)

  $dir = Split-Path -Path $Path -Parent
  if ($dir -and -not (Test-Path -Path $dir)) {
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
  }
}

function Get-SuffixedPath {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$BasePath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Suffix
  )

  if ($BasePath -match '\.csv$') { return ($BasePath -replace '\.csv$', "$Suffix") }
  return "$BasePath$Suffix"
}


function Get-WinRmState {
  [CmdletBinding()]
  param()

  $svc = $null
  $startMode = $null

  try {
    $svc = Get-Service -Name 'WinRM' -ErrorAction Stop
  }
  catch {
    $null = Add-Finding -FindingList $script:Findings -Code 'WEF-WinRMServiceMissingOrNoAccess' -Severity 'High' -Message ("WinRM service could not be queried: {0}" -f $_.Exception.Message)
    return [pscustomobject]@{ Status = $null; StartMode = $null }
  }

  if ($svc.Status -ne 'Running') {
    $null = Add-Finding -FindingList $script:Findings -Code 'WEF-WinRMNotRunning' -Severity 'High' -Message ("WinRM service is {0}; WEF sources require WinRM/WSMan." -f $svc.Status)
  }

  try {
    # S11 note: 'WinRM' is a hardcoded literal, safe from WQL injection.
    # If refactored to a variable, apply: $escaped = $name -replace "'", "''"
    $startMode = (Get-CimInstance -ClassName Win32_Service -Filter "Name='WinRM'" -ErrorAction Stop).StartMode
    if ($startMode -eq 'Disabled') {
      $null = Add-Finding -FindingList $script:Findings -Code 'WEF-WinRMDisabled' -Severity 'High' -Message 'WinRM start mode is Disabled; client is not WEF-ready.'
    }
  }
  catch {
    $null = Add-Finding -FindingList $script:Findings -Code 'WEF-WinRMStartModeUnknown' -Severity 'Low' -Message ("WinRM start mode could not be determined: {0}" -f $_.Exception.Message)
  }

  return [pscustomobject]@{ Status = [string]$svc.Status; StartMode = $startMode }
}

function Get-SubscriptionManagerPolicy {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$RegistryKeyPath
  )

  $values = New-Object System.Collections.Generic.List[string]

  try {
    if (Test-Path -Path $RegistryKeyPath) {
      $keyItem = Get-Item -Path $RegistryKeyPath -ErrorAction Stop
      foreach ($valueName in $keyItem.GetValueNames()) {
        $v = [string]$keyItem.GetValue($valueName)
        if ($v) { [void]$values.Add($v) }
      }
    }
  }
  catch {
    $null = Add-Finding -FindingList $script:Findings -Code 'WEF-SubscriptionManagerReadFailed' -Severity 'Medium' -Message ("SubscriptionManager key could not be read: {0}" -f $_.Exception.Message)
  }

  $joined = if ($values.Count -gt 0) { ($values.ToArray() -join ' | ') } else { $null }
  if (-not $joined) {
    $null = Add-Finding -FindingList $script:Findings -Code 'WEF-SubscriptionManagerMissing' -Severity 'Medium' -Message 'No SubscriptionManager policy value found; client likely not bound to a collector via GPO.'
  }

  return [pscustomobject]@{
    ValueJoined = $joined
    ValueCount  = $values.Count
    Values      = $values.ToArray()
  }
}

function Invoke-WecutilQc {
  [CmdletBinding()]
  param()

  try {
    # wecutil command reference. [web:32]
    return (wecutil qc /q 2>&1 | Out-String).Trim()
  }
  catch {
    $null = Add-Finding -FindingList $script:Findings -Code 'WEF-WecutilQcFailed' -Severity 'Low' -Message ("wecutil qc /q failed: {0}" -f $_.Exception.Message)
    return $null
  }
}

function Get-FindingCounts {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object[]]$Findings
  )

  $counts = @{ High=0; Medium=0; Low=0 }
  foreach ($f in $Findings) {
    if ($null -ne $f -and $counts.ContainsKey([string]$f.Severity)) {
      $counts[[string]$f.Severity]++
    }
  }
  return $counts
}

function Write-PrettySummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNull()][psobject]$Result
  )

  $counts = Get-FindingCounts -Findings $Result.Findings

  $headlineStyle = if ($Result.Summary.FindingsCount -gt 0) { 'Warning' } else { 'Success' }

  Write-ConsoleLine ''
  Write-ConsoleLine '============================================================' -Style 'Muted'
  Write-ConsoleLine 'WEF Client Forwarding Readiness Audit' -Style 'Header'
  Write-ConsoleLine '============================================================' -Style 'Muted'

  Write-ConsoleLine ("ComputerName : {0}" -f $Result.Summary.ComputerName) -Style 'Info'
  Write-ConsoleLine ("Timestamp    : {0}" -f $Result.Summary.Timestamp) -Style 'Info'

  Write-ConsoleLine ("Result       : Findings={0} (High={1}, Medium={2}, Low={3})" -f $Result.Summary.FindingsCount, $counts.High, $counts.Medium, $counts.Low) -Style $headlineStyle
  Write-ConsoleLine ''

  $winrmOk = ($Result.Indicators.WinRM_ServiceStatus -eq 'Running' -and $Result.Indicators.WinRM_StartMode -ne 'Disabled')
  if ($winrmOk) {
    Write-ConsoleLine ("WinRM        : OK (Status={0}, StartMode={1})" -f $Result.Indicators.WinRM_ServiceStatus, $Result.Indicators.WinRM_StartMode) -Style 'Success'
  }
  else {
    Write-ConsoleLine ("WinRM        : NOT OK (Status={0}, StartMode={1})" -f $Result.Indicators.WinRM_ServiceStatus, $Result.Indicators.WinRM_StartMode) -Style 'Error'
  }

  if ($Result.Indicators.SubscriptionManagerPolicy) {
    Write-ConsoleLine ("SubMgrPolicy : Present ({0} value(s))" -f $Result.Indicators.SubscriptionManagerValueCount) -Style 'Success'
  }
  else {
    Write-ConsoleLine 'SubMgrPolicy : Missing' -Style 'Warning'
  }

  if ($Result.Indicators.UsedDefaultConfig) {
    Write-ConsoleLine ("Config       : Defaults in use (ConfigPath='{0}')" -f $Result.Indicators.ConfigPath) -Style 'Muted'
  }
  else {
    Write-ConsoleLine ("Config       : Loaded (ConfigPath='{0}')" -f $Result.Indicators.ConfigPath) -Style 'Muted'
  }

  if ($Result.Indicators.ConfigLoadError) {
    Write-ConsoleLine ("ConfigError  : {0}" -f $Result.Indicators.ConfigLoadError) -Style 'Warning'
  }

  if ($Result.Indicators.WecutilQcOutput) {
    Write-ConsoleLine 'WecutilQc    : Collected (see Indicators.WecutilQcOutput)' -Style 'Muted'
  }

  if ($Result.Findings.Count -gt 0) {
    Write-ConsoleLine ''
    Write-ConsoleLine 'Top findings:' -Style 'Header'

    $Result.Findings |
      Sort-Object @{Expression={ switch ($_.Severity) { 'High' {0} 'Medium' {1} 'Low' {2} default {9} } }}, Code |
      Select-Object -First 10 |
      ForEach-Object {
        $style = switch ($_.Severity) { 'High' {'Error'} 'Medium' {'Warning'} 'Low' {'Info'} default {'Default'} }
        Write-ConsoleLine ("- [{0}] {1}: {2}" -f $_.Severity, $_.Code, $_.Message) -Style $style
      }
  }

  Write-ConsoleLine ''
  Write-ConsoleLine 'Tip: Use -PassThru for separate pipeline objects, or pipe the default Result to ConvertTo-Json.' -Style 'Muted'
  Write-ConsoleLine ''
}

# ----------------------------
# Main
# ----------------------------
$cfgResult = Read-ConfigWithDefaults -Path $ConfigPath -Defaults $Defaults
$script:Config = $cfgResult.Config
$script:ConfigUsedDefaults = [bool]$cfgResult.Meta.UsedDefaults
$script:ConfigLoadError = $cfgResult.Meta.Error

if ($script:ConfigLoadError) {
  $null = Add-Finding -FindingList $script:Findings -Code 'WEF-ConfigLoadFailed' -Severity 'Low' -Message ("Config JSON could not be loaded; using defaults. Error: {0}" -f $script:ConfigLoadError)
}

$winrmState = Get-WinRmState
$subMgrInfo = Get-SubscriptionManagerPolicy -RegistryKeyPath ([string]$script:Config.RegistrySubscriptionManagerKey)

$wecutilQcOutput = $null
if ($IncludeWecutilCheck) {
  $wecutilQcOutput = Invoke-WecutilQc
}

$winrmServiceStatus = if ($winrmState.PSObject.Properties.Name -contains 'Status') { $winrmState.Status } else { $null }
$winrmStartMode = if ($winrmState.PSObject.Properties.Name -contains 'StartMode') { $winrmState.StartMode } else { $null }

$indicators = [pscustomobject]@{
  ComputerName                  = $env:COMPUTERNAME
  Timestamp                     = Get-Date
  WinRM_ServiceStatus           = $winrmServiceStatus
  WinRM_StartMode               = $winrmStartMode
  SubscriptionManagerPolicy     = $subMgrInfo.ValueJoined
  SubscriptionManagerValueCount = $subMgrInfo.ValueCount
  SubscriptionManagerValues     = $subMgrInfo.Values
  WecutilQcOutput               = $wecutilQcOutput
  ConfigPath                    = $ConfigPath
  UsedDefaultConfig             = [bool]$script:ConfigUsedDefaults
  ConfigLoadError               = $script:ConfigLoadError
}

$summary = [pscustomobject]@{
  ComputerName  = $env:COMPUTERNAME
  FindingsCount = $script:Findings.Count
  Timestamp     = Get-Date
}

$result = [pscustomobject]@{
  Summary    = $summary
  Findings   = $script:Findings.ToArray()
  Indicators = $indicators
}

# Export (optional)
if ($ExportPath) {
  try {
    Ensure-ExportDirectory -Path $ExportPath

    $summaryPath    = $ExportPath
    $findingsPath   = Get-SuffixedPath -BasePath $ExportPath -Suffix '-findings.csv'
    $indicatorsPath = Get-SuffixedPath -BasePath $ExportPath -Suffix '-indicators.csv'

    $delimiter = [string]$script:Config.ExportDelimiter
    $encoding  = [string]$script:Config.ExportEncoding

    $result.Summary | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding $encoding -Delimiter $delimiter

    $rowTimestamp = if ($script:Config.ExportIncludeTimestampInRows) { Get-Date } else { $null }

    ($result.Findings | ForEach-Object {
      [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        Timestamp    = $rowTimestamp
        Code         = $_.Code
        Severity     = $_.Severity
        Message      = $_.Message
      }
    }) | Export-Csv -Path $findingsPath -NoTypeInformation -Encoding $encoding -Delimiter $delimiter

    $result.Indicators | Export-Csv -Path $indicatorsPath -NoTypeInformation -Encoding $encoding -Delimiter $delimiter
  }
  catch {
    $null = Add-Finding -FindingList $script:Findings -Code 'WEF-ExportFailed' -Severity 'Low' -Message ("CSV export failed: {0}" -f $_.Exception.Message)

    # Refresh result after adding export failure finding
    $result = [pscustomobject]@{
      Summary    = [pscustomobject]@{ ComputerName=$env:COMPUTERNAME; FindingsCount=$script:Findings.Count; Timestamp=Get-Date }
      Findings   = $script:Findings.ToArray()
      Indicators = $indicators
    }
  }
}

# Console summary (host/information stream only)
if ($script:Config.ConsoleSummary) {
  Write-PrettySummary -Result $result
}

# V2 output contract
$resultToken = if ($Strict -and $script:Findings.Count -gt 0) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = Get-V2ResultObject -ScriptName '45-WEF-Client-Forwarding-Readiness-Audit.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings.ToArray()) -Summary $result.Summary -Metadata @{ Indicators = $result.Indicators }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
