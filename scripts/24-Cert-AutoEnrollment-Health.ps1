#requires -version 5.1
<#
.SYNOPSIS
Triggers certificate autoenrollment, queries AutoEnrollment-related events, and reports expiring machine certificates.

.DESCRIPTION
Output model (best practice):
- Pipeline output: structured object(s) only (PSCustomObject) unless -Quiet is used.
- Console output: pretty summary via Write-Host only (no "pretty text" in the pipeline). [web:142][web:102]

.PARAMETER WarnDays
Certificates expiring within <= WarnDays are reported.

.PARAMETER HoursBack
How far back to query event logs.

.PARAMETER ExportPath
Optional base file path for CSV export (suffixes _summary/_events/_expiring are appended).

.PARAMETER ConfigPath
Optional JSON config path (e.g. "PATH/TO/JSON/config.json"). If missing/invalid, built-in defaults are used.

.PARAMETER IncludeExpired
Include already expired certificates.

.PARAMETER RequirePrivateKey
Only report certificates that have a private key (recommended).

.PARAMETER NoPulse
Skip 'certutil -pulse' (read-only health check mode).

.PARAMETER NoConsoleSummary
Do not print the console summary block.

.PARAMETER Quiet
Do not write the result object to the success output stream (console summary still shown unless suppressed).
.EXAMPLE
  .\24-Cert-AutoEnrollment-Health.ps1

#>


[CmdletBinding()]
param(
  [ValidateRange(1, 3650)]
  [int]$WarnDays = 30,

  [ValidateRange(1, 168)]
  [int]$HoursBack = 24,

  [string]$ExportPath,

  [string]$ConfigPath = "PATH/TO/JSON/config.json",

  [switch]$IncludeExpired,

  [switch]$RequirePrivateKey = $true,

  [switch]$NoPulse,

  [switch]$NoConsoleSummary,

  [switch]$Quiet
)

$script:LibPath = Join-Path $PSScriptRoot 'lib'
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force


Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'


function Get-ConfigValueInt {
  param(
    $ConfigObject,
    [string]$Name,
    [int]$DefaultValue,
    [int]$Min,
    [int]$Max
  )

  if ($null -eq $ConfigObject) { return $DefaultValue }

  $val = $null
  try { $val = $ConfigObject.$Name } catch { $val = $null }
  if ($null -eq $val) { return $DefaultValue }

  $intVal = $null
  if ([int]::TryParse([string]$val, [ref]$intVal)) {
    if ($intVal -lt $Min) { return $Min }
    if ($intVal -gt $Max) { return $Max }
    return $intVal
  }

  $DefaultValue
}

function Get-ConfigValueString {
  param(
    $ConfigObject,
    [string]$Name,
    [string]$DefaultValue
  )

  if ($null -eq $ConfigObject) { return $DefaultValue }

  $val = $null
  try { $val = $ConfigObject.$Name } catch { $val = $null }
  if ([string]::IsNullOrWhiteSpace([string]$val)) { return $DefaultValue }
  [string]$val
}

function Get-ConfigValueBool {
  param(
    $ConfigObject,
    [string]$Name,
    [bool]$DefaultValue
  )

  if ($null -eq $ConfigObject) { return $DefaultValue }

  $val = $null
  try { $val = $ConfigObject.$Name } catch { $val = $null }
  if ($null -eq $val) { return $DefaultValue }

  if ($val -is [bool]) { return [bool]$val }

  $s = ([string]$val).Trim()
  switch -Regex ($s.ToLowerInvariant()) {
    '^(1|true|yes|y)$' { $true; break }
    '^(0|false|no|n)$' { $false; break }
    default { $DefaultValue; break }
  }
}

function Get-AutoEnrollEvents {
  param(
    [Parameter(Mandatory)][DateTime]$StartTime,
    [Parameter(Mandatory)][string]$OperationalLogName
  )

  $out = [pscustomobject]@{
    Mode                 = $null
    LogNameUsed          = $null
    OperationalAvailable = $true
    Error                = $null
    Events               = @()
  }

  try {
    $ev = Get-WinEvent -FilterHashtable @{ LogName = $OperationalLogName; StartTime = $StartTime } -ErrorAction Stop
    $out.Mode = 'Operational'
    $out.LogNameUsed = $OperationalLogName
    $out.Events = $ev
    return $out
  } catch {
    $out.OperationalAvailable = $false
    $out.Error = $_.Exception.Message
  }

  try {
    $providers = @(
      'Microsoft-Windows-CertificateServicesClient-AutoEnrollment',
      'Microsoft-Windows-CertificateServicesClient-CertEnroll',
      'Microsoft-Windows-CertificateServicesClient'
    )

    $evAll = @()
    foreach ($p in $providers) {
      try {
        $evAll += Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = $p; StartTime = $StartTime } -ErrorAction Stop
      } catch {
        # Provider not present or access denied; ignore and continue.
      }
    }

    $out.Mode = 'ApplicationFallback'
    $out.LogNameUsed = 'Application'
    $out.Events = $evAll
    return $out
  } catch {
    $out.Mode = 'None'
    $out.LogNameUsed = $null
    $out.Events = @()
    if ($out.Error) { $out.Error = $out.Error + " | Fallback failed: " + $_.Exception.Message }
    else { $out.Error = $_.Exception.Message }
    return $out
  }
}

function Get-HealthStatus {
  param([Parameter(Mandatory)]$ResultObject)

  if ($ResultObject.CertificateReadError) { return 'Error' }
  if ($ResultObject.EventQueryMode -eq 'None') { return 'Error' }
  if (-not $ResultObject.NoPulse -and -not $ResultObject.AutoEnrollmentTriggered) { return 'Warning' }
  if ($ResultObject.ExpiringCertsFound -gt 0) { return 'Warning' }

  'OK'
}

function Write-ColorValue {
  param(
    [Parameter(Mandatory)][string]$Label,
    [Parameter(Mandatory)][string]$Value,
    [ConsoleColor]$LabelColor = 'Gray',
    [ConsoleColor]$ValueColor = 'Gray'
  )

  $pad = 28
  $left = ($Label + ':').PadRight($pad)
  Write-Host $left -NoNewline -ForegroundColor $LabelColor
  Write-Host $Value -ForegroundColor $ValueColor
}

function Show-ConsoleSummary {
  param([Parameter(Mandatory)]$ResultObject)

  $status = Get-HealthStatus -ResultObject $ResultObject

  $statusColor = 'Green'
  if ($status -eq 'Warning') { $statusColor = 'Yellow' }
  if ($status -eq 'Error')   { $statusColor = 'Red' }

  $headline = "Certificate AutoEnrollment Health"
  $line = ('=' * ($headline.Length + 10))

  Write-Host ""
  Write-Host $line -ForegroundColor DarkGray
  Write-Host ("===  {0}  ===" -f $headline) -ForegroundColor Cyan
  Write-Host $line -ForegroundColor DarkGray

  Write-ColorValue -Label 'Status' -Value $status -LabelColor Gray -ValueColor $statusColor
  Write-ColorValue -Label 'ComputerName' -Value $ResultObject.ComputerName -LabelColor Gray -ValueColor White
  Write-ColorValue -Label 'Timestamp' -Value ([string]$ResultObject.Timestamp) -LabelColor Gray -ValueColor White

  Write-Host ""
  Write-Host "Configuration" -ForegroundColor Cyan
  Write-Host ('-' * 40) -ForegroundColor DarkGray

  $cfgLoadedColor = 'DarkYellow'
  if ($ResultObject.ConfigLoaded) { $cfgLoadedColor = 'Green' }
  Write-ColorValue -Label 'ConfigLoaded' -Value ([string]$ResultObject.ConfigLoaded) -ValueColor $cfgLoadedColor

  if ($ResultObject.ConfigPath) {
    Write-ColorValue -Label 'ConfigPath' -Value $ResultObject.ConfigPath -ValueColor DarkGray
  }

  Write-Host ""
  Write-Host "AutoEnrollment" -ForegroundColor Cyan
  Write-Host ('-' * 40) -ForegroundColor DarkGray

  if ($ResultObject.NoPulse) {
    Write-ColorValue -Label 'Pulse' -Value 'Skipped (NoPulse)' -ValueColor DarkGray
  } else {
    $pulseColor = 'Red'
    if ($ResultObject.AutoEnrollmentTriggered) { $pulseColor = 'Green' }
    Write-ColorValue -Label 'PulseTriggered' -Value ([string]$ResultObject.AutoEnrollmentTriggered) -ValueColor $pulseColor

    if ($ResultObject.AutoEnrollmentError) {
      Write-ColorValue -Label 'PulseError' -Value $ResultObject.AutoEnrollmentError -ValueColor Red
    }
  }

  Write-Host ""
  Write-Host "Event Log" -ForegroundColor Cyan
  Write-Host ('-' * 40) -ForegroundColor DarkGray

  $modeColor = 'DarkYellow'
  if ($ResultObject.EventQueryMode -eq 'Operational') { $modeColor = 'Green' }
  if ($ResultObject.EventQueryMode -eq 'None') { $modeColor = 'Red' }
  Write-ColorValue -Label 'QueryMode' -Value $ResultObject.EventQueryMode -ValueColor $modeColor

  Write-ColorValue -Label 'LogNameUsed' -Value ([string]$ResultObject.LogNameUsed) -ValueColor White
  Write-ColorValue -Label 'HoursBack' -Value ([string]$ResultObject.HoursBack) -ValueColor White

  $eventsColor = 'Gray'
  if ($ResultObject.EventsFound -gt 0) { $eventsColor = 'DarkYellow' }
  Write-ColorValue -Label 'EventsFound' -Value ([string]$ResultObject.EventsFound) -ValueColor $eventsColor

  if ($ResultObject.EventQueryError) {
    Write-ColorValue -Label 'EventQueryError' -Value $ResultObject.EventQueryError -ValueColor DarkYellow
  }

  Write-Host ""
  Write-Host "Certificates (LocalMachine\\My)" -ForegroundColor Cyan
  Write-Host ('-' * 40) -ForegroundColor DarkGray

  Write-ColorValue -Label 'WarnDays' -Value ([string]$ResultObject.WarnDays) -ValueColor White
  Write-ColorValue -Label 'IncludeExpired' -Value ([string]$ResultObject.IncludeExpired) -ValueColor White
  Write-ColorValue -Label 'RequirePrivateKey' -Value ([string]$ResultObject.RequirePrivateKey) -ValueColor White

  $expColor = 'Green'
  if ($ResultObject.ExpiringCertsFound -gt 0) { $expColor = 'Yellow' }
  Write-ColorValue -Label 'ExpiringCertsFound' -Value ([string]$ResultObject.ExpiringCertsFound) -ValueColor $expColor

  if ($ResultObject.CertificateReadError) {
    Write-ColorValue -Label 'CertificateReadError' -Value $ResultObject.CertificateReadError -ValueColor Red
  }

  Write-Host ""
  Write-Host "Export" -ForegroundColor Cyan
  Write-Host ('-' * 40) -ForegroundColor DarkGray

  if ($ResultObject.ExportBasePath) {
    Write-ColorValue -Label 'CSV Export' -Value 'Enabled' -ValueColor Green
    Write-ColorValue -Label 'ExportBasePath' -Value $ResultObject.ExportBasePath -ValueColor White
  } else {
    Write-ColorValue -Label 'CSV Export' -Value 'Disabled' -ValueColor DarkGray
  }

  Write-Host $line -ForegroundColor DarkGray
  Write-Host ""
}

# Defaults + optional JSON config
$defaults = [pscustomobject]@{
  WarnDays          = 30
  HoursBack         = 24
  RequirePrivateKey = $true
  IncludeExpired    = $false
  ExportPath        = $null
  LogName           = 'Microsoft-Windows-CertificateServicesClient-AutoEnrollment/Operational'
}

$configObj = Read-JsonConfig -Path $ConfigPath

$WarnDays  = Get-ConfigValueInt -ConfigObject $configObj -Name 'WarnDays'  -DefaultValue $WarnDays  -Min 1 -Max 3650
$HoursBack = Get-ConfigValueInt -ConfigObject $configObj -Name 'HoursBack' -DefaultValue $HoursBack -Min 1 -Max 168

if (-not $PSBoundParameters.ContainsKey('RequirePrivateKey')) {
  $RequirePrivateKey = Get-ConfigValueBool -ConfigObject $configObj -Name 'RequirePrivateKey' -DefaultValue $defaults.RequirePrivateKey
}
if (-not $PSBoundParameters.ContainsKey('IncludeExpired')) {
  $IncludeExpired = Get-ConfigValueBool -ConfigObject $configObj -Name 'IncludeExpired' -DefaultValue $defaults.IncludeExpired
}
if (-not $PSBoundParameters.ContainsKey('ExportPath')) {
  $ExportPath = Get-ConfigValueString -ConfigObject $configObj -Name 'ExportPath' -DefaultValue $defaults.ExportPath
}

$logName = Get-ConfigValueString -ConfigObject $configObj -Name 'LogName' -DefaultValue $defaults.LogName

# Preconditions
if (-not (Test-IsAdmin)) { throw "Administrative privileges are required." }

if (-not (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue)) {
  throw "Cert: drive is not available. The Microsoft.PowerShell.Security provider/module may be missing."
}

# 1) Trigger autoenrollment (optional)
$autoEnrollTriggered = $false
$autoEnrollError     = $null

if ($NoPulse) {
  $autoEnrollTriggered = $false
  $autoEnrollError = "Skipped (NoPulse)."
} else {
  try {
    & certutil.exe -pulse | Out-Null
    $autoEnrollTriggered = $true
  } catch {
    $autoEnrollTriggered = $false
    $autoEnrollError     = $_.Exception.Message
  }
}

# 2) Query events
$startTime = (Get-Date).AddHours(-1 * $HoursBack)

$eventQuery = Get-AutoEnrollEvents -StartTime $startTime -OperationalLogName $logName

$eventsRaw = @($eventQuery.Events)
$eventOut = $eventsRaw | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message

# 3) Expiring machine certificates
$now      = Get-Date
$deadline = (Get-Date).AddDays($WarnDays)

$certReadError = $null
$certOut = @()

try {
  $certCandidates = Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop

  if ($RequirePrivateKey) {
    $certCandidates = $certCandidates | Where-Object { $_.HasPrivateKey }
  }

  $certCandidates = $certCandidates | Where-Object {
    if ($IncludeExpired) { $_.NotAfter -le $deadline }
    else { ($_.NotAfter -ge $now) -and ($_.NotAfter -le $deadline) }
  }

  $certOut = $certCandidates | Select-Object Subject, Thumbprint, NotAfter, Issuer, FriendlyName, HasPrivateKey
} catch {
  $certOut = @()
  $certReadError = $_.Exception.Message
}

# 4) Unified result object
$result = [pscustomobject]@{
  ComputerName              = $env:COMPUTERNAME
  Timestamp                 = Get-Date

  WarnDays                  = $WarnDays
  HoursBack                 = $HoursBack
  IncludeExpired            = [bool]$IncludeExpired
  RequirePrivateKey         = [bool]$RequirePrivateKey
  NoPulse                   = [bool]$NoPulse

  ConfigPath                = $ConfigPath
  ConfigLoaded              = ($null -ne $configObj)

  AutoEnrollmentTriggered   = $autoEnrollTriggered
  AutoEnrollmentError       = $autoEnrollError

  EventQueryMode            = $eventQuery.Mode
  AutoEnrollmentLogName     = $logName
  LogNameUsed               = $eventQuery.LogNameUsed
  OperationalLogAvailable   = [bool]$eventQuery.OperationalAvailable
  EventQueryError           = $eventQuery.Error
  EventsFound               = @($eventOut).Count

  ExpiringCertsFound        = @($certOut).Count
  CertificateReadError      = $certReadError

  ExportBasePath            = $ExportPath

  Events                    = $eventOut
  ExpiringCertificates      = $certOut
}

# 5) Optional CSV export
if ($ExportPath) {
  $folder = Split-Path -Path $ExportPath -Parent
  if (-not $folder) { $folder = (Get-Location).Path }
  Ensure-Directory -Path $folder

  $base = [IO.Path]::GetFileNameWithoutExtension($ExportPath)

  $summaryPath = Join-Path $folder ($base + "_summary.csv")
  $eventsPath  = Join-Path $folder ($base + "_events.csv")
  $certsPath   = Join-Path $folder ($base + "_expiring.csv")

  $result |
    Select-Object ComputerName, Timestamp, WarnDays, HoursBack, IncludeExpired, RequirePrivateKey, NoPulse,
                  ConfigPath, ConfigLoaded,
                  AutoEnrollmentTriggered, AutoEnrollmentError,
                  EventQueryMode, AutoEnrollmentLogName, LogNameUsed, OperationalLogAvailable, EventQueryError, EventsFound,
                  ExpiringCertsFound, CertificateReadError, ExportBasePath |
    Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8

  $eventOut | Export-Csv -Path $eventsPath -NoTypeInformation -Encoding UTF8
  $certOut  | Export-Csv -Path $certsPath  -NoTypeInformation -Encoding UTF8
}

# Console summary (host-only)
if (-not $NoConsoleSummary) {
  Show-ConsoleSummary -ResultObject $result
}

# Pipeline output (optional)
#if (-not $Quiet) {
#  $result
#}
