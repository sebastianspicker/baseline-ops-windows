#requires -version 5.1
<#
.SYNOPSIS
Audits Windows network configuration per interface (IP, gateways, DNS) and prints a human-friendly console report.

.DESCRIPTION
Uses Get-NetIPConfiguration (NetTCPIP) for structured per-interface data. [web:1]
Optionally exports CSV files (summary + interfaces). [web:18]
Optionally loads a JSON config (e.g. "PATH/TO/JSON/config.json"); if missing/invalid, built-in defaults are used.

.DESIGN GOALS
- Pipeline: structured objects only (safe for Export-Csv / ConvertTo-Json / Where-Object).
- Console: all "pretty" output via Write-Host or Write-Information only (no strings/format objects to pipeline). [web:58]

.PARAMETER ExportPath
Optional base file path for CSV exports. Creates:
<base>_summary.csv and <base>_interfaces.csv in the target folder.

.PARAMETER IncludeHidden
If set, includes ALL interfaces (virtual/loopback/disconnected) via Get-NetIPConfiguration -All. [web:148]

.PARAMETER JsonPath
Optional path to a JSON config file (e.g. "PATH/TO/JSON/config.json").

.PARAMETER Quiet
Suppress console output.

.PARAMETER PassThru
Emit structured pipeline output (object with Summary and Interfaces).
If not set, no pipeline output is emitted (interactive-friendly).

.OUTPUTS
With -PassThru: PSCustomObject with Summary and Interfaces.
Without -PassThru: no pipeline output.
.EXAMPLE
  .\29-Network-Config-Audit.ps1

#>


[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$ExportPath,

  [Parameter(Mandatory = $false)]
  [switch]$IncludeHidden,

  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$JsonPath = $null,

  [Parameter(Mandatory = $false)]
  [switch]$Quiet,

  [Parameter(Mandatory = $false)]
  [switch]$PassThru
)

$script:LibPath = Join-Path $PSScriptRoot 'lib'
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force


Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Ensure-Cmdlet {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Name
  )

  if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
    throw "Required cmdlet is missing: $Name. Verify OS / NetTCPIP module availability."
  }
}

function Get-OptionalPropertyValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [object]$InputObject,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$PropertyName
  )

  $p = $InputObject.PSObject.Properties[$PropertyName]
  if ($null -ne $p) { return $p.Value }
  return $null
}

function Resolve-ExportFolderAndBase {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ExportPath
  )

  $folder = Split-Path -Path $ExportPath -Parent
  if (-not $folder) { $folder = (Get-Location).Path }

  $base = [IO.Path]::GetFileNameWithoutExtension($ExportPath)
  if (-not $base) { throw "ExportPath must include a filename (e.g. C:\Temp\net_audit.csv)." }

  [pscustomobject]@{
    Folder = $folder
    Base   = $base
  }
}

function Get-DefaultConfig {
  [CmdletBinding()]
  param()

  [pscustomobject]@{
    FilterWhenNotIncludeHidden = $true
    CsvEncoding               = 'UTF8'
    CsvUseCultureDelimiter    = $true  # More Excel-friendly in many locales.
    ConsoleSummary            = $true
    ConsoleShowInterfaces     = $true
    ConsoleShowIssuesTable    = $true
    ConsoleUseInformation     = $false # If $true: Write-Information; else: Write-Host.
    ConsoleWidthHint          = 240     # Used only for Out-String -Width to reduce wrapping.
  }
}

function Import-JsonConfigOrDefault {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $false)]
    [string]$JsonPath
  )

  $cfg = Get-DefaultConfig

  if ([string]::IsNullOrWhiteSpace($JsonPath)) { return $cfg }
  if (-not (Test-Path -Path $JsonPath)) { return $cfg }

  try {
    $raw = Get-Content -Path $JsonPath -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { return $cfg }

    $json = $raw | ConvertFrom-Json

    $v = Get-OptionalPropertyValue -InputObject $json -PropertyName 'FilterWhenNotIncludeHidden'
    if ($null -ne $v) { $cfg.FilterWhenNotIncludeHidden = [bool]$v }

    $v = Get-OptionalPropertyValue -InputObject $json -PropertyName 'CsvEncoding'
    if ($null -ne $v -and -not [string]::IsNullOrWhiteSpace([string]$v)) { $cfg.CsvEncoding = [string]$v }

    $v = Get-OptionalPropertyValue -InputObject $json -PropertyName 'CsvUseCultureDelimiter'
    if ($null -ne $v) { $cfg.CsvUseCultureDelimiter = [bool]$v }

    $v = Get-OptionalPropertyValue -InputObject $json -PropertyName 'ConsoleSummary'
    if ($null -ne $v) { $cfg.ConsoleSummary = [bool]$v }

    $v = Get-OptionalPropertyValue -InputObject $json -PropertyName 'ConsoleShowInterfaces'
    if ($null -ne $v) { $cfg.ConsoleShowInterfaces = [bool]$v }

    $v = Get-OptionalPropertyValue -InputObject $json -PropertyName 'ConsoleShowIssuesTable'
    if ($null -ne $v) { $cfg.ConsoleShowIssuesTable = [bool]$v }

    $v = Get-OptionalPropertyValue -InputObject $json -PropertyName 'ConsoleUseInformation'
    if ($null -ne $v) { $cfg.ConsoleUseInformation = [bool]$v }

    $v = Get-OptionalPropertyValue -InputObject $json -PropertyName 'ConsoleWidthHint'
    if ($null -ne $v) { $cfg.ConsoleWidthHint = [int]$v }

    return $cfg
  }
  catch {
    return $cfg
  }
}


function To-ConsoleTableText {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [object[]]$InputObjects,

    [Parameter(Mandatory)]
    [int]$Width
  )

  # Console-only formatting; caller must write via Write-Host/Write-Information. [web:146]
  return ($InputObjects | Format-Table -AutoSize | Out-String -Width $Width)
}

function Write-ConsoleInterfaces {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [object[]]$Interfaces,

    [Parameter(Mandatory)]
    [pscustomobject]$Config
  )

  Write-ConsoleLine -Text "Interfaces (IP + DNS):" -Color White -Config $Config

  $rows = @(
    $Interfaces |
      Sort-Object InterfaceIndex, InterfaceAlias |
      Select-Object InterfaceAlias, IPv4Address, IPv6Address, DnsServers
  )

  if ($rows.Count -eq 0) {
    Write-ConsoleLine -Text "  (none)" -Color DarkGray -Config $Config
    return
  }

  $text = To-ConsoleTableText -InputObjects $rows -Width $Config.ConsoleWidthHint
  if ($Config.ConsoleUseInformation) { Write-Information -InformationAction Continue -MessageData $text }
  else { Write-Host $text }
}

function Write-ConsoleSummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [pscustomobject]$Summary,

    [Parameter(Mandatory)]
    [object[]]$Interfaces,

    [Parameter(Mandatory)]
    [pscustomobject]$Config
  )

  Write-ConsoleHeader -Title "Network Config Audit" -Right ("{0}  |  {1}" -f $Summary.ComputerName, $Summary.Timestamp) -Config $Config
  Write-ConsoleLine -Text "" -Config $Config

  $statusColor = if ($Summary.InterfacesWithDNS -gt 0 -and $Summary.InterfacesWithGateway -gt 0) { 'Green' } else { 'Yellow' }
  Write-ConsoleLine -Text "Summary:" -Color White -Config $Config
  Write-ConsoleLine -Text ("  Interfaces total        : {0}" -f $Summary.InterfacesCount) -Config $Config
  Write-ConsoleLine -Text ("  Interfaces with gateway : {0}" -f $Summary.InterfacesWithGateway) -Color $statusColor -Config $Config
  Write-ConsoleLine -Text ("  Interfaces with DNS     : {0}" -f $Summary.InterfacesWithDNS) -Color $statusColor -Config $Config
  Write-ConsoleLine -Text "" -Config $Config

  if ($Config.ConsoleShowInterfaces) {
    Write-ConsoleInterfaces -Interfaces $Interfaces -Config $Config
    Write-ConsoleLine -Text "" -Config $Config
  }

  if (-not $Config.ConsoleShowIssuesTable) { return }

  $issues = @(
    $Interfaces | Where-Object {
      (-not $_.DnsServers) -or
      ((-not $_.IPv4Gateway) -and (-not $_.IPv6Gateway))
    }
  )

  if ($issues.Count -eq 0) {
    Write-ConsoleLine -Text "No obvious issues detected (missing DNS and/or gateway)." -Color Green -Config $Config
    return
  }

  Write-ConsoleLine -Text ("Potential issues: {0} interface(s) missing DNS and/or gateway" -f $issues.Count) -Color Yellow -Config $Config

  $issueRows = @(
    $issues |
      Select-Object InterfaceAlias, InterfaceIndex, IPv4Address, IPv6Address, IPv4Gateway, IPv6Gateway, DnsServers
  )

  $issuesText = To-ConsoleTableText -InputObjects $issueRows -Width $Config.ConsoleWidthHint
  if ($Config.ConsoleUseInformation) { Write-Information -InformationAction Continue -MessageData $issuesText }
  else { Write-Host $issuesText }
}

# --- Main ---
Ensure-Cmdlet -Name 'Get-NetIPConfiguration'

$config = Import-JsonConfigOrDefault -JsonPath $JsonPath

# Get-NetIPConfiguration without parameters returns non-virtual connected interfaces;
# -All returns all interfaces (including virtual/loopback/disconnected). [web:1][web:148]
$netCfg = if ($IncludeHidden) { Get-NetIPConfiguration -All } else { Get-NetIPConfiguration }

if (-not $IncludeHidden -and $config.FilterWhenNotIncludeHidden) {
  $netCfg = $netCfg | Where-Object {
    $_.IPv4Address -or $_.IPv6Address -or $_.IPv4DefaultGateway -or $_.IPv6DefaultGateway -or $_.DNSServer
  }
}

$interfaces = $netCfg | ForEach-Object {
  $ipv4 = if ($_.IPv4Address) { ($_.IPv4Address | ForEach-Object { $_.IPAddress }) -join ', ' } else { $null }
  $ipv6 = if ($_.IPv6Address) { ($_.IPv6Address | ForEach-Object { $_.IPAddress }) -join ', ' } else { $null }

  $gw4 = if ($_.IPv4DefaultGateway) { $_.IPv4DefaultGateway.NextHop } else { $null }
  $gw6 = if ($_.IPv6DefaultGateway) { $_.IPv6DefaultGateway.NextHop } else { $null }

  $dns = if ($_.DNSServer -and $_.DNSServer.ServerAddresses) { ($_.DNSServer.ServerAddresses -join ', ') } else { $null }

  $profileName = if ($_.NetProfile) { $_.NetProfile.Name } else { $null }

  # DnsSuffix is not guaranteed on all objects -> safe lookup.
  $dnsSuffix = Get-OptionalPropertyValue -InputObject $_ -PropertyName 'DnsSuffix'

  [pscustomobject]@{
    InterfaceAlias        = $_.InterfaceAlias
    InterfaceIndex        = $_.InterfaceIndex
    InterfaceDescription  = $_.InterfaceDescription
    NetProfileName        = $profileName
    IPv4Address           = $ipv4
    IPv6Address           = $ipv6
    IPv4Gateway           = $gw4
    IPv6Gateway           = $gw6
    DnsServers            = $dns
    DnsSuffix             = $dnsSuffix
  }
}

$summary = [pscustomobject]@{
  ComputerName          = $env:COMPUTERNAME
  InterfacesCount       = @($interfaces).Count
  InterfacesWithGateway = @($interfaces | Where-Object { $_.IPv4Gateway -or $_.IPv6Gateway }).Count
  InterfacesWithDNS     = @($interfaces | Where-Object { $_.DnsServers }).Count
  Timestamp             = Get-Date
}

if ($ExportPath) {
  $target = Resolve-ExportFolderAndBase -ExportPath $ExportPath

  if (-not (Test-Path -Path $target.Folder)) {
    New-Item -Path $target.Folder -ItemType Directory -Force | Out-Null
  }

  # Do not format objects before Export-Csv; select properties instead. [web:18][web:146]
  if ($config.CsvUseCultureDelimiter) {
    $summary    | Export-Csv -Path (Join-Path $target.Folder ($target.Base + "_summary.csv"))    -NoTypeInformation -Encoding $config.CsvEncoding -UseCulture
    $interfaces | Export-Csv -Path (Join-Path $target.Folder ($target.Base + "_interfaces.csv")) -NoTypeInformation -Encoding $config.CsvEncoding -UseCulture
  }
  else {
    $summary    | Export-Csv -Path (Join-Path $target.Folder ($target.Base + "_summary.csv"))    -NoTypeInformation -Encoding $config.CsvEncoding
    $interfaces | Export-Csv -Path (Join-Path $target.Folder ($target.Base + "_interfaces.csv")) -NoTypeInformation -Encoding $config.CsvEncoding
  }
}

if (-not $Quiet -and $config.ConsoleSummary) {
  Write-ConsoleSummary -Summary $summary -Interfaces $interfaces -Config $config
}

#$result = [pscustomobject]@{
#  Summary    = $summary
#  Interfaces = $interfaces
#}

if ($PassThru) { $result }
