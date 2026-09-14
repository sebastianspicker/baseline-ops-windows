#requires -version 5.1
<#
.SYNOPSIS
Audits Windows network configuration per interface (IP, gateways, DNS) and prints a readable console report.

.DESCRIPTION
Uses Get-NetIPConfiguration (NetTCPIP) for structured per-interface data.
Optionally exports CSV files (summary + interfaces).
Optionally loads a JSON config from $JsonPath; if missing or invalid, built-in defaults are used.

.DESIGN GOALS
- Pipeline: structured objects only (safe for Export-Csv / ConvertTo-Json / Where-Object).
- Console: all formatting uses Write-UiLine or Write-Information and does not write strings or format objects to the pipeline.

.PARAMETER ExportPath
Optional base file path for CSV exports. Creates:
<base>_summary.csv and <base>_interfaces.csv in the target folder.

.PARAMETER IncludeHidden
If set, includes ALL interfaces (virtual/loopback/disconnected) via Get-NetIPConfiguration -All.

.PARAMETER JsonPath
Optional path to a JSON config file supplied with $JsonPath.

.PARAMETER Quiet
Suppress console output.

.PARAMETER PassThru
Emit structured pipeline output (object with Summary and Interfaces).
If not set, no pipeline output is emitted (interactive-friendly).


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER ConfigPath
  Path to JSON configuration file.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER Strict
  Treat warnings as failures.

.PARAMETER NoColor
  Disable colored output.

.OUTPUTS
With -PassThru: PSCustomObject with Summary and Interfaces.
Without -PassThru: no pipeline output.
.EXAMPLE
  .\29-Network-Config-Audit.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateNotNullOrEmpty()]
  [string]$ExportPath,

  [switch]$IncludeHidden,

  [ValidateNotNullOrEmpty()]
  [string]$JsonPath = $null,

  [switch]$Quiet,

  [switch]$PassThru

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [string]$ConfigPath,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$Strict,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
function Test-AllConditions {
  param([scriptblock[]]$Conditions)
  foreach ($condition in $Conditions) {
    if (-not (. $condition)) { return $false }
  }
  return $true
}
function Test-AnyCondition {
  param([scriptblock[]]$Conditions)
  foreach ($condition in $Conditions) {
    if (. $condition) { return $true }
  }
  return $false
}
function Initialize-Capability29Runtime {
  param($EntryBoundParameters)
  $RunState = @{

  }
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '29-Network-Config-Audit.ps1' -BoundParameters $EntryBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$RunState.isWindowsHost = ($env:OS -eq 'Windows_NT')
  $script:RunState = $RunState
}

. Initialize-Capability29Runtime -EntryBoundParameters $PSBoundParameters
if (-not $RunState.isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $RunState.result = Get-V2ResultObject -ScriptName '29-Network-Config-Audit.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $RunState.result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $RunState.result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

$script:Findings = Get-FindingsList

# Ensure-Cmdlet imported from lib/External.psm1

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
    ConsoleUseInformation     = $false # If $true: Write-Information; else: Write-UiLine.
    ConsoleWidthHint          = 240     # Used only for Out-String -Width to reduce wrapping.
  }
}

function Import-JsonConfigOrDefault {
  [CmdletBinding()]
  param(
    [string]$JsonPath
  )

  $cfg = Get-DefaultConfig

  if ([string]::IsNullOrWhiteSpace($JsonPath)) { return $cfg }
  if (-not (Test-Path -Path $JsonPath)) { return $cfg }

  try {
    $raw = Get-BoundedUtf8FileContent -Path $JsonPath -MaximumBytes 1048576
    if ([string]::IsNullOrWhiteSpace($raw)) { return $cfg }

    $json = $raw | ConvertFrom-Json

    Set-NetworkBooleanConfig -Config $cfg -Json $json
    $v = Get-OptionalPropertyValue -InputObject $json -PropertyName 'CsvEncoding'
    if ((Test-AllConditions -Conditions @({ $null -ne $v }, { -not [string]::IsNullOrWhiteSpace([string]$v) }))) { $cfg.CsvEncoding = [string]$v }

    $v = Get-OptionalPropertyValue -InputObject $json -PropertyName 'ConsoleWidthHint'
    if ($null -ne $v) { $cfg.ConsoleWidthHint = [int]$v }

    return $cfg
  }
  catch {
    return $cfg
  }
}
function Set-NetworkBooleanConfig {
  param($Config, $Json)
  foreach ($name in @('FilterWhenNotIncludeHidden','CsvUseCultureDelimiter','ConsoleSummary','ConsoleShowInterfaces','ConsoleShowIssuesTable','ConsoleUseInformation')) {
    $value = Get-OptionalPropertyValue -InputObject $Json -PropertyName $name
    if ($null -ne $value) { $Config.$name = [bool]$value }
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

  # Console-only formatting; caller must write via Write-UiLine/Write-Information.
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
  else { Write-UiLine $text }
}

# --- Main ---
function Invoke-Capability29MainPhase01 {
  param([hashtable]$RunState)
  Ensure-Cmdlet -Name 'Get-NetIPConfiguration'

  $RunState.config = Import-JsonConfigOrDefault -JsonPath $JsonPath

  # Get-NetIPConfiguration without parameters returns non-virtual connected interfaces;
  # -All returns all interfaces (including virtual/loopback/disconnected).
  $RunState.netCfg = if ($IncludeHidden) { Get-NetIPConfiguration -All } else { Get-NetIPConfiguration }
}
function Invoke-Capability29MainPhase02 {
  param([hashtable]$RunState)
  if (-not $IncludeHidden -and $RunState.config.FilterWhenNotIncludeHidden) {
    $RunState.netCfg = $RunState.netCfg | Where-Object {
      $_.IPv4Address -or $_.IPv6Address -or $_.IPv4DefaultGateway -or $_.IPv6DefaultGateway -or $_.DNSServer
    }
  }
}
function Invoke-Capability29MainPhase03 {
  param([hashtable]$RunState)
  $RunState.interfaces = $RunState.netCfg | ForEach-Object {
    $ipv4 = if ($_.IPv4Address) { ($_.IPv4Address | ForEach-Object { $_.IPAddress }) -join ', ' } else { $null }
    $ipv6 = if ($_.IPv6Address) { ($_.IPv6Address | ForEach-Object { $_.IPAddress }) -join ', ' } else { $null }

    $gw4 = if ($_.IPv4DefaultGateway) { $_.IPv4DefaultGateway.NextHop } else { $null }
    $gw6 = if ($_.IPv6DefaultGateway) { $_.IPv6DefaultGateway.NextHop } else { $null }

    $dns = if ((Test-AllConditions -Conditions @({ $_.DNSServer }, { $_.DNSServer.ServerAddresses }))) { ($_.DNSServer.ServerAddresses -join ', ') } else { $null }

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
}
function Invoke-Capability29MainPhase04 {
  param([hashtable]$RunState)
  $summary = [pscustomobject]@{
    ComputerName          = $env:COMPUTERNAME
    InterfacesCount       = @($RunState.interfaces).Count
    InterfacesWithGateway = @($RunState.interfaces | Where-Object { $_.IPv4Gateway -or $_.IPv6Gateway }).Count
    InterfacesWithDNS     = @($RunState.interfaces | Where-Object { $_.DnsServers }).Count
    Timestamp             = Get-Date
  }

  if ($ExportPath) {
    $target = Resolve-ExportFolderAndBase -ExportPath $ExportPath

    if (-not (Test-Path -Path $target.Folder)) {
      New-Item -Path $target.Folder -ItemType Directory -Force | Out-Null
    }

    # Do not format objects before Export-Csv; select properties instead.
    if ($RunState.config.CsvUseCultureDelimiter) {
      $summary    | Export-Csv -Path (Join-Path $target.Folder ($target.Base + "_summary.csv"))    -NoTypeInformation -Encoding $RunState.config.CsvEncoding -UseCulture
      $RunState.interfaces | Export-Csv -Path (Join-Path $target.Folder ($target.Base + "_interfaces.csv")) -NoTypeInformation -Encoding $RunState.config.CsvEncoding -UseCulture
    }
    else {
      $summary    | Export-Csv -Path (Join-Path $target.Folder ($target.Base + "_summary.csv"))    -NoTypeInformation -Encoding $RunState.config.CsvEncoding
      $RunState.interfaces | Export-Csv -Path (Join-Path $target.Folder ($target.Base + "_interfaces.csv")) -NoTypeInformation -Encoding $RunState.config.CsvEncoding
    }
  }
}
function Invoke-Capability29MainPhase05Step01 {
  param([hashtable]$RunState)
$findingsAL = ConvertTo-ArrayList -InputObject $script:Findings
    Write-ConsoleSummary -Summary $summary -Findings $findingsAL `
      -CustomFields ([ordered]@{
        InterfacesTotal       = $summary.InterfacesCount
        InterfacesWithGateway = $summary.InterfacesWithGateway
        InterfacesWithDNS     = $summary.InterfacesWithDNS
      })
    # Interfaces table
    if ($RunState.config.ConsoleShowInterfaces) {
      Write-ConsoleInterfaces -Interfaces $RunState.interfaces -Config $RunState.config
      Write-ConsoleLine -Text "" -Config $RunState.config
    }
}

function Invoke-Capability29MainPhase05Step02 {
  param([hashtable]$RunState)
if ($RunState.config.ConsoleShowIssuesTable) {
      $issues = @(
        $RunState.interfaces | Where-Object {
          (-not $_.DnsServers) -or
          ((-not $_.IPv4Gateway) -and (-not $_.IPv6Gateway))
        }
      )
      if ($issues.Count -eq 0) {
        Write-ConsoleLine -Text "No obvious issues detected (missing DNS and/or gateway)." -Color Green -Config $RunState.config
      } else {
        Write-ConsoleLine -Text ("Potential issues: {0} interface(s) missing DNS and/or gateway" -f $issues.Count) -Color Yellow -Config $RunState.config
        $issueRows = @($issues | Select-Object InterfaceAlias, InterfaceIndex, IPv4Address, IPv6Address, IPv4Gateway, IPv6Gateway, DnsServers)
        $issuesText = To-ConsoleTableText -InputObjects $issueRows -Width $RunState.config.ConsoleWidthHint
        if ($RunState.config.ConsoleUseInformation) { Write-Information -InformationAction Continue -MessageData $issuesText }
        else { Write-UiLine $issuesText }
      }
    }
}

function Invoke-Capability29MainPhase05 {
  param([hashtable]$RunState)
  if (-not $Quiet -and $RunState.config.ConsoleSummary) {
    . Invoke-Capability29MainPhase05Step01 -RunState $RunState
. Invoke-Capability29MainPhase05Step02 -RunState $RunState
  }
}
function Invoke-Capability29MainPhase06 {
  param([hashtable]$RunState)
  $RunState.result = [pscustomobject]@{
    Summary    = $summary
    Interfaces = $RunState.interfaces
  }

  $RunState.issueInterfaces = @($RunState.interfaces | Where-Object {
    (-not $_.DnsServers) -or ((-not $_.IPv4Gateway) -and (-not $_.IPv6Gateway))
  })
}
function Invoke-Capability29MainPhase07 {
  param([hashtable]$RunState)
  foreach ($iface in $RunState.issueInterfaces) {
    $issueType = @()
    if (-not $iface.DnsServers) { $issueType += 'missing DNS' }
    if (-not $iface.IPv4Gateway -and -not $iface.IPv6Gateway) { $issueType += 'missing gateway' }
    Add-Finding -FindingList $script:Findings -Code 'NET-InterfaceIssue' -Severity 'Medium' `
      -Message ("Interface '{0}' has {1}" -f $iface.InterfaceAlias, ($issueType -join ' and ')) `
      -Extra @{ InterfaceAlias = $iface.InterfaceAlias; InterfaceIndex = $iface.InterfaceIndex; IPv4Address = $iface.IPv4Address; DnsServers = $iface.DnsServers }
  }
}
function Invoke-Capability29Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation, [hashtable]$RunState)
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability29MainPhase01 -RunState $RunState
  . Invoke-Capability29MainPhase02 -RunState $RunState
  . Invoke-Capability29MainPhase03 -RunState $RunState
  . Invoke-Capability29MainPhase04 -RunState $RunState
  . Invoke-Capability29MainPhase05 -RunState $RunState
  . Invoke-Capability29MainPhase06 -RunState $RunState
  . Invoke-Capability29MainPhase07 -RunState $RunState
}
. Invoke-Capability29Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation -RunState $RunState

# V2 output contract
function Get-Capability29ResultToken {
  $resultToken = if ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
  if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
  return $resultToken
}
$resultToken = Get-Capability29ResultToken
$v2Result = Get-V2ResultObject -ScriptName '29-Network-Config-Audit.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $RunState.result.Summary -Metadata @{ Interfaces = $RunState.result.Interfaces }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
