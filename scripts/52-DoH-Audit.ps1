#requires -version 5.1
<#
.SYNOPSIS
Audit Windows DNS-over-HTTPS (DoH) client configuration.

.DESCRIPTION
Checks the Windows DNS client DoH settings in the registry, verifies that DoH
server endpoints are configured, audits whether plaintext DNS fallback is permitted,
and validates configured resolvers against a list of known DoH-capable servers.

Findings:
- FAIL if DoH is explicitly disabled and plaintext DNS fallback is unrestricted.
- WARN if DoH is not configured (EnableAutoDoh absent or 0).
- WARN if a configured DoH name server is not a known DoH-capable resolver.
- INFO when DoH is enabled and resolvers are recognized.

Pipeline output: structured objects only.
Console output: Write-UiLine / Write-Information only.

.PARAMETER Mode
Audit mode.

.PARAMETER ConfigPath
Path to JSON configuration file.

.PARAMETER OutputFormat
Console, Json, Csv, or None.

.PARAMETER OutputPath
Path for Json/Csv output.

.PARAMETER PassThru
Emit standardized v2 result object.

.PARAMETER Strict
Treat warnings as failures.

.PARAMETER Quiet
Suppress console output.

.PARAMETER NoColor
Disable colored output.

.OUTPUTS
None by default.
When -PassThru is used, emits a PSCustomObject v2 result with ScriptName, Mode,
Result, Findings, Summary, and Metadata properties.

.EXAMPLE
.\scripts\52-DoH-Audit.ps1

.EXAMPLE
.\scripts\52-DoH-Audit.ps1 -OutputFormat Json -OutputPath .\reports\doh.json -PassThru
#>

[CmdletBinding()]
param(
  [ValidateSet('Audit')]
  [string]$Mode = 'Audit',

  [string]$ConfigPath,

  [ValidateSet('Console','Json','Csv','None')]
  [string]$OutputFormat = 'Console',

  [string]$OutputPath,

  [switch]$PassThru,

  [switch]$Strict,

  [switch]$Quiet,

  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1')        -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1')       -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1')       -Force
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force

Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '52-DoH-Audit.ps1' -BoundParameters $PSBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
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
  $result = Get-V2ResultObject -ScriptName '52-DoH-Audit.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() `
    -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# ----------------------------
# Constants
# ----------------------------

function Invoke-Capability52MainPhase01 {
  param([hashtable]$RunState)
  $script:DnsCacheParams = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'

  # Well-known DoH-capable resolvers (IP addresses as registered with Windows DoH template list)
  $script:KnownDohResolvers = @(
    '1.1.1.1',        # Cloudflare
    '1.0.0.1',        # Cloudflare secondary
    '2606:4700:4700::1111', # Cloudflare IPv6
    '2606:4700:4700::1001', # Cloudflare IPv6 secondary
    '8.8.8.8',        # Google
    '8.8.4.4',        # Google secondary
    '2001:4860:4860::8888', # Google IPv6
    '2001:4860:4860::8844', # Google IPv6 secondary
    '9.9.9.9',        # Quad9
    '149.112.112.112',# Quad9 secondary
    '2620:fe::fe',    # Quad9 IPv6
    '2620:fe::9',     # Quad9 IPv6 secondary
    '208.67.222.222', # OpenDNS
    '208.67.220.220'  # OpenDNS secondary
  )

  # EnableAutoDoh values:
  # 0 = DoH disabled
  # 1 = DoH enabled, use IETF DoH
  # 2 = DoH enabled automatically when resolver supports it
  $script:DoHModeMap = @{
    0 = 'Disabled'
    1 = 'Enabled (Explicit)'
    2 = 'Enabled (Automatic)'
  }

  # ----------------------------
  # Main
  # ----------------------------

  $script:Findings = Get-FindingsList

  $RunState.enableAutoDoh          = $null
  $RunState.dohModeLabel           = 'NotConfigured'
  $RunState.dohNameServers         = @()
  $RunState.dohBootstrapAddresses  = @()
  $RunState.unknownResolvers       = @()

  # 1. Read EnableAutoDoh
  try {
    $RunState.enableAutoDoh = Get-RegValue -Path $script:DnsCacheParams -Name 'EnableAutoDoh' -ErrorAction SilentlyContinue
  } catch {
    $RunState.enableAutoDoh = $null
  }
}
function Invoke-Capability52MainPhase02 {
  param([hashtable]$RunState)
  if ($null -eq $RunState.enableAutoDoh) {
    $RunState.dohModeLabel = 'NotConfigured'
    Add-Finding -FindingList $script:Findings -Code 'DOH-NotConfigured' -Severity 'Medium' `
      -Message 'EnableAutoDoh registry value is absent. DoH is not explicitly configured; the DNS client may use plaintext DNS.'
  } else {
    $RunState.dohModeLabel = $script:DoHModeMap[[int]$RunState.enableAutoDoh]
    if (-not $RunState.dohModeLabel) { $RunState.dohModeLabel = "Unknown($($RunState.enableAutoDoh))" }

    switch ([int]$RunState.enableAutoDoh) {
      0 {
        Add-Finding -FindingList $script:Findings -Code 'DOH-Disabled' -Severity 'High' `
          -Message 'DoH is explicitly disabled (EnableAutoDoh=0). All DNS queries use plaintext UDP/TCP.'
      }
      1 {
        Add-Finding -FindingList $script:Findings -Code 'DOH-EnabledExplicit' -Severity 'Low' `
          -Message 'DoH is enabled with explicit server configuration (EnableAutoDoh=1).'
      }
      2 {
        Add-Finding -FindingList $script:Findings -Code 'DOH-EnabledAutomatic' -Severity 'Low' `
          -Message 'DoH is enabled automatically for supported resolvers (EnableAutoDoh=2).'
      }
      default {
        Add-Finding -FindingList $script:Findings -Code 'DOH-UnknownValue' -Severity 'Medium' `
          -Message ("EnableAutoDoh has an unexpected value: {0}." -f $RunState.enableAutoDoh)
      }
    }
  }
}
function Invoke-Capability52MainPhase03 {
  param([hashtable]$RunState)
  try {
    $rawServers = Get-RegValue -Path $script:DnsCacheParams -Name 'DohNameServers' -ErrorAction SilentlyContinue
    if ($null -ne $rawServers) {
      # Multi-string or space/newline-separated
      $RunState.dohNameServers = @($rawServers -split '[\r\n\s]+' | Where-Object { $_ -ne '' })

      foreach ($server in $RunState.dohNameServers) {
        if ($server -notin $script:KnownDohResolvers) {
          $RunState.unknownResolvers += $server
          Add-Finding -FindingList $script:Findings -Code 'DOH-UnknownResolver' -Severity 'Medium' `
            -Message ("DoH name server '{0}' is not in the list of known DoH-capable resolvers. Verify this is an authorized resolver." -f $server)
        } else {
          Add-Finding -FindingList $script:Findings -Code 'DOH-KnownResolver' -Severity 'Low' `
            -Message ("DoH name server '{0}' is a known DoH-capable resolver." -f $server)
        }
      }
    } else {
      if ($null -ne $RunState.enableAutoDoh -and [int]$RunState.enableAutoDoh -eq 1) {
        Add-Finding -FindingList $script:Findings -Code 'DOH-NoServersConfigured' -Severity 'High' `
          -Message 'DoH is set to explicit mode (EnableAutoDoh=1) but DohNameServers is not configured. DoH may not function.'
      }
    }
  } catch {
    Add-Finding -FindingList $script:Findings -Code 'DOH-ServerQueryFailed' -Severity 'Low' `
      -Message ("Could not query DohNameServers: {0}" -f $_.Exception.Message)
  }
}
function Invoke-Capability52MainPhase04 {
  param([hashtable]$RunState)
  try {
    $bootstrapRaw = Get-RegValue -Path $script:DnsCacheParams -Name 'ServerAddresses' -ErrorAction SilentlyContinue
    if ($null -ne $bootstrapRaw) {
      $RunState.dohBootstrapAddresses = @($bootstrapRaw -split '[\r\n\s]+' | Where-Object { $_ -ne '' })
    }
  } catch {
    Write-Verbose ("DoH bootstrap address query failed: {0}" -f $_.Exception.Message)
  }
}
function Invoke-Capability52MainPhase05 {
  param([hashtable]$RunState)
  try {
    $autoDohMode = if ($null -ne $RunState.enableAutoDoh) { [int]$RunState.enableAutoDoh } else { -1 }
    if ($autoDohMode -gt 0 -and $RunState.dohNameServers.Count -gt 0) {
      # DoH is configured; check whether fallback is restricted.
      $blockFallback = Get-RegValue -Path $script:DnsCacheParams -Name 'BlockUntrustedDoh' -ErrorAction SilentlyContinue
      if ($null -eq $blockFallback -or [int]$blockFallback -ne 1) {
        Add-Finding -FindingList $script:Findings -Code 'DOH-FallbackAllowed' -Severity 'Medium' `
          -Message 'DoH is configured but BlockUntrustedDoh is not set to 1. Plaintext DNS fallback may be permitted.'
      } else {
        Add-Finding -FindingList $script:Findings -Code 'DOH-FallbackBlocked' -Severity 'Low' `
          -Message 'BlockUntrustedDoh=1: plaintext DNS fallback is prohibited when DoH fails.'
      }
    }
  } catch {
    Write-Verbose ("DoH plaintext fallback query failed: {0}" -f $_.Exception.Message)
  }
}
function Invoke-Capability52MainPhase06 {
  param([hashtable]$RunState)
  $Findings = @($script:Findings.ToArray())
  $findingsCount = @($Findings).Count

  $RunState.summary = [pscustomobject]@{
    ComputerName           = $env:COMPUTERNAME
    Timestamp              = Get-Date
    Mode                   = $Mode
    DoHMode                = $RunState.dohModeLabel
    EnableAutoDoh          = $RunState.enableAutoDoh
    ConfiguredServers      = $RunState.dohNameServers.Count
    UnknownResolvers       = $RunState.unknownResolvers.Count
    BootstrapAddresses     = $RunState.dohBootstrapAddresses.Count
    FindingsCount          = $findingsCount
  }

  if (-not $Quiet -and $OutputFormat -eq 'Console') {
    Write-Section -Title 'DNS-over-HTTPS (DoH) Audit'
    Write-KeyValue -Key 'DoHMode'           -Value $RunState.dohModeLabel
    Write-KeyValue -Key 'ConfiguredServers' -Value ([string]$RunState.dohNameServers.Count)
    Write-KeyValue -Key 'UnknownResolvers'  -Value ([string]$RunState.unknownResolvers.Count)
    Write-KeyValue -Key 'Findings'          -Value ([string]$findingsCount)
  }

  $RunState.highFindings = @($Findings | Where-Object { $_.Severity -eq 'High' })
}
function Invoke-Capability52Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation)
  $RunState = @{

  }
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability52MainPhase01 -RunState $RunState
  . Invoke-Capability52MainPhase02 -RunState $RunState
  . Invoke-Capability52MainPhase03 -RunState $RunState
  . Invoke-Capability52MainPhase04 -RunState $RunState
  . Invoke-Capability52MainPhase05 -RunState $RunState
  . Invoke-Capability52MainPhase06 -RunState $RunState
  $script:RunState = $RunState
}

. Invoke-Capability52Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation
function Get-Capability52ResultToken {
  param([hashtable]$RunState)
  $resultToken  = if ($Strict -and $findingsCount -gt 0) { 'FAIL' }
    elseif ($RunState.highFindings.Count -gt 0) { 'FAIL' }
    elseif ($findingsCount -gt 0) { 'WARN' }
    else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability52ResultToken -RunState $RunState
$v2Result = Get-V2ResultObject -ScriptName '52-DoH-Audit.ps1' -Mode $Mode `
  -Result $resultToken -Findings $Findings -Summary $RunState.summary `
  -Metadata @{ UnknownResolvers = $RunState.unknownResolvers; DohNameServers = $RunState.dohNameServers }

Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
