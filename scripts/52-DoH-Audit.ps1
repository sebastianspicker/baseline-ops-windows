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
.\52-DoH-Audit.ps1

.EXAMPLE
.\52-DoH-Audit.ps1 -OutputFormat Json -OutputPath C:\Temp\doh.json -PassThru
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
Initialize-V2Context -BoundParameters $PSBoundParameters
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
  $result = New-V2ResultObject -ScriptName '52-DoH-Audit.ps1' -Mode $Mode -Result 'OK' -Findings @() `
    -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

# ----------------------------
# Constants
# ----------------------------

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

$script:Findings = New-FindingsList

$enableAutoDoh          = $null
$dohModeLabel           = 'NotConfigured'
$dohNameServers         = @()
$dohBootstrapAddresses  = @()
$unknownResolvers       = @()

# 1. Read EnableAutoDoh
try {
  $enableAutoDoh = Get-RegValue -Path $script:DnsCacheParams -Name 'EnableAutoDoh' -ErrorAction SilentlyContinue
} catch {
  $enableAutoDoh = $null
}

if ($null -eq $enableAutoDoh) {
  $dohModeLabel = 'NotConfigured'
  Add-Finding -FindingList $script:Findings -Code 'DOH-NotConfigured' -Severity 'Medium' `
    -Message 'EnableAutoDoh registry value is absent. DoH is not explicitly configured; the DNS client may use plaintext DNS.'
} else {
  $dohModeLabel = $script:DoHModeMap[[int]$enableAutoDoh]
  if (-not $dohModeLabel) { $dohModeLabel = "Unknown($enableAutoDoh)" }

  switch ([int]$enableAutoDoh) {
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
        -Message ("EnableAutoDoh has an unexpected value: {0}." -f $enableAutoDoh)
    }
  }
}

# 2. Read configured DoH name servers
try {
  $rawServers = Get-RegValue -Path $script:DnsCacheParams -Name 'DohNameServers' -ErrorAction SilentlyContinue
  if ($null -ne $rawServers) {
    # Multi-string or space/newline-separated
    $dohNameServers = @($rawServers -split '[\r\n\s]+' | Where-Object { $_ -ne '' })

    foreach ($server in $dohNameServers) {
      if ($server -notin $script:KnownDohResolvers) {
        $unknownResolvers += $server
        Add-Finding -FindingList $script:Findings -Code 'DOH-UnknownResolver' -Severity 'Medium' `
          -Message ("DoH name server '{0}' is not in the list of known DoH-capable resolvers. Verify this is an authorized resolver." -f $server)
      } else {
        Add-Finding -FindingList $script:Findings -Code 'DOH-KnownResolver' -Severity 'Low' `
          -Message ("DoH name server '{0}' is a known DoH-capable resolver." -f $server)
      }
    }
  } else {
    if ($null -ne $enableAutoDoh -and [int]$enableAutoDoh -eq 1) {
      Add-Finding -FindingList $script:Findings -Code 'DOH-NoServersConfigured' -Severity 'High' `
        -Message 'DoH is set to explicit mode (EnableAutoDoh=1) but DohNameServers is not configured. DoH may not function.'
    }
  }
} catch {
  Add-Finding -FindingList $script:Findings -Code 'DOH-ServerQueryFailed' -Severity 'Low' `
    -Message ("Could not query DohNameServers: {0}" -f $_.Exception.Message)
}

# 3. Check DoH bootstrap addresses (per-adapter or global fallback)
try {
  $bootstrapRaw = Get-RegValue -Path $script:DnsCacheParams -Name 'ServerAddresses' -ErrorAction SilentlyContinue
  if ($null -ne $bootstrapRaw) {
    $dohBootstrapAddresses = @($bootstrapRaw -split '[\r\n\s]+' | Where-Object { $_ -ne '' })
  }
} catch {
  # Non-critical; not all environments configure bootstrap addresses
}

# 4. Check if plaintext fallback is explicitly prohibited
try {
  $autoDohMode = if ($null -ne $enableAutoDoh) { [int]$enableAutoDoh } else { -1 }
  if ($autoDohMode -gt 0 -and $dohNameServers.Count -gt 0) {
    # DoH is configured — check if fallback is restricted
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
  # Non-critical check
}

# ----------------------------
# Build summary & result
# ----------------------------

$Findings = @($script:Findings.ToArray())
$findingsCount = @($Findings).Count

$summary = [pscustomobject]@{
  ComputerName           = $env:COMPUTERNAME
  Timestamp              = Get-Date
  Mode                   = $Mode
  DoHMode                = $dohModeLabel
  EnableAutoDoh          = $enableAutoDoh
  ConfiguredServers      = $dohNameServers.Count
  UnknownResolvers       = $unknownResolvers.Count
  BootstrapAddresses     = $dohBootstrapAddresses.Count
  FindingsCount          = $findingsCount
}

if (-not $Quiet -and $OutputFormat -eq 'Console') {
  Write-Section -Title 'DNS-over-HTTPS (DoH) Audit'
  Write-KeyValue -Key 'DoHMode'           -Value $dohModeLabel
  Write-KeyValue -Key 'ConfiguredServers' -Value ([string]$dohNameServers.Count)
  Write-KeyValue -Key 'UnknownResolvers'  -Value ([string]$unknownResolvers.Count)
  Write-KeyValue -Key 'Findings'          -Value ([string]$findingsCount)
}

$highFindings = @($Findings | Where-Object { $_.Severity -eq 'High' })
$resultToken  = if ($Strict -and $findingsCount -gt 0) { 'FAIL' }
  elseif ($highFindings.Count -gt 0) { 'FAIL' }
  elseif ($findingsCount -gt 0) { 'WARN' }
  else { 'OK' }

$v2Result = New-V2ResultObject -ScriptName '52-DoH-Audit.ps1' -Mode $Mode `
  -Result $resultToken -Findings $Findings -Summary $summary `
  -Metadata @{ UnknownResolvers = $unknownResolvers; DohNameServers = $dohNameServers }

Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
