#requires -version 5.1
<#
.SYNOPSIS
  Audits installed Windows software against a JSON-based whitelist/blacklist catalog and returns a structured audit result.

.DESCRIPTION
  This script builds a software inventory by reading the Uninstall registry locations (machine-wide 64-bit/32-bit and per-user). 
  The inventory is evaluated against a catalog that contains regex-based allow/deny rules for software names and (optionally) vendors/publishers. 
  The script prints a colorized, sectioned console report using host output only and emits exactly one structured object to the pipeline for filtering, export, or JSON serialization.

  Catalog loading order:
  1) -CatalogPath (explicit)
  2) -ConfigPath (reads Software.CatalogPath)
  3) Embedded default catalog (conservative baseline)
  4) Empty catalog (no rules) 

  Result classification:
  - Whitelisted: matches at least one whitelist rule
  - Blacklisted: matches at least one blacklist rule
  - Unknown: matches neither list 

  Exit codes:
  - 0 = OK (EventId 4900): no unknown and no blacklisted entries
  - 2 = WARN (EventId 4901): unknown entries or catalog warnings exist
  - 1 = FAIL (EventId 4902): blacklisted entries exist, or a runtime error occurred

.PARAMETER CatalogPath
  Path to a JSON catalog file containing Whitelist and/or Blacklist rule arrays. 
  When provided, this takes precedence over any catalog path found in -ConfigPath. 

  Expected JSON shape (example):
  {
    "Whitelist": [ { "NameRegex": "regex", "VendorRegex": "regex" } ],
    "Blacklist": [ { "NameRegex": "regex", "VendorRegex": "regex" } ]
  } 

  Rules are evaluated using regex matching:
  - NameRegex matches the installed software display name.
  - VendorRegex matches the installed software publisher (optional; empty means "ignore vendor"). 

.PARAMETER ConfigPath
  Path to a JSON configuration file used to discover the catalog path when -CatalogPath is not provided. 
  The script reads Software.CatalogPath from this file (if present) and tries to load the catalog from that location. 

.PARAMETER StatePath
  Path to write the proof/state JSON output (the complete structured result object). 
  If empty string is supplied, writing the proof JSON is disabled. 
  When enabled, the script creates the destination directory if needed. 

.PARAMETER Strict
  Switch that enforces stricter compliance behavior. 
  When set, any drift (Unknown or Blacklisted) results in a non-zero exit code, and Blacklisted always results in Error. 

.INPUTS
  None. 


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER PassThru
  Emit structured v2 result object to pipeline.

.PARAMETER Quiet
  Suppress console output.

.PARAMETER NoColor
  Disable colored output.

.OUTPUTS
  System.Management.Automation.PSCustomObject. 
  The script outputs exactly one object with high-level metadata, counts, status, and the full classified software lists (Whitelisted/Unknown/Blacklisted), designed to work cleanly with the pipeline. 

.EXAMPLE
  PS> .\19-Software-Audit.ps1
  Runs the audit using the embedded default catalog (unless ConfigPath points to a valid catalog) and prints the console report. 

.EXAMPLE
  PS> .\19-Software-Audit.ps1 -CatalogPath $CatalogPath
  Runs the audit with an explicit catalog file. 

.EXAMPLE
  PS> .\19-Software-Audit.ps1 -ConfigPath $ConfigPath
  Runs the audit and loads the catalog path from Software.CatalogPath in the config file. 

.EXAMPLE
  PS> .\19-Software-Audit.ps1 -StatePath $StatePath
  Runs the audit and writes the full result object as proof JSON to the specified path. 

.EXAMPLE
  PS> .\19-Software-Audit.ps1 -StatePath ""
  Runs the audit without writing any proof JSON file. 

.EXAMPLE
  PS> $r = .\19-Software-Audit.ps1; $r.Unknown | Select-Object Name, Version, Publisher
  Captures the structured result object and inspects unknown software entries using normal pipeline operations. 

.EXAMPLE
  PS> .\19-Software-Audit.ps1 | ConvertTo-Json -Depth 7
  Serializes the structured result object to JSON in the pipeline (useful for integrations). 

.EXAMPLE
  PS> .\19-Software-Audit.ps1 | Select-Object -ExpandProperty Blacklisted | Export-Csv $OutputPath -NoTypeInformation
  Exports only blacklisted entries to CSV. 

.NOTES
  The console output is intended for humans and is emitted via host output; it is not part of the pipeline output. 
  Event logging is best-effort: when the event source is not available, the script writes a fallback log line to a text file. 
  Catalog rules use regex matching; invalid regex patterns can cause evaluation errors and should be tested before deployment. 
#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$CatalogPath,
  [string]$StatePath,
  [switch]$Strict,
  [string]$ConfigPath

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Quiet,
  [switch]$NoColor
)

function Get-SoftwareAuditUnsupportedSummary {
  param([string]$Mode)
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  return $summary
}

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'JsonCatalog.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '19-Software-Audit.ps1' -BoundParameters $PSBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'
$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $summary = Get-SoftwareAuditUnsupportedSummary -Mode $Mode
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '19-Software-Audit.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

$softwareAuditHelperPath = Join-Path $PSScriptRoot 'internal/19-Software-Audit.helpers.ps1'
. $softwareAuditHelperPath


# -------------------- Settings --------------------
$Script:EventLogName     = 'Application'
$Script:EventSourceName  = 'Software-Audit'
if ([string]::IsNullOrWhiteSpace($StatePath)) { $StatePath = Join-Path ([System.IO.Path]::GetTempPath()) 'sw-inventory.json' }
$Script:FallbackEventLog = Join-Path ([System.IO.Path]::GetTempPath()) 'sw-inventory.eventlog-fallback.txt'

$Script:DefaultCatalogJson = @"
{
  "Whitelist": [
    { "NameRegex": "^(Microsoft Edge|Microsoft.*Update|PowerShell|Windows PowerShell)", "VendorRegex": "" },
    { "NameRegex": "Visual C..Redistributable", "VendorRegex": "" }
  ],
  "Blacklist": [
    { "NameRegex": "(?i)(teamviewer|anydesk|ultravnc|tightvnc|wireshark|nmap|tor|metasploit)", "VendorRegex": "" }
  ]
}
"@

$completion = Invoke-SoftwareAudit -CatalogPathProvided:$PSBoundParameters.ContainsKey('CatalogPath') -ConfigPathProvided:$PSBoundParameters.ContainsKey('ConfigPath')
$resultToken = $completion.ResultToken
$v2Result = Get-V2ResultObject -ScriptName '19-Software-Audit.ps1' -Mode $Mode -Result $resultToken -Findings @($completion.Findings) -Summary $completion.Summary -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
