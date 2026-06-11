#requires -version 5.1
<#
.SYNOPSIS
  Audits installed Windows software against a JSON-based whitelist/blacklist catalog and returns a structured audit result.

.DESCRIPTION
  This script builds a software inventory by reading the Uninstall registry locations (machine-wide 64-bit/32-bit and per-user). 
  The inventory is evaluated against a catalog that contains regex-based allow/deny rules for software names and (optionally) vendors/publishers. 
  The script prints a human-friendly console report (colors, sections, top lists) using host output only, and emits exactly one structured object to the pipeline for further processing (e.g., filtering, exporting, or JSON serialization). 

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
  - 1 = Warning (EventId 4901): unknown entries exist (and none are blacklisted)
  - 2 = Error (EventId 4902): blacklisted entries exist, or a runtime error occurred 

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
  PS> .\19-Software-Audit.ps1 -CatalogPath "PATH/TO/JSON/catalog.json"
  Runs the audit with an explicit catalog file. 

.EXAMPLE
  PS> .\19-Software-Audit.ps1 -ConfigPath "PATH/TO/JSON/config.json"
  Runs the audit and loads the catalog path from Software.CatalogPath in the config file. 

.EXAMPLE
  PS> .\19-Software-Audit.ps1 -StatePath "PATH/TO/PROOF/sw-inventory.json"
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
  PS> .\19-Software-Audit.ps1 | Select-Object -ExpandProperty Blacklisted | Export-Csv "PATH/TO/PROOF/blacklisted.csv" -NoTypeInformation
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

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'JsonCatalog.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
Initialize-V2Context -ScriptName '19-Software-Audit.ps1' -BoundParameters $PSBoundParameters
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
  $result = Get-V2ResultObject -ScriptName '19-Software-Audit.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

# -------------------- Settings --------------------
$Script:EventLogName     = 'Application'
$Script:EventSourceName  = 'Software-Audit'
if ([string]::IsNullOrWhiteSpace($StatePath)) {
  $StatePath = Join-Path ([System.IO.Path]::GetTempPath()) 'sw-inventory.json'
}
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

# -------------------- Helpers: safe property access --------------------
function Test-HasProperty {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]$Object,
    [Parameter(Mandatory=$true)][string]$Name
  )
  if (-not $Object) { return $false }
  return ($Object.PSObject.Properties.Match($Name).Count -gt 0)
}

function Get-PropString {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]$Object,
    [Parameter(Mandatory=$true)][string]$Name
  )
  if (-not (Test-HasProperty -Object $Object -Name $Name)) { return '' }
  return [string]$Object.$Name
}

function Get-PropInt {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]$Object,
    [Parameter(Mandatory=$true)][string]$Name,
    [int]$Default = 0
  )
  if (-not (Test-HasProperty -Object $Object -Name $Name)) { return $Default }
  try { return [int]$Object.$Name } catch { return $Default }
}

# -------------------- Helpers: filesystem + JSON --------------------

# Read-JsonFile replaced by Read-JsonFileSafe from lib/JsonCatalog.psm1

function ConvertFrom-JsonSafe {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$Json)

  try {
    if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
    $Json | ConvertFrom-Json -ErrorAction Stop
  } catch {
    return $null
  }
}

# -------------------- Catalog --------------------
function Get-CatalogWrapper {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$Source,
    [Parameter(Mandatory=$true)][bool]$Loaded,
    $CatalogObject,
    [object[]]$Issues = @(),
    [object[]]$Attempts = @()
  )

  $wl = @()
  $bl = @()

  if ($CatalogObject -and $CatalogObject.PSObject -and $CatalogObject.PSObject.Properties) {
    if ($CatalogObject.PSObject.Properties.Match('Whitelist').Count -gt 0 -and $CatalogObject.Whitelist) { $wl = @($CatalogObject.Whitelist) }
    if ($CatalogObject.PSObject.Properties.Match('Blacklist').Count -gt 0 -and $CatalogObject.Blacklist) { $bl = @($CatalogObject.Blacklist) }
  }

  if ($null -eq $wl) { $wl = @() }
  if ($null -eq $bl) { $bl = @() }

  [pscustomobject]@{
    Meta      = [pscustomobject]@{ Source = $Source; Loaded = $Loaded; Issues = @($Issues); Attempts = @($Attempts) }
    Whitelist = @($wl)
    Blacklist = @($bl)
  }
}

function Get-CatalogLoadIssue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$Kind,
    [Parameter(Mandatory=$true)]$Meta
  )

  [pscustomobject]@{
    Kind   = $Kind
    Path   = $Meta.Path
    Status = $Meta.Status
    Error  = $Meta.Error
  }
}

function Load-Catalog {
  [CmdletBinding()]
  param(
    [string]$CatalogPath,
    [string]$ConfigPath,
    [bool]$CatalogPathProvided,
    [bool]$ConfigPathProvided
  )

  $issues = @()
  $attempts = @()

  if (-not [string]::IsNullOrWhiteSpace($CatalogPath)) {
    $catLoad = Read-JsonFileWithStatus -Path $CatalogPath
    $attempts += [pscustomobject]@{ Kind = 'CatalogPath'; Meta = $catLoad.Meta }
    if ($catLoad.Meta.Loaded) { return (Get-CatalogWrapper -Source 'CatalogPath' -Loaded $true -CatalogObject $catLoad.Data -Issues $issues -Attempts $attempts) }
    if ($CatalogPathProvided) { $issues += (Get-CatalogLoadIssue -Kind 'CatalogPath' -Meta $catLoad.Meta) }
  }

  if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
    $cfgLoad = Read-JsonFileWithStatus -Path $ConfigPath
    $attempts += [pscustomobject]@{ Kind = 'ConfigPath'; Meta = $cfgLoad.Meta }
    $cfg = $cfgLoad.Data
    if ($ConfigPathProvided -and -not $cfgLoad.Meta.Loaded) { $issues += (Get-CatalogLoadIssue -Kind 'ConfigPath' -Meta $cfgLoad.Meta) }
    if ($cfg -and (Test-HasProperty $cfg 'Software') -and $cfg.Software -and (Test-HasProperty $cfg.Software 'CatalogPath')) {
      $p = [string]$cfg.Software.CatalogPath
      if (-not [string]::IsNullOrWhiteSpace($p)) {
        $catLoad = Read-JsonFileWithStatus -Path $p
        $attempts += [pscustomobject]@{ Kind = 'ConfigPath:Software.CatalogPath'; Meta = $catLoad.Meta }
        if ($catLoad.Meta.Loaded) { return (Get-CatalogWrapper -Source 'ConfigPath:Software.CatalogPath' -Loaded $true -CatalogObject $catLoad.Data -Issues $issues -Attempts $attempts) }
        $issues += (Get-CatalogLoadIssue -Kind 'ConfigPath:Software.CatalogPath' -Meta $catLoad.Meta)
      }
    }
  }

  $fallback = ConvertFrom-JsonSafe -Json $Script:DefaultCatalogJson
  if ($fallback) { return (Get-CatalogWrapper -Source 'EmbeddedDefault' -Loaded $true -CatalogObject $fallback -Issues $issues -Attempts $attempts) }

  Get-CatalogWrapper -Source 'EmptyFallback' -Loaded $false -CatalogObject $null -Issues $issues -Attempts $attempts
}

# -------------------- Event logging (best effort) --------------------


# -------------------- Inventory (pipeline-friendly) --------------------
function Get-InstalledSoftware {
  [CmdletBinding()]
  param()

  $paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
  )

  $items = @()

  foreach ($p in $paths) {
    $subKeys = Get-ChildItem -Path $p -ErrorAction SilentlyContinue
    foreach ($sk in $subKeys) {
      $v = Get-ItemProperty -Path $sk.PSPath -ErrorAction SilentlyContinue
      if (-not $v) { continue }

      if (-not (Test-HasProperty -Object $v -Name 'DisplayName')) { continue }
      $displayName = Get-PropString -Object $v -Name 'DisplayName'
      if ([string]::IsNullOrWhiteSpace($displayName)) { continue }

      $systemComponent = Get-PropInt -Object $v -Name 'SystemComponent' -Default 0
      if ($systemComponent -eq 1) { continue }

      $parentKeyName = Get-PropString -Object $v -Name 'ParentKeyName'
      if (-not [string]::IsNullOrWhiteSpace($parentKeyName)) { continue }

      $releaseType = Get-PropString -Object $v -Name 'ReleaseType'
      if (-not [string]::IsNullOrWhiteSpace($releaseType) -and ($releaseType -match 'Update|Hotfix|Security Update')) { continue }

      $items += [pscustomobject]@{
        Name            = $displayName
        Version         = Get-PropString -Object $v -Name 'DisplayVersion'
        Publisher       = Get-PropString -Object $v -Name 'Publisher'
        UninstallString = Get-PropString -Object $v -Name 'UninstallString'
        InstallDate     = Get-PropString -Object $v -Name 'InstallDate'
        Key             = [string]$sk.PSChildName
        HivePath        = [string]$p
        Source          = 'Registry'
      }
    }
  }

  $dedup = @{}
  foreach ($it in $items) {
    $k = ("{0}||{1}||{2}" -f $it.Name, $it.Version, $it.Publisher)
    if (-not $dedup.ContainsKey($k)) { $dedup[$k] = $it }
  }

  $dedup.Values | Sort-Object Name, Version
}

# -------------------- Compliance evaluation (pipeline-friendly) --------------------
function Test-SoftwareCompliance {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]$Inventory,
    [Parameter(Mandatory=$true)]$Catalog
  )

  $whitelist = @($Catalog.Whitelist)
  $blacklist = @($Catalog.Blacklist)

  $BLHits  = @()
  $WLHits  = @()
  $Unknown = @()

  foreach ($sw in $Inventory) {
    $name = [string]$sw.Name
    $pub  = [string]$sw.Publisher

    $WLMatch = $false
    foreach ($w in $whitelist) {
      $nr = [string]$w.NameRegex
      $vr = [string]$w.VendorRegex
      $nOk = ([string]::IsNullOrWhiteSpace($nr)) -or ($name -match $nr)
      $pOk = ([string]::IsNullOrWhiteSpace($vr)) -or ($pub  -match $vr)
      if ($nOk -and $pOk) { $WLMatch = $true; break }
    }

    $BLMatch = $false
    foreach ($b in $blacklist) {
      $nr = [string]$b.NameRegex
      $vr = [string]$b.VendorRegex
      $nOk = ([string]::IsNullOrWhiteSpace($nr)) -or ($name -match $nr)
      $pOk = ([string]::IsNullOrWhiteSpace($vr)) -or ($pub  -match $vr)
      if ($nOk -and $pOk) { $BLMatch = $true; break }
    }

    if ($BLMatch)      { $BLHits  += $sw }
    elseif ($WLMatch)  { $WLHits  += $sw }
    else               { $Unknown += $sw }
  }

  [pscustomobject]@{
    Blacklisted = @($BLHits)
    Whitelisted = @($WLHits)
    Unknown     = @($Unknown)
  }
}

function Get-AuditStatus {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][int]$BlacklistedCount,
    [Parameter(Mandatory=$true)][int]$UnknownCount,
    [int]$ConfigIssueCount = 0,
    [switch]$Strict
  )

  $eventId = 4900
  $level   = 'Information'

  if ($BlacklistedCount -gt 0) {
    $eventId = 4902; $level = 'Error'
  } elseif ($UnknownCount -gt 0 -or $ConfigIssueCount -gt 0) {
    $eventId = 4901; $level = 'Warning'
  }

  if ($Strict -and ($BlacklistedCount -gt 0 -or $UnknownCount -gt 0)) {
    if ($BlacklistedCount -gt 0) { $eventId = 4902; $level = 'Error' }
    else                         { $eventId = 4901; $level = 'Warning' }
  }

  [pscustomobject]@{
    EventId = [int]$eventId
    Level   = [string]$level
  }
}

function Get-SummaryLines {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][int]$Total,
    [Parameter(Mandatory=$true)][int]$Whitelisted,
    [Parameter(Mandatory=$true)][int]$Unknown,
    [Parameter(Mandatory=$true)][int]$Blacklisted,
    [Parameter(Mandatory=$true)]$Audit
  )

  $lines = @()
  $lines += ("Total={0}; Whitelisted={1}; Unknown={2}; Blacklisted={3}" -f $Total, $Whitelisted, $Unknown, $Blacklisted)

  if ($Blacklisted -gt 0) {
    $names = (@($Audit.Blacklisted) | Select-Object -ExpandProperty Name | Sort-Object)
    $lines += ("Blacklisted: " + ($names -join '; '))
  }
  if ($Unknown -gt 0) {
    $names = (@($Audit.Unknown) | Select-Object -ExpandProperty Name | Sort-Object)
    $lines += ("Unknown: " + ($names -join '; '))
  }

  return ,$lines
}

# -------------------- MAIN --------------------
$eventSourceReady = $true
if (-not (Ensure-EventSource)) {
  $eventSourceReady = $false
  Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
}

try {
  $catalogPathProvided = $PSBoundParameters.ContainsKey('CatalogPath')
  $configPathProvided = $PSBoundParameters.ContainsKey('ConfigPath')
  $catalog = Load-Catalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath `
    -CatalogPathProvided:$catalogPathProvided `
    -ConfigPathProvided:$configPathProvided
  $inv     = Get-InstalledSoftware
  $audit   = Test-SoftwareCompliance -Inventory $inv -Catalog $catalog

  $cntTotal = [int](@($inv).Count)
  $cntBL    = [int](@($audit.Blacklisted).Count)
  $cntWL    = [int](@($audit.Whitelisted).Count)
  $cntUK    = [int](@($audit.Unknown).Count)
  $catalogIssues = @($catalog.Meta.Issues)
  $findings = foreach ($issue in $catalogIssues) {
    [pscustomobject]@{
      Code     = 'CFG-CatalogLoadFailed'
      Severity = 'Medium'
      Message  = ("Explicit catalog/config input was not loaded ({0}: {1}). Defaults were used." -f $issue.Kind, $issue.Status)
      Kind     = $issue.Kind
      Path     = $issue.Path
      Status   = $issue.Status
      Error    = $issue.Error
    }
  }

  $status = Get-AuditStatus -BlacklistedCount $cntBL -UnknownCount $cntUK -ConfigIssueCount $catalogIssues.Count -Strict:$Strict
  $summaryLines = Get-SummaryLines -Total $cntTotal -Whitelisted $cntWL -Unknown $cntUK -Blacklisted $cntBL -Audit $audit

  $result = [pscustomobject]@{
    Time             = (Get-Date).ToString('s')
    Host             = [string]$env:COMPUTERNAME
    Catalog          = $catalog
    EventSource      = [pscustomobject]@{ Name = [string]$Script:EventSourceName; Ready = [bool]$eventSourceReady }
    Status           = $status

    Total            = $cntTotal
    CountWhitelisted = $cntWL
    CountUnknown     = $cntUK
    CountBlacklisted = $cntBL

    Summary          = @($summaryLines)
    Findings         = @($findings)

    # Pipeline-friendly structured data
    Whitelisted      = @($audit.Whitelisted)
    Blacklisted      = @($audit.Blacklisted)
    Unknown          = @($audit.Unknown)
  }

  # Proof JSON (optional)
  if (-not [string]::IsNullOrWhiteSpace($StatePath)) {
    try {
      $dir = Split-Path -Parent $StatePath
      if ($dir) { Ensure-Directory -Path $dir | Out-Null }
      ($result | ConvertTo-Json -Depth 7) | Set-Content -Encoding UTF8 -LiteralPath $StatePath
    } catch {
      Write-Verbose ("Software audit state write failed for '{0}': {1}" -f $StatePath,$_.Exception.Message)
    }
  }

  # Event (best effort)
  $msg = [string](@($summaryLines) -join "`r`n")
  Write-HealthEvent -Id $status.EventId -Msg $msg -Level $status.Level | Out-Null

  # Console summary (host output only)
  $summaryObj = [pscustomobject]@{ ComputerName = [string]$result.Host; Timestamp = Get-Date }
  Write-ConsoleSummary -Summary $summaryObj -Findings ([System.Collections.ArrayList]::new()) `
    -CustomFields ([ordered]@{
      Catalog     = [string]$result.Catalog.Meta.Source
      Status      = ("{0} ({1})" -f $result.Status.EventId, $result.Status.Level)
      Total       = $result.Total
      Whitelisted = $result.CountWhitelisted
      Unknown     = $result.CountUnknown
      Blacklisted = $result.CountBlacklisted
      CatalogWarnings = @($catalogIssues).Count
    })
  # Summary lines
  Write-UiLine ""
  Write-UiLine "Summary:" -ForegroundColor 'Gray'
  foreach ($l in @($result.Summary)) {
    Write-UiLine ("  " + [string]$l) -ForegroundColor 'Gray'
  }
  # Blacklisted and Unknown lists
  $blNames = @($result.Blacklisted | Select-Object -ExpandProperty Name | Sort-Object)
  $ukNames = @($result.Unknown     | Select-Object -ExpandProperty Name | Sort-Object)
  Write-UiLine ""
  Write-ConsoleList -Header "Blacklisted items:" -Items $blNames -HeaderColor 'Red' -ItemColor 'Red' -MaxItems 20
  Write-ConsoleList -Header "Unknown items:"     -Items $ukNames -HeaderColor 'Yellow' -ItemColor 'Yellow' -MaxItems 20

  # Pipeline output (structured object only)
  $result

  if     ($status.EventId -eq 4902) { exit 2 }
  elseif ($status.EventId -eq 4901) { exit 1 }
  else                              { exit 0 }

} catch {
  $errMsg = [string]("SW Inventory Error: " + $_.Exception.Message)

  Write-HealthEvent -Id 4902 -Msg $errMsg -Level 'Error' | Out-Null

  Write-ConsoleBanner -Title "Software Audit (FAILED)" -Color 'Red'
  Write-UiLine ("Error: {0}" -f $errMsg) -ForegroundColor 'Red'

  if ($_.InvocationInfo) {
    Write-UiLine ("Line:    {0}" -f $_.InvocationInfo.ScriptLineNumber) -ForegroundColor 'DarkGray'
    Write-UiLine ("Cmd:     {0}" -f $_.InvocationInfo.Line.Trim()) -ForegroundColor 'DarkGray'
  }

  Write-UiLine ""
  exit 2
}

# V2 output contract
$v2Result = Get-V2ResultObject -ScriptName '19-Software-Audit.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary ([pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Timestamp = Get-Date }) -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
