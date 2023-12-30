#requires -version 5.1
<#
.SYNOPSIS
Audit device identity (hostname, domain/workgroup, domain role, OS base data).

.DESCRIPTION
Pipeline: emits exactly one structured object (no strings, no formatting objects).
Console: prints a human-readable summary using Write-Host only (not the pipeline). [web:135]

.PARAMETER ExpectedDomain
Optional. If provided (or loaded from JSON), deviations are reported as findings.

.PARAMETER ExportPath
Optional. If provided (or loaded from JSON), exports the Summary to CSV.

.PARAMETER ConfigPath
Optional JSON configuration file path (placeholder: PATH/TO/JSON\identity-audit.json).

.PARAMETER NoConsoleSummary
Suppress the console summary output.

.OUTPUTS
PSCustomObject with:
- Flattened top-level properties for a clean default view
- Summary  (PSCustomObject)
- Findings (object[])
.EXAMPLE
  .\28-Join-Identity-Audit.ps1

#>

[CmdletBinding()]
param(
  [string]$ExpectedDomain,
  [string]$ExportPath,
  [string]$ConfigPath = 'PATH/TO/JSON\identity-audit.json',
  [switch]$NoConsoleSummary
)

$script:LibPath = Join-Path $PSScriptRoot 'lib'
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# region Helpers

$script:FindingsTimestampLocal = $true
$Findings = New-FindingsList

function Get-StringOrNull {
  [CmdletBinding()]
  param([AllowNull()][object]$Value)

  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  $s
}

function Resolve-DomainRoleText {
  [CmdletBinding()]
  param([AllowNull()][Nullable[int]]$DomainRole)

  switch ($DomainRole) {
    0 { 'Standalone_Workstation' }
    1 { 'Member_Workstation' }
    2 { 'Standalone_Server' }
    3 { 'Member_Server' }
    4 { 'Backup_Domain_Controller' }
    5 { 'Primary_Domain_Controller' }
    default { if ($null -eq $DomainRole) { $null } else { "Unknown($DomainRole)" } }
  }
}

function Import-JsonConfig {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  if (-not (Test-Path -LiteralPath $Path)) { return $null }

  try {
    $raw = Get-Content -LiteralPath $Path -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $raw | ConvertFrom-Json
  }
  catch {
    Add-Finding -Code 'CONFIG-JsonInvalid' -Severity 'Medium' -Message ("Config JSON could not be loaded from '{0}': {1}" -f $Path, $_.Exception.Message)
    $null
  }
}

function Write-ColorLine {
  [CmdletBinding()]
  param(
    # Allow empty lines for pretty console output without validation errors.
    [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
    [ValidateSet('Gray','DarkGray','Green','Yellow','Red','Cyan','White')][string]$Color = 'Gray'
  )

  Write-Host $Text -ForegroundColor $Color
}

function Write-KeyValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Key,
    [AllowNull()][object]$Value,
    [ValidateSet('Gray','DarkGray','Green','Yellow','Red','Cyan','White')][string]$ValueColor = 'Gray'
  )

  $v = if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { '<none>' } else { [string]$Value }
  Write-Host ("{0,-14}: " -f $Key) -NoNewline -ForegroundColor DarkGray
  Write-Host $v -ForegroundColor $ValueColor
}

function Get-SeverityRank {
  param([string]$Severity)
  switch ($Severity) {
    'High'   { 0 }
    'Medium' { 1 }
    'Low'    { 2 }
    default  { 9 }
  }
}

# endregion Helpers

# region Defaults + config overlay

$effective = [pscustomobject]@{
  ExpectedDomain = $null
  ExportPath     = $null
  ConfigPathUsed = $ConfigPath
  ConfigLoaded   = $false
}

$config = Import-JsonConfig -Path $ConfigPath
if ($config) {
  $effective.ConfigLoaded = $true

  $cfgExpectedDomain = Get-StringOrNull $config.ExpectedDomain
  if ($cfgExpectedDomain) { $effective.ExpectedDomain = $cfgExpectedDomain }

  $cfgExportPath = Get-StringOrNull $config.ExportPath
  if ($cfgExportPath) { $effective.ExportPath = $cfgExportPath }
}

# Parameters win
if ($PSBoundParameters.ContainsKey('ExpectedDomain')) {
  $p = Get-StringOrNull $ExpectedDomain
  if ($p) { $effective.ExpectedDomain = $p }
}
if ($PSBoundParameters.ContainsKey('ExportPath')) {
  $p = Get-StringOrNull $ExportPath
  if ($p) { $effective.ExportPath = $p }
}

# endregion Defaults + config overlay

# region Data collection

$ci = $null
try {
  $ci = Get-ComputerInfo -Property `
    CsName, CsDomain, CsWorkgroup, CsDomainRole, CsDNSHostName, `
    OsName, OsVersion, OsBuildNumber, WindowsProductName, WindowsVersion, TimeZone
}
catch {
  Add-Finding -Code 'DATA-GetComputerInfo-Failed' -Severity 'High' -Message ("Get-ComputerInfo failed: {0}" -f $_.Exception.Message)
}

$cs = $null
try {
  $cs = Get-CimInstance -ClassName Win32_ComputerSystem
}
catch {
  Add-Finding -Code 'DATA-CIM-Win32_ComputerSystem-Failed' -Severity 'High' -Message ("Get-CimInstance Win32_ComputerSystem failed: {0}" -f $_.Exception.Message)
}

$domainRoleValue = if ($cs -and $null -ne $cs.DomainRole) { [int]$cs.DomainRole } else { $null }
$domainRoleText  = Resolve-DomainRoleText -DomainRole $domainRoleValue

# endregion Data collection

# region Audit checks

if ($effective.ExpectedDomain) {
  if (-not $cs) {
    Add-Finding -Code 'JOIN-Unknown' -Severity 'Medium' -Message 'Domain join status could not be determined (Win32_ComputerSystem not available).'
  }
  else {
    if ($cs.PartOfDomain -ne $true) {
      Add-Finding -Code 'JOIN-NotDomainJoined' -Severity 'High' -Message 'System is not domain-joined (PartOfDomain is False/Null).'
    }
    else {
      if ([string]::IsNullOrWhiteSpace([string]$cs.Domain)) {
        Add-Finding -Code 'JOIN-DomainEmpty' -Severity 'Medium' -Message 'PartOfDomain=True but Domain is empty/whitespace (unexpected).'
      }
      elseif ($cs.Domain.ToLowerInvariant() -ne $effective.ExpectedDomain.ToLowerInvariant()) {
        Add-Finding -Code 'JOIN-DomainMismatch' -Severity 'High' -Message ("Domain='{0}' differs from ExpectedDomain='{1}'." -f $cs.Domain, $effective.ExpectedDomain)
      }
    }
  }
}

# endregion Audit checks

# region Summary + export

$summary = [pscustomobject]@{
  ComputerName   = if ($ci) { Get-StringOrNull $ci.CsName } else { $env:COMPUTERNAME }
  DNSHostName    = if ($ci) { Get-StringOrNull $ci.CsDNSHostName } else { $null }

  Domain         = if ($cs) { Get-StringOrNull $cs.Domain } else { if ($ci) { Get-StringOrNull $ci.CsDomain } else { $null } }
  Workgroup      = if ($ci) { Get-StringOrNull $ci.CsWorkgroup } else { $null }
  PartOfDomain   = if ($cs) { $cs.PartOfDomain } else { $null }

  DomainRole     = $domainRoleValue
  DomainRoleText = $domainRoleText

  OSName         = if ($ci) { Get-StringOrNull $ci.OsName } else { $null }
  OSVersion      = if ($ci) { Get-StringOrNull $ci.OsVersion } else { $null }
  OSBuildNumber  = if ($ci) { Get-StringOrNull $ci.OsBuildNumber } else { $null }
  WindowsProduct = if ($ci) { Get-StringOrNull $ci.WindowsProductName } else { $null }
  WindowsVersion = if ($ci) { Get-StringOrNull $ci.WindowsVersion } else { $null }
  TimeZone       = if ($ci) { $ci.TimeZone } else { $null }

  ExpectedDomain = $effective.ExpectedDomain
  ExportPath     = $effective.ExportPath

  FindingsCount  = $Findings.Count
  Timestamp      = Get-Date
}

if ($effective.ExportPath) {
  try {
    $dir = Split-Path -Path $effective.ExportPath -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
      New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
    $summary | Export-Csv -Path $effective.ExportPath -NoTypeInformation -Encoding UTF8
  }
  catch {
    Add-Finding -Code 'EXPORT-Csv-Failed' -Severity 'Medium' -Message ("Export-Csv failed: {0}" -f $_.Exception.Message)

    $summary = [pscustomobject]@{
      ComputerName   = $summary.ComputerName
      DNSHostName    = $summary.DNSHostName
      Domain         = $summary.Domain
      Workgroup      = $summary.Workgroup
      PartOfDomain   = $summary.PartOfDomain
      DomainRole     = $summary.DomainRole
      DomainRoleText = $summary.DomainRoleText
      OSName         = $summary.OSName
      OSVersion      = $summary.OSVersion
      OSBuildNumber  = $summary.OSBuildNumber
      WindowsProduct = $summary.WindowsProduct
      WindowsVersion = $summary.WindowsVersion
      TimeZone       = $summary.TimeZone
      ExpectedDomain = $summary.ExpectedDomain
      ExportPath     = $summary.ExportPath
      FindingsCount  = $Findings.Count
      Timestamp      = $summary.Timestamp
    }
  }
}

# endregion Summary + export

# region Result object

$result = [pscustomobject]@{
  ComputerName   = $summary.ComputerName
  Domain         = $summary.Domain
  Workgroup      = $summary.Workgroup
  PartOfDomain   = $summary.PartOfDomain
  DomainRoleText = $summary.DomainRoleText
  OSVersion      = $summary.OSVersion
  OSBuildNumber  = $summary.OSBuildNumber
  FindingsCount  = $Findings.Count
  Timestamp      = $summary.Timestamp

  Summary        = $summary
  Findings       = $Findings.ToArray()
}

$defaultProps = 'ComputerName','Domain','Workgroup','PartOfDomain','DomainRoleText','OSVersion','OSBuildNumber','FindingsCount','Timestamp'
$displaySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet',[string[]]$defaultProps)
$result | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value ([System.Management.Automation.PSMemberInfo[]]@($displaySet)) -Force

# endregion Result object

# region Pretty console output (host only)

if (-not $NoConsoleSummary) {

  $statusColor = if ($Findings.Count -gt 0) { 'Yellow' } else { 'Green' }
  $statusText  = if ($Findings.Count -gt 0) { 'ATTENTION' } else { 'OK' }

  Write-ColorLine '' 'Gray'
  Write-ColorLine '========================================' 'DarkGray'
  Write-ColorLine (' Identity Audit - {0}' -f $statusText) $statusColor
  Write-ColorLine '========================================' 'DarkGray'

  Write-KeyValue -Key 'Computer' -Value $summary.ComputerName -ValueColor 'Cyan'
  Write-KeyValue -Key 'DNS'      -Value $summary.DNSHostName -ValueColor 'Gray'

  if ($summary.PartOfDomain -eq $true) {
    Write-KeyValue -Key 'Domain' -Value $summary.Domain -ValueColor 'Green'
  }
  else {
    $domainDisplay = if ([string]::IsNullOrWhiteSpace($summary.Domain)) { '<none>' } else { $summary.Domain }
    Write-KeyValue -Key 'Domain' -Value $domainDisplay -ValueColor 'Yellow'
  }

  Write-KeyValue -Key 'Workgroup' -Value $summary.Workgroup -ValueColor 'Gray'
  Write-KeyValue -Key 'Role'      -Value $summary.DomainRoleText -ValueColor 'Gray'
  Write-KeyValue -Key 'OS'        -Value $summary.WindowsProduct -ValueColor 'Gray'
  Write-KeyValue -Key 'Build'     -Value ("{0} ({1})" -f $summary.OSVersion, $summary.OSBuildNumber) -ValueColor 'Gray'
  Write-KeyValue -Key 'TimeZone'  -Value $summary.TimeZone -ValueColor 'Gray'
  Write-KeyValue -Key 'Findings'  -Value $Findings.Count -ValueColor $statusColor

  if ($effective.ExpectedDomain) {
    $match = ($summary.PartOfDomain -eq $true -and -not [string]::IsNullOrWhiteSpace($summary.Domain) -and ($summary.Domain.ToLowerInvariant() -eq $effective.ExpectedDomain.ToLowerInvariant()))
    Write-KeyValue -Key 'Expected' -Value $effective.ExpectedDomain -ValueColor (if ($match) { 'Green' } else { 'Yellow' })
  }

  if ($effective.ExportPath) {
    Write-KeyValue -Key 'CSV' -Value $effective.ExportPath -ValueColor 'Gray'
  }

  if ($Findings.Count -gt 0) {
    Write-ColorLine '' 'Gray'
    Write-ColorLine 'Findings:' 'Yellow'
    foreach ($f in ($Findings | Sort-Object @{Expression={ Get-SeverityRank $_.Severity }}, Code)) {
      $c = switch ($f.Severity) { 'High' { 'Red' } 'Medium' { 'Yellow' } default { 'Gray' } }
      Write-ColorLine ("- [{0}] {1}: {2}" -f $f.Severity, $f.Code, $f.Message) $c
    }
  }

  Write-ColorLine '' 'Gray'
}

# endregion Pretty console output

# Pipeline output: exactly one structured object
#$result
