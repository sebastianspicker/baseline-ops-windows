#requires -version 5.1
<#
.SYNOPSIS
Audit device identity (hostname, domain/workgroup, domain role, OS base data).

.DESCRIPTION
Pipeline: emits exactly one structured object (no strings, no formatting objects).
Console: prints a human-readable summary using Write-UiLine only (not the pipeline). [web:135]

.PARAMETER ExpectedDomain
Optional. If provided (or loaded from JSON), deviations are reported as findings.

.PARAMETER ExportPath
Optional. If provided (or loaded from JSON), exports the Summary to CSV.

.PARAMETER ConfigPath
Optional JSON configuration file path (placeholder: PATH/TO/JSON\identity-audit.json).

.PARAMETER NoConsoleSummary
Suppress the console summary output.


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

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
PSCustomObject with:
- Flattened top-level properties for a clean default view
- Summary  (PSCustomObject)
- Findings (object[])
.EXAMPLE
  .\28-Join-Identity-Audit.ps1

#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$ExpectedDomain,
  [string]$ExportPath,
  [string]$ConfigPath,
  [switch]$NoConsoleSummary

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
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
  $result = New-V2ResultObject -ScriptName '28-Join-Identity-Audit.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

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
  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  if (-not (Test-Path -LiteralPath $Path)) { return $null }

  try {
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $raw | ConvertFrom-Json
  }
  catch {
    Add-Finding -FindingList $Findings -Code 'CONFIG-JsonInvalid' -Severity 'Medium' -Message ("Config JSON could not be loaded from '{0}': {1}" -f $Path, $_.Exception.Message)
    $null
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
  Add-Finding -FindingList $Findings -Code 'DATA-GetComputerInfo-Failed' -Severity 'High' -Message ("Get-ComputerInfo failed: {0}" -f $_.Exception.Message)
}

$cs = $null
try {
  $cs = Get-CimInstance -ClassName Win32_ComputerSystem
}
catch {
  Add-Finding -FindingList $Findings -Code 'DATA-CIM-Win32_ComputerSystem-Failed' -Severity 'High' -Message ("Get-CimInstance Win32_ComputerSystem failed: {0}" -f $_.Exception.Message)
}

$domainRoleValue = if ($cs -and $null -ne $cs.DomainRole) { [int]$cs.DomainRole } else { $null }
$domainRoleText  = Resolve-DomainRoleText -DomainRole $domainRoleValue

# endregion Data collection

# region Audit checks

if ($effective.ExpectedDomain) {
  if (-not $cs) {
    Add-Finding -FindingList $Findings -Code 'JOIN-Unknown' -Severity 'Medium' -Message 'Domain join status could not be determined (Win32_ComputerSystem not available).'
  }
  else {
    if ($cs.PartOfDomain -ne $true) {
      Add-Finding -FindingList $Findings -Code 'JOIN-NotDomainJoined' -Severity 'High' -Message 'System is not domain-joined (PartOfDomain is False/Null).'
    }
    else {
      if ([string]::IsNullOrWhiteSpace([string]$cs.Domain)) {
        Add-Finding -FindingList $Findings -Code 'JOIN-DomainEmpty' -Severity 'Medium' -Message 'PartOfDomain=True but Domain is empty/whitespace (unexpected).'
      }
      elseif ($cs.Domain.ToLowerInvariant() -ne $effective.ExpectedDomain.ToLowerInvariant()) {
        Add-Finding -FindingList $Findings -Code 'JOIN-DomainMismatch' -Severity 'High' -Message ("Domain='{0}' differs from ExpectedDomain='{1}'." -f $cs.Domain, $effective.ExpectedDomain)
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
    Add-Finding -FindingList $Findings -Code 'EXPORT-Csv-Failed' -Severity 'Medium' -Message ("Export-Csv failed: {0}" -f $_.Exception.Message)

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
    Write-KeyValue -Key 'Expected' -Value $effective.ExpectedDomain -ValueColor $(if ($match) { 'Green' } else { 'Yellow' })
  }

  if ($effective.ExportPath) {
    Write-KeyValue -Key 'CSV' -Value $effective.ExportPath -ValueColor 'Gray'
  }

  if ($Findings.Count -gt 0) {
    Write-ColorLine '' 'Gray'
    Write-ColorLine 'Findings:' 'Yellow'
    foreach ($f in ($Findings | Sort-Object @{Expression={ Get-SeverityRank -Severity $_.Severity }; Descending = $true }, Code)) {
      $c = switch ($f.Severity) { 'High' { 'Red' } 'Medium' { 'Yellow' } default { 'Gray' } }
      Write-ColorLine ("- [{0}] {1}: {2}" -f $f.Severity, $f.Code, $f.Message) $c
    }
  }

  Write-ColorLine '' 'Gray'
}

# endregion Pretty console output

# V2 output contract
$resultToken = if ($Strict -and $Findings.Count -gt 0) { 'FAIL' } elseif ($Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = New-V2ResultObject -ScriptName '28-Join-Identity-Audit.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $Findings.ToArray()) -Summary $result.Summary -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
