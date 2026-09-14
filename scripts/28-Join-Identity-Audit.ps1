#requires -version 5.1
<#
.SYNOPSIS
Audit device identity (hostname, domain/workgroup, domain role, OS base data).

.DESCRIPTION
Pipeline: emits exactly one structured object (no strings, no formatting objects).
Console: prints a human-readable summary using Write-UiLine only (not the pipeline).

.PARAMETER ExpectedDomain
Optional. If provided (or loaded from JSON), deviations are reported as findings.

.PARAMETER ExportPath
Optional. If provided (or loaded from JSON), exports the Summary to CSV.

.PARAMETER ConfigPath
Optional JSON configuration file path supplied with $ConfigPath.

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
Import-Module (Join-Path $script:LibPath 'Validation.psm1')

Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '28-Join-Identity-Audit.ps1' -BoundParameters $PSBoundParameters `
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
  $result = Get-V2ResultObject -ScriptName '28-Join-Identity-Audit.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# region Helpers

$Findings = Get-FindingsList

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

  if ($null -eq $DomainRole) { return $null }
  $roles = @('Standalone_Workstation', 'Member_Workstation', 'Standalone_Server', 'Member_Server', 'Backup_Domain_Controller', 'Primary_Domain_Controller')
  if ($DomainRole -ge 0 -and $DomainRole -lt $roles.Count) { return $roles[[int]$DomainRole] }
  return "Unknown($DomainRole)"
}

function Import-JsonConfig {
  [CmdletBinding()]
  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  if (-not (Test-Path -LiteralPath $Path)) { return $null }

  try {
    $raw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $raw | ConvertFrom-Json
  }
  catch {
    Add-Finding -FindingList $Findings -Code 'CONFIG-JsonInvalid' -Severity 'Medium' -Message ("Config JSON could not be loaded from '{0}': {1}" -f $Path, $_.Exception.Message) -TimestampLocal
    $null
  }
}



# endregion Helpers

# region Defaults + config overlay

function Invoke-Capability28MainPhase01 {
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
  if ($script:__EntryBoundParameters.ContainsKey('ExpectedDomain')) {
    $p = Get-StringOrNull $ExpectedDomain
    if ($p) { $effective.ExpectedDomain = $p }
  }
}
function Invoke-Capability28MainPhase02 {
  param([hashtable]$RunState)
  if ($script:__EntryBoundParameters.ContainsKey('ExportPath')) {
    $p = Get-StringOrNull $ExportPath
    if ($p) { $effective.ExportPath = $p }
  }

  # endregion Defaults + config overlay

  # region Data collection

  $RunState.ci = $null
  try {
    $RunState.ci = Get-ComputerInfo -Property `
      CsName, CsDomain, CsWorkgroup, CsDomainRole, CsDNSHostName, `
      OsName, OsVersion, OsBuildNumber, WindowsProductName, WindowsVersion, TimeZone
  }
  catch {
    Add-Finding -FindingList $Findings -Code 'DATA-GetComputerInfo-Failed' -Severity 'High' -Message ("Get-ComputerInfo failed: {0}" -f $_.Exception.Message) -TimestampLocal
  }

  $RunState.cs = $null
  try {
    $RunState.cs = Get-CimInstance -ClassName Win32_ComputerSystem
  }
  catch {
    Add-Finding -FindingList $Findings -Code 'DATA-CIM-Win32_ComputerSystem-Failed' -Severity 'High' -Message ("Get-CimInstance Win32_ComputerSystem failed: {0}" -f $_.Exception.Message) -TimestampLocal
  }
}
function Invoke-Capability28MainPhase03 {
  param([hashtable]$RunState)
  $domainRoleValue = if ($RunState.cs -and $null -ne $RunState.cs.DomainRole) { [int]$RunState.cs.DomainRole } else { $null }
  $RunState.domainRoleText  = Resolve-DomainRoleText -DomainRole $domainRoleValue
}
function Invoke-Capability28MainPhase04 {
  param([hashtable]$RunState)
  if ($effective.ExpectedDomain) {
    if (-not $RunState.cs) {
      Add-Finding -FindingList $Findings -Code 'JOIN-Unknown' -Severity 'Medium' -Message 'Domain join status could not be determined (Win32_ComputerSystem not available).' -TimestampLocal
    }
    else {
      if ($RunState.cs.PartOfDomain -ne $true) {
        Add-Finding -FindingList $Findings -Code 'JOIN-NotDomainJoined' -Severity 'High' -Message 'System is not domain-joined (PartOfDomain is False/Null).' -TimestampLocal
      }
      else {
        if ([string]::IsNullOrWhiteSpace([string]$RunState.cs.Domain)) {
          Add-Finding -FindingList $Findings -Code 'JOIN-DomainEmpty' -Severity 'Medium' -Message 'PartOfDomain=True but Domain is empty/whitespace (unexpected).' -TimestampLocal
        }
        elseif ($RunState.cs.Domain.ToLowerInvariant() -ne $effective.ExpectedDomain.ToLowerInvariant()) {
          Add-Finding -FindingList $Findings -Code 'JOIN-DomainMismatch' -Severity 'High' -Message ("Domain='{0}' differs from ExpectedDomain='{1}'." -f $RunState.cs.Domain, $effective.ExpectedDomain) -TimestampLocal
        }
      }
    }
  }
}
function Invoke-Capability28MainPhase05 {
  param([hashtable]$RunState)
  $RunState.summary = [pscustomobject]@{
    ComputerName   = Get-JoinProperty -Object $RunState.ci -Name 'CsName' -Default $env:COMPUTERNAME
    DNSHostName    = Get-JoinProperty -Object $RunState.ci -Name 'CsDNSHostName'

    Domain         = Get-JoinDomain -ComputerSystem $RunState.cs -ComputerInfo $RunState.ci
    Workgroup      = Get-JoinProperty -Object $RunState.ci -Name 'CsWorkgroup'
    PartOfDomain   = Get-JoinProperty -Object $RunState.cs -Name 'PartOfDomain'

    DomainRole     = $domainRoleValue
    DomainRoleText = $RunState.domainRoleText

    OSName         = Get-JoinProperty -Object $RunState.ci -Name 'OsName'
    OSVersion      = Get-JoinProperty -Object $RunState.ci -Name 'OsVersion'
    OSBuildNumber  = Get-JoinProperty -Object $RunState.ci -Name 'OsBuildNumber'
    WindowsProduct = Get-JoinProperty -Object $RunState.ci -Name 'WindowsProductName'
    WindowsVersion = Get-JoinProperty -Object $RunState.ci -Name 'WindowsVersion'
    TimeZone       = Get-JoinProperty -Object $RunState.ci -Name 'TimeZone' -Raw

    ExpectedDomain = $effective.ExpectedDomain
    ExportPath     = $effective.ExportPath

    FindingsCount  = $Findings.Count
    Timestamp      = Get-Date
  }
}
function Get-JoinProperty {
  param([AllowNull()]$Object, [string]$Name, [AllowNull()]$Default = $null, [switch]$Raw)
  if (-not $Object) { return $Default }
  if ($Raw) { return $Object.$Name }
  return Get-StringOrNull $Object.$Name
}
function Get-JoinDomain {
  param([AllowNull()]$ComputerSystem, [AllowNull()]$ComputerInfo)
  if ($ComputerSystem) { return Get-StringOrNull $ComputerSystem.Domain }
  return Get-JoinProperty -Object $ComputerInfo -Name 'CsDomain'
}
function Invoke-Capability28MainPhase06 {
  param([hashtable]$RunState)
  if ($effective.ExportPath) {
    try {
      $dir = Split-Path -Path $effective.ExportPath -Parent
      if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
      }
      $RunState.summary | Export-Csv -Path $effective.ExportPath -NoTypeInformation -Encoding UTF8
    }
    catch {
      Add-Finding -FindingList $Findings -Code 'EXPORT-Csv-Failed' -Severity 'Medium' -Message ("Export-Csv failed: {0}" -f $_.Exception.Message) -TimestampLocal

      $RunState.summary = [pscustomobject]@{
        ComputerName   = $RunState.summary.ComputerName
        DNSHostName    = $RunState.summary.DNSHostName
        Domain         = $RunState.summary.Domain
        Workgroup      = $RunState.summary.Workgroup
        PartOfDomain   = $RunState.summary.PartOfDomain
        DomainRole     = $RunState.summary.DomainRole
        DomainRoleText = $RunState.summary.DomainRoleText
        OSName         = $RunState.summary.OSName
        OSVersion      = $RunState.summary.OSVersion
        OSBuildNumber  = $RunState.summary.OSBuildNumber
        WindowsProduct = $RunState.summary.WindowsProduct
        WindowsVersion = $RunState.summary.WindowsVersion
        TimeZone       = $RunState.summary.TimeZone
        ExpectedDomain = $RunState.summary.ExpectedDomain
        ExportPath     = $RunState.summary.ExportPath
        FindingsCount  = $Findings.Count
        Timestamp      = $RunState.summary.Timestamp
      }
    }
  }
}
function Invoke-Capability28MainPhase07 {
  param([hashtable]$RunState)
  $result = [pscustomobject]@{
    ComputerName   = $RunState.summary.ComputerName
    Domain         = $RunState.summary.Domain
    Workgroup      = $RunState.summary.Workgroup
    PartOfDomain   = $RunState.summary.PartOfDomain
    DomainRoleText = $RunState.summary.DomainRoleText
    OSVersion      = $RunState.summary.OSVersion
    OSBuildNumber  = $RunState.summary.OSBuildNumber
    FindingsCount  = $Findings.Count
    Timestamp      = $RunState.summary.Timestamp

    Summary        = $RunState.summary
    Findings       = $Findings.ToArray()
  }

  $defaultProps = 'ComputerName','Domain','Workgroup','PartOfDomain','DomainRoleText','OSVersion','OSBuildNumber','FindingsCount','Timestamp'
  $displaySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet',[string[]]$defaultProps)
  $result | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value ([System.Management.Automation.PSMemberInfo[]]@($displaySet)) -Force
}
function Invoke-Capability28MainPhase08Step01 {
  param([hashtable]$RunState)
$statusColor = if ($Findings.Count -gt 0) { 'Yellow' } else { 'Green' }
    $statusText  = if ($Findings.Count -gt 0) { 'ATTENTION' } else { 'OK' }

    Write-UiLine '' 'Gray'
    Write-UiLine '========================================' 'DarkGray'
    Write-UiLine (' Identity Audit - {0}' -f $statusText) $statusColor
    Write-UiLine '========================================' 'DarkGray'

    Write-KeyValue -Key 'Computer' -Value $RunState.summary.ComputerName -ValueColor 'Cyan'
    Write-KeyValue -Key 'DNS'      -Value $RunState.summary.DNSHostName -ValueColor 'Gray'

    if ($RunState.summary.PartOfDomain -eq $true) {
      Write-KeyValue -Key 'Domain' -Value $RunState.summary.Domain -ValueColor 'Green'
    }
    else {
      $domainDisplay = if ([string]::IsNullOrWhiteSpace($RunState.summary.Domain)) { '<none>' } else { $RunState.summary.Domain }
      Write-KeyValue -Key 'Domain' -Value $domainDisplay -ValueColor 'Yellow'
    }

    Write-KeyValue -Key 'Workgroup' -Value $RunState.summary.Workgroup -ValueColor 'Gray'
    Write-KeyValue -Key 'Role'      -Value $RunState.summary.DomainRoleText -ValueColor 'Gray'
    Write-KeyValue -Key 'OS'        -Value $RunState.summary.WindowsProduct -ValueColor 'Gray'
    Write-KeyValue -Key 'Build'     -Value ("{0} ({1})" -f $RunState.summary.OSVersion, $RunState.summary.OSBuildNumber) -ValueColor 'Gray'
    Write-KeyValue -Key 'TimeZone'  -Value $RunState.summary.TimeZone -ValueColor 'Gray'
    Write-KeyValue -Key 'Findings'  -Value $Findings.Count -ValueColor $statusColor
}

function Invoke-Capability28MainPhase08Step02 {
  param([hashtable]$RunState)
if ($effective.ExpectedDomain) {
      $match = ($RunState.summary.PartOfDomain -eq $true -and -not [string]::IsNullOrWhiteSpace($RunState.summary.Domain) -and ($RunState.summary.Domain.ToLowerInvariant() -eq $effective.ExpectedDomain.ToLowerInvariant()))
      Write-KeyValue -Key 'Expected' -Value $effective.ExpectedDomain -ValueColor $(if ($match) { 'Green' } else { 'Yellow' })
    }

    if ($effective.ExportPath) {
      Write-KeyValue -Key 'CSV' -Value $effective.ExportPath -ValueColor 'Gray'
    }
}

function Invoke-Capability28MainPhase08Step03 {
if ($Findings.Count -gt 0) {
      Write-UiLine '' 'Gray'
      Write-UiLine 'Findings:' 'Yellow'
      foreach ($f in ($Findings | Sort-Object @{Expression={ Get-SeverityRank -Severity $_.Severity }; Descending = $true }, Code)) {
        $c = switch ($f.Severity) { 'High' { 'Red' } 'Medium' { 'Yellow' } default { 'Gray' } }
        Write-UiLine ("- [{0}] {1}: {2}" -f $f.Severity, $f.Code, $f.Message) $c
      }
    }

    Write-UiLine '' 'Gray'
}

function Invoke-Capability28MainPhase08 {
  param([hashtable]$RunState)
  if (-not $NoConsoleSummary) {

    . Invoke-Capability28MainPhase08Step01 -RunState $RunState
. Invoke-Capability28MainPhase08Step02 -RunState $RunState
. Invoke-Capability28MainPhase08Step03
  }
}
function Invoke-Capability28Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation)
  $RunState = @{

  }
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability28MainPhase01
  . Invoke-Capability28MainPhase02 -RunState $RunState
  . Invoke-Capability28MainPhase03 -RunState $RunState
  . Invoke-Capability28MainPhase04 -RunState $RunState
  . Invoke-Capability28MainPhase05 -RunState $RunState
  . Invoke-Capability28MainPhase06 -RunState $RunState
  . Invoke-Capability28MainPhase07 -RunState $RunState
  . Invoke-Capability28MainPhase08 -RunState $RunState
  $script:RunState = $RunState
}

. Invoke-Capability28Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation

# endregion Formatted console output

# V2 output contract
function Get-Capability28ResultToken {
  $resultToken = if ($Strict -and $Findings.Count -gt 0) { 'FAIL' } elseif ($Findings.Count -gt 0) { 'WARN' } else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability28ResultToken
$v2Result = Get-V2ResultObject -ScriptName '28-Join-Identity-Audit.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $Findings.ToArray()) -Summary $result.Summary -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
