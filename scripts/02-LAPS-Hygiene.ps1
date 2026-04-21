#requires -version 5.1
<#
.SYNOPSIS
  Checks Local Administrator Password Solution (LAPS) health on a Windows device and optionally triggers a Windows LAPS password rotation.
.DESCRIPTION
  This script inspects the local device to determine whether Windows LAPS or Legacy Microsoft LAPS (AdmPwd) is configured and active.
  It identifies the managed local administrator account (from policy if available, otherwise falls back to the built-in RID-500 account),
  reads the account state (exists/enabled) and the last password set timestamp, then evaluates whether the password is due for rotation
  based on the effective policy age and an optional early-rotation offset.
  The script is designed for automation:
  - Pipeline output is exactly one structured object (PSCustomObject) for easy filtering and exporting.
  - Human-readable console output is printed separately (not via pipeline), with optional color formatting.
  - Optional event log writing can be enabled/disabled via JSON configuration.
.PARAMETER Remediate
  If specified and Windows LAPS is active, triggers password rotation when the script determines rotation is due.
  If Windows LAPS is not active (Legacy LAPS or no policy), remediation is not performed.
.PARAMETER MinDaysBeforeRotate
  Rotates earlier than the policy-defined maximum password age by this many days.
  Example: PolicyAge=30 and MinDaysBeforeRotate=5 => rotation becomes due at day 25.
  Default: 0 (rotate only when the configured maximum age is reached).
.PARAMETER ConfigPath
  Path to an optional JSON configuration file.
  If the file is missing, empty, or invalid JSON, the script continues with built-in safe defaults.
  The JSON can override selected settings such as event log writing, console formatting, and remediation behavior.
.INPUTS
  None. This script does not accept pipeline input.
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
  System.Management.Automation.PSCustomObject
  The script returns exactly one object with (typical) properties:
  - TimestampUtc (DateTime): Execution time in UTC.
  - Remediate (bool): Whether remediation mode was requested.
  - MinDaysBeforeRotate (int): Early-rotation offset used for evaluation.
  - PolicyType (string): 'WindowsLAPS', 'LegacyLAPS', or 'None'.
  - PolicyMechanism (string): Policy source indicator (for example 'CSP', 'GPO', 'Local', or 'n/a').
  - PolicyRoot (string): Registry root path used to read policy settings (or 'n/a').
  - ManagedAccount (string): The local account name considered managed by LAPS.
  - ManagedAccountExists (bool): Whether the account exists locally.
  - ManagedAccountEnabled (bool): Whether the account is enabled.
  - PasswordLastSet (DateTime/null): Last password set timestamp when available; otherwise null.
  - PasswordAgeDays (int/null): Calculated password age in days when PasswordLastSet is known; otherwise null.
  - PolicyPasswordAgeDays (int): Effective policy password age in days (includes fallback defaults when not readable).
  - ThresholdDays (int/null): The effective rotation threshold after MinDaysBeforeRotate is applied.
  - PasswordComplexity (int/null): Complexity value when available from policy; otherwise null.
  - BackupDirectoryRaw (int/null): Raw Windows LAPS backup target value (Windows LAPS only).
  - BackupDirectory (string): Human-readable backup target text (Windows LAPS only).
  - AADJoined (bool): Whether the device is Azure AD joined (best-effort).
  - ADJoined (bool): Whether the device is Active Directory domain joined (best-effort).
  - NeedsRotate (bool): Whether rotation is considered due based on current findings.
  - Rotated (bool): Whether a rotation attempt succeeded (only when Remediate is used and Windows LAPS is active).
  - RotationMethod (string): The method used (or the failure context).
  - RotationError (string/null): Error details when rotation fails.
  - DiagnosticsCollected (bool): Whether diagnostics were collected after a failed rotation attempt.
  - DiagnosticsInfo (string/null): Diagnostics summary or error message.
  - OkOverall (bool): Final overall compliance verdict.
  - Reasons (string[]): List of reasons explaining non-compliance or notable findings.
.EXAMPLE
  .\02-LAPS-Hygiene.ps1
  Runs the hygiene check using defaults.
  Returns one structured result object and prints a readable console summary.
.EXAMPLE
  .\02-LAPS-Hygiene.ps1 -MinDaysBeforeRotate 7
  Checks compliance but treats rotation as due 7 days earlier than the policy maximum age.
.EXAMPLE
  .\02-LAPS-Hygiene.ps1 -Remediate
  Checks compliance and triggers Windows LAPS password rotation if rotation is due.
  If Windows LAPS is not active, the script will not attempt remediation.
.EXAMPLE
  .\02-LAPS-Hygiene.ps1 -ConfigPath 'PATH/TO/JSON/config.json'
  Uses the specified JSON file to override selected defaults (for example event log, console, remediation options).
.EXAMPLE
  # Automation-friendly usage (export pipeline object)
  .\02-LAPS-Hygiene.ps1 -Remediate -MinDaysBeforeRotate 3 | ConvertTo-Json -Depth 6
  Runs in remediation mode and exports the single result object as JSON.
.EXAMPLE
  # CI/MDM-style check (exit code indicates health)
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\02-LAPS-Hygiene.ps1
  if ($LASTEXITCODE -ne 0) { 'NOT OK' } else { 'OK' }
  Uses the script exit code (0 = OK, 1 = NOT OK) for simple integration checks.
.NOTES
  Behavior and design decisions:
  - The pipeline output is always exactly one object; all “pretty” console formatting is printed separately.
  - Event log writing is best-effort: if permissions or source registration prevent writing, the script continues.
  - Remediation is intentionally limited to Windows LAPS; Legacy LAPS remediation is not implemented.
  - Device join detection and some account properties are best-effort and may vary by OS and available modules.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [int]$MinDaysBeforeRotate = 0,
  [string]$ConfigPath
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
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
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
$Remediate = ($Mode -eq 'Remediate')
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
  $result = New-V2ResultObject -ScriptName '02-LAPS-Hygiene.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

# --------------------------- Defaults / Config -------------------------------------
$Defaults = [pscustomobject]@{
  EventLog = [pscustomobject]@{
    Enabled     = $true
    LogName     = 'Application'
    Source      = 'LAPS-Hygiene'
    OkEventId   = 3400
    WarnEventId = 3410
  }
  PolicyDefaults = [pscustomobject]@{
    PasswordAgeDays = 30
  }
  Remediation = [pscustomobject]@{
    SleepAfterRotateSec        = 3
    CollectDiagnosticsOnFail   = $true
    DiagnosticsFolder          = "$env:TEMP\LapsDiagnostics"
  }
  Console = [pscustomobject]@{
    Enabled            = $true
    UseWriteInformation= $false  # colors only via Write-UiLine
    ShowConfigPath     = $false
    Width              = 60
  }
}
function Copy-ObjectDeep {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$InputObject, [int]$Depth = 12)
  return ($InputObject | ConvertTo-Json -Depth $Depth | ConvertFrom-Json)
}
function Merge-ConfigObject {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Base,
    [Parameter(Mandatory)]$Override
  )
  if ($null -eq $Override) { return $Base }
  if ($Override.PSObject.Properties['EventLog']) {
    $o = $Override.EventLog
    if ($o.PSObject.Properties['Enabled'])     { $Base.EventLog.Enabled     = [bool]$o.Enabled }
    if ($o.PSObject.Properties['LogName'])     { $Base.EventLog.LogName     = [string]$o.LogName }
    if ($o.PSObject.Properties['Source'])      { $Base.EventLog.Source      = [string]$o.Source }
    if ($o.PSObject.Properties['OkEventId'])   { $Base.EventLog.OkEventId   = [int]$o.OkEventId }
    if ($o.PSObject.Properties['WarnEventId']) { $Base.EventLog.WarnEventId = [int]$o.WarnEventId }
  }
  if ($Override.PSObject.Properties['PolicyDefaults']) {
    $o = $Override.PolicyDefaults
    if ($o.PSObject.Properties['PasswordAgeDays']) { $Base.PolicyDefaults.PasswordAgeDays = [int]$o.PasswordAgeDays }
  }
  if ($Override.PSObject.Properties['Remediation']) {
    $o = $Override.Remediation
    if ($o.PSObject.Properties['SleepAfterRotateSec'])      { $Base.Remediation.SleepAfterRotateSec = [int]$o.SleepAfterRotateSec }
    if ($o.PSObject.Properties['CollectDiagnosticsOnFail']) { $Base.Remediation.CollectDiagnosticsOnFail = [bool]$o.CollectDiagnosticsOnFail }
    if ($o.PSObject.Properties['DiagnosticsFolder'])        { $Base.Remediation.DiagnosticsFolder = [string]$o.DiagnosticsFolder }
  }
  if ($Override.PSObject.Properties['Console']) {
    $o = $Override.Console
    if ($o.PSObject.Properties['Enabled'])             { $Base.Console.Enabled = [bool]$o.Enabled }
    if ($o.PSObject.Properties['UseWriteInformation']) { $Base.Console.UseWriteInformation = [bool]$o.UseWriteInformation }
    if ($o.PSObject.Properties['ShowConfigPath'])      { $Base.Console.ShowConfigPath = [bool]$o.ShowConfigPath }
    if ($o.PSObject.Properties['Width'])               { $Base.Console.Width = [int]$o.Width }
  }
  return $Base
}
function Get-ConfigFromJson {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)]$DefaultsObject
  )
  $cfg = Copy-ObjectDeep -InputObject $DefaultsObject -Depth 12
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $cfg }
  try {
    $sanitized = Sanitize-Path -Path $Path -MustExist
    if (-not $sanitized) { return $cfg }
    $raw = Get-Content -LiteralPath $sanitized -Raw -Encoding UTF8 -ErrorAction Stop
    if (-not $raw -or -not $raw.Trim()) { return $cfg }
    $j = $raw | ConvertFrom-Json -ErrorAction Stop
    return (Merge-ConfigObject -Base $cfg -Override $j)
  } catch {
    return $cfg
  }
}
$Config = Get-ConfigFromJson -Path $ConfigPath -DefaultsObject $Defaults
# Clamp values
if ($MinDaysBeforeRotate -lt 0) { $MinDaysBeforeRotate = 0 }
if ([int]$Config.PolicyDefaults.PasswordAgeDays -lt 1) { $Config.PolicyDefaults.PasswordAgeDays = 30 }
if ([int]$Config.Remediation.SleepAfterRotateSec -lt 0) { $Config.Remediation.SleepAfterRotateSec = 0 }
if ([int]$Config.Console.Width -lt 40) { $Config.Console.Width = 60 }
# --------------------------- Pretty Console Helpers --------------------------------
# Never type UI parameters as [bool]; accept anything and normalize internally.
function ConvertTo-BoolSafe {
  [CmdletBinding()]
  param([AllowNull()]$Value, [bool]$Default = $false)
  if ($null -eq $Value) { return $Default }
  if ($Value -is [bool]) { return [bool]$Value }
  if ($Value -is [int] -or $Value -is [long]) { return ([int]$Value -ne 0) }
  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $Default }
  switch ($s.Trim().ToLowerInvariant()) {
    'true' { return $true }
    'false'{ return $false }
    'yes'  { return $true }
    'no'   { return $false }
    '1'    { return $true }
    '0'    { return $false }
    default { return $Default }
  }
}
function Get-StyleForOk {
  param([AllowNull()]$Ok)
  if (ConvertTo-BoolSafe -Value $Ok -Default $false) { return 'Good' }
  return 'Bad'
}
function Get-StyleForBool {
  param([AllowNull()]$Value)
  if (ConvertTo-BoolSafe -Value $Value -Default $false) { return 'Good' }
  return 'Dim'
}
# --------------------------- Event Log Helpers -------------------------------------
function Try-WriteHealthEvent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][bool]$Enabled,
    [Parameter(Mandatory)][int]$Id,
    [Parameter(Mandatory)][string]$Msg,
    [ValidateSet('Information','Warning','Error')]
    [string]$Level='Information',
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$LogName
  )
  if (-not $Enabled) { return $false }
  try {
    Write-EventLog -LogName $LogName -Source $Source -EntryType $Level -EventId $Id -Message $Msg -ErrorAction Stop
    return $true
  } catch {
    return $false
  }
}
# --------------------------- Core Helpers ------------------------------------------
function To-Iso {
  param($dt)
  if ($null -eq $dt) { return $null }
  try { return (Get-Date $dt).ToString('s') } catch { return [string]$dt }
}
function Get-RegistryPropertiesCount {
  param($obj)
  if (-not $obj) { return 0 }
  $skip = @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')
  return @($obj.PSObject.Properties.Name | Where-Object { $_ -notin $skip }).Count
}
function Get-ActiveLapsPolicy {
  # Policy roots and selection order are documented by Microsoft.
  $roots = @(
    @{ Type='WindowsLAPS'; Mechanism='CSP';   Path='HKLM:\Software\Microsoft\Policies\LAPS' },
    @{ Type='WindowsLAPS'; Mechanism='GPO';   Path='HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS' },
    @{ Type='WindowsLAPS'; Mechanism='Local'; Path='HKLM:\Software\Microsoft\Windows\CurrentVersion\LAPS\Config' }
  )
  foreach ($r in $roots) {
    try {
      if (Test-Path -LiteralPath $r.Path) {
        $p = Get-ItemProperty -LiteralPath $r.Path -ErrorAction Stop
        if ((Get-RegistryPropertiesCount $p) -gt 0) {
          return [pscustomobject]@{
            Type      = $r.Type
            Mechanism = $r.Mechanism
            RootPath  = $r.Path
            Policy    = $p
          }
        }
      }
    } catch { <# best-effort: registry path may not exist or be accessible #> }
  }
  $legacyRoot = 'HKLM:\Software\Policies\Microsoft Services\AdmPwd'
  try {
    if (Test-Path -LiteralPath $legacyRoot) {
      $lp = Get-ItemProperty -LiteralPath $legacyRoot -ErrorAction Stop
      if ((Get-RegistryPropertiesCount $lp) -gt 0) {
        return [pscustomobject]@{
          Type      = 'LegacyLAPS'
          Mechanism = 'GPO'
          RootPath  = $legacyRoot
          Policy    = $lp
        }
      }
    }
  } catch { <# best-effort: legacy LAPS registry may not exist #> }
  return $null
}
function Get-BuiltInAdminNameRid500 {
  try {
    $acc = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '-500$' } | Select-Object -First 1
    if ($acc) { return $acc.Name }
  } catch {
    try {
      $acc2 = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE '%-500'" -ErrorAction Stop | Select-Object -First 1
      if ($acc2) { return $acc2.Name }
    } catch { <# best-effort: CIM fallback for admin name discovery #> }
  }
  return 'Administrator'
}
function Get-ManagedAdminAccountName {
  param(
    [Parameter(Mandatory)][string]$PolicyType,
    $PolicyObject
  )
  if ($PolicyType -eq 'WindowsLAPS') {
    try {
      if ($PolicyObject -and $PolicyObject.PSObject.Properties['AdministratorAccountName']) {
        $n = [string]$PolicyObject.AdministratorAccountName
        if ($n -and $n.Trim().Length -gt 0) { return $n.Trim() }
      }
    } catch { <# best-effort: policy property may not exist or be castable #> }
  }
  if ($PolicyType -eq 'LegacyLAPS') {
    try {
      if ($PolicyObject -and $PolicyObject.PSObject.Properties['AdminAccountName']) {
        $n = [string]$PolicyObject.AdminAccountName
        if ($n -and $n.Trim().Length -gt 0) { return $n.Trim() }
      }
    } catch { <# best-effort: legacy policy property may not exist or be castable #> }
  }
  return (Get-BuiltInAdminNameRid500)
}
function Get-LocalAdminInfo {
  param([Parameter(Mandatory)][string]$Name)
  try {
    $u = Get-LocalUser -Name $Name -ErrorAction Stop
    return [pscustomobject]@{
      Exists          = $true
      Enabled         = [bool]$u.Enabled
      PasswordLastSet = $u.PasswordLastSet
      Source          = 'Get-LocalUser'
    }
  } catch {
    try {
      $escapedName = $Name -replace "'", "''"
      $u2 = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND Name='$escapedName'" -ErrorAction Stop | Select-Object -First 1
      if ($u2) {
        return [pscustomobject]@{
          Exists          = $true
          Enabled         = -not [bool]$u2.Disabled
          PasswordLastSet = $null
          Source          = 'CIM'
        }
      }
    } catch { <# best-effort: CIM fallback for local user info #> }
    return [pscustomobject]@{
      Exists          = $false
      Enabled         = $false
      PasswordLastSet = $null
      Source          = 'n/a'
    }
  }
}
function Get-AADJoin {
  # Always return [bool]
  try {
    $out = (dsregcmd /status) 2>$null
    return [bool]($out -match 'AzureAdJoined\s*:\s*YES')
  } catch { return $false }
}
function Get-ADJoin {
  # Always return [bool]
  try {
    return [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain
  } catch { return $false }
}
function Try-RotateWindowsLAPS {
  # Cmdlets are documented by Microsoft.
  [CmdletBinding()]
  param([switch]$DoIt)
  if (-not $DoIt) { return $false, "DryRun" }
  $err1 = ''
  $err2 = ''
  try {
    $cmd = Get-Command Reset-LapsPassword -ErrorAction SilentlyContinue
    if ($cmd) {
      Reset-LapsPassword -ErrorAction Stop | Out-Null
      return $true, 'Reset-LapsPassword'
    }
  } catch { $err1 = $_.Exception.Message }
  try {
    $cmd2 = Get-Command Invoke-LapsPolicyProcessing -ErrorAction SilentlyContinue
    if ($cmd2) {
      Invoke-LapsPolicyProcessing -ErrorAction Stop | Out-Null
      return $true, 'Invoke-LapsPolicyProcessing'
    }
  } catch { $err2 = $_.Exception.Message }
  $msg = "No rotation cmdlet available"
  if ($err1) { $msg += " | Reset-LapsPassword: $err1" }
  if ($err2) { $msg += " | Invoke-LapsPolicyProcessing: $err2" }
  return $false, $msg
}
function Try-CollectLapsDiagnostics {
  [CmdletBinding()]
  param(
    [switch]$DoIt,
    [string]$OutputFolder
  )
  if (-not $DoIt) { return $false, "DryRun" }
  try {
    $cmd = Get-Command Get-LapsDiagnostics -ErrorAction SilentlyContinue
    if (-not $cmd) { return $false, "Get-LapsDiagnostics not available" }
    $null = New-Item -ItemType Directory -Path $OutputFolder -Force -ErrorAction Stop
    $out = Get-LapsDiagnostics -OutputFolder $OutputFolder -ErrorAction Stop
    return $true, (($out | Out-String).Trim())
  } catch {
    return $false, $_.Exception.Message
  }
}
function Get-PolicyPasswordAgeDays {
  param(
    [Parameter(Mandatory)][string]$PolicyType,
    $PolicyObject,
    [Parameter(Mandatory)][int]$DefaultAgeDays
  )
  if ($PolicyType -eq 'WindowsLAPS') {
    if ($PolicyObject -and $PolicyObject.PSObject.Properties['PasswordAgeDays']) {
      try { return [int]$PolicyObject.PasswordAgeDays } catch { <# best-effort: property cast may fail #> }
    }
    return $DefaultAgeDays
  }
  if ($PolicyType -eq 'LegacyLAPS') {
    if ($PolicyObject -and $PolicyObject.PSObject.Properties['PasswordAge']) {
      try {
        $hours = [int]$PolicyObject.PasswordAge
        return [math]::Ceiling($hours / 24)
      } catch { <# best-effort: legacy policy hours-to-days cast may fail #> }
    }
    return $DefaultAgeDays
  }
  return $DefaultAgeDays
}
function Get-PolicyComplexity {
  param($PolicyObject)
  try {
    if ($PolicyObject -and $PolicyObject.PSObject.Properties['PasswordComplexity']) { return [int]$PolicyObject.PasswordComplexity }
  } catch { <# best-effort: policy property cast may fail #> }
  return $null
}
function Get-WindowsLapsBackupDirectory {
  param($PolicyObject)
  try {
    if ($PolicyObject -and $PolicyObject.PSObject.Properties['BackupDirectory']) { return [int]$PolicyObject.BackupDirectory }
  } catch { <# best-effort: policy property cast may fail #> }
  return $null
}
function Convert-BackupDirectoryToText {
  param([int]$BackupDirectory)
  if ($BackupDirectory -eq 1) { return 'AAD' }
  if ($BackupDirectory -eq 2) { return 'AD DS' }
  if ($BackupDirectory -eq 0) { return 'Disabled' }
  return '(unknown/not set)'
}
# --------------------------- Main --------------------------------------------------
if ($Config.EventLog.Enabled) {
  Ensure-EventSource -Source $Config.EventLog.Source -LogName $Config.EventLog.LogName
}
$script:Findings = New-FindingsList
$reasonsList = New-Object System.Collections.Generic.List[string]
$result = [pscustomobject]@{
  TimestampUtc          = (Get-Date).ToUniversalTime()
  Remediate             = [bool]$Remediate
  MinDaysBeforeRotate   = [int]$MinDaysBeforeRotate
  PolicyType            = 'None'
  PolicyMechanism       = 'n/a'
  PolicyRoot            = 'n/a'
  ManagedAccount        = $null
  ManagedAccountExists  = $false
  ManagedAccountEnabled = $false
  PasswordLastSet       = $null
  PasswordAgeDays       = $null
  PolicyPasswordAgeDays = $null
  ThresholdDays         = $null
  PasswordComplexity    = $null
  BackupDirectoryRaw    = $null
  BackupDirectory       = '(n/a)'
  AADJoined             = $false
  ADJoined              = $false
  NeedsRotate           = $false
  Rotated               = $false
  RotationMethod        = '(n/a)'
  RotationError         = $null
  DiagnosticsCollected  = $false
  DiagnosticsInfo       = $null
  OkOverall             = $false
  Reasons               = @()
}
try {
  $active = Get-ActiveLapsPolicy
  $policyType = 'None'
  $mechanism  = 'n/a'
  $rootPath   = 'n/a'
  $policyObj  = $null
  if ($active) {
    $policyType = [string]$active.Type
    $mechanism  = [string]$active.Mechanism
    $rootPath   = [string]$active.RootPath
    $policyObj  = $active.Policy
  }
  $result.PolicyType      = $policyType
  $result.PolicyMechanism = $mechanism
  $result.PolicyRoot      = $rootPath
  $isWin = ($policyType -eq 'WindowsLAPS')
  $isLeg = ($policyType -eq 'LegacyLAPS')
  $result.PolicyPasswordAgeDays = Get-PolicyPasswordAgeDays -PolicyType $policyType -PolicyObject $policyObj -DefaultAgeDays $Config.PolicyDefaults.PasswordAgeDays
  $result.PasswordComplexity    = Get-PolicyComplexity -PolicyObject $policyObj
  $result.ManagedAccount = Get-ManagedAdminAccountName -PolicyType $policyType -PolicyObject $policyObj
  $adminInfo = Get-LocalAdminInfo -Name $result.ManagedAccount
  $result.ManagedAccountExists  = [bool]$adminInfo.Exists
  $result.ManagedAccountEnabled = [bool]$adminInfo.Enabled
  $result.PasswordLastSet       = $adminInfo.PasswordLastSet
  if ($adminInfo.PasswordLastSet) {
    try { $result.PasswordAgeDays = [math]::Floor((New-TimeSpan -Start $adminInfo.PasswordLastSet -End (Get-Date)).TotalDays) } catch { <# best-effort: date arithmetic may fail on invalid timestamps #> $result.PasswordAgeDays = $null }
  }
  $result.AADJoined = [bool](Get-AADJoin)
  $result.ADJoined  = [bool](Get-ADJoin)
  if ($isWin) {
    $bd = Get-WindowsLapsBackupDirectory -PolicyObject $policyObj
    $result.BackupDirectoryRaw = $bd
    $result.BackupDirectory = Convert-BackupDirectoryToText -BackupDirectory $bd
  }
  if ($null -ne $result.PolicyPasswordAgeDays) {
    $result.ThresholdDays = [math]::Max(0, ([int]$result.PolicyPasswordAgeDays - [int]$MinDaysBeforeRotate))
  }
  if (-not $active) {
    $reasonsList.Add("No LAPS policy detected")
  } else {
    if (-not $result.ManagedAccountExists) {
      $reasonsList.Add("Managed admin account not found: $($result.ManagedAccount)")
      $result.NeedsRotate = $true
    }
    if ($null -eq $result.PasswordAgeDays) {
      $reasonsList.Add("PasswordLastSet unknown (source=$($adminInfo.Source))")
      if ($isWin) { $result.NeedsRotate = $true }
    } else {
      if ($null -ne $result.ThresholdDays -and $result.PasswordAgeDays -ge $result.ThresholdDays) {
        $reasonsList.Add("Password age $($result.PasswordAgeDays) d >= threshold $($result.ThresholdDays) d")
        $result.NeedsRotate = $true
      }
    }
    if ($isWin -and ($null -eq $result.BackupDirectoryRaw -or $result.BackupDirectoryRaw -eq 0)) {
      $reasonsList.Add("BackupDirectory is not configured or disabled")
      Add-Finding -Code 'LAPS-MissingBackup' -Severity 'High' -Message "Windows LAPS backup directory is not configured or is disabled."
    }
  }
  if ($result.NeedsRotate -and $Remediate -and $isWin) {
    $tmp = @(Try-RotateWindowsLAPS -DoIt)
    $result.Rotated = ($tmp.Count -ge 1) -and ([bool]$tmp[0])
    $result.RotationMethod = if ($tmp.Count -ge 2) { [string]$tmp[1] } else { '' }
    if (-not $result.Rotated) {
      $result.RotationError = $result.RotationMethod
      if ($Config.Remediation.CollectDiagnosticsOnFail) {
        $dtmp = @(Try-CollectLapsDiagnostics -DoIt -OutputFolder $Config.Remediation.DiagnosticsFolder)
        $result.DiagnosticsCollected = ($dtmp.Count -ge 1) -and ([bool]$dtmp[0])
        $result.DiagnosticsInfo = if ($dtmp.Count -ge 2) { [string]$dtmp[1] } else { '' }
      }
    } else {
      Start-Sleep -Seconds $Config.Remediation.SleepAfterRotateSec
      $adminInfo2 = Get-LocalAdminInfo -Name $result.ManagedAccount
      $result.PasswordLastSet = $adminInfo2.PasswordLastSet
      if ($adminInfo2.PasswordLastSet) {
        try { $result.PasswordAgeDays = [math]::Floor((New-TimeSpan -Start $adminInfo2.PasswordLastSet -End (Get-Date)).TotalDays) } catch { <# best-effort: date arithmetic may fail #> }
      }
    }
  }
  $ok = $true
  if (-not $active) { $ok = $false }
  if ($isWin -and ($null -eq $result.BackupDirectoryRaw -or $result.BackupDirectoryRaw -eq 0)) { $ok = $false }
  if ($Remediate -and $isWin -and $result.NeedsRotate -and -not $result.Rotated) { $ok = $false }
  if ($Remediate -and $isLeg -and $result.NeedsRotate) { $ok = $false; $reasonsList.Add("Remediation for Legacy LAPS is not implemented") }
  $result.OkOverall = $ok
  if (-not $result.OkOverall) {
      Add-Finding -Code 'LAPS-NotCompliant' -Severity 'Medium' -Message "LAPS health check failed: $([string]::Join('; ', $result.Reasons))" -Extra @{ Reasons = $result.Reasons }
  }
} catch {
  $result.OkOverall = $false
  $msg = "Unhandled error: $($_.Exception.Message)"
  $reasonsList.Add($msg)
  Add-Finding -Code 'LAPS-Error' -Severity 'High' -Message $msg
}
$result.Reasons = @($reasonsList)
# Event log (best effort)
$eventMessage = @(
  "LAPS Hygiene",
  "PolicyType=$($result.PolicyType) Mechanism=$($result.PolicyMechanism) Root=$($result.PolicyRoot)",
  "Account=$($result.ManagedAccount) Exists=$($result.ManagedAccountExists) Enabled=$($result.ManagedAccountEnabled)",
  "PasswordLastSet=$(To-Iso $result.PasswordLastSet) AgeDays=$(if ($null -ne $result.PasswordAgeDays) { $result.PasswordAgeDays } else { 'n/a' })",
  "PolicyAgeDays=$($result.PolicyPasswordAgeDays) MinDaysBeforeRotate=$($result.MinDaysBeforeRotate) ThresholdDays=$(if ($null -ne $result.ThresholdDays) { $result.ThresholdDays } else { 'n/a' })",
  "BackupDirectory=$($result.BackupDirectory)",
  "Joined: AAD=$($result.AADJoined) AD=$($result.ADJoined)",
  "NeedsRotate=$($result.NeedsRotate) Remediate=$($result.Remediate) Rotated=$($result.Rotated) Via=$($result.RotationMethod)",
  "OkOverall=$($result.OkOverall)",
  "Reasons=$([string]::Join('; ', @($result.Reasons)))"
) -join "`r`n"
if ($Config.EventLog.Enabled) {
  $eventId = $Config.EventLog.WarnEventId
  $eventLevel = 'Warning'
  if ($result.OkOverall) { $eventId = $Config.EventLog.OkEventId; $eventLevel = 'Information' }
  $null = Try-WriteHealthEvent -Enabled $Config.EventLog.Enabled -Id $eventId -Msg $eventMessage -Level $eventLevel -Source $Config.EventLog.Source -LogName $Config.EventLog.LogName
}
# Pretty console (never via pipeline)
Write-UiLine -Text "" -Style 'Default'
Write-UiSeparator -Char '=' -Width $Config.Console.Width -Style 'Dim'
Write-UiLine -Text "LAPS Hygiene (Windows PowerShell 5.1)" -Style 'Title'
Write-UiSeparator -Char '=' -Width $Config.Console.Width -Style 'Dim'
Write-KeyValue -Key "Time (UTC)"     -Value ((Get-Date $result.TimestampUtc -Format s) + "Z") -ValueStyle 'Dim'
if ($Config.Console.ShowConfigPath) { Write-KeyValue -Key "ConfigPath" -Value $ConfigPath -ValueStyle 'Dim' }
Write-KeyValue -Key "Policy"         -Value ("{0} ({1})" -f $result.PolicyType, $result.PolicyMechanism) -ValueStyle 'Default'
Write-KeyValue -Key "Policy root"    -Value $result.PolicyRoot -ValueStyle 'Dim'
Write-UiSeparator -Char '-' -Width $Config.Console.Width -Style 'Dim'
Write-KeyValue -Key "Managed account" -Value ([string]$result.ManagedAccount) -ValueStyle 'Default'
Write-KeyValue -Key "Account exists"  -Value ([string]$result.ManagedAccountExists) -ValueStyle (Get-StyleForBool $result.ManagedAccountExists)
Write-KeyValue -Key "Account enabled" -Value ([string]$result.ManagedAccountEnabled) -ValueStyle (Get-StyleForBool $result.ManagedAccountEnabled)
Write-KeyValue -Key "Pwd last set"    -Value ([string](To-Iso $result.PasswordLastSet)) -ValueStyle 'Dim'
Write-KeyValue -Key "Pwd age (days)"  -Value ([string]($(if ($null -ne $result.PasswordAgeDays) { $result.PasswordAgeDays } else { 'n/a' }))) -ValueStyle 'Default'
Write-UiSeparator -Char '-' -Width $Config.Console.Width -Style 'Dim'
Write-KeyValue -Key "Policy age (d)"  -Value ([string]$result.PolicyPasswordAgeDays) -ValueStyle 'Default'
Write-KeyValue -Key "Threshold (d)"   -Value ([string]($(if ($null -ne $result.ThresholdDays) { $result.ThresholdDays } else { 'n/a' }))) -ValueStyle 'Default'
$bdStyle = 'Dim'
if ($result.PolicyType -eq 'WindowsLAPS') {
  if ($null -eq $result.BackupDirectoryRaw -or $result.BackupDirectoryRaw -eq 0) { $bdStyle = 'Bad' } else { $bdStyle = 'Good' }
}
Write-KeyValue -Key "BackupDirectory" -Value $result.BackupDirectory -ValueStyle $bdStyle
Write-KeyValue -Key "AAD joined"      -Value ([string]$result.AADJoined) -ValueStyle (Get-StyleForBool $result.AADJoined)
Write-KeyValue -Key "AD joined"       -Value ([string]$result.ADJoined)  -ValueStyle (Get-StyleForBool $result.ADJoined)
Write-UiSeparator -Char '-' -Width $Config.Console.Width -Style 'Dim'
$rotateStyle = 'Dim'
if ($result.NeedsRotate -and -not $result.Rotated -and $result.Remediate) { $rotateStyle = 'Bad' }
elseif ($result.NeedsRotate -and $result.Rotated) { $rotateStyle = 'Good' }
elseif ($result.NeedsRotate -and -not $result.Remediate) { $rotateStyle = 'Warn' }
Write-KeyValue -Key "Needs rotate"    -Value ([string]$result.NeedsRotate) -ValueStyle $rotateStyle
Write-KeyValue -Key "Remediate"       -Value ([string]$result.Remediate) -ValueStyle (Get-StyleForBool $result.Remediate)
Write-KeyValue -Key "Rotated"         -Value ("{0} ({1})" -f $result.Rotated, $result.RotationMethod) -ValueStyle $rotateStyle
Write-UiSeparator -Char '=' -Width $Config.Console.Width -Style 'Dim'
Write-KeyValue -Key "Overall"         -Value ($(if ($result.OkOverall) { 'OK' } else { 'NOT OK' })) -ValueStyle (Get-StyleForOk $result.OkOverall)
if ($result.Reasons.Count -gt 0) {
  Write-UiLine -Text "" -Style 'Default'
  Write-UiLine -Text "Reasons" -Style 'Title'
  foreach ($r in $result.Reasons) { Write-UiLine -Text (" - {0}" -f $r) -Style 'Warn' }
}
if ($result.DiagnosticsCollected) {
  Write-UiLine -Text "" -Style 'Default'
  Write-UiLine -Text "Diagnostics" -Style 'Title'
  Write-UiLine -Text (" {0}" -f $result.DiagnosticsInfo) -Style 'Dim'
}
# V2 output contract
$resultToken = if (-not $result.OkOverall) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = New-V2ResultObject -ScriptName '02-LAPS-Hygiene.ps1' -Mode $Mode -Result $resultToken -Findings @($script:Findings) -Summary $result -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
# Exit code for CI/MDM
if ($result.OkOverall) { exit 0 } else { exit 1 }
