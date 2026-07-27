#requires -version 5.1
<#
.SYNOPSIS
Lightweight client "Security Baseline" report (read-only).

.DESCRIPTION
- Pipeline output: ONLY structured objects.
- Console output: formatting via Write-UiLine / Write-Information only.
- Optional JSON reference for expected values; safe defaults when missing or invalid.

.PARAMETER ExportPath
Optional CSV export:
- <ExportPath> (summary)
- <basename>_sections.csv (rows)

.PARAMETER ReferenceJsonPath
Optional JSON reference file path supplied with $ReferenceJsonPath.

.PARAMETER NoConsoleSummary
Disable the human-readable summary block at the end.

.PARAMETER Quiet
Suppress informational console output (still returns objects).


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER ConfigPath
  Path to JSON configuration file.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER PassThru
  Emit structured v2 result object to pipeline.

.PARAMETER Strict
  Treat warnings as failures.

.PARAMETER NoColor
  Disable colored output.

.OUTPUTS
- BaselineReport.Summary
- BaselineReport.Row
.EXAMPLE
  .\42-Client-SecurityBaseline-Report-IntuneRef.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$ExportPath,
  [string]$ReferenceJsonPath,
  [switch]$NoConsoleSummary,
  [switch]$Quiet

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [string]$ConfigPath,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


$script:Quiet = [bool]$Quiet
$script:NoConsoleSummary = [bool]$NoConsoleSummary

Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '42-Client-SecurityBaseline-Report-IntuneRef.ps1' -BoundParameters $PSBoundParameters `
  -Mode $Mode -ConfigPath $ConfigPath -OutputFormat $OutputFormat -OutputPath $OutputPath `
  -PassThru:$PassThru -Strict:$Strict -Quiet:$Quiet -NoColor:$NoColor
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
  $result = Get-V2ResultObject -ScriptName '42-Client-SecurityBaseline-Report-IntuneRef.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

#region Helpers





function Test-RegKey {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)
  try { Test-Path -Path $Path } catch { $false }
}

# Ensure-Directory imported from lib/Common.psm1

function ConvertTo-ScalarString {
  [CmdletBinding()]
  param([object]$Value)

  if ($null -eq $Value) { return $null }
  if ($Value -is [System.Array]) { return ($Value | ForEach-Object { $_.ToString() }) -join ',' }
  return $Value.ToString()
}

function ConvertTo-DisplayString {
  [CmdletBinding()]
  param([object]$Value)

  $s = ConvertTo-ScalarString -Value $Value
  if ([string]::IsNullOrWhiteSpace($s)) { return '<not set>' }
  return $s
}

function Get-ObjectList {
  # Strong list internally, but do NOT expose as typed parameter to avoid empty-collection binding issues.
  New-Object 'System.Collections.Generic.List[object]'
}

function Add-Row {
  [CmdletBinding()]
  param(
    # Accept as object to avoid PowerShell "empty collection" parameter binding pitfalls with generic lists.
    [Parameter(Mandatory)]
    [object]$List,

    [Parameter(Mandatory)]
    [hashtable]$Data
  )

  if ($null -eq $List) { throw "Add-Row: List is null." }

  $row = [pscustomobject]$Data
  $row.PSObject.TypeNames.Insert(0, 'BaselineReport.Row')

  # Support both List[T] and arraylist-like types
  if ($List -is [System.Collections.IList]) {
    [void]$List.Add($row)
    return
  }

  throw ("Add-Row: Unsupported list type: {0}" -f $List.GetType().FullName)
}

function Get-ReferenceDefaults {
  return @{
    Metadata = @{
      Name    = 'DefaultReference'
      Version = '1.0'
      Note    = 'Using built-in defaults because JSON reference was not loaded.'
    }
    Expected = @{
      'CredentialGuard/VBS' = @{
        EnableVirtualizationBasedSecurity = $null
        RequirePlatformSecurityFeatures   = $null
        LsaCfgFlags                       = $null
      }
      'LSAProtection(PPL)' = @{ RunAsPPL = $null }
      'PowerShellLogging(Policy)' = @{
        EnableScriptBlockLogging           = $null
        EnableScriptBlockInvocationLogging = $null
        EnableModuleLogging                = $null
        EnableTranscripting                = $null
      }
      'FirewallProfile' = @{
        Enabled    = $null
        LogAllowed = $null
        LogBlocked = $null
      }
    }
  }
}

function Load-ReferenceJson {
  [CmdletBinding()]
  param([string]$Path)

  $result = [ordered]@{ Loaded=$false; Path=$null; Error=$null; Reference=$null }

  if ([string]::IsNullOrWhiteSpace($Path)) {
    $result.Reference = Get-ReferenceDefaults
    return [pscustomobject]$result
  }

  $result.Path = $Path

  try {
    if (-not (Test-Path -LiteralPath $Path)) {
      $result.Error = "Reference JSON not found: $Path"
      $result.Reference = Get-ReferenceDefaults
      return [pscustomobject]$result
    }

    $raw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
    if ([string]::IsNullOrWhiteSpace($raw)) {
      $result.Error = "Reference JSON is empty: $Path"
      $result.Reference = Get-ReferenceDefaults
      return [pscustomobject]$result
    }

    $obj = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $obj) {
      $result.Error = "Reference JSON parsed to null: $Path"
      $result.Reference = Get-ReferenceDefaults
      return [pscustomobject]$result
    }

    $result.Loaded = $true
    $result.Reference = $obj
    return [pscustomobject]$result
  }
  catch {
    $result.Error = $_.Exception.Message
    $result.Reference = Get-ReferenceDefaults
    return [pscustomobject]$result
  }
}

function Get-ExpectedValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$Reference,
    [Parameter(Mandatory)][string]$SectionName,
    [Parameter(Mandatory)][string]$FieldName
  )

  try {
    $sec = $Reference.Expected.$SectionName
    if ($null -eq $sec) { return $null }
    return $sec.$FieldName
  } catch { $null }
}

function Compare-ToExpected {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$Reference,
    [Parameter(Mandatory)][string]$SectionName,
    [Parameter(Mandatory)][string]$FieldName,
    [object]$ActualValue
  )

  $expected = Get-ExpectedValue -Reference $Reference -SectionName $SectionName -FieldName $FieldName
  if ($null -eq $expected) { return [pscustomobject]@{ Expected=$null; Match=$null; Note=$null } }

  $match = $false
  if ($null -eq $ActualValue -and $null -eq $expected) { $match = $true }
  elseif ($null -ne $ActualValue) { $match = ($ActualValue.ToString() -eq $expected.ToString()) }

  [pscustomobject]@{ Expected=$expected; Match=$match; Note=$null }
}

function Resolve-VbsStatusText {
  [CmdletBinding()]
  param([object]$Value)

  switch ($Value) {
    0 { 'VBS not enabled' }
    1 { 'VBS enabled, not running' }
    2 { 'VBS enabled and running' }
    default { if ($null -eq $Value) { 'Unknown' } else { "Unknown ($Value)" } }
  }
}

function Resolve-CredentialGuardRunningText {
  [CmdletBinding()]
  param([object]$SecurityServicesRunning)

  $csv = ConvertTo-ScalarString $SecurityServicesRunning
  if ([string]::IsNullOrWhiteSpace($csv)) { return 'Unknown' }

  $t = $csv.Trim()
  if ($t -eq '0') { return 'Not running' }
  if ($t -eq '1') { return 'Running' }
  "Unknown ($t)"
}

function Get-LevelForMatch {
  [CmdletBinding()]
  param([object]$MatchValue)

  if ($null -eq $MatchValue) { return 'Dim' }
  if ($MatchValue -eq $true) { return 'Good' }
  'Bad'
}

#endregion Helpers

#region Main

$refInfo = Load-ReferenceJson -Path $ReferenceJsonPath
$ref     = $refInfo.Reference
$partialReasons = New-Object 'System.Collections.Generic.List[string]'
$sourceStatus = [ordered]@{
  Reference = [ordered]@{
    Requested = -not [string]::IsNullOrWhiteSpace($ReferenceJsonPath)
    Loaded    = [bool]$refInfo.Loaded
    Error     = $refInfo.Error
  }
  FirewallProfile = [ordered]@{
    Attempted = $false
    Succeeded = $null
    Error     = $null
  }
}
if ($sourceStatus.Reference.Requested -and -not $refInfo.Loaded) {
  [void]$partialReasons.Add("Reference JSON failed: $($refInfo.Error)")
}

$dgRuntime   = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
$lsaRuntime  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$dgPolicy    = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
$psPolicy    = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$psSBPolicy  = Join-Path $psPolicy 'ScriptBlockLogging'
$psMLPolicy  = Join-Path $psPolicy 'ModuleLogging'
$psTRPolicy  = Join-Path $psPolicy 'Transcription'

$rows = Get-ObjectList

# Credential Guard / VBS - runtime intent
$enableVbs = Get-RegValue -Path $dgRuntime  -Name 'EnableVirtualizationBasedSecurity'
$reqPlat   = Get-RegValue -Path $dgRuntime  -Name 'RequirePlatformSecurityFeatures'
$lsaCfg    = Get-RegValue -Path $lsaRuntime -Name 'LsaCfgFlags'

$cmpVbs = Compare-ToExpected -Reference $ref -SectionName 'CredentialGuard/VBS' -FieldName 'EnableVirtualizationBasedSecurity' -ActualValue $enableVbs
$cmpReq = Compare-ToExpected -Reference $ref -SectionName 'CredentialGuard/VBS' -FieldName 'RequirePlatformSecurityFeatures' -ActualValue $reqPlat
$cmpLsa = Compare-ToExpected -Reference $ref -SectionName 'CredentialGuard/VBS' -FieldName 'LsaCfgFlags' -ActualValue $lsaCfg

Add-Row -List $rows -Data @{
  Section = 'CredentialGuard/VBS'
  Source  = 'Runtime'
  EnableVirtualizationBasedSecurity = $enableVbs
  RequirePlatformSecurityFeatures   = $reqPlat
  LsaCfgFlags                       = $lsaCfg
  Expected_EnableVirtualizationBasedSecurity = $cmpVbs.Expected
  Match_EnableVirtualizationBasedSecurity    = $cmpVbs.Match
  Expected_RequirePlatformSecurityFeatures   = $cmpReq.Expected
  Match_RequirePlatformSecurityFeatures      = $cmpReq.Match
  Expected_LsaCfgFlags                       = $cmpLsa.Expected
  Match_LsaCfgFlags                          = $cmpLsa.Match
  Interpretation = $null
}

# Credential Guard / VBS - policy intent
if (Test-RegKey -Path $dgPolicy) {
  Add-Row -List $rows -Data @{
    Section = 'CredentialGuard/VBS'
    Source  = 'Policy'
    EnableVirtualizationBasedSecurity = Get-RegValue -Path $dgPolicy -Name 'EnableVirtualizationBasedSecurity'
    RequirePlatformSecurityFeatures   = Get-RegValue -Path $dgPolicy -Name 'RequirePlatformSecurityFeatures'
    LsaCfgFlags                       = Get-RegValue -Path $dgPolicy -Name 'LsaCfgFlags'
    Interpretation = 'Policy path present.'
  }
} else {
  Add-Row -List $rows -Data @{
    Section = 'CredentialGuard/VBS'
    Source  = 'Policy'
    Interpretation = 'Policy path not present.'
  }
}

# Win32_DeviceGuard - CIM runtime status
try {
  $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
  Add-Row -List $rows -Data @{
    Section = 'DeviceGuardStatus(CIM)'
    Source  = 'CIM'
    SecurityServicesConfigured        = ConvertTo-ScalarString $dg.SecurityServicesConfigured
    SecurityServicesRunning           = ConvertTo-ScalarString $dg.SecurityServicesRunning
    VirtualizationBasedSecurityStatus = ConvertTo-ScalarString $dg.VirtualizationBasedSecurityStatus
    Interpretation = 'CIM query succeeded.'
  }
} catch {
  Add-Row -List $rows -Data @{
    Section = 'DeviceGuardStatus(CIM)'
    Source  = 'CIM'
    Interpretation = ('CIM query failed: {0}' -f $_.Exception.Message)
  }
}

# LSA protection (RunAsPPL)
$runAsPpl = Get-RegValue -Path $lsaRuntime -Name 'RunAsPPL'
$cmpPpl   = Compare-ToExpected -Reference $ref -SectionName 'LSAProtection(PPL)' -FieldName 'RunAsPPL' -ActualValue $runAsPpl

Add-Row -List $rows -Data @{
  Section  = 'LSAProtection(PPL)'
  Source   = 'Runtime'
  RunAsPPL = $runAsPpl
  Expected_RunAsPPL = $cmpPpl.Expected
  Match_RunAsPPL    = $cmpPpl.Match
  Interpretation    = $null
}

# PowerShell logging (policy)
$sbEnabled = Get-RegValue -Path $psSBPolicy -Name 'EnableScriptBlockLogging'
$sbInvoc   = Get-RegValue -Path $psSBPolicy -Name 'EnableScriptBlockInvocationLogging'
$mlEnabled = Get-RegValue -Path $psMLPolicy -Name 'EnableModuleLogging'
$trEnabled = Get-RegValue -Path $psTRPolicy -Name 'EnableTranscripting'

$cmpSb  = Compare-ToExpected -Reference $ref -SectionName 'PowerShellLogging(Policy)' -FieldName 'EnableScriptBlockLogging' -ActualValue $sbEnabled
$cmpSbI = Compare-ToExpected -Reference $ref -SectionName 'PowerShellLogging(Policy)' -FieldName 'EnableScriptBlockInvocationLogging' -ActualValue $sbInvoc
$cmpMl  = Compare-ToExpected -Reference $ref -SectionName 'PowerShellLogging(Policy)' -FieldName 'EnableModuleLogging' -ActualValue $mlEnabled
$cmpTr  = Compare-ToExpected -Reference $ref -SectionName 'PowerShellLogging(Policy)' -FieldName 'EnableTranscripting' -ActualValue $trEnabled

Add-Row -List $rows -Data @{
  Section = 'PowerShellLogging(Policy)'
  Source  = 'Policy'
  BaseKeyExists = (Test-RegKey -Path $psPolicy)
  ScriptBlockLoggingKeyExists        = (Test-RegKey -Path $psSBPolicy)
  EnableScriptBlockLogging           = $sbEnabled
  EnableScriptBlockInvocationLogging = $sbInvoc
  ModuleLoggingKeyExists             = (Test-RegKey -Path $psMLPolicy)
  EnableModuleLogging                = $mlEnabled
  TranscriptionKeyExists             = (Test-RegKey -Path $psTRPolicy)
  EnableTranscripting                = $trEnabled
  Expected_EnableScriptBlockLogging           = $cmpSb.Expected
  Match_EnableScriptBlockLogging              = $cmpSb.Match
  Expected_EnableScriptBlockInvocationLogging  = $cmpSbI.Expected
  Match_EnableScriptBlockInvocationLogging     = $cmpSbI.Match
  Expected_EnableModuleLogging                = $cmpMl.Expected
  Match_EnableModuleLogging                   = $cmpMl.Match
  Expected_EnableTranscripting                = $cmpTr.Expected
  Match_EnableTranscripting                   = $cmpTr.Match
  Interpretation = $null
}

# Firewall profiles
if (Get-Command -Name Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
  $sourceStatus.FirewallProfile.Attempted = $true
  try {
    foreach ($p in (Get-NetFirewallProfile -ErrorAction Stop)) {
      Add-Row -List $rows -Data @{
        Section = 'FirewallProfile'
        Source  = 'NetSecurity'
        Name    = $p.Name
        Enabled = $p.Enabled
        LogAllowed = $p.LogAllowed
        LogBlocked = $p.LogBlocked
        LogFileName = $p.LogFileName
        LogMaxSizeKilobytes = $p.LogMaxSizeKilobytes
        Interpretation = $null
      }
    }
    $sourceStatus.FirewallProfile.Succeeded = $true
  } catch {
    $sourceStatus.FirewallProfile.Succeeded = $false
    $sourceStatus.FirewallProfile.Error = $_.Exception.Message
    [void]$partialReasons.Add("Firewall profile source failed: $($sourceStatus.FirewallProfile.Error)")
    Add-Row -List $rows -Data @{
      Section = 'FirewallProfile'
      Source  = 'NetSecurity'
      Interpretation = ('Get-NetFirewallProfile failed: {0}' -f $_.Exception.Message)
    }
  }
} else {
  $sourceStatus.FirewallProfile.Succeeded = $false
  $sourceStatus.FirewallProfile.Error = 'Get-NetFirewallProfile not available.'
  [void]$partialReasons.Add($sourceStatus.FirewallProfile.Error)
  Add-Row -List $rows -Data @{
    Section = 'FirewallProfile'
    Source  = 'NetSecurity'
    Interpretation = 'Get-NetFirewallProfile not available.'
  }
}

$summary = [pscustomobject]@{
  ComputerName = $env:COMPUTERNAME
  Timestamp    = (Get-Date)
  Rows         = $rows.Count
  ReferenceJsonPath  = if ($ReferenceJsonPath) { '[configured path]' } else { $null }
  ReferenceLoaded    = $refInfo.Loaded
  ReferenceLoadError = $refInfo.Error
  Partial            = ($partialReasons.Count -gt 0)
  PartialReasons     = $partialReasons.ToArray()
  SourceStatus       = [pscustomobject]@{
    Reference       = [pscustomobject]$sourceStatus.Reference
    FirewallProfile = [pscustomobject]$sourceStatus.FirewallProfile
  }
}
$summary.PSObject.TypeNames.Insert(0, 'BaselineReport.Summary')

if ($ExportPath) {
  $folder = Split-Path -Path $ExportPath -Parent
  if (-not $folder) { $folder = (Get-Location).Path }
  [void](Ensure-Directory -Path $folder)

  $summary | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
  $base = [IO.Path]::GetFileNameWithoutExtension($ExportPath)
  $rows.ToArray() | Export-Csv -Path (Join-Path $folder ($base + '_sections.csv')) -NoTypeInformation -Encoding UTF8
}

if (-not $script:Quiet -and -not $script:NoConsoleSummary) {
  $rowsArr = $rows.ToArray()
  $refText  = 'Defaults (no path provided)'
  if ($refInfo.Loaded) { $refText = 'Loaded ([configured path])' }
  elseif ($refInfo.Path) { $refText = 'Defaults (failed: [configured path])' }

  Write-ConsoleSummary -Summary $summary -Findings ([System.Collections.ArrayList]::new()) `
    -CustomFields ([ordered]@{
      Rows            = $summary.Rows
      'Reference JSON' = $refText
    })

  # VBS / Credential Guard
  $cgRuntime = $rowsArr | Where-Object { $_.Section -eq 'CredentialGuard/VBS' -and $_.Source -eq 'Runtime' } | Select-Object -First 1
  $ppl       = $rowsArr | Where-Object { $_.Section -eq 'LSAProtection(PPL)' -and $_.Source -eq 'Runtime' } | Select-Object -First 1
  $dgCim     = $rowsArr | Where-Object { $_.Section -eq 'DeviceGuardStatus(CIM)' -and $_.Source -eq 'CIM' } | Select-Object -First 1

  $vbsRegText = '<n/a>'; $cgRegText = '<n/a>'; $vbsMatch = $null; $cgMatch = $null
  if ($cgRuntime) {
    $vbsRegText = ConvertTo-DisplayString $cgRuntime.EnableVirtualizationBasedSecurity
    $cgRegText  = ConvertTo-DisplayString $cgRuntime.LsaCfgFlags
    $vbsMatch   = $cgRuntime.Match_EnableVirtualizationBasedSecurity
    $cgMatch    = $cgRuntime.Match_LsaCfgFlags
  }
  $vbsCimVal = $null; $vbsCimTxt = 'Unknown'; $cgRunTxt = 'Unknown'
  if ($dgCim) {
    $vbsCimVal = $dgCim.VirtualizationBasedSecurityStatus
    $vbsCimTxt = Resolve-VbsStatusText -Value $vbsCimVal
    $cgRunTxt  = Resolve-CredentialGuardRunningText -SecurityServicesRunning $dgCim.SecurityServicesRunning
  }
  $runAsPplText = '<n/a>'; $pplMatch = $null
  if ($ppl) { $runAsPplText = ConvertTo-DisplayString $ppl.RunAsPPL; $pplMatch = $ppl.Match_RunAsPPL }
  $cgRunLevel = if ($cgRunTxt -eq 'Running') { 'Warn' } else { 'Good' }

  Write-UiHeader -Title 'VBS / Credential Guard'
  Write-KeyValue -Key 'VBS intent (registry)' -Value $vbsRegText -Level (Get-LevelForMatch $vbsMatch)
  Write-KeyValue -Key 'CG intent (registry)'  -Value $cgRegText  -Level (Get-LevelForMatch $cgMatch)
  Write-KeyValue -Key 'VBS status (CIM)'      -Value ("{0} ({1})" -f (ConvertTo-DisplayString $vbsCimVal), $vbsCimTxt) -Level 'Info'
  Write-KeyValue -Key 'CG running (CIM)'      -Value $cgRunTxt -Level $cgRunLevel

  # LSA Protection
  Write-UiHeader -Title 'LSA Protection'
  Write-KeyValue -Key 'RunAsPPL' -Value $runAsPplText -Level (Get-LevelForMatch $pplMatch)

  # Firewall (first 3 profiles)
  Write-UiHeader -Title 'Firewall (first 3 profiles)'
  $fw = $rowsArr | Where-Object { $_.Section -eq 'FirewallProfile' -and $_.Name } | Select-Object -First 3
  if ($fw) {
    foreach ($p in $fw) {
      $profileText = "{0}: Enabled={1}, LogAllowed={2}, LogBlocked={3}" -f $p.Name, $p.Enabled, $p.LogAllowed, $p.LogBlocked
      $profileLevel = 'Info'
      if ($p.Enabled -ne $true) { $profileLevel = 'Bad' }
      Write-KeyValue -Key 'Profile' -Value $profileText -Level $profileLevel
    }
  } else {
    Write-KeyValue -Key 'Profiles' -Value 'No data' -Level 'Dim'
  }
  Write-UiLine ''
}

# V2 output contract
$findings = @()
if ($sourceStatus.Reference.Requested -and -not $refInfo.Loaded) {
  $findings += [pscustomobject]@{
    Code     = 'BASELINE-ReferenceLoadFailed'
    Severity = 'Medium'
    Message  = ("Requested reference JSON was not loaded: {0}" -f $refInfo.Error)
  }
}
if ($sourceStatus.FirewallProfile.Succeeded -eq $false) {
  $findings += [pscustomobject]@{
    Code     = 'BASELINE-SourceFailed'
    Severity = 'Medium'
    Message  = ("Firewall profile source failed: {0}" -f $sourceStatus.FirewallProfile.Error)
  }
}
$resultToken = if ($findings.Count -gt 0) { 'WARN' } else { 'OK' }
if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
$v2Result = Get-V2ResultObject -ScriptName '42-Client-SecurityBaseline-Report-IntuneRef.ps1' -Mode $Mode -Result $resultToken -Findings $findings -Summary $summary -Metadata @{ Rows = @($rows.ToArray()); RefInfo = $refInfo }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }

#endregion Main
exit (Get-V2ExitCode -Result $resultToken)
