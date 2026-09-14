#Requires -RunAsAdministrator
#requires -version 5.1
<#
.SYNOPSIS
Audits Advanced Audit Policy (subcategories) via auditpol.exe, detects common misconfigurations,
optionally compares against a desired-state JSON and can remediate.

.DESCRIPTION
- Pipeline output: single structured object (Summary, Findings, ParsedPolicies).
- Console output: formatted blocks via Write-UiLine only.
- Desired policy:
  - If JSON is missing/unreadable/invalid => built-in defaults are used for drift checks only.
  - Remediate requires a valid JSON file.
- PowerShell 5.1 safe: avoids Generic.List binder edge-cases.

.PARAMETER Mode
Audit | Remediate

.PARAMETER DesiredPolicyJson
Path to JSON with desired subcategory settings supplied with $DesiredPolicyJson.

.PARAMETER ExportPath
Optional base path for CSV export. Creates: *_summary.csv, *_findings.csv, *_policies.csv

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

.PARAMETER Quiet
  Suppress console output.

.PARAMETER NoColor
  Disable colored output.


.OUTPUTS
  None by default.
  When -PassThru is used, emits a PSCustomObject v2 result with Script, Mode, Result, Findings, Summary, and Metadata properties.

.EXAMPLE
  .\33-AdvancedAuditPolicy-Audit.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateSet('Audit','Remediate')]
  [string]$Mode = 'Audit',

  [string]$DesiredPolicyJson,

  [string]$ExportPath

,
  [string]$ConfigPath,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '33-AdvancedAuditPolicy-Audit.ps1' -BoundParameters $PSBoundParameters `
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
  $result = Get-V2ResultObject -ScriptName '33-AdvancedAuditPolicy-Audit.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

$script:Findings = Get-FindingsList

# -------------------- Helpers --------------------


# Get-FindingStats imported from lib/Console.psm1

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
function Get-AuditPolText {
  # Use /r flag for CSV output (locale-independent)
  $r = Invoke-Auditpol -Arguments @('/get', '/category:*', '/r') -CaptureOutput
  if ($null -eq $r) { throw 'auditpol did not return a process result.' }
  if ($r.TimedOut) { throw 'auditpol evidence query timed out.' }
  if ($r.OutputTruncated -or $r.StderrTruncated) { throw 'auditpol evidence query produced truncated output.' }
  if (-not $r.Success) { throw "auditpol exited with code $($r.ExitCode)." }
  if ([string]::IsNullOrWhiteSpace([string]$r.Stdout)) { throw 'auditpol evidence query returned no CSV output.' }
  return [string]$r.Stdout
}

function Parse-AuditPolTextSection01 {
  param([hashtable]$RunState)
$RunState.policies = @()

  if ([string]::IsNullOrWhiteSpace($RunState.Text)) { throw 'auditpol CSV is empty.' }

  # Parse CSV output from auditpol /get /category:* /r (locale-independent)
  $lines = @($RunState.Text -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if ($lines.Count -lt 2) { throw 'auditpol CSV has no data rows.' }

  $RunState.csvRows = @($lines | ConvertFrom-Csv -ErrorAction Stop)
  $RunState.seenGuids = @{}
  $RunState.seenSubcategories = @{}
}

function Parse-AuditPolTextSection02 {
  param([hashtable]$RunState)
foreach ($row in $RunState.csvRows) {
    # /r has a stable six-column order even when display headers are localized:
    # machine, target, subcategory, subcategory GUID, inclusion, exclusion.
    $properties = @($row.PSObject.Properties)
    if ($properties.Count -lt 6) { throw 'auditpol CSV row has fewer than six columns.' }
    $sub = [string]$properties[2].Value
    $guidText = [string]$properties[3].Value
    $set = [string]$properties[4].Value
    $guid = [guid]::Empty
    if ((Test-AnyCondition -Conditions @({ [string]::IsNullOrWhiteSpace($sub) }, { [string]::IsNullOrWhiteSpace($set) })) -or -not [guid]::TryParse($guidText, [ref]$guid)) {
      throw 'auditpol CSV contains an invalid subcategory, GUID, or inclusion setting.'
    }
    $guidKey = $guid.ToString('D')
    if ((Test-AnyCondition -Conditions @({ $RunState.seenGuids.ContainsKey($guidKey) }, { $RunState.seenSubcategories.ContainsKey($sub) }))) {
      throw 'auditpol CSV contains duplicate subcategory evidence.'
    }
    $RunState.seenGuids[$guidKey] = $true
    $RunState.seenSubcategories[$sub] = $true
    $RunState.policies += [pscustomobject]@{
      Category        = '(NotReported)'
      Subcategory     = $sub
      SubcategoryGuid = $guidKey
      Setting         = $set
    }
  }
}

function Parse-AuditPolTextSection03 {
  param([hashtable]$RunState)
if ($RunState.policies.Count -lt 10) { throw 'auditpol CSV contains too few policy rows to be complete.' }

  $RunState.policies
}

function Parse-AuditPolText {
  param([Parameter(Mandatory=$true)][string]$Text, [hashtable]$RunState)
  $RunState.Text = $Text

  # Return policies as object[] (arrays behave best in PS pipeline and serializers).
    . Parse-AuditPolTextSection01 -RunState $RunState
    . Parse-AuditPolTextSection02 -RunState $RunState
    . Parse-AuditPolTextSection03 -RunState $RunState
}

function Convert-DesiredSettingToFlags {
  param([Parameter(Mandatory=$true)][string]$SettingString)

  $success = $false
  $failure = $false

  switch -Regex ($SettingString.Trim()) {
    '^Success and Failure$' { $success = $true;  $failure = $true;  break }
    '^Success$'             { $success = $true;  $failure = $false; break }
    '^Failure$'             { $success = $false; $failure = $true;  break }
    '^No Auditing$'         { $success = $false; $failure = $false; break }
    default { throw "Unknown setting string: '$SettingString'. Allowed: 'Success', 'Failure', 'Success and Failure', 'No Auditing'." }
  }

  [pscustomobject]@{ Success = $success; Failure = $failure }
}

function Get-DefaultDesiredPolicy {
  # Defaults are intentionally minimal: safe drift checks even without JSON.
  $json = @'
{
  "Logon/Logoff": {
    "Logon": "Success and Failure",
    "Special Logon": "Success"
  },
  "Account Logon": {
    "Kerberos Service Ticket Operations": "Failure",
    "Kerberos Authentication Service": "Failure"
  },
  "Policy Change": {
    "Audit Policy Change": "Success and Failure"
  }
}
'@
  $json | ConvertFrom-Json
}

function Try-ReadDesiredPolicyJson {
  param([string]$Path, [hashtable]$RunState)

  $sanitized = Sanitize-Path -Path $Path -MustExist
  if (-not $sanitized) {
    return [pscustomobject]@{ Desired = $null; Source = 'Missing'; Error = "DesiredPolicyJson not found or invalid: $Path" }
  }

  try {
    $RunState.desired = Get-BoundedUtf8FileContent -Path $sanitized -MaximumBytes 1048576 | ConvertFrom-Json
    if ((Test-AnyCondition -Conditions @({ $null -eq $RunState.desired }, { $RunState.desired -isnot [psobject] }))) { throw "Invalid JSON root object." }

    Assert-DesiredAuditPolicy -Desired $RunState.desired

    return [pscustomobject]@{ Desired = $RunState.desired; Source = 'Json'; Error = $null }
  }
  catch {
    return [pscustomobject]@{ Desired = $null; Source = 'Invalid'; Error = $_.Exception.Message }
  }
}
function Assert-DesiredAuditPolicy {
  param($Desired)
  foreach ($category in $Desired.PSObject.Properties) {
    if ($null -eq $category.Value -or $category.Value -isnot [psobject]) {
      throw "Invalid JSON: category '$($category.Name)' is not an object."
    }
    foreach ($subcategory in $category.Value.PSObject.Properties) {
      $value = [string]$subcategory.Value
      if ([string]::IsNullOrWhiteSpace($value)) {
        throw "Invalid JSON: empty setting for '$($category.Name) -> $($subcategory.Name)'."
      }
      [void](Convert-DesiredSettingToFlags -SettingString $value)
    }
  }
}

# -------------------- Console UI (Write-ConsoleSummary / Get-SeverityColor from lib/Console.psm1) --------------------

function Write-FindingsConsole {
  param([Parameter(Mandatory=$true)][System.Collections.IList]$Findings)

  Write-DecorativeRule -Title ("Findings ({0})" -f $Findings.Count)

  if ($Findings.Count -eq 0) {
    Write-UiLine 'No findings.' -ForegroundColor Green
    return
  }

  $order = @('High','Medium','Low','Info')
  foreach ($sev in $order) {
    $items = @($Findings | Where-Object { $_.Severity -eq $sev })
    if ($items.Count -eq 0) { continue }

    $color = Get-SeverityColor -Severity $sev
    Write-UiLine ("{0} ({1})" -f $sev.ToUpperInvariant(), $items.Count) -ForegroundColor $color

    foreach ($f in $items) {
      Write-UiLine ("  [{0}] {1}" -f $f.Code, $f.Message) -ForegroundColor $color
    }

    Write-UiLine ''
  }
}

# -------------------- Main --------------------

function Invoke-Capability33MainPhase01 {
  param([hashtable]$RunState)
  Require-Admin
  Ensure-Exe -Name 'auditpol.exe'

  $RunState.auditEvidenceComplete = $true
  $RunState.policies = @()
  try {
    $txt = Get-AuditPolText
    $RunState.policies = Parse-AuditPolText -Text $txt -RunState $RunState
  } catch {
    $RunState.auditEvidenceComplete = $false
    Add-Finding -FindingList $script:Findings -Code 'AUD-EvidenceIncomplete' -Severity 'High' -Message ("Audit policy evidence is incomplete: {0}" -f $_.Exception.Message)
  }

  if ($RunState.policies.Count -eq 0) {
    Add-Finding -FindingList $script:Findings -Code 'AUD-ParserEmpty' -Severity 'High' -Message 'Parsed 0 audit policies. Check parser/locale/Windows version.'
  }

  # Basic audit checks.
  $mustHave = @(
    @{ CategoryLike='Logon*';         SubLike='Logon';               Severity='High';   Code='AUD-LogonOff';         Message='Logon auditing is disabled (No Auditing).' },
    @{ CategoryLike='Account Logon*'; SubLike='Kerberos*';           Severity='Medium'; Code='AUD-KerberosOff';      Message='Kerberos auditing is disabled (No Auditing).' },
    @{ CategoryLike='Policy Change*'; SubLike='Audit Policy Change'; Severity='Low';    Code='AUD-PolicyChangeOff'; Message='Audit Policy Change is disabled (No Auditing).' }
  )

  foreach ($m in $mustHave) {
    $hit = $RunState.policies | Where-Object { $_.Subcategory -like $m.SubLike } | Select-Object -First 1
    if ($hit) {
      if ([string]$hit.Setting -match 'No Auditing') {
        Add-Finding -FindingList $script:Findings -Code $m.Code -Severity $m.Severity -Message ("{0} Category='{1}', Subcategory='{2}', Setting='{3}'." -f $m.Message, $hit.Category, $hit.Subcategory, $hit.Setting)
      }
    } else {
      Add-Finding -FindingList $script:Findings -Code 'AUD-ParserMiss' -Severity 'High' -Message ("Required audit subcategory is missing from complete evidence: {0}" -f $m.SubLike)
    }
  }

  # Desired policy (JSON or defaults).
  $desiredInfo   = Try-ReadDesiredPolicyJson -Path $DesiredPolicyJson -RunState $RunState
  $RunState.desired       = $desiredInfo.Desired
  $RunState.desiredSource = $desiredInfo.Source
  $RunState.desiredError  = $desiredInfo.Error
}
function Invoke-Capability33MainPhase02 {
  param([hashtable]$RunState)
  if (-not $RunState.desired) {
    $RunState.desired = Get-DefaultDesiredPolicy
    $RunState.desiredSource = if ($RunState.desiredSource -eq 'None') { 'Default' } else { ("{0} -> Default" -f $RunState.desiredSource) }

    if ($RunState.desiredError) {
      Add-Finding -FindingList $script:Findings -Code 'AUD-DesiredPolicyFallback' -Severity 'Info' -Message ("DesiredPolicyJson could not be loaded; using defaults. Error: {0}" -f $RunState.desiredError)
    } else {
      Add-Finding -FindingList $script:Findings -Code 'AUD-DesiredPolicyDefault' -Severity 'Info' -Message 'No DesiredPolicyJson provided; using built-in defaults for drift checks.'
    }
  }
}
function Invoke-Capability33MainPhase03 {
  param([hashtable]$RunState)
  foreach ($catProp in $RunState.desired.PSObject.Properties) {
    $catName = $catProp.Name
    $subsObj = $catProp.Value

    foreach ($subProp in $subsObj.PSObject.Properties) {
      $subName = $subProp.Name
      $wanted  = [string]$subProp.Value

      $current = $RunState.policies | Where-Object { $_.Subcategory -eq $subName } | Select-Object -First 1
      if (-not $current) {
        Add-Finding -FindingList $script:Findings -Code 'AUD-DesiredNotFound' -Severity 'High' -Message ("Desired policy has '{0} -> {1}', but it was not found in auditpol output." -f $catName, $subName)
        continue
      }

      if ([string]$current.Setting -ne $wanted) {
        Add-Finding -FindingList $script:Findings -Code 'AUD-Drift' -Severity 'Medium' -Message ("Drift: '{0} -> {1}' is '{2}', expected '{3}'." -f $catName, $subName, $current.Setting, $wanted) -Extra @{ Category = $catName; Subcategory = $subName; Current = $current.Setting; Desired = $wanted }
      }
    }
  }
}
function Invoke-Capability33MainPhase04 {
  param([hashtable]$RunState)
  if ($Mode -eq 'Remediate') {
    . Assert-AuditPolicyRemediationPreconditions -RunState $RunState
    . Set-DesiredAuditPolicy -RunState $RunState
    . Confirm-DesiredAuditPolicy -RunState $RunState
  }
}
function Assert-AuditPolicyRemediationPreconditions {
  param([hashtable]$RunState)
    if (-not $RunState.auditEvidenceComplete) {
      $msg = 'Mode=Remediate requires complete pre-remediation audit policy evidence.'
      Add-Finding -FindingList $script:Findings -Code 'AuditPol-IncompletePrecondition' -Severity 'Critical' -Message $msg
      $v2Result = Get-V2ResultObject -ScriptName '33-AdvancedAuditPolicy-Audit.ps1' -Mode $Mode -Result 'FAIL' -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary @{ Error = $msg } -Metadata @{}
      Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
      if ($PassThru) { $v2Result }
      exit (Get-V2ExitCode -Result 'FAIL')
    }
    if ($desiredInfo.Source -ne 'Json') {
      $msg = 'Mode=Remediate requires a readable file passed with -DesiredPolicyJson; built-in defaults cannot be remediated.'
      Write-Warning $msg
      Add-Finding -FindingList $script:Findings -Code 'AuditPol-NoDesiredPolicy' -Severity 'Critical' -Message $msg
      $v2Result = Get-V2ResultObject -ScriptName '33-AdvancedAuditPolicy-Audit.ps1' -Mode $Mode -Result 'FAIL' -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary @{ Error = $msg } -Metadata @{}
      Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
      if ($PassThru) { $v2Result }
      exit (Get-V2ExitCode -Result 'FAIL')
    }
}
function Set-DesiredAuditPolicy {
  param([hashtable]$RunState)
    foreach ($catProp in $RunState.desired.PSObject.Properties) {
      $subsObj = $catProp.Value

      foreach ($subProp in $subsObj.PSObject.Properties) {
        Set-DesiredAuditSubcategory -Property $subProp
      }
    }
}
function Set-DesiredAuditSubcategory {
  param($Property)
  $subName = $Property.Name
  if ($subName -notmatch '^[a-zA-Z0-9 \-\/]+$') {
    Add-Finding -FindingList $script:Findings -Code 'AuditPol-InvalidSubcategory' -Severity 'High' -Message ("Subcategory name contains invalid characters, skipped: {0}" -f $subName)
    return
  }
  $flags = Convert-DesiredSettingToFlags -SettingString ([string]$Property.Value)
  $successArg = if ($flags.Success) { '/success:enable' } else { '/success:disable' }
  $failureArg = if ($flags.Failure) { '/failure:enable' } else { '/failure:disable' }
  $operation = ('auditpol.exe /set /subcategory:"{0}" {1} {2}' -f $subName, $successArg, $failureArg)
  if ($script:__EntryCmdlet.ShouldProcess($subName, $operation)) {
    $auditArgs = @('/set', "/subcategory:`"$subName`"", $successArg, $failureArg)
    if ((Invoke-Auditpol -Arguments $auditArgs) -ne $true) {
      Add-Finding -FindingList $script:Findings -Code 'AuditPol-SetFailed' -Severity 'High' -Message ("auditpol /set failed for subcategory: {0}" -f $subName)
    }
  }
}
function Confirm-DesiredAuditPolicy {
  param([hashtable]$RunState)
    try {
      $txt = Get-AuditPolText
      $RunState.policies = Parse-AuditPolText -Text $txt -RunState $RunState
      foreach ($catProp in $RunState.desired.PSObject.Properties) {
        foreach ($subProp in $catProp.Value.PSObject.Properties) {
          $verified = $RunState.policies | Where-Object { $_.Subcategory -eq $subProp.Name } | Select-Object -First 1
          if ((Test-AnyCondition -Conditions @({ -not $verified }, { [string]$verified.Setting -ne [string]$subProp.Value }))) {
            Add-Finding -FindingList $script:Findings -Code 'AuditPol-PostconditionFailed' -Severity 'High' -Message ("Post-remediation policy mismatch: {0} -> {1}." -f $catProp.Name,$subProp.Name)
          }
        }
      }
    } catch {
      $RunState.auditEvidenceComplete = $false
      Add-Finding -FindingList $script:Findings -Code 'AUD-PostRemediationEvidenceIncomplete' -Severity 'High' -Message ("Post-remediation audit evidence is incomplete: {0}" -f $_.Exception.Message)
    }
}
function Invoke-Capability33MainPhase05 {
  param([hashtable]$RunState)
  $summary = [pscustomobject]@{
    ComputerName   = [string]$env:COMPUTERNAME
    Mode           = [string]$Mode
    PoliciesParsed = [int]$RunState.policies.Count
    FindingsCount  = [int]$script:Findings.Count
    Timestamp      = [datetime](Get-Date)
    DesiredPolicy  = [string]$RunState.desiredSource
  }

  # Optional export.
  if ($ExportPath) {
    $dir = Split-Path -Path $ExportPath -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
      New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    $base   = [IO.Path]::GetFileNameWithoutExtension($ExportPath)
    $folder = Split-Path -Path $ExportPath -Parent
    if (-not $folder) { $folder = (Get-Location).Path }

    $summary               | Export-Csv -Path (Join-Path $folder ($base + "_summary.csv"))   -NoTypeInformation -Encoding UTF8
    @($script:Findings)    | Export-Csv -Path (Join-Path $folder ($base + "_findings.csv"))  -NoTypeInformation -Encoding UTF8
    $RunState.policies              | Export-Csv -Path (Join-Path $folder ($base + "_policies.csv"))  -NoTypeInformation -Encoding UTF8
  }

  # Formatted console output (does not write to the pipeline).
  $customFields = [ordered]@{
    'Mode'          = $summary.Mode
    'Parsed'        = [string]$summary.PoliciesParsed
    'DesiredPolicy' = $RunState.desiredSource
  }
  if ($RunState.desiredError) { $customFields['PolicyError'] = $RunState.desiredError }
  Write-ConsoleSummary -Summary $summary -Findings $script:Findings `
    -Title 'Advanced Audit Policy - Summary' `
    -CustomFields $customFields
  Write-FindingsConsole -Findings $script:Findings
}
function Invoke-Capability33Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation)
  $RunState = @{

  }
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability33MainPhase01 -RunState $RunState
  . Invoke-Capability33MainPhase02 -RunState $RunState
  . Invoke-Capability33MainPhase03 -RunState $RunState
  . Invoke-Capability33MainPhase04 -RunState $RunState
  . Invoke-Capability33MainPhase05 -RunState $RunState
  $script:RunState = $RunState
}

. Invoke-Capability33Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation

# V2 output contract
function Get-Capability33ResultToken {
  param([hashtable]$RunState)
  $resultToken = if (-not $RunState.auditEvidenceComplete) { 'FAIL' } elseif ($Strict -and $script:Findings.Count -gt 0) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability33ResultToken -RunState $RunState
$v2Result = Get-V2ResultObject -ScriptName '33-AdvancedAuditPolicy-Audit.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $summary -Metadata @{ ParsedPolicies = $RunState.policies }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
