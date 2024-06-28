#requires -version 5.1
<#
.SYNOPSIS
Audits Advanced Audit Policy (subcategories) via auditpol.exe, detects common misconfigurations,
optionally compares against a desired-state JSON and can remediate.

.DESCRIPTION
- Pipeline output: single structured object (Summary, Findings, ParsedPolicies).
- Console output: pretty, human-friendly blocks via Write-Host only.
- Desired policy:
  - If JSON is missing/unreadable/invalid => built-in defaults are used for drift checks only.
  - Remediate requires a valid JSON file.
- PowerShell 5.1 safe: avoids Generic.List binder edge-cases.

.PARAMETER Mode
AuditOnly | Remediate

.PARAMETER DesiredPolicyJson
Path to JSON with desired subcategory settings (example: PATH/TO/JSON/auditpolicy.json).

.PARAMETER ExportPath
Optional base path for CSV export. Creates: *_summary.csv, *_findings.csv, *_policies.csv
.EXAMPLE
  .\33-AdvancedAuditPolicy-Audit.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateSet('AuditOnly','Remediate')]
  [string]$Mode = 'AuditOnly',

  [string]$DesiredPolicyJson,

  [string]$ExportPath
)

$script:LibPath = Join-Path $PSScriptRoot 'lib'
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force


Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Findings are kept in ArrayList to avoid PS 5.1 DLR binder edge-cases with Generic.List.
$script:Findings = New-Object System.Collections.ArrayList

# -------------------- Helpers --------------------


function Ensure-Exe {
  param([Parameter(Mandatory=$true)][string]$Name)
  $cmd = Get-Command -Name $Name -ErrorAction SilentlyContinue
  if (-not $cmd) { throw "Executable not found: $Name" }
}

function Get-FindingStats {
  param([Parameter(Mandatory=$true)][System.Collections.ArrayList]$Findings)

  $h = @{ Info = 0; Low = 0; Medium = 0; High = 0 }
  foreach ($f in $Findings) {
    if ($null -eq $f) { continue }
    $sev = [string]$f.Severity
    if ($h.ContainsKey($sev)) { $h[$sev]++ }
  }
  [pscustomobject]$h
}

function Get-AuditPolText {
  $raw = & auditpol.exe /get /category:* 2>&1
  ($raw | Out-String)
}

function Parse-AuditPolText {
  param([Parameter(Mandatory=$true)][string]$Text)

  # Return policies as object[] (arrays behave best in PS pipeline and serializers).
  $policies = @()

  $lines = $Text -split "`r?`n"
  $currentCategory = $null

  foreach ($l in $lines) {
    $line = $l.TrimEnd()
    if ([string]::IsNullOrWhiteSpace($line)) { continue }

    # Category line heuristic (locale dependent).
    if ($line -notmatch '\s{2,}' -and $line -notmatch '^-{2,}$') {
      if ($line -match 'Subcategory' -or $line -match 'Category' -or $line -match 'Setting') { continue }
      $currentCategory = $line.Trim()
      continue
    }

    # Data line heuristic: 2+ spaces as column delimiter.
    if ($line -match '\s{2,}') {
      $parts = $line -split '\s{2,}'
      if ($parts.Count -ge 2) {
        $sub = ($parts[0]).Trim()
        $set = ($parts[$parts.Count - 1]).Trim()

        if ([string]::IsNullOrWhiteSpace($sub) -or [string]::IsNullOrWhiteSpace($set)) { continue }
        if ($sub -match 'Subcategory' -or $set -match 'Setting') { continue }

        if ([string]::IsNullOrWhiteSpace($currentCategory)) { $currentCategory = '(Unknown)' }

        $policies += [pscustomobject]@{
          Category    = $currentCategory
          Subcategory = $sub
          Setting     = $set
        }
      }
    }
  }

  ,$policies
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
  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) {
    return [pscustomobject]@{ Desired = $null; Source = 'None'; Error = $null }
  }

  if (-not (Test-Path -LiteralPath $Path)) {
    return [pscustomobject]@{ Desired = $null; Source = 'Missing'; Error = "DesiredPolicyJson not found: $Path" }
  }

  try {
    $desired = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($null -eq $desired -or $desired -isnot [psobject]) { throw "Invalid JSON root object." }

    # Validate values up-front (prevents remediation surprises).
    foreach ($catProp in $desired.PSObject.Properties) {
      if ($null -eq $catProp.Value -or $catProp.Value -isnot [psobject]) {
        throw "Invalid JSON: category '$($catProp.Name)' is not an object."
      }
      foreach ($subProp in $catProp.Value.PSObject.Properties) {
        $val = [string]$subProp.Value
        if ([string]::IsNullOrWhiteSpace($val)) {
          throw "Invalid JSON: empty setting for '$($catProp.Name) -> $($subProp.Name)'."
        }
        [void](Convert-DesiredSettingToFlags -SettingString $val)
      }
    }

    return [pscustomobject]@{ Desired = $desired; Source = 'Json'; Error = $null }
  }
  catch {
    return [pscustomobject]@{ Desired = $null; Source = 'Invalid'; Error = $_.Exception.Message }
  }
}

# -------------------- Console UI --------------------

function Get-SeverityColor {
  param([Parameter(Mandatory=$true)][ValidateSet('Info','Low','Medium','High')][string]$Severity)

  switch ($Severity) {
    'High'   { 'Red' }
    'Medium' { 'Yellow' }
    'Low'    { 'Cyan' }
    default  { 'Gray' }
  }
}

function Write-Rule {
  param([string]$Title)

  $line = ('=' * 62)
  Write-Host ''
  Write-Host $line -ForegroundColor DarkCyan
  if ($Title) { Write-Host ("{0}" -f $Title) -ForegroundColor Cyan }
  Write-Host $line -ForegroundColor DarkCyan
}

function Write-ConsoleSummary {
  param(
    [Parameter(Mandatory=$true)][psobject]$Summary,
    [Parameter(Mandatory=$true)][System.Collections.ArrayList]$Findings,
    [Parameter(Mandatory=$true)][string]$DesiredPolicySource,
    [string]$DesiredPolicyError
  )

  $stats = Get-FindingStats -Findings $Findings

  Write-Rule -Title 'Advanced Audit Policy - Summary'

  Write-Host ("ComputerName     : {0}" -f $Summary.ComputerName)
  Write-Host ("Mode             : {0}" -f $Summary.Mode)
  Write-Host ("Policies parsed  : {0}" -f $Summary.PoliciesParsed)

  $countLine = ("Findings         : {0} (High={1}, Medium={2}, Low={3}, Info={4})" -f $Findings.Count, $stats.High, $stats.Medium, $stats.Low, $stats.Info)
  $countColor = if ($stats.High -gt 0) { 'Red' } elseif ($stats.Medium -gt 0) { 'Yellow' } elseif ($Findings.Count -gt 0) { 'Cyan' } else { 'Green' }
  Write-Host $countLine -ForegroundColor $countColor

  Write-Host ("Desired policy   : {0}" -f $DesiredPolicySource)
  if ($DesiredPolicyError) {
    Write-Host ("DesiredPolicyError: {0}" -f $DesiredPolicyError) -ForegroundColor Yellow
  }

  Write-Host ("Timestamp        : {0}" -f $Summary.Timestamp)
}

function Write-FindingsConsole {
  param([Parameter(Mandatory=$true)][System.Collections.ArrayList]$Findings)

  Write-Rule -Title ("Findings ({0})" -f $Findings.Count)

  if ($Findings.Count -eq 0) {
    Write-Host 'No findings.' -ForegroundColor Green
    return
  }

  $order = @('High','Medium','Low','Info')
  foreach ($sev in $order) {
    $items = @($Findings | Where-Object { $_.Severity -eq $sev })
    if ($items.Count -eq 0) { continue }

    $color = Get-SeverityColor -Severity $sev
    Write-Host ("{0} ({1})" -f $sev.ToUpperInvariant(), $items.Count) -ForegroundColor $color

    foreach ($f in $items) {
      Write-Host ("  [{0}] {1}" -f $f.Code, $f.Message) -ForegroundColor $color
    }

    Write-Host ''
  }
}

# -------------------- Main --------------------

if (-not (Test-IsAdmin)) { throw "Administrative privileges are required." }
Ensure-Exe -Name 'auditpol.exe'

$txt = Get-AuditPolText
$policies = Parse-AuditPolText -Text $txt

if ($policies.Count -eq 0) {
  Add-Finding -Code 'AUD-ParserEmpty' -Severity 'High' -Message 'Parsed 0 audit policies. Check parser/locale/Windows version.'
}

# Basic checks (kept from your version).
$mustHave = @(
  @{ CategoryLike='Logon*';         SubLike='Logon';               Severity='High';   Code='AUD-LogonOff';         Message='Logon auditing is disabled (No Auditing).' },
  @{ CategoryLike='Account Logon*'; SubLike='Kerberos*';           Severity='Medium'; Code='AUD-KerberosOff';      Message='Kerberos auditing is disabled (No Auditing).' },
  @{ CategoryLike='Policy Change*'; SubLike='Audit Policy Change'; Severity='Low';    Code='AUD-PolicyChangeOff'; Message='Audit Policy Change is disabled (No Auditing).' }
)

foreach ($m in $mustHave) {
  $hit = $policies | Where-Object { ($_.Category -like $m.CategoryLike) -and ($_.Subcategory -like $m.SubLike) } | Select-Object -First 1
  if ($hit) {
    if ([string]$hit.Setting -match 'No Auditing') {
      Add-Finding -Code $m.Code -Severity $m.Severity -Message ("{0} Category='{1}', Subcategory='{2}', Setting='{3}'." -f $m.Message, $hit.Category, $hit.Subcategory, $hit.Setting)
    }
  } else {
    Add-Finding -Code 'AUD-ParserMiss' -Severity 'Info' -Message ("Could not find subcategory (parser/locale): {0}/{1}" -f $m.CategoryLike, $m.SubLike)
  }
}

# Desired policy (JSON or defaults).
$desiredInfo   = Try-ReadDesiredPolicyJson -Path $DesiredPolicyJson
$desired       = $desiredInfo.Desired
$desiredSource = $desiredInfo.Source
$desiredError  = $desiredInfo.Error

if (-not $desired) {
  $desired = Get-DefaultDesiredPolicy
  $desiredSource = if ($desiredSource -eq 'None') { 'Default' } else { ("{0} -> Default" -f $desiredSource) }

  if ($desiredError) {
    Add-Finding -Code 'AUD-DesiredPolicyFallback' -Severity 'Info' -Message ("DesiredPolicyJson could not be loaded; using defaults. Error: {0}" -f $desiredError)
  } else {
    Add-Finding -Code 'AUD-DesiredPolicyDefault' -Severity 'Info' -Message 'No DesiredPolicyJson provided; using built-in defaults for drift checks.'
  }
}

# Drift checks.
foreach ($catProp in $desired.PSObject.Properties) {
  $catName = $catProp.Name
  $subsObj = $catProp.Value

  foreach ($subProp in $subsObj.PSObject.Properties) {
    $subName = $subProp.Name
    $wanted  = [string]$subProp.Value

    $current = $policies | Where-Object { ($_.Category -eq $catName) -and ($_.Subcategory -eq $subName) } | Select-Object -First 1
    if (-not $current) {
      Add-Finding -Code 'AUD-DesiredNotFound' -Severity 'Info' -Message ("Desired policy has '{0} -> {1}', but it was not found in auditpol output." -f $catName, $subName)
      continue
    }

    if ([string]$current.Setting -ne $wanted) {
      Add-Finding -Code 'AUD-Drift' -Severity 'Medium' -Message ("Drift: '{0} -> {1}' is '{2}', expected '{3}'." -f $catName, $subName, $current.Setting, $wanted)
    }
  }
}

# Remediation: only with valid JSON (never with defaults).
if ($Mode -eq 'Remediate') {
  if ($desiredInfo.Source -ne 'Json') {
    throw "Mode=Remediate requires a valid -DesiredPolicyJson (not defaults). Example: PATH/TO/JSON/auditpolicy.json"
  }

  foreach ($catProp in $desired.PSObject.Properties) {
    $subsObj = $catProp.Value

    foreach ($subProp in $subsObj.PSObject.Properties) {
      $subName   = $subProp.Name
      $setWanted = [string]$subProp.Value

      $flags      = Convert-DesiredSettingToFlags -SettingString $setWanted
      $successArg = if ($flags.Success) { '/success:enable' } else { '/success:disable' }
      $failureArg = if ($flags.Failure) { '/failure:enable' } else { '/failure:disable' }

      # auditpol /set syntax [page:1]
      $operation = ('auditpol.exe /set /subcategory:"{0}" {1} {2}' -f $subName, $successArg, $failureArg)
      if ($PSCmdlet.ShouldProcess($subName, $operation)) {
        $auditArgs = @('/set', "/subcategory:$subName", $successArg, $failureArg)
        & auditpol.exe @auditArgs | Out-Null
      }
    }
  }

  $txt = Get-AuditPolText
  $policies = Parse-AuditPolText -Text $txt
}

# Summary object (materialized primitives to keep StrictMode and serialization safe).
$summary = [pscustomobject]@{
  ComputerName   = [string]$env:COMPUTERNAME
  Mode           = [string]$Mode
  PoliciesParsed = [int]$policies.Count
  FindingsCount  = [int]$script:Findings.Count
  Timestamp      = [datetime](Get-Date)
  DesiredPolicy  = [string]$desiredSource
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
  $policies              | Export-Csv -Path (Join-Path $folder ($base + "_policies.csv"))  -NoTypeInformation -Encoding UTF8
}

# Pretty console output (does not touch pipeline).
Write-ConsoleSummary -Summary $summary -Findings $script:Findings -DesiredPolicySource $desiredSource -DesiredPolicyError $desiredError
Write-FindingsConsole -Findings $script:Findings

# Pipeline output (structured only).
#[pscustomobject]@{
#  Summary        = $summary
#  Findings       = @($script:Findings)
#  ParsedPolicies = $policies
#}
