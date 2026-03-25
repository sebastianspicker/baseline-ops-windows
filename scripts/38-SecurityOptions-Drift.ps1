#requires -version 5.1
<#
.SYNOPSIS
Audit/drift sensor for selected "Security Options"-adjacent settings via registry indicators.

.DESCRIPTION
- Always runs built-in baseline checks (LmCompatibilityLevel, EnableLUA).
- Optionally loads desired state from JSON (path or inline JSON), compares, and can remediate drift.
- If DesiredJson is missing/unreadable/invalid, continues with baseline checks only.
- Pipeline output: exactly one structured object (safe for Export-Csv / ConvertTo-Json / Where-Object).
- Console output: pretty, human-readable, colorized summary via Write-UiLine / Write-Information only.

.PARAMETER Mode
Audit | Remediate

.PARAMETER DesiredJson
Either:
1) Path to a JSON file (example: PATH/TO/JSON/securityoptions.json), or
2) Inline JSON string.

.PARAMETER ExportPath
Optional base path for CSV export (suffixes will be appended).

.PARAMETER Quiet
Suppress console output (still returns structured object).

.PARAMETER NoColor
Disable colorized console output.


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

.OUTPUTS
PSCustomObject with Summary, Findings, CurrentValues, Drift, DesiredLoaded.
.EXAMPLE
  .\38-SecurityOptions-Drift.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateSet('Audit','Remediate')]
  [string]$Mode = 'Audit',

  [string]$DesiredJson,

  [string]$ExportPath,

  [switch]$Quiet,

  [switch]$NoColor

,
  [string]$ConfigPath,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
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

# -------------------------
# Script-scope state (avoid null method calls under StrictMode)
# -------------------------
$script:Quiet         = [bool]$Quiet
$script:NoColor       = [bool]$NoColor
$script:FindingsTimestampLocal = $true
$script:Findings      = New-FindingsList
$script:CurrentValues = New-Object System.Collections.Generic.List[object]
$script:Drift         = New-Object System.Collections.Generic.List[object]

# -------------------------
# Console helpers (Get-SeverityColor from lib/Console.psm1; custom Write-ConsoleSummary for Drift/CurrentValues)
# -------------------------

function Format-Value {
  param([object]$Value)

  if ($null -eq $Value) { return '<null>' }
  if ($Value -is [byte[]]) { return ('0x' + (($Value | ForEach-Object { $_.ToString('X2') }) -join '')) }
  if ($Value -is [string[]]) { return ('[' + ($Value -join ',') + ']') }
  return ($Value.ToString())
}

function Write-ConsoleSummary {
  param(
    [Parameter(Mandatory)][pscustomobject]$Summary,

    [Parameter(Mandatory)]
    [AllowEmptyCollection()]
    [System.Collections.Generic.List[object]]$Findings,

    [Parameter(Mandatory)]
    [AllowEmptyCollection()]
    [System.Collections.Generic.List[object]]$CurrentValues,

    [Parameter(Mandatory)]
    [AllowEmptyCollection()]
    [System.Collections.Generic.List[object]]$Drift
  )

  if ($script:Quiet) { return }

  $sevOrder = @('High','Medium','Low','Info')
  $counts = @{}
  foreach ($s in $sevOrder) { $counts[$s] = 0 }
  foreach ($f in $Findings) {
    $sev = [string]$f.Severity
    if ($counts.ContainsKey($sev)) { $counts[$sev]++ }
  }

  # StrictMode-safe counting: use Measure-Object, not (...).Count on pipeline results. [web:161]
  $driftCount = ($Drift | Where-Object { $_.Drift } | Measure-Object).Count
  $remediated = ($Drift | Where-Object { $_.Remediated -eq $true } | Measure-Object).Count
  $failed     = ($Drift | Where-Object { $_.RemediateError } | Measure-Object).Count

  $headlineColor =
    if ($counts['High'] -gt 0 -or $failed -gt 0) { [ConsoleColor]::Red }
    elseif ($counts['Medium'] -gt 0 -or $driftCount -gt 0) { [ConsoleColor]::Yellow }
    else { [ConsoleColor]::Green }

  Write-BlankLine
  Write-UiLine -Text "========== SecurityOptions Drift ==========" -Color $headlineColor
  Write-UiLine -Text ("Computer   : {0}" -f $Summary.ComputerName) -Color Gray
  Write-UiLine -Text ("Mode       : {0}" -f $Summary.Mode) -Color Gray
  Write-UiLine -Text ("Desired    : {0}" -f ($(if ($Summary.DesiredLoaded) { 'Loaded' } else { 'Not loaded (baseline only)' }))) -Color Gray
  Write-UiLine -Text ("Timestamp  : {0}" -f $Summary.Timestamp) -Color Gray
  Write-BlankLine

  Write-UiLine -Text "Findings:" -Color White
  foreach ($s in $sevOrder) {
    $c = $counts[$s]
    $col = Get-SeverityColor -Severity $s
    Write-UiLine -Text ("  {0,-6}: {1}" -f $s, $c) -Color $col
  }

  Write-BlankLine
  Write-UiLine -Text ("Drift items: Total={0}, Drift={1}, Remediated={2}, Failed={3}" -f $Summary.DriftItems, $driftCount, $remediated, $failed) -Color White

  Write-BlankLine
  Write-UiLine -Text "Current values:" -Color White
  foreach ($cv in $CurrentValues) {
    $valText = Format-Value -Value $cv.Value
    Write-UiLine -Text ("  {0}\{1} = {2} ({3})" -f $cv.Path, $cv.Name, $valText, $cv.SourceHint) -Color Gray
  }

  $topFindings = $Findings |
    Sort-Object @{ Expression = { @('High','Medium','Low','Info').IndexOf([string]$_.Severity) }; Ascending = $true }, Timestamp |
    Select-Object -First 10

  Write-BlankLine
  Write-UiLine -Text "Top findings (max 10):" -Color White
  if (($topFindings | Measure-Object).Count -eq 0) {
    Write-UiLine -Text "  None" -Color Green
  } else {
    foreach ($f in $topFindings) {
      $col = Get-SeverityColor -Severity ([string]$f.Severity)
      Write-UiLine -Text ("  [{0}] {1}: {2}" -f $f.Severity, $f.Code, $f.Message) -Color $col
    }
  }

  $topDrift = $Drift | Where-Object { $_.Drift } | Select-Object -First 10
  Write-BlankLine
  Write-UiLine -Text "Drift (max 10):" -Color White
  if (($topDrift | Measure-Object).Count -eq 0) {
    Write-UiLine -Text "  None" -Color Green
  } else {
    foreach ($d in $topDrift) {
      $cur = Format-Value -Value $d.Current
      $des = Format-Value -Value $d.Desired
      $statusColor = if ($d.Remediated -eq $true) { [ConsoleColor]::Green } else { [ConsoleColor]::Yellow }
      $suffix = if ($d.RemediateError) { " ERROR: $($d.RemediateError)" } else { '' }
      Write-UiLine -Text ("  {0}\{1} ({2}) Current={3} Desired={4} Remediated={5}{6}" -f $d.Path, $d.Name, $d.Type, $cur, $des, $d.Remediated, $suffix) -Color $statusColor
    }
  }

  Write-BlankLine
  Write-UiLine -Text "==========================================" -Color $headlineColor
  Write-BlankLine
}

# -------------------------
# Core helpers
# -------------------------

function Get-Reg {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name
  )

  try {
    (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
  } catch {
    return $null
  }
}

function Ensure-RegKey {
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -Path $Path -Force | Out-Null
  }
}

function Normalize-RegistryType {
  param([Parameter(Mandatory)][string]$TypeRaw)

  $t = $TypeRaw.ToString().Trim()
  switch -Regex ($t) {
    '^dword$'        { return 'DWord' }
    '^qword$'        { return 'QWord' }
    '^string$'       { return 'String' }
    '^expandstring$' { return 'ExpandString' }
    '^multistring$'  { return 'MultiString' }
    '^binary$'       { return 'Binary' }
    '^unknown$'      { return 'Unknown' }
    default          { return $null }
  }
}

function Normalize-ValueForType {
  param(
    [Parameter(Mandatory)][string]$Type,
    [Parameter(Mandatory)][object]$Value
  )

  switch ($Type) {
    'DWord' { return [int]$Value }
    'QWord' { return [long]$Value }
    'MultiString' {
      if ($Value -is [System.Array]) { return [string[]]$Value }
      return [string[]]@([string]$Value)
    }
    'Binary' {
      if ($Value -is [byte[]]) { return $Value }

      $s = [string]$Value
      $s = ($s -replace '^0x','') -replace '[-\s]',''
      if ($s.Length -eq 0) { return [byte[]]@() }
      if (($s.Length % 2) -ne 0) { throw "Binary value has odd hex length: '$Value'." }

      $bytes = New-Object byte[] ($s.Length / 2)
      for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($s.Substring($i * 2, 2), 16)
      }
      return $bytes
    }
    default { return $Value }
  }
}

function Convert-ToDesiredObjectSafe {
  param([string]$InputValue)

  if ([string]::IsNullOrWhiteSpace($InputValue)) { return $null }

  try {
    if (Test-Path -LiteralPath $InputValue) {
      $sanitized = Sanitize-Path -Path $InputValue -MustExist
      if ($sanitized) {
        $raw = Get-Content -LiteralPath $sanitized -Raw -Encoding UTF8
        return ($raw | ConvertFrom-Json)
      }
    }

    return ($InputValue | ConvertFrom-Json)
  } catch {
    $hint = if (Test-Path -LiteralPath $InputValue) { ' (file read failed or invalid JSON)' } else { ' (path not found; then tried as inline JSON and parse failed)' }
    Add-Finding -Code 'SECOPT-DesiredLoadFailed' -Severity 'Medium' -Message ("Desired JSON could not be loaded/parsed{0}; continuing with baseline checks only. Error: {1}" -f $hint, $_.Exception.Message)
    return $null
  }
}

function Set-Reg {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)]
    [ValidateSet('String','ExpandString','MultiString','Binary','DWord','QWord','Unknown')]
    [string]$Type,
    [Parameter(Mandatory)][object]$Value
  )

  Ensure-RegKey -Path $Path
  New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
}

function Compare-Value {
  param(
    [Parameter(Mandatory)][string]$Type,
    [Parameter(Mandatory)][object]$Current,
    [Parameter(Mandatory)][object]$Desired
  )

  if ($Type -eq 'Binary') {
    $c = if ($null -eq $Current) { [byte[]]@() } else { [byte[]]$Current }
    $d = if ($null -eq $Desired) { [byte[]]@() } else { [byte[]]$Desired }
    if ($c.Length -ne $d.Length) { return $false }
    for ($i = 0; $i -lt $c.Length; $i++) { if ($c[$i] -ne $d[$i]) { return $false } }
    return $true
  }

  if ($Type -eq 'MultiString') {
    $c = if ($null -eq $Current) { @() } else { [string[]]$Current }
    $d = if ($null -eq $Desired) { @() } else { [string[]]$Desired }
    if ($c.Length -ne $d.Length) { return $false }
    for ($i = 0; $i -lt $c.Length; $i++) { if ($c[$i] -ne $d[$i]) { return $false } }
    return $true
  }

  return ($Current -eq $Desired)
}

# -------------------------
# Preconditions
# -------------------------

Require-Admin

# -------------------------
# Built-in baseline checks (always)
# -------------------------

$lmPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$lmName = 'LmCompatibilityLevel'
$lmVal  = Get-Reg -Path $lmPath -Name $lmName

$uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$uacName = 'EnableLUA'
$uacVal  = Get-Reg -Path $uacPath -Name $uacName

$script:CurrentValues.Add([pscustomobject]@{
  Path       = $lmPath
  Name       = $lmName
  Value      = $lmVal
  SourceHint = 'LAN Manager auth level'
}) | Out-Null

$script:CurrentValues.Add([pscustomobject]@{
  Path       = $uacPath
  Name       = $uacName
  Value      = $uacVal
  SourceHint = 'UAC master switch'
}) | Out-Null

if ($null -eq $lmVal) {
  Add-Finding -Code 'SECOPT-LmCompatibilityMissing' -Severity 'Info' -Message 'LmCompatibilityLevel is not set (policy/default may still apply).'
} else {
  $lmValInt = [int]$lmVal
  if ($lmValInt -lt 3) {
    Add-Finding -Code 'SECOPT-LmCompatibilityWeak' -Severity 'High' -Message ("LmCompatibilityLevel={0} is low (legacy/NTLM risk)." -f $lmValInt) -Extra @{ Level = $lmValInt }
  }
}

if ($null -eq $uacVal) {
  Add-Finding -Code 'SECOPT-UACMissing' -Severity 'Info' -Message 'EnableLUA is not set (policy/default may still apply).'
} elseif ([int]$uacVal -eq 0) {
  Add-Finding -Code 'SECOPT-UACDisabled' -Severity 'High' -Message 'EnableLUA=0 indicates UAC is disabled; changes may require reboot/logoff.'
}

# -------------------------
# Desired compare / remediate (optional)
# -------------------------

$desiredLoaded = $false
$desired = Convert-ToDesiredObjectSafe -Input $DesiredJson
if ($null -ne $desired) { $desiredLoaded = $true }

if (-not $desiredLoaded) {
  if ([string]::IsNullOrWhiteSpace($DesiredJson)) {
    Add-Finding -Code 'SECOPT-DesiredNotProvided' -Severity 'Info' -Message 'No DesiredJson provided; running baseline checks only.'
  } else {
    Add-Finding -Code 'SECOPT-DesiredSkipped' -Severity 'Low' -Message 'Desired compare/remediation skipped because desired state is not available.'
  }
} else {
  foreach ($pathProp in $desired.PSObject.Properties) {
    $path = [string]$pathProp.Name
    $vals = $pathProp.Value

    if (-not $vals -or -not $vals.PSObject -or $vals.PSObject.Properties.Count -eq 0) {
      Add-Finding -Code 'SECOPT-DesiredEmptyPath' -Severity 'Low' -Message ("Desired JSON has no values under path: {0}" -f $path)
      continue
    }

    foreach ($valProp in $vals.PSObject.Properties) {
      $name = [string]$valProp.Name

      $typeRaw = $null
      $valueRaw = $null
      try {
        $typeRaw  = [string]$valProp.Value.Type
        $valueRaw = $valProp.Value.Value
      } catch {
        $typeRaw = $null
      }

      if ([string]::IsNullOrWhiteSpace($typeRaw)) {
        Add-Finding -Code 'SECOPT-DesiredMalformed' -Severity 'Medium' -Message ("Desired JSON malformed at {0}\{1} (expected Type/Value)." -f $path, $name)
        continue
      }

      $type = Normalize-RegistryType -TypeRaw $typeRaw
      if (-not $type) {
        Add-Finding -Code 'SECOPT-DesiredBadType' -Severity 'Medium' -Message ("Unsupported registry type '{0}' for {1}\{2}." -f $typeRaw, $path, $name)
        continue
      }

      $want = $null
      try {
        $want = Normalize-ValueForType -Type $type -Value $valueRaw
      } catch {
        Add-Finding -Code 'SECOPT-DesiredValueInvalid' -Severity 'Medium' -Message ("Desired value invalid for {0}\{1} (Type={2}): {3}" -f $path, $name, $type, $_.Exception.Message)
        continue
      }

      $have = Get-Reg -Path $path -Name $name

      $haveNorm = $have
      if ($null -ne $have) {
        try {
          $haveNorm = Normalize-ValueForType -Type $type -Value $have
        } catch {
          Add-Finding -Code 'SECOPT-CurrentNormalizeFailed' -Severity 'Low' -Message ("Could not normalize current value at {0}\{1} (Type={2}): {3}" -f $path, $name, $type, $_.Exception.Message)
          $haveNorm = $have
        }
      }

      $isEqual = Compare-Value -Type $type -Current $haveNorm -Desired $want
      $isDrift = -not $isEqual

      $row = [pscustomobject]@{
        Path           = $path
        Name           = $name
        Type           = $type
        Desired        = $want
        Current        = $have
        Drift          = $isDrift
        Remediated     = $false
        RemediateError = $null
      }

      if ($isDrift) {
        Add-Finding -Code 'SECOPT-Drift' -Severity 'Medium' -Message ("Drift detected: {0}\{1} Current='{2}' Desired='{3}' (Type={4})." -f $path, $name, $have, $want, $type) -Extra @{ Path = $path; Name = $name; Current = $have; Desired = $want; Type = $type }

        if ($Mode -eq 'Remediate') {
          if ($PSCmdlet.ShouldProcess("$path\$name", "Set to '$want' ($type)")) {
            try {
              Set-Reg -Path $path -Name $name -Type $type -Value $want
              $row.Remediated = $true
            } catch {
              $row.RemediateError = $_.Exception.Message
              Add-Finding -Code 'SECOPT-RemediateFailed' -Severity 'High' -Message ("Remediation failed at {0}\{1}: {2}" -f $path, $name, $_.Exception.Message)
            }
          }
        }
      }

      $script:Drift.Add($row) | Out-Null
    }
  }
}

# -------------------------
# Summary + Export
# -------------------------

$summary = [pscustomobject]@{
  ComputerName  = $env:COMPUTERNAME
  Mode          = $Mode
  DesiredLoaded = $desiredLoaded
  FindingsCount = $script:Findings.Count
  DriftItems    = $script:Drift.Count
  Timestamp     = (Get-Date)
}

if ($ExportPath) {
  $dir = Split-Path -Path $ExportPath -Parent
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
  }

  $base   = [IO.Path]::GetFileNameWithoutExtension($ExportPath)
  $folder = Split-Path -Path $ExportPath -Parent
  if (-not $folder) { $folder = (Get-Location).Path }

  $summary              | Export-Csv -Path (Join-Path $folder ($base + "_summary.csv"))   -NoTypeInformation -Encoding UTF8
  $script:Findings      | Export-Csv -Path (Join-Path $folder ($base + "_findings.csv"))  -NoTypeInformation -Encoding UTF8
  $script:CurrentValues | Export-Csv -Path (Join-Path $folder ($base + "_current.csv"))   -NoTypeInformation -Encoding UTF8
  $script:Drift         | Export-Csv -Path (Join-Path $folder ($base + "_drift.csv"))     -NoTypeInformation -Encoding UTF8
}

Write-ConsoleSummary -Summary $summary -Findings $script:Findings -CurrentValues $script:CurrentValues -Drift $script:Drift

# V2 output contract
$resultToken = if ($Strict -and $script:Findings.Count -gt 0) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = New-V2ResultObject -ScriptName '38-SecurityOptions-Drift.ps1' -Mode $Mode -Result $resultToken -Findings @($script:Findings) -Summary $summary -Metadata @{ CurrentValues = [object[]]$script:CurrentValues; Drift = [object[]]$script:Drift; DesiredLoaded = $desiredLoaded }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
