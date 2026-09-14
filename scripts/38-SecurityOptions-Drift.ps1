#Requires -RunAsAdministrator
#requires -version 5.1
<#
.SYNOPSIS
Audit/drift sensor for selected "Security Options"-adjacent settings via registry indicators.

.DESCRIPTION
- Always runs built-in baseline checks (LmCompatibilityLevel, EnableLUA).
- Optionally loads desired state from JSON (path or inline JSON), compares, and can remediate drift.
- If DesiredJson is missing/unreadable/invalid, continues with baseline checks only.
- Pipeline output: exactly one structured object (safe for Export-Csv / ConvertTo-Json / Where-Object).
- Console output: formatted, colorized summary via Write-UiLine / Write-Information only.

.PARAMETER Mode
Audit | Remediate

.PARAMETER DesiredJson
Either:
1) Path to a JSON file supplied with $DesiredJson, or
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
function Initialize-Capability38Runtime {
  param($EntryBoundParameters)
  $RunState = @{

  }
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '38-SecurityOptions-Drift.ps1' -BoundParameters $EntryBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$RunState.isWindowsHost = ($env:OS -eq 'Windows_NT')
  $script:RunState = $RunState
}

. Initialize-Capability38Runtime -EntryBoundParameters $PSBoundParameters
if (-not $RunState.isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '38-SecurityOptions-Drift.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# -------------------------
# Script-scope state (avoid null method calls under StrictMode)
# -------------------------
function Initialize-SecurityOptionsCollections {
  param()
$script:Quiet         = [bool]$Quiet
$script:NoColor       = [bool]$NoColor
$script:Findings      = Get-FindingsList
$script:CurrentValues = New-Object System.Collections.Generic.List[object]
$script:Drift         = New-Object System.Collections.Generic.List[object]
}
. Initialize-SecurityOptionsCollections

# -------------------------
# Console helpers (Get-SeverityColor from lib/Console.psm1; Write-ConsoleSummary)
# -------------------------

function Format-Value {
  param([object]$Value)

  if ($null -eq $Value) { return '<null>' }
  if ($Value -is [byte[]]) { return ('0x' + (($Value | ForEach-Object { $_.ToString('X2') }) -join '')) }
  if ($Value -is [string[]]) { return ('[' + ($Value -join ',') + ']') }
  return ($Value.ToString())
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

  $types = @{ dword = 'DWord'; qword = 'QWord'; string = 'String'; expandstring = 'ExpandString'; multistring = 'MultiString'; binary = 'Binary'; unknown = 'Unknown' }
  $key = $TypeRaw.Trim().ToLowerInvariant()
  if ($types.ContainsKey($key)) { return $types[$key] }
  return $null
}
function ConvertFrom-HexBytes {
  param([Parameter(Mandatory)][object]$Value)
  if ($Value -is [byte[]]) { return $Value }
  $text = (([string]$Value) -replace '^0x','') -replace '[-\s]',''
  if ($text.Length -eq 0) { return [byte[]]@() }
  if (($text.Length % 2) -ne 0) { throw "Binary value has odd hex length: '$Value'." }
  $bytes = New-Object byte[] ($text.Length / 2)
  for ($index = 0; $index -lt $bytes.Length; $index++) { $bytes[$index] = [Convert]::ToByte($text.Substring($index * 2, 2), 16) }
  return $bytes
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
      return (ConvertFrom-HexBytes -Value $Value)
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
        $raw = Get-BoundedUtf8FileContent -Path $sanitized -MaximumBytes 1048576
        return ($raw | ConvertFrom-Json)
      }
    }

    return ($InputValue | ConvertFrom-Json)
  } catch {
    $hint = if (Test-Path -LiteralPath $InputValue) { ' (file read failed or invalid JSON)' } else { ' (path not found; then tried as inline JSON and parse failed)' }
    Add-Finding -FindingList $script:Findings -Code 'SECOPT-DesiredLoadFailed' -Severity 'Medium' -Message ("Desired JSON could not be loaded/parsed{0}; continuing with baseline checks only. Error: {1}" -f $hint, $_.Exception.Message) -TimestampLocal
    return $null
  }
}

function Set-Reg {
  [CmdletBinding(SupportsShouldProcess = $true)]
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

function Compare-OrderedArray {
  param([object[]]$Current, [object[]]$Desired)
  if ($Current.Length -ne $Desired.Length) { return $false }
  for ($index = 0; $index -lt $Current.Length; $index++) {
    if ($Current[$index] -ne $Desired[$index]) { return $false }
  }
  return $true
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
    return (Compare-OrderedArray -Current $c -Desired $d)
  }

  if ($Type -eq 'MultiString') {
    $c = if ($null -eq $Current) { @() } else { [string[]]$Current }
    $d = if ($null -eq $Desired) { @() } else { [string[]]$Desired }
    return (Compare-OrderedArray -Current $c -Desired $d)
  }

  return ($Current -eq $Desired)
}

# -------------------------
# Preconditions
# -------------------------

function Invoke-Capability38MainPhase01 {
  param([hashtable]$RunState)
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
    Add-Finding -FindingList $script:Findings -Code 'SECOPT-LmCompatibilityMissing' -Severity 'Info' -Message 'LmCompatibilityLevel is not set (policy/default may still apply).' -TimestampLocal
  } else {
    $lmValInt = [int]$lmVal
    if ($lmValInt -lt 3) {
      Add-Finding -FindingList $script:Findings -Code 'SECOPT-LmCompatibilityWeak' -Severity 'High' -Message ("LmCompatibilityLevel={0} is low (legacy/NTLM risk)." -f $lmValInt) -Extra @{ Level = $lmValInt } -TimestampLocal
    }
  }

  if ($null -eq $uacVal) {
    Add-Finding -FindingList $script:Findings -Code 'SECOPT-UACMissing' -Severity 'Info' -Message 'EnableLUA is not set (policy/default may still apply).' -TimestampLocal
  } elseif ([int]$uacVal -eq 0) {
    Add-Finding -FindingList $script:Findings -Code 'SECOPT-UACDisabled' -Severity 'High' -Message 'EnableLUA=0 indicates UAC is disabled; changes may require reboot/logoff.' -TimestampLocal
  }

  # -------------------------
  # Desired compare / remediate (optional)
  # -------------------------

  $RunState.desiredLoaded = $false
  $desired = Convert-ToDesiredObjectSafe -Input $DesiredJson
  if ($null -ne $desired) { $RunState.desiredLoaded = $true }
}
function Invoke-Capability38MainPhase02 {
  param([hashtable]$RunState)
  if (-not $RunState.desiredLoaded) {
    Add-SecurityOptionsUnavailableDesiredFinding
    return
  }
  foreach ($pathProperty in $desired.PSObject.Properties) {
    Invoke-SecurityOptionsDesiredPath -PathProperty $pathProperty
  }
}
function Add-SecurityOptionsUnavailableDesiredFinding {
  if ([string]::IsNullOrWhiteSpace($DesiredJson)) {
    Add-Finding -FindingList $script:Findings -Code 'SECOPT-DesiredNotProvided' -Severity 'Info' -Message 'No DesiredJson provided; running baseline checks only.' -TimestampLocal
  } else {
    Add-Finding -FindingList $script:Findings -Code 'SECOPT-DesiredSkipped' -Severity 'Low' -Message 'Desired compare/remediation skipped because desired state is not available.' -TimestampLocal
  }
}
function Invoke-SecurityOptionsDesiredPath {
  param($PathProperty)
  $path = [string]$PathProperty.Name
  $values = $PathProperty.Value
  if (-not $values -or -not $values.PSObject -or $values.PSObject.Properties.Count -eq 0) {
    Add-Finding -FindingList $script:Findings -Code 'SECOPT-DesiredEmptyPath' -Severity 'Low' -Message ("Desired JSON has no values under path: {0}" -f $path) -TimestampLocal
    return
  }
  foreach ($valueProperty in $values.PSObject.Properties) {
    Invoke-SecurityOptionsDesiredValue -Path $path -ValueProperty $valueProperty
  }
}
function Resolve-SecurityOptionsDesiredValue {
  param([string]$Path, $ValueProperty)
  $name = [string]$ValueProperty.Name
  try {
    $typeRaw = [string]$ValueProperty.Value.Type
    $valueRaw = $ValueProperty.Value.Value
  } catch {
    $typeRaw = $null
  }
  if ([string]::IsNullOrWhiteSpace($typeRaw)) {
    Add-Finding -FindingList $script:Findings -Code 'SECOPT-DesiredMalformed' -Severity 'Medium' -Message ("Desired JSON malformed at {0}\{1} (expected Type/Value)." -f $Path, $name) -TimestampLocal
    return $null
  }
  $type = Normalize-RegistryType -TypeRaw $typeRaw
  if (-not $type) {
    Add-Finding -FindingList $script:Findings -Code 'SECOPT-DesiredBadType' -Severity 'Medium' -Message ("Unsupported registry type '{0}' for {1}\{2}." -f $typeRaw, $Path, $name) -TimestampLocal
    return $null
  }
  try {
    $want = Normalize-ValueForType -Type $type -Value $valueRaw
  } catch {
    Add-Finding -FindingList $script:Findings -Code 'SECOPT-DesiredValueInvalid' -Severity 'Medium' -Message ("Desired value invalid for {0}\{1} (Type={2}): {3}" -f $Path, $name, $type, $_.Exception.Message) -TimestampLocal
    return $null
  }
  return [pscustomobject]@{ Name = $name; Type = $type; Value = $want }
}
function Get-NormalizedSecurityOptionCurrentValue {
  param([string]$Path, [string]$Name, [string]$Type, [AllowNull()]$Value)
  if ($null -eq $Value) { return $null }
  try {
    return Normalize-ValueForType -Type $Type -Value $Value
  } catch {
    Add-Finding -FindingList $script:Findings -Code 'SECOPT-CurrentNormalizeFailed' -Severity 'Low' -Message ("Could not normalize current value at {0}\{1} (Type={2}): {3}" -f $Path, $Name, $Type, $_.Exception.Message) -TimestampLocal
    return $Value
  }
}
function Invoke-SecurityOptionsDesiredValue {
  param([string]$Path, $ValueProperty)
  $target = Resolve-SecurityOptionsDesiredValue -Path $Path -ValueProperty $ValueProperty
  if ($null -eq $target) { return }
  $have = Get-Reg -Path $Path -Name $target.Name
  $haveNorm = Get-NormalizedSecurityOptionCurrentValue -Path $Path -Name $target.Name -Type $target.Type -Value $have
  $isDrift = -not (Compare-Value -Type $target.Type -Current $haveNorm -Desired $target.Value)
  $row = [pscustomobject]@{
    Path = $Path
    Name = $target.Name
    Type = $target.Type
    Desired = $target.Value
    Current = $have
    Drift = $isDrift
    Remediated = $false
    RemediateError = $null
  }
  if ($isDrift) { Set-SecurityOptionDrift -Row $row }
  $script:Drift.Add($row) | Out-Null
}
function Set-SecurityOptionDrift {
  param($Row)
  Add-Finding -FindingList $script:Findings -Code 'SECOPT-Drift' -Severity 'Medium' -Message ("Drift detected: {0}\{1} Current='{2}' Desired='{3}' (Type={4})." -f $Row.Path, $Row.Name, $Row.Current, $Row.Desired, $Row.Type) -Extra @{ Path = $Row.Path; Name = $Row.Name; Current = $Row.Current; Desired = $Row.Desired; Type = $Row.Type } -TimestampLocal
  if ($Mode -ne 'Remediate') { return }
  if (-not $script:__EntryCmdlet.ShouldProcess("$($Row.Path)\$($Row.Name)", "Set to '$($Row.Desired)' ($($Row.Type))")) { return }
  try {
    Set-Reg -Path $Row.Path -Name $Row.Name -Type $Row.Type -Value $Row.Desired
    $Row.Remediated = $true
  } catch {
    $Row.RemediateError = $_.Exception.Message
    Add-Finding -FindingList $script:Findings -Code 'SECOPT-RemediateFailed' -Severity 'High' -Message ("Remediation failed at {0}\{1}: {2}" -f $Row.Path, $Row.Name, $_.Exception.Message) -TimestampLocal
  }
}
function Invoke-Capability38MainPhase03 {
  param([hashtable]$RunState)
  $summary = [pscustomobject]@{
    ComputerName  = $env:COMPUTERNAME
    Mode          = $Mode
    DesiredLoaded = $RunState.desiredLoaded
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
}
function Invoke-Capability38MainPhase04Step01 {
  param([hashtable]$RunState)
$findingsAL = ConvertTo-ArrayList -InputObject $script:Findings
    Write-ConsoleSummary -Summary $summary -Findings $findingsAL `
      -CustomFields ([ordered]@{
        Mode          = $Mode
        DesiredLoaded = $RunState.desiredLoaded
        DriftItems    = $script:Drift.Count
      })
    # Current values
    if ($script:CurrentValues.Count -gt 0) {
      Write-UiLine -Text '' -Color 'Gray'
      Write-UiLine -Text 'Current values:' -Color 'White'
      foreach ($cv in $script:CurrentValues) {
        $valText = Format-Value -Value $cv.Value
        Write-UiLine -Text ("  {0}\{1} = {2} ({3})" -f $cv.Path, $cv.Name, $valText, $cv.SourceHint) -Color 'Gray'
      }
    }
    # Drift (max 10)
    $RunState.topDrift = $script:Drift | Where-Object { $_.Drift } | Select-Object -First 10
    Write-UiLine -Text '' -Color 'Gray'
    Write-UiLine -Text 'Drift (max 10):' -Color 'White'
}

function Invoke-Capability38MainPhase04Step02 {
  param([hashtable]$RunState)
if (($RunState.topDrift | Measure-Object).Count -eq 0) {
      Write-UiLine -Text '  None' -Color 'Green'
    } else {
      foreach ($d in $RunState.topDrift) {
        $cur = Format-Value -Value $d.Current
        $des = Format-Value -Value $d.Desired
        $statusColor = if ($d.Remediated -eq $true) { [ConsoleColor]::Green } else { [ConsoleColor]::Yellow }
        $suffix = if ($d.RemediateError) { " ERROR: $($d.RemediateError)" } else { '' }
        Write-UiLine -Text ("  {0}\{1} ({2}) Current={3} Desired={4} Remediated={5}{6}" -f $d.Path, $d.Name, $d.Type, $cur, $des, $d.Remediated, $suffix) -Color $statusColor
      }
      if (($script:Drift | Where-Object { $_.Drift } | Measure-Object).Count -gt 10) {
        $extra = ($script:Drift | Where-Object { $_.Drift } | Measure-Object).Count - 10
        Write-UiLine -Text "  ... and $extra more drift item(s)" -Color 'DarkYellow'
      }
    }
}

function Invoke-Capability38MainPhase04 {
  param([hashtable]$RunState)
  if (-not $script:Quiet) {
    . Invoke-Capability38MainPhase04Step01 -RunState $RunState
. Invoke-Capability38MainPhase04Step02 -RunState $RunState
  }
}
function Invoke-Capability38Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation, [hashtable]$RunState)
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability38MainPhase01 -RunState $RunState
  . Invoke-Capability38MainPhase02 -RunState $RunState
  . Invoke-Capability38MainPhase03 -RunState $RunState
  . Invoke-Capability38MainPhase04 -RunState $RunState
}
. Invoke-Capability38Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation -RunState $RunState

# V2 output contract
function Get-Capability38ResultToken {
  $resultToken = if ($Strict -and $script:Findings.Count -gt 0) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability38ResultToken
$v2Result = Get-V2ResultObject -ScriptName '38-SecurityOptions-Drift.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $summary -Metadata @{ CurrentValues = [object[]]$script:CurrentValues; Drift = [object[]]$script:Drift; DesiredLoaded = $RunState.desiredLoaded }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
