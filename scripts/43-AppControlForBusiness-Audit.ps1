#requires -version 5.1
<#
.SYNOPSIS
Audit WDAC / App Control for Business indicators (best-effort).

.DESCRIPTION
- Reads Code Integrity Operational events (recent).
- Scans for deployed policy files in common OS and EFI locations (EFI best-effort).
- Supports optional JSON config overrides (safe defaults if missing/invalid).
- Optional CSV export.
- Prints a console summary at the end.

Pipeline output: structured objects only.
Console output: Write-UiLine (and optional Write-Information) only.

PowerShell: Windows PowerShell 5.1 compatible.

.PARAMETER HoursBack
How far back to query Code Integrity events.

.PARAMETER ExportPath
Optional CSV export path.

.PARAMETER ConfigJsonPath
Optional JSON config path for overrides.

.PARAMETER MaxEvents
Maximum number of CI events to read.

.PARAMETER RecurseMaxDepth
Maximum recursion depth when scanning policy locations.

.PARAMETER MaxPolicyFiles
Maximum policy files to enumerate.

.PARAMETER ExportEventsTop
Max number of events to include in export.


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

.PARAMETER Quiet
  Suppress console output.

.PARAMETER NoColor
  Disable colored output.


.OUTPUTS
  None by default.
  When -PassThru is used, emits a PSCustomObject v2 result with Script, Mode, Result, Findings, Summary, and Metadata properties.

.EXAMPLE
  .\43-AppControlForBusiness-Audit.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateSet('Audit','Remediate')]
  [string]$Mode = 'Audit',

  [ValidateRange(1, 720)]
  [int]$HoursBack = 24,

  [string]$ExportPath,

  [string]$ConfigJsonPath = $null,

  [ValidateRange(1, 50000)]
  [int]$MaxEvents = 5000,

  [ValidateRange(0, 10)]
  [int]$RecurseMaxDepth = 4,

  [ValidateRange(1, 20000)]
  [int]$MaxPolicyFiles = 5000,

  [ValidateRange(1, 2000)]
  [int]$ExportEventsTop = 200,

  [ValidateSet('Console','Json','Csv','None')]
  [string]$OutputFormat = 'Console',

  [string]$OutputPath,

  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor

,
  [string]$ConfigPath
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force


Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '43-AppControlForBusiness-Audit.ps1' -BoundParameters $PSBoundParameters `
  -Mode $Mode -ConfigPath $ConfigPath -OutputFormat $OutputFormat -OutputPath $OutputPath `
  -PassThru:$PassThru -Strict:$Strict -Quiet:$Quiet -NoColor:$NoColor
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($OutputPath) -and -not [string]::IsNullOrWhiteSpace($ExportPath)) {
  $OutputPath = $ExportPath
}

if ([string]::IsNullOrWhiteSpace($ConfigPath) -and -not [string]::IsNullOrWhiteSpace($ConfigJsonPath)) {
  $ConfigPath = $ConfigJsonPath
  $script:__V2Context.ConfigPath = $ConfigPath
}

# --------------------------
# Findings
# --------------------------
$script:Findings = Get-FindingsList
$Findings = $script:Findings
$strictModeEnabled = [bool]$Strict
$noColorEnabled = [bool]$NoColor

$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName  = $env:COMPUTERNAME
    LikelyActive  = $false
    FindingsCount = 0
    Timestamp     = Get-Date
    Supported     = $false
    Notes         = @('Skipped: App Control for Business auditing is only supported on Windows hosts.')
  }

  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $resultObject = Get-V2ResultObject `
    -ScriptName '43-AppControlForBusiness-Audit.ps1' `
    -Mode 'Audit' `
    -Result $unsupportedResult `
    -Findings @() `
    -Summary $summary `
    -Metadata @{ UnsupportedHost = $true; Indicators = $null; PolicyFiles = @(); RecentEvents = @() }

  Write-ResultObject -ResultObject $resultObject -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $resultObject }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

if ($Mode -eq 'Remediate') {
  Add-Finding -FindingList $script:Findings -Code 'AC-ModeDowngradeToAudit' -Severity 'Warning' -Message 'Remediate mode is not supported by this script; running in audit behavior.'
}

# --------------------------
# Helpers
# --------------------------

function ConvertTo-BooleanOrNull {
  [CmdletBinding()]
  param([object]$Value)

  if ($null -eq $Value) { return $null }

  if ($Value -is [bool]) { return [bool]$Value }

  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }

  switch -Regex ($s.Trim()) {
    '^(true|1|yes|y)$'  { return $true }
    '^(false|0|no|n)$'  { return $false }
    default            { return $null }
  }
}

function Get-EfiBootPaths {
  [CmdletBinding()]
  param()

  $paths = New-Object 'System.Collections.Generic.List[string]'

  try {
    # Best-effort: EFI is often not mounted; we only see mounted FAT32 volumes with drive letters.
    $vols = Get-Volume -ErrorAction Stop
    foreach ($v in $vols) {
      if ($null -ne $v.DriveLetter -and $v.FileSystemType -eq 'FAT32') {
        $paths.Add(("{0}:\Microsoft\Boot" -f $v.DriveLetter)) | Out-Null
      }
    }
  } catch {
    Add-Finding -FindingList $script:Findings -Code 'AC-EFIVolumeEnumFailed' -Severity 'Info' -Message ("EFI volumes could not be enumerated (best-effort): {0}" -f $_.Exception.Message)
  }

  return @($paths.ToArray())
}

function Get-ChildItemDepthLimited {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [ValidateRange(0, 10)][int]$MaxDepth = 4
  )

  $results = New-Object 'System.Collections.Generic.List[object]'

  if ($MaxDepth -le 0) {
    try {
      foreach ($f in @(Get-ChildItem -LiteralPath $Path -File -ErrorAction SilentlyContinue)) {
        $results.Add($f) | Out-Null
      }
    } catch {
      Write-Verbose ("App Control directory enumeration failed for '{0}': {1}" -f $Path,$_.Exception.Message)
    }
    return @($results.ToArray())
  }

  # BFS to implement depth limit (PS 5.1 has no -Depth on Get-ChildItem)
  $q = New-Object 'System.Collections.Generic.Queue[object]'
  $q.Enqueue([pscustomobject]@{ Dir = $Path; Depth = 0 })

  while ($q.Count -gt 0) {
    $node = $q.Dequeue()

    $files = @()
    try { $files = @(Get-ChildItem -LiteralPath $node.Dir -File -ErrorAction SilentlyContinue) } catch { $files = @() }
    foreach ($f in $files) { $results.Add($f) | Out-Null }

    if ($node.Depth -ge $MaxDepth) { continue }

    $dirs = @()
    try { $dirs = @(Get-ChildItem -LiteralPath $node.Dir -Directory -ErrorAction SilentlyContinue) } catch { $dirs = @() }
    foreach ($d in $dirs) {
      $q.Enqueue([pscustomobject]@{ Dir = $d.FullName; Depth = ($node.Depth + 1) })
    }
  }

  return @($results.ToArray())
}

function Get-PolicyFilesFromRoots {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string[]]$Roots,
    [ValidateRange(0, 10)][int]$MaxDepth = 4,
    [bool]$IncludeCip = $true,
    [bool]$IncludeP7b = $true,
    [bool]$IncludeXml = $true,
    [ValidateRange(1, 20000)][int]$MaxFiles = 5000
  )

  $allowedExt = @()
  if ($IncludeCip) { $allowedExt += '.cip' }
  if ($IncludeP7b) { $allowedExt += '.p7b' }
  if ($IncludeXml) { $allowedExt += '.xml' }

  $out = New-Object 'System.Collections.Generic.List[object]'

  foreach ($root in ($Roots | Where-Object { $_ } | Sort-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $root)) { continue }

    $items = Get-ChildItemDepthLimited -Path $root -MaxDepth $MaxDepth

    foreach ($i in $items) {
      if ($out.Count -ge $MaxFiles) {
        Add-Finding -FindingList $script:Findings -Code 'AC-PolicyScanTruncated' -Severity 'Warning' -Message ("Policy scan truncated at MaxPolicyFiles={0}." -f $MaxFiles)
        return @($out.ToArray())
      }

      if (($allowedExt.Count -gt 0 -and $i.Extension -in $allowedExt) -or $i.Name -ieq 'SiPolicy.p7b') {

        $policyId = $null
        if ($i.Name -match '^\{[0-9A-Fa-f-]{36}\}\.cip$') { $policyId = ($i.Name -replace '\.cip$','') }
        elseif ($i.BaseName -match '^\{[0-9A-Fa-f-]{36}\}$') { $policyId = $i.BaseName }

        $kind = 'Unknown'
        if ($i.Name -ieq 'SiPolicy.p7b') { $kind = 'SinglePolicyFormat' }
        elseif ($i.Extension -ieq '.cip' -and $policyId) { $kind = 'MultiplePolicyFormat' }

        # Output only lightweight records
        $out.Add([pscustomobject]@{
          Path          = $i.FullName
          Name          = $i.Name
          Extension     = $i.Extension
          Length        = [int64]$i.Length
          LastWriteTime = $i.LastWriteTime
          PolicyIdHint  = $policyId
          KindHint      = $kind
          Root          = $root
        }) | Out-Null
      }
    }
  }

  return @($out.ToArray())
}

# --------------------------
# Main
# --------------------------
$configDefaults = @{
  Enabled               = $true
  AdditionalPolicyRoots = @()     # Caller-provided policy roots can be added here.
  IncludeEfiScan        = $true
  IncludeXmlFiles       = $true
  IncludeP7bFiles       = $true
  IncludeCipFiles       = $true
  ExportDelimiter       = ','
  PreferWriteInformation= $false  # if true: summary uses Write-Information additionally
}

$sanitized = if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $null } else { Sanitize-Path -Path $ConfigPath -MustExist }
$cfgResult = Read-ConfigWithDefaults -Path $sanitized -Defaults $configDefaults
$config = $cfgResult.Config

if (-not $cfgResult.Meta.Provided) {
  Add-Finding -FindingList $script:Findings -Code 'AC-ConfigMissing' -Severity 'Info' -Message 'No config JSON provided; using defaults.'
} elseif (-not $cfgResult.Meta.Loaded) {
  if ($cfgResult.Meta.Error -eq 'ConfigPath not found.') {
    Add-Finding -FindingList $script:Findings -Code 'AC-ConfigNotFound' -Severity 'Warning' -Message 'Config JSON not found at [configured path]; using defaults.'
  } elseif ($cfgResult.Meta.Error -eq 'Config file is empty.') {
    Add-Finding -FindingList $script:Findings -Code 'AC-ConfigEmpty' -Severity 'Warning' -Message 'Config JSON is empty; using defaults.'
  } else {
    Add-Finding -FindingList $script:Findings -Code 'AC-ConfigInvalidJson' -Severity 'Warning' -Message ("Config JSON could not be parsed; using defaults. Error: {0}" -f $cfgResult.Meta.Error)
  }
}

$b = ConvertTo-BooleanOrNull $config.Enabled
if ($null -ne $b) { $config.Enabled = $b } else { $config.Enabled = $configDefaults.Enabled }

$b = ConvertTo-BooleanOrNull $config.IncludeEfiScan
if ($null -ne $b) { $config.IncludeEfiScan = $b } else { $config.IncludeEfiScan = $configDefaults.IncludeEfiScan }

$b = ConvertTo-BooleanOrNull $config.IncludeXmlFiles
if ($null -ne $b) { $config.IncludeXmlFiles = $b } else { $config.IncludeXmlFiles = $configDefaults.IncludeXmlFiles }

$b = ConvertTo-BooleanOrNull $config.IncludeP7bFiles
if ($null -ne $b) { $config.IncludeP7bFiles = $b } else { $config.IncludeP7bFiles = $configDefaults.IncludeP7bFiles }

$b = ConvertTo-BooleanOrNull $config.IncludeCipFiles
if ($null -ne $b) { $config.IncludeCipFiles = $b } else { $config.IncludeCipFiles = $configDefaults.IncludeCipFiles }

$b = ConvertTo-BooleanOrNull $config.PreferWriteInformation
if ($null -ne $b) { $config.PreferWriteInformation = $b } else { $config.PreferWriteInformation = $configDefaults.PreferWriteInformation }

if ($null -ne $config.ExportDelimiter -and [string]$config.ExportDelimiter) {
  $d = [string]$config.ExportDelimiter
  if ($d.Length -eq 1) { $config.ExportDelimiter = $d }
  else {
    Add-Finding -FindingList $script:Findings -Code 'AC-ConfigBadDelimiter' -Severity 'Warning' -Message 'ExportDelimiter must be a single character; using default.'
    $config.ExportDelimiter = $configDefaults.ExportDelimiter
  }
}

if ($null -ne $config.AdditionalPolicyRoots) {
  $roots = @()
  foreach ($r in @($config.AdditionalPolicyRoots)) {
    $s = [string]$r
    if (-not [string]::IsNullOrWhiteSpace($s)) { $roots += $s }
  }
  $config.AdditionalPolicyRoots = $roots
} else {
  $config.AdditionalPolicyRoots = @()
}

if (-not $config.Enabled) {
  Add-Finding -FindingList $script:Findings -Code 'AC-DisabledByConfig' -Severity 'Info' -Message 'Audit disabled by config; exiting.'

  $summary = [pscustomobject]@{
    ComputerName  = $env:COMPUTERNAME
    LikelyActive  = $null
    FindingsCount = $script:Findings.Count
    Timestamp     = Get-Date
  }

  $emptyIndicators = [pscustomobject]@{
    CodeIntegrityLogName = 'Microsoft-Windows-CodeIntegrity/Operational'
    LookbackHours        = $HoursBack
    RunningAsAdmin       = Test-IsAdmin
    CILogEnabled         = $null
    RecentCIEventsCount  = 0
    PolicyFilesCount     = 0
    LikelyActive         = $null
    ScannedRootsCount    = 0
  }

  $findingsAL = ConvertTo-ArrayList -InputObject $script:Findings.ToArray()

  if (-not $Quiet) {
    Write-ConsoleSummary -Summary $summary -Findings $findingsAL `
      -CustomFields ([ordered]@{
        RunningAsAdmin   = $emptyIndicators.RunningAsAdmin
        'CI Log Enabled' = $emptyIndicators.CILogEnabled
        'CI Events'      = $emptyIndicators.RecentCIEventsCount
        'Policies Found' = $emptyIndicators.PolicyFilesCount
        LikelyActive     = $summary.LikelyActive
      })
    if ($config.PreferWriteInformation) {
      Write-Information ("AppControl audit complete. LikelyActive={0}" -f $summary.LikelyActive) -InformationAction Continue
    }
  }

  $disabledFindings = @($script:Findings.ToArray())
  $disabledResultToken = if ($strictModeEnabled -and $disabledFindings.Count -gt 0) { 'FAIL' } elseif ($disabledFindings.Count -gt 0) { 'WARN' } else { 'OK' }
  $disabledResult = Get-V2ResultObject `
    -ScriptName '43-AppControlForBusiness-Audit.ps1' `
    -Mode 'Audit' `
    -Result $disabledResultToken `
    -Findings $disabledFindings `
    -Summary $summary `
    -Metadata @{ Indicators = $emptyIndicators; PolicyFiles = @(); RecentEvents = @() }

  Write-ResultObject -ResultObject $disabledResult -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $disabledResult }
  exit (Get-V2ExitCode -Result $disabledResultToken)
}

$runningAsAdmin = Test-IsAdmin
if (-not $runningAsAdmin) {
  Add-Finding -FindingList $script:Findings -Code 'AC-NotElevated' -Severity 'Info' -Message 'Not running elevated; log/file access may be incomplete.'
}

# 1) Code Integrity events
$ciLog = 'Microsoft-Windows-CodeIntegrity/Operational'
$ciLogInfo = $null
try {
  $ciLogInfo = Get-WinEvent -ListLog $ciLog -ErrorAction Stop
} catch {
  Add-Finding -FindingList $script:Findings -Code 'AC-CILogNotFoundOrNoAccess' -Severity 'Warning' -Message ("CI Operational log not available or no access: {0}" -f $_.Exception.Message)
}

$events = @()
if ($ciLogInfo -and $ciLogInfo.IsEnabled) {
  try {
    $startTime = (Get-Date).AddHours(-1 * $HoursBack)
    $events = Get-WinEvent -FilterHashtable @{ LogName = $ciLog; StartTime = $startTime } -MaxEvents $MaxEvents -ErrorAction Stop |
      Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
      Sort-Object TimeCreated -Descending
  } catch {
    Add-Finding -FindingList $script:Findings -Code 'AC-CILogReadFailed' -Severity 'Warning' -Message ("CI events could not be read: {0}" -f $_.Exception.Message)
  }
} elseif ($ciLogInfo -and -not $ciLogInfo.IsEnabled) {
  Add-Finding -FindingList $script:Findings -Code 'AC-CILogDisabled' -Severity 'Info' -Message 'CI Operational log is disabled.'
}

# 2) Policy files
$windowsRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
if ([string]::IsNullOrWhiteSpace($windowsRoot)) { throw 'Trusted Windows directory is unavailable.' }
$osRoots = @(
  ("{0}\System32\CodeIntegrity\CiPolicies\Active" -f $windowsRoot.TrimEnd('\')),
  ("{0}\System32\CodeIntegrity" -f $windowsRoot.TrimEnd('\')),
  ("{0}\System32\CodeIntegrity\CiPolicies" -f $windowsRoot.TrimEnd('\'))
)

$efiRoots = @()
if ($config.IncludeEfiScan) {
  $efiRoots = Get-EfiBootPaths
}

$roots = @($osRoots + $efiRoots + @($config.AdditionalPolicyRoots)) | Where-Object { $_ }

$policyFiles = Get-PolicyFilesFromRoots -Roots $roots -MaxDepth $RecurseMaxDepth `
  -IncludeCip $config.IncludeCipFiles -IncludeP7b $config.IncludeP7bFiles -IncludeXml $config.IncludeXmlFiles `
  -MaxFiles $MaxPolicyFiles

$policyFiles = @($policyFiles)

if ($policyFiles.Count -eq 0) {
  Add-Finding -FindingList $script:Findings -Code 'AC-NoPolicyFilesFound' -Severity 'Info' -Message 'No policy files found in scanned roots (deployment can still exist via other mechanisms).'
} else {
    Add-Finding -FindingList $script:Findings -Code 'AC-PoliciesDetected' -Severity 'Low' -Message "Detected $($policyFiles.Count) App Control policy files." -Extra @{ Files = $policyFiles.Path }
}

# 3) Indicators + Summary
$eventsCount  = ($events | Measure-Object).Count
$likelyActive = ($policyFiles.Count -gt 0) -or ($eventsCount -gt 0)

$indicators = [pscustomobject]@{
  CodeIntegrityLogName = $ciLog
  LookbackHours        = $HoursBack
  RunningAsAdmin       = $runningAsAdmin
  CILogEnabled         = if ($ciLogInfo) { [bool]$ciLogInfo.IsEnabled } else { $null }
  RecentCIEventsCount  = $eventsCount
  PolicyFilesCount     = $policyFiles.Count
  LikelyActive         = $likelyActive
  ScannedRootsCount    = ($roots | Sort-Object -Unique | Measure-Object).Count
}

$summary = [pscustomobject]@{
  ComputerName  = $env:COMPUTERNAME
  LikelyActive  = $likelyActive
  FindingsCount = $script:Findings.Count
  Timestamp     = Get-Date
}

# 4) Export
if ($ExportPath) {
  $folder = Split-Path -Path $ExportPath -Parent
  if (-not $folder) { $folder = (Get-Location).Path }
  if (-not (Test-Path -LiteralPath $folder)) {
    New-Item -Path $folder -ItemType Directory -Force | Out-Null
  }

  $base  = [IO.Path]::GetFileNameWithoutExtension($ExportPath)
  $delim = $config.ExportDelimiter

  $summary                 | Export-Csv -Path (Join-Path $folder ($base + "_summary.csv"))          -NoTypeInformation -Encoding UTF8 -Delimiter $delim
  $indicators              | Export-Csv -Path (Join-Path $folder ($base + "_indicators.csv"))       -NoTypeInformation -Encoding UTF8 -Delimiter $delim
  @($script:Findings.ToArray()) | Export-Csv -Path (Join-Path $folder ($base + "_findings.csv"))    -NoTypeInformation -Encoding UTF8 -Delimiter $delim
  $policyFiles             | Export-Csv -Path (Join-Path $folder ($base + "_policyfiles.csv"))      -NoTypeInformation -Encoding UTF8 -Delimiter $delim
  ($events | Select-Object -First $ExportEventsTop) | Export-Csv -Path (Join-Path $folder ($base + "_recent_ci_events.csv")) -NoTypeInformation -Encoding UTF8 -Delimiter $delim
}

# 5) Console summary
$findingsAL = ConvertTo-ArrayList -InputObject $script:Findings.ToArray()
if (-not $Quiet) {
  Write-ConsoleSummary -Summary $summary -Findings $findingsAL `
    -CustomFields ([ordered]@{
      RunningAsAdmin   = $indicators.RunningAsAdmin
      'CI Log Enabled' = $indicators.CILogEnabled
      'CI Events'      = $indicators.RecentCIEventsCount
      'Policies Found' = $indicators.PolicyFilesCount
      LikelyActive     = $summary.LikelyActive
    })
  # Policy files by kind
  if ($policyFiles.Count -gt 0) {
    Write-UiLine ''
    Write-UiLine 'Policy files by kind:' -ForegroundColor Cyan
    $policyFiles | Group-Object KindHint | Sort-Object Name | ForEach-Object {
      Write-UiLine ("- {0}: {1}" -f $_.Name, $_.Count)
    }
  }
  # Latest CI event
  $latestEvent = @($events) | Select-Object -First 1
  if ($latestEvent) {
    Write-UiLine ''
    Write-UiLine ("Latest CI event    : {0} (Id {1}, {2})" -f $latestEvent.TimeCreated, $latestEvent.Id, $latestEvent.LevelDisplayName)
  }
  if ($config.PreferWriteInformation) {
    Write-Information ("AppControl audit complete. LikelyActive={0}" -f $summary.LikelyActive) -InformationAction Continue
  }
}

$findingsArr = @($findingsAL)

$resultToken = if ($strictModeEnabled -and $findingsArr.Count -gt 0) { 'FAIL' } elseif ($findingsArr.Count -gt 0) { 'WARN' } else { 'OK' }
$resultObject = Get-V2ResultObject `
  -ScriptName '43-AppControlForBusiness-Audit.ps1' `
  -Mode 'Audit' `
  -Result $resultToken `
  -Findings $findingsArr `
  -Summary $summary `
  -Metadata @{ Indicators = $indicators; PolicyFiles = @($policyFiles); RecentEvents = @($events | Select-Object -First $ExportEventsTop); Strict = $strictModeEnabled; NoColor = $noColorEnabled }

Write-ResultObject -ResultObject $resultObject -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) {
  $resultObject
}

exit (Get-V2ExitCode -Result $resultToken)
