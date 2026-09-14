#requires -version 5.1
<#
.SYNOPSIS
Capability-private presentation and normalization helpers.

.DESCRIPTION
Provides bounded helper functions loaded by the matching public capability
after repository bootstrap and trust validation complete.
#>

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
    foreach ($file in @(Get-AppControlDirectoryFiles -Path $Path)) { $results.Add($file) | Out-Null }
    return @($results.ToArray())
  }

  # BFS to implement depth limit (PS 5.1 has no -Depth on Get-ChildItem)
  $q = New-Object 'System.Collections.Generic.Queue[object]'
  $q.Enqueue([pscustomobject]@{ Dir = $Path; Depth = 0 })

  while ($q.Count -gt 0) {
    $node = $q.Dequeue()

    $files = @(Get-AppControlDirectoryFiles -Path $node.Dir)
    foreach ($f in $files) { $results.Add($f) | Out-Null }

    if ($node.Depth -ge $MaxDepth) { continue }

    $dirs = @(Get-AppControlChildDirectories -Path $node.Dir)
    foreach ($d in $dirs) {
      $q.Enqueue([pscustomobject]@{ Dir = $d.FullName; Depth = ($node.Depth + 1) })
    }
  }

  return @($results.ToArray())
}
function Get-AppControlDirectoryFiles {
  param([string]$Path)
  try { return @(Get-ChildItem -LiteralPath $Path -File -ErrorAction SilentlyContinue) }
  catch { Write-Verbose ("App Control directory enumeration failed for '{0}': {1}" -f $Path,$_.Exception.Message); return @() }
}
function Get-AppControlChildDirectories {
  param([string]$Path)
  try { return @(Get-ChildItem -LiteralPath $Path -Directory -ErrorAction SilentlyContinue) }
  catch { return @() }
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

  $allowedExt = @(Get-AppControlPolicyExtensions -IncludeCip $IncludeCip -IncludeP7b $IncludeP7b -IncludeXml $IncludeXml)

  $out = New-Object 'System.Collections.Generic.List[object]'

  foreach ($root in ($Roots | Where-Object { $_ } | Sort-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $root)) { continue }

    $items = Get-ChildItemDepthLimited -Path $root -MaxDepth $MaxDepth

    foreach ($i in $items) {
      if ($out.Count -ge $MaxFiles) {
        Add-Finding -FindingList $script:Findings -Code 'AC-PolicyScanTruncated' -Severity 'Warning' -Message ("Policy scan truncated at MaxPolicyFiles={0}." -f $MaxFiles)
        return @($out.ToArray())
      }

      if (Test-AppControlPolicyFile -Item $i -AllowedExtensions $allowedExt) {
        $metadata = Get-AppControlPolicyMetadata -Item $i
        $out.Add([pscustomobject]@{
          Path          = $i.FullName
          Name          = $i.Name
          Extension     = $i.Extension
          Length        = [int64]$i.Length
          LastWriteTime = $i.LastWriteTime
          PolicyIdHint  = $metadata.PolicyId
          KindHint      = $metadata.Kind
          Root          = $root
        }) | Out-Null
      }
    }
  }

  return @($out.ToArray())
}
function Get-AppControlPolicyExtensions {
  param([bool]$IncludeCip, [bool]$IncludeP7b, [bool]$IncludeXml)
  if ($IncludeCip) { '.cip' }
  if ($IncludeP7b) { '.p7b' }
  if ($IncludeXml) { '.xml' }
}
function Test-AppControlPolicyFile {
  param($Item, [string[]]$AllowedExtensions)
  if ($Item.Name -ieq 'SiPolicy.p7b') { return $true }
  return ($AllowedExtensions.Count -gt 0 -and $Item.Extension -in $AllowedExtensions)
}
function Get-AppControlPolicyMetadata {
  param($Item)
  $policyId = $null
  if ($Item.Name -match '^\{[0-9A-Fa-f-]{36}\}\.cip$') { $policyId = ($Item.Name -replace '\.cip$','') }
  elseif ($Item.BaseName -match '^\{[0-9A-Fa-f-]{36}\}$') { $policyId = $Item.BaseName }
  $kind = 'Unknown'
  if ($Item.Name -ieq 'SiPolicy.p7b') { $kind = 'SinglePolicyFormat' }
  elseif ($Item.Extension -ieq '.cip' -and $policyId) { $kind = 'MultiplePolicyFormat' }
  return [pscustomobject]@{ PolicyId = $policyId; Kind = $kind }
}

function Invoke-Capability43MainPhase01 {
  param([hashtable]$RunState)
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

  $RunState.b = ConvertTo-BooleanOrNull $config.Enabled
}

function Invoke-Capability43MainPhase02 {
  param([hashtable]$RunState)
  if ($null -ne $RunState.b) { $config.Enabled = $RunState.b } else { $config.Enabled = $configDefaults.Enabled }

  $RunState.b = ConvertTo-BooleanOrNull $config.IncludeEfiScan
  if ($null -ne $RunState.b) { $config.IncludeEfiScan = $RunState.b } else { $config.IncludeEfiScan = $configDefaults.IncludeEfiScan }

  $RunState.b = ConvertTo-BooleanOrNull $config.IncludeXmlFiles
  if ($null -ne $RunState.b) { $config.IncludeXmlFiles = $RunState.b } else { $config.IncludeXmlFiles = $configDefaults.IncludeXmlFiles }

  $RunState.b = ConvertTo-BooleanOrNull $config.IncludeP7bFiles
  if ($null -ne $RunState.b) { $config.IncludeP7bFiles = $RunState.b } else { $config.IncludeP7bFiles = $configDefaults.IncludeP7bFiles }

  $RunState.b = ConvertTo-BooleanOrNull $config.IncludeCipFiles
  if ($null -ne $RunState.b) { $config.IncludeCipFiles = $RunState.b } else { $config.IncludeCipFiles = $configDefaults.IncludeCipFiles }

  $RunState.b = ConvertTo-BooleanOrNull $config.PreferWriteInformation
}

function Invoke-Capability43MainPhase03 {
  param([hashtable]$RunState)
  if ($null -ne $RunState.b) { $config.PreferWriteInformation = $RunState.b } else { $config.PreferWriteInformation = $configDefaults.PreferWriteInformation }

  if ($null -ne $config.ExportDelimiter -and [string]$config.ExportDelimiter) {
    $d = [string]$config.ExportDelimiter
    if ($d.Length -eq 1) { $config.ExportDelimiter = $d }
    else {
      Add-Finding -FindingList $script:Findings -Code 'AC-ConfigBadDelimiter' -Severity 'Warning' -Message 'ExportDelimiter must be a single character; using default.'
      $config.ExportDelimiter = $configDefaults.ExportDelimiter
    }
  }
}

function Invoke-Capability43MainPhase04 {
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
}

function Invoke-Capability43MainPhase06 {
  param([hashtable]$RunState)
  $runningAsAdmin = Test-IsAdmin
  if (-not $runningAsAdmin) {
    Add-Finding -FindingList $script:Findings -Code 'AC-NotElevated' -Severity 'Info' -Message 'Not running elevated; log/file access may be incomplete.'
  }

  # 1) Code Integrity events
  $ciLog = 'Microsoft-Windows-CodeIntegrity/Operational'
  $RunState.ciLogInfo = $null
  try {
    $RunState.ciLogInfo = Get-WinEvent -ListLog $ciLog -ErrorAction Stop
  } catch {
    Add-Finding -FindingList $script:Findings -Code 'AC-CILogNotFoundOrNoAccess' -Severity 'Warning' -Message ("CI Operational log not available or no access: {0}" -f $_.Exception.Message)
  }

  $RunState.events = @()
}

function Invoke-Capability43MainPhase07 {
  param([hashtable]$RunState)
  if ($RunState.ciLogInfo -and $RunState.ciLogInfo.IsEnabled) {
    try {
      $startTime = (Get-Date).AddHours(-1 * $HoursBack)
      $RunState.events = Get-WinEvent -FilterHashtable @{ LogName = $ciLog; StartTime = $startTime } -MaxEvents $MaxEvents -ErrorAction Stop |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
        Sort-Object TimeCreated -Descending
    } catch {
      Add-Finding -FindingList $script:Findings -Code 'AC-CILogReadFailed' -Severity 'Warning' -Message ("CI events could not be read: {0}" -f $_.Exception.Message)
    }
  } elseif ($RunState.ciLogInfo -and -not $RunState.ciLogInfo.IsEnabled) {
    Add-Finding -FindingList $script:Findings -Code 'AC-CILogDisabled' -Severity 'Info' -Message 'CI Operational log is disabled.'
  }

  # 2) Policy files
  $RunState.windowsRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
}

function Invoke-Capability43MainPhase08 {
  param([hashtable]$RunState)
  if ([string]::IsNullOrWhiteSpace($RunState.windowsRoot)) { throw 'Trusted Windows directory is unavailable.' }
  $osRoots = @(
    ("{0}\System32\CodeIntegrity\CiPolicies\Active" -f $RunState.windowsRoot.TrimEnd('\')),
    ("{0}\System32\CodeIntegrity" -f $RunState.windowsRoot.TrimEnd('\')),
    ("{0}\System32\CodeIntegrity\CiPolicies" -f $RunState.windowsRoot.TrimEnd('\'))
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
  $eventsCount  = ($RunState.events | Measure-Object).Count
  $likelyActive = ($policyFiles.Count -gt 0) -or ($eventsCount -gt 0)

  $RunState.indicators = [pscustomobject]@{
    CodeIntegrityLogName = $ciLog
    LookbackHours        = $HoursBack
    RunningAsAdmin       = $runningAsAdmin
    CILogEnabled         = if ($RunState.ciLogInfo) { [bool]$RunState.ciLogInfo.IsEnabled } else { $null }
    RecentCIEventsCount  = $eventsCount
    PolicyFilesCount     = $policyFiles.Count
    LikelyActive         = $likelyActive
    ScannedRootsCount    = ($roots | Sort-Object -Unique | Measure-Object).Count
  }

  $RunState.summary = [pscustomobject]@{
    ComputerName  = $env:COMPUTERNAME
    LikelyActive  = $likelyActive
    FindingsCount = $script:Findings.Count
    Timestamp     = Get-Date
  }
}

function Invoke-Capability43MainPhase09 {
  param([hashtable]$RunState)
  if ($ExportPath) {
    $folder = Split-Path -Path $ExportPath -Parent
    if (-not $folder) { $folder = (Get-Location).Path }
    if (-not (Test-Path -LiteralPath $folder)) {
      New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }

    $base  = [IO.Path]::GetFileNameWithoutExtension($ExportPath)
    $delim = $config.ExportDelimiter

    $RunState.summary                 | Export-Csv -Path (Join-Path $folder ($base + "_summary.csv"))          -NoTypeInformation -Encoding UTF8 -Delimiter $delim
    $RunState.indicators              | Export-Csv -Path (Join-Path $folder ($base + "_indicators.csv"))       -NoTypeInformation -Encoding UTF8 -Delimiter $delim
    @($script:Findings.ToArray()) | Export-Csv -Path (Join-Path $folder ($base + "_findings.csv"))    -NoTypeInformation -Encoding UTF8 -Delimiter $delim
    $policyFiles             | Export-Csv -Path (Join-Path $folder ($base + "_policyfiles.csv"))      -NoTypeInformation -Encoding UTF8 -Delimiter $delim
    ($RunState.events | Select-Object -First $ExportEventsTop) | Export-Csv -Path (Join-Path $folder ($base + "_recent_ci_events.csv")) -NoTypeInformation -Encoding UTF8 -Delimiter $delim
  }

  # 5) Console summary
  $RunState.findingsAL = ConvertTo-ArrayList -InputObject $script:Findings.ToArray()
}

function Invoke-Capability43MainPhase10 {
  param([hashtable]$RunState)
  if (-not $Quiet) {
    Write-ConsoleSummary -Summary $RunState.summary -Findings $RunState.findingsAL `
      -CustomFields ([ordered]@{
        RunningAsAdmin   = $RunState.indicators.RunningAsAdmin
        'CI Log Enabled' = $RunState.indicators.CILogEnabled
        'CI Events'      = $RunState.indicators.RecentCIEventsCount
        'Policies Found' = $RunState.indicators.PolicyFilesCount
        LikelyActive     = $RunState.summary.LikelyActive
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
    $latestEvent = @($RunState.events) | Select-Object -First 1
    if ($latestEvent) {
      Write-UiLine ''
      Write-UiLine ("Latest CI event    : {0} (Id {1}, {2})" -f $latestEvent.TimeCreated, $latestEvent.Id, $latestEvent.LevelDisplayName)
    }
    if ($config.PreferWriteInformation) {
      Write-Information ("AppControl audit complete. LikelyActive={0}" -f $RunState.summary.LikelyActive) -InformationAction Continue
    }
  }

  $RunState.findingsArr = @($RunState.findingsAL)
}

function Invoke-Capability43Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation, [hashtable]$RunState)
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability43MainPhase01 -RunState $RunState
  . Invoke-Capability43MainPhase02 -RunState $RunState
  . Invoke-Capability43MainPhase03 -RunState $RunState
  . Invoke-Capability43MainPhase04
  . Invoke-Capability43MainPhase05 -RunState $RunState
  . Invoke-Capability43MainPhase06 -RunState $RunState
  . Invoke-Capability43MainPhase07 -RunState $RunState
  . Invoke-Capability43MainPhase08 -RunState $RunState
  . Invoke-Capability43MainPhase09 -RunState $RunState
  . Invoke-Capability43MainPhase10 -RunState $RunState
}

function Get-Capability43ResultToken {
  param([hashtable]$RunState)
  $resultToken = if ($RunState.strictModeEnabled -and $RunState.findingsArr.Count -gt 0) { 'FAIL' } elseif ($RunState.findingsArr.Count -gt 0) { 'WARN' } else { 'OK' }
  return $resultToken
}
