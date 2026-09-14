<#
.SYNOPSIS
Support bundle collection helpers.

.DESCRIPTION
Contains capability-private support bundle collection behavior.
#>

function SB_TryGetRegValue {
  param(
    [Parameter(Mandatory)][string]$KeyPath,
    [Parameter(Mandatory)][string]$Name
  )
  try { return (Get-ItemPropertyValue -Path $KeyPath -Name $Name -ErrorAction Stop) }
  catch { return $null }
}

function SB_GetRegistryTrigger {
  param([Parameter(Mandatory)][string]$KeyPath)

  try {
    if (-not (Test-Path -Path $KeyPath)) {
      return [pscustomobject]@{ Ok=$false; Error="Path not found: $KeyPath" }
    }

    return [pscustomobject]@{
      Ok                     = $true
      Error                  = $null
      Request                = SB_TryGetRegValue -KeyPath $KeyPath -Name 'Request'
      Days                   = SB_TryGetRegValue -KeyPath $KeyPath -Name 'Days'
      IncludeSecurity        = SB_TryGetRegValue -KeyPath $KeyPath -Name 'IncludeSecurity'
      IncludeDefenderSupport = SB_TryGetRegValue -KeyPath $KeyPath -Name 'IncludeDefenderSupport'
      Reason                 = SB_TryGetRegValue -KeyPath $KeyPath -Name 'Reason'
    }
  } catch {
    return [pscustomobject]@{ Ok=$false; Error=$_.Exception.Message }
  }
}

function SB_TestEventLogExists {
  param([Parameter(Mandatory)][string]$LogName)
  try {
    $native = Invoke-NativeCommand -Command 'wevtutil.exe' -Arguments @('gl', $LogName) -CaptureOutput -Quiet -TimeoutSeconds 30 -MaxOutputBytes 65536
    return ($null -ne $native -and $native.Success -and -not $native.TimedOut -and -not $native.OutputTruncated -and -not $native.StderrTruncated)
  } catch { return $false }
}

function SB_ExportEventLogEvtx {
  param(
    [Parameter(Mandatory)][string]$LogName,
    [Parameter(Mandatory)][string]$OutFile,
    [ValidateRange(1,365)]
    [int]$DaysBack = 7
  )

  [void](Ensure-Directory -Path (Split-Path -Parent $OutFile))

  $ms    = [int64]($DaysBack * 24 * 60 * 60 * 1000)
  $xpath = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"

  try {
    $wevtArgs = @('epl', $LogName, $OutFile, "/q:$xpath", '/ow:true')
    $native = Invoke-NativeCommand -Command 'wevtutil.exe' -Arguments $wevtArgs -ThrowOnError -CaptureOutput -TimeoutSeconds 120 -MaxOutputBytes 2097152
    if ($native.TimedOut -or $native.OutputTruncated -or $native.StderrTruncated) { throw 'wevtutil export timed out or produced truncated output.' }
    return (SB_NewRecord -Name ("EVTX:{0}" -f $LogName) -Ok $true -ArtifactPath $OutFile -Note $null -Error $null)
  } catch {
    return (SB_NewRecord -Name ("EVTX:{0}" -f $LogName) -Ok $false -ArtifactPath $OutFile -Note $null -Error $_.Exception.Message)
  }
}

function SB_ExportEventLogFallback {
  param(
    [Parameter(Mandatory)][string]$LogName,
    [Parameter(Mandatory)][string]$OutFileBase,
    [ValidateRange(1,365)]
    [int]$DaysBack = 7,
    [ValidateRange(1,100000)]
    [int]$MaxEvents = 10000
  )

  $ms    = [int64]($DaysBack * 24 * 60 * 60 * 1000)
  $xpath = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"

  try {
    # Get-WinEvent otherwise materializes every matching event before either
    # report is written.  Keep the fallback bounded as it is used precisely
    # when the native EVTX export path was unavailable.
    $events = @(Get-WinEvent -LogName $LogName -FilterXPath $xpath -MaxEvents $MaxEvents -ErrorAction Stop)

    $csv = $OutFileBase + '.csv'
    $txt = $OutFileBase + '.txt'
    [void](Ensure-Directory -Path (Split-Path -Parent $csv))

    $events |
      Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, LogName, Message |
      Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8

    ($events | Select-Object -First ([Math]::Min(200, $MaxEvents)) | Format-List * | Out-String -Width 4000) |
      Out-File -FilePath $txt -Encoding utf8

    return (SB_NewRecord -Name ("Fallback:{0}" -f $LogName) -Ok $true -ArtifactPath $csv -Note 'Fallback CSV/TXT created' -Error $null)
  } catch {
    return (SB_NewRecord -Name ("Fallback:{0}" -f $LogName) -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}

function SB_CopyIfExists {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$DestDir
  )

  try {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
      return (SB_NewRecord -Name 'CopyProof' -Ok $true -ArtifactPath $null -Note ("Skip (not found): {0}" -f $Path) -Error $null)
    }

    [void](Ensure-Directory -Path $DestDir)
    Copy-Item -LiteralPath $Path -Destination $DestDir -Force -ErrorAction Stop
    return (SB_NewRecord -Name 'CopyProof' -Ok $true -ArtifactPath $DestDir -Note ("Copied: {0}" -f (Split-Path -Leaf $Path)) -Error $null)
  } catch {
    return (SB_NewRecord -Name 'CopyProof' -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}

function SB_ExportTextCommand {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Command,
    [Parameter(Mandatory)][string[]]$Arguments,
    [Parameter(Mandatory)][string]$OutDir
  )

  try {
    [void](Ensure-Directory -Path $OutDir)
    $path = Join-Path $OutDir ($Name + '.txt')
    $native = Invoke-NativeCommand -Command $Command -Arguments $Arguments -CaptureOutput -Quiet -TimeoutSeconds 60 -MaxOutputBytes 1048576
    if ($null -eq $native -or -not $native.Success -or $native.TimedOut -or $native.OutputTruncated -or $native.StderrTruncated) { throw "$Name timed out, failed, or produced truncated output." }
    $text = $native.Output
    SB_SaveTextFile -Path $path -Text $text
    return (SB_NewRecord -Name ("Report:{0}" -f $Name) -Ok $true -ArtifactPath $path -Note $null -Error $null)
  } catch {
    return (SB_NewRecord -Name ("Report:{0}" -f $Name) -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}

function SB_ExportSystemReports {
  param([Parameter(Mandatory)][string]$OutDir)

  $list = @()

  $list += (SB_ExportTextCommand -Name 'systeminfo'          -OutDir $OutDir -Command 'systeminfo.exe' -Arguments @())
  $list += (SB_ExportTextCommand -Name 'ipconfig_all'        -OutDir $OutDir -Command 'ipconfig.exe' -Arguments @('/all'))
  $list += (SB_ExportTextCommand -Name 'route_print'         -OutDir $OutDir -Command 'route.exe' -Arguments @('print'))
  $list += (SB_ExportTextCommand -Name 'netsh_winhttp_proxy' -OutDir $OutDir -Command 'netsh.exe' -Arguments @('winhttp','show','proxy'))
  $list += (SB_ExportTextCommand -Name 'whoami_all'          -OutDir $OutDir -Command 'whoami.exe' -Arguments @('/all'))

  $list += (SB_TryStep -Name 'Report:hotfixes' -Code {
    [void](Ensure-Directory -Path $OutDir)
    $path = Join-Path $OutDir 'hotfixes.json'
    $hotfix = Get-HotFix | Select-Object HotFixID, InstalledOn, Description, InstalledBy
    SB_SaveJsonFile -Path $path -Object $hotfix
    SB_NewRecord -Name 'Report:hotfixes' -Ok $true -ArtifactPath $path -Note $null -Error $null
  })

  $idx = Join-Path $OutDir 'ReportsIndex.json'
  SB_SaveJsonFile -Path $idx -Object $list
  $list += (SB_NewRecord -Name 'Report:index' -Ok $true -ArtifactPath $idx -Note $null -Error $null)

  return $list
}

function SB_GetMissingKbState {
  param($KbFeed, [object[]]$InstalledKb)
  $state = @{ Critical = @(); ZeroDay = @() }
  if (-not $KbFeed -or -not $KbFeed.KBs) { return $state }
  foreach ($kb in $KbFeed.KBs) {
    if ($InstalledKb -contains $kb.KB) { continue }
    if ($kb.IsZeroDay -eq $true) { $state.ZeroDay += $kb } else { $state.Critical += $kb }
  }
  return $state
}

function SB_GetMissingKbNote {
  param([object[]]$Critical, [object[]]$ZeroDay)
  if ($ZeroDay.Count -gt 0) {
    return "Missing Zero-Day KB(s): " + (($ZeroDay | ForEach-Object { $_.KB }) -join ', ')
  }
  if ($Critical.Count -gt 0) {
    return "Missing critical KB(s): " + (($Critical | ForEach-Object { $_.KB }) -join ', ')
  }
  return $null
}

function SB_WriteKbStatus {
  param([string]$KbFeedPath, [string]$OutFile, [object[]]$InstalledKb, [hashtable]$Missing)
    $kbStatus = [pscustomobject]@{
      CriticalFeedPath   = $KbFeedPath
      Time               = (Get-Date).ToString('s')
      InstalledHotFixIDs = $InstalledKb
      MissingCritical    = $Missing.Critical
      MissingZeroDay     = $Missing.ZeroDay
      Summary            = "MissingCritical=$($Missing.Critical.Count), ZeroDay=$($Missing.ZeroDay.Count)"
      MethodNote         = 'InstalledHotFixIDs from Get-HotFix; may not reflect full LCU/SSU state.'
    }
    SB_SaveJsonFile -Path $OutFile -Object $kbStatus
}

function SB_ExportKbStatus {
  param([Parameter(Mandatory)][string]$KbFeedPath, [Parameter(Mandatory)][string]$OutFile)
  if (-not (Test-Path -LiteralPath $KbFeedPath)) {
    return (SB_NewRecord -Name 'KBFeed' -Ok $true -ArtifactPath $null -Note ("KB feed not found (skip): {0}" -f $KbFeedPath) -Error $null)
  }
  try {
    $kbFeed = Get-BoundedUtf8FileContent -Path $KbFeedPath -MaximumBytes 16777216 | ConvertFrom-Json
    $installedKb = @(Get-HotFix | Select-Object -ExpandProperty HotFixID)
    $missing = SB_GetMissingKbState -KbFeed $kbFeed -InstalledKb $installedKb
    SB_WriteKbStatus -KbFeedPath $KbFeedPath -OutFile $OutFile -InstalledKb $installedKb -Missing $missing
    $note = SB_GetMissingKbNote -Critical $missing.Critical -ZeroDay $missing.ZeroDay

    return (SB_NewRecord -Name 'KBFeed' -Ok $true -ArtifactPath $OutFile -Note $note -Error $null)
  }
  catch {
    return (SB_NewRecord -Name 'KBFeed' -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}

function SB_ExportDefenderStatus {
  param([Parameter(Mandatory)][string]$OutDir)

  $list = @()
  [void](Ensure-Directory -Path $OutDir)

  $list += (SB_TryStep -Name 'Defender:status' -Code {
    $cmd = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
    if (-not $cmd) { throw 'Get-MpComputerStatus not available.' }
    $path = Join-Path $OutDir 'DefenderStatus.json'
    SB_SaveJsonFile -Path $path -Object (Get-MpComputerStatus)
    SB_NewRecord -Name 'Defender:status' -Ok $true -ArtifactPath $path -Note $null -Error $null
  })

  $list += (SB_TryStep -Name 'Defender:preference' -Code {
    $cmd = Get-Command Get-MpPreference -ErrorAction SilentlyContinue
    if (-not $cmd) { throw 'Get-MpPreference not available.' }
    $path = Join-Path $OutDir 'DefenderPreference.json'
    SB_SaveJsonFile -Path $path -Object (Get-MpPreference)
    SB_NewRecord -Name 'Defender:preference' -Ok $true -ArtifactPath $path -Note $null -Error $null
  })

  $idx = Join-Path $OutDir 'DefenderIndex.json'
  SB_SaveJsonFile -Path $idx -Object $list
  $list += (SB_NewRecord -Name 'Defender:index' -Ok $true -ArtifactPath $idx -Note $null -Error $null)

  return $list
}

function SB_GetProgramFilesMpCmdRun {
  $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
  if ([string]::IsNullOrWhiteSpace($programFiles)) { return $null }
  $candidate = Join-Path $programFiles 'Windows Defender\MpCmdRun.exe'
  if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
  return $null
}

function SB_GetPlatformMpCmdRun {
  $commonData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  $platformRoot = if ([string]::IsNullOrWhiteSpace($commonData)) { $null } else { Join-Path $commonData 'Microsoft\Windows Defender\Platform' }
  if ([string]::IsNullOrWhiteSpace($platformRoot) -or -not (Test-Path -LiteralPath $platformRoot -PathType Container)) { return $null }
  $latest = Get-ChildItem -LiteralPath $platformRoot -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending | Select-Object -First 1
  if (-not $latest) { return $null }
  $candidate = Join-Path $latest.FullName 'MpCmdRun.exe'
  if (Test-Path -LiteralPath $candidate) { return $candidate }
  return $null
}

function SB_ResolveMpCmdRun {
  $candidates = @(SB_GetProgramFilesMpCmdRun; SB_GetPlatformMpCmdRun)
  if ($candidates.Count -gt 0) { return $candidates[0] }
  return $null
}

function SB_InvokeDefenderSupportCollection {
  param([string]$MpCmdRun, [string]$CabDefault, [string]$CabOut)
  if (-not $MpCmdRun) { throw 'MpCmdRun.exe not found.' }
  $native = Invoke-NativeCommand -Command $MpCmdRun -Arguments @('-GetFiles') -CaptureOutput -Quiet -TimeoutSeconds 600 -MaxOutputBytes 1048576
  if (-not (SB_TestSuccessfulNativeResult -NativeResult $native)) {
    throw 'MpCmdRun -GetFiles timed out, failed, or produced truncated output.'
  }
  if (-not (Test-Path -LiteralPath $CabDefault)) { throw "CAB not found at expected path: $CabDefault" }
  Copy-Item -LiteralPath $CabDefault -Destination $CabOut -Force
}

function SB_TestSuccessfulNativeResult {
  param($NativeResult)
  return ($null -ne $NativeResult -and $NativeResult.Success -and -not $NativeResult.TimedOut -and
    -not $NativeResult.OutputTruncated -and -not $NativeResult.StderrTruncated)
}

function SB_NewDefenderSupportCab {
  param([Parameter(Mandatory)][string]$OutDir)

  [void](Ensure-Directory -Path $OutDir)

  $mpCmdRun   = SB_ResolveMpCmdRun
  $commonData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  if ([string]::IsNullOrWhiteSpace($commonData)) { throw 'CommonApplicationData could not be resolved.' }
  $cabDefault = Join-Path $commonData 'Microsoft\Windows Defender\Support\MpSupportFiles.cab'
  $cabOut     = Join-Path $OutDir ("MpSupportFiles-{0}.cab" -f (Get-Date).ToString('yyyyMMdd-HHmmss'))

  try {
    SB_InvokeDefenderSupportCollection -MpCmdRun $mpCmdRun -CabDefault $cabDefault -CabOut $cabOut
    return (SB_NewRecord -Name 'Defender:supportCab' -Ok $true -ArtifactPath $cabOut -Note $null -Error $null)
  } catch {
    return (SB_NewRecord -Name 'Defender:supportCab' -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}
