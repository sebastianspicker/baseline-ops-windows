# Helper functions extracted from 09-SupportBundle.ps1
function SB_WriteUi {
  param(
    [AllowNull()]
    [AllowEmptyString()]
    [string]$Message,

    [ConsoleColor]$Color = [ConsoleColor]::Gray,
    [switch]$NoNewline
  )

  # Never throw on empty UI output; it's UI, not logic.
  if ($null -eq $Message) { return }

  if ($script:UseInformationStream) {
    if ([string]::IsNullOrEmpty($Message)) { return }
    Write-Information -MessageData $Message -InformationAction Continue
    return
  }

  if ($NoNewline) {
    Write-UiLine $Message -ForegroundColor $Color -NoNewline
  } else {
    Write-UiLine $Message -ForegroundColor $Color
  }
}

function SB_WriteLog {
  param(
    [AllowNull()]
    [AllowEmptyString()]
    [string]$Message,

    [ValidateSet('INFO','WARN','ERROR','OK')]
    [string]$Level = 'INFO'
  )

  # Never throw on empty log lines.
  if ([string]::IsNullOrEmpty($Message)) { return }

  $prefix = "[{0}] " -f $Level
  switch ($Level) {
    'INFO'  { SB_WriteUi -Message ($prefix + $Message) -Color Gray }
    'OK'    { SB_WriteUi -Message ($prefix + $Message) -Color Green }
    'WARN'  { SB_WriteUi -Message ($prefix + $Message) -Color Yellow }
    'ERROR' { SB_WriteUi -Message ($prefix + $Message) -Color Red }
  }
}

function SB_WriteSection {
  param([Parameter(Mandatory)][string]$Title)

  $line = ('-' * 72)
  SB_WriteUi -Message ("[INFO] {0}" -f $line) -Color DarkGray
  SB_WriteUi -Message ("[INFO] {0}" -f $Title) -Color Cyan
  SB_WriteUi -Message ("[INFO] {0}" -f $line) -Color DarkGray
}

function SB_WriteHealthEvent {
  param(
    [int]$Id,
    [string]$Msg,
    [ValidateSet('Information','Warning','Error')]
    [string]$Level = 'Information'
  )

  try {
    Write-EventLog -LogName Application -Source $EventSource -EntryType $Level -EventId $Id -Message $Msg
  } catch {
    SB_WriteLog -Level $(if ($Level -eq 'Error') { 'ERROR' } elseif ($Level -eq 'Warning') { 'WARN' } else { 'INFO' }) -Message $Msg
  }
}

# -------------------- Basic helpers --------------------
function SB_IsAdmin {
  try {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function SB_EnsureDir {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function SB_SaveTextFile {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Text
  )
  SB_EnsureDir -Path (Split-Path -Parent $Path)
  $Text | Out-File -FilePath $Path -Encoding utf8
}

function SB_SaveJsonFile {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)]$Object
  )
  SB_EnsureDir -Path (Split-Path -Parent $Path)
  ($Object | ConvertTo-Json -Depth 40) | Out-File -FilePath $Path -Encoding utf8
}

function SB_SafeFileName {
  param([Parameter(Mandatory)][string]$Name)
  return ($Name -replace '[<>:"/\\|?*\x00-\x1F]', '_')
}

# -------------------- Structured records --------------------
function SB_NewRecord {
  param(
    [Parameter(Mandatory)][string]$Name,
    [bool]$Ok,
    [string]$ArtifactPath,
    [string]$Note,
    [Alias('Error')]
    [string]$ErrorText
  )

  [pscustomobject]@{
    Name         = $Name
    Ok           = [bool]$Ok
    ArtifactPath = $ArtifactPath
    Note         = $Note
    Error        = $ErrorText
    Time         = (Get-Date).ToString('s')
  }
}

function SB_NewSummary {
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][bool]$IsAdminNow,
    [Parameter(Mandatory)][int]$DaysBack,
    [Parameter(Mandatory)][bool]$IncludeSec,
    [Parameter(Mandatory)][bool]$IncludeDef,
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$ProofDir,
    [string]$ReasonText
  )

  [pscustomobject]@{
    Hostname    = $ComputerName
    Time        = (Get-Date).ToString('s')
    User        = $env:USERNAME
    Admin       = $IsAdminNow
    DaysBack    = $DaysBack
    IncludeSec  = $IncludeSec
    IncludeDef  = $IncludeDef
    ConfigPath  = $ConfigPath
    ProofDir    = $ProofDir
    Reason      = $ReasonText
    ZipPath     = $null
    WorkDir     = $null
    Records     = @()
  }
}

function SB_AddRecord {
  param(
    [Parameter(Mandatory)][object]$Summary,
    [Parameter(Mandatory)][pscustomobject]$Record
  )

  if (-not $Summary) { return }
  if (@($Summary.PSObject.Properties.Name) -notcontains 'Records') { return }

  if ($Summary.Records -isnot [object[]]) {
    $Summary.Records = @($Summary.Records)
  }

  $Summary.Records += $Record
}

function SB_TryStep {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][scriptblock]$Code
  )

  try {
    $r = & $Code
    if ($r -is [pscustomobject]) { return $r }
    return (SB_NewRecord -Name $Name -Ok $true -ArtifactPath $null -Note $null -Error $null)
  } catch {
    return (SB_NewRecord -Name $Name -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}

# -------------------- Summary printing (console-only) --------------------
function SB_ShowSummary {
  param([Parameter(Mandatory)][object]$Summary)

  if (-not $Summary) {
    SB_WriteLog -Level 'ERROR' -Message 'Summary is null (unexpected).'
    return
  }

  if (@($Summary.PSObject.Properties.Name) -notcontains 'Records') {
    SB_WriteLog -Level 'ERROR' -Message ("Summary missing Records. Type={0}" -f $Summary.GetType().FullName)
    return
  }

  $records = @()
  try { $records = @($Summary.Records) } catch { $records = @() }

  $errors = @($records | Where-Object { -not $_.Ok })
  $ok     = @($records | Where-Object { $_.Ok })

  SB_WriteSection -Title 'SupportBundle summary'
  SB_WriteLog -Message ("Host            : {0}" -f $Summary.Hostname) -Level 'INFO'
  SB_WriteLog -Message ("Time            : {0}" -f $Summary.Time) -Level 'INFO'
  SB_WriteLog -Message ("User            : {0}" -f $Summary.User) -Level 'INFO'
  SB_WriteLog -Message ("Admin           : {0}" -f $Summary.Admin) -Level $(if ($Summary.Admin) { 'OK' } else { 'WARN' })
  SB_WriteLog -Message ("DaysBack        : {0}" -f $Summary.DaysBack) -Level 'INFO'
  SB_WriteLog -Message ("IncludeSecurity : {0}" -f $Summary.IncludeSec) -Level 'INFO'
  SB_WriteLog -Message ("IncludeDefender : {0}" -f $Summary.IncludeDef) -Level 'INFO'
  if (-not [string]::IsNullOrWhiteSpace($Summary.Reason)) {
    SB_WriteLog -Message ("Reason          : {0}" -f $Summary.Reason) -Level 'INFO'
  }

  SB_WriteLog -Message ("WorkDir         : {0}" -f $(if (-not [string]::IsNullOrWhiteSpace($Summary.WorkDir)) { $Summary.WorkDir } else { '(not created)' })) -Level 'INFO'
  SB_WriteLog -Message ("Zip             : {0}" -f $(if (-not [string]::IsNullOrWhiteSpace($Summary.ZipPath)) { $Summary.ZipPath } else { '(not created)' })) -Level 'INFO'

  SB_WriteUi -Message "" -Color Gray
  SB_WriteLog -Message ("Records         : {0}" -f $records.Count) -Level 'INFO'
  SB_WriteLog -Message ("Successful      : {0}" -f $ok.Count) -Level 'OK'

  if ($errors.Count -gt 0) {
    SB_WriteLog -Message ("Errors          : {0}" -f $errors.Count) -Level 'ERROR'
    foreach ($e in ($errors | Select-Object -First 25)) {
      $msg = if (-not [string]::IsNullOrEmpty($e.Error)) { $e.Error } else { 'Unknown error' }
      SB_WriteLog -Level 'ERROR' -Message ("  ! {0} :: {1}" -f $e.Name, $msg)
    }
    if ($errors.Count -gt 25) {
      SB_WriteLog -Level 'WARN' -Message ("  ... ({0} more errors)" -f ($errors.Count - 25))
    }
  } else {
    SB_WriteLog -Message "Errors          : 0" -Level 'OK'
  }
}

# -------------------- Config --------------------
function SB_NewDefaultConfig {
  param([Parameter(Mandatory)][string]$ProofDirDefault)

  [pscustomobject]@{
    Paths = [pscustomobject]@{
      ProofDir = $ProofDirDefault
    }
    ProofOutFiles = [pscustomobject]@{
      SysmonState       = $null
      SysmonDriftState  = $null
      SoftwareInventory = $null
      FirewallAudit     = $null
      HardwareAudit     = $null
    }
  }
}

function SB_LoadJsonConfig {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][pscustomobject]$DefaultConfig
  )

  try {
    if (-not (Test-Path -LiteralPath $Path)) { return $DefaultConfig }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) { return $DefaultConfig }

    $cfg = $raw | ConvertFrom-Json
    if (-not $cfg) { return $DefaultConfig }

    if (-not ($cfg.PSObject.Properties.Name -contains 'Paths')) {
      $cfg | Add-Member -NotePropertyName Paths -NotePropertyValue ([pscustomobject]@{})
    }
    if (-not ($cfg.PSObject.Properties.Name -contains 'ProofOutFiles')) {
      $cfg | Add-Member -NotePropertyName ProofOutFiles -NotePropertyValue ([pscustomobject]@{})
    }
    if (-not ($cfg.Paths.PSObject.Properties.Name -contains 'ProofDir')) {
      $cfg.Paths | Add-Member -NotePropertyName ProofDir -NotePropertyValue $DefaultConfig.Paths.ProofDir
    }

    return $cfg
  } catch {
    return $DefaultConfig
  }
}

# -------------------- Registry trigger (StrictMode-safe) --------------------
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
# -------------------- Event logs --------------------
function SB_TestEventLogExists {
  param([Parameter(Mandatory)][string]$LogName)
  try {
    $p = Start-Process -FilePath "$env:WINDIR\System32\wevtutil.exe" -ArgumentList @('gl', $LogName) -Wait -PassThru -WindowStyle Hidden
    return ($p.ExitCode -eq 0)
  } catch { return $false }
}

function SB_ExportEventLogEvtx {
  param(
    [Parameter(Mandatory)][string]$LogName,
    [Parameter(Mandatory)][string]$OutFile,
    [ValidateRange(1,365)]
    [int]$DaysBack = 7
  )

  SB_EnsureDir -Path (Split-Path -Parent $OutFile)

  $ms    = [int64]($DaysBack * 24 * 60 * 60 * 1000)
  $xpath = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"

  try {
    # S13 fix: use Invoke-Wevtutil wrapper with array-based args instead of direct wevtutil call
    $wevtArgs = @('epl', $LogName, $OutFile, "/q:$xpath", '/ow:true')
    Invoke-Wevtutil -Arguments $wevtArgs -ThrowOnError | Out-Null
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
    [int]$DaysBack = 7
  )

  $ms    = [int64]($DaysBack * 24 * 60 * 60 * 1000)
  $xpath = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"

  try {
    $events = Get-WinEvent -LogName $LogName -FilterXPath $xpath -ErrorAction Stop

    $csv = $OutFileBase + '.csv'
    $txt = $OutFileBase + '.txt'
    SB_EnsureDir -Path (Split-Path -Parent $csv)

    $events |
      Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, LogName, Message |
      Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8

    ($events | Select-Object -First 200 | Format-List * | Out-String -Width 4000) |
      Out-File -FilePath $txt -Encoding utf8

    return (SB_NewRecord -Name ("Fallback:{0}" -f $LogName) -Ok $true -ArtifactPath $csv -Note 'Fallback CSV/TXT created' -Error $null)
  } catch {
    return (SB_NewRecord -Name ("Fallback:{0}" -f $LogName) -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}

# -------------------- Proofs --------------------
function SB_CopyIfExists {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$DestDir
  )

  try {
    if (-not (Test-Path -LiteralPath $Path)) {
      return (SB_NewRecord -Name 'CopyProof' -Ok $true -ArtifactPath $null -Note ("Skip (not found): {0}" -f $Path) -Error $null)
    }

    SB_EnsureDir -Path $DestDir
    Copy-Item -LiteralPath $Path -Destination $DestDir -Recurse -Force -ErrorAction Stop
    return (SB_NewRecord -Name 'CopyProof' -Ok $true -ArtifactPath $DestDir -Note ("Copied: {0}" -f (Split-Path -Leaf $Path)) -Error $null)
  } catch {
    return (SB_NewRecord -Name 'CopyProof' -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}

# -------------------- Reports --------------------
function SB_ExportTextCommand {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][scriptblock]$Command,
    [Parameter(Mandatory)][string]$OutDir
  )

  try {
    SB_EnsureDir -Path $OutDir
    $path = Join-Path $OutDir ($Name + '.txt')
    $text = (& $Command | Out-String -Width 4000)
    SB_SaveTextFile -Path $path -Text $text
    return (SB_NewRecord -Name ("Report:{0}" -f $Name) -Ok $true -ArtifactPath $path -Note $null -Error $null)
  } catch {
    return (SB_NewRecord -Name ("Report:{0}" -f $Name) -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}

function SB_ExportSystemReports {
  param([Parameter(Mandatory)][string]$OutDir)

  $list = @()

  $list += (SB_ExportTextCommand -Name 'systeminfo'          -OutDir $OutDir -Command { cmd.exe /c systeminfo })
  $list += (SB_ExportTextCommand -Name 'ipconfig_all'        -OutDir $OutDir -Command { cmd.exe /c ipconfig /all })
  $list += (SB_ExportTextCommand -Name 'route_print'         -OutDir $OutDir -Command { cmd.exe /c route print })
  $list += (SB_ExportTextCommand -Name 'netsh_winhttp_proxy' -OutDir $OutDir -Command { cmd.exe /c 'netsh winhttp show proxy' })
  $list += (SB_ExportTextCommand -Name 'whoami_all'          -OutDir $OutDir -Command { cmd.exe /c 'whoami /all' })

  $list += (SB_TryStep -Name 'Report:hotfixes' -Code {
    SB_EnsureDir -Path $OutDir
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

# -------------------- KB feed --------------------
function SB_ExportKbStatus {
  param(
    [Parameter(Mandatory)][string]$KbFeedPath,
    [Parameter(Mandatory)][string]$OutFile
  )

  if (-not (Test-Path -LiteralPath $KbFeedPath)) {
    return (SB_NewRecord -Name 'KBFeed' -Ok $true -ArtifactPath $null -Note ("KB feed not found (skip): {0}" -f $KbFeedPath) -Error $null)
  }

  try {
    $kbfeed = Get-Content -LiteralPath $KbFeedPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $installedKB = @(Get-HotFix | Select-Object -ExpandProperty HotFixID)

    $missingCritical = @()
    $missingZeroDay  = @()

    if ($kbfeed -and $kbfeed.KBs) {
      foreach ($kb in $kbfeed.KBs) {
        if ($installedKB -notcontains $kb.KB) {
          if ($kb.IsZeroDay -eq $true) { $missingZeroDay += $kb } else { $missingCritical += $kb }
        }
      }
    }

    $kbStatus = [pscustomobject]@{
      CriticalFeedPath   = $KbFeedPath
      Time               = (Get-Date).ToString('s')
      InstalledHotFixIDs = $installedKB
      MissingCritical    = $missingCritical
      MissingZeroDay     = $missingZeroDay
      Summary            = "MissingCritical=$($missingCritical.Count), ZeroDay=$($missingZeroDay.Count)"
      MethodNote         = 'InstalledHotFixIDs from Get-HotFix; may not reflect full LCU/SSU state.'
    }

    SB_SaveJsonFile -Path $OutFile -Object $kbStatus

    $note = $null
    if ($missingZeroDay.Count -gt 0) {
      $note = "Missing Zero-Day KB(s): " + (($missingZeroDay | ForEach-Object { $_.KB }) -join ', ')
    } elseif ($missingCritical.Count -gt 0) {
      $note = "Missing critical KB(s): " + (($missingCritical | ForEach-Object { $_.KB }) -join ', ')
    }

    return (SB_NewRecord -Name 'KBFeed' -Ok $true -ArtifactPath $OutFile -Note $note -Error $null)
  } catch {
    return (SB_NewRecord -Name 'KBFeed' -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}

# -------------------- Defender --------------------
function SB_ExportDefenderStatus {
  param([Parameter(Mandatory)][string]$OutDir)

  $list = @()
  SB_EnsureDir -Path $OutDir

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

function SB_ResolveMpCmdRun {
  $candidates = @()

  $pfCandidate = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
  if (Test-Path -LiteralPath $pfCandidate) { $candidates += $pfCandidate }

  $platformRoot = 'C:\ProgramData\Microsoft\Windows Defender\Platform'
  if (Test-Path -LiteralPath $platformRoot) {
    $latest = Get-ChildItem -LiteralPath $platformRoot -Directory -ErrorAction SilentlyContinue |
      Sort-Object Name -Descending |
      Select-Object -First 1
    if ($latest) {
      $platCandidate = Join-Path $latest.FullName 'MpCmdRun.exe'
      if (Test-Path -LiteralPath $platCandidate) { $candidates += $platCandidate }
    }
  }

  if ($candidates.Count -gt 0) { return $candidates[0] }
  return $null
}

function SB_NewDefenderSupportCab {
  param([Parameter(Mandatory)][string]$OutDir)

  SB_EnsureDir -Path $OutDir

  $mpCmdRun   = SB_ResolveMpCmdRun
  $cabDefault = 'C:\ProgramData\Microsoft\Windows Defender\Support\MpSupportFiles.cab'
  $cabOut     = Join-Path $OutDir ("MpSupportFiles-{0}.cab" -f (Get-Date).ToString('yyyyMMdd-HHmmss'))

  try {
    if (-not $mpCmdRun) { throw 'MpCmdRun.exe not found.' }

    $p = Start-Process -FilePath $mpCmdRun -ArgumentList @('-GetFiles') -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -ne 0) { throw "MpCmdRun -GetFiles ExitCode $($p.ExitCode)" }

    if (-not (Test-Path -LiteralPath $cabDefault)) { throw "CAB not found at expected path: $cabDefault" }
    Copy-Item -LiteralPath $cabDefault -Destination $cabOut -Force

    return (SB_NewRecord -Name 'Defender:supportCab' -Ok $true -ArtifactPath $cabOut -Note $null -Error $null)
  } catch {
    return (SB_NewRecord -Name 'Defender:supportCab' -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}
