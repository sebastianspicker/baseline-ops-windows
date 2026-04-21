# Helper functions extracted from 12-Suspicious-Artifact-Grabber.ps1
function New-ResultObject([string]$Name) {
  [pscustomobject]@{
    Name   = $Name
    Counts = @{}
    Errors = (New-Object System.Collections.Generic.List[string])
    Notes  = (New-Object System.Collections.Generic.List[string])
  }
}

function Add-Error([object]$res,[string]$msg) { if ($msg) { [void]$res.Errors.Add($msg) } }
function Add-Note ([object]$res,[string]$msg) { if ($msg) { [void]$res.Notes.Add($msg) } }

function Safe-ToInt {
  param([object]$Value,[int]$Default = 0)
  try {
    if ($null -eq $Value) { return $Default }
    return [int]$Value
  } catch { return $Default }
}

function Safe-ToBool {
  param([object]$Value,[bool]$Default = $false)
  try {
    if ($null -eq $Value) { return $Default }
    return [bool]$Value
  } catch { return $Default }
}

function Get-FileSignatureInfo([string]$File) {
  $o = [pscustomobject]@{
    Path            = $File
    SignatureStatus = $null
    Signed          = $false
    Publisher       = $null
  }
  try {
    if (-not (Test-Path -LiteralPath $File)) { return $o }
    $sig = Get-AuthenticodeSignature -FilePath $File -ErrorAction Stop
    $o.SignatureStatus = [string]$sig.Status
    $o.Signed = ($sig.Status -eq 'Valid')
    if ($sig.SignerCertificate) { $o.Publisher = $sig.SignerCertificate.Subject }
  } catch { <# best-effort: Authenticode check may fail for in-use or inaccessible files #> }
  return $o
}

function Get-PSObjectPropertyValue {
  param([object]$Obj,[string]$Name)
  try {
    if ($null -eq $Obj) { return $null }
    if ($Obj.PSObject.Properties.Name -contains $Name) { return $Obj.$Name }
  } catch { <# best-effort: property access on dynamic object #> }
  return $null
}

function New-RunId {
  (Get-Date).ToString('yyyyMMdd-HHmmss')
}

function New-BaseClone {
  param([object]$Obj)
  # JSON roundtrip clone to avoid accidental cross-run mutation
  return ($Obj | ConvertTo-Json -Depth 30 | ConvertFrom-Json)
}

# -------------------------
# Defaults (used when JSON is missing/unreadable)
# -------------------------
$DefaultCatalog = [pscustomobject]@{
  OutputBase = "PATH/TO/OUTPUT/ir/H2"
  Trigger    = [pscustomobject]@{
    Registry = 'HKLM:\SOFTWARE\IR\Grabber'
    FileFlag = 'PATH/TO/FLAG/GRAB.txt'
  }
  Process    = [pscustomobject]@{
    HashUserlandOnly = $true
    UserPathsRegex   = @(
      '^C:\\Users\\[^\\]+\\AppData\\',
      '^C:\\ProgramData\\',
      '^C:\\Windows\\Temp\\'
    )
  }
  Samples    = [pscustomobject]@{
    Enable                = $false
    MaxFileSizeMB         = 20
    MaxTotalMB            = 100
    OnlyUnsignedOrUnknown = $true
    PathIncludeRegex      = @(
      '^C:\\Users\\[^\\]+\\AppData\\',
      '^C:\\ProgramData\\'
    )
  }
  Tasks      = [pscustomobject]@{
    ExportXmlForSuspicious = $true
    SuspiciousRegex        = @(
      '(?i)\\Users\\[^\\]+\\AppData\\',
      '(?i)\\Temp\\',
      '(?i)\\ProgramData\\'
    )
    MaxXml                = 50
  }
}

function Merge-Catalog {
  param($base,$override)

  if ($null -eq $override) { return $base }

  foreach ($section in @('OutputBase','Trigger','Process','Samples','Tasks')) {
    if ($section -eq 'OutputBase') {
      $v = Get-PSObjectPropertyValue -Obj $override -Name 'OutputBase'
      if ($v) { $base.OutputBase = [string]$v }
      continue
    }

    $ov = Get-PSObjectPropertyValue -Obj $override -Name $section
    if ($null -eq $ov) { continue }

    foreach ($p in $base.$section.PSObject.Properties.Name) {
      $v = Get-PSObjectPropertyValue -Obj $ov -Name $p
      if ($null -ne $v -and $v -ne '') { $base.$section.$p = $v }
    }

    foreach ($p in $ov.PSObject.Properties.Name) {
      if (-not ($base.$section.PSObject.Properties.Name -contains $p)) {
        try { $base.$section | Add-Member -NotePropertyName $p -NotePropertyValue $ov.$p -Force } catch { <# best-effort: catalog merge for optional properties #> }
      }
    }
  }

  return $base
}

function Load-Catalog {
  param([string]$CatalogPath,[string]$ConfigPath,[ref]$CatalogLoadNote)

  $CatalogLoadNote.Value = $null
  $cat = $null

  $sanitizedCatalog = Sanitize-Path -Path $CatalogPath -MustExist
  if ($sanitizedCatalog) {
    $cat = Read-JsonFileSafe -Path $sanitizedCatalog
    if ($cat) { $CatalogLoadNote.Value = "Catalog loaded from -CatalogPath" }
  }

  if ($null -eq $cat -and $ConfigPath) {
    $sanitizedConfig = Sanitize-Path -Path $ConfigPath -MustExist
    if ($sanitizedConfig) {
      $cfg = Read-JsonFileSafe -Path $sanitizedConfig
      $p = $null
      try { $p = $cfg.Grabber.CatalogPath } catch { $p = $null }
      if ($p) {
        $sanitizedP = Sanitize-Path -Path $p -MustExist
        if ($sanitizedP) {
          $cat = Read-JsonFileSafe -Path $sanitizedP
          if ($cat) { $CatalogLoadNote.Value = "Catalog loaded from ConfigPath reference" }
        }
      }
    }
  }

  if ($null -eq $cat) { $CatalogLoadNote.Value = "Using defaults (no JSON or unreadable JSON)" }

  $baseClone = New-BaseClone $DefaultCatalog
  return (Merge-Catalog -base $baseClone -override $cat)
}

function Read-Trigger {
  param($cat,[switch]$Force,[switch]$CollectSamples)

  $reason   = $null
  $want     = $false
  $samples  = $false

  $maxFileMB  = Safe-ToInt $cat.Samples.MaxFileSizeMB 20
  $maxTotalMB = Safe-ToInt $cat.Samples.MaxTotalMB 100

  if ($Force) { $want = $true }

  try {
    $k = [string]$cat.Trigger.Registry
    $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
    if ($p) {
      if ($p.Request -eq 1) { $want = $true }
      if ($p.IncludeSamples -eq 1) { $samples = $true }
      if ($p.PSObject.Properties.Name -contains 'Reason') { $reason = [string]$p.Reason }
      if ($p.PSObject.Properties.Name -contains 'MaxFileSizeMB') { $maxFileMB = Safe-ToInt $p.MaxFileSizeMB $maxFileMB }
      if ($p.PSObject.Properties.Name -contains 'MaxTotalMB') { $maxTotalMB = Safe-ToInt $p.MaxTotalMB $maxTotalMB }
    }
  } catch { <# best-effort: trigger registry key may not exist #> }

  try {
    $ff = Expand-Env ([string]$cat.Trigger.FileFlag)
    if ($ff -and (Test-Path -LiteralPath $ff)) { $want = $true }
  } catch { <# best-effort: trigger file flag path may be invalid #> }

  if ($CollectSamples) { $samples = $true }

  [pscustomobject]@{
    Want       = $want
    Reason     = $reason
    Samples    = $samples
    MaxFileMB  = $maxFileMB
    MaxTotalMB = $maxTotalMB
  }
}

# -------------------------
# Collectors
# -------------------------
function Collect-Processes {
  param([string]$outDir,$cat,[switch]$hashAll)

  $res = New-ResultObject 'Processes'
  $csv = Join-Path $outDir 'processes.csv'

  try {
    Ensure-Directory $outDir

    $rxList=@(); try { $rxList=@($cat.Process.UserPathsRegex) } catch { <# best-effort: catalog property may not exist #> }
    $hashUserlandOnly = Safe-ToBool $cat.Process.HashUserlandOnly $true

    $procs = Get-CimInstance Win32_Process
    $rows = foreach ($p in $procs) {
      $path=$null; try { $path=[string]$p.ExecutablePath } catch { <# best-effort: process path may be inaccessible #> }

      $userlandMatch=$false
      if ($path) { foreach ($rx in $rxList) { if ($path -match $rx) { $userlandMatch=$true; break } } }

      $doHash=$false
      if ($hashAll) { $doHash=$true }
      elseif (-not $hashUserlandOnly) { $doHash=$true }
      elseif ($userlandMatch) { $doHash=$true }

      $sha=$null
      $sig=[pscustomobject]@{ Signed=$false; Publisher=$null; SignatureStatus=$null }
      if ($path) {
        if ($doHash) { $sha = Get-FileSha256 -Path $path }
        $sig = Get-FileSignatureInfo $path
      }

      [pscustomobject]@{
        ProcessId    = $p.ProcessId
        Name         = $p.Name
        CommandLine  = $p.CommandLine
        Path         = $path
        UserlandPath = $userlandMatch
        Sha256       = $sha
        Signed       = [string]$sig.Signed
        Publisher    = $sig.Publisher
        SigStatus    = $sig.SignatureStatus
      }
    }

    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csv
    $res.Counts.Count = @($rows).Count
  } catch {
    Add-Error $res ("process: " + $_.Exception.Message)
    $res.Counts.Count = 0
  }

  return $res
}

function Try-CollectNetworkNetCmdlets {
  param([string]$outDir,[ref]$counts,[ref]$note)

  $note.Value = $null
  try {
    $tcp = Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess
    $tcp | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'net_tcp.csv')

    $listen = $tcp | Where-Object { $_.State -eq 'Listen' }
    $listen | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'net_tcp_listen.csv')

    $counts.Value.Tcp = @($tcp).Count
    $counts.Value.Listeners = @($listen).Count

    try {
      $udp = Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess
      $udp | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'net_udp.csv')
      $counts.Value.Udp = @($udp).Count
    } catch {
      $counts.Value.Udp = 0
      $note.Value = "UDP cmdlet unavailable: " + $_.Exception.Message
    }

    try { Get-NetIPConfiguration | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'net_ipconfig.csv') } catch { <# best-effort: IP configuration cmdlet may not be available #> }
    try {
      Get-NetRoute | Select-Object ifIndex,DestinationPrefix,NextHop,RouteMetric,PolicyStore |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'net_routes.csv')
    } catch { <# best-effort: routing table cmdlet may not be available #> }
    try { Get-DnsClientCache | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'dns_cache.csv') } catch { <# best-effort: DNS cache cmdlet may not be available on all OS versions #> }

    return $true
  } catch {
    $note.Value = "NetTCPConnection unavailable: " + $_.Exception.Message
    return $false
  }
}

function Collect-NetworkNetstatFallback {
  param([string]$outDir,[ref]$counts,[ref]$note)

  $note.Value = "Using netstat fallback"
  $counts.Value.Tcp = 0
  $counts.Value.Listeners = 0
  $counts.Value.Udp = 0

  try {
    $raw = & netstat.exe -ano 2>$null
    $rows = foreach ($line in @($raw)) {
      $t = ($line -as [string]).Trim()
      if (-not $t) { continue }
      if ($t -match '^(TCP|UDP)\s+') {
        $parts = $t -split '\s+'
        if ($parts.Count -lt 4) { continue }

        $proto = $parts[0]
        $local = $parts[1]
        $remote = $parts[2]

        $state = $null
        $processId = $null

        if ($proto -eq 'TCP') {
          if ($parts.Count -ge 5) {
            $state = $parts[3]
            $processId = $parts[4]
          }
        } else {
          $processId = $parts[3]
        }

        $la=$null;$lp=$null;$ra=$null;$rp=$null

        if ($local -match '^(.*):(\d+)$') { $la=$matches[1]; $lp=[int]$matches[2] } else { $la=$local }
        if ($remote -match '^(.*):(\d+)$') { $ra=$matches[1]; $rp=[int]$matches[2] } else { $ra=$remote }

        [pscustomobject]@{
          Protocol      = $proto
          LocalAddress  = $la
          LocalPort     = $lp
          RemoteAddress = $ra
          RemotePort    = $rp
          State         = $state
          OwningProcess = $processId
        }
      }
    }

    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'net_netstat_ano.csv')

    $tcp = @($rows | Where-Object { $_.Protocol -eq 'TCP' })
    $udp = @($rows | Where-Object { $_.Protocol -eq 'UDP' })
    $lst = @($tcp | Where-Object { $_.State -eq 'LISTENING' })

    $counts.Value.Tcp = $tcp.Count
    $counts.Value.Udp = $udp.Count
    $counts.Value.Listeners = $lst.Count

    return $true
  } catch {
    $note.Value = "netstat fallback failed: " + $_.Exception.Message
    return $false
  }
}

function Collect-Network {
  param([string]$outDir)

  $res = New-ResultObject 'Network'
  try {
    Ensure-Directory $outDir

    $counts = [ref](@{ Tcp=0; Listeners=0; Udp=0 })
    $note = [ref]$null

    $okNet = Try-CollectNetworkNetCmdlets -outDir $outDir -counts $counts -note $note
    if (-not $okNet) {
      $okNet = Collect-NetworkNetstatFallback -outDir $outDir -counts $counts -note $note
    }

    $res.Counts = $counts.Value
    if ($note.Value) { Add-Note $res $note.Value }

    if (-not $okNet) {
      Add-Error $res "network: no usable collection method"
    }
  } catch {
    Add-Error $res ("network: " + $_.Exception.Message)
    $res.Counts = @{ Tcp=0; Listeners=0; Udp=0 }
  }

  return $res
}

function Convert-TaskActionsToText {
  param([object[]]$Actions)

  if ($null -eq $Actions -or $Actions.Count -eq 0) { return '' }

  $parts = New-Object System.Collections.Generic.List[string]

  foreach ($a in $Actions) {
    try {
      $pnames = @($a.PSObject.Properties.Name)

      if ($pnames -contains 'Execute') {
        $exe = [string]$a.Execute
        $arg = $null
        if ($pnames -contains 'Arguments') { $arg = [string]$a.Arguments }

        if ($exe -and $arg)      { [void]$parts.Add(($exe + ' ' + $arg)) }
        elseif ($exe)            { [void]$parts.Add($exe) }
        else                     { [void]$parts.Add('[ExecAction]') }
        continue
      }

      if ($pnames -contains 'ClassId') {
        [void]$parts.Add(('[ComHandlerAction] ClassId=' + [string]$a.ClassId))
        continue
      }

      [void]$parts.Add(('[Action] ' + $a.GetType().FullName))
    } catch {
      [void]$parts.Add('[Action] <unreadable>')
    }
  }

  return ($parts -join ' | ')
}

function Export-SuspiciousTaskXml {
  param(
    [string]$outDir,
    [array]$taskRows,
    [int]$MaxXml
  )

  Ensure-Directory $outDir
  $exported = 0

  foreach ($t in ($taskRows | Where-Object { $_.Suspicious -eq $true })) {
    if ($exported -ge $MaxXml) { break }
    try {
      $safe = (($t.TaskPath + $t.TaskName) -replace '[\\/:*?"<>|]','_')
      $xmlPath = Join-Path $outDir ($safe + '.xml')
      # S14 fix: validate constructed path does not escape the output directory
      Assert-NoPathTraversal -Path $safe -ParameterName 'TaskName'
      if (-not (Test-PathUnderRoot -Path $xmlPath -Root $outDir)) { continue }
      Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath | Out-File -FilePath $xmlPath -Encoding UTF8
      $exported++
    } catch { <# best-effort: individual task XML export may fail #> }
  }

  return $exported
}

function Collect-Tasks {
  param([string]$outDir,$cat)

  $res = New-ResultObject 'Tasks'
  $rx=@(); try { $rx=@($cat.Tasks.SuspiciousRegex) } catch { <# best-effort: catalog property may not exist #> }
  $exportXml = Safe-ToBool $cat.Tasks.ExportXmlForSuspicious $true
  $maxXml    = Safe-ToInt  $cat.Tasks.MaxXml 50

  try {
    Ensure-Directory $outDir

    $tasks = Get-ScheduledTask
    $flat = foreach ($t in $tasks) {
      $actions=@(); try { $actions=@($t.Actions) } catch { <# best-effort: task actions may not be accessible #> }
      $actionText = Convert-TaskActionsToText -Actions $actions

      $isSusp=$false
      foreach ($r in $rx) { if ($actionText -match $r) { $isSusp=$true; break } }

      $state=$null
      try { $state = (Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue).State } catch { <# best-effort: task state may not be readable #> }

      [pscustomobject]@{
        TaskName   = $t.TaskName
        TaskPath   = $t.TaskPath
        State      = $state
        Author     = $t.Principal.UserId
        Actions    = $actionText
        Suspicious = $isSusp
      }
    }

    $flat | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'tasks.csv')
    $res.Counts.Total = @($flat).Count
    $res.Counts.Suspicious = @($flat | Where-Object { $_.Suspicious }).Count

    if ($exportXml -and ($res.Counts.Suspicious -gt 0)) {
      $xmlDir = Join-Path $outDir 'xml'
      $exported = Export-SuspiciousTaskXml -outDir $xmlDir -taskRows $flat -MaxXml $maxXml
      $res.Counts.XmlExported = $exported
    } else {
      $res.Counts.XmlExported = 0
    }

    foreach ($t in ($flat | Where-Object { $_.Suspicious })) {
        Add-Finding -Code 'Grabber-SuspiciousTask' -Severity 'Medium' -Message "Suspicious scheduled task detected: $($t.TaskPath)$($t.TaskName)" -Extra $t
    }
  } catch {
    Add-Error $res ("tasks: " + $_.Exception.Message)
    $res.Counts.Total = 0
    $res.Counts.Suspicious = 0
    $res.Counts.XmlExported = 0
  }

  return $res
}

function Collect-WmiPersistence {
  param([string]$outDir)

  $res = New-ResultObject 'WMI'
  try {
    Ensure-Directory $outDir

    $filters  = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
    $bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue

    $cmdConsumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    $asConsumers  = Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue
    $evConsumers  = Get-CimInstance -Namespace root\subscription -ClassName NTEventLogEventConsumer -ErrorAction SilentlyContinue
    $lfConsumers  = Get-CimInstance -Namespace root\subscription -ClassName LogFileEventConsumer -ErrorAction SilentlyContinue

    @($filters)      | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'wmi_eventfilters.csv')
    @($bindings)     | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'wmi_bindings.csv')
    @($cmdConsumers) | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'wmi_consumers_cmdline.csv')
    @($asConsumers)  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'wmi_consumers_activescript.csv')
    @($evConsumers)  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'wmi_consumers_eventlog.csv')
    @($lfConsumers)  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'wmi_consumers_logfile.csv')

    $res.Counts.Filters      = @($filters).Count
    $res.Counts.Bindings     = @($bindings).Count
    $res.Counts.Cmd          = @($cmdConsumers).Count
    $res.Counts.ActiveScript = @($asConsumers).Count
    $res.Counts.NTEventLog   = @($evConsumers).Count
    $res.Counts.LogFile      = @($lfConsumers).Count
  } catch {
    Add-Error $res ("wmi: " + $_.Exception.Message)
    $res.Counts = @{
      Filters=0; Bindings=0; Cmd=0; ActiveScript=0; NTEventLog=0; LogFile=0
    }
  }

  return $res
}

function Export-Autoruns {
  param([string]$outDir)

  $res = New-ResultObject 'Autoruns'
  try {
    Ensure-Directory $outDir

    $targets=@(
      'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
      'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
      'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
      'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    $rows = foreach ($k in $targets) {
      try {
        if (-not (Test-Path -LiteralPath $k)) { continue }
        $p = Get-ItemProperty -Path $k -ErrorAction Stop
        foreach ($prop in $p.PSObject.Properties) {
          if ($prop.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
          [pscustomobject]@{ Key=$k; Name=$prop.Name; Value=[string]$prop.Value }
        }
      } catch {
        Add-Note $res ("autorun read failed: " + $k)
      }
    }

    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'autoruns_runkeys.csv')
    $res.Counts.Items = @($rows).Count
  } catch {
    Add-Error $res ("autoruns: " + $_.Exception.Message)
    $res.Counts.Items = 0
  }

  return $res
}

function Print-ConsoleSummary {
  param(
    [hashtable]$Summary,
    [System.Collections.Generic.List[string]]$Errors,
    [bool]$Findings,
    [string]$CatalogLoadNote
  )

  Write-UiHeader -Title ("IR Grabber Summary (v{0})" -f $ScriptVersion) -Subtitle ("Host: {0} | Time: {1}" -f $Summary.Host,$Summary.Time)

  if ($CatalogLoadNote) {
    Write-UiStatus -Label 'Config' -State 'INFO' -Text $CatalogLoadNote
  }

  Write-KeyValue -Key 'WorkDir' -Value ([string]$Summary.Output.WorkDir)
  Write-KeyValue -Key 'Zip'     -Value ([string]$Summary.Output.Zip)

  Write-UiLine
  Write-UiLine "Counts:" -ForegroundColor Gray

  try { Write-UiLine ("  Processes : {0}" -f (Safe-ToInt $Summary.Counts.Processes 0)) -ForegroundColor White } catch { <# best-effort: console summary display #> }

  try {
    $tcp = Safe-ToInt $Summary.Counts.Network.Tcp 0
    $lst = Safe-ToInt $Summary.Counts.Network.Listeners 0
    $udp = Safe-ToInt $Summary.Counts.Network.Udp 0
    Write-UiLine ("  Network   : TCP={0} Listeners={1} UDP={2}" -f $tcp,$lst,$udp) -ForegroundColor White
  } catch { <# best-effort: console summary display #> }

  try {
    $tot = Safe-ToInt $Summary.Counts.Tasks.Total 0
    $sus = Safe-ToInt $Summary.Counts.Tasks.Suspicious 0
    $xml = Safe-ToInt $Summary.Counts.Tasks.XmlExported 0

    $c = 'White'
    if ($sus -gt 0) { $c = 'Yellow' }
    Write-UiLine ("  Tasks     : Total={0} Suspicious={1} XmlExported={2}" -f $tot,$sus,$xml) -ForegroundColor $c
  } catch { <# best-effort: console summary display #> }

  try {
    $f = Safe-ToInt $Summary.Counts.WMI.Filters 0
    $b = Safe-ToInt $Summary.Counts.WMI.Bindings 0
    $c1 = Safe-ToInt $Summary.Counts.WMI.Cmd 0
    $a = Safe-ToInt $Summary.Counts.WMI.ActiveScript 0
    $e = Safe-ToInt $Summary.Counts.WMI.NTEventLog 0
    $l = Safe-ToInt $Summary.Counts.WMI.LogFile 0

    $wTotal = $f + $b + $c1 + $a + $e + $l
    $col = 'White'
    if ($wTotal -gt 0) { $col = 'Yellow' }

    Write-UiLine ("  WMI       : Filters={0} Bindings={1} Cmd={2} ActiveScript={3} NTEventLog={4} LogFile={5}" -f $f,$b,$c1,$a,$e,$l) -ForegroundColor $col
  } catch { <# best-effort: console summary display #> }

  try { Write-UiLine ("  Autoruns  : Items={0}" -f (Safe-ToInt $Summary.Counts.Autoruns.Items 0)) -ForegroundColor White } catch { <# best-effort: console summary display #> }

  try {
    if ($Summary.Counts.ContainsKey('Samples')) {
      $cop = Safe-ToInt $Summary.Counts.Samples.Copied 0
      $m1  = Safe-ToInt $Summary.Counts.Samples.MaxFileMB 0
      $m2  = Safe-ToInt $Summary.Counts.Samples.MaxTotalMB 0

      $col = 'White'
      if ($cop -gt 0) { $col = 'Yellow' }

      Write-UiLine ("  Samples   : Copied={0} (MaxFileMB={1}, MaxTotalMB={2})" -f $cop,$m1,$m2) -ForegroundColor $col
    }
  } catch { <# best-effort: console summary display #> }

  Write-UiLine

  if ($Errors -and $Errors.Count -gt 0) {
    Write-UiStatus -Label 'Errors' -State 'WARN' -Text ("{0} error(s) occurred" -f $Errors.Count)
    foreach ($e in @($Errors)) { Write-UiLine ("  - {0}" -f $e) -ForegroundColor Yellow }
  } else {
    Write-UiStatus -Label 'Errors' -State 'OK' -Text "None"
  }

  if ($Findings) {
    Write-UiStatus -Label 'Findings' -State 'WARN' -Text "YES (review outputs)"
  } else {
    Write-UiStatus -Label 'Findings' -State 'OK' -Text "NO"
  }

  Write-UiLine
}
