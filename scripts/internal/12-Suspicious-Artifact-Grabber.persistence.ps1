#requires -version 5.1
<#
.SYNOPSIS
  Provides private artifact collection phases.
.DESCRIPTION
  Preserves protected evidence paths, bounded observations, trigger decisions, and artifact proof ordering within this capability.
#>


function Convert-TaskActionsToText {
  param([object[]]$Actions)

  if ($null -eq $Actions -or $Actions.Count -eq 0) {
    return ''
  }

  $parts = New-Object System.Collections.Generic.List[string]

  foreach ($a in $Actions) {
    Add-ArtifactTaskActionText -Parts $parts -Action $a
  }

  return ($parts -join ' | ')
}
function Add-ArtifactTaskActionText {
  param($Parts, $Action)
  $a = $Action
  try {
    $pnames = @($a.PSObject.Properties.Name)

    if ($pnames -contains 'Execute') {
      Add-ArtifactExecActionText -Parts $parts -Action $a -PropertyNames $pnames
      return
    }

    if ($pnames -contains 'ClassId') {
      [void]$parts.Add(('[ComHandlerAction] ClassId=' + [string]$a.ClassId))
      return
    }

    [void]$parts.Add(('[Action] ' + $a.GetType().FullName))
  }
  catch {
    [void]$parts.Add('[Action] <unreadable>')
  }

}

function Export-SuspiciousTaskXml {
  param(
    [string]$outDir,
    [array]$taskRows,
    [int]$MaxXml
  )

  [void](Ensure-Directory $outDir)
  $exported = 0

  foreach ($t in ($taskRows | Where-Object { $_.Suspicious -eq $true })) {
    if ($exported -ge $MaxXml) {
      break
    }
    try {
      $safe = (($t.TaskPath + $t.TaskName) -replace '[\\/:*?"<>|]', '_')
      $xmlPath = Join-Path $outDir ($safe + '.xml')
      # S14 fix: validate constructed path does not escape the output directory
      Assert-NoPathTraversal -Path $safe -ParameterName 'TaskName'
      if (-not (Test-PathUnderRoot -Path $xmlPath -Root $outDir)) {
        continue
      }
      Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath | Out-File -FilePath $xmlPath -Encoding UTF8
      $exported++
    }
    catch {
      Write-Verbose ("Task XML export failed for '{0}{1}': {2}" -f $t.TaskPath, $t.TaskName, $_.Exception.Message)
    }
  }

  return $exported
}
function Collect-Tasks {
  param([string]$outDir, $cat)

  $res = Get-ResultObject 'Tasks'
  $rx = @()
  try {
    $rx = @($cat.Tasks.__SuspiciousRegex)
  }
  catch {
    Add-Note $res ("task suspicious-regex lookup failed: " + $_.Exception.Message)
  }
  $exportXml = Safe-ToBool $cat.Tasks.ExportXmlForSuspicious $true
  $maxXml = Safe-ToInt  $cat.Tasks.MaxXml 50

  try {
    [void](Ensure-Directory $outDir)

    $tasks = Get-ScheduledTask
    $flat = foreach ($t in $tasks) {
      Get-ArtifactTaskRow -t $t -rx $rx -res $res
    }

    $flat | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'tasks.csv')
    $res.Counts.Total = @($flat).Count
    $res.Counts.Suspicious = @($flat | Where-Object { $_.Suspicious }).Count

    if ($exportXml -and ($res.Counts.Suspicious -gt 0)) {
      $xmlDir = Join-Path $outDir 'xml'
      $exported = Export-SuspiciousTaskXml -outDir $xmlDir -taskRows $flat -MaxXml $maxXml
      $res.Counts.XmlExported = $exported
    }
    else {
      $res.Counts.XmlExported = 0
    }

    Add-ArtifactTaskFindings -flat $flat
  }
  catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
    throw
  }
  catch {
    Add-Error $res ("tasks: " + $_.Exception.Message)
    $res.Counts.Total = 0
    $res.Counts.Suspicious = 0
    $res.Counts.XmlExported = 0
  }

  return $res
}
function Get-ArtifactTaskRow {
  param($t, $rx, $res)
  $actions = @()
  try {
    $actions = @($t.Actions)
  }
  catch {
    Add-Note $res ("task actions unreadable for $($t.TaskPath)$($t.TaskName): " + $_.Exception.Message)
  }
  $actionText = Convert-TaskActionsToText -Actions $actions

  $isSusp = Test-ArtifactRegexMatch -Value $actionText -RegexList $rx

  $state = $null
  try {
    $state = (Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue).State
  }
  catch {
    Add-Note $res ("task state unreadable for $($t.TaskPath)$($t.TaskName): " + $_.Exception.Message)
  }

  [pscustomobject]@{
    TaskName = $t.TaskName
    TaskPath = $t.TaskPath
    State = $state
    Author = $t.Principal.UserId
    Actions = $actionText
    Suspicious = $isSusp
  }

}

function Add-ArtifactTaskFindings {
  param($flat)
  foreach ($t in ($flat | Where-Object { $_.Suspicious })) {
    $extra = @{}
    foreach ($prop in $t.PSObject.Properties) {
      $extra[$prop.Name] = $prop.Value
    }
    [void](Add-Finding -FindingList $script:Findings -Code 'Grabber-SuspiciousTask' -Severity 'Medium' -Message "Suspicious scheduled task detected: $($t.TaskPath)$($t.TaskName)" -Extra $extra)
  }

}

function Collect-WmiPersistence {
  param([string]$outDir)

  $res = Get-ResultObject 'WMI'
  try {
    [void](Ensure-Directory $outDir)

    $filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
    $bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue

    $cmdConsumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    $asConsumers = Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue
    $evConsumers = Get-CimInstance -Namespace root\subscription -ClassName NTEventLogEventConsumer -ErrorAction SilentlyContinue
    $lfConsumers = Get-CimInstance -Namespace root\subscription -ClassName LogFileEventConsumer -ErrorAction SilentlyContinue

    @($filters)      | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'wmi_eventfilters.csv')
    @($bindings)     | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'wmi_bindings.csv')
    @($cmdConsumers) | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'wmi_consumers_cmdline.csv')
    @($asConsumers)  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'wmi_consumers_activescript.csv')
    @($evConsumers)  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'wmi_consumers_eventlog.csv')
    @($lfConsumers)  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'wmi_consumers_logfile.csv')

    $res.Counts.Filters = @($filters).Count
    $res.Counts.Bindings = @($bindings).Count
    $res.Counts.Cmd = @($cmdConsumers).Count
    $res.Counts.ActiveScript = @($asConsumers).Count
    $res.Counts.NTEventLog = @($evConsumers).Count
    $res.Counts.LogFile = @($lfConsumers).Count
  }
  catch {
    Add-Error $res ("wmi: " + $_.Exception.Message)
    $res.Counts = @{
      Filters = 0
      Bindings = 0
      Cmd = 0
      ActiveScript = 0
      NTEventLog = 0
      LogFile = 0
    }
  }

  return $res
}
function Export-Autoruns {
  param([string]$outDir)

  $res = Get-ResultObject 'Autoruns'
  try {
    [void](Ensure-Directory $outDir)

    $targets = @(
      'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
      'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
      'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
      'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    $rows = foreach ($k in $targets) {
      try {
        if (-not (Test-Path -LiteralPath $k)) {
          continue
        }
        $p = Get-ItemProperty -Path $k -ErrorAction Stop
        foreach ($prop in $p.PSObject.Properties) {
          if ($prop.Name -in 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') {
            continue
          }
          [pscustomobject]@{ Key = $k
            Name = $prop.Name
            Value = [string]$prop.Value
          }
        }
      }
      catch {
        Add-Note $res ("autorun read failed: " + $k)
      }
    }

    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'autoruns_runkeys.csv')
    $res.Counts.Items = @($rows).Count
  }
  catch {
    Add-Error $res ("autoruns: " + $_.Exception.Message)
    $res.Counts.Items = 0
  }

  return $res
}

function Add-ArtifactExecActionText {
  param($Parts, $Action, $PropertyNames)
  $a = $Action
  $pnames = $PropertyNames
  $exe = [string]$a.Execute
  $arg = $null
  if ($pnames -contains 'Arguments') {
    $arg = [string]$a.Arguments
  }

  if ($exe -and $arg) {
    [void]$parts.Add(($exe + ' ' + $arg))
  }
  elseif ($exe) {
    [void]$parts.Add($exe)
  }
  else {
    [void]$parts.Add('[ExecAction]')
  }
}
