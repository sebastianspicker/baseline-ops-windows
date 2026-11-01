<#
.SYNOPSIS
Scheduled task hygiene actions helpers.

.DESCRIPTION
Contains capability-private actions behavior for scheduled task inventory and policy evaluation.
#>
function Get-ScheduledTaskEnabledState {
  param($Task)
  $enabledProperty = Get-PropValue -Object $Task -Name 'Enabled' -Default $null
  if ($null -ne $enabledProperty) { return [bool]$enabledProperty }
  $state = [string](Get-PropValue -Object $Task -Name 'State' -Default '')
  if ($state -eq 'Disabled') { return $false }
  if ($state) { return $true }
  return $null
}

function Enable-TaskIfPresent {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([string]$TaskName,[string]$TaskPath,[switch]$Remediate)
  $TaskPath = Normalize-TaskPath $TaskPath
  $full = "$TaskPath$TaskName"
  try {
    $t = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
    $isEnabled = Get-ScheduledTaskEnabledState -Task $t
    if ($isEnabled -eq $false) {
      if ($Remediate -and $PSCmdlet.ShouldProcess($full,"Enable-ScheduledTask")) {
        Enable-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop | Out-Null
        return [pscustomobject]([ordered]@{ Ok=$true;  Message="Enabled $full" })
      }
      return [pscustomobject]([ordered]@{ Ok=$false; Message="$full disabled" })
    }
    return [pscustomobject]([ordered]@{ Ok=$true; Message=$null })
  } catch {
    return [pscustomobject]([ordered]@{ Ok=$false; Message="$full missing" })
  }
}

function Save-QuarantineTaskXml {
  param([string]$TaskName,[string]$TaskPath,[string]$QuarantineDir,[string]$Full,$CommandContext,$Actions)
  try {
    $xmlObj = Export-TaskXmlObject -TaskName $TaskName -TaskPath $TaskPath
    if (-not $xmlObj) { $Actions.Add("Export failed for $Full (no XML)"); return 'Failed' }
    $safeName = ($Full.TrimStart('\') -replace '[\\/:*?"<>|]','_') + ".xml"
    $outPath  = Join-Path $QuarantineDir $safeName
    if (-not $CommandContext.ShouldProcess($outPath,"Write quarantine XML")) { return 'Declined' }
    [void](Ensure-Directory $QuarantineDir)
    [System.IO.File]::WriteAllText($outPath, $xmlObj.OuterXml, (New-Object System.Text.UTF8Encoding($false)))
    $Actions.Add("Exported $Full -> $outPath")
    return 'Exported'
  } catch {
    $Actions.Add("Export failed for ${TaskPath}${TaskName}: $($_.Exception.Message)")
    return 'Failed'
  }
}

function Quarantine-Task {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([string]$TaskName,[string]$TaskPath,[string]$QuarantineDir,[switch]$Remediate)
  $TaskPath = Normalize-TaskPath $TaskPath
  $full = "$TaskPath$TaskName"
  if (-not $Remediate) {
    return [pscustomobject]([ordered]@{ Ok=$false; Actions=@(); Error="Remediation off" })
  }
  $act = New-Object System.Collections.Generic.List[string]
  $export = Save-QuarantineTaskXml $TaskName $TaskPath $QuarantineDir $full $PSCmdlet $act
  if ($export -eq 'Failed') {
    $act.Add("Disable skipped: no backup for $full")
    return [pscustomobject]([ordered]@{ Ok=$false; Actions=$act.ToArray(); Error=(@($act) -join '; ') })
  }
  if ($export -ne 'Exported') {
    return [pscustomobject]([ordered]@{ Ok=$true; Actions=$act.ToArray(); Error=$null })
  }
  try {
    if ($PSCmdlet.ShouldProcess($full,"Disable-ScheduledTask")) {
      Disable-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop | Out-Null
      $act.Add("Disabled $full")
    }
  } catch {
    $act.Add("Disable failed for ${TaskPath}${TaskName}: $($_.Exception.Message)")
  }
  return [pscustomobject]([ordered]@{ Ok=$true; Actions=$act.ToArray(); Error=$null })
}
