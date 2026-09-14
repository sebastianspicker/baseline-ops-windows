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

function Quarantine-Task {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([string]$TaskName,[string]$TaskPath,[string]$QuarantineDir,[switch]$Remediate)
  $TaskPath = Normalize-TaskPath $TaskPath
  $full = "$TaskPath$TaskName"
  if (-not $Remediate) {
    return [pscustomobject]([ordered]@{ Ok=$false; Actions=@(); Error="Remediation off" })
  }
  $act = New-Object System.Collections.Generic.List[string]
  try {
    [void](Ensure-Directory $QuarantineDir)
    $xmlObj = Export-TaskXmlObject -TaskName $TaskName -TaskPath $TaskPath
    if ($xmlObj) {
      $safeName = ($full.TrimStart('\') -replace '[\\/:*?"<>|]','_') + ".xml"
      $outPath  = Join-Path $QuarantineDir $safeName
      $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
      if ($PSCmdlet.ShouldProcess($outPath,"Write quarantine XML")) {
        [System.IO.File]::WriteAllText($outPath, $xmlObj.OuterXml, $utf8NoBom)
      }
      $act.Add("Exported $full -> $outPath")
    } else {
      $act.Add("Export failed for $full (no XML)")
    }
  } catch {
    $act.Add("Export failed for ${TaskPath}${TaskName}: $($_.Exception.Message)")
  }
  try {
    if ($PSCmdlet.ShouldProcess($full,"Disable-ScheduledTask")) {
      Disable-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop | Out-Null
    }
    $act.Add("Disabled $full")
  } catch {
    $act.Add("Disable failed for ${TaskPath}${TaskName}: $($_.Exception.Message)")
  }
  return [pscustomobject]([ordered]@{ Ok=$true; Actions=$act.ToArray(); Error=$null })
}
