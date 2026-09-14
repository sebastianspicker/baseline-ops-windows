<#
.SYNOPSIS
Builds capability-private SMB unsupported-feature failures.

.DESCRIPTION
Preserves warning, finding, and V2 result construction for unavailable SMB
configuration properties while leaving terminal output and exit ownership in
the public capability.
#>

function New-SmbUnsupportedFeatureFailure {
  param(
    [string]$Message,
    [string]$Mode,
    $FindingList
  )

  Write-Warning $Message
  Add-Finding -FindingList $FindingList -Code 'SMB-UnsupportedFeature' -Severity 'Critical' -Message $Message
  $result = Get-V2ResultObject -ScriptName '22-SMB-Encryption-Enforcer.ps1' -Mode $Mode -Result 'FAIL' `
    -Findings (ConvertTo-ObjectArray -InputObject $FindingList) -Summary @{ Error = $Message } -Metadata @{}
  return [pscustomobject]@{ Result = $result; Token = 'FAIL' }
}
