#requires -version 5.1
<#
.SYNOPSIS
Creates terminal Run-Profile failure results.
.DESCRIPTION
Builds the canonical v2 failure object used by profile validation and execution phases.
#>
function New-RunProfileFailureResult {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Options,
    [Parameter(Mandatory)][string]$Code,
    [Parameter(Mandatory)][string]$Message,
    [AllowNull()][object]$ValidationResult
  )

  $failureFindings = [System.Collections.Generic.List[object]]::new()
  [void]$failureFindings.Add([pscustomobject]@{
    Code = $Code
    Severity = 'High'
    Message = $Message
  })
  if ($null -ne $ValidationResult -and (Has-Property -Object $ValidationResult -Name 'Findings')) {
    foreach ($finding in @($ValidationResult.Findings)) {
      [void]$failureFindings.Add($finding)
    }
  }
  return Get-V2ResultObject `
    -ScriptName '00-Run-Profile.ps1' `
    -Mode $Options.Mode `
    -Result 'FAIL' `
    -Findings $failureFindings.ToArray() `
    -Summary ([pscustomobject]@{
      ProfilePath = $Options.ProfilePath
      StepsTotal = 0
      StepsFailed = 1
      StepsPartial = 0
      StepsSkipped = 0
      Error = $Message
    }) `
    -Metadata @{ Validation = $ValidationResult }
}
