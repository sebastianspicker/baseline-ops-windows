#requires -version 5.1
<#
.SYNOPSIS
Generate a v2 script template.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [ValidatePattern('^\d{2}-[A-Za-z0-9-]+$')]
  [string]$Name,

  [string]$Destination = '.\scripts',

  [switch]$SupportsRemediate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Destination -PathType Container)) {
  throw "Destination folder not found: $Destination"
}

$filePath = Join-Path $Destination ("{0}.ps1" -f $Name)
if (Test-Path -LiteralPath $filePath) {
  throw "File already exists: $filePath"
}

$cmdletBinding = if ($SupportsRemediate) {
  '[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = ''High'')]'
} else {
  '[CmdletBinding()]'
}

$modeComment = if ($SupportsRemediate) {
@'
.PARAMETER Mode
Audit or Remediate mode.
'@
} else {
@'
.PARAMETER Mode
Audit mode only.
'@
}

$modeValidateSet = if ($SupportsRemediate) {
  "'Audit','Remediate'"
} else {
  "'Audit'"
}

# New scripts start audit-only so they cannot accidentally expose a remediation
# surface before the author has added explicit ShouldProcess-protected changes.
$modeBody = if ($SupportsRemediate) {
@'
if ($Mode -eq 'Remediate') {
  if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Apply remediation')) {
    # TODO: remediation logic
  }
}
'@
} else {
  ''
}

$template = @"
#requires -version 5.1
<#
.SYNOPSIS
TODO: add synopsis.

.DESCRIPTION
TODO: add description.

$modeComment
.PARAMETER OutputFormat
Console, Json, Csv, or None.

.PARAMETER OutputPath
Path for Json/Csv output.

.PARAMETER PassThru
Emit standardized v2 result object.
#>

$cmdletBinding
param(
  [ValidateSet($modeValidateSet)]
  [string]
  `$Mode = 'Audit',

  [ValidateSet('Console','Json','Csv','None')]
  [string]
  `$OutputFormat = 'Console',

  [string]
  `$OutputPath,

  [switch]
  `$PassThru,

  [switch]
  `$Strict,

  [switch]
  `$Quiet,

  [switch]
  `$NoColor
)

. (Join-Path `$PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path `$script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path `$script:LibPath 'Serialization.psm1') -Force

Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'

$modeBody

`$summary = [pscustomobject]@{
  Script = '$Name.ps1'
  Mode = `$Mode
}

`$result = Get-V2ResultObject -ScriptName '$Name.ps1' -Mode `$Mode -Result 'OK' -Findings @() -Summary `$summary -Metadata @{}

if (-not `$Quiet -and `$OutputFormat -eq 'Console') {
  Write-Section -Title '$Name'
  Write-KeyValue -Key 'Mode' -Value `$Mode
}

Write-ResultObject -ResultObject `$result -OutputFormat `$OutputFormat -OutputPath `$OutputPath
if (`$PassThru) { `$result }
exit 0
"@

Set-Content -LiteralPath $filePath -Value $template -Encoding UTF8
Write-Information -MessageData "Created $filePath" -InformationAction Continue
