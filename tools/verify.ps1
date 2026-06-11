#requires -version 5.1

[CmdletBinding()]
param(
  [string]$RootPath = '',
  [switch]$SkipAnalyzer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RootPath)) {
  $scriptPath = $MyInvocation.MyCommand.Path
  if (-not $scriptPath) { $scriptPath = $PSCommandPath }
  if (-not $scriptPath) { $scriptPath = (Get-Location).Path }

  if (Test-Path -LiteralPath $scriptPath -PathType Container) {
    $scriptDir = $scriptPath
  } else {
    $scriptDir = Split-Path -Parent $scriptPath
  }

  $RootPath = (Resolve-Path (Join-Path $scriptDir '..')).Path
}

$bootstrapPath = [System.IO.Path]::Combine($RootPath, 'scripts', '_lib', 'Bootstrap.ps1')
if (-not (Test-Path -LiteralPath $bootstrapPath)) {
  Write-Error "Bootstrap not found: $bootstrapPath"
  exit 1
}
. $bootstrapPath
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force

Write-Section -Title 'verify.ps1 - Static Checks'

$script:GateResults = New-Object System.Collections.Generic.List[object]

function Add-GateResult {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet('PASS','FAILED','SKIPPED')][string]$Status,
    [string]$Detail = ''
  )

  [void]$script:GateResults.Add([pscustomobject]@{
      Name   = $Name
      Status = $Status
      Detail = $Detail
    })
}

function Complete-Verification {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('PASS','FAILED','PARTIAL')][string]$Verdict,
    [Parameter(Mandatory)][int]$ExitCode
  )

  Write-Section -Title 'Verification Gate Summary'
  foreach ($gate in $script:GateResults) {
    Write-UiLine ("{0,-12} {1,-8} {2}" -f $gate.Name, $gate.Status, $gate.Detail)
  }

  switch ($Verdict) {
    'PASS' { Write-Success -Message 'VERDICT: PASS' }
    'PARTIAL' { Write-Warn -Message 'VERDICT: PARTIAL' }
    'FAILED' { Write-ErrorLine -Message 'VERDICT: FAILED' }
  }

  exit $ExitCode
}

if (-not (Test-Path -LiteralPath (Join-Path $RootPath 'scripts'))) {
  Write-ErrorLine -Message "scripts/ folder not found under $RootPath"
  exit 1
}
if (-not (Test-Path -LiteralPath (Join-Path $RootPath 'lib'))) {
  Write-ErrorLine -Message "lib/ folder not found under $RootPath"
  exit 1
}
if (-not (Test-Path -LiteralPath $bootstrapPath)) {
  Write-ErrorLine -Message "scripts/_lib/Bootstrap.ps1 not found under $RootPath"
  exit 1
}

$targets = @()
$targets += Get-ChildItem -Path (Join-Path $RootPath 'scripts') -Filter '*.ps1' -File -Recurse
$targets += Get-ChildItem -Path (Join-Path $RootPath 'lib') -Filter '*.psm1' -File -Recurse
if (Test-Path -LiteralPath (Join-Path $RootPath 'tools')) {
  $targets += Get-ChildItem -Path (Join-Path $RootPath 'tools') -Filter '*.ps1' -File -Recurse
}

Write-Info -Message ("Parsing {0} PowerShell files..." -f $targets.Count)
$parseErrors = @()

foreach ($t in $targets) {
  $tokens = $null
  $errors = $null
  [System.Management.Automation.Language.Parser]::ParseFile($t.FullName, [ref]$tokens, [ref]$errors) | Out-Null
  if ($errors -and $errors.Count -gt 0) {
    foreach ($e in $errors) {
      $parseErrors += [pscustomobject]@{
        File    = $t.FullName
        Message = $e.Message
        Line    = $e.Extent.StartLineNumber
        Column  = $e.Extent.StartColumnNumber
      }
    }
  }
}

if ($parseErrors.Count -gt 0) {
  Write-ErrorLine -Message ("Parse errors: {0}" -f $parseErrors.Count)
  $parseErrors | Sort-Object File,Line,Column | ForEach-Object {
    Write-UiLine ("- {0}:{1}:{2} {3}" -f $_.File, $_.Line, $_.Column, $_.Message) -ForegroundColor Yellow
  }
  Add-GateResult -Name 'Parse' -Status 'FAILED' -Detail ("{0} file(s), {1} parse error(s)" -f $targets.Count, $parseErrors.Count)
  Complete-Verification -Verdict 'FAILED' -ExitCode 1
}

Write-Success -Message 'Parse checks: OK'
Add-GateResult -Name 'Parse' -Status 'PASS' -Detail ("{0} file(s)" -f $targets.Count)

if ($SkipAnalyzer) {
  Write-Warn -Message 'PSScriptAnalyzer: SKIPPED (-SkipAnalyzer)'
  Add-GateResult -Name 'Analyzer' -Status 'SKIPPED' -Detail 'Skipped by explicit -SkipAnalyzer request'
  Complete-Verification -Verdict 'PARTIAL' -ExitCode 0
}

$settingsPath = Join-Path $RootPath 'PSScriptAnalyzerSettings.psd1'
if (-not (Get-Command -Name Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue)) {
  Write-ErrorLine -Message 'Invoke-ScriptAnalyzer not available. Analyzer did not run.'
  Add-GateResult -Name 'Analyzer' -Status 'FAILED' -Detail 'Invoke-ScriptAnalyzer not available'
  Complete-Verification -Verdict 'FAILED' -ExitCode 2
}

if (-not (Test-Path -LiteralPath $settingsPath)) {
  Write-ErrorLine -Message "PSScriptAnalyzer settings not found: $settingsPath"
  Add-GateResult -Name 'Analyzer' -Status 'FAILED' -Detail 'Settings file missing'
  Complete-Verification -Verdict 'FAILED' -ExitCode 2
}

Write-Info -Message 'Running PSScriptAnalyzer...'
$analyzerPaths = @()
foreach ($p in @(
  (Join-Path $RootPath 'scripts'),
  (Join-Path $RootPath 'lib'),
  (Join-Path $RootPath 'tools')
)) {
  if (Test-Path -LiteralPath $p) { $analyzerPaths += $p }
}

$analyzer = @()
foreach ($path in $analyzerPaths) {
  $result = Invoke-ScriptAnalyzer -Path $path -Settings $settingsPath -Recurse -ErrorAction Continue
  if ($result) { $analyzer += $result }
}
if ($analyzer -and $analyzer.Count -gt 0) {
  Write-Warn -Message ("PSScriptAnalyzer reported {0} issue(s)." -f $analyzer.Count)
  $analyzer | Sort-Object ScriptName,Line,Column | ForEach-Object {
    Write-UiLine ("- {0}:{1}:{2} {3} ({4})" -f $_.ScriptName, $_.Line, $_.Column, $_.Message, $_.RuleName) -ForegroundColor Yellow
  }
  Add-GateResult -Name 'Analyzer' -Status 'FAILED' -Detail ("{0} issue(s)" -f $analyzer.Count)
  Complete-Verification -Verdict 'FAILED' -ExitCode 2
}
Write-Success -Message 'PSScriptAnalyzer: OK'
Add-GateResult -Name 'Analyzer' -Status 'PASS' -Detail ("{0} path(s)" -f $analyzerPaths.Count)
Complete-Verification -Verdict 'PASS' -ExitCode 0
