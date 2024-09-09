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
  Write-Host "ERROR: Bootstrap not found: $bootstrapPath" -ForegroundColor Red
  exit 1
}
. $bootstrapPath
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force

Write-Section -Title 'verify.ps1 - Static Checks'

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
  exit 1
}

Write-Success -Message 'Parse checks: OK'

if (-not $SkipAnalyzer) {
  $settingsPath = Join-Path $RootPath 'PSScriptAnalyzerSettings.psd1'
  if (Get-Command -Name Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue) {
    if (Test-Path -LiteralPath $settingsPath) {
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
        exit 2
      }
      Write-Success -Message 'PSScriptAnalyzer: OK'
    } else {
      Write-Warn -Message "PSScriptAnalyzer settings not found: $settingsPath"
    }
  } else {
    Write-Warn -Message 'Invoke-ScriptAnalyzer not available. Skipping analyzer.'
  }
}

Write-Success -Message 'verify.ps1 completed successfully'
