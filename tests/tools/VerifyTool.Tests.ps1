#requires -version 5.1

Describe 'tools/verify.ps1 gate reporting' {
  BeforeAll {
    $script:VerifyTool = Join-Path $PSScriptRoot '../../tools/verify.ps1'

    function Get-MinimalVerifyRoot {
      [CmdletBinding()]
      param([Parameter(Mandatory)][string]$Path)

      $scriptsDir = Join-Path $Path 'scripts'
      $bootstrapDir = Join-Path $scriptsDir '_lib'
      $libDir = Join-Path $Path 'lib'

      New-Item -Path $bootstrapDir -ItemType Directory -Force | Out-Null
      New-Item -Path $libDir -ItemType Directory -Force | Out-Null

      @'
$script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:LibPath = Join-Path $script:RepoRoot 'lib'
'@ | Set-Content -LiteralPath (Join-Path $bootstrapDir 'Bootstrap.ps1') -Encoding UTF8

      @'
function Write-Section { param([string]$Title) Write-Host $Title }
function Write-ErrorLine { param([string]$Message) Write-Host "[FAIL] $Message" }
function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" }
function Write-Warn { param([string]$Message) Write-Host "[WARN] $Message" }
function Write-UiLine { param([string]$Message) Write-Host $Message }
'@ | Set-Content -LiteralPath (Join-Path $libDir 'Output.psm1') -Encoding UTF8

      'param()' | Set-Content -LiteralPath (Join-Path $scriptsDir '01-Smoke.ps1') -Encoding UTF8
    }
  }

  It 'Reports explicit analyzer skip as partial verification instead of full success' {
    $root = Join-Path $TestDrive 'verify-skip-analyzer'
    Get-MinimalVerifyRoot -Path $root

    $output = & pwsh -NoProfile -File $script:VerifyTool -RootPath $root -SkipAnalyzer 2>&1
    $exitCode = $LASTEXITCODE
    $text = $output | Out-String

    $exitCode | Should -Be 0
    $text | Should -Match 'Analyzer.*SKIPPED'
    $text | Should -Match 'VERDICT: PARTIAL'
    $text | Should -Not -Match 'completed successfully'
  }

  It 'Fails loud when analyzer prerequisites are missing and analyzer was not explicitly skipped' {
    $root = Join-Path $TestDrive 'verify-missing-analyzer-prereq'
    Get-MinimalVerifyRoot -Path $root

    $output = & pwsh -NoProfile -File $script:VerifyTool -RootPath $root 2>&1
    $exitCode = $LASTEXITCODE
    $text = $output | Out-String

    $exitCode | Should -Be 2
    $text | Should -Match 'Analyzer.*FAILED'
    $text | Should -Match 'VERDICT: FAILED'
    $text | Should -Not -Match 'completed successfully'
  }
}
