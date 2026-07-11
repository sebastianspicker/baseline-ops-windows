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

    function Add-VerifyFile {
      [CmdletBinding()]
      param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$RelativePath
      )

      $path = Join-Path $Root $RelativePath
      $parent = Split-Path -Parent $path
      New-Item -Path $parent -ItemType Directory -Force | Out-Null
      'placeholder' | Set-Content -LiteralPath $path -Encoding UTF8
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

  It 'Allows the internal helper layer and normal public documentation' {
    $root = Join-Path $TestDrive 'verify-public-surface-allowed'
    Get-MinimalVerifyRoot -Path $root
    Add-VerifyFile -Root $root -RelativePath 'scripts/internal/helper.ps1'
    Add-VerifyFile -Root $root -RelativePath 'docs/README.md'
    Add-VerifyFile -Root $root -RelativePath 'docs/launcher-gui.md'
    Add-VerifyFile -Root $root -RelativePath 'SECURITY.md'

    $output = & pwsh -NoProfile -File $script:VerifyTool -RootPath $root -SkipAnalyzer 2>&1
    $exitCode = $LASTEXITCODE
    $text = $output | Out-String

    $exitCode | Should -Be 0
    $text | Should -Match 'PublicSurface.*PASS'
    $text | Should -Match 'VERDICT: PARTIAL'
  }

  It 'rejects unreviewed documentation outside the public allowlist' {
    $root = Join-Path $TestDrive 'verify-doc-allowlist'
    Get-MinimalVerifyRoot -Path $root
    Add-VerifyFile -Root $root -RelativePath 'docs/unreviewed-notes.md'

    $output = & pwsh -NoProfile -File $script:VerifyTool -RootPath $root -SkipAnalyzer 2>&1
    $exitCode = $LASTEXITCODE
    $text = $output | Out-String

    $exitCode | Should -Be 1
    $text | Should -Match 'docs[\\/]unreviewed-notes\.md'
    $text | Should -Match 'public allowlist'
  }

  It 'checks untracked non-ignored files inside a git worktree' {
    if (-not (Get-Command -Name git -ErrorAction SilentlyContinue)) {
      Set-ItResult -Skipped -Because 'git is not available.'
      return
    }
    $root = Join-Path $TestDrive 'verify-untracked-git'
    Get-MinimalVerifyRoot -Path $root
    & git -C $root init --quiet
    & git -C $root add scripts lib
    Add-VerifyFile -Root $root -RelativePath 'private/untracked-note.md'

    $output = & pwsh -NoProfile -File $script:VerifyTool -RootPath $root -SkipAnalyzer 2>&1
    $exitCode = $LASTEXITCODE
    $text = $output | Out-String

    $exitCode | Should -Be 1
    $text | Should -Match 'private[\\/]untracked-note\.md'
  }

  It 'Fails on prohibited public-surface paths without reading their contents' {
    $root = Join-Path $TestDrive 'verify-public-surface-forbidden'
    Get-MinimalVerifyRoot -Path $root
    Add-VerifyFile -Root $root -RelativePath 'scripts/private/helper.ps1'
    Add-VerifyFile -Root $root -RelativePath 'docs/agent/remediation-ledger.md'
    Add-VerifyFile -Root $root -RelativePath '.codex/state.json'
    Add-VerifyFile -Root $root -RelativePath '.github/prompts/review.md'
    Add-VerifyFile -Root $root -RelativePath 'REMEDIATION_PLAN.md'
    Add-VerifyFile -Root $root -RelativePath 'archive/audit.md'
    Add-VerifyFile -Root $root -RelativePath 'credentials/token.txt'
    Add-VerifyFile -Root $root -RelativePath 'config/.env.local'
    Add-VerifyFile -Root $root -RelativePath 'certificates/signing.pem'

    $output = & pwsh -NoProfile -File $script:VerifyTool -RootPath $root -SkipAnalyzer 2>&1
    $exitCode = $LASTEXITCODE
    $text = $output | Out-String

    $exitCode | Should -Be 1
    $text | Should -Match 'PublicSurface.*FAILED'
    $text | Should -Match 'scripts[\\/]private[\\/]helper\.ps1'
    $text | Should -Match 'docs[\\/]agent[\\/]remediation-ledger\.md'
    $text | Should -Match '\.codex[\\/]state\.json'
    $text | Should -Match '\.github[\\/]prompts[\\/]review\.md'
    $text | Should -Match 'REMEDIATION_PLAN.md'
    $text | Should -Match 'VERDICT: FAILED'
  }

  It 'Parses PowerShell modules under tools' {
    $root = Join-Path $TestDrive 'verify-tool-module'
    Get-MinimalVerifyRoot -Path $root
    $toolsDir = Join-Path $root 'tools'
    New-Item -Path $toolsDir -ItemType Directory -Force | Out-Null
    'function Broken-ToolModule {' | Set-Content -LiteralPath (Join-Path $toolsDir 'Broken.psm1') -Encoding UTF8

    $output = & pwsh -NoProfile -File $script:VerifyTool -RootPath $root -SkipAnalyzer 2>&1
    $exitCode = $LASTEXITCODE
    $text = $output | Out-String

    $exitCode | Should -Be 1
    $text | Should -Match 'Parse.*FAILED'
    $text | Should -Match 'Broken\.psm1'
  }
}
