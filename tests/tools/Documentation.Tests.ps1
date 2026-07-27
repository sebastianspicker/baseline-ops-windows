#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for repository documentation-tooling contracts.

.DESCRIPTION
Verifies tooling safeguards that protect maintainers and releases.
#>

Describe 'tools/Test-Documentation.ps1' {
  BeforeAll {
    $script:DocumentationTool = Join-Path $PSScriptRoot '../../tools/Test-Documentation.ps1'
    $script:DocumentationToolSource = Get-Content -LiteralPath $script:DocumentationTool -Raw

    function Invoke-DocumentationCheck {
      param(
        [Parameter(Mandatory)][string]$Root,
        [switch]$Discover,
        [string[]]$Files = @('README.md')
      )

      $previousErrorActionPreference = $ErrorActionPreference
      try {
        # Windows PowerShell represents redirected native stderr as ErrorRecord
        # objects. Keep child failures as assertion data in both host editions.
        $ErrorActionPreference = 'Continue'
        $output = if ($Discover) {
          @(& pwsh -NoProfile -File $script:DocumentationTool -RootPath $Root 2>&1)
        } else {
          @(& pwsh -NoProfile -File $script:DocumentationTool -RootPath $Root -Files $Files 2>&1)
        }
        $exitCode = $LASTEXITCODE
      } finally {
        $ErrorActionPreference = $previousErrorActionPreference
      }
      [pscustomobject]@{
        ExitCode = $exitCode
        Output   = (@($output | ForEach-Object { $_.ToString() }) -join "`n")
      }
    }
  }

  It 'uses capture-friendly information output instead of Write-Host' {
    $script:DocumentationToolSource | Should -Not -Match '(?m)^\s*Write-Host\b'
    $script:DocumentationToolSource | Should -Match '\bWrite-Information\b'
  }

  It 'accepts valid local links, images with alt text, and fenced examples' {
    $root = Join-Path $TestDrive 'valid-docs'
    New-Item -Path (Join-Path $root 'docs') -ItemType Directory -Force | Out-Null
    '# Guide' | Set-Content -LiteralPath (Join-Path $root 'docs/guide.md') -Encoding UTF8
    '<svg></svg>' | Set-Content -LiteralPath (Join-Path $root 'docs/proof.svg') -Encoding UTF8
    @'
# Project

[Guide](docs/guide.md)
![Verification summary](docs/proof.svg)
[External](https://example.com/)

```markdown
[Illustrative missing link](missing.md)
```
'@ | Set-Content -LiteralPath (Join-Path $root 'README.md') -Encoding UTF8

    $result = Invoke-DocumentationCheck -Root $root
    $result.ExitCode | Should -Be 0 -Because $result.Output
    $result.Output | Should -Match 'Documentation checks: PASS'
  }

  It 'rejects a missing local target' {
    $root = Join-Path $TestDrive 'missing-target'
    New-Item -Path $root -ItemType Directory -Force | Out-Null
    '[Missing](docs/missing.md)' | Set-Content -LiteralPath (Join-Path $root 'README.md') -Encoding UTF8

    $result = Invoke-DocumentationCheck -Root $root
    $result.ExitCode | Should -Be 1
    $result.Output | Should -Match 'local target does not exist'
  }

  It 'rejects empty image alt text' {
    $root = Join-Path $TestDrive 'empty-alt'
    New-Item -Path $root -ItemType Directory -Force | Out-Null
    '<svg></svg>' | Set-Content -LiteralPath (Join-Path $root 'proof.svg') -Encoding UTF8
    '[![](proof.svg)](README.md)' | Set-Content -LiteralPath (Join-Path $root 'README.md') -Encoding UTF8

    $result = Invoke-DocumentationCheck -Root $root
    $result.ExitCode | Should -Be 1
    $result.Output | Should -Match 'image alt text is empty'
  }

  It 'accepts a PowerShell file with leading synopsis and description help' {
    $root = Join-Path $TestDrive 'documented-powershell'
    New-Item -Path (Join-Path $root 'tools') -ItemType Directory -Force | Out-Null
    @'
<#
.SYNOPSIS
Fixture tool.

.DESCRIPTION
Exercises the documentation contract.
#>
param()
'@ | Set-Content -LiteralPath (Join-Path $root 'tools/documented.ps1') -Encoding UTF8

    $result = Invoke-DocumentationCheck -Root $root -Files 'tools/documented.ps1'
    $result.ExitCode | Should -Be 0 -Because $result.Output
    $result.Output | Should -Match '1 PowerShell files'
  }

  It 'rejects a maintained PowerShell file without leading help' {
    $root = Join-Path $TestDrive 'undocumented-powershell'
    New-Item -Path (Join-Path $root 'scripts') -ItemType Directory -Force | Out-Null
    'param()' | Set-Content -LiteralPath (Join-Path $root 'scripts/undocumented.ps1') -Encoding UTF8

    $result = Invoke-DocumentationCheck -Root $root -Files 'scripts/undocumented.ps1'
    $result.ExitCode | Should -Be 1
    $result.Output | Should -Match 'missing leading comment-based help with \.SYNOPSIS and \.DESCRIPTION'
  }

  It 'accepts supported non-PowerShell source with a purpose comment' {
    $root = Join-Path $TestDrive 'documented-yaml'
    New-Item -Path (Join-Path $root '.github') -ItemType Directory -Force | Out-Null
    @'
# Explains why this workflow metadata exists.
name: fixture
'@ | Set-Content -LiteralPath (Join-Path $root '.github/fixture.yml') -Encoding UTF8

    $result = Invoke-DocumentationCheck -Root $root -Files '.github/fixture.yml'
    $result.ExitCode | Should -Be 0 -Because $result.Output
    $result.Output | Should -Match '1 commented source files'
  }

  It 'rejects supported non-PowerShell source without a purpose comment' {
    $root = Join-Path $TestDrive 'undocumented-javascript'
    New-Item -Path (Join-Path $root 'tests') -ItemType Directory -Force | Out-Null
    'export const fixture = true;' |
      Set-Content -LiteralPath (Join-Path $root 'tests/fixture.mjs') -Encoding UTF8

    $result = Invoke-DocumentationCheck -Root $root -Files 'tests/fixture.mjs'
    $result.ExitCode | Should -Be 1
    $result.Output | Should -Match 'missing a leading purpose comment'
  }

  It 'discovers maintained PowerShell files and ignores unrelated file types' {
    if (-not (Get-Command -Name git -ErrorAction SilentlyContinue)) {
      Set-ItResult -Skipped -Because 'git is required for default documentation discovery.'
      return
    }

    $root = Join-Path $TestDrive 'powershell-discovery'
    New-Item -Path (Join-Path $root 'tools') -ItemType Directory -Force | Out-Null
    'param()' | Set-Content -LiteralPath (Join-Path $root 'tools/undocumented.ps1') -Encoding UTF8
    '{}' | Set-Content -LiteralPath (Join-Path $root 'tools/generated.json') -Encoding UTF8
    & git -C $root init --quiet

    $result = Invoke-DocumentationCheck -Root $root -Discover
    $result.ExitCode | Should -Be 1
    $result.Output | Should -Match 'tools/undocumented\.ps1'
    $result.Output | Should -Not -Match 'generated\.json'
  }

  It 'rejects links that escape the repository root' {
    $root = Join-Path $TestDrive 'escaping-link/repo'
    New-Item -Path $root -ItemType Directory -Force | Out-Null
    'outside' | Set-Content -LiteralPath (Join-Path (Split-Path -Parent $root) 'outside.md') -Encoding UTF8
    '[Outside](../outside.md)' | Set-Content -LiteralPath (Join-Path $root 'README.md') -Encoding UTF8

    $result = Invoke-DocumentationCheck -Root $root
    $result.ExitCode | Should -Be 1
    $result.Output | Should -Match 'link escapes the repository root'
  }

  It 'checks untracked non-ignored Markdown files by default' {
    if (-not (Get-Command -Name git -ErrorAction SilentlyContinue)) {
      Set-ItResult -Skipped -Because 'git is required for default documentation discovery.'
      return
    }

    $root = Join-Path $TestDrive 'untracked-docs'
    New-Item -Path (Join-Path $root 'docs') -ItemType Directory -Force | Out-Null
    '# Project' | Set-Content -LiteralPath (Join-Path $root 'README.md') -Encoding UTF8
    '[Missing](missing.md)' | Set-Content -LiteralPath (Join-Path $root 'docs/untracked.md') -Encoding UTF8
    & git -C $root init --quiet

    $result = Invoke-DocumentationCheck -Root $root -Discover
    $result.ExitCode | Should -Be 1
    $result.Output | Should -Match 'docs/untracked\.md'
    $result.Output | Should -Match 'local target does not exist'
  }

  It 'discovers Markdown files recursively when checking an extracted package without .git metadata' {
    $root = Join-Path $TestDrive 'package-without-git'
    New-Item -Path (Join-Path $root 'docs') -ItemType Directory -Force | Out-Null
    '# Project' | Set-Content -LiteralPath (Join-Path $root 'README.md') -Encoding UTF8
    '[Missing](missing.md)' | Set-Content -LiteralPath (Join-Path $root 'docs/package-guide.md') -Encoding UTF8

    $result = Invoke-DocumentationCheck -Root $root -Discover
    $result.ExitCode | Should -Be 1
    $result.Output | Should -Match 'docs/package-guide\.md'
    $result.Output | Should -Match 'local target does not exist'
  }

  It 'fails loudly when repository Markdown discovery through git fails' {
    $root = Join-Path $TestDrive 'broken-git-discovery'
    New-Item -Path $root -ItemType Directory -Force | Out-Null
    '# Project' | Set-Content -LiteralPath (Join-Path $root 'README.md') -Encoding UTF8
    'not a valid gitdir file' | Set-Content -LiteralPath (Join-Path $root '.git') -Encoding UTF8

    $result = Invoke-DocumentationCheck -Root $root -Discover
    $result.ExitCode | Should -Be 1
    $result.Output | Should -Match 'git ls-files failed\s+while discovering Markdown\s+files'
  }

  It 'rejects a local target reached through a symbolic link when supported' {
    $root = Join-Path $TestDrive 'symlink-target/repo'
    $outside = Join-Path $TestDrive 'symlink-target/outside'
    New-Item -Path $root -ItemType Directory -Force | Out-Null
    New-Item -Path $outside -ItemType Directory -Force | Out-Null
    'outside' | Set-Content -LiteralPath (Join-Path $outside 'guide.md') -Encoding UTF8
    '[Guide](linked/guide.md)' | Set-Content -LiteralPath (Join-Path $root 'README.md') -Encoding UTF8

    try {
      New-Item -Path (Join-Path $root 'linked') -ItemType SymbolicLink -Value $outside -ErrorAction Stop | Out-Null
    } catch {
      Set-ItResult -Skipped -Because "Symbolic links are unavailable: $($_.Exception.Message)"
      return
    }

    $result = Invoke-DocumentationCheck -Root $root
    $result.ExitCode | Should -Be 1
    $result.Output | Should -Match 'local target traverses a symlink or reparse point'
  }
}

Describe 'alpha release privileged-install documentation' {
  BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:RootReadme = Get-Content -LiteralPath (Join-Path $repoRoot 'README.md') -Raw
    $script:AlphaGuide = Get-Content -LiteralPath (Join-Path $repoRoot 'docs/alpha-release.md') -Raw
    $script:LauncherGuide = Get-Content -LiteralPath (Join-Path $repoRoot 'docs/launcher-gui.md') -Raw
  }

  It 'keeps user-owned extraction checks non-privileged and non-operational' {
    $readmePackage = [regex]::Match(
      $script:RootReadme,
      '(?ms)^### Extracted release ZIP\s+(?<body>.*?)(?=^### Full tag checkout)'
    )
    $alphaPackage = [regex]::Match(
      $script:AlphaGuide,
      '(?ms)^### Check the extracted operator package\s+(?<body>.*?)(?=^### Install a protected Windows copy)'
    )

    $readmePackage.Success | Should -BeTrue
    $alphaPackage.Success | Should -BeTrue
    $readmePackage.Groups['body'].Value | Should -Match 'without elevation'
    $alphaPackage.Groups['body'].Value | Should -Match 'without\s+elevation'
    $readmePackage.Groups['body'].Value | Should -Not -Match '00-Run-Profile|Launcher-GUI'
    $alphaPackage.Groups['body'].Value | Should -Not -Match '00-Run-Profile|Launcher-GUI'
  }

  It 'documents a parseable built-in-only protected installation block' {
    $installMatch = [regex]::Match(
      $script:AlphaGuide,
      '(?ms)^### Install a protected Windows copy.*?^```powershell\s*\r?\n(?<body>.*?)^```'
    )
    $installMatch.Success | Should -BeTrue
    $installSource = $installMatch.Groups['body'].Value
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseInput(
      $installSource,
      [ref]$tokens,
      [ref]$parseErrors
    ) | Out-Null

    @($parseErrors).Count | Should -Be 0 -Because (@($parseErrors) -join [Environment]::NewLine)
    $installSource | Should -Match 'GetFolderPath\(\[Environment\+SpecialFolder\]::ProgramFiles\)'
    $installSource | Should -Match 'Join-Path \$ProgramFilesItem\.FullName ''BaselineOpsForWindows-v2\.3\.0-alpha\.1'''
    $installSource | Should -Match 'Refusing existing install root'
    $installSource | Should -Match 'SetAccessRuleProtection\(\$true, \$false\)'
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-32-545')) {
      $installSource | Should -Match ([regex]::Escape($sid))
    }
    $installSource | Should -Not -Match '00-(Copy-Local|Run-Local|Run-Profile)|Launcher-GUI'
  }

  It 'stages and authenticates bytes before extraction and documents the trusted runtime root' {
    $installMatch = [regex]::Match(
      $script:AlphaGuide,
      '(?ms)^### Install a protected Windows copy.*?^```powershell\s*\r?\n(?<body>.*?)^```'
    )
    $installSource = $installMatch.Groups['body'].Value
    $copyIndex = $installSource.IndexOf('Copy-Item -LiteralPath $ZipPath -Destination $StagedZip')
    $hashIndex = $installSource.IndexOf('Get-FileHash -Algorithm SHA256 -LiteralPath $StagedZip')
    $extractIndex = $installSource.IndexOf('Expand-Archive -LiteralPath $StagedZip')

    $copyIndex | Should -BeGreaterOrEqual 0
    $hashIndex | Should -BeGreaterThan $copyIndex
    $extractIndex | Should -BeGreaterThan $hashIndex
    $script:AlphaGuide | Should -Match '(?s)00-Copy-Local\.ps1.*?not a bootstrap'
    $script:RootReadme | Should -Match '(?s)Do not run privileged scripts.*?Downloads extraction'
    $script:LauncherGuide | Should -Match '(?s)Do not start an elevated launcher.*?Downloads\s+extraction'
    $script:LauncherGuide | Should -Match 'GetFolderPath\(\[Environment\+SpecialFolder\]::ProgramFiles\)'
  }
}

Describe 'shipped configuration examples' {
  BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path

    function Read-ExampleConfig {
      param([Parameter(Mandatory)][string]$Name)

      Get-Content -LiteralPath (Join-Path $repoRoot "examples/configs/$Name") -Raw |
        ConvertFrom-Json
    }
  }

  It 'uses the Defender and ASR allow-list contract' {
    $config = Read-ExampleConfig -Name 'asr-defender-allowlist.json'
    @($config.Defender.ExclusionPaths).Count | Should -Be 0
    @($config.Defender.ExclusionProcesses).Count | Should -Be 0
    @($config.Defender.ExclusionExtensions).Count | Should -Be 0
    @($config.ASR.OnlyExclusions).Count | Should -Be 0
    @($config.CFA.AllowedApplications).Count | Should -Be 0
    @($config.CFA.ProtectedFolders).Count | Should -Be 0
  }

  It 'uses the local administrator allow-list contract' {
    $config = Read-ExampleConfig -Name 'local-admins-allowlist.json'
    @($config.LocalAdmins.Allowed).Count | Should -Be 0
    $config.LocalAdmins.PSObject.Properties.Name | Should -Not -Contain 'AllowList'
  }

  It 'uses the firewall catalog contract' {
    $config = Read-ExampleConfig -Name 'firewall-baseline.json'
    @($config.Profiles.PSObject.Properties.Name) | Should -Be @('Domain', 'Private', 'Public')
    @($config.DisableInboundByNameLike).Count | Should -Be 0
    @($config.EnsureRules).Count | Should -Be 0
    $config.PSObject.Properties.Name | Should -Not -Contain 'Rules'
  }

  It 'uses the Windows Update for Business catalog contract' {
    $config = Read-ExampleConfig -Name 'wufb-proofing.json'
    $config.UpdateSource | Should -Be 'WUfB'
    $config.TargetRelease.Enable | Should -BeFalse
    $config.ActiveHours.Enable | Should -BeFalse
    $config.PSObject.Properties.Name | Should -Not -Contain 'UpdateSettings'
  }
}
