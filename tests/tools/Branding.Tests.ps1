<#
.SYNOPSIS
Verifies the BaselineOps for Windows source-brand contract.

.DESCRIPTION
Prevents legacy product, runtime, and repository identifiers from returning.
#>

BeforeAll {
  $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

Describe 'BaselineOps for Windows branding' {
  It 'uses the canonical public and package identities' {
    (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'README.md') -TotalCount 1) |
      Should -Be '# BaselineOps for Windows'

    $package = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'package.json') -Raw |
      ConvertFrom-Json
    $package.name | Should -Be 'baselineops-windows'
    $package.version | Should -Be '0.0.0'

    $releaseWorkflow = Get-Content -LiteralPath (
      Join-Path $script:RepoRoot '.github/workflows/release.yml'
    ) -Raw
    $releaseWorkflow | Should -Match 'asset="baselineops-windows-\$\{tag\}\.zip"'
  }

  It 'rejects legacy identifiers across maintained text' {
    $oldSlug = ('win' + '-mdm-security-hardening-kit')
    $forbiddenTokens = @(
      $oldSlug,
      ('Win' + 'Mdm'),
      ('WIN' + 'MDM'),
      ('WIN' + '_MDM'),
      ('Win' + '-MDM'),
      ('win' + '-mdm'),
      ('Windows MDM Endpoint Security ' + 'Hardening Kit'),
      ('Windows MDM Security ' + 'Hardening Kit')
    )
    $textExtensions = @(
      '.editorconfig', '.json', '.js', '.md', '.mjs', '.ps1', '.psd1', '.psm1',
      '.sh', '.yaml', '.yml'
    )
    $git = Get-Command -Name git -ErrorAction Stop
    $files = @(& $git.Source -C $script:RepoRoot ls-files --cached --others --exclude-standard)
    $LASTEXITCODE | Should -Be 0

    $violations = New-Object System.Collections.Generic.List[string]
    foreach ($relativePath in $files) {
      $fileName = [System.IO.Path]::GetFileName($relativePath)
      $extension = [System.IO.Path]::GetExtension($relativePath).ToLowerInvariant()
      if ($extension -notin $textExtensions -and $fileName -ne 'Dockerfile') {
        continue
      }

      $path = Join-Path $script:RepoRoot $relativePath
      if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
      $lineNumber = 0
      foreach ($line in Get-Content -LiteralPath $path -Encoding UTF8) {
        $lineNumber++
        foreach ($token in $forbiddenTokens) {
          if ($line.Contains($token)) {
            [void]$violations.Add("$relativePath`:$lineNumber contains $token")
          }
        }
      }
    }

    @($violations) | Should -BeNullOrEmpty -Because ($violations -join [Environment]::NewLine)
  }

  It 'binds bootstrap, provenance, advisory, and fuzz metadata to the canonical repository' {
    $repository = 'sebastianspicker/baseline-ops'
    $copyLocalPath = Join-Path $script:RepoRoot 'scripts/00-Copy-Local.ps1'
    $copyLocal = Get-Content -LiteralPath $copyLocalPath -Raw
    $tokens = $null
    $parseErrors = $null
    $copyLocalAst = [System.Management.Automation.Language.Parser]::ParseFile(
      $copyLocalPath,
      [ref]$tokens,
      [ref]$parseErrors
    )
    @($parseErrors) | Should -BeNullOrEmpty
    $repoUrlParameter = $copyLocalAst.ParamBlock.Parameters |
      Where-Object { $_.Name.VariablePath.UserPath -ceq 'RepoUrl' } |
      Select-Object -First 1
    $repoUrlParameter | Should -Not -BeNullOrEmpty
    $repoUrlParameter.DefaultValue.Value | Should -Be "https://github.com/$repository.git"
    $copyLocal | Should -Match ([regex]::Escape(".\00-Copy-Local.ps1 -RepoUrl https://github.com/$repository.git"))

    $alphaGuide = Get-Content -LiteralPath (
      Join-Path $script:RepoRoot 'docs/alpha-release.md'
    ) -Raw
    $securityPolicy = Get-Content -LiteralPath (
      Join-Path $script:RepoRoot 'SECURITY.md'
    ) -Raw
    $fuzzProject = Get-Content -LiteralPath (
      Join-Path $script:RepoRoot '.clusterfuzzlite/project.yaml'
    ) -Raw
    $issueTemplate = Get-Content -LiteralPath (
      Join-Path $script:RepoRoot '.github/ISSUE_TEMPLATE/config.yml'
    ) -Raw

    $alphaGuide | Should -Match ([regex]::Escape("--repo $repository"))
    $alphaGuide | Should -Match ([regex]::Escape("--signer-workflow github.com/$repository/.github/workflows/release.yml"))
    $securityPolicy | Should -Match ([regex]::Escape("https://github.com/$repository/security/advisories/new"))
    $fuzzProject | Should -Match ([regex]::Escape("homepage: https://github.com/$repository"))
    $issueTemplate | Should -Match ([regex]::Escape("https://github.com/$repository/security/advisories/new"))
    $issueTemplate | Should -Match ([regex]::Escape("https://github.com/$repository/blob/main/SECURITY.md"))
  }
}
