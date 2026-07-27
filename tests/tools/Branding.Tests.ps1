<#
.SYNOPSIS
Verifies the BaselineOps for Windows source-brand contract.

.DESCRIPTION
Prevents legacy product and runtime identifiers from returning outside the
hosted repository URLs that remain unchanged by the source-only rebrand.
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

  It 'keeps legacy identifiers only in unchanged hosted repository coordinates' {
    $oldSlug = ('win' + '-mdm-security-hardening-kit')
    $hostedCoordinate = 'sebastianspicker/' + $oldSlug
    $forbiddenTokens = @(
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
          if ($line.Contains($token) -and -not $line.Contains($hostedCoordinate)) {
            [void]$violations.Add("$relativePath`:$lineNumber contains $token")
          }
        }
      }
    }

    @($violations) | Should -BeNullOrEmpty -Because ($violations -join [Environment]::NewLine)
  }
}
