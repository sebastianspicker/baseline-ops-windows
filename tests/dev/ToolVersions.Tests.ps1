#requires -version 5.1
<#
.SYNOPSIS
  Keeps pinned tool versions in GitHub metadata equal to the version manifest.
.DESCRIPTION
  Treats dev/quality/tool-versions.psd1 as the single source of pinned PowerShell,
  Pester, and PSScriptAnalyzer versions, and requires every literal pin in the
  workflows and pull request template to match it.
#>

BeforeAll {
  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
  $script:Manifest = Import-PowerShellDataFile -LiteralPath (Join-Path $repoRoot 'dev/quality/tool-versions.psd1')
  $script:WorkflowRoot = Join-Path $repoRoot '.github/workflows'
  $script:Sources = @(
    Get-ChildItem -LiteralPath $script:WorkflowRoot -File | Where-Object { $_.Extension -in @('.yml', '.yaml') }
    Get-Item -LiteralPath (Join-Path $repoRoot '.github/pull_request_template.md')
  ) | ForEach-Object {
    [pscustomobject]@{ Name = $_.Name; Text = Get-Content -LiteralPath $_.FullName -Raw }
  }

  function Get-PinnedValues {
    param([string[]]$Patterns, [object[]]$Sources)

    foreach ($source in $Sources) {
      foreach ($pattern in $Patterns) {
        foreach ($match in [regex]::Matches($source.Text, $pattern)) {
          [pscustomobject]@{ Source = $source.Name; Value = $match.Groups[1].Value }
        }
      }
    }
  }

  function Get-WorkflowText {
    param([string]$Name)

    return Get-Content -LiteralPath (Join-Path $script:WorkflowRoot $Name) -Raw
  }
}

Describe 'Pinned tool versions' {
  It 'pins every workflow and template <Tool> version to the manifest' -ForEach @(
    @{ Tool = 'PowerShell'; Patterns = @("POWERSHELL_VERSION:\s*'([^']+)'", 'PowerShell v?(\d+\.\d+\.\d+)', 'core-(\d+\.\d+\.\d+)') }
    @{ Tool = 'Pester'; Patterns = @("PESTER_VERSION:\s*'([^']+)'", "Pester -RequiredVersion '?(\d+\.\d+\.\d+)") }
    @{ Tool = 'PSScriptAnalyzer'; Patterns = @("PSSCRIPTANALYZER_VERSION:\s*'([^']+)'", "PSScriptAnalyzer -RequiredVersion '?(\d+\.\d+\.\d+)") }
  ) {
    $expected = [string]$script:Manifest[$Tool]
    $expected | Should -Not -BeNullOrEmpty
    $pins = @(Get-PinnedValues -Patterns $Patterns -Sources $script:Sources)
    $pins.Count | Should -BeGreaterThan 0
    @($pins | Where-Object { $_.Value -cne $expected } | ForEach-Object { '{0}: {1}' -f $_.Source, $_.Value }) |
      Should -BeNullOrEmpty
  }

  It 'declares the pinned runtime and module versions in the <Name> workflow' -ForEach @(
    @{ Name = 'ci.yml' }
    @{ Name = 'release.yml' }
  ) {
    $text = Get-WorkflowText -Name $Name
    foreach ($variable in @('POWERSHELL_VERSION', 'PESTER_VERSION', 'PSSCRIPTANALYZER_VERSION')) {
      $text | Should -Match ("(?m)^\s+{0}:\s*'[^']+'" -f $variable)
    }
  }

  It 'uses one PowerShell Linux archive checksum across workflows' {
    $pattern = "POWERSHELL_LINUX_X64_SHA256:\s*'([0-9a-f]{64})'"
    $ciPins = @([regex]::Matches((Get-WorkflowText -Name 'ci.yml'), $pattern))
    $releasePins = @([regex]::Matches((Get-WorkflowText -Name 'release.yml'), $pattern))
    $ciPins.Count | Should -BeGreaterThan 0
    $releasePins.Count | Should -BeGreaterThan 0
    $workflowSources = @($script:Sources | Where-Object { $_.Name -ne 'pull_request_template.md' })
    $values = @(Get-PinnedValues -Patterns @($pattern) -Sources $workflowSources | ForEach-Object Value | Sort-Object -Unique)
    $values.Count | Should -Be 1
    $values[0] | Should -Be $ciPins[0].Groups[1].Value
  }
}
