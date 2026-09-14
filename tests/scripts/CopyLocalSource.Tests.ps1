#requires -version 5.1
<#
.SYNOPSIS
Verifies deployment source argument validation.
.DESCRIPTION
Exercises option injection, pinned commit, URL, and executable path rejection without acquiring remote content or changing an endpoint.
#>
BeforeAll {
  . (Join-Path $PSScriptRoot '../../scripts/internal/00-Copy-Local.helpers.ps1')
  Import-Module (Join-Path $PSScriptRoot '../../lib/Validation.psm1') -Force
}
Describe 'CopyLocal source validation' {
  It 'rejects option injection before interpreting a commit identifier' {
    $state = New-CopyLocalRunState -Inputs @{ RepoUrl = '-unsafe'; RepoPath = ''; RepoRef = 'branch' }
    { Assert-CopyLocalSourceArguments -RunState $state } | Should -Throw '*RepoUrl*'
  }
  It 'rejects branch names and preserves the authenticated full commit' {
    $state = New-CopyLocalRunState -Inputs @{ RepoUrl = 'https://example.test/repo'; RepoPath = ''; RepoRef = 'main' }
    { Assert-CopyLocalSourceArguments -RunState $state } | Should -Throw '*full 40- or 64-character*'
    $state.RepoRef = 'a' * 40
    { Assert-CopyLocalSourceArguments -RunState $state } | Should -Not -Throw
    $state.RepoRef | Should -Be ('a' * 40)
  }
  It 'rejects credentials and non-HTTPS repository URLs' {
    foreach ($url in @('https://user:password@example.test/repo', 'file:///tmp/repo', 'http://example.test/repo')) {
      { Assert-CopyLocalRepositoryUrl -RunState @{ RepoUrl = $url } } | Should -Throw '*absolute HTTPS*'
    }
  }
  It 'rejects an explicit relative executable path' {
    { Get-CopyLocalGitCandidate -GitPath './git' } | Should -Throw 'GitPath must be absolute.'
  }
}
