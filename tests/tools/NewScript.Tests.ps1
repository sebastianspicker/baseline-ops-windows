#requires -version 5.1

[CmdletBinding()]
param()

Describe 'tools/new-script.ps1' {
  BeforeAll {
    $script:ToolPath = Join-Path $PSScriptRoot '../../tools/new-script.ps1'
  }

  It 'generates an audit-only template by default' {
    & $script:ToolPath -Name '99-TestTemplate' -Destination $TestDrive

    $generated = Join-Path $TestDrive '99-TestTemplate.ps1'
    Test-Path -LiteralPath $generated | Should -BeTrue
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($generated, [ref]$tokens, [ref]$errors) | Out-Null
    $errors | Should -BeNullOrEmpty

    $content = Get-Content -LiteralPath $generated -Raw
    $content | Should -Match "\[ValidateSet\('Audit'\)\]"
    $content | Should -Not -Match 'SupportsShouldProcess'
    $content | Should -Not -Match 'Remediate not supported'
    $content | Should -Not -Match '\$Mode -eq ''Remediate'''
    $content | Should -Not -Match 'TODO'
  }

  It 'emits remediation support only when requested' {
    & $script:ToolPath -Name '98-RemediateTemplate' -Destination $TestDrive -SupportsRemediate

    $generated = Join-Path $TestDrive '98-RemediateTemplate.ps1'
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($generated, [ref]$tokens, [ref]$errors) | Out-Null
    $errors | Should -BeNullOrEmpty
    $content = Get-Content -LiteralPath $generated -Raw

    $content | Should -Match "\[ValidateSet\('Audit','Remediate'\)\]"
    $content | Should -Match 'SupportsShouldProcess = \$true'
    $content | Should -Match '\$Mode -eq ''Remediate'''
    $content | Should -Not -Match 'TODO'
    $content | Should -Match "throw 'Remediation logic must be implemented before Remediate mode is used\.'"
  }
}
