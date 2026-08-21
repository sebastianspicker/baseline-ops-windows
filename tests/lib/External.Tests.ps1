#requires -version 5.1
<#
.SYNOPSIS
Direct native process-boundary checks.
.DESCRIPTION
Verifies canonical executable resolution, direct argument passing, and rejection before spawn.
#>
Describe 'External native command boundary' -Tag 'Security' {
  BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../lib/External.psm1') -Force
    $script:NativeHost = (Get-Process -Id $PID -ErrorAction Stop).Path
  }

  It 'uses a canonical executable, direct process launch, and exact argument boundaries' {
    $echo = Join-Path $TestDrive 'echo-argv.ps1'
    @'
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Values)
[Console]::Out.Write(([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Values | ConvertTo-Json -Compress)))))
'@ | Set-Content -LiteralPath $echo -Encoding UTF8

    $expected = @('', 'value with spaces', 'quote"value', 'trailing\\')
    $result = Invoke-NativeCommand -Command $script:NativeHost -Arguments (@('-NoProfile', '-File', $echo) + $expected) -CaptureOutput -Quiet
    $result.Success | Should -BeTrue
    $decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($result.Stdout)) | ConvertFrom-Json
    $actual = [string[]]$decoded
    $actual.Count | Should -Be $expected.Count
    for ($index = 0; $index -lt $expected.Count; $index++) {
      $actual[$index] | Should -BeExactly $expected[$index]
    }

    $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../lib/External.psm1') -Raw
    $source | Should -Match 'UseShellExecute = \$false'
    $source | Should -Match 'FileName = \[string\]\$manifest\.Command'
  }

  It 'rejects control-character command text before a process can spawn' {
    { Invoke-NativeCommand -Command "$script:NativeHost`n--version" -Arguments @('--version') -ThrowOnError } |
      Should -Throw '*control characters*'
  }
}
