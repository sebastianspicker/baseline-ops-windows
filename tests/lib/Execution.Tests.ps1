#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for library-module contracts.

.DESCRIPTION
Verifies module behavior that security automation depends on.
#>

$script:ExecutionModulePath = Join-Path $PSScriptRoot '../../lib/Execution.psm1'
Import-Module $script:ExecutionModulePath -Force

Describe 'Execution module export surface' {
  It 'Does not export dead process helpers' {
    $exports = (Get-Command -Module Execution).Name

    $exports | Should -Contain 'Convert-ArgumentTokens'
    $exports | Should -Contain 'Invoke-ScriptWithTiming'
    $exports | Should -Not -Contain 'Invoke-WithRetry'
    $exports | Should -Not -Contain 'Invoke-NativeProcess'
  }

  It 'Does not keep private definitions for dead process helpers' {
    $modulePath = Join-Path $PSScriptRoot '../../lib/Execution.psm1'
    $moduleText = Get-Content -LiteralPath $modulePath -Raw -Encoding UTF8

    $moduleText | Should -Not -Match 'function\s+Invoke-WithRetry\b'
    $moduleText | Should -Not -Match 'function\s+Invoke-NativeProcess\b'
  }
}

Describe 'Invoke-ScriptWithTiming' {
  It 'Returns success for temp script' {
    $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ("exec-test-{0}.ps1" -f [guid]::NewGuid().ToString('N'))
    try {
      Set-Content -LiteralPath $tempFile -Encoding UTF8 -Value 'Start-Sleep -Milliseconds 75; Write-Output "hello"'
      $res = Invoke-ScriptWithTiming -ScriptPath $tempFile
      $res.Success | Should -Be $true
      $res.ExitCode | Should -Be 0
      $res.DurationMs | Should -BeGreaterThan 40
    } finally {
      if (Test-Path -LiteralPath $tempFile) { Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'Returns failure when script throws' {
    $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ("exec-fail-{0}.ps1" -f [guid]::NewGuid().ToString('N'))
    try {
      Set-Content -LiteralPath $tempFile -Encoding UTF8 -Value 'throw "intentional failure"'
      $res = Invoke-ScriptWithTiming -ScriptPath $tempFile
      $res.Success | Should -Be $false
      $res.ExitCode | Should -Be 1
      $res.ErrorMessage | Should -Match 'intentional failure'
    } finally {
      if (Test-Path -LiteralPath $tempFile) { Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'Does not clear a pre-existing LASTEXITCODE before invoking a clean script' {
    $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ("exec-preserve-last-{0}.ps1" -f [guid]::NewGuid().ToString('N'))
    $markerFile = Join-Path ([System.IO.Path]::GetTempPath()) ("exec-preserve-last-{0}.txt" -f [guid]::NewGuid().ToString('N'))
    try {
      & pwsh -NoProfile -Command 'exit 37'
      $LASTEXITCODE | Should -Be 37

      Set-Content -LiteralPath $tempFile -Encoding UTF8 -Value "[System.IO.File]::WriteAllText('$markerFile', [string]`$global:LASTEXITCODE)"
      $res = Invoke-ScriptWithTiming -ScriptPath $tempFile

      $res.Success | Should -Be $true
      $res.ExitCode | Should -Be 0
      Get-Content -LiteralPath $markerFile -Raw | Should -Be '37'
    } finally {
      if (Test-Path -LiteralPath $tempFile) { Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue }
      if (Test-Path -LiteralPath $markerFile) { Remove-Item -LiteralPath $markerFile -Force -ErrorAction SilentlyContinue }
      & pwsh -NoProfile -Command 'exit 0'
    }
  }

  It 'Reports a non-zero exit from the invoked script' {
    $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ("exec-exit-{0}.ps1" -f [guid]::NewGuid().ToString('N'))
    try {
      Set-Content -LiteralPath $tempFile -Encoding UTF8 -Value 'exit 42'
      $res = Invoke-ScriptWithTiming -ScriptPath $tempFile
      $res.Success | Should -Be $false
      $res.ExitCode | Should -Be 42
      $LASTEXITCODE | Should -Be 42
    } finally {
      if (Test-Path -LiteralPath $tempFile) { Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue }
      & pwsh -NoProfile -Command 'exit 0'
    }
  }
}

Describe 'Convert-ArgumentTokens' {
  It 'Parses named tokens and values' {
    $parsed = Convert-ArgumentTokens -Arguments @('-Name','bob','-OutputFormat','None')
    $parsed.Named.Name | Should -Be 'bob'
    $parsed.Named.OutputFormat | Should -Be 'None'
    @($parsed.Positional).Count | Should -Be 0
  }

  It 'Parses colon-style boolean values' {
    $parsed = Convert-ArgumentTokens -Arguments @('-Strict:$false','-NoColor:$true')
    $parsed.Named.Strict | Should -Be $false
    $parsed.Named.NoColor | Should -Be $true
  }

  It 'Handles empty arguments array' {
    $parsed = Convert-ArgumentTokens -Arguments @()
    $parsed.Named.Count | Should -Be 0
    @($parsed.Positional).Count | Should -Be 0
  }

  It 'Handles an explicitly null arguments array' {
    $parsed = Convert-ArgumentTokens -Arguments $null
    $parsed.Named.Count | Should -Be 0
    @($parsed.Positional).Count | Should -Be 0
  }

  It 'Captures positional arguments' {
    $parsed = Convert-ArgumentTokens -Arguments @('foo','bar')
    @($parsed.Positional).Count | Should -Be 2
    $parsed.Positional[0] | Should -Be 'foo'
    $parsed.Positional[1] | Should -Be 'bar'
  }

  It 'Treats flag without value as true' {
    $parsed = Convert-ArgumentTokens -Arguments @('-Verbose')
    $parsed.Named.Verbose | Should -Be $true
  }

  It 'Accumulates duplicate named keys into array' {
    $parsed = Convert-ArgumentTokens -Arguments @('-Tag','alpha','-Tag','beta')
    @($parsed.Named.Tag).Count | Should -Be 2
  }
}
