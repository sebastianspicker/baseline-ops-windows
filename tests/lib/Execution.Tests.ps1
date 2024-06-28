#requires -version 5.1

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../lib/Execution.psm1') -Force
}

Describe 'Invoke-WithRetry' {
  It 'Retries and succeeds' {
    $script:attempts = 0
    $result = Invoke-WithRetry -MaxAttempts 3 -DelaySeconds 0 -Action {
      $script:attempts++
      if ($script:attempts -lt 2) { throw 'fail once' }
      'ok'
    }

    $result | Should -Be 'ok'
    $script:attempts | Should -Be 2
  }

  It 'Throws when MaxAttempts is less than 1' {
    { Invoke-WithRetry -MaxAttempts 0 -DelaySeconds 0 -Action { 'nope' } } | Should -Throw '*MaxAttempts*'
  }

  It 'Throws when DelaySeconds is negative' {
    { Invoke-WithRetry -MaxAttempts 1 -DelaySeconds -1 -Action { 'nope' } } | Should -Throw '*DelaySeconds*'
  }

  It 'Throws when all retries are exhausted' {
    { Invoke-WithRetry -MaxAttempts 2 -DelaySeconds 0 -Action { throw 'always fail' } } | Should -Throw 'always fail'
  }

  It 'Returns result on first attempt when action succeeds immediately' {
    $result = Invoke-WithRetry -MaxAttempts 1 -DelaySeconds 0 -Action { 42 }
    $result | Should -Be 42
  }
}

Describe 'Invoke-ScriptWithTiming' {
  It 'Returns success for temp script' {
    $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ("exec-test-{0}.ps1" -f [guid]::NewGuid().ToString('N'))
    try {
      Set-Content -LiteralPath $tempFile -Encoding UTF8 -Value 'Write-Output "hello"'
      $res = Invoke-ScriptWithTiming -ScriptPath $tempFile
      $res.Success | Should -Be $true
      $res.ExitCode | Should -Be 0
      $res.DurationMs | Should -BeGreaterThan -1
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

Describe 'Invoke-NativeProcess' {
  It 'Captures stdout from a simple command' {
    # Use pwsh itself to echo text
    $result = Invoke-NativeProcess -FilePath 'pwsh' -Arguments @('-NoProfile','-Command','Write-Output "hello stdout"')
    $result.Success | Should -Be $true
    $result.ExitCode | Should -Be 0
    $result.StdOut.Trim() | Should -Be 'hello stdout'
  }

  It 'Captures stderr output' {
    $result = Invoke-NativeProcess -FilePath 'pwsh' -Arguments @('-NoProfile','-Command','[Console]::Error.WriteLine("stderr msg")')
    $result.StdErr.Trim() | Should -Be 'stderr msg'
  }

  It 'Handles mixed stdout and stderr without deadlock' {
    # This test verifies the async pipe read fix: both stdout and stderr
    # are read concurrently before WaitForExit to prevent pipe-buffer deadlock.
    $cmd = '[Console]::Out.WriteLine("out1"); [Console]::Error.WriteLine("err1"); [Console]::Out.WriteLine("out2")'
    $result = Invoke-NativeProcess -FilePath 'pwsh' -Arguments @('-NoProfile','-Command',$cmd)
    $result.StdOut | Should -Match 'out1'
    $result.StdOut | Should -Match 'out2'
    $result.StdErr | Should -Match 'err1'
  }

  It 'Reports non-zero exit code' {
    $result = Invoke-NativeProcess -FilePath 'pwsh' -Arguments @('-NoProfile','-Command','exit 42')
    $result.Success | Should -Be $false
    $result.ExitCode | Should -Be 42
  }

  It 'Throws with ThrowOnError on non-zero exit' {
    { Invoke-NativeProcess -FilePath 'pwsh' -Arguments @('-NoProfile','-Command','exit 1') -ThrowOnError } | Should -Throw '*Process failed*'
  }

  It 'Does not throw with ThrowOnError on zero exit' {
    { Invoke-NativeProcess -FilePath 'pwsh' -Arguments @('-NoProfile','-Command','exit 0') -ThrowOnError } | Should -Not -Throw
  }

  It 'Returns result object with expected properties' {
    $result = Invoke-NativeProcess -FilePath 'pwsh' -Arguments @('-NoProfile','-Command','exit 0')
    $result.PSObject.Properties.Name | Should -Contain 'FilePath'
    $result.PSObject.Properties.Name | Should -Contain 'Arguments'
    $result.PSObject.Properties.Name | Should -Contain 'ExitCode'
    $result.PSObject.Properties.Name | Should -Contain 'StdOut'
    $result.PSObject.Properties.Name | Should -Contain 'StdErr'
    $result.PSObject.Properties.Name | Should -Contain 'Success'
  }

  It 'Throws on timeout for long-running process' {
    { Invoke-NativeProcess -FilePath 'pwsh' -Arguments @('-NoProfile','-Command','Start-Sleep -Seconds 30') -TimeoutSeconds 1 } | Should -Throw '*timeout*'
  }
}
