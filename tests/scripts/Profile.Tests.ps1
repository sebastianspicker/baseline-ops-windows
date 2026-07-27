#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

Describe '00-Validate-Profile' {
  BeforeAll {
    $script:ValidateProfileScript = Join-Path $PSScriptRoot '../../scripts/00-Validate-Profile.ps1'

    function Invoke-ProfileValidation {
      [CmdletBinding()]
      param(
        [Parameter(Mandatory)][string]$ProfilePath
      )

      $output = & $script:ValidateProfileScript -ProfilePath $ProfilePath -OutputFormat None -PassThru 2>&1 3>&1 6>&1
      $exitCode = $LASTEXITCODE
      $result = @($output | Where-Object {
          $null -ne $_ -and
          $_.PSObject.Properties.Name -contains 'Result' -and
          $_.PSObject.Properties.Name -contains 'Findings'
        })[-1]

      [pscustomobject]@{
        ExitCode = $exitCode
        Result   = $result
        Text     = ($output | Out-String)
      }
    }
  }

  It 'Validates baseline profile successfully' {
    $profileSpec = (Resolve-Path (Join-Path $PSScriptRoot '../../examples/profiles/baseline-audit.json')).Path

    $run = Invoke-ProfileValidation -ProfilePath $profileSpec

    $run.ExitCode | Should -Be 0
    $run.Result.Result | Should -Be 'OK'
    @($run.Result.Findings).Count | Should -Be 0
  }

  It 'Reports the missing required fields that make a profile invalid' {
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("bad-profile-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      Set-Content -LiteralPath $temp -Encoding UTF8 -Value '{"ProfileName":"bad"}'
      $run = Invoke-ProfileValidation -ProfilePath $temp

      $run.ExitCode | Should -Be 1
      $run.Result.Result | Should -Be 'FAIL'
      @($run.Result.Findings | Where-Object { $_.Code -eq 'PROFILE-MISSING-FIELD' }).Count |
        Should -Be 4
    } finally {
      if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'Reports malformed profile JSON with a structured finding code' {
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("malformed-profile-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      Set-Content -LiteralPath $temp -Encoding UTF8 -Value '{ not json'
      $run = Invoke-ProfileValidation -ProfilePath $temp

      $run.ExitCode | Should -Be 1
      $run.Result.Result | Should -Be 'FAIL'
      @($run.Result.Findings | Where-Object { $_.Code -eq 'PROFILE-INVALID-JSON' }).Count |
        Should -Be 1
    } finally {
      if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'rejects an oversized profile before JSON parsing' {
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("oversized-profile-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      [System.IO.File]::WriteAllBytes($temp, (New-Object byte[] (1048577)))
      $run = Invoke-ProfileValidation -ProfilePath $temp

      $run.ExitCode | Should -Be 1
      $run.Result.Result | Should -Be 'FAIL'
      @($run.Result.Findings | Where-Object { $_.Code -eq 'PROFILE-TOO-LARGE' }).Count | Should -Be 1
    } finally {
      if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'Reports unsafe profile paths with a structured finding code' {
    $unsafePath = (Join-Path ([System.IO.Path]::GetTempPath()) '../unsafe-profile.json')

    $run = Invoke-ProfileValidation -ProfilePath $unsafePath

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    @($run.Result.Findings | Where-Object { $_.Code -eq 'PROFILE-PATH-TRAVERSAL' }).Count |
      Should -Be 1
  }

  It 'Reports duplicate step scripts by code' {
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("dup-profile-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      $profileSpec = @{
        ProfileName = 'dup'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit' }
        Steps = @(
          @{ Script = '01-ASR-Defender-Allowlist.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() },
          @{ Script = '01-ASR-Defender-Allowlist.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temp -Encoding UTF8
      $run = Invoke-ProfileValidation -ProfilePath $temp

      $run.ExitCode | Should -Be 1
      $run.Result.Result | Should -Be 'FAIL'
      @($run.Result.Findings | Where-Object { $_.Code -eq 'PROFILE-STEP-DUPLICATE' }).Count |
        Should -Be 1
    } finally {
      if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'Reports non-string Args values by code' {
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("bad-args-profile-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      $profileSpec = @{
        ProfileName = 'bad-args'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit' }
        Steps = @(
          @{ Script = '01-ASR-Defender-Allowlist.ps1'; Args = @(@{ Value = 1 }); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temp -Encoding UTF8
      $run = Invoke-ProfileValidation -ProfilePath $temp

      $run.ExitCode | Should -Be 1
      $run.Result.Result | Should -Be 'FAIL'
      @($run.Result.Findings | Where-Object { $_.Code -eq 'PROFILE-STEP-ARGS-TYPE' }).Count |
        Should -Be 1
    } finally {
      if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'rejects CatalogPath and Force in profile Args' {
    $temp = Join-Path $TestDrive 'profile-args-catalog-force.json'
    [ordered]@{
      ProfileName = 'untrusted-args'
      Version = '2.0'
      Defaults = [ordered]@{ Mode = 'Audit' }
      Steps = @([ordered]@{ Script = '01-ASR-Defender-Allowlist.ps1'; Args = @('-CatalogPath', 'untrusted.json', '-Force'); ContinueOnError = $false; DependsOn = @() })
      Integrity = [ordered]@{ RequireSigned = $false; ExpectedHashes = [ordered]@{} }
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temp -Encoding UTF8

    $run = Invoke-ProfileValidation -ProfilePath $temp

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    @($run.Result.Findings | Where-Object Code -eq 'PROFILE-STEP-ARGS-NOT-ALLOWED').Count | Should -Be 1
  }

  It 'rejects string values for profile booleans instead of coercing them' {
    $cases = @(
      @{ Name = 'ContinueOnError'; Code = 'PROFILE-STEP-CONTINUE-TYPE'; Mutate = { param($p) $p.Steps[0].ContinueOnError = 'false' } },
      @{ Name = 'Defaults.Strict'; Code = 'PROFILE-DEFAULTS-STRICT-TYPE'; Mutate = { param($p) $p.Defaults.Strict = 'false' } },
      @{ Name = 'Integrity.RequireSigned'; Code = 'PROFILE-INTEGRITY-SIGNED-TYPE'; Mutate = { param($p) $p.Integrity.RequireSigned = 'false' } }
    )

    foreach ($case in $cases) {
      $temp = Join-Path $TestDrive ("bad-boolean-{0}.json" -f $case.Name.Replace('.', '-'))
      $profileSpec = [ordered]@{
        ProfileName = 'bad-boolean'
        Version = '2.0'
        Defaults = [ordered]@{ Mode = 'Audit'; Strict = $false }
        Steps = @([ordered]@{ Script = '01-ASR-Defender-Allowlist.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() })
        Integrity = [ordered]@{ RequireSigned = $false; ExpectedHashes = [ordered]@{} }
      }
      & $case.Mutate $profileSpec
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temp -Encoding UTF8

      $run = Invoke-ProfileValidation -ProfilePath $temp

      $run.ExitCode | Should -Be 1 -Because $case.Name
      @($run.Result.Findings | Where-Object Code -eq $case.Code).Count | Should -Be 1 -Because $case.Name
    }
  }
}
