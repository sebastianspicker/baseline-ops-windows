#requires -version 5.1

Describe '00-Validate-Profile' {
  It 'Validates baseline profile successfully' {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/00-Validate-Profile.ps1'
    $profile = (Resolve-Path (Join-Path $PSScriptRoot '../../examples/profiles/baseline-audit.json')).Path

    & $scriptPath -ProfilePath $profile -OutputFormat None -PassThru | Out-Null
    $LASTEXITCODE | Should -Be 0
  }

  It 'Fails invalid profile' {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/00-Validate-Profile.ps1'
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("bad-profile-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      Set-Content -LiteralPath $temp -Encoding UTF8 -Value '{"ProfileName":"bad"}'
      & $scriptPath -ProfilePath $temp -OutputFormat None -PassThru | Out-Null
      $LASTEXITCODE | Should -Be 1
    } finally {
      if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'Fails profile with duplicate step scripts' {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/00-Validate-Profile.ps1'
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("dup-profile-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      $profile = @{
        ProfileName = 'dup'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit' }
        Steps = @(
          @{ Script = '01-ASR-Defender-Allowlist.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() },
          @{ Script = '01-ASR-Defender-Allowlist.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temp -Encoding UTF8
      & $scriptPath -ProfilePath $temp -OutputFormat None -PassThru | Out-Null
      $LASTEXITCODE | Should -Be 1
    } finally {
      if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'Fails profile when Args contains non-string values' {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/00-Validate-Profile.ps1'
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("bad-args-profile-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      $profile = @{
        ProfileName = 'bad-args'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit' }
        Steps = @(
          @{ Script = '01-ASR-Defender-Allowlist.ps1'; Args = @(@{ Value = 1 }); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temp -Encoding UTF8
      & $scriptPath -ProfilePath $temp -OutputFormat None -PassThru | Out-Null
      $LASTEXITCODE | Should -Be 1
    } finally {
      if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
  }
}
