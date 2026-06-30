#requires -version 5.1

Describe '00-Run-Local argument forwarding' {
  It 'Maps captured child V2 FAIL to a failed local runner exit even when the child exits zero' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runlocal-v2-fail-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

      $scriptContent = @'
param(
  [switch]$PassThru,
  [ValidateSet('Console','Json','Csv','None')]
  [string]$OutputFormat = 'Console'
)
if ($PassThru) {
  [pscustomobject]@{
    SchemaVersion = '2.0'
    ScriptName = '00-V2-Fail.ps1'
    Mode = 'Audit'
    Result = 'FAIL'
    Findings = @()
    Summary = [pscustomobject]@{}
    Metadata = @{}
  }
}
exit 0
'@
      Set-Content -LiteralPath (Join-Path $scriptsDir '00-V2-Fail.ps1') -Value $scriptContent -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
      $result = & $runner -ScriptName '00-V2-Fail.ps1' -RootPath $tempRoot -OutputFormat None -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      $result.RunnerExitMismatch | Should -BeTrue
      $result.RunnerExpectedExitCode | Should -Be 1
      $result.RunnerActualExitCode | Should -Be 0
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Maps captured child V2 WARN to a partial local runner exit even when the child exits zero' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runlocal-v2-warn-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

      $scriptContent = @'
param(
  [switch]$PassThru,
  [ValidateSet('Console','Json','Csv','None')]
  [string]$OutputFormat = 'Console'
)
if ($PassThru) {
  [pscustomobject]@{
    SchemaVersion = '2.0'
    ScriptName = '00-V2-Warn.ps1'
    Mode = 'Audit'
    Result = 'WARN'
    Findings = @()
    Summary = [pscustomobject]@{}
    Metadata = @{}
  }
}
exit 0
'@
      Set-Content -LiteralPath (Join-Path $scriptsDir '00-V2-Warn.ps1') -Value $scriptContent -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
      $result = & $runner -ScriptName '00-V2-Warn.ps1' -RootPath $tempRoot -OutputFormat None -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 2
      $result.Result | Should -Be 'WARN'
      $result.RunnerExitMismatch | Should -BeTrue
      $result.RunnerExpectedExitCode | Should -Be 2
      $result.RunnerActualExitCode | Should -Be 0
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Annotates captured child V2 OK when the child process exits nonzero' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runlocal-v2-ok-bad-exit-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

      $scriptContent = @'
param(
  [switch]$PassThru,
  [ValidateSet('Console','Json','Csv','None')]
  [string]$OutputFormat = 'Console'
)
if ($PassThru) {
  [pscustomobject]@{
    SchemaVersion = '2.0'
    ScriptName = '00-V2-Ok-Bad-Exit.ps1'
    Mode = 'Audit'
    Result = 'OK'
    Findings = @()
    Summary = [pscustomobject]@{}
    Metadata = @{}
  }
}
exit 1
'@
      Set-Content -LiteralPath (Join-Path $scriptsDir '00-V2-Ok-Bad-Exit.ps1') -Value $scriptContent -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
      $result = & $runner -ScriptName '00-V2-Ok-Bad-Exit.ps1' -RootPath $tempRoot -OutputFormat None -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 0
      $result.Result | Should -Be 'OK'
      $result.RunnerExitMismatch | Should -BeTrue
      $result.RunnerExpectedExitCode | Should -Be 0
      $result.RunnerActualExitCode | Should -Be 1
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Forwards named arguments correctly from ScriptArgs array' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runlocal-root-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

      $scriptContent = @'
param(
  [string]$Name,
  [ValidateSet('Console','Json','Csv','None')]
  [string]$OutputFormat = 'Console'
)
if ($Name -eq 'bob' -and $OutputFormat -eq 'None') { exit 0 }
exit 1
'@
      Set-Content -LiteralPath (Join-Path $scriptsDir '00-Dump-Args.ps1') -Value $scriptContent -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
      & $runner -ScriptName '00-Dump-Args.ps1' -RootPath $tempRoot -ScriptArgs @('-Name','bob','-OutputFormat','None') -Confirm:$false
      $LASTEXITCODE | Should -Be 0
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Forwards colon-style boolean argument values' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runlocal-colon-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

      $scriptContent = @'
param(
  [bool]$Strict = $true
)
if ($Strict -eq $false) { exit 0 }
exit 1
'@
      Set-Content -LiteralPath (Join-Path $scriptsDir '00-Colon.ps1') -Value $scriptContent -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
      & $runner -ScriptName '00-Colon.ps1' -RootPath $tempRoot -ScriptArgs @('-Strict:$false') -Confirm:$false
      $LASTEXITCODE | Should -Be 0
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Rejects script symlink that resolves outside scripts root' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runlocal-symlink-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $outsideDir = Join-Path $tempRoot 'scripts2'
    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      New-Item -Path $outsideDir -ItemType Directory -Force | Out-Null
      Set-Content -LiteralPath (Join-Path $outsideDir 'evil.ps1') -Value 'exit 0' -Encoding UTF8

      $linkPath = Join-Path $scriptsDir '01-Link.ps1'
      try {
        New-Item -ItemType SymbolicLink -Path $linkPath -Target (Join-Path $outsideDir 'evil.ps1') -Force -ErrorAction Stop | Out-Null
      } catch {
        Set-ItResult -Skipped -Because 'Symbolic links are not available in this environment.'
        return
      }

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
      { & $runner -ScriptName '01-Link.ps1' -RootPath $tempRoot } | Should -Throw
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Does not execute target script when -WhatIf is used' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runlocal-whatif-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $markerPath = Join-Path $tempRoot 'marker.txt'
    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

      $scriptContent = @"
[System.IO.File]::WriteAllText('$markerPath', 'executed')
exit 0
"@
      Set-Content -LiteralPath (Join-Path $scriptsDir '00-WhatIf.ps1') -Value $scriptContent -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
      & $runner -ScriptName '00-WhatIf.ps1' -RootPath $tempRoot -WhatIf

      $LASTEXITCODE | Should -Be 0
      (Test-Path -LiteralPath $markerPath) | Should -BeFalse
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Rejects weak inline hash algorithms in ExpectedHash' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runlocal-hash-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $markerPath = Join-Path $tempRoot 'marker.txt'
    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

      $scriptPath = Join-Path $scriptsDir '00-Hash.ps1'
      $scriptContent = @"
[System.IO.File]::WriteAllText('$markerPath', 'executed')
exit 0
"@
      Set-Content -LiteralPath $scriptPath -Value $scriptContent -Encoding UTF8
    $md5Hash = '00000000000000000000000000000000'

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
      { & $runner -ScriptName '00-Hash.ps1' -RootPath $tempRoot -ExpectedHash "MD5:$md5Hash" -Confirm:$false } |
        Should -Throw '*Unsupported hash algorithm*'
      Test-Path -LiteralPath $markerPath | Should -BeFalse
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Refuses to run when ExpectedHash does not match the script hash' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runlocal-hash-mismatch-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $markerPath = Join-Path $tempRoot 'marker.txt'
    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

      $scriptPath = Join-Path $scriptsDir '00-HashMismatch.ps1'
      $scriptContent = @"
[System.IO.File]::WriteAllText('$markerPath', 'executed')
exit 0
"@
      Set-Content -LiteralPath $scriptPath -Value $scriptContent -Encoding UTF8

      $realHash = (Get-FileHash -Path $scriptPath -Algorithm SHA256).Hash
      $wrongHash = 'A' * 64
      if ([string]::Equals($realHash, $wrongHash, [System.StringComparison]::OrdinalIgnoreCase)) {
        $wrongHash = 'B' * 64
      }

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
      { & $runner -ScriptName '00-HashMismatch.ps1' -RootPath $tempRoot -ExpectedHash "SHA256:$wrongHash" -Confirm:$false } |
        Should -Throw '*Hash mismatch*'
      Test-Path -LiteralPath $markerPath | Should -BeFalse
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Accepts strong inline hash algorithms in ExpectedHash' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runlocal-strong-hash-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $markerPath = Join-Path $tempRoot 'marker.txt'
    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

      $scriptPath = Join-Path $scriptsDir '00-StrongHash.ps1'
      $scriptContent = @"
[System.IO.File]::WriteAllText('$markerPath', 'executed')
exit 0
"@
      Set-Content -LiteralPath $scriptPath -Value $scriptContent -Encoding UTF8
      $sha256Hash = (Get-FileHash -Path $scriptPath -Algorithm SHA256).Hash

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
      & $runner -ScriptName '00-StrongHash.ps1' -RootPath $tempRoot -ExpectedHash "sha256:$sha256Hash" -Confirm:$false

      $LASTEXITCODE | Should -Be 0
      Test-Path -LiteralPath $markerPath | Should -BeTrue
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Falls back to the repo root when the default Windows root is unavailable' {
    $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
    & $runner -ScriptName '27-Defender-Health-Audit.ps1' -WhatIf
    $LASTEXITCODE | Should -Be 0
  }
}
