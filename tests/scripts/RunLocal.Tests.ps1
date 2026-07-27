#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

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

  It 'Fails captured child V2 OK when the child process exits nonzero' {
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

      $LASTEXITCODE | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      $result.RunnerExitMismatch | Should -BeTrue
      $result.RunnerDeclaredResult | Should -Be 'OK'
      $result.RunnerExpectedExitCode | Should -Be 0
      $result.RunnerActualExitCode | Should -Be 1
      @($result.Findings | Where-Object Code -eq 'RunLocal-ExitContractMismatch') | Should -HaveCount 1
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'fails when a child emits more than one V2 terminal object' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runlocal-v2-multiple-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      $scriptContent = @'
param([switch]$PassThru, [string]$OutputFormat)
if ($PassThru) {
  1..2 | ForEach-Object {
    [pscustomobject]@{ SchemaVersion='2.0'; ScriptName='00-V2-Multiple.ps1'; Mode='Audit'; Result='OK'; Findings=@(); Summary=[pscustomobject]@{}; Metadata=@{} }
  }
}
exit 0
'@
      Set-Content -LiteralPath (Join-Path $scriptsDir '00-V2-Multiple.ps1') -Value $scriptContent -Encoding UTF8
      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'

      $result = & $runner -ScriptName '00-V2-Multiple.ps1' -RootPath $tempRoot -OutputFormat None -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      @($result.Findings | Where-Object Code -eq 'RunLocal-MultipleV2Results') | Should -HaveCount 1
      $result.Summary.Error | Should -Match 'exactly one is required'
    } finally {
      if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'fails one valid V2 result mixed with any additional success-stream output' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runlocal-v2-extraneous-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      $valid = "[pscustomobject]@{ SchemaVersion='2.0'; ScriptName='01-Mixed.ps1'; Mode='Audit'; Result='OK'; Findings=@(); Summary=[pscustomobject]@{}; Metadata=@{} }"
      $malformed = "[pscustomobject]@{ Result='OK' }"
      $variants = [ordered]@{
        '01-ValidString.ps1' = "$valid; 'extra'"
        '02-ValidMalformed.ps1' = "$valid; $malformed"
        '03-MalformedValid.ps1' = "$malformed; $valid"
      }
      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
      foreach ($entry in $variants.GetEnumerator()) {
        $scriptContent = "param([switch]`$PassThru, [string]`$OutputFormat)`nif (`$PassThru) { $($entry.Value) }`nexit 0"
        Set-Content -LiteralPath (Join-Path $scriptsDir $entry.Key) -Value $scriptContent -Encoding UTF8

        $result = & $runner -ScriptName $entry.Key -RootPath $tempRoot -OutputFormat None -PassThru -Confirm:$false

        $LASTEXITCODE | Should -Be 1
        $result.Result | Should -Be 'FAIL'
        @($result.Findings | Where-Object Code -eq 'RunLocal-ExtraneousOutput') | Should -HaveCount 1
      }
    } finally {
      if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'fails malformed result-like output instead of accepting only a Result token' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runlocal-v2-malformed-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      $scriptContent = @'
param([switch]$PassThru, [string]$OutputFormat)
if ($PassThru) { [pscustomobject]@{ Result='OK' } }
exit 0
'@
      Set-Content -LiteralPath (Join-Path $scriptsDir '00-V2-Malformed.ps1') -Value $scriptContent -Encoding UTF8
      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'

      $result = & $runner -ScriptName '00-V2-Malformed.ps1' -RootPath $tempRoot -OutputFormat None -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      @($result.Findings | Where-Object Code -eq 'RunLocal-MissingV2Result') | Should -HaveCount 1
    } finally {
      if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
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
      $result = & $runner -ScriptName '00-WhatIf.ps1' -RootPath $tempRoot -OutputFormat None -PassThru -WhatIf

      $LASTEXITCODE | Should -Be 2
      $result.Result | Should -Be 'WARN'
      $result.Summary.Executed | Should -BeFalse
      (Test-Path -LiteralPath $markerPath) | Should -BeFalse
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'promotes WhatIf WARN to FAIL when Strict is requested' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runlocal-strict-whatif-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      Set-Content -LiteralPath (Join-Path $scriptsDir '00-Strict-WhatIf.ps1') -Value 'exit 0' -Encoding UTF8
      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
      $result = & $runner -ScriptName '00-Strict-WhatIf.ps1' -RootPath $tempRoot -OutputFormat None -PassThru -Strict -WhatIf

      $LASTEXITCODE | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      $result.Summary.Executed | Should -BeFalse
    } finally {
      if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'forwards runner v2 controls unless ScriptArgs explicitly owns them' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runlocal-v2-controls-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      $target = @'
param(
  [ValidateSet('Audit','Remediate')][string]$Mode,
  [string]$ConfigPath,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor,
  [switch]$PassThru,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat
)
if ($PassThru) {
  [pscustomobject]@{ SchemaVersion='2.0'; ScriptName='00-V2-Controls.ps1'; Mode=$Mode; Result='OK'; Findings=@(); Summary=[pscustomobject]@{ ConfigPath=$ConfigPath; Strict=[bool]$Strict; Quiet=[bool]$Quiet; NoColor=[bool]$NoColor; OutputFormat=$OutputFormat }; Metadata=@{} }
}
exit 0
'@
      Set-Content -LiteralPath (Join-Path $scriptsDir '00-V2-Controls.ps1') -Value $target -Encoding UTF8
      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
      $result = & $runner -ScriptName '00-V2-Controls.ps1' -RootPath $tempRoot -Mode Remediate -ConfigPath 'runner.json' -Strict -Quiet -NoColor -OutputFormat None -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 0
      $result.Mode | Should -Be 'Remediate'
      $result.Summary.ConfigPath | Should -Be 'runner.json'
      $result.Summary.Strict | Should -BeTrue
      $result.Summary.Quiet | Should -BeTrue
      $result.Summary.NoColor | Should -BeTrue
      $result.Summary.OutputFormat | Should -Be 'None'

      $override = & $runner -ScriptName '00-V2-Controls.ps1' -RootPath $tempRoot -Mode Remediate -ConfigPath 'runner.json' -Strict -Quiet -NoColor -OutputFormat None -PassThru -ScriptArgs @('-Mode','Audit','-ConfigPath','child.json','-Strict:$false','-Quiet:$false','-NoColor:$false') -Confirm:$false
      $override.Mode | Should -Be 'Audit'
      $override.Summary.ConfigPath | Should -Be 'child.json'
      $override.Summary.Strict | Should -BeFalse
      $override.Summary.Quiet | Should -BeFalse
      $override.Summary.NoColor | Should -BeFalse
    } finally {
      if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'preserves target defaults when ScriptArgs is omitted' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runlocal-default-args-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      $target = @'
param(
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateRange(1,10)][int]$HoursBack = 2,
  [switch]$PassThru,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console'
)
if ($PassThru) {
  [pscustomobject]@{ SchemaVersion='2.0'; ScriptName='00-V2-Defaults.ps1'; Mode=$Mode; Result='OK'; Findings=@(); Summary=[pscustomobject]@{ HoursBack=$HoursBack }; Metadata=@{} }
}
exit 0
'@
      Set-Content -LiteralPath (Join-Path $scriptsDir '00-V2-Defaults.ps1') -Value $target -Encoding UTF8
      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'

      $result = & $runner -ScriptName '00-V2-Defaults.ps1' -RootPath $tempRoot -Mode Audit -OutputFormat None -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 0
      $result.Result | Should -Be 'OK'
      $result.Summary.HoursBack | Should -Be 2
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'accepts one V2 result from a child that records a finding' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runlocal-finding-output-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      $resultsModulePath = (Resolve-Path (Join-Path $PSScriptRoot '../../lib/Results.psm1')).Path.Replace("'", "''")
      $target = @'
param(
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [switch]$PassThru,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console'
)
Import-Module '__RESULTS_MODULE__' -Force
$findings = Get-FindingsList
Add-Finding -FindingList $findings -Code 'CHILD-001' -Severity 'Info' -Message 'Child finding'
if ($PassThru) {
  [pscustomobject]@{ SchemaVersion='2.0'; ScriptName='00-V2-Finding.ps1'; Mode=$Mode; Result='OK'; Findings=@($findings); Summary=[pscustomobject]@{}; Metadata=@{} }
}
exit 0
'@.Replace('__RESULTS_MODULE__', $resultsModulePath)
      Set-Content -LiteralPath (Join-Path $scriptsDir '00-V2-Finding.ps1') -Value $target -Encoding UTF8
      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'

      $result = & $runner -ScriptName '00-V2-Finding.ps1' -RootPath $tempRoot -Mode Audit -OutputFormat None -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 0
      $result.Result | Should -Be 'OK'
      @($result.Findings).Count | Should -Be 1
      $result.Findings[0].Code | Should -Be 'CHILD-001'
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
    $result = & $runner -ScriptName '27-Defender-Health-Audit.ps1' -OutputFormat None -PassThru -WhatIf
    $LASTEXITCODE | Should -Be 2
    $result.Result | Should -Be 'WARN'
  }

  It 'Returns a V2 FAIL result for unsafe script names when PassThru is requested' {
    $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
    $result = & $runner -ScriptName '../escape.ps1' -RootPath (Join-Path $PSScriptRoot '../..') -OutputFormat None -PassThru -Confirm:$false

    $LASTEXITCODE | Should -Be 1
    $result.ScriptName | Should -Be '00-Run-Local.ps1'
    $result.Result | Should -Be 'FAIL'
    @($result.Findings | Where-Object Code -eq 'RunLocal-UnsafeScriptName').Count | Should -Be 1
  }

  It 'Rejects direct self-execution before recursion can begin' {
    $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path

    $result = & $runner `
      -ScriptName '00-Run-Local.ps1' `
      -ScriptArgs @('-ScriptName', '00-Run-Local.ps1') `
      -RootPath $repoRoot `
      -OutputFormat None `
      -PassThru `
      -Confirm:$false

    $LASTEXITCODE | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    @($result.Findings | Where-Object Code -eq 'RunLocal-ControlPlaneRecursion').Count | Should -Be 1
  }

  It 'keeps a deny-write/delete handle from verification through target invocation' {
    $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
    $source = Get-Content -LiteralPath $runner -Raw

    $source | Should -Match 'System\.IO\.FileStream\(\$scriptPath, \[System\.IO\.FileMode\]::Open, \[System\.IO\.FileAccess\]::Read, \[System\.IO\.FileShare\]::Read\)'
    $source | Should -Match 'Get-FileHash -InputStream \$lockedScriptStream'
    $source | Should -Match 'Test-PathOrAncestorIsReparsePoint'
    $source.IndexOf('$lockedScriptStream = New-Object') | Should -BeLessThan $source.IndexOf('Get-AuthenticodeSignature -FilePath $scriptPath')
    $source.IndexOf('$lockedScriptStream = New-Object') | Should -BeLessThan $source.IndexOf('Invoke-TargetScript -Path $scriptPath')
    $source.IndexOf('Invoke-TargetScript -Path $scriptPath') | Should -BeLessThan $source.LastIndexOf('$lockedScriptStream.Dispose()')
  }

  It 'post-lock validates the selected elevated target and locks its bounded code closure' {
    $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
    $source = Get-Content -LiteralPath $runner -Raw

    $source | Should -Match 'function Add-RunLocalTrustedCodeClosureLocks'
    $source | Should -Match 'Join-Path \$RootPath ''scripts/_lib'''
    $source | Should -Match 'Join-Path \$RootPath ''scripts/internal'''
    $source | Should -Match 'Join-Path \$RootPath ''lib'''
    $source | Should -Match 'Privileged code closure contains a reparse-point (directory|item)'
    $source | Should -Match 'System\.Collections\.Generic\.List\[System\.IO\.FileStream\]'
    $source | Should -Match '\$LockedStreams\.Add\(\$lockedStream\)'
    $source | Should -Match '\[ValidateRange\(1, 8192\)\]\[int\]\$MaximumItems = 4096'
    $source | Should -Match 'EnumerateFileSystemEntries'
    $source | Should -Match 'Privileged code closure exceeds the \$MaximumItems-item safety limit'

    $targetLock = $source.IndexOf('$lockedScriptStream = New-Object')
    $targetAcl = $source.IndexOf('Assert-RunLocalTrustedWindowsAcl -Path $scriptPath')
    $closureLocks = $source.IndexOf('Add-RunLocalTrustedCodeClosureLocks -Roots')
    $invocation = $source.IndexOf('Invoke-TargetScript -Path $scriptPath')
    $targetLock | Should -BeLessThan $targetAcl
    $targetAcl | Should -BeLessThan $closureLocks
    $closureLocks | Should -BeLessThan $invocation
    $invocation | Should -BeLessThan $source.LastIndexOf('$lockedClosureStream.Dispose()')
  }

  It 'documents Windows-only weak target and helper/module ACL rejection coverage' {
    $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
    $source = Get-Content -LiteralPath $runner -Raw

    # Cross-platform source coverage proves the post-lock trust boundary. On
    # Windows an elevated Pester run can exercise it with a Users or
    # Authenticated Users Modify ACE and assert that its marker is never run.
    $source | Should -Match 'untrusted SID'
    $source | Should -Match 'Assert-RunLocalTrustedWindowsAcl -Path \$lockedItem\.FullName'
  }

  It 'validates the privileged bootstrap and deployment ACLs before importing repository code' {
    $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
    $source = Get-Content -LiteralPath $runner -Raw

    $source | Should -Match "'S-1-5-18'"
    $source | Should -Match "'S-1-5-32-544'"
    $source | Should -Match 'GetAccessRules\(\$true, \$true, \[System\.Security\.Principal\.SecurityIdentifier\]\)'
    $source | Should -Match 'PropagationFlags\]::InheritOnly'
    $source | Should -Match 'Privileged execution path grants write/replace rights to an untrusted SID'
    $source.IndexOf('Assert-RunLocalTrustedWindowsAcl -Path $trustedPath') |
      Should -BeLessThan $source.IndexOf(". (Join-Path `$PSScriptRoot '_lib/Bootstrap.ps1')")
  }

  It 'uses checkout fallback only when RootPath was omitted' {
    $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1'
    $source = Get-Content -LiteralPath $runner -Raw

    $source | Should -Match "PSBoundParameters\.ContainsKey\('RootPath'\)"
    $source | Should -Match '-not \$rootPathWasExplicitlyBound'
  }
}
