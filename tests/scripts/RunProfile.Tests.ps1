#requires -version 5.1

Describe '00-Run-Profile dependency and failure flow' {
  BeforeAll {
  function Get-TestStepScript {
    [CmdletBinding()]
    param(
      [ValidateSet('OK','WARN','FAIL')]
      [string]$Result = 'OK',
      [int]$ExitCode = 0,
      [string]$Body = '',
      [string]$FindingsExpression = '@()',
      [string]$SummaryExpression = '[pscustomobject]@{}',
      [string]$MetadataExpression = '@{}'
    )

    @"
param(
  [ValidateSet('Audit','Remediate')]
  [string]`$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')]
  [string]`$OutputFormat = 'Console',
  [string]`$OutputPath,
  [switch]`$PassThru,
  [switch]`$Strict,
  [switch]`$Quiet,
  [switch]`$NoColor,
  [Parameter(ValueFromRemainingArguments = `$true)]
  [object[]]`$Remaining
)
$Body
if (`$PassThru) {
  [pscustomobject]@{
    SchemaVersion = '2.0'
    ScriptName = Split-Path -Leaf `$PSCommandPath
    Mode = `$Mode
    Result = '$Result'
    Findings = $FindingsExpression
    Summary = $SummaryExpression
    Metadata = $MetadataExpression
  }
}
exit $ExitCode
"@
  }
  }

  It 'Runs a valid profile step that omits optional Args and DependsOn' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-optional-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Ok.ps1') -Value (Get-TestStepScript -Result OK) -Encoding UTF8

      $profileSpec = @{
        ProfileName = 'test-profile-optional'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Ok.ps1'; ContinueOnError = $false }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      $result = & $runner -ProfilePath $profilePath -RootPath $tempRoot -OutputFormat None -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 0
      $result.Result | Should -Be 'OK'
      @($result.Metadata.Steps).Count | Should -Be 1
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Marks dependent step as skipped when dependency fails' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-root-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Ok.ps1') -Value (Get-TestStepScript -Result OK) -Encoding UTF8
      Set-Content -LiteralPath (Join-Path $scriptsDir '02-Fail.ps1') -Value (Get-TestStepScript -Result FAIL -ExitCode 0) -Encoding UTF8
      Set-Content -LiteralPath (Join-Path $scriptsDir '03-Dependent.ps1') -Value (Get-TestStepScript -Result OK) -Encoding UTF8

      $profileSpec = @{
        ProfileName = 'test-profile'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Ok.ps1'; Args = @(); ContinueOnError = $true; DependsOn = @() },
          @{ Script = '02-Fail.ps1'; Args = @(); ContinueOnError = $true; DependsOn = @() },
          @{ Script = '03-Dependent.ps1'; Args = @(); ContinueOnError = $true; DependsOn = @('02-Fail.ps1') }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      $result = & $runner -ProfilePath $profilePath -RootPath $tempRoot -OutputFormat None -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 1
      $steps = @($result.Metadata.Steps)
      (@($steps | Where-Object { $_.Status -eq 'Failed' }).Count) | Should -Be 1
      (@($steps | Where-Object { $_.Status -eq 'Skipped' }).Count) | Should -Be 1
      ($steps | Where-Object { $_.ScriptName -eq '02-Fail.ps1' }).ExitCode | Should -Be 1
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Fails the profile and reports a finding when dependencies form a cycle' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-cycle-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

      Set-Content -LiteralPath (Join-Path $scriptsDir '01-A.ps1') -Value (Get-TestStepScript -Result OK) -Encoding UTF8
      Set-Content -LiteralPath (Join-Path $scriptsDir '02-B.ps1') -Value (Get-TestStepScript -Result OK) -Encoding UTF8

      $profileSpec = @{
        ProfileName = 'test-profile-cycle'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-A.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @('02-B.ps1') },
          @{ Script = '02-B.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @('01-A.ps1') }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      $result = & $runner -ProfilePath $profilePath -RootPath $tempRoot -OutputFormat None -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      $result.Summary.DependencyCycle | Should -BeTrue
      $result.Summary.StepsFailed | Should -Be 1
      $result.Summary.StepsSkipped | Should -Be 2
      $finding = @($result.Findings | Where-Object Code -eq 'Profile-DependencyCycle')[0]
      $finding | Should -Not -BeNullOrEmpty
      $finding.Message | Should -Match '01-A.ps1'
      $finding.Message | Should -Match '02-B.ps1'
      @($result.Metadata.Steps | Where-Object { $_.Message -eq 'Dependency cycle or unresolved dependency.' }).Count | Should -Be 2
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Marks child V2 WARN as partial even when the process exits zero' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-warn-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Warn.ps1') -Value (Get-TestStepScript -Result WARN -ExitCode 0) -Encoding UTF8

      $profileSpec = @{
        ProfileName = 'test-profile-warn'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Warn.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      $result = & $runner -ProfilePath $profilePath -RootPath $tempRoot -OutputFormat None -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 2
      $result.Result | Should -Be 'WARN'
      $step = @($result.Metadata.Steps)[0]
      $step.Status | Should -Be 'Partial'
      $step.ExitCode | Should -Be 2
      $step.ChildResult | Should -Be 'WARN'
      $step.RunnerExitCode | Should -Be 2
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Fails when a child reports OK but exits nonzero' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-mismatch-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-OkBadExit.ps1') -Value (Get-TestStepScript -Result OK -ExitCode 1) -Encoding UTF8

      $profileSpec = @{
        ProfileName = 'test-profile-mismatch'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-OkBadExit.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      $result = & $runner -ProfilePath $profilePath -RootPath $tempRoot -OutputFormat None -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      $step = @($result.Metadata.Steps)[0]
      $step.Status | Should -Be 'Failed'
      $step.ChildResult | Should -Be 'OK'
      $step.RunnerExitCode | Should -Be 0
      $step.Message | Should -Match 'mismatch'
      $finding = @($result.Findings | Where-Object Code -eq 'Profile-ChildResultExitMismatch')[0]
      $finding | Should -Not -BeNullOrEmpty
      $finding.ScriptName | Should -Be '01-OkBadExit.ps1'
      $finding.ExpectedExitCode | Should -Be 0
      $finding.ActualExitCode | Should -Be 1
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Propagates child V2 findings to the profile result' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-finding-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      $findingExpression = "@([pscustomobject]@{ Code = 'CHILD-Fail'; Severity = 'High'; Message = 'child failed' })"
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-FailWithFinding.ps1') -Value (Get-TestStepScript -Result FAIL -ExitCode 0 -FindingsExpression $findingExpression) -Encoding UTF8

      $profileSpec = @{
        ProfileName = 'test-profile-finding'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-FailWithFinding.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      $result = & $runner -ProfilePath $profilePath -RootPath $tempRoot -OutputFormat None -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      $finding = @($result.Findings | Where-Object Code -eq 'CHILD-Fail')[0]
      $finding | Should -Not -BeNullOrEmpty
      $finding.Severity | Should -Be 'High'
      $finding.Message | Should -Be 'child failed'
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Aggregates unsupported-host WARN children as partial rather than success' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-unsupported-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Ok.ps1') -Value (Get-TestStepScript -Result OK) -Encoding UTF8
      Set-Content -LiteralPath (Join-Path $scriptsDir '02-Unsupported.ps1') -Value (Get-TestStepScript -Result WARN -ExitCode 2 -SummaryExpression '[pscustomobject]@{ Supported = $false }' -MetadataExpression '@{ UnsupportedHost = $true }') -Encoding UTF8

      $profileSpec = @{
        ProfileName = 'test-profile-unsupported'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Ok.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() },
          @{ Script = '02-Unsupported.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      $result = & $runner -ProfilePath $profilePath -RootPath $tempRoot -OutputFormat None -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 2
      $result.Result | Should -Be 'WARN'
      $result.Summary.StepsPartial | Should -Be 1
      $unsupportedStep = @($result.Metadata.Steps | Where-Object { $_.ScriptName -eq '02-Unsupported.ps1' })[0]
      $unsupportedStep.Status | Should -Be 'Partial'
      $unsupportedStep.ExitCode | Should -Be 2
      $unsupportedStep.ChildResult | Should -Be 'WARN'
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Fails the profile when child V2 output is malformed even if the process exits zero' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-malformed-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      $badScript = @'
param(
  [switch]$PassThru,
  [ValidateSet('Console','Json','Csv','None')]
  [string]$OutputFormat = 'Console'
)
if ($PassThru) {
  [pscustomobject]@{ Result = 'MAYBE'; ScriptName = '01-Bad.ps1' }
}
exit 0
'@
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Bad.ps1') -Value $badScript -Encoding UTF8

      $profileSpec = @{
        ProfileName = 'test-profile-malformed'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Bad.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      $result = & $runner -ProfilePath $profilePath -RootPath $tempRoot -OutputFormat None -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      $step = @($result.Metadata.Steps)[0]
      $step.Status | Should -Be 'Failed'
      $step.Message | Should -Match 'valid V2 result'
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Fails the profile when a child exits nonzero without a V2 result' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-no-v2-fail-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-PlainFail.ps1') -Value 'exit 1' -Encoding UTF8

      $profileSpec = @{
        ProfileName = 'test-profile-no-v2-fail'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-PlainFail.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      $result = & $runner -ProfilePath $profilePath -RootPath $tempRoot -OutputFormat None -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      @($result.Metadata.Steps)[0].Status | Should -Be 'Failed'
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Passes -Mode Remediate to v2 step scripts when profile run mode is Remediate' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-mode-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

      $modeScript = Get-TestStepScript -Result OK -Body "if (`$Mode -ne 'Remediate') { exit 1 }"
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Needs-Mode.ps1') -Value $modeScript -Encoding UTF8

      $profileSpec = @{
        ProfileName = 'test-profile-mode'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Needs-Mode.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      & $runner -ProfilePath $profilePath -RootPath $tempRoot -Mode Remediate -OutputFormat None -Confirm:$false

      $LASTEXITCODE | Should -Be 0
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Ignores profile output defaults when CLI output parameters are omitted' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-output-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'
    $outputPath = Join-Path $tempRoot 'profile-output.json'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Ok.ps1') -Value (Get-TestStepScript -Result OK) -Encoding UTF8

      $profileSpec = @{
        ProfileName = 'test-profile-output'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Json'; OutputPath = $outputPath }
        Steps = @(
          @{ Script = '01-Ok.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      & $runner -ProfilePath $profilePath -RootPath $tempRoot -Confirm:$false

      $LASTEXITCODE | Should -Be 0
      Test-Path -LiteralPath $outputPath | Should -BeFalse
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Lets CLI output format override profile output defaults' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-output-override-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'
    $outputPath = Join-Path $tempRoot 'profile-output.json'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Ok.ps1') -Value (Get-TestStepScript -Result OK) -Encoding UTF8

      $profileSpec = @{
        ProfileName = 'test-profile-output-override'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Json'; OutputPath = $outputPath }
        Steps = @(
          @{ Script = '01-Ok.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      & $runner -ProfilePath $profilePath -RootPath $tempRoot -OutputFormat None -Confirm:$false

      $LASTEXITCODE | Should -Be 0
      Test-Path -LiteralPath $outputPath | Should -BeFalse
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Writes runner output only when CLI output parameters request it' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-output-cli-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'
    $outputPath = Join-Path $tempRoot 'runner-output.json'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Ok.ps1') -Value (Get-TestStepScript -Result OK) -Encoding UTF8

      $profileSpec = @{
        ProfileName = 'test-profile-output-cli'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Ok.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      & $runner -ProfilePath $profilePath -RootPath $tempRoot -OutputFormat Json -OutputPath $outputPath -Confirm:$false

      $LASTEXITCODE | Should -Be 0
      Test-Path -LiteralPath $outputPath | Should -BeTrue
      $result = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json
      $result.ScriptName | Should -Be '00-Run-Profile.ps1'
      $result.Result | Should -Be 'OK'
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Ignores profile default remediation mode unless CLI requests it' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-default-mode-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'
    $modePath = Join-Path $tempRoot 'mode.txt'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

      $scriptContent = Get-TestStepScript -Result OK -Body "Set-Content -LiteralPath '$modePath' -Value `$Mode -Encoding UTF8"
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Capture-Mode.ps1') -Value $scriptContent -Encoding UTF8

      $profileSpec = @{
        ProfileName = 'test-profile-default-mode'
        Version = '2.0'
        Defaults = @{ Mode = 'Remediate'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Capture-Mode.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      & $runner -ProfilePath $profilePath -RootPath $tempRoot -OutputFormat None -Confirm:$false

      $LASTEXITCODE | Should -Be 0
      (Get-Content -LiteralPath $modePath -Raw).Trim() | Should -Be 'Audit'
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Removes blocked profile step argument tokens and paired values' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-blocked-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

      $scriptContent = Get-TestStepScript -Result OK -Body "if (@(`$Remaining) -contains 'LEAKED') { exit 1 }"
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Blocked.ps1') -Value $scriptContent -Encoding UTF8

      $profileSpec = @{
        ProfileName = 'test-profile-blocked'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Blocked.ps1'; Args = @('-RootPath','LEAKED','-ConfigPath','LEAKED','-ExpectedHash','LEAKED'); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      & $runner -ProfilePath $profilePath -RootPath $tempRoot -OutputFormat None -Confirm:$false

      $LASTEXITCODE | Should -Be 0
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Prevents profile step mode from overriding the profile run mode' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-mode-blocked-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'
    $modePath = Join-Path $tempRoot 'mode.txt'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

      $scriptContent = Get-TestStepScript -Result OK -Body "Set-Content -LiteralPath '$modePath' -Value `$Mode -Encoding UTF8"
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Mode-Blocked.ps1') -Value $scriptContent -Encoding UTF8

      $profileSpec = @{
        ProfileName = 'test-profile-mode-blocked'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Mode-Blocked.ps1'; Args = @('-Mode','Remediate','-Remediate'); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      & $runner -ProfilePath $profilePath -RootPath $tempRoot -Mode Audit -OutputFormat None -Confirm:$false

      $LASTEXITCODE | Should -Be 0
      (Get-Content -LiteralPath $modePath -Raw).Trim() | Should -Be 'Audit'
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Removes profile step confirmation controls before invoking child scripts' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-confirm-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Ok.ps1') -Value (Get-TestStepScript -Result OK) -Encoding UTF8

      $profileSpec = @{
        ProfileName = 'test-profile-confirm'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Ok.ps1'; Args = @('-Confirm:$false','-WhatIf'); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      & $runner -ProfilePath $profilePath -RootPath $tempRoot -OutputFormat None -Confirm:$false

      $LASTEXITCODE | Should -Be 0
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'Exits 0 for profile WhatIf runs when every step is intentionally skipped' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-whatif-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Ok.ps1') -Value 'exit 0' -Encoding UTF8

    $profileSpec = @{
        ProfileName = 'test-profile-whatif'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Ok.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
    $profileSpec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      & $runner -ProfilePath $profilePath -RootPath $tempRoot -OutputFormat None -WhatIf -Confirm:$false

      $LASTEXITCODE | Should -Be 0
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }
}
