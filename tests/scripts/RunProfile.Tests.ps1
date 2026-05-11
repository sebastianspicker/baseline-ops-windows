#requires -version 5.1

Describe '00-Run-Profile dependency and failure flow' {
  It 'Marks dependent step as skipped when dependency fails' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("runprofile-root-{0}" -f [guid]::NewGuid().ToString('N'))
    $scriptsDir = Join-Path $tempRoot 'scripts'
    $profilePath = Join-Path $tempRoot 'profile.json'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Ok.ps1') -Value 'exit 0' -Encoding UTF8
      Set-Content -LiteralPath (Join-Path $scriptsDir '02-Fail.ps1') -Value 'exit 1' -Encoding UTF8
      Set-Content -LiteralPath (Join-Path $scriptsDir '03-Dependent.ps1') -Value 'exit 0' -Encoding UTF8

      $profile = @{
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
      $profile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

      $runner = Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1'
      $result = & $runner -ProfilePath $profilePath -RootPath $tempRoot -OutputFormat None -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 1
      $steps = @($result.Metadata.Steps)
      (@($steps | Where-Object { $_.Status -eq 'Failed' }).Count) | Should -Be 1
      (@($steps | Where-Object { $_.Status -eq 'Skipped' }).Count) | Should -Be 1
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

      $modeScript = @'
param(
  [ValidateSet('Audit','Remediate')]
  [string]$Mode = 'Audit'
)
if ($Mode -eq 'Remediate') { exit 0 }
exit 1
'@
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Needs-Mode.ps1') -Value $modeScript -Encoding UTF8

      $profile = @{
        ProfileName = 'test-profile-mode'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Needs-Mode.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

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
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Ok.ps1') -Value 'exit 0' -Encoding UTF8

      $profile = @{
        ProfileName = 'test-profile-output'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Json'; OutputPath = $outputPath }
        Steps = @(
          @{ Script = '01-Ok.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

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
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Ok.ps1') -Value 'exit 0' -Encoding UTF8

      $profile = @{
        ProfileName = 'test-profile-output-override'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Json'; OutputPath = $outputPath }
        Steps = @(
          @{ Script = '01-Ok.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

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
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Ok.ps1') -Value 'exit 0' -Encoding UTF8

      $profile = @{
        ProfileName = 'test-profile-output-cli'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Ok.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

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

      $scriptContent = @"
param(
  [ValidateSet('Audit','Remediate')]
  [string]`$Mode = 'Audit'
)
Set-Content -LiteralPath '$modePath' -Value `$Mode -Encoding UTF8
exit 0
"@
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Capture-Mode.ps1') -Value $scriptContent -Encoding UTF8

      $profile = @{
        ProfileName = 'test-profile-default-mode'
        Version = '2.0'
        Defaults = @{ Mode = 'Remediate'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Capture-Mode.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

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

      $scriptContent = @'
param(
  [string]$Mode = 'Audit',
  [Parameter(ValueFromRemainingArguments = $true)]
  [object[]]$Remaining
)
if (@($Remaining) -contains 'LEAKED') { exit 1 }
exit 0
'@
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Blocked.ps1') -Value $scriptContent -Encoding UTF8

      $profile = @{
        ProfileName = 'test-profile-blocked'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Blocked.ps1'; Args = @('-RootPath','LEAKED','-ConfigPath','LEAKED','-ExpectedHash','LEAKED'); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

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

      $scriptContent = @"
param(
  [ValidateSet('Audit','Remediate')]
  [string]`$Mode = 'Audit'
)
Set-Content -LiteralPath '$modePath' -Value `$Mode -Encoding UTF8
exit 0
"@
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Mode-Blocked.ps1') -Value $scriptContent -Encoding UTF8

      $profile = @{
        ProfileName = 'test-profile-mode-blocked'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Mode-Blocked.ps1'; Args = @('-Mode','Remediate','-Remediate'); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

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
      Set-Content -LiteralPath (Join-Path $scriptsDir '01-Ok.ps1') -Value 'exit 0' -Encoding UTF8

      $profile = @{
        ProfileName = 'test-profile-confirm'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Ok.ps1'; Args = @('-Confirm:$false','-WhatIf'); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

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

      $profile = @{
        ProfileName = 'test-profile-whatif'
        Version = '2.0'
        Defaults = @{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
        Steps = @(
          @{ Script = '01-Ok.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
        )
        Integrity = @{ RequireSigned = $false; ExpectedHashes = @{} }
      }
      $profile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profilePath -Encoding UTF8

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
