#requires -version 5.1

# ---------------------------------------------------------------------------
# Integration tests for orchestration scripts:
#   00-Validate-Profile.ps1
#   00-Run-Batch.ps1
#   00-Report-Aggregate.ps1
# ---------------------------------------------------------------------------

Describe '00-Validate-Profile orchestration' {
  BeforeAll {
    $script:ScriptsRoot = Join-Path $PSScriptRoot '../../scripts'
    $script:ValidateScript = Join-Path $script:ScriptsRoot '00-Validate-Profile.ps1'
    $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "orch-validate-$(Get-Random)"
    New-Item -Path $script:TempDir -ItemType Directory -Force | Out-Null
  }

  AfterAll {
    if (Test-Path $script:TempDir) {
      Remove-Item -Path $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Validates baseline-audit.json example profile successfully' {
    $profileSpec = (Resolve-Path (Join-Path $PSScriptRoot '../../examples/profiles/baseline-audit.json')).Path
    & $script:ValidateScript -ProfilePath $profileSpec -OutputFormat None -PassThru | Out-Null
    $LASTEXITCODE | Should -Be 0
  }

  It 'Validates rapid-triage.json example profile successfully' {
    $profileSpec = (Resolve-Path (Join-Path $PSScriptRoot '../../examples/profiles/rapid-triage.json')).Path
    & $script:ValidateScript -ProfilePath $profileSpec -OutputFormat None -PassThru | Out-Null
    $LASTEXITCODE | Should -Be 0
  }

  It 'Validates hardening-remediate.json example profile successfully' {
    $profileSpec = (Resolve-Path (Join-Path $PSScriptRoot '../../examples/profiles/hardening-remediate.json')).Path
    & $script:ValidateScript -ProfilePath $profileSpec -OutputFormat None -PassThru | Out-Null
    $LASTEXITCODE | Should -Be 0
  }

  It 'Validates full-audit.json example profile successfully' {
    $profileSpec = (Resolve-Path (Join-Path $PSScriptRoot '../../examples/profiles/full-audit.json')).Path
    & $script:ValidateScript -ProfilePath $profileSpec -OutputFormat None -PassThru | Out-Null
    $LASTEXITCODE | Should -Be 0
  }

  It 'Validates endpoint-health-check.json example profile successfully' {
    $profileSpec = (Resolve-Path (Join-Path $PSScriptRoot '../../examples/profiles/endpoint-health-check.json')).Path
    & $script:ValidateScript -ProfilePath $profileSpec -OutputFormat None -PassThru | Out-Null
    $LASTEXITCODE | Should -Be 0
  }

  It 'Validates incident-response.json example profile with DependsOn successfully' {
    $profileSpec = (Resolve-Path (Join-Path $PSScriptRoot '../../examples/profiles/incident-response.json')).Path
    $result = & $script:ValidateScript -ProfilePath $profileSpec -OutputFormat None -PassThru
    $LASTEXITCODE | Should -Be 0
    $result | Should -Not -BeNullOrEmpty
    $result.Result | Should -Be 'OK'
  }

  It 'Validates compliance-full.json example profile successfully' {
    $profileSpec = (Resolve-Path (Join-Path $PSScriptRoot '../../examples/profiles/compliance-full.json')).Path
    & $script:ValidateScript -ProfilePath $profileSpec -OutputFormat None -PassThru | Out-Null
    $LASTEXITCODE | Should -Be 0
  }

  It 'Fails when required fields are missing' {
    $temp = Join-Path $script:TempDir "missing-fields-$(Get-Random).json"
    # Only ProfileName present -- Version, Defaults, Steps, Integrity are missing
    $doc = @{ ProfileName = 'incomplete' }
    $doc | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $temp -Encoding UTF8

    $result = & $script:ValidateScript -ProfilePath $temp -OutputFormat None -PassThru
    $LASTEXITCODE | Should -Be 1
    @($result.Findings | Where-Object { $_.Code -eq 'PROFILE-MISSING-FIELD' }).Count |
      Should -Be 4
  }

  It 'Fails when a step references a non-existent script name pattern' {
    $temp = Join-Path $script:TempDir "bad-script-ref-$(Get-Random).json"
    # This profile is structurally valid but references a script with unsafe chars.
    # The validator checks script name safety, not file existence.
    # So test with an unsafe name (contains path separator).
    $doc = @{
      ProfileName = 'bad-ref'
      Version     = '2.0'
      Defaults    = @{ Mode = 'Audit' }
      Steps       = @(
        @{ Script = '../evil.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
      )
      Integrity   = @{ RequireSigned = $false; ExpectedHashes = @{} }
    }
    $doc | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temp -Encoding UTF8

    $result = & $script:ValidateScript -ProfilePath $temp -OutputFormat None -PassThru
    $LASTEXITCODE | Should -Be 1
    @($result.Findings | Where-Object { $_.Code -eq 'PROFILE-STEP-SCRIPT-NAME' }).Count |
      Should -Be 1
    @($result.Findings | Where-Object { $_.Code -eq 'PROFILE-STEP-SCRIPT-NOT-FOUND' }).Count |
      Should -Be 0
  }

  It 'Fails when a step references a missing but syntactically safe script file' {
    $temp = Join-Path $script:TempDir "missing-script-$(Get-Random).json"
    $doc = @{
      ProfileName = 'missing-script'
      Version     = '2.0'
      Defaults    = @{ Mode = 'Audit' }
      Steps       = @(
        @{ Script = '99-Does-Not-Exist.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @() }
      )
      Integrity   = @{ RequireSigned = $false; ExpectedHashes = @{} }
    }
    $doc | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temp -Encoding UTF8

    $result = & $script:ValidateScript -ProfilePath $temp -OutputFormat None -PassThru
    $LASTEXITCODE | Should -Be 1
    @($result.Findings | Where-Object { $_.Code -eq 'PROFILE-STEP-SCRIPT-NOT-FOUND' }).Count |
      Should -Be 1
  }

  It 'Fails when DependsOn references an unknown script' {
    $temp = Join-Path $script:TempDir "bad-dep-$(Get-Random).json"
    $doc = @{
      ProfileName = 'bad-dep'
      Version     = '2.0'
      Defaults    = @{ Mode = 'Audit' }
      Steps       = @(
        @{ Script = '01-ASR-Defender-Allowlist.ps1'; Args = @(); ContinueOnError = $false; DependsOn = @('99-Does-Not-Exist.ps1') }
      )
      Integrity   = @{ RequireSigned = $false; ExpectedHashes = @{} }
    }
    $doc | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temp -Encoding UTF8

    $result = & $script:ValidateScript -ProfilePath $temp -OutputFormat None -PassThru
    $LASTEXITCODE | Should -Be 1
    @($result.Findings | Where-Object { $_.Code -eq 'PROFILE-STEP-DEPENDS-NOT-FOUND' }).Count |
      Should -Be 1
    @($result.Findings | Where-Object { $_.Code -eq 'PROFILE-STEP-SCRIPT-NOT-FOUND' }).Count |
      Should -Be 0
  }

  It 'Returns PassThru result with correct ScriptName and Result properties' {
    $profileSpec = (Resolve-Path (Join-Path $PSScriptRoot '../../examples/profiles/baseline-audit.json')).Path
    $result = & $script:ValidateScript -ProfilePath $profileSpec -OutputFormat None -PassThru
    $LASTEXITCODE | Should -Be 0
    $result | Should -Not -BeNullOrEmpty
    $result.ScriptName | Should -Be '00-Validate-Profile.ps1'
    $result.Result | Should -Be 'OK'
  }

  It 'Handles empty Steps array without crashing' {
    $temp = Join-Path $script:TempDir "empty-steps-$(Get-Random).json"
    $doc = @{
      ProfileName = 'empty-steps'
      Version     = '2.0'
      Defaults    = @{ Mode = 'Audit' }
      Steps       = @()
      Integrity   = @{ RequireSigned = $false; ExpectedHashes = @{} }
    }
    $doc | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temp -Encoding UTF8

    # Should not crash -- an empty steps array is structurally valid
    & $script:ValidateScript -ProfilePath $temp -OutputFormat None -PassThru | Out-Null
    $LASTEXITCODE | Should -BeIn @(0, 2)
  }

  It 'Fails on profile with invalid Defaults.Mode value' {
    $temp = Join-Path $script:TempDir "bad-mode-$(Get-Random).json"
    $doc = @{
      ProfileName = 'bad-mode'
      Version     = '2.0'
      Defaults    = @{ Mode = 'Invalid' }
      Steps       = @()
      Integrity   = @{ RequireSigned = $false; ExpectedHashes = @{} }
    }
    $doc | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temp -Encoding UTF8

    $result = & $script:ValidateScript -ProfilePath $temp -OutputFormat None -PassThru
    $LASTEXITCODE | Should -Be 1
    @($result.Findings | Where-Object { $_.Code -eq 'PROFILE-DEFAULTS-MODE-VALUE' }).Count |
      Should -Be 1
  }
}


Describe '00-Run-Batch orchestration' {
  BeforeAll {
    $script:ScriptsRoot = Join-Path $PSScriptRoot '../../scripts'
    $script:BatchScript = Join-Path $script:ScriptsRoot '00-Run-Batch.ps1'
    $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "orch-batch-$(Get-Random)"
    New-Item -Path $script:TempDir -ItemType Directory -Force | Out-Null

    function Get-GeneratedBatchProfile {
      param([Parameter(Mandatory)][string]$Category)

      $tempRoot = Join-Path $script:TempDir "batch-profile-$(Get-Random)"
      $tempScripts = Join-Path $tempRoot 'scripts'

      try {
        New-Item -Path $tempScripts -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $tempScripts '_lib') -ItemType Directory -Force | Out-Null
        Copy-Item -LiteralPath $script:BatchScript -Destination (Join-Path $tempScripts '00-Run-Batch.ps1') -Force
        Copy-Item -LiteralPath (Join-Path $script:ScriptsRoot '_lib/Bootstrap.ps1') -Destination (Join-Path $tempScripts '_lib/Bootstrap.ps1') -Force

        $fakeRunProfile = @'
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory)]
  [string]$ProfilePath,
  [ValidateSet('Audit','Remediate')]
  [string]$Mode = 'Audit',
  [string]$RootPath,
  [ValidateSet('Console','Json','Csv','None')]
  [string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$Strict,
  [switch]$RequireSigned,
  [switch]$PassThru
)

if ($PassThru) {
  Get-Content -LiteralPath $ProfilePath -Raw | ConvertFrom-Json
}
exit 0
'@
        Set-Content -LiteralPath (Join-Path $tempScripts '00-Run-Profile.ps1') -Value $fakeRunProfile -Encoding UTF8

        Get-ChildItem -LiteralPath $script:ScriptsRoot -Filter '*.ps1' -File |
          Where-Object { $_.Name -match '^\d{2}-' -and $_.Name -notin @('00-Run-Batch.ps1','00-Run-Profile.ps1') } |
          ForEach-Object {
            Set-Content -LiteralPath (Join-Path $tempScripts $_.Name) -Value '# placeholder' -Encoding UTF8
          }

        $tempBatchScript = Join-Path $tempScripts '00-Run-Batch.ps1'
        $profileSpec = & $tempBatchScript -Category $Category -OutputFormat None -RootPath $tempRoot -PassThru -Confirm:$false
        $LASTEXITCODE | Should -Be 0
        $profileSpec | Should -Not -BeNullOrEmpty
        return $profileSpec
      } finally {
        if (Test-Path -LiteralPath $tempRoot) {
          Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
      }
    }
  }

  AfterAll {
    if (Test-Path $script:TempDir) {
      Remove-Item -Path $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Runs with -Category Audit and -OutputFormat None using -WhatIf without crashing' {
    # Use -WhatIf to avoid actually executing target scripts, which may require
    # Windows-specific cmdlets. The point is that the batch orchestrator
    # assembles a valid temp profile and invokes Run-Profile without error.
    & $script:BatchScript -Category Audit -OutputFormat None -RootPath (Split-Path $script:ScriptsRoot -Parent) -WhatIf
    # WhatIf causes ShouldProcess to deny and exit 0
    $LASTEXITCODE | Should -Be 0
  }

  It 'Builds a valid batch profile for the Audit category' {
    # Run with -WhatIf so no scripts are actually executed
    & $script:BatchScript -Category Audit -OutputFormat None -RootPath (Split-Path $script:ScriptsRoot -Parent) -WhatIf
    $LASTEXITCODE | Should -Be 0
  }

  It 'Includes all documented late-number audit scripts in the generated Audit batch profile' {
    $profileSpec = Get-GeneratedBatchProfile -Category Audit
    $scripts = @($profileSpec.Steps | ForEach-Object { $_.Script })

    $scripts | Should -Contain '46-SecureBoot-UEFI-Audit.ps1'
    $scripts | Should -Contain '47-WDAG-Readiness-Audit.ps1'
    $scripts | Should -Contain '48-ExploitProtection-Audit.ps1'
    $scripts | Should -Contain '49-DriverSigning-Integrity-Audit.ps1'
    $scripts | Should -Contain '50-AMSI-Audit.ps1'
    $scripts | Should -Contain '51-AppLocker-Audit.ps1'
    $scripts | Should -Contain '52-DoH-Audit.ps1'
  }

  It 'Handles Remediation category with -WhatIf without crashing' {
    & $script:BatchScript -Category Remediation -OutputFormat None -RootPath (Split-Path $script:ScriptsRoot -Parent) -WhatIf
    $LASTEXITCODE | Should -Be 0
  }

  It 'Propagates unsupported-host WARN children through batch orchestration' {
    $tempRoot = Join-Path $script:TempDir "unsupported-batch-$(Get-Random)"
    $scriptsDir = Join-Path $tempRoot 'scripts'

    try {
      New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
      $unsupportedScript = @'
param(
  [ValidateSet('Audit','Remediate')]
  [string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')]
  [string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)
if ($PassThru) {
  [pscustomobject]@{
    SchemaVersion = '2.0'
    ScriptName = '09-SupportBundle.ps1'
    Mode = $Mode
    Result = 'WARN'
    Findings = @()
    Summary = [pscustomobject]@{ Supported = $false }
    Metadata = @{ UnsupportedHost = $true }
  }
}
exit 2
'@
      Set-Content -LiteralPath (Join-Path $scriptsDir '09-SupportBundle.ps1') -Value $unsupportedScript -Encoding UTF8

      $result = & $script:BatchScript -Category Collection -OutputFormat None -RootPath $tempRoot -PassThru -Confirm:$false

      $LASTEXITCODE | Should -Be 2
      $result.Result | Should -Be 'WARN'
      $step = @($result.Metadata.Steps)[0]
      $step.ScriptName | Should -Be '09-SupportBundle.ps1'
      $step.Status | Should -Be 'Partial'
      $step.ChildResult | Should -Be 'WARN'
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }
}


Describe '00-Report-Aggregate orchestration' {
  BeforeAll {
    $script:ScriptsRoot = Join-Path $PSScriptRoot '../../scripts'
    $script:AggregateScript = Join-Path $script:ScriptsRoot '00-Report-Aggregate.ps1'
    $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "orch-aggregate-$(Get-Random)"
    New-Item -Path $script:TempDir -ItemType Directory -Force | Out-Null
  }

  AfterAll {
    if (Test-Path $script:TempDir) {
      Remove-Item -Path $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Aggregates multiple v2 result JSON files correctly' {
    $resultsDir = Join-Path $script:TempDir "multi-$(Get-Random)"
    New-Item -Path $resultsDir -ItemType Directory -Force | Out-Null

    $r1 = @{ ScriptName = '01-Test.ps1'; Mode = 'Audit'; Result = 'OK'; Findings = @(); Summary = @{}; Metadata = @{} }
    $r2 = @{ ScriptName = '02-Test.ps1'; Mode = 'Audit'; Result = 'WARN'; Findings = @(); Summary = @{}; Metadata = @{} }
    $r3 = @{ ScriptName = '03-Test.ps1'; Mode = 'Audit'; Result = 'FAIL'; Findings = @(); Summary = @{}; Metadata = @{} }

    $r1 | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $resultsDir 'r1.json') -Encoding UTF8
    $r2 | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $resultsDir 'r2.json') -Encoding UTF8
    $r3 | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $resultsDir 'r3.json') -Encoding UTF8

    $result = & $script:AggregateScript -InputPath $resultsDir -OutputFormat None -PassThru
    # Overall result should be FAIL because one file has FAIL
    $result.Result | Should -Be 'FAIL'
    $result.Summary.Files | Should -Be 3
    $result.Summary.OK | Should -Be 1
    $result.Summary.WARN | Should -Be 1
    $result.Summary.FAIL | Should -Be 1
  }

  It 'Returns OK when all input files are OK' {
    $resultsDir = Join-Path $script:TempDir "allok-$(Get-Random)"
    New-Item -Path $resultsDir -ItemType Directory -Force | Out-Null

    $ok1 = @{ ScriptName = '01-Test.ps1'; Mode = 'Audit'; Result = 'OK'; Findings = @(); Summary = @{}; Metadata = @{} }
    $ok2 = @{ ScriptName = '02-Test.ps1'; Mode = 'Audit'; Result = 'OK'; Findings = @(); Summary = @{}; Metadata = @{} }

    $ok1 | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $resultsDir 'ok1.json') -Encoding UTF8
    $ok2 | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $resultsDir 'ok2.json') -Encoding UTF8

    $result = & $script:AggregateScript -InputPath $resultsDir -OutputFormat None -PassThru
    $LASTEXITCODE | Should -Be 0
    $result.Result | Should -Be 'OK'
    $result.Summary.OK | Should -Be 2
    $result.Summary.FAIL | Should -Be 0
    $result.Summary.WARN | Should -Be 0
  }

  It 'Throws when given an empty directory with no JSON files' {
    $emptyDir = Join-Path $script:TempDir "empty-$(Get-Random)"
    New-Item -Path $emptyDir -ItemType Directory -Force | Out-Null

    { & $script:AggregateScript -InputPath $emptyDir -OutputFormat None -PassThru } | Should -Throw '*No JSON result files*'
  }

  It 'Throws when given a directory containing only non-JSON files' {
    $noJsonDir = Join-Path $script:TempDir "nojson-$(Get-Random)"
    New-Item -Path $noJsonDir -ItemType Directory -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $noJsonDir 'readme.txt') -Value 'not json' -Encoding UTF8

    { & $script:AggregateScript -InputPath $noJsonDir -OutputFormat None -PassThru } | Should -Throw '*No JSON result files*'
  }

  It 'Fails when all discovered JSON result files are rejected' {
    $badDir = Join-Path $script:TempDir "badjson-$(Get-Random)"
    New-Item -Path $badDir -ItemType Directory -Force | Out-Null

    Set-Content -LiteralPath (Join-Path $badDir 'corrupt.json') -Value '{{{invalid json' -Encoding UTF8
    @{ Hello = 1 } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $badDir 'wrong-shape.json') -Encoding UTF8

    $result = & $script:AggregateScript -InputPath $badDir -OutputFormat None -PassThru 3>&1
    $resultObj = $result | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] }
    $resultObj.Result | Should -Be 'FAIL'
    $resultObj.Summary.Files | Should -Be 0
    $resultObj.Summary.RejectedFiles | Should -Be 2
  }

  It 'Accepts a single JSON file path as InputPath' {
    $singleFile = Join-Path $script:TempDir "single-$(Get-Random).json"
    $doc = @{ ScriptName = '01-Test.ps1'; Mode = 'Audit'; Result = 'WARN'; Findings = @(); Summary = @{}; Metadata = @{} }
    $doc | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $singleFile -Encoding UTF8

    $result = & $script:AggregateScript -InputPath $singleFile -OutputFormat None -PassThru
    $result.Result | Should -Be 'WARN'
    $result.Summary.Files | Should -Be 1
  }
}
