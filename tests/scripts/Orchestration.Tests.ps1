#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

# ---------------------------------------------------------------------------
# Integration tests for orchestration scripts:
#   00-Validate-Profile.ps1
#   00-Run-Batch.ps1
#   00-Report-Aggregate.ps1
# ---------------------------------------------------------------------------

Describe '00-Validate-Profile orchestration' {
  BeforeAll {
    $script:ScriptsRoot = Join-Path $PSScriptRoot '../../scripts'
    $script:LibRoot = Join-Path $PSScriptRoot '../../lib'
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

  It 'Rejects control-plane scripts as profile steps' {
    $temp = Join-Path $script:TempDir "control-plane-step-$(Get-Random).json"
    $doc = @{
      ProfileName = 'control-plane-step'
      Version     = '2.0'
      Defaults    = @{ Mode = 'Audit' }
      Steps       = @(
        @{ Script = '00-Run-Profile.ps1'; Args = @('-ProfilePath', $temp); ContinueOnError = $false; DependsOn = @() }
      )
      Integrity   = @{ RequireSigned = $false; ExpectedHashes = @{} }
    }
    $doc | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temp -Encoding UTF8

    $result = & $script:ValidateScript -ProfilePath $temp -OutputFormat None -PassThru

    $LASTEXITCODE | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    @($result.Findings | Where-Object Code -eq 'PROFILE-STEP-CONTROL-PLANE').Count | Should -Be 1
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
    $script:LibRoot = Join-Path $PSScriptRoot '../../lib'
    $script:BatchScript = Join-Path $script:ScriptsRoot '00-Run-Batch.ps1'
    $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "orch-batch-$(Get-Random)"
    New-Item -Path $script:TempDir -ItemType Directory -Force | Out-Null
    $script:IsElevatedWindows = $false
    if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
      $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
      try {
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        $script:IsElevatedWindows = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
      } finally {
        $identity.Dispose()
      }
    }

    $tokens = $null
    $parseErrors = $null
    $batchAst = [System.Management.Automation.Language.Parser]::ParseFile(
      (Resolve-Path $script:BatchScript),
      [ref]$tokens,
      [ref]$parseErrors
    )
    $parseErrors | Should -BeNullOrEmpty
    $setAclFunction = @($batchAst.FindAll({
          param($node)
          $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Set-BatchAdminSystemAcl'
        }, $true))[0]
    . ([scriptblock]::Create($setAclFunction.Extent.Text))

    $pureBatchHelperNames = @('Get-BatchCategoryMap', 'Get-BatchSelectedScripts', 'New-BatchProfileDocument')
    foreach ($helperName in $pureBatchHelperNames) {
      $helperFunction = @($batchAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
              $node.Name -eq $helperName
          }, $true))[0]
      $helperFunction | Should -Not -BeNullOrEmpty
      . ([scriptblock]::Create($helperFunction.Extent.Text))
    }

    function New-RunBatchFixtureRoot {
      [CmdletBinding(SupportsShouldProcess = $true)]
      param([Parameter(Mandatory)][string]$Name)

      if (-not $PSCmdlet.ShouldProcess($Name, 'Create protected Run-Batch fixture root')) { return $null }
      if ($script:IsElevatedWindows) {
        $systemDirectory = [System.Environment]::GetFolderPath(
          [System.Environment+SpecialFolder]::System
        )
        $trustedParent = Join-Path $systemDirectory 'config\systemprofile'
        return Join-Path $trustedParent ("BaselineOpsForWindows-OrchestrationTests-{0}-{1}" -f $Name, [guid]::NewGuid().ToString('N'))
      }

      return Join-Path $script:TempDir ("{0}-{1}" -f $Name, (Get-Random))
    }

    function Set-RunBatchFixtureTrustedAcl {
      [CmdletBinding(SupportsShouldProcess = $true)]
      param([Parameter(Mandatory)][string]$Path)

      if (-not $script:IsElevatedWindows) { return }
      if (-not $PSCmdlet.ShouldProcess($Path, 'Protect Run-Batch fixture ACL')) { return }

      $items = @(
        Get-ChildItem -LiteralPath $Path -Force -Recurse |
          Sort-Object { $_.FullName.Length } -Descending
      )
      foreach ($item in $items) {
        Set-BatchAdminSystemAcl -Path $item.FullName -Directory:$item.PSIsContainer
      }
      Set-BatchAdminSystemAcl -Path $Path -Directory
    }

    function Get-GeneratedBatchProfile {
      param([Parameter(Mandatory)][string]$Category)

      $tempRoot = New-RunBatchFixtureRoot -Name 'batch-profile'
      $tempScripts = Join-Path $tempRoot 'scripts'
      $tempLib = Join-Path $tempRoot 'lib'

      try {
        New-Item -Path $tempScripts -ItemType Directory -Force | Out-Null
        New-Item -Path $tempLib -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $tempScripts '_lib') -ItemType Directory -Force | Out-Null
        Copy-Item -LiteralPath $script:BatchScript -Destination (Join-Path $tempScripts '00-Run-Batch.ps1') -Force
        Copy-Item -LiteralPath (Join-Path $script:ScriptsRoot '_lib/Bootstrap.ps1') -Destination (Join-Path $tempScripts '_lib/Bootstrap.ps1') -Force
        foreach ($moduleName in @('Common.psm1','Console.psm1','Output.psm1','Serialization.psm1','Validation.psm1')) {
          Copy-Item -LiteralPath (Join-Path $script:LibRoot $moduleName) -Destination (Join-Path $tempLib $moduleName) -Force
        }

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
            Set-Content -LiteralPath (Join-Path $tempScripts $_.Name) -Value '# generated fixture' -Encoding UTF8
          }

        $tempBatchScript = Join-Path $tempScripts '00-Run-Batch.ps1'
        Set-RunBatchFixtureTrustedAcl -Path $tempRoot
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
    # WhatIf causes ShouldProcess to deny execution and reports a warning.
    $LASTEXITCODE | Should -Be 2
  }

  It 'Builds a valid batch profile for the Audit category' {
    # Run with -WhatIf so no scripts are actually executed
    & $script:BatchScript -Category Audit -OutputFormat None -RootPath (Split-Path $script:ScriptsRoot -Parent) -WhatIf
    $LASTEXITCODE | Should -Be 2
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

  It 'selects category scripts in stable unique lexical order' {
    $fixtureScripts = @(
      '20-Storage-Audit.ps1',
      '09-SupportBundle.ps1',
      '12-Collection.ps1',
      '10-Events.ps1',
      '11-Network.ps1',
      '09-Alternate.ps1',
      '01-NotCollection.ps1'
    )

    $selected = @(Get-BatchSelectedScripts -Category Collection -ScriptNames $fixtureScripts)

    $selected | Should -Be @(
      '09-Alternate.ps1',
      '09-SupportBundle.ps1',
      '10-Events.ps1',
      '11-Network.ps1',
      '12-Collection.ps1',
      '20-Storage-Audit.ps1'
    )
    @(Get-BatchSelectedScripts -Category All -ScriptNames $fixtureScripts) |
      Should -Be @($fixtureScripts | Sort-Object)
  }

  It 'constructs the generated profile with the established v2 schema and step flags' {
    $profile = New-BatchProfileDocument -Category Collection -Mode Remediate -Strict $true -RequireSigned $true -ContinueOnError $true -SelectedScripts @('09-SupportBundle.ps1', '10-Events.ps1')
    $serialized = $profile | ConvertTo-Json -Depth 8 | ConvertFrom-Json

    @($serialized.PSObject.Properties.Name) | Should -Be @('ProfileName', 'Version', 'Defaults', 'Steps', 'Integrity')
    $serialized.ProfileName | Should -Be 'batch-collection'
    $serialized.Version | Should -Be '2.0'
    $serialized.Defaults.Mode | Should -Be 'Remediate'
    $serialized.Defaults.Strict | Should -BeTrue
    $serialized.Defaults.OutputFormat | Should -Be 'Console'
    $serialized.Defaults.OutputPath | Should -BeNullOrEmpty
    $serialized.Integrity.RequireSigned | Should -BeTrue
    @($serialized.Integrity.ExpectedHashes.PSObject.Properties).Count | Should -Be 0
    @($serialized.Steps).Count | Should -Be 2
    foreach ($step in @($serialized.Steps)) {
      @($step.PSObject.Properties.Name) | Should -Be @('Script', 'Args', 'ContinueOnError', 'DependsOn')
      $step.Args | Should -BeNullOrEmpty
      $step.ContinueOnError | Should -BeTrue
      $step.DependsOn | Should -BeNullOrEmpty
    }
  }

  It 'Handles Remediation category with -WhatIf without crashing' {
    & $script:BatchScript -Category Remediation -OutputFormat None -RootPath (Split-Path $script:ScriptsRoot -Parent) -WhatIf
    $LASTEXITCODE | Should -Be 2
  }

  It 'Excludes 00 control-plane scripts from the All category' {
    $profileSpec = Get-GeneratedBatchProfile -Category All
    $scripts = @($profileSpec.Steps | ForEach-Object { $_.Script })

    @($scripts | Where-Object { $_ -like '00-*' }) | Should -BeNullOrEmpty
    $scripts | Should -Contain '01-ASR-Defender-Allowlist.ps1'
    $scripts | Should -Contain '52-DoH-Audit.ps1'
  }

  It 'Returns a V2 warning when WhatIf skips the batch' {
    $result = & $script:BatchScript -Category Audit -OutputFormat None -RootPath (Split-Path $script:ScriptsRoot -Parent) -PassThru -WhatIf

    $LASTEXITCODE | Should -Be 2
    $result.ScriptName | Should -Be '00-Run-Batch.ps1'
    $result.Result | Should -Be 'WARN'
    $result.Summary.Executed | Should -BeFalse
  }

  It 'checks the privileged batch closure before importing repository code' {
    $source = Get-Content -LiteralPath $script:BatchScript -Raw

    $source | Should -Match "Join-Path \`$runnerLib 'Output\.psm1'"
    $source | Should -Match "Join-Path \`$runnerLib 'Serialization\.psm1'"
    $source | Should -Match '\$runProfilePath,'
    $source | Should -Match 'PropagationFlags\]::InheritOnly'
    $source.IndexOf('Assert-RunBatchTrustedWindowsAcl -Path $trustedPath') |
      Should -BeLessThan $source.IndexOf(". (Join-Path `$PSScriptRoot '_lib/Bootstrap.ps1')")
  }

  It 'uses a protected elevated workspace and keeps the profile read-only during invocation' {
    $source = Get-Content -LiteralPath $script:BatchScript -Raw

    $source | Should -Match 'CommonApplicationData'
    $source | Should -Match 'Join-Path \$programData ''Microsoft\\Windows'''
    $source | Should -Match 'Assert-RunBatchTrustedWindowsAcl -Path \$trustedParent -CheckAncestors'
    $source | Should -Match 'BaselineOpsForWindows-Batch-{0}'
    $source | Should -Not -Match 'BaselineOpsForWindows-Batch''\)'
    $source | Should -Match 'Set-BatchAdminSystemAcl -Path \$tempProfile'
    $source | Should -Match '\[System\.IO\.FileShare\]::Read'
    $source.IndexOf('$profileLockStream = New-Object System.IO.FileStream') |
      Should -BeLessThan $source.IndexOf('& $runProfilePath @params')
    $source.IndexOf('& $runProfilePath @params') |
      Should -BeLessThan $source.IndexOf('$profileLockStream.Dispose()')
  }

  It 'does not replace an explicitly bound default root on non-Windows' -Skip:([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    $result = & $script:BatchScript -Category Audit -RootPath 'C:\install\mdm\ps1' -OutputFormat None -PassThru -WhatIf

    $LASTEXITCODE | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    @($result.Findings | Where-Object Code -eq 'Batch-MissingScriptsDirectory').Count | Should -Be 1
  }

  It 'uses checkout fallback when the default root was omitted on non-Windows' -Skip:([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    $result = & $script:BatchScript -Category Audit -OutputFormat None -PassThru -WhatIf

    $LASTEXITCODE | Should -Be 2
    $result.Result | Should -Be 'WARN'
  }

  It 'protects elevated batch workspaces for Administrators and SYSTEM only' -Skip:([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
      Set-ItResult -Skipped -Because 'The Windows ACL fixture requires an elevated test process.'
      return
    }

    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
      (Resolve-Path $script:BatchScript),
      [ref]$tokens,
      [ref]$parseErrors
    )
    $functionAst = @($ast.FindAll({
          param($node)
          $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Set-BatchAdminSystemAcl'
        }, $true))[0]
    . ([scriptblock]::Create($functionAst.Extent.Text))

    $aclDirectory = Join-Path $TestDrive 'admin-system-only'
    New-Item -Path $aclDirectory -ItemType Directory -Force | Out-Null
    Set-BatchAdminSystemAcl -Path $aclDirectory -Directory

    $acl = Get-Acl -LiteralPath $aclDirectory
    $acl.AreAccessRulesProtected | Should -BeTrue
    $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value | Should -Be 'S-1-5-32-544'
    $allowSids = @(
      $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
        Where-Object AccessControlType -eq ([System.Security.AccessControl.AccessControlType]::Allow) |
        ForEach-Object { $_.IdentityReference.Value } |
        Sort-Object -Unique
    )
    $allowSids | Should -Be @('S-1-5-18', 'S-1-5-32-544')
  }

  It 'Propagates unsupported-host WARN children through batch orchestration' {
    $tempRoot = New-RunBatchFixtureRoot -Name 'unsupported-batch'
    $scriptsDir = Join-Path $tempRoot 'scripts'

    try {
      New-Item -Path $scriptsDir, (Join-Path $scriptsDir '_lib'), (Join-Path $scriptsDir 'internal'), (Join-Path $tempRoot 'lib') -ItemType Directory -Force | Out-Null
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

      Set-RunBatchFixtureTrustedAcl -Path $tempRoot
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

  It 'Returns a V2 FAIL result for an empty directory with no JSON files' {
    $emptyDir = Join-Path $script:TempDir "empty-$(Get-Random)"
    New-Item -Path $emptyDir -ItemType Directory -Force | Out-Null

    $result = & $script:AggregateScript -InputPath $emptyDir -OutputFormat None -PassThru

    $LASTEXITCODE | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    $result.Summary.Error | Should -Match 'No JSON result files'
  }

  It 'Returns a V2 FAIL result for a directory containing only non-JSON files' {
    $noJsonDir = Join-Path $script:TempDir "nojson-$(Get-Random)"
    New-Item -Path $noJsonDir -ItemType Directory -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $noJsonDir 'readme.txt') -Value 'not json' -Encoding UTF8

    $result = & $script:AggregateScript -InputPath $noJsonDir -OutputFormat None -PassThru

    $LASTEXITCODE | Should -Be 1
    $result.Result | Should -Be 'FAIL'
  }

  It 'Fails when all discovered JSON result files are rejected' {
    $badDir = Join-Path $script:TempDir "badjson-$(Get-Random)"
    New-Item -Path $badDir -ItemType Directory -Force | Out-Null

    Set-Content -LiteralPath (Join-Path $badDir 'corrupt.json') -Value '{{{invalid json' -Encoding UTF8
    @{ Hello = 1 } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $badDir 'wrong-shape.json') -Encoding UTF8

    $result = & $script:AggregateScript -InputPath $badDir -OutputFormat None -PassThru 3>&1
    $resultObj = $result | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] }
    $LASTEXITCODE | Should -Be 1
    $resultObj.Result | Should -Be 'FAIL'
    $resultObj.Summary.Files | Should -Be 0
    $resultObj.Summary.RejectedFiles | Should -Be 2
  }

  It 'Accepts a single JSON file path as InputPath' {
    $singleFile = Join-Path $script:TempDir "single-$(Get-Random).json"
    $doc = @{ ScriptName = '01-Test.ps1'; Mode = 'Audit'; Result = 'WARN'; Findings = @(); Summary = @{}; Metadata = @{} }
    $doc | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $singleFile -Encoding UTF8

    $result = & $script:AggregateScript -InputPath $singleFile -OutputFormat None -PassThru
    $LASTEXITCODE | Should -Be 2
    $result.Result | Should -Be 'WARN'
    $result.Summary.Files | Should -Be 1
  }

  It 'Returns WARN when valid input is accompanied by a rejected result file' {
    $mixedDir = Join-Path $script:TempDir "mixed-$(Get-Random)"
    New-Item -Path $mixedDir -ItemType Directory -Force | Out-Null

    @{ ScriptName = '01-Test.ps1'; Mode = 'Audit'; Result = 'OK' } |
      ConvertTo-Json | Set-Content -LiteralPath (Join-Path $mixedDir 'valid.json') -Encoding UTF8
    @{ ScriptName = '02-Test.ps1'; Mode = 'Audit'; Result = 'UNKNOWN' } |
      ConvertTo-Json | Set-Content -LiteralPath (Join-Path $mixedDir 'invalid.json') -Encoding UTF8

    $output = & $script:AggregateScript -InputPath $mixedDir -OutputFormat None -PassThru 3>&1
    $result = $output | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] }

    $LASTEXITCODE | Should -Be 2
    $result.Result | Should -Be 'WARN'
    $result.Summary.Files | Should -Be 1
    $result.Summary.RejectedFiles | Should -Be 1
    @($result.Findings | Where-Object Code -eq 'Aggregate-InvalidResult').Count | Should -Be 1
  }

  It 'Excludes its own output on repeated runs inside an input directory' {
    $resultsDir = Join-Path $script:TempDir "repeated-output-$(Get-Random)"
    New-Item -Path $resultsDir -ItemType Directory -Force | Out-Null
    $inputPath = Join-Path $resultsDir 'current.json'
    $outputPath = Join-Path $resultsDir 'aggregate.json'

    @{ ScriptName = '01-Test.ps1'; Mode = 'Audit'; Result = 'FAIL'; Findings = @(); Summary = @{}; Metadata = @{} } |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $inputPath -Encoding UTF8
    $first = & $script:AggregateScript -InputPath $resultsDir -OutputFormat Json -OutputPath $outputPath -PassThru
    $LASTEXITCODE | Should -Be 1
    $first.Result | Should -Be 'FAIL'

    @{ ScriptName = '01-Test.ps1'; Mode = 'Audit'; Result = 'OK'; Findings = @(); Summary = @{}; Metadata = @{} } |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $inputPath -Encoding UTF8
    $second = & $script:AggregateScript -InputPath $resultsDir -OutputFormat Json -OutputPath $outputPath -PassThru

    $LASTEXITCODE | Should -Be 0
    $second.Result | Should -Be 'OK'
    $second.Summary.Files | Should -Be 1
    @($second.Metadata.Items).Count | Should -Be 1
    $second.Metadata.Items[0].File | Should -Be (Resolve-Path -LiteralPath $inputPath).Path
  }

  It 'collapses case-alias inputs and excludes case-alias output on case-insensitive filesystems' {
    $caseProbePath = Join-Path $script:TempDir "case-insensitive-probe-$(Get-Random)"
    Set-Content -LiteralPath $caseProbePath -Value 'probe' -Encoding UTF8
    if (-not (Test-Path -LiteralPath $caseProbePath.ToUpperInvariant())) {
      Set-ItResult -Skipped -Because 'The test fixture directory is case-sensitive.'
      return
    }

    $aliasInputDir = Join-Path $script:TempDir "case-alias-input-$(Get-Random)"
    New-Item -Path $aliasInputDir -ItemType Directory -Force | Out-Null
    $inputPath = Join-Path $aliasInputDir 'result.json'
    @{ ScriptName = 'alias-input.ps1'; Mode = 'Audit'; Result = 'OK'; Findings = @(); Summary = @{}; Metadata = @{} } |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $inputPath -Encoding UTF8

    $aliasInputResult = & $script:AggregateScript -InputPath @($inputPath, $inputPath.ToUpperInvariant()) -OutputFormat None -PassThru

    $LASTEXITCODE | Should -Be 0
    $aliasInputResult.Summary.Files | Should -Be 1
    $aliasInputResult.Metadata.Items[0].File | Should -Be (Get-Item -LiteralPath $inputPath).FullName

    $outputAliasDir = Join-Path $script:TempDir "case-alias-output-$(Get-Random)"
    New-Item -Path $outputAliasDir -ItemType Directory -Force | Out-Null
    $sourcePath = Join-Path $outputAliasDir 'input.json'
    $staleOutputPath = Join-Path $outputAliasDir 'aggregate.json'
    $outputPath = Join-Path $outputAliasDir 'Aggregate.json'
    @{ ScriptName = 'source.ps1'; Mode = 'Audit'; Result = 'OK'; Findings = @(); Summary = @{}; Metadata = @{} } |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $sourcePath -Encoding UTF8
    @{ ScriptName = '00-Report-Aggregate.ps1'; Mode = 'Audit'; Result = 'FAIL'; Findings = @(); Summary = @{}; Metadata = @{} } |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $staleOutputPath -Encoding UTF8

    $outputAliasResult = & $script:AggregateScript -InputPath $outputAliasDir -OutputFormat Json -OutputPath $outputPath -PassThru

    $LASTEXITCODE | Should -Be 0
    $outputAliasResult.Summary.Files | Should -Be 1
    $outputAliasResult.Metadata.Items[0].File | Should -Be (Get-Item -LiteralPath $sourcePath).FullName
  }

  It 'preserves case-distinct inputs and excludes only the exact output path on case-sensitive filesystems' {
    $caseProbePath = Join-Path $script:TempDir "case-sensitivity-probe-$(Get-Random)"
    Set-Content -LiteralPath $caseProbePath -Value 'probe' -Encoding UTF8
    if (Test-Path -LiteralPath $caseProbePath.ToUpperInvariant()) {
      Set-ItResult -Skipped -Because 'The test fixture directory is case-insensitive.'
      return
    }

    $caseDistinctDir = Join-Path $script:TempDir "case-distinct-$(Get-Random)"
    New-Item -Path $caseDistinctDir -ItemType Directory -Force | Out-Null
    $lowerCaseInput = Join-Path $caseDistinctDir 'result.json'
    $upperCaseInput = Join-Path $caseDistinctDir 'Result.json'

    @{ ScriptName = 'lower-case.ps1'; Mode = 'Audit'; Result = 'OK'; Findings = @(); Summary = @{}; Metadata = @{} } |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $lowerCaseInput -Encoding UTF8
    @{ ScriptName = 'upper-case.ps1'; Mode = 'Audit'; Result = 'OK'; Findings = @(); Summary = @{}; Metadata = @{} } |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $upperCaseInput -Encoding UTF8

    $caseDistinctResult = & $script:AggregateScript -InputPath $caseDistinctDir -OutputFormat None -PassThru

    $LASTEXITCODE | Should -Be 0
    $caseDistinctResult.Summary.Files | Should -Be 2
    @($caseDistinctResult.Metadata.Items.File) | Should -Contain (Resolve-Path -LiteralPath $lowerCaseInput).Path
    @($caseDistinctResult.Metadata.Items.File) | Should -Contain (Resolve-Path -LiteralPath $upperCaseInput).Path

    $outputExactnessDir = Join-Path $script:TempDir "output-exactness-$(Get-Random)"
    New-Item -Path $outputExactnessDir -ItemType Directory -Force | Out-Null
    $inputPath = Join-Path $outputExactnessDir 'aggregate.json'
    $outputPath = Join-Path $outputExactnessDir 'Aggregate.json'
    @{ ScriptName = 'case-distinct-output.ps1'; Mode = 'Audit'; Result = 'OK'; Findings = @(); Summary = @{}; Metadata = @{} } |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $inputPath -Encoding UTF8

    $outputExactnessResult = & $script:AggregateScript -InputPath $outputExactnessDir -OutputFormat Json -OutputPath $outputPath -PassThru

    $LASTEXITCODE | Should -Be 0
    $outputExactnessResult.Summary.Files | Should -Be 1
    $outputExactnessResult.Metadata.Items[0].File | Should -Be (Resolve-Path -LiteralPath $inputPath).Path
  }
}
