#requires -version 5.1
<#
.SYNOPSIS
  Verifies public v2 script contracts.
.DESCRIPTION
  Retains parameter, result, and process-exit assertions for public scripts.
#>

function Test-V2NodeInsideFunction {
  param($Node)
  $parent = $Node.Parent
  while ($parent) {
    if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) { return $true }
    $parent = $parent.Parent
  }
  return $false
}

function Test-V2NameExposesRequiredV2Params {
  $requiredParams = @(
    'Mode',
    'ConfigPath',
    'OutputFormat',
    'OutputPath',
    'PassThru',
    'Strict',
    'Quiet',
    'NoColor'
  )
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    $ast.ParamBlock | Should -Not -BeNullOrEmpty

    $paramNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    foreach ($required in $requiredParams) {
      ($paramNames -contains $required) | Should -BeTrue
    }
  }

function Test-V2NameDoesNotExposeLegacyRemediateParameter {
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    $paramNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    ($paramNames -contains 'Remediate') | Should -BeFalse
  }

function Test-V2NameDoesNotUseLegacyAuditOnlyModeValue {
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    $modeParameter = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Mode' } | Select-Object -First 1
    $modeValidateSet = $modeParameter.Attributes |
      Where-Object { $_.TypeName.FullName -eq 'ValidateSet' } |
      Select-Object -First 1
    ($null -eq $modeValidateSet -or (@($modeValidateSet.PositionalArguments.Value) -notcontains 'AuditOnly')) | Should -BeTrue
  }

function Test-V2NameDoesNotDefineParameterNamesThatCollideWithParameterAliases {
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty

    $params = @($ast.ParamBlock.Parameters)
    $paramNames = @($params | ForEach-Object { $_.Name.VariablePath.UserPath })
    $aliases = @(
      foreach ($param in $params) {
        foreach ($attr in @($param.Attributes | Where-Object { $_.TypeName.FullName -eq 'Alias' })) {
          foreach ($arg in @($attr.PositionalArguments)) {
            [string]$arg.SafeGetValue()
          }
        }
      }
    )

    @($paramNames | Where-Object { $aliases -contains $_ }) | Should -BeNullOrEmpty
  }

function Test-V2NameEnforcesShouldProcessWhenModeSupportsRemediate {
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    $paramNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    if (-not ($paramNames -contains 'Mode')) {
      Set-ItResult -Skipped -Because 'Script has no Mode parameter.'
      return
    }

    $modeParameter = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Mode' } | Select-Object -First 1
    $modeValidateSet = $modeParameter.Attributes |
      Where-Object { $_.TypeName.FullName -eq 'ValidateSet' } |
      Select-Object -First 1

    $supportsRemediate = $false
    if ($modeValidateSet) {
      $supportsRemediate = @($modeValidateSet.PositionalArguments.Value) -contains 'Remediate'
    }

    if (-not $supportsRemediate) {
      Set-ItResult -Skipped -Because 'Mode does not support Remediate.'
      return
    }

    $content = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
    ($content -match 'SupportsShouldProcess\s*=\s*\$true') | Should -BeTrue
  }

function Test-V2AuditedScriptsDoNotExposeStaleLegacyRemediateHelpTextInTheTopCommentBlock {
    $scriptsPath = Join-Path $PSScriptRoot '../../scripts'
    $legacyHelpCases = Get-ChildItem -Path $scriptsPath -File |
      Where-Object { $_.Name -match '^\d{2}-' } |
      Where-Object {
        $errors = $null
        $tokens = $null
      $null = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors)
        if ($errors) { return $false }

        $content = Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8
        $helpBlock = [regex]::Match($content, '(?s)<#.*?#>').Value
        $helpBlock -match '\.PARAMETER\s+Remediate|-Remediate\b'
      } |
      Select-Object -ExpandProperty Name

    foreach ($name in $legacyHelpCases) {
      $path = Join-Path $scriptsPath $name
      $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8
      $helpBlock = [regex]::Match($content, '(?s)<#.*?#>').Value

      $helpBlock | Should -Not -Match '\.PARAMETER\s+Remediate'
      $helpBlock | Should -Not -Match '-Remediate\b'
    }
  }

function Test-V2ScriptsWithFilteredFindingCountsForceArraySemanticsBeforeReadingCount {
    foreach ($name in @('47-WDAG-Readiness-Audit.ps1', '49-DriverSigning-Integrity-Audit.ps1')) {
      $path = Join-Path (Join-Path $PSScriptRoot '../../scripts') $name
      $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

      $content | Should -Match '@\(\$Findings \| Where-Object \{ \$_.Severity -eq ''High'' \}\)\.Count'
      $content | Should -Match '@\(\$Findings \| Where-Object \{ \$_.Severity -eq ''Medium'' \}\)\.Count'
    }
  }

function Test-V227DefenderHealthAuditPermitsAnOmittedSettingsJsonPathDuringConfigLoad {
    $path = Join-Path $PSScriptRoot '../../scripts/27-Defender-Health-Audit.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '\[AllowEmptyString\(\)\]\s*\[string\]\$Path'
  }

function Test-V217SysmonRuleDriftSensorClassifiesRuntimeErrorsAsFAIL {
    $path = Join-Path $PSScriptRoot '../../scripts/17-Sysmon-Rule-Drift-Sensor.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '\$final\.Status\s+-in\s+@\(''FAIL'',\s*''ERROR''\)'
  }

function Test-V217SysmonRuleDriftSensorLocksEveryPlatformImplementationLoadedByExternalPsm1 {
    $repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).ProviderPath
    $updaterPath = Join-Path $repositoryRoot 'scripts/16-Sysmon-Config-Updater.ps1'
    . (Join-Path $repositoryRoot 'scripts/internal/17-Sysmon-Rule-Drift-Sensor.helpers.ps1')

    $actualPlatformClosure = @(
      Get-SysmonRemediationExecutionClosure -ScriptPath $updaterPath |
        Where-Object { $_ -like (Join-Path $repositoryRoot 'lib/platform/*') }
    )
    $expectedPlatformClosure = @(
      'Executable.ps1',
      'NativeProcess.ps1',
      'NativeTools.ps1',
      'WindowsOperations.ps1'
    ) | ForEach-Object { Join-Path $repositoryRoot (Join-Path 'lib/platform' $_) }

    $actualPlatformClosure | Should -HaveCount $expectedPlatformClosure.Count
    for ($index = 0; $index -lt $expectedPlatformClosure.Count; $index++) {
      $actualPlatformClosure[$index] | Should -BeExactly $expectedPlatformClosure[$index]
    }
  }

function Test-V2AdvertisedStrictHasTerminalWARNToFAILHandlingInAuditedScripts {
    $strictPaths = @(
      '00-Copy-Local.ps1', '00-Report-Aggregate.ps1', '00-Run-Local.ps1', '00-Validate-Profile.ps1',
      '01-ASR-Defender-Allowlist.ps1', '02-LAPS-Hygiene.ps1', '03-LocalAdmins-Guardrail.ps1',
      '10-SupportBundle-Parser.ps1', '25-WinGet-Config-Baseline-Runner.ps1', '26-Get-WinEvent-FastTriage.ps1',
      '29-Network-Config-Audit.ps1', '30-Service-Process-Audit.ps1', '42-Client-SecurityBaseline-Report-IntuneRef.ps1'
    )
    foreach ($name in $strictPaths) {
      $content = Read-V2CapabilitySource -ScriptPath (Join-Path $PSScriptRoot "../../scripts/$name")
      $content | Should -Match '\[switch\]\$Strict'
      $content | Should -Match '\$(?:(?:RunState|Options)\.)?Strict\s*-and\s+\$(?:RunState\.)?\w+\s+-eq\s+''WARN''|if\s*\(\$(?:(?:RunState|Options)\.)?Strict\)\s*\{\s*(?:\$(?:RunState\.)?\w+\s*=\s*)?''FAIL''\s*\}'
    }
  }

function Test-V2NamePreservesV2OutputSwitchesAfterInitializeV2ContextMigration {
    $case = $_
    if ($env:OS -eq 'Windows_NT') {
      Set-ItResult -Skipped -Because 'Smoke uses the unsupported-host branch to avoid Windows provider side effects.'
      return
    }

    $result = & $case.Path -OutputFormat None -PassThru -Strict:$false -Quiet -NoColor
    $exitCode = $LASTEXITCODE

    $exitCode | Should -Be 2
    $result.Result | Should -Be 'WARN'
    $result.ScriptName | Should -Be $case.Name
    $result.Mode | Should -Be 'Audit'
    $result.Summary.Mode | Should -Be 'Audit'
    $result.Summary.Supported | Should -BeFalse
    $result.Metadata.UnsupportedHost | Should -BeTrue
  }

function Test-V2ReturnsATerminalV2FAILBeforeExecutionWhenOutputFormatLacksOutputPath {
    param($OutputFormat)

    $path = Join-Path $PSScriptRoot '../../scripts/47-WDAG-Readiness-Audit.ps1'
    $output = @(& $path -OutputFormat $OutputFormat -PassThru -Quiet -NoColor 2>&1 3>&1 6>&1)
    $results = @($output | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'Result' })

    $LASTEXITCODE | Should -Be 1
    $results | Should -HaveCount 1
    $results[0].Result | Should -Be 'FAIL'
    @($results[0].Findings | Where-Object Code -eq 'V2-OutputConfigurationInvalid').Count | Should -Be 1
  }

function Test-V2NameCanConstructAV2ResultForItsOwnTerminalPaths {
    $content = Read-V2CapabilitySource -ScriptPath $_.Path

    $content | Should -Match 'Serialization\.psm1'
    $content | Should -Match 'Get-V2ResultObject'
  }

function Test-V2NameReportsUnsupportedHostAsWARNNotSuccess {
    $case = $_
    if ($env:OS -eq 'Windows_NT') {
      Set-ItResult -Skipped -Because 'Unsupported-host branch requires a non-Windows host.'
      return
    }

    $result = & $case.Path -OutputFormat None -PassThru -Strict:$false -Quiet -NoColor
    $exitCode = $LASTEXITCODE

    $exitCode | Should -Be 2
    $result.Result | Should -Be 'WARN'
    $result.Summary.Supported | Should -BeFalse
    $result.Metadata.UnsupportedHost | Should -BeTrue
  }

function Test-V2NamePromotesUnsupportedHostToFAILWhenStrictIsRequested {
    $case = $_
    if ($env:OS -eq 'Windows_NT') {
      Set-ItResult -Skipped -Because 'Unsupported-host branch requires a non-Windows host.'
      return
    }

    $result = & $case.Path -OutputFormat None -PassThru -Strict:$true -Quiet -NoColor
    $exitCode = $LASTEXITCODE

    $exitCode | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    $result.Summary.Supported | Should -BeFalse
    $result.Metadata.UnsupportedHost | Should -BeTrue
  }

function Test-V2NameKeepsItsUnsupportedHostBranchTiedToStrictAndGetV2ExitCode {
    $content = Read-V2CapabilitySource -ScriptPath $_.Path

    $content | Should -Match '\$(?:RunState\.)?(?:unsupportedResult|resultToken)\s*=\s*if\s*\(\$Strict\)\s*\{\s*''FAIL''\s*\}\s*else\s*\{\s*''WARN''\s*\}'
    $content | Should -Match 'exit\s*\(\s*Get-V2ExitCode\s+-Result\s+\$(?:RunState\.)?(?:unsupportedResult|resultToken)\s*\)'
  }

function Test-V2ReturnsInitializedDisabledConfigFindingsAndAStrictFAILAtRuntime {
    $path = Join-Path $PSScriptRoot '../../scripts/43-AppControlForBusiness-Audit.ps1'
    $configPath = Join-Path $TestDrive 'disabled.json'
    [System.IO.File]::WriteAllText($configPath, ([pscustomobject]@{ Enabled = $false } | ConvertTo-Json), [System.Text.UTF8Encoding]::new($false))

    $originalOs = $env:OS
    try {
      if ($env:OS -ne 'Windows_NT') { $env:OS = 'Windows_NT' }
      $output = @(& $path -ConfigPath $configPath -OutputFormat None -PassThru -Strict -Quiet -NoColor)
      $exitCode = $LASTEXITCODE
    } finally {
      $env:OS = $originalOs
    }

    $result = @($output | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'Result' }) | Select-Object -First 1
    $exitCode | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    @($result.Findings | Where-Object Code -eq 'AC-DisabledByConfig').Count | Should -Be 1
  }

function Test-V2UsesInitializedFindingsAndPromotesItsDisabledConfigResultUnderStrict {
    $path = Join-Path $PSScriptRoot '../../scripts/43-AppControlForBusiness-Audit.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '\$disabledFindings\s*=\s*@\(\$script:Findings\.ToArray\(\)\)'
    $content | Should -Match '\$disabledResultToken\s*=\s*if\s*\(\$(?:RunState\.)?strictModeEnabled\s+-and\s+\$disabledFindings\.Count\s+-gt\s+0\)\s*\{\s*''FAIL''\s*\}'
    $content | Should -Match '-Findings\s+\$disabledFindings'
    $content | Should -Match 'exit\s*\(\s*Get-V2ExitCode\s+-Result\s+\$disabledResultToken\s*\)'
    $content | Should -Not -Match '-Findings\s+\$findingsArr\s*`?\s*\r?\n\s*-Summary\s+\$summary\s*`?\s*\r?\n\s*-Metadata\s+@\{ Indicators = \$emptyIndicators'
  }

function Test-V2NameMapsItsFinalV2ResultTokenToTheStandardExitCode {
    $case = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($case.Path, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty

    $topLevelExits = @(
      $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ExitStatementAst] }, $true) |
        Where-Object {
          -not (Test-V2NodeInsideFunction -Node $_)
        } |
        Sort-Object { $_.Extent.StartOffset }
    )

    $topLevelExits | Should -Not -BeNullOrEmpty
    $topLevelExits[-1].Extent.Text | Should -Match '^exit\s*\(\s*Get-V2ExitCode\s+-Result\s+\$resultToken\s*\)$'
  }

function Test-V2NameDoesNotBypassV2OutputOnAnEarlyTopLevelExit {
    $case = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($case.Path, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty

    $topLevelExits = @(
      $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ExitStatementAst] }, $true) |
        Where-Object {
          -not (Test-V2NodeInsideFunction -Node $_)
        } |
        Sort-Object { $_.Extent.StartOffset }
    )

    $earlyExits = if ($topLevelExits.Count -gt 1) {
      @($topLevelExits[0..($topLevelExits.Count - 2)])
    } else {
      @()
    }

    foreach ($earlyExit in $earlyExits) {
      Test-V2EarlyExitOutput -EarlyExit $earlyExit -RootAst $ast -ScriptPath $case.Path
    }
  }

function Test-V2NameDoesNotBypassTerminalV2OutputWithATopLevelReturn {
    $case = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($case.Path, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty

    $topLevelReturns = @(
      $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ReturnStatementAst] }, $true) |
        Where-Object {
          $insideNestedCode = $false
          $parent = $_.Parent
          while ($parent) {
            if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst] -or
                $parent -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
              $insideNestedCode = $true
              break
            }
            $parent = $parent.Parent
          }
          -not $insideNestedCode
        }
    )

    $topLevelReturns | Should -BeNullOrEmpty
  }

function Test-V2EarlyExitOutput {
  param($EarlyExit, $RootAst, [string]$ScriptPath)
      $containingBlock = $earlyExit.Parent
      while ($containingBlock -and $containingBlock -isnot [System.Management.Automation.Language.StatementBlockAst]) {
        $containingBlock = $containingBlock.Parent
      }

      $containingBlock | Should -Not -BeNullOrEmpty
      $functions = Get-V2CapabilityFunctionIndex -RootAst $RootAst -ScriptPath $ScriptPath
      $outputSource = Get-V2CalledClosureText -Block $containingBlock -Functions $functions
      $outputSource | Should -Match 'Get-V2ResultObject'

      $resultMatch = [regex]::Match($outputSource, "-Result\s+'(OK|WARN|FAIL)'")
      $exitMatch = [regex]::Match($earlyExit.Extent.Text, '^exit\s+([012])$')
      if ($resultMatch.Success -and $exitMatch.Success) {
        $expectedExit = @{ OK = 0; WARN = 2; FAIL = 1 }[$resultMatch.Groups[1].Value]
        [int]$exitMatch.Groups[1].Value | Should -Be $expectedExit
      }
}

function Get-V2CapabilityFunctionIndex {
  param($RootAst, [string]$ScriptPath)
  $asts = @($RootAst)
  $helperRoot = Join-Path (Split-Path -Parent $ScriptPath) 'internal'
  $stem = [IO.Path]::GetFileNameWithoutExtension($ScriptPath)
  foreach ($file in @(Get-ChildItem -LiteralPath $helperRoot -Filter "$stem*.ps1" -File | Sort-Object Name)) {
    $tokens = $null
    $errors = $null
    $asts += [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    @($errors) | Should -HaveCount 0
  }
  $index = @{}
  foreach ($ast in $asts) {
    foreach ($definition in @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true))) {
      $index[$definition.Name] = $definition.Body
    }
  }
  return $index
}

function Get-V2CalledClosureText {
  param($Block, [hashtable]$Functions)
  $queue = [Collections.Generic.Queue[object]]::new()
  $queue.Enqueue($Block)
  $visited = @{}
  $source = [Collections.Generic.List[string]]::new()
  while ($queue.Count -gt 0) {
    $current = $queue.Dequeue()
    $source.Add($current.Extent.Text)
    foreach ($command in @($current.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true))) {
      $name = $command.GetCommandName()
      if (-not $name) { continue }
      if (-not $Functions.ContainsKey($name)) { continue }
      if ($visited.ContainsKey($name)) { continue }
      $visited[$name] = $true
      $queue.Enqueue($Functions[$name])
    }
  }
  return $source -join "`n"
}

function Read-V2CapabilitySource {
  param([string]$ScriptPath)
  $paths = @($ScriptPath)
  $helperRoot = Join-Path (Split-Path -Parent $ScriptPath) 'internal'
  $stem = [IO.Path]::GetFileNameWithoutExtension($ScriptPath)
  $paths += Get-ChildItem -LiteralPath $helperRoot -Filter "$stem*.ps1" -File | Sort-Object Name | ForEach-Object FullName
  return (@($paths | ForEach-Object { Get-Content -LiteralPath $_ -Raw -Encoding UTF8 }) -join "`n")
}
