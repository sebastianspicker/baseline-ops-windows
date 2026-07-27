#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

$script:IsWindowsHost = ($env:OS -eq 'Windows_NT')
$script:SkipNonSystemWindowsIntegration = $false
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
  try {
    $script:SkipNonSystemWindowsIntegration =
      [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'
  } catch {
    $script:SkipNonSystemWindowsIntegration = $true
  }
}

Describe 'WinGet config baseline runner config input reporting' -Tag 'Config' {
  BeforeAll {
    # Pester evaluates top-level code during discovery in a separate scope.
    # Re-establish the platform flag for runtime branches inside the tests.
    $script:IsWindowsHost = ($env:OS -eq 'Windows_NT')

    $script:WinGetRunnerScript = Join-Path $PSScriptRoot '../../scripts/25-WinGet-Config-Baseline-Runner.ps1'
    $script:WinGetRunnerHelper = Join-Path $PSScriptRoot '../../scripts/internal/25-WinGet-Config-Baseline-Runner.helpers.ps1'
    Import-Module (Join-Path $PSScriptRoot '../../lib/External.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/Validation.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/Results.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/Serialization.psm1') -Force

    $tokens = $null
    $parseErrors = $null
    $runnerAst = [System.Management.Automation.Language.Parser]::ParseFile($script:WinGetRunnerScript, [ref]$tokens, [ref]$parseErrors)
    $parseErrors | Should -BeNullOrEmpty
    $helperTokens = $null
    $helperParseErrors = $null
    $helperAst = [System.Management.Automation.Language.Parser]::ParseFile($script:WinGetRunnerHelper, [ref]$helperTokens, [ref]$helperParseErrors)
    $helperParseErrors | Should -BeNullOrEmpty
    $requiredHelpers = @(
      'Test-WinGetPhaseSuccess', 'Get-WinGetAggregateExitCode', 'Get-WinGetResultToken',
      'New-WinGetAdminOnlyDirectorySecurity', 'New-WinGetAdminOnlyDirectory',
      'Initialize-WinGetStagingRoot', 'New-WinGetStagedConfiguration',
      'Remove-WinGetStagedConfiguration'
    )
    $helperDefinitions = @($helperAst.FindAll({
          param($node)
          $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
          $requiredHelpers -contains $node.Name
        }, $true) | Sort-Object { $_.Extent.StartOffset })
    $helperDefinitions.Count | Should -Be $requiredHelpers.Count
    foreach ($definition in $helperDefinitions) { . ([scriptblock]::Create($definition.Extent.Text)) }
    $runnerHelperNames = @('Add-BoundedUtf8Log', 'Complete-WinGetStagingCleanup', 'Invoke-WinGet')
    $runnerHelperDefinitions = @($runnerAst.FindAll({
          param($node)
          $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
          $runnerHelperNames -contains $node.Name
        }, $true) | Sort-Object { $_.Extent.StartOffset })
    $runnerHelperDefinitions.Count | Should -Be $runnerHelperNames.Count
    foreach ($definition in $runnerHelperDefinitions) { . ([scriptblock]::Create($definition.Extent.Text)) }

    function Invoke-WinGetConfigBaselineCase {
      [CmdletBinding()]
      param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$SummaryJsonPath,
        [string[]]$ExtraArgs = @()
      )

      $oldOS = $env:OS
      $oldComputerName = $env:COMPUTERNAME
      $oldUserName = $env:USERNAME
      try {
        $env:OS = 'Windows_NT'
        $env:COMPUTERNAME = 'TEST-HOST'
        $env:USERNAME = 'test-user'
        Set-Variable -Name WinGetConfigBaselineInvocations -Scope Global -Value ([System.Collections.ArrayList]::new())

        function global:Get-Command {
          [CmdletBinding()]
          param(
            [string]$Name,
            [System.Management.Automation.CommandTypes[]]$CommandType
          )

          if ($Name -eq 'winget.exe') {
            return [pscustomobject]@{
              Name = 'winget.exe'
              CommandType = 'Application'
              Source = 'mock'
            }
          }

          Microsoft.PowerShell.Core\Get-Command @PSBoundParameters
        }

        function global:winget.exe {
          $invocations = Get-Variable -Name WinGetConfigBaselineInvocations -Scope Global -ValueOnly
          [void]$invocations.Add(@($args))
          Set-Variable -Name LASTEXITCODE -Scope Global -Value 0
        }

        Mock -CommandName Invoke-NativeCommand -ModuleName External -MockWith {
          param([string]$Command, [string[]]$Arguments, [switch]$CaptureOutput, [switch]$Quiet, [int]$TimeoutSeconds, [int]$MaxOutputBytes)
          $null = $Command, $CaptureOutput, $Quiet, $TimeoutSeconds, $MaxOutputBytes
          $invocations = Get-Variable -Name WinGetConfigBaselineInvocations -Scope Global -ValueOnly
          [void]$invocations.Add(@($Arguments))
          [pscustomobject]@{ ExitCode = 0; Output = ''; Stdout = ''; Stderr = ''; TimedOut = $false; OutputTruncated = $false; StderrTruncated = $false }
        }

        $runnerParameters = @{
          ConfigPath = $ConfigPath
          SummaryJsonPath = $SummaryJsonPath
          OutputFormat = 'None'
          PassThru = $true
          QuietConsole = $true
          NoColor = $true
          Confirm = $false
        }
        if ($ExtraArgs.Count -gt 0) { $runnerParameters.ExtraArgs = $ExtraArgs }
        $output = & $script:WinGetRunnerScript @runnerParameters 2>&1 3>&1 6>&1
        $exitCode = $LASTEXITCODE
      } finally {
        if ($null -eq $oldOS) {
          Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue
        } else {
          $env:OS = $oldOS
        }
        if ($null -eq $oldComputerName) {
          Remove-Item -LiteralPath Env:COMPUTERNAME -ErrorAction SilentlyContinue
        } else {
          $env:COMPUTERNAME = $oldComputerName
        }
        if ($null -eq $oldUserName) {
          Remove-Item -LiteralPath Env:USERNAME -ErrorAction SilentlyContinue
        } else {
          $env:USERNAME = $oldUserName
        }
        Remove-Item -LiteralPath Function:\Get-Command -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\winget.exe -ErrorAction SilentlyContinue
      }

      $result = @($output | Where-Object {
          $null -ne $_ -and
          $_.PSObject.Properties.Name -contains 'Result' -and
          $_.PSObject.Properties.Name -contains 'Findings'
        })[-1]

      [pscustomobject]@{
        ExitCode = $exitCode
        Result = $result
        Text = ($output | Out-String)
        Invocations = @((Get-Variable -Name WinGetConfigBaselineInvocations -Scope Global -ValueOnly).ToArray())
      }
    }
  }

  AfterEach {
    Remove-Item -LiteralPath Function:\Get-Command -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath Function:\winget.exe -ErrorAction SilentlyContinue
    Remove-Variable -Name WinGetConfigBaselineInvocations -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name WingetExecutablePath -Scope Script -ErrorAction SilentlyContinue
    Remove-Variable -Name Findings -Scope Script -ErrorAction SilentlyContinue
  }

  It 'reports invalid explicit summary JSON as WARN instead of clean OK' -Skip:((-not $script:IsWindowsHost) -or $script:SkipNonSystemWindowsIntegration) {
    $configPath = Join-Path $TestDrive 'baseline.dsc.yaml'
    Set-Content -LiteralPath $configPath -Value 'properties: {}' -Encoding UTF8
    $summaryJsonPath = Join-Path $TestDrive 'bad-summary.json'
    Set-Content -LiteralPath $summaryJsonPath -Value '{ not json' -Encoding UTF8

    $run = Invoke-WinGetConfigBaselineCase -ConfigPath $configPath -SummaryJsonPath $summaryJsonPath

    $run.ExitCode | Should -Be 2
    $run.Result.Result | Should -Be 'WARN'
    @($run.Result.Findings | Where-Object Code -eq 'WINGET-ConfigLoadFailed').Count | Should -Be 1
    @($run.Invocations).Count | Should -Be 2
  }

  It 'reports unsafe extra arguments as a V2 FAIL result before invoking WinGet' -TestCases @(
    @{ ExtraArgs = @('--header=one;two'); Expected = 'shell metacharacters' }
    @{ ExtraArgs = @('--override=unsafe'); Expected = 'blocked flag' }
  ) {
    param($ExtraArgs, $Expected)

    $configPath = Join-Path $TestDrive 'baseline.dsc.yaml'
    Set-Content -LiteralPath $configPath -Value 'properties: {}' -Encoding UTF8
    $run = Invoke-WinGetConfigBaselineCase -ConfigPath $configPath -SummaryJsonPath (Join-Path $TestDrive 'summary.json') -ExtraArgs $ExtraArgs

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    @($run.Result.Findings | Where-Object Code -eq 'WINGET-UnsafeExtraArgs').Count | Should -Be 1
    @($run.Result.Findings | Where-Object Code -eq 'WINGET-UnsafeExtraArgs')[0].Message | Should -Match $Expected
    @($run.Invocations).Count | Should -Be 0
  }

  It 'routes every WinGet phase through the bounded shared native helper' {
    $content = Get-Content -LiteralPath $script:WinGetRunnerScript -Raw -Encoding UTF8
    $content | Should -Match 'Resolve-TrustedWingetPath'
    $content | Should -Match 'Invoke-NativeCommand -Command \$script:WingetExecutablePath'
    $content | Should -Not -Match 'Invoke-NativeCommand -Command ''winget\.exe'''
    $content | Should -Not -Match '& winget\.exe'
    $content | Should -Match 'WINGET-Timeout'
    $content | Should -Match 'WINGET-OutputTruncated'
  }

  It 'runs all phases against one immutable staged configuration snapshot' -Skip:$script:SkipNonSystemWindowsIntegration {
    $sourcePath = Join-Path $TestDrive 'baseline.dsc.yaml'
    $stagingRoot = Join-Path $TestDrive 'staging'
    [System.IO.File]::WriteAllText($sourcePath, 'properties: { original: true }')

    $stageParameters = @{ SourcePath = $sourcePath }
    if (-not $script:IsWindowsHost) { $stageParameters.StagingRoot = $stagingRoot }
    $staged = New-WinGetStagedConfiguration @stageParameters
    $stagedDirectory = $staged.Directory
    try {
      $staged.Path | Should -Not -Be $staged.SourcePath
      if ($script:IsWindowsHost) {
        $expectedRoot = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'BaselineOpsForWindows\WinGetConfigStaging'
        $staged.Path | Should -BeLike "$expectedRoot*"
      } else {
        $staged.Path | Should -BeLike "$stagingRoot*"
      }
      [System.IO.File]::WriteAllText($sourcePath, 'properties: { attacker: changed }')
      [System.IO.File]::ReadAllText($staged.Path) | Should -Be 'properties: { original: true }'
      (Get-FileHash -LiteralPath $staged.Path -Algorithm SHA256).Hash | Should -Be $staged.Sha256
      if ($script:IsWindowsHost) {
        $reader = [System.IO.File]::OpenRead($staged.Path)
        $reader.Dispose()
        { [System.IO.File]::Open($staged.Path, 'Open', 'Write', 'ReadWrite').Dispose() } | Should -Throw
        { Remove-Item -LiteralPath $staged.Path -Force -ErrorAction Stop } | Should -Throw
      }
    } finally {
      Remove-WinGetStagedConfiguration -StagedConfiguration $staged
    }

    Test-Path -LiteralPath $stagedDirectory | Should -BeFalse
  }

  It 'keeps reporting and confirmation on the source path while executing the snapshot' {
    $content = Get-Content -LiteralPath $script:WinGetRunnerScript -Raw -Encoding UTF8
    $content | Should -Match '\$argsValidate\s*=\s*@\(\$argsCommon \+ @\(''validate'', ''-f'', \$executionConfigPath\)\)'
    $content | Should -Match '\$argsTest\s*=\s*@\(\$argsCommon \+ @\(''test'',\s+''-f'', \$executionConfigPath\)\)'
    $content | Should -Match '\$argsApply\s*=\s*@\(\$argsCommon \+ @\(''-f'', \$executionConfigPath\)\)'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$resolvedConfigPath, ''Run winget configure apply''\)'
    $content | Should -Match 'finally\s*\{[\s\S]*Remove-WinGetStagedConfiguration'
  }

  It 'uses identity-backed SYSTEM detection instead of a mutable environment variable' {
    $content = Get-Content -LiteralPath $script:WinGetRunnerScript -Raw -Encoding UTF8
    $content | Should -Match 'WindowsIdentity\]::GetCurrent\(\)'
    $content | Should -Match '\$identity\.IsSystem'
    $content | Should -Not -Match '\$env:USERNAME\s*-eq\s*''SYSTEM'''
  }

  It 'creates protected directories with the supported Desktop and Core ACL APIs' {
    $content = Get-Content -LiteralPath $script:WinGetRunnerHelper -Raw -Encoding UTF8
    $content | Should -Match 'PSEdition\s*-eq\s*''Desktop'''
    $content | Should -Match 'Directory\]::CreateDirectory\(\$Path,\s*\$security\)'
    $content | Should -Match 'FileSystemAclExtensions\]::CreateDirectory\(\$security,\s*\$Path\)'
  }

  It 'blocks apply unless validate and test both complete successfully' {
    $content = Get-Content -LiteralPath $script:WinGetRunnerScript -Raw -Encoding UTF8
    $content | Should -Match '\$preflightSucceeded\s*=\s*\(\$validateSucceeded\s*-and\s*\$testSucceeded\)'
    $content | Should -Match '\(\$Mode\s*-eq\s*''Remediate''\)[^\r\n]+\$preflightSucceeded'
    $content | Should -Match 'WINGET-ApplyBlocked'
    $content | Should -Match '\$failedPhases\s*=\s*@\(\$results\.ToArray\(\)'
  }

  It 'classifies phase failures and retains the first failing exit status' -TestCases @(
    @{ Results = @(@{ ExitCode = 0; TimedOut = $false }, @{ ExitCode = 0; TimedOut = $false }); Expected = 0 }
    @{ Results = @(@{ ExitCode = 5; TimedOut = $false }, @{ ExitCode = 0; TimedOut = $false }); Expected = 5 }
    @{ Results = @(@{ ExitCode = 0; TimedOut = $true }, @{ ExitCode = 0; TimedOut = $false }); Expected = -1 }
    @{ Results = @(@{ ExitCode = 0; TimedOut = $false }, @{ ExitCode = 7; TimedOut = $false }, @{ ExitCode = 0; TimedOut = $false }); Expected = 7 }
  ) {
    param($Results, $Expected)

    (Get-WinGetAggregateExitCode -PhaseResults $Results) | Should -Be $Expected
    (Test-WinGetPhaseSuccess -PhaseResult $Results[0]) | Should -Be ($Expected -eq 0 -or $Results[0].ExitCode -eq 0 -and -not $Results[0].TimedOut)
  }

  It 'reports a requested log failure without losing the completed phase result' {
    $script:WingetExecutablePath = if ($script:IsWindowsHost) { 'C:\Windows\System32\winget.exe' } else { '/mock/winget' }
    Mock -CommandName Invoke-NativeCommand -MockWith {
      [pscustomobject]@{ ExitCode = 0; Stdout = 'ok'; Stderr = ''; TimedOut = $false; OutputTruncated = $false; StderrTruncated = $false }
    }
    Mock -CommandName Add-BoundedUtf8Log -MockWith { throw 'log path denied' }

    $phase = Invoke-WinGet -ArgsWinget @('configure', 'validate') -Phase 'validate' `
      -LogPathEffective '/unwritable/log.txt' -TimeoutSecondsEffective 30 -MaxOutputBytesEffective 4096

    $phase.ExitCode | Should -Be 0
    $phase.LogError | Should -Match 'log path denied'
    $phase.LogTruncated | Should -BeFalse
  }

  It 'turns a protected staging cleanup failure into a warning or strict failure before output' {
    $script:Findings = Get-FindingsList
    Mock -CommandName Remove-WinGetStagedConfiguration -MockWith { throw 'cleanup denied' }

    $cleanup = Complete-WinGetStagingCleanup -StagedConfiguration ([pscustomobject]@{ Directory = '/protected/stage'; Stream = $null })

    $cleanup.Succeeded | Should -BeFalse
    $cleanup.Error | Should -Match 'cleanup denied'
    @($script:Findings | Where-Object Code -eq 'WINGET-StagingCleanupFailed').Count | Should -Be 1
    $warningToken = Get-WinGetResultToken -FinalExitCode 0 -FindingsCount $script:Findings.Count -StrictMode $false
    $warningToken | Should -Be 'WARN'
    (Get-V2ExitCode -Result $warningToken) | Should -Be 2
    $strictToken = Get-WinGetResultToken -FinalExitCode 0 -FindingsCount $script:Findings.Count -StrictMode $true
    $strictToken | Should -Be 'FAIL'
    (Get-V2ExitCode -Result $strictToken) | Should -Be 1

    $content = Get-Content -LiteralPath $script:WinGetRunnerScript -Raw -Encoding UTF8
    $content.LastIndexOf('$cleanupOutcome = Complete-WinGetStagingCleanup') | Should -BeLessThan $content.IndexOf('# V2 output contract')
  }
}
