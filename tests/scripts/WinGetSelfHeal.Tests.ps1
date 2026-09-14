#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for the WinGet audit/remediation boundary.

.DESCRIPTION
Verifies that audit mode remains observational and that configuration needed
only to add a missing source is not required when checking an existing source.
#>

BeforeAll {
  function Get-WingetTestDefinitions {
    $definitions = @{}
    foreach ($name in @('Ensure-PrivateSource', 'Test-WingetSourceOutputContainsName',
        'Protect-WingetProcessMetadata', 'Get-PrivateSourceResultMetadata', 'Invoke-Winget', 'ConvertFrom-WingetNativeResult', 'Get-WingetEffectiveExitCode', 'Update-WinGetSources')) {
      $definitions[$name] = $script:Ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
      }, $true)
    }
    return $definitions
  }
  $script:ScriptPath = Join-Path $PSScriptRoot '../../scripts/08-WinGet-SelfHeal.ps1'
  $script:Tokens = $null
  $script:ParseErrors = $null
  $sourcePaths = @($script:ScriptPath)
  foreach ($name in @('records', 'winget', 'install', 'runtime')) {
    $sourcePaths += Join-Path $PSScriptRoot ("../../scripts/internal/08-WinGet-SelfHeal.{0}.ps1" -f $name)
  }
  $script:ScriptSource = ($sourcePaths | ForEach-Object { Get-Content -LiteralPath $_ -Raw }) -join "`n"
  $script:Ast = [System.Management.Automation.Language.Parser]::ParseInput(
    $script:ScriptSource, [ref]$script:Tokens, [ref]$script:ParseErrors)

  $definitions = Get-WingetTestDefinitions

  $testModuleSource = @'
$script:SourcePresent = $true
$script:AddCalls = 0
$script:NativeStdOut = ''
$script:NativeStdErr = ''

function Test-WingetSourcePresent {
  param([string]$WingetPath, [string]$Name)
  return $script:SourcePresent, 'test detail'
}

function Test-WingetPrivateSourceDefinition {
  param([string]$Url, [string]$Type)
  return $false
}

function Invoke-NativeCommand {
  param([string]$Command, [string[]]$Arguments)
  $script:AddCalls++
  return [pscustomobject]@{
    ExitCode = 0
    StdErr = $script:NativeStdErr
    StdOut = $script:NativeStdOut
    TimedOut = $false
    OutputTruncated = $false
    StderrTruncated = $false
    Success = $true
  }
}

function Set-WingetSourceTestState {
  param([bool]$Present)
  $script:SourcePresent = $Present
  $script:AddCalls = 0
}

function Set-WingetProcessTestOutput {
  param([string]$StdOut, [string]$StdErr)
  $script:NativeStdOut = $StdOut
  $script:NativeStdErr = $StdErr
}

function Get-WingetSourceTestState {
  [pscustomobject]@{ AddCalls = $script:AddCalls }
}
function Get-CheckRecord { param($Name, $Status, $Message) }
function Add-Record { param($List, $Record) }
function Invoke-WingetSourceUpdate {
  param($WingetPath, [switch]$SupportAcceptSourceAgreements)
  $script:UpdateCalls++
  return @{ ExitCode = 0 }
}
function Invoke-WingetUpdateFixture {
  param([bool]$Present, [bool]$Remediate, [bool]$Allow)
  $script:UpdateCalls = 0
  $context = [pscustomobject]@{ Allow = $Allow }
  $context | Add-Member ScriptMethod ShouldProcess { return $this.Allow }
  $state = @{ WingetPath = if ($Present) { 'winget.exe' } else { $null }
    Inputs = @{ Remediate = $Remediate; DecisionContext = $context }
    Records = [Collections.Generic.List[object]]::new()
    SupportsSourceAgreement = $false }
  Update-WinGetSources -RunState $state
  return $script:UpdateCalls
}

'@
  $testModuleSource += "`n" + $definitions['Protect-WingetProcessMetadata'].Extent.Text
  $testModuleSource += "`n" + $definitions['Get-PrivateSourceResultMetadata'].Extent.Text
  $testModuleSource += "`n" + $definitions['Get-WingetEffectiveExitCode'].Extent.Text
  $testModuleSource += "`n" + $definitions['Update-WinGetSources'].Extent.Text
  $testModuleSource += "`n" + $definitions['ConvertFrom-WingetNativeResult'].Extent.Text
  $testModuleSource += "`n" + $definitions['Invoke-Winget'].Extent.Text
  $testModuleSource += "`n" + $definitions['Ensure-PrivateSource'].Extent.Text
  $testModuleSource += "`n" + $definitions['Test-WingetSourceOutputContainsName'].Extent.Text
  $testModuleSource += "`nExport-ModuleMember -Function Invoke-WingetUpdateFixture,Ensure-PrivateSource,Test-WingetSourceOutputContainsName,Invoke-Winget,Get-PrivateSourceResultMetadata,Set-WingetSourceTestState,Set-WingetProcessTestOutput,Get-WingetSourceTestState"
  $script:WinGetTestModule = New-Module -Name WinGetSelfHealContract -ScriptBlock ([scriptblock]::Create($testModuleSource))
  Import-Module $script:WinGetTestModule -Force
}

AfterAll {
  Remove-Module WinGetSelfHealContract -Force -ErrorAction SilentlyContinue
}

Describe 'WinGet audit boundary' {
  BeforeAll {
function Test-WingetChecksAnExistingPrivateSourceWithoutRequiringAddOnlyConfiguration {
    Set-WingetSourceTestState -Present $true

    $present, $detail = Ensure-PrivateSource -WingetPath 'winget.exe' -Name 'corp' -DoIt:$false

    $present | Should -BeTrue
    $detail | Should -Be 'Present'
    (Get-WingetSourceTestState).AddCalls | Should -Be 0
  }

function Test-WingetDoesNotAttemptToAddAMissingSourceInAuditMode {
    Set-WingetSourceTestState -Present $false

    $present, $detail = Ensure-PrivateSource -WingetPath 'winget.exe' -Name 'corp' -Url 'not-a-url' -Type 'unsupported' -DoIt:$false

    $present | Should -BeFalse
    $detail | Should -Match '^Missing \(no remediation\)'
    (Get-WingetSourceTestState).AddCalls | Should -Be 0
  }

function Test-WingetGuardsEverySourceUpdateBehindRemediationModeAndShouldProcess {
    foreach ($present in @($false, $true)) {
      foreach ($remediate in @($false, $true)) {
        foreach ($allow in @($false, $true)) {
          $calls = Invoke-WingetUpdateFixture -Present $present -Remediate $remediate -Allow $allow
          $calls | Should -Be ([int]($present -and $remediate -and $allow))
        }
      }
    }
  }

function Test-WingetDoesNotLetWrapperConfigurationGrantRemediationAuthority {
    $script:ScriptSource | Should -Not -Match 'Get-NestedPropValue\s+-Object\s+\$cfg\s+-Path\s+@\(''VCppRedist'''
    $script:ScriptSource | Should -Not -Match 'Get-NestedPropValue\s+-Object\s+\$cfg\s+-Path\s+@\(''Winget'',''PrivateSourceUrl'''
    $script:ScriptSource | Should -Match '(?:PSBoundParameters|RunState\.Inputs\.BoundParameters)\.ContainsKey\(''PrivateSourceName''\)'
    $script:ScriptSource | Should -Match '(?:PSBoundParameters|RunState\.Inputs\.BoundParameters)\.ContainsKey\(''PrivateSourceUrl''\)'
  }

function Test-WingetRedactsCredentialBearingURLsFromWinGetProcessMetadata {
    $credentialUrl = 'https://operator:do-not-log@packages.example.test/cache'
    $queryUrl = 'https://packages.example.test/cache?access_token=do-not-log'
    Set-WingetProcessTestOutput -StdOut "Source $credentialUrl" -StdErr "Failed $queryUrl"

    $result = Invoke-Winget -WingetPath 'winget.exe' -WingetArgs @('source', 'add', '-a', $credentialUrl, '--legacy', $queryUrl)
    $metadata = $result | ConvertTo-Json -Depth 4 -Compress

    $metadata | Should -Not -Match ([regex]::Escape($credentialUrl))
    $metadata | Should -Not -Match ([regex]::Escape($queryUrl))
    $metadata | Should -Match '\[credential-bearing URL redacted\]'
  }

function Test-WingetOmitsThePrivateSourceEndpointFromStructuredResultMetadata {
    $credentialUrl = 'https://operator:do-not-log@packages.example.test/cache'
    $metadata = Get-PrivateSourceResultMetadata -Name 'corp' -Type 'Microsoft.Rest'

    $metadata.ContainsKey('Url') | Should -BeFalse
    $metadata.Endpoint | Should -Be '[not recorded]'
    ($metadata | ConvertTo-Json -Compress) | Should -Not -Match ([regex]::Escape($credentialUrl))
  }

function Test-WingetRequiresPositiveSourceIdentityEvidence {
    $sourceFunction = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Test-WingetSourcePresent'
    }, $true)

    $sourceFunction.Extent.Text | Should -Not -Match 'assumed present'
    $sourceFunction.Extent.Text | Should -Match 'Test-WingetSourceOutputContainsName'
  }

function Test-WingetMatchesOnlyTheExactWinGetSourceName {
    Test-WingetSourceOutputContainsName -Text "Name Argument`ncorp https://packages.example.test" -Name 'corp' | Should -BeTrue
    Test-WingetSourceOutputContainsName -Text 'Name: CORP' -Name 'corp' | Should -BeTrue
    Test-WingetSourceOutputContainsName -Text 'corporate https://packages.example.test' -Name 'corp' | Should -BeFalse
    Test-WingetSourceOutputContainsName -Text 'corp-prod https://packages.example.test' -Name 'corp' | Should -BeFalse
    Test-WingetSourceOutputContainsName -Text 'mycorp https://packages.example.test' -Name 'corp' | Should -BeFalse
  }
  }

  It 'checks an existing private source without requiring add-only configuration' { Test-WingetChecksAnExistingPrivateSourceWithoutRequiringAddOnlyConfiguration }

  It 'does not attempt to add a missing source in audit mode' { Test-WingetDoesNotAttemptToAddAMissingSourceInAuditMode }

  It 'guards every source update behind remediation mode and ShouldProcess' { Test-WingetGuardsEverySourceUpdateBehindRemediationModeAndShouldProcess }

  It 'does not let wrapper configuration grant remediation authority' { Test-WingetDoesNotLetWrapperConfigurationGrantRemediationAuthority }

  It 'requires endpoint-only private-source URLs and out-of-band authentication' {
    $script:ScriptSource | Should -Match 'without credentials, query, or fragment'
    $script:ScriptSource | Should -Match 'Configure source authentication out of band'
  }

  It 'redacts credential-bearing URLs from WinGet process metadata' { Test-WingetRedactsCredentialBearingURLsFromWinGetProcessMetadata }

  It 'omits the private-source endpoint from structured result metadata' { Test-WingetOmitsThePrivateSourceEndpointFromStructuredResultMetadata }

  It 'requires positive source identity evidence' { Test-WingetRequiresPositiveSourceIdentityEvidence }

  It 'matches only the exact WinGet source name' { Test-WingetMatchesOnlyTheExactWinGetSourceName }
}
