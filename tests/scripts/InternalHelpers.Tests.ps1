#requires -version 5.1
<#
.SYNOPSIS
  Pester tests for scripts/internal/ helper files.

.DESCRIPTION
  Dot-sources each helper file and validates that all exported functions are
  callable and return expected types. Tests focus on pure/stateless helpers
  with no external OS dependencies.
#>

[CmdletBinding()]
param()

$script:SkipNonSystemWindowsIntegration = $false
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
  try {
    $script:SkipNonSystemWindowsIntegration =
      [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'
  } catch {
    $script:SkipNonSystemWindowsIntegration = $true
  }
}

Describe 'Extracted script helpers' {
  It 'keeps each helper parseable and dot-sourced by its main script' -ForEach @(
    @{ Main = '00-Copy-Local.ps1'; Helper = '00-Copy-Local.helpers.ps1'; Functions = @('Invoke-GitCommand', 'Test-CopyLocalBlockedGitEnvironmentName', 'Get-CopyLocalSafeGitEnvironment', 'Enable-CopyLocalSafeGitEnvironment', 'Restore-CopyLocalGitEnvironment', 'Get-FullPath', 'Test-RepoPathOverlapsDeploymentTarget', 'Remove-CopyLocalCommittedBackup', 'Restore-CopyLocalDeploymentSwaps') }
    @{ Main = '16-Sysmon-Config-Updater.ps1'; Helper = '16-Sysmon-Config-Updater.helpers.ps1'; Functions = @('Test-ManifestPolicy', 'New-StagedTrustedSysmonExecutable', 'Ensure-SysmonChannel') }
    @{ Main = '17-Sysmon-Rule-Drift-Sensor.ps1'; Helper = '17-Sysmon-Rule-Drift-Sensor.helpers.ps1'; Functions = @('Resolve-RemediationScriptPath', 'Invoke-RemediationScript') }
  ) {
    param($Main, $Helper, $Functions)
    $scriptsDir = Join-Path $PSScriptRoot '../../scripts'
    $mainPath = Join-Path $scriptsDir $Main
    $helperPath = Join-Path $scriptsDir (Join-Path 'internal' $Helper)
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($helperPath, [ref]$tokens, [ref]$errors)

    $errors | Should -BeNullOrEmpty
    (Get-Content -LiteralPath $mainPath -Raw -Encoding UTF8) | Should -Match ([regex]::Escape($Helper))
    $defined = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object Name)
    foreach ($functionName in $Functions) {
      $defined | Should -Contain $functionName
    }
  }
}

# ---------------------------------------------------------------------------
# 04 - OfficeBrowser helpers
# ---------------------------------------------------------------------------
Describe '04 OfficeBrowser helpers' {
  BeforeAll {
    $helperPath = Join-Path $PSScriptRoot '../../scripts/internal/04-OfficeBrowser-Hardening-Proof.helpers.ps1'
    . $helperPath
  }

  Context 'Get-TextOrNull' {
    It 'returns null for null input' {
      Get-TextOrNull -Value $null | Should -BeNullOrEmpty
    }

    It 'returns null for empty string' {
      Get-TextOrNull -Value '' | Should -BeNullOrEmpty
    }

    It 'returns null for whitespace-only string' {
      Get-TextOrNull -Value '   ' | Should -BeNullOrEmpty
    }

    It 'returns the string for non-empty input' {
      Get-TextOrNull -Value 'hello' | Should -Be 'hello'
    }
  }

  Context 'Get-BoolDefault' {
    It 'returns default when value is null' {
      Get-BoolDefault -Value $null -Default $true | Should -Be $true
      Get-BoolDefault -Value $null -Default $false | Should -Be $false
    }

    It 'converts truthy value to true' {
      Get-BoolDefault -Value $true -Default $false | Should -Be $true
    }

    It 'converts falsy value to false' {
      Get-BoolDefault -Value $false -Default $true | Should -Be $false
    }
  }

  Context 'Get-IntDefault' {
    It 'returns default when value is null' {
      Get-IntDefault -Value $null -Default 42 | Should -Be 42
    }

    It 'converts numeric value' {
      Get-IntDefault -Value 7 -Default 0 | Should -Be 7
    }
  }

  Context 'Get-ArrayStrings' {
    It 'returns empty array for null' {
      $result = @(Get-ArrayStrings -Value $null)
      $result.Count | Should -Be 0
    }

    It 'returns string array for array input' {
      $result = Get-ArrayStrings -Value @('a', 'b')
      $result.Count | Should -Be 2
    }
  }

  Context 'Get-ProofItem' {
    It 'returns a PSCustomObject' {
      $item = Get-ProofItem -Product 'Office' -Area 'Macro' -Policy 'BlockVBA' `
        -Target 'HKLM:\...' -Name 'BlockMacros' -Type 'DWord' -Expected 1 -Actual 1 -Compliant $true
      $item | Should -Not -BeNullOrEmpty
      $item.PSObject.TypeNames | Should -Contain 'System.Management.Automation.PSCustomObject'
    }

    It 'carries the Name field' {
      $item = Get-ProofItem -Product 'Edge' -Area 'Security' -Policy 'SmartScreen' `
        -Target 'HKLM:\...' -Name 'SmartScreenEnabled' -Type 'DWord' -Expected 1 -Actual 1 -Compliant $true
      $item.Name | Should -Be 'SmartScreenEnabled'
    }
  }

  Context 'Get-ResultSummary' {
    It 'returns a PSCustomObject with Section and Ok fields' {
      $item = Get-ProofItem -Product 'Edge' -Area 'Security' -Policy 'SmartScreen' `
        -Target 'HKLM:\...' -Name 'SmartScreenEnabled' -Type 'DWord' -Expected 1 -Actual 1 -Compliant $true
      $s = Get-ResultSummary -Section 'Edge' -Items @($item)
      $s | Should -Not -BeNullOrEmpty
      $s.Section | Should -Be 'Edge'
      $s.Ok | Should -Be $true
      $s.NonCompliant | Should -Be 0
    }

    It 'sets Ok false when any item is non-compliant' {
      $item = Get-ProofItem -Product 'Edge' -Area 'Security' -Policy 'SmartScreen' `
        -Target 'HKLM:\...' -Name 'SmartScreenEnabled' -Type 'DWord' -Expected 1 -Actual 0 -Compliant $false
      $s = Get-ResultSummary -Section 'Edge' -Items @($item)
      $s.Ok | Should -Be $false
      $s.NonCompliant | Should -Be 1
    }
  }

  Context 'functions are dot-sourceable and defined' {
    It 'exports all expected function names' {
      $expected = @(
        'Get-TextOrNull', 'Get-BoolDefault', 'Get-IntDefault', 'Get-ArrayStrings',
        'Convert-RegValue', 'Get-ProofItem', 'Get-EdgeBaseKey', 'Has-Prop',
        'Get-EdgePolicyDefinitions', 'Get-EdgeStartupUrlMap', 'Get-EdgeStartupUrlValues',
        'Get-EdgeStartupUrlAuditProofItems', 'Clear-EdgeStartupUrlValues', 'Set-EdgeStartupUrlProof',
        'Bool-Prop', 'Ensure-ProofItemLike', 'Get-ResultSummary', 'Load-Catalog'
      )
      foreach ($fn in $expected) {
        Get-Command -Name $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$fn must be defined after dot-sourcing"
      }
    }
  }
}

# ---------------------------------------------------------------------------
# 09 - SupportBundle helpers
# ---------------------------------------------------------------------------
Describe '09 SupportBundle helpers' {
  BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/Output.psm1') -Force
    $helperPath = Join-Path $PSScriptRoot '../../scripts/internal/09-SupportBundle.helpers.ps1'
    . $helperPath
  }

  Context 'SB_NewRecord' {
    It 'creates a record with Name, Ok, ArtifactPath properties' {
      $rec = SB_NewRecord -Name 'TestRecord' -Ok $true -ArtifactPath 'C:\test.log' -Note ''
      $rec.Name | Should -Be 'TestRecord'
      $rec.Ok   | Should -Be $true
    }

    It 'creates a failed record' {
      $rec = SB_NewRecord -Name 'FailRecord' -Ok $false -ArtifactPath '' -Note 'something failed'
      $rec.Ok | Should -Be $false
    }
  }

  Context 'SB_NewDefaultConfig' {
    It 'returns a config object with Paths.ProofDir set' {
      $cfg = SB_NewDefaultConfig -ProofDirDefault 'C:\Temp\Proof'
      $cfg | Should -Not -BeNullOrEmpty
      $cfg.Paths.ProofDir | Should -Be 'C:\Temp\Proof'
    }
  }

  Context 'trusted SupportBundle proof paths' {
    It 'derives the default root from CommonApplicationData rather than a temporary directory' {
      $oldProgramData = $env:ProgramData
      try {
        $env:ProgramData = $TestDrive
        $root = SB_GetDefaultTrustedOutputRoot
      } finally {
        $env:ProgramData = $oldProgramData
      }
      $commonData = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
      } else {
        $TestDrive
      }
      $root | Should -Be (Join-Path (Join-Path $commonData 'BaselineOpsForWindows') 'SupportBundles')
    }

    It 'rejects a configured proof file outside the trusted root' {
      $root = Join-Path $TestDrive 'proof-root'
      New-Item -ItemType Directory -Path $root -Force | Out-Null
      { SB_ResolveTrustedProofFile -ConfiguredPath (Join-Path $TestDrive 'outside.json') -TrustedRoot $root -ExpectedFileName 'SysmonState.json' -PropertyName 'SysmonState' } |
        Should -Throw
    }

    It 'rejects a configured proof directory even when its name is expected' {
      $root = Join-Path $TestDrive 'proof-root'
      New-Item -ItemType Directory -Path $root -Force | Out-Null
      New-Item -ItemType Directory -Path (Join-Path $root 'SysmonState.json') | Out-Null
      { SB_ResolveTrustedProofFile -ConfiguredPath 'SysmonState.json' -TrustedRoot $root -ExpectedFileName 'SysmonState.json' -PropertyName 'SysmonState' } |
        Should -Throw
    }

    It 'rejects a configured proof symlink when the platform permits creating one' {
      $root = Join-Path $TestDrive 'proof-root'
      New-Item -ItemType Directory -Path $root -Force | Out-Null
      $link = Join-Path $root 'SysmonState.json'
      try {
        New-Item -ItemType SymbolicLink -Path $link -Target (Join-Path $TestDrive 'outside.json') -ErrorAction Stop | Out-Null
      } catch {
        Set-ItResult -Skipped -Because 'Symbolic links are unavailable to this test host.'
        return
      }
      { SB_ResolveTrustedProofFile -ConfiguredPath 'SysmonState.json' -TrustedRoot $root -ExpectedFileName 'SysmonState.json' -PropertyName 'SysmonState' } |
        Should -Throw
    }

    It 'fails an explicit unreadable or wrong-schema config instead of substituting defaults' {
      $path = Join-Path $TestDrive 'wrong-schema.json'
      '{"Paths":{"ProofDir":"C:\\unsafe"},"Unexpected":true}' | Set-Content -LiteralPath $path -Encoding UTF8
      $result = SB_LoadJsonConfig -Path $path -DefaultConfig (SB_NewDefaultConfig -ProofDirDefault $TestDrive)
      $result.Ok | Should -BeFalse
      $result.Error | Should -Match 'unsupported property|must contain'
    }
  }

  Context 'functions are dot-sourceable and defined' {
    It 'exports all expected function names' {
      $expected = @(
        'SB_WriteLog', 'SB_NewRecord',
        'SB_NewSummary', 'SB_AddRecord', 'SB_NewDefaultConfig',
        'SB_TryStep', 'SB_LoadJsonConfig', 'SB_AssertTrustedOutputRoot', 'SB_AssertTrustedChildDirectory',
        'SB_GetDefaultTrustedOutputRoot', 'SB_SetRestrictedDirectoryAcl', 'SB_ResolveTrustedProofFile', 'SB_TryGetRegValue'
      )
      foreach ($fn in $expected) {
        Get-Command -Name $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$fn must be defined after dot-sourcing"
      }
    }

    It 'does not redefine shared lib helper wrappers' {
      $removed = @('SB_WriteUi', 'SB_IsAdmin', 'SB_EnsureDir', 'SB_SafeFileName')
      foreach ($fn in $removed) {
        Get-Command -Name $fn -ErrorAction SilentlyContinue | Should -BeNullOrEmpty -Because "$fn must come from lib helpers or direct calls now"
      }
    }
  }
}

# ---------------------------------------------------------------------------
# 12 - SuspiciousArtifactGrabber helpers
# ---------------------------------------------------------------------------
Describe '11 IOC sweep helpers' {
  BeforeAll {
    $helperPath = Join-Path $PSScriptRoot '../../scripts/internal/11-IOC-Sweep-Defender.helpers.ps1'
    . $helperPath
  }

  It 'precompiles catalog regexes with a finite timeout' {
    $regex = New-IocRegex -Pattern '^safe$' -Label 'test'
    $regex.IsMatch('safe') | Should -BeTrue
    $regex.MatchTimeout.TotalMilliseconds | Should -Be 250
  }

  It 'rejects oversized or invalid catalog regexes before scanning' {
    { New-IocRegex -Pattern ('a' * 1025) -Label 'test' } | Should -Throw '*1024-character limit*'
    { New-IocRegex -Pattern '(' -Label 'test' } | Should -Throw '*invalid*'
  }
}

Describe '21 EmergencyKillSwitch helpers' {
  BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../lib/Results.psm1') -Force
    $script:Run = [pscustomobject]@{ Errors = (New-Object System.Collections.Generic.List[string]); Actions = @{}; Effective = @{}; Outcome = @{} }
    $script:Findings = Get-FindingsList
    function Add-RunError { param([string]$Message) [void]$script:Run.Errors.Add($Message) }
    function global:Get-NetFirewallRule { [pscustomobject]@{ Name = 'owner-unknown' } }
    function global:New-NetFirewallRule { throw 'must not replace an existing rule' }
    . (Join-Path $PSScriptRoot '../../scripts/internal/21-EmergencyKillSwitch.helpers.ps1')
  }

  AfterAll {
    Remove-Item -LiteralPath Function:\Get-NetFirewallRule -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath Function:\New-NetFirewallRule -ErrorAction SilentlyContinue
  }

  It 'preserves an owner-unknown colliding firewall rule' {
    (New-OrReplaceRule -Name 'existing-rule' -DisplayName 'test' -Direction Inbound -Action Block -Confirm:$false) | Should -BeFalse
    @($script:Run.Errors | Where-Object { $_ -match 'refusing to replace owner-unknown' }).Count | Should -Be 1
    @($script:Findings.ToArray() | Where-Object Code -eq 'Firewall-RuleCollision').Count | Should -Be 1
  }
}

Describe '12 SuspiciousArtifactGrabber helpers' {
  BeforeAll {
    $helperPath = Join-Path $PSScriptRoot '../../scripts/internal/12-Suspicious-Artifact-Grabber.helpers.ps1'
    . $helperPath
  }

  Context 'Safe-ToInt' {
    It 'returns default for null' {
      Safe-ToInt -Value $null -Default 5 | Should -Be 5
    }

    It 'converts integer string' {
      Safe-ToInt -Value '42' -Default 0 | Should -Be 42
    }

    It 'returns default for unconvertible value' {
      Safe-ToInt -Value 'not-a-number' -Default 99 | Should -Be 99
    }
  }

  Context 'Safe-ToBool' {
    It 'returns default for null' {
      Safe-ToBool -Value $null -Default $true | Should -Be $true
    }

    It 'converts true value' {
      Safe-ToBool -Value $true -Default $false | Should -Be $true
    }
  }

  Context 'Get-ResultObject' {
    It 'creates object with correct Name' {
      $obj = Get-ResultObject -Name 'TestScan'
      $obj.Name | Should -Be 'TestScan'
    }

    It 'initializes Errors and Notes as empty lists' {
      $obj = Get-ResultObject -Name 'X'
      $obj.Errors.Count | Should -Be 0
      $obj.Notes.Count  | Should -Be 0
    }
  }

  Context 'Add-Error / Add-Note' {
    It 'appends an error message' {
      $obj = Get-ResultObject -Name 'X'
      Add-Error -res $obj -msg 'something broke'
      $obj.Errors.Count | Should -Be 1
      $obj.Errors[0]    | Should -Be 'something broke'
    }

    It 'appends a note message' {
      $obj = Get-ResultObject -Name 'X'
      Add-Note -res $obj -msg 'a note'
      $obj.Notes.Count | Should -Be 1
    }

    It 'ignores null/empty error message' {
      $obj = Get-ResultObject -Name 'X'
      Add-Error -res $obj -msg $null
      Add-Error -res $obj -msg ''
      $obj.Errors.Count | Should -Be 0
    }
  }

  Context 'Get-RunId' {
    It 'returns a collision-resistant timestamped identifier' {
      $first = Get-RunId
      $second = Get-RunId

      $first | Should -Match '^\d{8}-\d{6}-[a-f0-9]{32}$'
      $second | Should -Not -Be $first
    }
  }

  Context 'Get-BaseClone' {
    It 'returns a deep copy of the object' {
      $orig = [pscustomobject]@{ Foo = 'bar'; Nested = @{ X = 1 } }
      $clone = Get-BaseClone -Obj $orig
      $clone.Foo    | Should -Be 'bar'
      $clone.Nested.X | Should -Be 1
    }
  }

  Context 'DefaultCatalog' {
    It 'uses concrete defaults instead of placeholder paths' {
      [string]$DefaultCatalog.OutputBase | Should -Not -Match 'PATH/TO|PLACEHOLDER|TODO'
      [string]$DefaultCatalog.Trigger.Registry | Should -Not -Match 'PATH/TO|PLACEHOLDER|TODO'
      $DefaultCatalog.Trigger.FileFlag | Should -BeNullOrEmpty
    }

    It 'handles a null trigger file without activating collection' {
      $trigger = Read-Trigger -cat $DefaultCatalog

      $trigger.Want | Should -BeFalse
    }
  }

  Context 'catalog regex hardening' {
    It 'precompiles bounded patterns with a finite timeout' {
      $regex = New-ArtifactRegex -Pattern '^safe$' -Label 'test'
      $regex.IsMatch('safe') | Should -BeTrue
      $regex.MatchTimeout.TotalMilliseconds | Should -Be 250
    }

    It 'rejects oversized, invalid, and over-count catalog patterns before collection' {
      { New-ArtifactRegex -Pattern ('a' * 1025) -Label 'test' } | Should -Throw '*1024-character limit*'
      { New-ArtifactRegex -Pattern '(' -Label 'test' } | Should -Throw '*invalid*'
      $catalog = Get-BaseClone -Obj $DefaultCatalog
      $catalog.Tasks.SuspiciousRegex = @(1..257 | ForEach-Object { 'safe' })
      { Initialize-ArtifactRegexRules -Catalog $catalog } | Should -Throw '*at most 256 patterns*'
    }

    It 'times out catastrophic catalog matches instead of using unbounded matching' {
      $regex = New-ArtifactRegex -Pattern '^(a+)+$' -Label 'test'
      { $regex.IsMatch((('a' * 24000) + '!')) } | Should -Throw
    }
  }

  Context 'functions are dot-sourceable and defined' {
    It 'exports all expected function names' {
      $expected = @(
        'Get-ResultObject', 'Add-Error', 'Add-Note', 'Safe-ToInt', 'Safe-ToBool',
        'Get-RunId', 'Get-BaseClone', 'Merge-Catalog', 'Load-Catalog',
        'Read-Trigger', 'Collect-Processes'
      )
      foreach ($fn in $expected) {
        Get-Command -Name $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$fn must be defined after dot-sourcing"
      }
    }
  }
}

Describe '12 SuspiciousArtifactGrabber parent behavior' -Tag 'SuspiciousArtifactGrabber' -Skip:$script:SkipNonSystemWindowsIntegration {
  BeforeAll {
    $script:ArtifactGrabberScript = Join-Path $PSScriptRoot '../../scripts/12-Suspicious-Artifact-Grabber.ps1'
    Import-Module (Join-Path $PSScriptRoot '../../lib/EventLog.psm1') -Force
    $helperPath = Join-Path $PSScriptRoot '../../scripts/internal/12-Suspicious-Artifact-Grabber.helpers.ps1'
    . $helperPath

    function Invoke-ArtifactGrabberParentCase {
      param(
        [switch]$SuspiciousTask,
        [switch]$ProcessError,
        [switch]$InvalidRegex,
        [switch]$CatastrophicRegex,
        [switch]$MissingCatalog,
        [switch]$InvalidCatalogJson,
        [switch]$RemoteOutputBase,
        [switch]$NoTrigger
      )

      $oldOS = $env:OS
      $oldComputerName = $env:COMPUTERNAME
      Set-Variable -Name __ArtifactGrabberProcessError -Scope Global -Value ([bool]$ProcessError)
      try {
        $env:OS = 'Windows_NT'
        $env:COMPUTERNAME = 'TEST-HOST'

        Mock -CommandName Get-ArtifactEvidenceRoot -MockWith {
          Join-Path $TestDrive 'artifact-evidence'
        }
        Mock -CommandName Assert-TrustedWindowsPathAcl -MockWith { }

        $catalogPath = Join-Path $TestDrive ("grabber-catalog-{0}.json" -f [guid]::NewGuid().ToString('N'))
        $catalog = [ordered]@{
          OutputBase = $(if ($RemoteOutputBase) { '\\server\share\evidence' } else { Get-ArtifactEvidenceRoot })
          Trigger    = [ordered]@{
            Registry = 'HKLM:\Software\TestArtifactGrabber'
            FileFlag = (Join-Path $TestDrive 'missing.flag')
          }
          Samples    = [ordered]@{
            Enable = $false
          }
          Tasks      = [ordered]@{
            ExportXmlForSuspicious = $false
            SuspiciousRegex        = $(if ($InvalidRegex) { @('(') } elseif ($CatastrophicRegex) { @('^(a+)+$') } else { @('AppData') })
            MaxXml                 = 0
          }
        }
        if ($InvalidCatalogJson) {
          Set-Content -LiteralPath $catalogPath -Value '{ not json' -Encoding UTF8
        } elseif (-not $MissingCatalog) {
          $catalog | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $catalogPath -Encoding UTF8
        }

        function global:Get-ScheduledTask {
          Set-Variable -Name __ArtifactGrabberEnumerationReached -Scope Global -Value $true
          if (Get-Variable -Name __ArtifactGrabberSuspiciousTask -Scope Global -ValueOnly) {
            return @(
              [pscustomobject]@{
                TaskName  = 'SuspiciousTask'
                TaskPath  = '\'
                Principal = [pscustomobject]@{ UserId = 'SYSTEM' }
                Actions   = @(
                  [pscustomobject]@{
                    Execute   = $(if ($CatastrophicRegex) { (('a' * 24000) + '!') } else { 'C:\Users\alice\AppData\Roaming\bad.exe' })
                    Arguments = ''
                  }
                )
              }
            )
          }

          return @()
        }

        function global:Get-ScheduledTaskInfo {
          [pscustomobject]@{ State = 'Ready' }
        }

        function global:Get-CimInstance {
          param(
            [string]$ClassName,
            [string]$Namespace
          )
          [void]$Namespace

          if ((Get-Variable -Name __ArtifactGrabberProcessError -Scope Global -ValueOnly) -and $ClassName -eq 'Win32_Process') {
            throw 'process source unavailable'
          }

          return @()
        }

        function global:Get-NetTCPConnection {
          @()
        }

        function global:Get-NetUDPEndpoint {
          @()
        }

        function global:Get-NetIPConfiguration {
          @()
        }

        function global:Get-NetRoute {
          @()
        }

        function global:Get-DnsClientCache {
          @()
        }

        function global:Compress-Archive {
          param(
            [string[]]$Path,
            [string]$DestinationPath,
            [switch]$Force
          )
          [void]$Path
          [void]$DestinationPath
          [void]$Force
        }

        Set-Variable -Name __ArtifactGrabberSuspiciousTask -Scope Global -Value ([bool]$SuspiciousTask)
        Set-Variable -Name __ArtifactGrabberEnumerationReached -Scope Global -Value $false

        Mock -CommandName Ensure-EventSource -MockWith { }
        Mock -CommandName Write-HealthEvent -MockWith { $true }

        $runParameters = @{
          CatalogPath = $catalogPath
          OutputFormat = 'None'
          PassThru = $true
          Quiet = $true
          Confirm = $false
        }
        if (-not $NoTrigger) { $runParameters.Force = $true }
        $output = & $script:ArtifactGrabberScript @runParameters 2>&1 3>&1 6>&1
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
        Remove-Item -LiteralPath Function:\Get-ScheduledTask -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\Get-CimInstance -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\Get-NetTCPConnection -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\Get-NetUDPEndpoint -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\Get-NetIPConfiguration -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\Get-NetRoute -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\Get-DnsClientCache -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\Compress-Archive -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name __ArtifactGrabberSuspiciousTask -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name __ArtifactGrabberProcessError -ErrorAction SilentlyContinue
      }

      $result = @($output | Where-Object {
          $null -ne $_ -and
          $_.PSObject.Properties.Name -contains 'Result' -and
          $_.PSObject.Properties.Name -contains 'Summary'
        })[-1]
      $enumerationReached = Get-Variable -Name __ArtifactGrabberEnumerationReached -Scope Global -ValueOnly -ErrorAction SilentlyContinue
      Remove-Variable -Scope Global -Name __ArtifactGrabberEnumerationReached -ErrorAction SilentlyContinue

      [pscustomobject]@{
        ExitCode = $exitCode
        Result   = $result
        Text     = ($output | Out-String)
        EnumerationReached = $enumerationReached
      }
    }
  }

  It 'Surfaces suspicious task findings in the parent V2 result' {
    $run = Invoke-ArtifactGrabberParentCase -SuspiciousTask

    $run.Result.Result | Should -Be 'WARN'
    $run.Result.Summary.Counts.Tasks.Suspicious | Should -Be 1
    @($run.Result.Findings | Where-Object {
        $_.Code -eq 'Grabber-SuspiciousTask' -and $_.Severity -eq 'Medium'
      }).Count | Should -Be 1
  }

  It 'Reports helper collection errors as a failed parent V2 result' {
    $run = Invoke-ArtifactGrabberParentCase -ProcessError

    $run.Result.Result | Should -Be 'FAIL'
    @($run.Result.Summary.Errors | Where-Object { $_ -match 'process source unavailable' }).Count | Should -Be 1
  }

  It 'fails invalid catalog regexes before collection starts' {
    $run = Invoke-ArtifactGrabberParentCase -InvalidRegex

    $run.Result.Result | Should -Be 'FAIL'
    $run.EnumerationReached | Should -BeFalse
    $run.Result.Summary.Errors[0] | Should -Match 'regex is invalid'
  }

  It 'treats a catalog regex timeout as an incomplete-evidence failure' {
    $run = Invoke-ArtifactGrabberParentCase -CatastrophicRegex -SuspiciousTask

    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.Errors[0] | Should -Match 'incomplete evidence: regex match timed out'
  }

  It 'fails explicit unusable catalogs before artifact collection' -TestCases @(
    @{ Missing = $true; Invalid = $false }
    @{ Missing = $false; Invalid = $true }
  ) {
    param($Missing, $Invalid)
    $run = Invoke-ArtifactGrabberParentCase -MissingCatalog:$Missing -InvalidCatalogJson:$Invalid

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.Errors[0] | Should -Match 'Explicit artifact catalog'
    $run.EnumerationReached | Should -BeFalse
  }

  It 'rejects a UNC catalog OutputBase before collection starts' {
    $run = Invoke-ArtifactGrabberParentCase -RemoteOutputBase

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.Errors[0] | Should -Match 'UNC, device, or remote path'
    $run.EnumerationReached | Should -BeFalse
  }

  It 'returns one terminal V2 result when no collection trigger is set' {
    $run = Invoke-ArtifactGrabberParentCase -NoTrigger

    $run.ExitCode | Should -Be 0
    $run.Result.Result | Should -Be 'OK'
    $run.Result.Summary.Output.WorkDir | Should -BeNullOrEmpty
    $run.EnumerationReached | Should -BeFalse
  }
}
