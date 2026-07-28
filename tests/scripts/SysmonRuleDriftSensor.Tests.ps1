#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

$script:SkipNonSystemWindowsIntegration = $false
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
  try {
    $script:SkipNonSystemWindowsIntegration =
      [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'
  } catch {
    $script:SkipNonSystemWindowsIntegration = $true
  }
}

Describe '17-Sysmon-Rule-Drift-Sensor hardened input and mode contract' -Tag 'SysmonRuleDriftSensor' {
  BeforeAll {
    $script:SensorScript = Join-Path $PSScriptRoot '../../scripts/17-Sysmon-Rule-Drift-Sensor.ps1'
    $script:SensorHelper = Join-Path $PSScriptRoot '../../scripts/internal/17-Sysmon-Rule-Drift-Sensor.helpers.ps1'
    Import-Module (Join-Path $PSScriptRoot '../../lib/EventLog.psm1') -Force
    . $script:SensorHelper
  }

  It 'fails unsupported hosts when Strict is requested' {
    $oldOS = $env:OS
    try {
      $env:OS = 'Unix'
      $output = & $script:SensorScript -Strict -PassThru -OutputFormat None -Quiet 2>&1 3>&1 6>&1
      $result = @($output | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'Result' })[-1]

      $LASTEXITCODE | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      $result.Metadata.UnsupportedHost | Should -BeTrue
    } finally {
      if ($null -eq $oldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue }
      else { $env:OS = $oldOS }
    }
  }

  It 'emits one V2 FAIL when explicit CatalogPath is <Name>' -TestCases @(
    @{ Name = 'missing'; Content = $null }
    @{ Name = 'invalid JSON'; Content = '{' }
    @{ Name = 'a scalar JSON value'; Content = '"not-a-catalog"' }
    @{ Name = 'a catalog with an unknown rule property'; Content = '{"Rules":[{"Id":1,"Unexpected":true}]}' }
    @{ Name = 'a catalog with duplicate rule IDs'; Content = '{"Rules":[{"Id":1},{"Id":1}]}' }
  ) {
    param([string]$Content)
    $oldOS = $env:OS
    try {
      $env:OS = 'Windows_NT'
      $catalogPath = Join-Path $TestDrive 'catalog.json'
      if ($null -ne $Content) { Set-Content -LiteralPath $catalogPath -Value $Content -Encoding UTF8 }
      $output = & $script:SensorScript -CatalogPath $catalogPath -PassThru -OutputFormat None -Quiet -Confirm:$false 2>&1 3>&1 6>&1
      $results = @($output | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'Result' })

      $LASTEXITCODE | Should -Be 1
      $results.Count | Should -Be 1
      $results[0].Result | Should -Be 'FAIL'
      $results[0].Findings.Count | Should -Be 1
      $results[0].Findings[0].Code | Should -Be 'SYS-CatalogInvalid'
    } finally {
      if ($null -eq $oldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue }
      else { $env:OS = $oldOS }
    }
  }

  It 'accepts optional null rule fields and zero-valued thresholds without treating them as invalid policy' -Skip:$script:SkipNonSystemWindowsIntegration {
    $oldOS = $env:OS
    try {
      $env:OS = 'Windows_NT'
      $catalogPath = Join-Path $TestDrive 'valid-optional-catalog.json'
      Set-Content -LiteralPath $catalogPath -Encoding UTF8 -Value '{"RatioFloor":0,"MinBaselineToCompare":0,"Rules":[{"Id":1,"MinPerWindow":null,"MessageRegex":null}]}'
      Mock Get-SysmonStatePath { Join-Path $TestDrive 'rule-drift-sensor-state.json' }

      $output = & $script:SensorScript -CatalogPath $catalogPath -PassThru -OutputFormat None -Quiet -Confirm:$false 2>&1 3>&1 6>&1
      $result = @($output | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'Result' })[-1]

      $result | Should -Not -BeNullOrEmpty
      @($result.Findings | Where-Object Code -eq 'SYS-CatalogInvalid').Count | Should -Be 0
    } finally {
      if ($null -eq $oldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue }
      else { $env:OS = $oldOS }
    }
  }

  It 'rejects an explicit catalog larger than 256 KiB before parsing it' {
    $oldOS = $env:OS
    try {
      $env:OS = 'Windows_NT'
      $catalogPath = Join-Path $TestDrive 'oversized-catalog.json'
      Set-Content -LiteralPath $catalogPath -Encoding UTF8 -NoNewline -Value ('{' + (' ' * 262145) + '}')

      $output = & $script:SensorScript -CatalogPath $catalogPath -PassThru -OutputFormat None -Quiet -Confirm:$false 2>&1 3>&1 6>&1
      $results = @($output | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'Result' })

      $LASTEXITCODE | Should -Be 1
      $results | Should -HaveCount 1
      $results[0].Findings[0].Code | Should -Be 'SYS-CatalogInvalid'
    } finally {
      if ($null -eq $oldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue }
      else { $env:OS = $oldOS }
    }
  }

  It 'keeps query failures distinct from zero-count hard-zero rules in source' {
    $source = (Get-Content -LiteralPath $script:SensorScript -Raw), (Get-Content -LiteralPath $script:SensorHelper -Raw) -join [Environment]::NewLine

    $source | Should -Match 'Success = \$false; Count = \$null; Error = \$_.Exception.Message'
    $source | Should -Match "Status 'QUERY_ERROR'"
    $source | Should -Match '-not \$eventQueryFailed'
  }

  It 'gates channel enablement and reapply remediation to Remediate mode with a locked trusted closure' {
    $source = (Get-Content -LiteralPath $script:SensorScript -Raw), (Get-Content -LiteralPath $script:SensorHelper -Raw) -join [Environment]::NewLine

    $source | Should -Match '\$Mode -ne ''Remediate'' -or -not \$AttemptEnableChannel'
    $source | Should -Match '\$Mode -eq ''Remediate'' -and \$TriggerReapply -and \$evidenceComplete -and \$overallStatus -ne ''ERROR'''
    $source | Should -Match 'IsNullOrWhiteSpace\(\$RemediationScriptPath\)'
    $source | Should -Match '\$RemediationScriptPath = Join-Path \$PSScriptRoot ''16-Sysmon-Config-Updater\.ps1'''
    $source | Should -Match 'Remediation execution is restricted to 16-Sysmon-Config-Updater\.ps1'
    $source | Should -Match 'SpecialFolder\]::System'
    $source | Should -Match '''WindowsPowerShell\\v1\.0\\powershell\.exe'''
    $source | Should -Match 'Assert-TrustedWindowsPathAcl -Path \$windowsPowerShell -CheckAncestors'
    $source | Should -Match 'Invoke-NativeCommand -Command \$windowsPowerShell'
    $source | Should -Match '\[IO\.FileMode\]::Open'
    $source | Should -Not -Match '\[IO\.FileMode\]::CreateNew'
    $source | Should -Match '\[IO\.FileShare\]::Read'
    $source | Should -Match 'Get-SysmonRemediationExecutionClosure'
    $source | Should -Match 'Assert-LockedSysmonRemediationClosure'
    $source | Should -Match 'Assert-TrustedWindowsPathAcl -Path \$item\.FullName -CheckAncestors'
    $source | Should -Match "'16-Sysmon-Config-Updater\.ps1'"
    $source | Should -Match '16-Sysmon-Config-Updater\.helpers\.ps1'
    $source | Should -Match 'Bootstrap\.ps1'
    $source | Should -Match "'Validation\.psm1'"
    $source | Should -Not -Match 'Get-ChildItem -LiteralPath \(Join-Path \(Split-Path -Parent \$ScriptPath\) ''\.\.\\\\lib''\)'
    $lockIndex = $source.IndexOf('$stage.Streams += [IO.File]::Open')
    $aclIndex = $source.IndexOf('Assert-LockedSysmonRemediationClosure -ClosurePaths $closurePaths')
    $signatureIndex = $source.IndexOf('Get-AuthenticodeSignature -FilePath $ScriptPath')
    $invokeIndex = $source.IndexOf('Invoke-NativeCommand -Command $windowsPowerShell')
    $lockIndex | Should -BeLessThan $aclIndex
    $aclIndex | Should -BeLessThan $signatureIndex
    $signatureIndex | Should -BeLessThan $invokeIndex
    $source | Should -Match '-not \$native\.OutputTruncated -and -not \$native\.StderrTruncated'
    $source | Should -Not -Match 'SpecialFolder\]::Windows'
    $source | Should -Match 'closurePaths'
    $source | Should -Not -Match 'Join-Path \$env:WINDIR'
  }

  It 'rejects the remediation closure when a child ACL is untrusted' -Skip:([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    $scriptsDirectory = Join-Path $TestDrive 'scripts'
    $internalDirectory = Join-Path $scriptsDirectory 'internal'
    $libDirectory = Join-Path $TestDrive 'lib'
    New-Item -ItemType Directory -Path $internalDirectory, $libDirectory -Force | Out-Null
    $entryScript = Join-Path $scriptsDirectory '16-Sysmon-Config-Updater.ps1'
    $childPath = Join-Path $internalDirectory '16-Sysmon-Config-Updater.helpers.ps1'
    Set-Content -LiteralPath $entryScript -Value '# fixture' -Encoding UTF8
    Set-Content -LiteralPath $childPath -Value '# fixture' -Encoding UTF8
    Mock Assert-TrustedWindowsPathAcl { Get-Item -LiteralPath $Path -Force } -ParameterFilter { $Path -ne $childPath }
    Mock Assert-TrustedWindowsPathAcl { throw "Path ACL is not trusted for privileged execution: $Path" } -ParameterFilter { $Path -eq $childPath }
    { Assert-LockedSysmonRemediationClosure -ClosurePaths @($entryScript, $childPath) -RepositoryRoot $TestDrive } | Should -Throw '*not trusted*'
  }

  It 'promotes an attempted failed HARDZERO remediation to ERROR and V2 FAIL' {
    $oldOS = $env:OS
    try {
      $env:OS = 'Windows_NT'
      $statePath = Join-Path $TestDrive 'rule-drift-sensor-state.json'
      $remediationPath = Join-Path $TestDrive '16-Sysmon-Config-Updater.ps1'

      Mock Get-SysmonStatePath { $statePath }
      Mock Ensure-EventSource { $true }
      Mock Get-ExplicitCatalog {
        [pscustomobject]@{
          Rules = @(
            [pscustomobject]@{
              Id = 1
              Name = 'Process Create'
              Critical = $true
              MinPerWindow = 1
              MessageRegex = $null
              Disabled = $false
            }
          )
        }
      }
      Mock Get-SysmonChannelStatus {
        [pscustomobject]@{
          LogName = 'Microsoft-Windows-Sysmon/Operational'
          Exists = $true
          Enabled = $true
          MaxSize = 1048576
          OldestRecord = $null
          Error = $null
        }
      }
      Mock Enable-SysmonChannelIfRequested { $ChannelStatus }
      Mock Read-ValidatedSysmonState { $null }
      Mock Get-BoundedSysmonEventEvidence {
        [pscustomobject]@{
          Complete = $true
          Truncated = $false
          TimedOut = $false
          Error = $null
          EventIds = @(1, 16)
          EventsRead = 0
          MaximumEvents = 50000
          MaximumSeconds = 30
          ElapsedMilliseconds = 1
          Events = @()
        }
      }
      Mock Get-EventCountFromEvidence {
        [pscustomobject]@{ Success = $true; Count = 0; Error = $null }
      }
      Mock Write-SysmonState { }
      Mock Invoke-RemediationScript {
        [pscustomobject]@{
          Attempted = $true
          Success = $false
          ExitCode = 7
          Error = 'simulated remediation failure'
          ScriptPath = $remediationPath
        }
      }
      Mock Write-AuditEvent { }

      $output = & $script:SensorScript -Mode Remediate -CatalogPath 'mock-catalog.json' -StatePath $statePath `
        -TriggerReapply -RemediationScriptPath $remediationPath -PassThru -OutputFormat None -Quiet -Confirm:$false 2>&1 3>&1 6>&1
      $result = @($output | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'Result' })[-1]

      $LASTEXITCODE | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      $result.Summary.Status | Should -Be 'ERROR'
      $result.Summary.Remediation.Attempted | Should -BeTrue
      $result.Summary.Remediation.Success | Should -BeFalse
      $result.Summary.Remediation.ExitCode | Should -Be 7
      $result.Summary.Remediation.Error | Should -Be 'simulated remediation failure'
      Should -Invoke Invoke-RemediationScript -Times 1 -Exactly -Scope It -ParameterFilter { $ScriptPath -eq $remediationPath }
    } finally {
      if ($null -eq $oldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue }
      else { $env:OS = $oldOS }
    }
  }
}

Describe '17-Sysmon-Rule-Drift-Sensor evidence and state integrity' -Tag 'SysmonRuleDriftSensor' {
  BeforeAll {
    $script:SensorScript = Join-Path $PSScriptRoot '../../scripts/17-Sysmon-Rule-Drift-Sensor.ps1'
    $script:SensorHelper = Join-Path $PSScriptRoot '../../scripts/internal/17-Sysmon-Rule-Drift-Sensor.helpers.ps1'
    . $script:SensorHelper
  }

  It 'keeps ERROR above anomalies and OK when query evidence is mixed' {
    $mixed = @(
      [pscustomobject]@{ Status = 'HARDZERO' },
      [pscustomobject]@{ Status = 'QUERY_ERROR' }
    )

    Resolve-SysmonOverallStatus -Rules $mixed -StateWriteOk $true -EvidenceComplete $true | Should -Be 'ERROR'
    Resolve-SysmonOverallStatus -Rules @([pscustomobject]@{ Status = 'LOW' }) -StateWriteOk $true -EvidenceComplete $true | Should -Be 'ANOMALIES_DETECTED'
    Resolve-SysmonOverallStatus -Rules @([pscustomobject]@{ Status = 'OK' }) -StateWriteOk $true -EvidenceComplete $true | Should -Be 'OK'
  }

  It 'rejects forged sensor state versions and unsupported fields' {
    $state = [pscustomobject]@{
      Version = 2
      HostName = 'host'
      Timestamp = '2026-01-01T00:00:00'
      WindowHours = 24
      Alpha = [double]0.3
      Baseline = [pscustomobject]@{ '1' = [double]4 }
      ConfigChanged = $false
      CatalogSource = 'test'
    }

    { Assert-SysmonSensorStateSchema -State $state } | Should -Throw '*Version*'
    $state.Version = 1
    $state | Add-Member -NotePropertyName Unexpected -NotePropertyValue $true
    { Assert-SysmonSensorStateSchema -State $state } | Should -Throw '*missing or unsupported*'
  }

  It 'uses one unique-ID query with global count and time budgets' {
    $source = Get-Content -LiteralPath $script:SensorHelper -Raw
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
      $script:SensorHelper,
      [ref]$tokens,
      [ref]$parseErrors
    )
    @($parseErrors) | Should -HaveCount 0
    @($tokens | Where-Object {
        $_.Kind -eq [System.Management.Automation.Language.TokenKind]::StringLiteral -and
        $_.Value -eq 'Get-WinEvent'
      }) | Should -HaveCount 1
    $source | Should -Match 'Sort-Object -Unique'
    $source | Should -Match 'AddParameter\(''MaxEvents'',\(\$MaximumEvents \+ 1\)\)'
    $source | Should -Match 'AsyncWaitHandle\.WaitOne'
    $source | Should -Match 'MaximumSeconds'
    $source | Should -Match 'Diagnostics\.Stopwatch'
    $source | Should -Match 'Truncated = \$truncated'
    $source | Should -Match 'TimedOut = \$timedOut'
  }

  It 'deduplicates IDs and marks the single bounded query incomplete when it truncates' {
    $script:SysmonLogName = 'Microsoft-Windows-Sysmon/Operational'
    Mock Invoke-BoundedSysmonEventQuery {
      [pscustomobject]@{
        Events = @(
          [pscustomobject]@{ Id = 1; Message = 'one' },
          [pscustomobject]@{ Id = 16; Message = 'two' },
          [pscustomobject]@{ Id = 1; Message = 'three' },
          [pscustomobject]@{ Id = 16; Message = 'overflow' }
        )
        Error = $null
        TimedOut = $false
        ElapsedMilliseconds = 1
      }
    }

    $evidence = Get-BoundedSysmonEventEvidence -EventIds @(16,1,16) -StartTime (Get-Date).AddHours(-1) -MaximumEvents 3 -MaximumSeconds 30

    $evidence.EventIds | Should -Be @(1,16)
    $evidence.EventsRead | Should -Be 3
    $evidence.Truncated | Should -BeTrue
    $evidence.Complete | Should -BeFalse
    Should -Invoke Invoke-BoundedSysmonEventQuery -Times 1 -Exactly -Scope It -ParameterFilter { $FilterHashtable.ID.Count -eq 2 -and $MaximumEvents -eq 3 -and $MaximumSeconds -eq 30 }
  }

  It 'uses SID allowlisting, protected ACLs, and a bounded closed state reader' {
    $source = Get-Content -LiteralPath $script:SensorHelper -Raw
    $source | Should -Match "'S-1-5-18','S-1-5-32-544'"
    $source | Should -Match 'Translate\(\[Security\.Principal\.SecurityIdentifier\]\)'
    $source | Should -Match 'AreAccessRulesProtected'
    $source | Should -Match 'MaximumBytes 65536'
    $source | Should -Match 'Assert-SysmonSensorStateSchema'
    $source | Should -Match 'FileSystemAclExtensions\]::Create'
    $source | Should -Match 'New-TrustedStateDirectory'
    $source | Should -Match 'PropagationFlags\]::InheritOnly'
    $source | Should -Not -Match 'Everyone\|Users\|Authenticated Users\|Guests'
  }

  It 'allows effective Users ReadAndExecute but rejects an atomic Users WriteData ACE' -Skip:([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    $path = Join-Path $TestDrive 'trusted-state-acl'
    New-Item -Path $path -ItemType Directory -Force | Out-Null
    try {
      $administrators = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
      $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
      $users = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
      $creatorOwner = New-Object Security.Principal.SecurityIdentifier('S-1-3-0')
      $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
      $security = New-Object Security.AccessControl.DirectorySecurity
      $security.SetOwner($administrators)
      $security.SetAccessRuleProtection($true, $false)
      foreach ($sid in @($administrators, $system)) {
        [void]$security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
              $sid,
              [Security.AccessControl.FileSystemRights]::FullControl,
              $inheritance,
              [Security.AccessControl.PropagationFlags]::None,
              [Security.AccessControl.AccessControlType]::Allow)))
      }
      [void]$security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $creatorOwner,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::InheritOnly,
            [Security.AccessControl.AccessControlType]::Allow)))
      [void]$security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $users,
            ([Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
              [Security.AccessControl.FileSystemRights]::Synchronize),
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)))
      Set-Acl -LiteralPath $path -AclObject $security -ErrorAction Stop
    } catch {
      Set-ItResult -Skipped -Because "The current Windows test identity cannot create the required ACL fixture: $($_.Exception.Message)"
      return
    }

    { Assert-TrustedStateAcl -Path $path } | Should -Not -Throw
    $unsafe = Get-Acl -LiteralPath $path
    [void]$unsafe.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
          $users,
          [Security.AccessControl.FileSystemRights]::WriteData,
          $inheritance,
          [Security.AccessControl.PropagationFlags]::None,
          [Security.AccessControl.AccessControlType]::Allow)))
    Set-Acl -LiteralPath $path -AclObject $unsafe -ErrorAction Stop
    { Assert-TrustedStateAcl -Path $path } | Should -Throw "*untrusted SID 'S-1-5-32-545'*"
  }

  It 'cannot write state or remediate from incomplete evidence' {
    $source = Get-Content -LiteralPath $script:SensorScript -Raw
    $source | Should -Match 'if \(\$evidenceComplete\) \{[\s\S]*Write-SysmonState'
    $source | Should -Match '\$TriggerReapply -and \$evidenceComplete'
    $source | Should -Match 'Resolve-SysmonOverallStatus[^\r\n]+-EvidenceComplete \$evidenceComplete'
  }
}
