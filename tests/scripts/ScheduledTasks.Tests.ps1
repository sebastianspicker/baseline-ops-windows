#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

Describe '07-ScheduledTasks-Hygiene pure helpers' {
  BeforeAll {
    . (Join-Path $PSScriptRoot '../../scripts/internal/07-ScheduledTasks-Hygiene.helpers.ps1')
  }

  It 'returns a property value or the requested default' {
    $item = [pscustomobject]@{ Name = 'Scheduled item' }

    Get-PropValue -Object $item -Name 'Name' -Default 'missing' | Should -BeExactly 'Scheduled item'
    Get-PropValue -Object $item -Name 'Absent' -Default 'missing' | Should -BeExactly 'missing'
  }

  It 'coalesces null and whitespace values without changing non-empty text' {
    Coalesce-String -Value $null -Default 'fallback' | Should -BeExactly 'fallback'
    Coalesce-String -Value '   ' -Default 'fallback' | Should -BeExactly 'fallback'
    Coalesce-String -Value 42 -Default 'fallback' | Should -BeExactly '42'
  }

  It 'normalizes task paths and full task identities deterministically' {
    Normalize-TaskPath -TaskPath $null | Should -BeExactly '\'
    Normalize-TaskPath -TaskPath 'Vendor\Product' | Should -BeExactly '\Vendor\Product\'
    Normalize-TaskPath -TaskPath '\Vendor\Product\' | Should -BeExactly '\Vendor\Product\'
    Normalize-FullTaskPath -TaskPath 'Vendor\Product' -TaskName 'HealthCheck' |
      Should -BeExactly '\Vendor\Product\HealthCheck'
  }
}

Describe '07-ScheduledTasks-Hygiene fail-loud behavior' {
  BeforeAll {
    $script:ScheduledTasksScript = Join-Path $PSScriptRoot '../../scripts/07-ScheduledTasks-Hygiene.ps1'
  }

  It 'Reports scheduled-task enumeration failure as WARN instead of compliant success' {
    $oldOS = $env:OS
    $catalogPath = Join-Path $TestDrive 'tasks-catalog.json'
    $proofPath = Join-Path $TestDrive 'tasks-proof.json'

    $catalog = @{
      CriticalTasks = @()
      AllowTaskExact = @()
      AllowActionPathPrefixes = @()
      DenyActionPathRegex = @()
      DenyCommandLineRegex = @()
      AllowPublisherOrgRegex = @()
      PurgeUnapproved = $false
      QuarantineDir = (Join-Path $TestDrive 'quarantine')
      Proof = @{ OutFile = $proofPath }
    }
    $catalog | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $catalogPath -Encoding UTF8

    try {
      $env:OS = 'Windows_NT'
      function global:Get-ScheduledTask {
        throw 'scheduled task enumeration failed'
      }

      $output = & $script:ScheduledTasksScript -CatalogPath $catalogPath -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
      $exitCode = $LASTEXITCODE
    } finally {
      if ($null -eq $oldOS) {
        Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue
      } else {
        $env:OS = $oldOS
      }
      Remove-Item -LiteralPath Function:\Get-ScheduledTask -ErrorAction SilentlyContinue
    }

    $result = @($output | Where-Object {
        $null -ne $_ -and
        $_.PSObject.Properties.Name -contains 'Result' -and
        $_.PSObject.Properties.Name -contains 'Findings'
      })[-1]
    $text = $output | Out-String

    $exitCode | Should -Be 2
    $result.Result | Should -Be 'WARN'
    $result.Summary.EnumerationSucceeded | Should -BeFalse
    $result.Summary.EnumerationError | Should -Match 'scheduled task enumeration failed'
    @($result.Findings | Where-Object { $_.Code -eq 'TASK-EnumerationFailed' }).Count | Should -Be 1
    $text | Should -Not -Match 'Scheduled tasks compliant'
  }

  It 'Reports a risky scheduled task as a machine-readable finding' {
    $oldOS = $env:OS
    $catalogPath = Join-Path $TestDrive 'risky-tasks-catalog.json'
    $proofPath = Join-Path $TestDrive 'risky-tasks-proof.json'

    $catalog = @{
      CriticalTasks = @()
      AllowTaskExact = @()
      AllowActionPathPrefixes = @('C:\Windows\')
      DenyActionPathRegex = @('(?i)\\Users\\[^\\]+\\AppData\\')
      DenyCommandLineRegex = @()
      AllowPublisherOrgRegex = @()
      PurgeUnapproved = $false
      QuarantineDir = (Join-Path $TestDrive 'quarantine')
      Proof = @{ OutFile = $proofPath }
    }
    $catalog | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $catalogPath -Encoding UTF8

    try {
      $env:OS = 'Windows_NT'
      function global:Test-IsAdmin { $true }
      function global:Get-ScheduledTask {
        [pscustomobject]@{
          TaskName = 'SuspiciousTask'
          TaskPath = '\'
        }
      }
      function global:Get-ScheduledTaskInfo {
        [pscustomobject]@{
          State = 'Ready'
          NextRunTime = $null
          LastRunTime = $null
          LastTaskResult = 0
        }
      }
      function global:Export-ScheduledTask {
        @'
<Task>
  <RegistrationInfo>
    <Author>attacker</Author>
  </RegistrationInfo>
  <Principals>
    <Principal>
      <UserId>SYSTEM</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Hidden>false</Hidden>
  </Settings>
  <Triggers />
  <Actions>
    <Exec>
      <Command>C:\Users\alice\AppData\Roaming\evil.exe</Command>
      <Arguments>-run</Arguments>
    </Exec>
  </Actions>
</Task>
'@
      }

      $output = & $script:ScheduledTasksScript -CatalogPath $catalogPath -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
      $exitCode = $LASTEXITCODE
    } finally {
      if ($null -eq $oldOS) {
        Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue
      } else {
        $env:OS = $oldOS
      }
      foreach ($name in @('Test-IsAdmin','Get-ScheduledTask','Get-ScheduledTaskInfo','Export-ScheduledTask')) {
        Remove-Item -LiteralPath "Function:\$name" -ErrorAction SilentlyContinue
      }
    }

    $result = @($output | Where-Object {
        $null -ne $_ -and
        $_.PSObject.Properties.Name -contains 'Result' -and
        $_.PSObject.Properties.Name -contains 'Findings'
      })[-1]

    $exitCode | Should -Be 2 -Because ($result | ConvertTo-Json -Depth 6)
    $result.Result | Should -Be 'WARN'
    $result.Summary.RiskyDetected | Should -Be 1
    @($result.Findings | Where-Object {
        $_.Code -eq 'TASK-Suspicious' -and
        $_.Message -match 'SuspiciousTask'
    }).Count | Should -Be 1
  }

  It 'rejects invalid external regexes before scheduled-task enumeration or remediation' {
    $oldOS = $env:OS
    $catalogPath = Join-Path $TestDrive 'invalid-regex-tasks-catalog.json'
    $catalog = @{ CriticalTasks = @('('); AllowTaskExact = @(); AllowActionPathPrefixes = @(); DenyActionPathRegex = @(); DenyCommandLineRegex = @(); AllowPublisherOrgRegex = @(); PurgeUnapproved = $true; QuarantineDir = (Join-Path $TestDrive 'quarantine'); Proof = @{ OutFile = (Join-Path $TestDrive 'proof.json') } }
    $catalog | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $catalogPath -Encoding UTF8
    try {
      $env:OS = 'Windows_NT'
      function global:Get-ScheduledTask { throw 'enumeration must not run for invalid regex' }
      $output = & $script:ScheduledTasksScript -CatalogPath $catalogPath -Mode Remediate -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
      $exitCode = $LASTEXITCODE
    } finally {
      if ($null -eq $oldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue } else { $env:OS = $oldOS }
      Remove-Item -LiteralPath Function:\Get-ScheduledTask -ErrorAction SilentlyContinue
    }
    $result = @($output | Where-Object { $null -ne $_ -and $_.PSObject.Properties.Name -contains 'Result' })[-1]
    $exitCode | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    $result.Summary.Error | Should -Match 'regex is invalid'
    ($output | Out-String) | Should -Not -Match 'enumeration must not run'
  }

  It 'fails an explicit unusable catalog before scheduled-task inventory' -TestCases @(
    @{ Kind = 'missing' }
    @{ Kind = 'invalid' }
  ) {
    param($Kind)
    $oldOS = $env:OS
    $catalogPath = Join-Path $TestDrive ("explicit-$Kind-tasks-catalog.json")
    if ($Kind -eq 'invalid') { Set-Content -LiteralPath $catalogPath -Value '{ not json' -Encoding UTF8 }
    Set-Variable -Name __ScheduledInventoryReached -Scope Global -Value $false
    try {
      $env:OS = 'Windows_NT'
      function global:Get-ScheduledTask {
        Set-Variable -Name __ScheduledInventoryReached -Scope Global -Value $true
        @()
      }
      $output = & $script:ScheduledTasksScript -CatalogPath $catalogPath -Mode Remediate -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
      $exitCode = $LASTEXITCODE
    } finally {
      if ($null -eq $oldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue } else { $env:OS = $oldOS }
      Remove-Item -LiteralPath Function:\Get-ScheduledTask -ErrorAction SilentlyContinue
    }
    $inventoryReached = Get-Variable -Name __ScheduledInventoryReached -Scope Global -ValueOnly
    Remove-Variable -Name __ScheduledInventoryReached -Scope Global -ErrorAction SilentlyContinue
    $result = @($output | Where-Object { $null -ne $_ -and $_.PSObject.Properties.Name -contains 'Result' })[-1]

    $exitCode | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    $result.Summary.Error | Should -Match 'Explicit task catalog failed to load'
    $inventoryReached | Should -BeFalse
  }
}
