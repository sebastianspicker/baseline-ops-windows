#requires -version 5.1

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
}
