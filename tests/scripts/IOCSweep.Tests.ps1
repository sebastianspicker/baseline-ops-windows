#requires -version 5.1

Describe '11-IOC-Sweep-Defender source failure reporting' {
  BeforeAll {
    $script:IocScript = Join-Path $PSScriptRoot '../../scripts/11-IOC-Sweep-Defender.ps1'

    function Invoke-IocSweepSourceFailureCase {
      [CmdletBinding()]
      param(
        [Parameter(Mandatory)][hashtable]$CatalogOverrides,
        [Parameter(Mandatory)][scriptblock]$MockCommands
      )

      $catalogPath = Join-Path $TestDrive ("ioc-catalog-{0}.json" -f [guid]::NewGuid().ToString('N'))
      $proofPath = Join-Path $TestDrive ("ioc-proof-{0}.json" -f [guid]::NewGuid().ToString('N'))
      $evidenceDir = Join-Path $TestDrive ("ioc-evidence-{0}" -f [guid]::NewGuid().ToString('N'))
      $catalog = @{
        Proof = @{ OutFile = $proofPath }
        EvidenceDir = $evidenceDir
        Files = @()
        FileGlobs = @()
        Registry = @()
        Services = @()
        ScheduledTasks = @()
        Processes = @()
        IPs = @()
        Domains = @()
      }
      foreach ($key in $CatalogOverrides.Keys) {
        $catalog[$key] = $CatalogOverrides[$key]
      }
      $catalog | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $catalogPath -Encoding UTF8

      $oldOS = $env:OS
      try {
        $env:OS = 'Windows_NT'
        & $MockCommands
        $output = & $script:IocScript -CatalogPath $catalogPath -ScanType None -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
        $exitCode = $LASTEXITCODE
      } finally {
        if ($null -eq $oldOS) {
          Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue
        } else {
          $env:OS = $oldOS
        }
        foreach ($name in @('Get-CimInstance','Get-ScheduledTask','Get-Process','Get-NetTCPConnection','Get-DnsClientCache')) {
          Remove-Item -LiteralPath "Function:\$name" -ErrorAction SilentlyContinue
        }
      }

      $result = @($output | Where-Object {
          $null -ne $_ -and
          $_.PSObject.Properties.Name -contains 'Result' -and
          $_.PSObject.Properties.Name -contains 'Findings'
        })[-1]

      return [pscustomobject]@{
        ExitCode = $exitCode
        Result = $result
        Text = ($output | Out-String)
      }
    }

    function Invoke-IocSweepDefenderScanCase {
      [CmdletBinding()]
      param(
        [Parameter(Mandatory)][int]$DefenderExitCode,
        [ValidateSet('Quick','Full','None')][string]$ScanType = 'Quick',
        [string[]]$CustomScanPaths = @()
      )

      $catalogPath = Join-Path $TestDrive ("ioc-catalog-{0}.json" -f [guid]::NewGuid().ToString('N'))
      $proofPath = Join-Path $TestDrive ("ioc-proof-{0}.json" -f [guid]::NewGuid().ToString('N'))
      $evidenceDir = Join-Path $TestDrive ("ioc-evidence-{0}" -f [guid]::NewGuid().ToString('N'))
      @{
        Proof = @{ OutFile = $proofPath }
        EvidenceDir = $evidenceDir
        Files = @()
        FileGlobs = @()
        Registry = @()
        Services = @()
        ScheduledTasks = @()
        Processes = @()
        IPs = @()
        Domains = @()
      } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $catalogPath -Encoding UTF8

      $oldOS = $env:OS
      $oldProgramFiles = $env:ProgramFiles
      try {
        $env:OS = 'Windows_NT'
        $env:ProgramFiles = Join-Path $TestDrive 'ProgramFiles'
        $fakeMpCmdRun = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
        New-Item -ItemType File -Path $fakeMpCmdRun -Force | Out-Null
        Set-Variable -Name __IocDefenderExitCode -Scope Global -Value $DefenderExitCode

        function global:Start-Process {
          [CmdletBinding()]
          param(
            [string]$FilePath,
            [string[]]$ArgumentList,
            [switch]$PassThru,
            [switch]$Wait,
            [object]$WindowStyle
          )
          [void]$FilePath
          [void]$ArgumentList
          [void]$PassThru
          [void]$Wait
          [void]$WindowStyle
          return [pscustomobject]@{ ExitCode = (Get-Variable -Name __IocDefenderExitCode -Scope Global -ValueOnly) }
        }

        $invokeArgs = @{
          CatalogPath = $catalogPath
          ScanType = $ScanType
          OutputFormat = 'None'
          PassThru = $true
          Confirm = $false
        }
        if ($CustomScanPaths.Count -gt 0) {
          $invokeArgs.CustomScanPaths = $CustomScanPaths
        }

        $output = & $script:IocScript @invokeArgs 2>&1 3>&1 6>&1
        $exitCode = $LASTEXITCODE
      } finally {
        if ($null -eq $oldOS) {
          Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue
        } else {
          $env:OS = $oldOS
        }
        if ($null -eq $oldProgramFiles) {
          Remove-Item -LiteralPath Env:ProgramFiles -ErrorAction SilentlyContinue
        } else {
          $env:ProgramFiles = $oldProgramFiles
        }
        Remove-Item -LiteralPath Function:\Start-Process -ErrorAction SilentlyContinue
        Remove-Variable -Name __IocDefenderExitCode -Scope Global -ErrorAction SilentlyContinue
      }

      $result = @($output | Where-Object {
          $null -ne $_ -and
          $_.PSObject.Properties.Name -contains 'Result' -and
          $_.PSObject.Properties.Name -contains 'Findings'
        })[-1]

      return [pscustomobject]@{
        ExitCode = $exitCode
        Result = $result
        Text = ($output | Out-String)
      }
    }
  }

  It 'Reports service source failure instead of a clean no-IOC result' {
    $run = Invoke-IocSweepSourceFailureCase `
      -CatalogOverrides @{ Services = @(@{ Name = 'SuspiciousSvc' }) } `
      -MockCommands {
        function global:Get-CimInstance { throw 'service source failed' }
      }

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.SourceStatus.Services.Succeeded | Should -BeFalse
    @($run.Result.Summary.Errors | Where-Object { $_ -match 'service source failed' }).Count | Should -BeGreaterThan 0
  }

  It 'Reports scheduled-task source failure instead of an empty task scan' {
    $run = Invoke-IocSweepSourceFailureCase `
      -CatalogOverrides @{ ScheduledTasks = @(@{ Regex = 'SuspiciousTask' }) } `
      -MockCommands {
        function global:Get-ScheduledTask { throw 'task source failed' }
      }

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.SourceStatus.ScheduledTasks.Succeeded | Should -BeFalse
    @($run.Result.Summary.Errors | Where-Object { $_ -match 'task source failed' }).Count | Should -BeGreaterThan 0
  }

  It 'Reports process source failure instead of silently scanning no processes' {
    $run = Invoke-IocSweepSourceFailureCase `
      -CatalogOverrides @{ Processes = @(@{ ImageRegex = 'suspicious\.exe' }) } `
      -MockCommands {
        function global:Get-Process {
          [CmdletBinding()]
          param([int]$Id)
          [void]$Id
          Write-Error 'process source failed'
        }
      }

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.SourceStatus.Processes.Succeeded | Should -BeFalse
    @($run.Result.Summary.Errors | Where-Object { $_ -match 'process source failed' }).Count | Should -BeGreaterThan 0
  }

  It 'Reports network connection source failure instead of silently scanning no connections' {
    $run = Invoke-IocSweepSourceFailureCase `
      -CatalogOverrides @{ IPs = @('203.0.113.10') } `
      -MockCommands {
        function global:Get-NetTCPConnection {
          [CmdletBinding()]
          param([string[]]$State)
          [void]$State
          Write-Error 'network connection source failed'
        }
      }

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.SourceStatus.NetworkConnections.Succeeded | Should -BeFalse
    @($run.Result.Summary.Errors | Where-Object { $_ -match 'network connection source failed' }).Count | Should -BeGreaterThan 0
  }

  It 'Reports DNS source failure instead of silently scanning no cached domains' {
    $run = Invoke-IocSweepSourceFailureCase `
      -CatalogOverrides @{ Domains = @('bad.example') } `
      -MockCommands {
        function global:Get-DnsClientCache { throw 'dns source failed' }
      }

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.SourceStatus.DnsCache.Succeeded | Should -BeFalse
    @($run.Result.Summary.Errors | Where-Object { $_ -match 'dns source failed' }).Count | Should -BeGreaterThan 0
  }

  It 'Reports FAIL when MpCmdRun exits 2 for a Defender scan' {
    $run = Invoke-IocSweepDefenderScanCase -DefenderExitCode 2 -ScanType Quick

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.Scan.Result | Should -Be 'exit:2'
    @($run.Result.Findings | Where-Object Code -eq 'IOC-DefenderDetection').Count | Should -Be 1
  }

  It 'Reports FAIL when a custom Defender scan exits 2' {
    $customPath = Join-Path $TestDrive 'custom-scan-target'
    New-Item -ItemType Directory -Path $customPath -Force | Out-Null

    $run = Invoke-IocSweepDefenderScanCase -DefenderExitCode 2 -ScanType None -CustomScanPaths @($customPath)

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.Scan.Result | Should -Match 'exit:2'
    @($run.Result.Findings | Where-Object Code -eq 'IOC-DefenderDetection').Count | Should -Be 1
  }

  It 'Reports FAIL when MpCmdRun exits with an unexpected nonzero code' {
    $run = Invoke-IocSweepDefenderScanCase -DefenderExitCode 5 -ScanType Quick

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.Scan.Result | Should -Be 'exit:5'
    @($run.Result.Findings | Where-Object Code -eq 'IOC-DefenderError').Count | Should -Be 1
  }
}
