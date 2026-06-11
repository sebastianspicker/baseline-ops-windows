#requires -version 5.1

Describe 'explicit config and catalog input reporting' -Tag 'Config' {
  BeforeAll {
    $script:ServiceProcessScript = Join-Path $PSScriptRoot '../../scripts/30-Service-Process-Audit.ps1'
    $script:SoftwareAuditScript = Join-Path $PSScriptRoot '../../scripts/19-Software-Audit.ps1'

    function Invoke-ServiceProcessConfigCase {
      [CmdletBinding()]
      param(
        [string]$ConfigJsonPath
      )

      $oldOS = $env:OS
      $oldComputerName = $env:COMPUTERNAME
      try {
        $env:OS = 'Windows_NT'
        $env:COMPUTERNAME = 'TEST-HOST'

        function global:Get-Process {
          [System.Diagnostics.Process]::GetCurrentProcess()
        }
        function global:Get-CimInstance {
          [CmdletBinding()]
          param([string]$ClassName)

          [pscustomobject]@{
            Name        = 'TestSvc'
            DisplayName = 'Test Service'
            State       = 'Running'
            StartMode   = 'Auto'
            StartName   = 'LocalSystem'
            ProcessId   = [System.Diagnostics.Process]::GetCurrentProcess().Id
            PathName    = 'C:\Windows\System32\svchost.exe'
          }
        }

        $params = @{
          OutputFormat = 'None'
          PassThru     = $true
          NoConsole    = $true
          Quiet        = $true
          Confirm      = $false
        }
        if (-not [string]::IsNullOrWhiteSpace($ConfigJsonPath)) {
          $params.ConfigJsonPath = $ConfigJsonPath
        }

        $output = & $script:ServiceProcessScript @params 2>&1 3>&1 6>&1
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
        Remove-Item -LiteralPath Function:\Get-Process -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\Get-CimInstance -ErrorAction SilentlyContinue
      }

      $result = @($output | Where-Object {
          $null -ne $_ -and
          $_.PSObject.Properties.Name -contains 'Result' -and
          $_.PSObject.Properties.Name -contains 'Summary'
        })[-1]

      [pscustomobject]@{
        ExitCode = $exitCode
        Result   = $result
        Text     = ($output | Out-String)
      }
    }

    function Invoke-SoftwareAuditCatalogCase {
      [CmdletBinding()]
      param(
        [Parameter(Mandatory)][string]$CatalogPath
      )

      $oldOS = $env:OS
      $oldComputerName = $env:COMPUTERNAME
      try {
        $env:OS = 'Windows_NT'
        $env:COMPUTERNAME = 'TEST-HOST'

        function global:Get-ChildItem {
          [CmdletBinding()]
          param(
            [string]$Path,
            [string]$Filter,
            [switch]$File,
            [switch]$Directory,
            [switch]$Recurse
          )

          if ($Path -like 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall*' -or
              $Path -like 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall*' -or
              $Path -like 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall*') {
            [pscustomobject]@{
              PSPath      = 'FakeSoftwareKey'
              PSChildName = 'FakeSoftware'
            }
            return
          }

          Microsoft.PowerShell.Management\Get-ChildItem @PSBoundParameters
        }
        function global:Get-ItemProperty {
          [CmdletBinding()]
          param([string]$Path)

          if ($Path -eq 'FakeSoftwareKey') {
            [pscustomobject]@{
              DisplayName     = 'Microsoft Edge'
              DisplayVersion  = '1.0'
              Publisher       = 'Microsoft'
              UninstallString = ''
              InstallDate     = ''
              SystemComponent = 0
              ParentKeyName   = ''
              ReleaseType     = ''
            }
            return
          }

          Microsoft.PowerShell.Management\Get-ItemProperty @PSBoundParameters
        }

        $output = & $script:SoftwareAuditScript `
          -CatalogPath $CatalogPath `
          -StatePath '' `
          -OutputFormat None `
          -PassThru `
          -Quiet `
          -NoColor `
          -Confirm:$false 2>&1 3>&1 6>&1
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
        Remove-Item -LiteralPath Function:\Get-ChildItem -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\Get-ItemProperty -ErrorAction SilentlyContinue
      }

      $result = @($output | Where-Object {
          $null -ne $_ -and
          $_.PSObject.Properties.Name -contains 'Catalog' -and
          $_.PSObject.Properties.Name -contains 'Status'
        })[-1]

      [pscustomobject]@{
        ExitCode = $exitCode
        Result   = $result
        Text     = ($output | Out-String)
      }
    }
  }

  AfterEach {
    Remove-Item -LiteralPath Function:\Get-ChildItem -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath Function:\Get-ItemProperty -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath Function:\Get-Process -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath Function:\Get-CimInstance -ErrorAction SilentlyContinue
  }

  It 'Leaves missing optional process/service config as a clean defaulted run' {
    $run = Invoke-ServiceProcessConfigCase

    $run.ExitCode | Should -Be 0
    $run.Result.Result | Should -Be 'OK'
    $run.Result.Summary.ConfigPathProvided | Should -BeFalse
    $run.Result.Summary.ConfigLoaded | Should -BeFalse
    @($run.Result.Findings | Where-Object { $_.Code -eq 'CFG-ConfigLoadFailed' }).Count |
      Should -Be 0
  }

  It 'Reports invalid explicit process/service config as WARN instead of clean OK' {
    $configPath = Join-Path $TestDrive 'bad-process-config.json'
    Set-Content -LiteralPath $configPath -Value '{ not json' -Encoding UTF8

    $run = Invoke-ServiceProcessConfigCase -ConfigJsonPath $configPath

    $run.ExitCode | Should -Be 2
    $run.Result.Result | Should -Be 'WARN'
    $run.Result.Summary.ConfigPathProvided | Should -BeTrue
    $run.Result.Summary.ConfigLoadStatus | Should -Be 'Invalid'
    $run.Result.Summary.ConfigLoadError | Should -Not -BeNullOrEmpty
    @($run.Result.Findings | Where-Object { $_.Code -eq 'CFG-ConfigLoadFailed' }).Count |
      Should -Be 1
  }

  It 'Reports missing explicit process/service config path as WARN instead of clean OK' {
    $configPath = Join-Path $TestDrive 'missing-process-config.json'

    $run = Invoke-ServiceProcessConfigCase -ConfigJsonPath $configPath

    $run.ExitCode | Should -Be 2
    $run.Result.Result | Should -Be 'WARN'
    $run.Result.Summary.ConfigPathProvided | Should -BeTrue
    $run.Result.Summary.ConfigLoadStatus | Should -Be 'Missing'
    @($run.Result.Findings | Where-Object { $_.Code -eq 'CFG-ConfigLoadFailed' }).Count |
      Should -Be 1
  }

  It 'Reports invalid explicit software catalog as warning metadata instead of clean OK' {
    $catalogPath = Join-Path $TestDrive 'bad-software-catalog.json'
    Set-Content -LiteralPath $catalogPath -Value '{ not json' -Encoding UTF8

    $run = Invoke-SoftwareAuditCatalogCase -CatalogPath $catalogPath

    $run.ExitCode | Should -Be 1
    $run.Result.Status.Level | Should -Be 'Warning'
    @($run.Result.Catalog.Meta.Issues | Where-Object { $_.Kind -eq 'CatalogPath' }).Count |
      Should -Be 1
    @($run.Result.Findings | Where-Object { $_.Code -eq 'CFG-CatalogLoadFailed' }).Count |
      Should -Be 1
  }
}
