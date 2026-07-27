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

Describe '16-Sysmon-Config-Updater channel failure reporting' -Tag 'Sysmon' -Skip:$script:SkipNonSystemWindowsIntegration {
  BeforeAll {
    $script:SysmonConfigUpdaterScript = Join-Path $PSScriptRoot '../../scripts/16-Sysmon-Config-Updater.ps1'

    Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/EventLog.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/External.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/Results.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/Serialization.psm1') -Force
  }

  AfterEach {
    if ($null -eq $script:OldOS) {
      Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue
    } else {
      $env:OS = $script:OldOS
    }
    if ($null -eq $script:OldComputerName) {
      Remove-Item -LiteralPath Env:COMPUTERNAME -ErrorAction SilentlyContinue
    } else {
      $env:COMPUTERNAME = $script:OldComputerName
    }
    Remove-Variable -Name OldOS -Scope Script -ErrorAction SilentlyContinue
    Remove-Variable -Name OldComputerName -Scope Script -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath Function:\Get-Service -ErrorAction SilentlyContinue
  }

  It 'adds a specific finding when wevtutil fails to enable the Sysmon channel' {
    $script:OldOS = $env:OS
    $script:OldComputerName = $env:COMPUTERNAME
    $env:OS = 'Windows_NT'
    $env:COMPUTERNAME = 'TEST-HOST'

    $configPath = Join-Path $TestDrive 'sysmon.xml'
    Set-Content -LiteralPath $configPath -Value '<Sysmon schemaversion="4.90"><EventFiltering /></Sysmon>' -Encoding UTF8
    $exePath = Join-Path $TestDrive 'Sysmon64.exe'
    Set-Content -LiteralPath $exePath -Value 'mock sysmon exe' -Encoding UTF8
    $configHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $statePath = Join-Path $TestDrive 'state.json'
    @{
      Config = @{ Sha256 = $configHash }
      Runtime = @{ CurrentDumpSha256 = $null }
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $statePath -Encoding UTF8

    Mock -CommandName Test-IsAdmin -MockWith { $true }
    Mock -CommandName Ensure-EventSource -MockWith { $true }
    Mock -CommandName Write-HealthEvent -MockWith {}
    function global:Get-Service {
      param([string]$Name)
      [pscustomobject]@{ Name = $Name }
    }
  Mock -CommandName Invoke-Wevtutil -MockWith {
    param([string[]]$Arguments, [switch]$ThrowOnError, [switch]$CaptureOutput)
    $null = $ThrowOnError, $CaptureOutput

    if ($Arguments[0] -eq 'gl') {
        return [pscustomobject]@{
          Output = @(
            'enabled: false',
            'maximum size: 1048576'
          )
          ExitCode = 0
          Success = $true
        }
      }
      if ($Arguments[0] -eq 'sl' -and $Arguments -contains '/e:true') {
        return $false
      }
      return $true
    }
    Mock -CommandName Invoke-NativeCommand -MockWith {
      [pscustomobject]@{ ExitCode = 0; Success = $true; TimedOut = $false; OutputTruncated = $false; StderrTruncated = $false; Output = '' }
    }

    $output = & $script:SysmonConfigUpdaterScript `
      -ConfigPath $configPath `
      -SysmonExePath $exePath `
      -EnsureChannel `
      -ChannelSizeMiB 1 `
      -Mode Remediate `
      -OutputFormat None `
      -PassThru `
      -NoConsoleSummary `
      -Quiet `
      -NoColor `
      -Confirm:$false 2>&1 3>&1 6>&1

    $result = @($output | Where-Object {
        $null -ne $_ -and
        $_.PSObject.Properties.Name -contains 'ScriptName' -and
        $_.PSObject.Properties.Name -contains 'Findings'
      })[-1]

    $result.Result | Should -Be 'WARN'
    $LASTEXITCODE | Should -Be 2
    @($result.Findings | Where-Object Code -eq 'Sysmon-ChannelEnableFailed').Count | Should -Be 1
  }
}

Describe '16-Sysmon-Config-Updater trust boundaries' -Tag 'Sysmon' {
  It 'treats ConfigNameHint as a literal single-result selector' {
    $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/internal/16-Sysmon-Config-Updater.helpers.ps1') -Raw
    $source | Should -Match 'IndexOf\(\$NameHint, \[StringComparison\]::OrdinalIgnoreCase\)'
    $source | Should -Match 'ConfigNameHint must select exactly one'
    $source | Should -Not -Match '\$_\.Name -match \$NameHint'
  }

  It 'anchors state writes with exclusive locks and atomic replacement' {
    $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/internal/16-Sysmon-Config-Updater.helpers.ps1') -Raw
    $source | Should -Match 'SpecialFolder\]::CommonApplicationData'
    $source | Should -Match 'FileShare\]::None'
    $source | Should -Match '\[IO\.File\]::Replace'
    $source | Should -Match 'StatePath is fixed to the admin-owned CommonApplicationData Sysmon state directory'
  }

  It 'derives default Sysmon discovery roots without mutable environment variables' {
    $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/internal/16-Sysmon-Config-Updater.helpers.ps1') -Raw
    $source | Should -Match 'SpecialFolder\]::Windows'
    $source | Should -Match 'SpecialFolder\]::ProgramFiles'
    $source | Should -Match 'SpecialFolder\]::ProgramFilesX86'
    $source | Should -Match 'candidate\.StartsWith\(\$canonicalRoot'
    $source | Should -Not -Match '\$env:SystemRoot|\$env:ProgramFiles'
  }

  It 'uses SID allowlisting and a closed bounded state schema' {
    $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/internal/16-Sysmon-Config-Updater.helpers.ps1') -Raw
    $source | Should -Match "'S-1-5-18','S-1-5-32-544'"
    $source | Should -Match 'Translate\(\[Security\.Principal\.SecurityIdentifier\]\)'
    $source | Should -Match 'AreAccessRulesProtected'
    $source | Should -Match 'MaximumBytes 65536'
    $source | Should -Match 'Assert-SysmonStateSchema'
    $source | Should -Match 'FileSystemAclExtensions\]::Create'
    $source | Should -Match 'New-TrustedStateDirectory'
    $source | Should -Match 'PropagationFlags\]::InheritOnly'
    $source | Should -Not -Match 'Everyone\|Users\|Authenticated Users\|Guests'
  }

  It 'ignores inherit-only updater state ACL templates but rejects an effective Users Modify ACE' -Skip:([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    . (Join-Path $PSScriptRoot '../../scripts/internal/16-Sysmon-Config-Updater.helpers.ps1')
    $path = Join-Path $TestDrive 'trusted-updater-state-acl'
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
      Set-Acl -LiteralPath $path -AclObject $security -ErrorAction Stop
    } catch {
      Set-ItResult -Skipped -Because "The current Windows test identity cannot create the required ACL fixture: $($_.Exception.Message)"
      return
    }

    { Assert-TrustedStateAcl -Path $path } | Should -Not -Throw
    $unsafe = Get-Acl -LiteralPath $path
    [void]$unsafe.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
          $users,
          [Security.AccessControl.FileSystemRights]::Modify,
          $inheritance,
          [Security.AccessControl.PropagationFlags]::None,
          [Security.AccessControl.AccessControlType]::Allow)))
    Set-Acl -LiteralPath $path -AclObject $unsafe -ErrorAction Stop
    { Assert-TrustedStateAcl -Path $path } | Should -Throw "*untrusted SID 'S-1-5-32-545'*"
  }

  It 'treats forged updater state hashes or fields as invalid' {
    . (Join-Path $PSScriptRoot '../../scripts/internal/16-Sysmon-Config-Updater.helpers.ps1')
    $forged = [pscustomobject]@{
      Version = 2; Time = '2026-01-01T00:00:00'; Host = 'host'
      Engine = [pscustomobject]@{ Version = $null; ExePath = $null; Service = $null }
      Observed = [pscustomobject]@{ Path = 'config.xml'; DesiredSha256 = 'forged'; Source = 'test'; Valid = $true }
      Applied = [pscustomobject]@{ Sha256 = ('a' * 64) }
      Runtime = [pscustomobject]@{ CurrentDumpSha256 = $null }
    }
    { Assert-SysmonStateSchema -State $forged } | Should -Throw '*SHA256*'
    $forged.Observed.DesiredSha256 = 'b' * 64
    $forged | Add-Member -NotePropertyName Unexpected -NotePropertyValue $true
    { Assert-SysmonStateSchema -State $forged } | Should -Throw '*missing or unsupported*'
  }

  It 'loads malformed state as absent so it cannot suppress a required apply' {
    Import-Module (Join-Path $PSScriptRoot '../../lib/Validation.psm1') -Force
    . (Join-Path $PSScriptRoot '../../scripts/internal/16-Sysmon-Config-Updater.helpers.ps1')
    $statePath = Join-Path $TestDrive 'forged-state.json'
    Set-Content -LiteralPath $statePath -Encoding UTF8 -Value '{"Version":2,"Time":"2026-01-01T00:00:00","Host":"host","Engine":{"Version":null,"ExePath":null,"Service":null},"Observed":{"Path":"config.xml","DesiredSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","Source":"test","Valid":true},"Applied":{"Sha256":"forged"},"Runtime":{"CurrentDumpSha256":null}}'
    $default = @{ Version = 2; Observed = @{ DesiredSha256 = $null }; Applied = @{ Sha256 = $null }; Runtime = @{ CurrentDumpSha256 = $null } }

    $loaded = Load-JsonOrDefault -Path $statePath -DefaultObject $default

    $loaded.Applied.Sha256 | Should -BeNullOrEmpty
  }
}

Describe '16-Sysmon-Config-Updater strict unsupported-host result' -Tag 'Sysmon' {
  It 'turns the unsupported-host warning into FAIL under Strict' {
    $oldOs = $env:OS
    try {
      $env:OS = 'NotWindows'
      $scriptPath = Join-Path $PSScriptRoot '../../scripts/16-Sysmon-Config-Updater.ps1'
      $result = & $scriptPath -Mode Audit -Strict -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor

      $LASTEXITCODE | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      $result.Metadata.UnsupportedHost | Should -BeTrue
    } finally {
      if ($null -eq $oldOs) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue } else { $env:OS = $oldOs }
    }
  }
}

Describe '16-Sysmon-Config-Updater policy gates' -Tag 'Sysmon' -Skip:$script:SkipNonSystemWindowsIntegration {
  BeforeEach {
    $script:OldOS = $env:OS
    $script:OldComputerName = $env:COMPUTERNAME
    $env:OS = 'Windows_NT'
    $env:COMPUTERNAME = 'TEST-HOST'
    $script:SysmonConfigUpdaterScript = Join-Path $PSScriptRoot '../../scripts/16-Sysmon-Config-Updater.ps1'
    $script:ConfigPath = Join-Path $TestDrive 'sysmon.xml'
    $script:SourceDir = Join-Path $TestDrive 'payload'
    $script:ExePath = Join-Path $TestDrive 'Sysmon64.exe'
    New-Item -ItemType Directory -Path $script:SourceDir -Force | Out-Null
    Set-Content -LiteralPath $script:ConfigPath -Value '<Sysmon schemaversion="4.90"><EventFiltering /></Sysmon>' -Encoding UTF8
    Copy-Item -LiteralPath $script:ConfigPath -Destination (Join-Path $script:SourceDir 'sysmon.xml')
    Set-Content -LiteralPath $script:ExePath -Value 'mock sysmon exe' -Encoding UTF8

    Mock -CommandName Test-IsAdmin -MockWith { $true }
    Mock -CommandName Ensure-EventSource -MockWith { $true }
    Mock -CommandName Write-HealthEvent -MockWith {}
    function global:Get-Service {
      param([string]$Name)
      [pscustomobject]@{ Name = $Name }
    }
    Mock -CommandName Invoke-NativeCommand -MockWith {
      [pscustomobject]@{ ExitCode = 0; Success = $true; TimedOut = $false; OutputTruncated = $false; StderrTruncated = $false; Output = '' }
    }
  }

  AfterEach {
    if ($null -eq $script:OldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue } else { $env:OS = $script:OldOS }
    if ($null -eq $script:OldComputerName) { Remove-Item -LiteralPath Env:COMPUTERNAME -ErrorAction SilentlyContinue } else { $env:COMPUTERNAME = $script:OldComputerName }
    Remove-Item -LiteralPath Function:\Get-Service -ErrorAction SilentlyContinue
  }

  It 'does not launch Sysmon when the selected hash is not allowlisted' {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    @{ AllowedHashes = @(('0' * 64), ('1' * 64)) } | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $LASTEXITCODE | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    $result.Summary.PolicyBlocked | Should -BeTrue
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

  It 'does not launch Sysmon when its engine is below the required minimum' {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    @{ MinEngine = '16.0' } | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

  It 'does not launch Sysmon when manifest Config.File escapes SourceDir' {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    @{ Config = @{ File = '../sysmon.xml' } } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    & $script:SysmonConfigUpdaterScript -SourceDir $script:SourceDir -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

  It 'does not launch Sysmon for an explicitly supplied invalid manifest' {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    Set-Content -LiteralPath $manifestPath -Value '{not json' -Encoding UTF8

    & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

  It 'rejects an oversized explicit manifest before parsing or launching Sysmon' {
    $manifestPath = Join-Path $TestDrive 'oversized-manifest.json'
    [System.IO.File]::WriteAllBytes($manifestPath, (New-Object byte[] 1048577))

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $LASTEXITCODE | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    $result.Summary.PolicyBlocked | Should -BeTrue
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

  It 'does not fall back when manifest Config.File is missing beneath SourceDir' {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    @{ Config = @{ File = 'missing.xml' } } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    $result = & $script:SysmonConfigUpdaterScript -SourceDir $script:SourceDir -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $LASTEXITCODE | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    $result.Summary.PolicyBlocked | Should -BeTrue
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

  It 'rejects a scalar manifest root as invalid policy input' {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    Set-Content -LiteralPath $manifestPath -Value '42' -Encoding UTF8

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $LASTEXITCODE | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    $result.Summary.PolicyBlocked | Should -BeTrue
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

  It 'rejects an invalid explicit MinEngine value instead of disabling the requirement' {
    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -MinEngine 'not-a-version' -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $LASTEXITCODE | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    $result.Summary.PolicyBlocked | Should -BeTrue
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

  It 'rejects present but empty AllowedHashes under the closed manifest schema' {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    @{ AllowedHashes = @() } | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $result.Result | Should -Be 'FAIL'
    $result.Summary.PolicyBlocked | Should -BeTrue
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

  It 'rejects unknown manifest properties case-insensitively' {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    @{ allowedhashes = @('0' * 64); Unexpected = 'value' } | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $result.Result | Should -Be 'FAIL'
    $result.Summary.PolicyBlocked | Should -BeTrue
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

  It 'rejects duplicate manifest properties that differ only by case' {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    Set-Content -LiteralPath $manifestPath -Value '{"MinEngine":"15.0","minengine":"16.0"}' -Encoding UTF8

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $result.Result | Should -Be 'FAIL'
    $result.Summary.PolicyBlocked | Should -BeTrue
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

  It 'rejects DTD-bearing configuration XML without launching Sysmon' {
    Set-Content -LiteralPath $script:ConfigPath -Value '<!DOCTYPE Sysmon [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Sysmon schemaversion="4.90"><EventFiltering>&xxe;</EventFiltering></Sysmon>' -Encoding UTF8

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $result.Result | Should -Be 'FAIL'
    @($result.Findings | Where-Object Message -Match 'DTD').Count | Should -BeGreaterThan 0
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

  It 'does not execute an explicitly supplied Sysmon path during Audit' {
    & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -SysmonExePath $script:ExePath -Mode Audit -OutputFormat None -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

  It 'gives an explicit trusted executable precedence over service discovery' {
    $serviceExe = Join-Path $TestDrive 'service/Sysmon64.exe'
    New-Item -ItemType Directory -Path (Split-Path -Parent $serviceExe) -Force | Out-Null
    Set-Content -LiteralPath $serviceExe -Value 'service binary' -Encoding UTF8
    Mock -CommandName Get-ItemProperty -MockWith { [pscustomobject]@{ ImagePath = '"' + $serviceExe + '"' } }

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -SysmonExePath $script:ExePath -Mode Audit -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $result.Summary.SysmonExe | Should -Be (Get-Item -LiteralPath $script:ExePath).FullName
    Should -Invoke Get-ItemProperty -Times 0 -Scope It
  }

  It 'does not launch an explicitly supplied untrusted executable during Audit' {
    $untrustedExe = Join-Path $TestDrive 'not-sysmon.exe'
    Set-Content -LiteralPath $untrustedExe -Value 'untrusted executable' -Encoding UTF8

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -SysmonExePath $untrustedExe -Mode Audit -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $result.Result | Should -Be 'FAIL'
    $result.Summary.PolicyBlocked | Should -BeTrue
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

  It 'launches Sysmon to apply a config only when manifest policy matches' {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    $configHash = (Get-FileHash -LiteralPath $script:ConfigPath -Algorithm SHA256).Hash
    @{ AllowedHashes = @($configHash, $configHash) } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 1
  }

  It 'treats a bounded native-command timeout as a failed apply' {
    Mock -CommandName Invoke-NativeCommand -MockWith {
      [pscustomobject]@{ ExitCode = -1; Success = $false; TimedOut = $true; OutputTruncated = $false; StderrTruncated = $false; Output = '' }
    }

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $result.Result | Should -Be 'WARN'
    $result.Summary.Warnings | Should -Contain 'Update failed: timed out'
  }

  It 'does not let a failed apply suppress the next remediation attempt' {
    $global:SysmonApplyAttempt = 0
    Mock -CommandName Invoke-NativeCommand -MockWith {
      $global:SysmonApplyAttempt++
      $success = $global:SysmonApplyAttempt -ne 1
      [pscustomobject]@{ ExitCode = if ($success) { 0 } else { 5 }; Success = $success; TimedOut = $false; OutputTruncated = $false; StderrTruncated = $false; Output = '' }
    }

    & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -NoConsoleSummary -Quiet -NoColor -Confirm:$false
    & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 2 -Exactly
    Remove-Variable -Name SysmonApplyAttempt -Scope Global -ErrorAction SilentlyContinue
  }
}
