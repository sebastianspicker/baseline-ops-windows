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

Describe '16-Sysmon-Config-Updater trust boundaries' -Tag 'Sysmon' {
  BeforeAll {
    function Read-SysmonHelperClosure {
      $helperRoot = Join-Path $PSScriptRoot '../../scripts/internal'
      $paths = @(Join-Path $helperRoot '16-Sysmon-Config-Updater.helpers.ps1')
      $paths += @('manifest', 'trust', 'presentation', 'runtime') | ForEach-Object { Join-Path $helperRoot ('16-Sysmon-Config-Updater.{0}.ps1' -f $_) }
      return (@($paths | ForEach-Object { Get-Content -LiteralPath $_ -Raw }) -join "`n")
    }

function Initialize-SysmonReadOnlyAcl {
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

}

function Test-SysmonTreatsConfigNameHintAsALiteralSingleResultSelector {
    $source = Read-SysmonHelperClosure
    $source | Should -Match 'IndexOf\(\$NameHint,\s*\[StringComparison\]::OrdinalIgnoreCase\)'
    $source | Should -Match 'ConfigNameHint must select exactly one'
    $source | Should -Not -Match '\$_\.Name -match \$NameHint'
  }

function Test-SysmonAnchorsStateWritesWithExclusiveLocksAndAtomicReplacement {
    $source = Read-SysmonHelperClosure
    $source | Should -Match 'SpecialFolder\]::CommonApplicationData'
    $source | Should -Match 'FileShare\]::None'
    $source | Should -Match '\[IO\.File\]::Replace'
    $source | Should -Match 'StatePath is fixed to the admin-owned CommonApplicationData Sysmon state directory'
  }

function Test-SysmonDerivesDefaultSysmonDiscoveryRootsWithoutMutableEnvironmentVariables {
    $source = Read-SysmonHelperClosure
    $source | Should -Match 'SpecialFolder\]::Windows'
    $source | Should -Match 'SpecialFolder\]::ProgramFiles'
    $source | Should -Match 'SpecialFolder\]::ProgramFilesX86'
    $source | Should -Match 'candidate\.StartsWith\(\$canonicalRoot'
    $source | Should -Not -Match '\$env:SystemRoot|\$env:ProgramFiles'
  }

function Test-SysmonUsesSIDAllowlistingAndAClosedBoundedStateSchema {
    $source = Read-SysmonHelperClosure
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

function Test-SysmonAllowsEffectiveUsersReadAndExecuteButRejectsAnAtomicUsersWriteDataACE {
    . (Join-Path $PSScriptRoot '../../scripts/internal/16-Sysmon-Config-Updater.helpers.ps1')
    $path = Join-Path $TestDrive 'trusted-updater-state-acl'
    New-Item -Path $path -ItemType Directory -Force | Out-Null
    try {
      . Initialize-SysmonReadOnlyAcl
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

function Test-SysmonTreatsForgedUpdaterStateHashesOrFieldsAsInvalid {
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

function Test-SysmonLoadsMalformedStateAsAbsentSoItCannotSuppressARequiredApply {
    Import-Module (Join-Path $PSScriptRoot '../../lib/Validation.psm1') -Force
    . (Join-Path $PSScriptRoot '../../scripts/internal/16-Sysmon-Config-Updater.helpers.ps1')
    $statePath = Join-Path $TestDrive 'forged-state.json'
    Set-Content -LiteralPath $statePath -Encoding UTF8 -Value '{"Version":2,"Time":"2026-01-01T00:00:00","Host":"host","Engine":{"Version":null,"ExePath":null,"Service":null},"Observed":{"Path":"config.xml","DesiredSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","Source":"test","Valid":true},"Applied":{"Sha256":"forged"},"Runtime":{"CurrentDumpSha256":null}}'
    $default = @{ Version = 2; Observed = @{ DesiredSha256 = $null }; Applied = @{ Sha256 = $null }; Runtime = @{ CurrentDumpSha256 = $null } }

    $loaded = Load-JsonOrDefault -Path $statePath -DefaultObject $default

    $loaded.Applied.Sha256 | Should -BeNullOrEmpty
  }
  }

  It 'treats ConfigNameHint as a literal single-result selector' { Test-SysmonTreatsConfigNameHintAsALiteralSingleResultSelector }

  It 'anchors state writes with exclusive locks and atomic replacement' { Test-SysmonAnchorsStateWritesWithExclusiveLocksAndAtomicReplacement }

  It 'derives default Sysmon discovery roots without mutable environment variables' { Test-SysmonDerivesDefaultSysmonDiscoveryRootsWithoutMutableEnvironmentVariables }

  It 'uses SID allowlisting and a closed bounded state schema' { Test-SysmonUsesSIDAllowlistingAndAClosedBoundedStateSchema }

  It 'allows effective Users ReadAndExecute but rejects an atomic Users WriteData ACE' -Skip:([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { Test-SysmonAllowsEffectiveUsersReadAndExecuteButRejectsAnAtomicUsersWriteDataACE }

  It 'treats forged updater state hashes or fields as invalid' { Test-SysmonTreatsForgedUpdaterStateHashesOrFieldsAsInvalid }

  It 'loads malformed state as absent so it cannot suppress a required apply' { Test-SysmonLoadsMalformedStateAsAbsentSoItCannotSuppressARequiredApply }
}
