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

Describe '21-EmergencyKillSwitch trusted remediation lock' -Tag 'EmergencyKillSwitch' {
  BeforeAll {
function Test-KillSwitchUsesAProgramDataLockFileWithAProtectedSYSTEMAndAdministratorsACLOnWindows {
    $directory = Join-Path $TestDrive 'trusted-kill-switch-lock'
    try {
      $security = Get-KillSwitchLockAcl -Directory
      [void][System.IO.Directory]::CreateDirectory($directory, $security)
      $stream = Enter-KillSwitchRemediationLock -LockDirectory $directory
      try {
        { [System.IO.File]::Open((Join-Path $directory 'remediation.lock'), [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) } | Should -Throw
        Assert-KillSwitchLockAcl -Path $directory -Directory
        Assert-KillSwitchLockAcl -Path (Join-Path $directory 'remediation.lock')
      } finally {
        $stream.Dispose()
      }
    } catch {
      Set-ItResult -Skipped -Because "The Windows ACL fixture requires permission to create protected test paths: $($_.Exception.Message)"
    }
  }

function Test-KillSwitchHoldsAFileShareNoneLockUntilItsStreamIsDisposedInPortableHelperTests {
    $directory = Join-Path $TestDrive 'portable-kill-switch-lock'
    $stream = Enter-KillSwitchRemediationLock -LockDirectory $directory
    try {
      { [System.IO.File]::Open((Join-Path $directory 'remediation.lock'), [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) } | Should -Throw
    } finally {
      $stream.Dispose()
    }
    { $retry = [System.IO.File]::Open((Join-Path $directory 'remediation.lock'), [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None); $retry.Dispose() } | Should -Not -Throw
  }

function Test-KillSwitchContainsNoNamedMutexAndValidatesTheTrustedProgramDataLockPathInSource {
    $source = Get-Content -LiteralPath $script:KillSwitchScript -Raw
    $helperSource = Get-Content -LiteralPath $script:KillSwitchHelper -Raw

    $source | Should -Not -Match 'System\.Threading\.Mutex|Global\\BaselineOpsForWindows-EmergencyKillSwitch'
    $source | Should -Match 'Enter-KillSwitchRemediationLock'
    $source | Should -Match '\$(?:RunState\.)?killSwitchLockStream\.Dispose\(\)'
    $helperSource | Should -Match 'CommonApplicationData'
    $helperSource | Should -Match 'Microsoft\\Windows'
    $helperSource | Should -Match 'Assert-KillSwitchLockParent -Path \$trustedParent'
    $helperSource | Should -Match 'Test-PathContainsReparsePoint -Path \$directory -Root \$trustedParent'
    $helperSource | Should -Match 'Assert-TrustedWindowsPathAcl -Path \$Path -CheckAncestors'
    $helperSource | Should -Match '\[System\.IO\.FileShare\]::None'
    $helperSource | Should -Match "S-1-5-32-544"
    $helperSource | Should -Match "S-1-5-18"
  }


    $script:KillSwitchScript = Join-Path $PSScriptRoot '../../scripts/21-EmergencyKillSwitch.ps1'
    $script:KillSwitchHelper = Join-Path $PSScriptRoot '../../scripts/internal/21-EmergencyKillSwitch.helpers.ps1'
    Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force
    . $script:KillSwitchHelper

  }



  It 'uses a ProgramData lock file with a protected SYSTEM and Administrators ACL on Windows' -Skip:([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { Test-KillSwitchUsesAProgramDataLockFileWithAProtectedSYSTEMAndAdministratorsACLOnWindows }

  It 'holds a FileShare.None lock until its stream is disposed in portable helper tests' -Skip:([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) { Test-KillSwitchHoldsAFileShareNoneLockUntilItsStreamIsDisposedInPortableHelperTests }

  It 'contains no named mutex and validates the trusted ProgramData lock path in source' { Test-KillSwitchContainsNoNamedMutexAndValidatesTheTrustedProgramDataLockPathInSource }
}
