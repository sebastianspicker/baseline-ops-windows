<#
.SYNOPSIS
  Verifies Validation library contracts.
.DESCRIPTION
  Retains explicit contract cases and shared fixture setup for the library.
#>

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../lib/Validation.psm1') -Force

  . (Join-Path $PSScriptRoot 'Validation.Cases.ps1')
}

Describe 'Windows privileged-path ACL validation' {
  It 'excludes inherit-only templates from current-object rights in every host build' {
    (Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../lib/Validation.psm1') -Raw) |
      Should -Match 'PropagationFlags\]::InheritOnly'
  }

  It 'uses the same atomic leaf write capabilities in every duplicated privileged-path guard' { Test-ValidationUsesTheSameAtomicLeafWriteCapabilitiesInEveryDuplicatedPrivilegedPathGuard }

  It 'is a portable no-op on non-Windows hosts' -Skip:([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    Test-TrustedWindowsPathAcl -Path $TestDrive | Should -BeTrue
    { Assert-TrustedWindowsPathAcl -Path $TestDrive | Out-Null } | Should -Not -Throw
  }

  It 'allows effective Users ReadAndExecute but rejects an atomic Users WriteData ACE' -Skip:([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { Test-ValidationAllowsEffectiveUsersReadAndExecuteButRejectsAnAtomicUsersWriteDataACE }
}
