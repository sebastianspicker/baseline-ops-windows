<#
.SYNOPSIS
  Verifies Validation library contracts.
.DESCRIPTION
  Retains explicit contract cases and shared fixture setup for the library.
#>

function Test-ValidationReturnsFalseForNullOrEmptyInput {
    Test-PathTraversal -Path $null | Should -Be $false
    Test-PathTraversal -Path '' | Should -Be $false
    Test-PathTraversal -Path '   ' | Should -Be $false
}

function Test-ValidationRejectsNullOrEmptyInput {
    Test-SafeScriptName -Name $null | Should -Be $false
    Test-SafeScriptName -Name '' | Should -Be $false
    Test-SafeScriptName -Name '   ' | Should -Be $false
}

function Test-ValidationRejectsNullOrEmptyRef {
    Test-ValidGitRef -Ref $null | Should -Be $false
    Test-ValidGitRef -Ref '' | Should -Be $false
    Test-ValidGitRef -Ref '   ' | Should -Be $false
}

function Test-ValidationRejectsNullOrEmpty {
    Test-SafeUrl -Url $null | Should -Be $false
    Test-SafeUrl -Url '' | Should -Be $false
    Test-SafeUrl -Url '   ' | Should -Be $false
}

function Test-ValidationReturnsTrueWhenPathIsUnderRoot {
    $tempRoot = if ([string]::IsNullOrWhiteSpace($env:TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:TEMP }
    $child = Join-Path $tempRoot 'subdir/file.txt'
    Test-PathUnderRoot -Path $child -Root $tempRoot | Should -Be $true
}

function Test-ValidationReturnsFalseWhenPathEscapesRoot {
    $tempRoot = if ([string]::IsNullOrWhiteSpace($env:TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:TEMP }
    $escaped = Join-Path $tempRoot '../../etc/passwd'
    Test-PathUnderRoot -Path $escaped -Root $tempRoot | Should -Be $false
}

function Test-ValidationReturnsFalseForASiblingDirectory {
    $tempRoot = if ([string]::IsNullOrWhiteSpace($env:TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:TEMP }
    $sibling = Join-Path (Split-Path $tempRoot -Parent) 'sibling-dir'
    Test-PathUnderRoot -Path $sibling -Root $tempRoot | Should -Be $false
}

function Test-ValidationDoesNotCollapseCaseDistinctionsOnNonWindowsHosts {
    $root = Join-Path $TestDrive 'CaseSensitiveRoot'
    $caseSibling = Join-Path $TestDrive 'casesensitiveroot/file.txt'

    Test-PathUnderRoot -Path $caseSibling -Root $root | Should -BeFalse
}

function Test-ValidationUsesTheSameAtomicLeafWriteCapabilitiesInEveryDuplicatedPrivilegedPathGuard {
    $guards = @(
      @{ Source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../lib/Validation.psm1') -Raw; Pattern = '(?s)WriteMask\s*=\s*(.*?)AncestorReplacementMask' },
      @{ Source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/00-Run-Local.ps1') -Raw; Pattern = '(?s)\$writeMask\s*=\s*(.*?)\$ancestorReplacementMask' },
      @{ Source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/00-Run-Batch.ps1') -Raw; Pattern = '(?s)\$writeMask\s*=\s*(.*?)\$ancestorReplacementMask' },
      @{ Source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/00-Copy-Local.ps1') -Raw; Pattern = '(?s)\$writeMask\s*=\s*(.*?)\$replaceMask' },
      @{ Source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1') -Raw; Pattern = '(?s)\$writeMask\s*=\s*(.*?)\$replacementMask' },
      @{ Source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/internal/16-Sysmon-Config-Updater.helpers.ps1') -Raw; Pattern = '(?s)function Get-TrustedStateWriteMask\s*\{(.*?)\n\}' },
      @{ Source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/internal/17-Sysmon-Rule-Drift-Sensor.helpers.ps1') -Raw; Pattern = '(?s)\$writeMask\s*=\s*(.*?)foreach \(\$accessRule' },
      @{ Source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/internal/21-EmergencyKillSwitch.helpers.ps1') -Raw; Pattern = '(?s)\$writeMask\s*=\s*(.*?)foreach \(\$rule' }
    )
    $capabilities = @(
      'WriteData', 'AppendData', 'WriteExtendedAttributes', 'WriteAttributes',
      'DeleteSubdirectoriesAndFiles', 'Delete', 'ChangePermissions', 'TakeOwnership'
    )

    foreach ($guard in $guards) {
      $match = [regex]::Match($guard.Source, $guard.Pattern)
      $match.Success | Should -BeTrue
      $leafMask = $match.Groups[1].Value
      $leafMask | Should -Not -Match 'FileSystemRights\]::(Write|Modify|FullControl)\s*-bor'
      foreach ($capability in $capabilities) {
        $leafMask | Should -Match ('FileSystemRights\]::{0}' -f $capability)
        $rights = [int64][System.Security.AccessControl.FileSystemRights]::$capability
        $readAndExecute = [int64](
          [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
          [System.Security.AccessControl.FileSystemRights]::Synchronize
        )
        ($readAndExecute -band $rights) | Should -Be 0
        ($rights -band $rights) | Should -Be $rights
      }
    }
}

function Test-ValidationAllowsEffectiveUsersReadAndExecuteButRejectsAnAtomicUsersWriteDataACE {
    $path = Join-Path $TestDrive 'trusted-acl'
    New-Item -Path $path -ItemType Directory -Force | Out-Null
    try {
      $administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
      $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
      $users = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
      $creatorOwner = New-Object System.Security.Principal.SecurityIdentifier('S-1-3-0')
      $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
      $security = New-ValidationReadOnlyAcl $administrators $system $users $creatorOwner $inheritance
      Set-Acl -LiteralPath $path -AclObject $security -ErrorAction Stop
    } catch {
      Set-ItResult -Skipped -Because "The current Windows test identity cannot create the required ACL fixture: $($_.Exception.Message)"
      return
    }

    Test-TrustedWindowsPathAcl -Path $path | Should -BeTrue
    $unsafe = Get-Acl -LiteralPath $path
    [void]$unsafe.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
          $users,
          [System.Security.AccessControl.FileSystemRights]::WriteData,
          $inheritance,
          [System.Security.AccessControl.PropagationFlags]::None,
          [System.Security.AccessControl.AccessControlType]::Allow)))
    Set-Acl -LiteralPath $path -AclObject $unsafe -ErrorAction Stop
    Test-TrustedWindowsPathAcl -Path $path | Should -BeFalse
}

function Test-ValidationPreservesTheFilesystemRootWhileWalkingPathComponents {
    $volumeRoot = [System.IO.Path]::GetPathRoot($TestDrive)

    Test-PathContainsReparsePoint -Path $TestDrive -Root $volumeRoot | Should -BeFalse
}

function Test-ValidationAcceptsAnOrdinaryExistingChildPath {
    $root = Join-Path $TestDrive 'plain-root'
    $childDir = Join-Path $root 'child'
    $child = Join-Path $childDir 'script.ps1'
    New-Item -Path $childDir -ItemType Directory -Force | Out-Null
    Set-Content -LiteralPath $child -Value 'param()' -Encoding UTF8

    Test-PathContainsReparsePoint -Path $child -Root $root | Should -BeFalse
}

function Test-ValidationFailsClosedForAMissingOrOutOfRootPath {
    $root = Join-Path $TestDrive 'closed-root'
    New-Item -Path $root -ItemType Directory -Force | Out-Null

    Test-PathContainsReparsePoint -Path (Join-Path $root 'missing.ps1') -Root $root | Should -BeTrue
    Test-PathContainsReparsePoint -Path (Join-Path $TestDrive 'outside.ps1') -Root $root | Should -BeTrue
}

function Test-ValidationRejectsAnAncestorSymbolicLink {
    $root = Join-Path $TestDrive 'linked-root'
    $outside = Join-Path $TestDrive 'linked-outside'
    New-Item -Path $root -ItemType Directory -Force | Out-Null
    New-Item -Path $outside -ItemType Directory -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $outside 'script.ps1') -Value 'param()' -Encoding UTF8
    $link = Join-Path $root 'link'
    try {
      New-Item -Path $link -ItemType SymbolicLink -Target $outside -ErrorAction Stop | Out-Null
    } catch {
      Set-ItResult -Skipped -Because 'Symbolic links are not available in this environment.'
      return
    }

    Test-PathContainsReparsePoint -Path (Join-Path $link 'script.ps1') -Root $root | Should -BeTrue
}

function Test-ValidationAcceptsALocalOutputPathWithoutCreatingMissingParents {
    $path = Join-Path $TestDrive 'output/nested/report.csv'

    Test-SafeOutputFilePath -Path $path | Should -BeTrue
    Test-Path -LiteralPath ([System.IO.Path]::GetDirectoryName($path)) | Should -BeFalse
}

function Test-ValidationCreatesMissingParentsThroughTheExplicitInitializer {
    $path = Join-Path $TestDrive 'output/nested/report.csv'

    Initialize-SafeOutputFilePath -Path $path | Should -BeTrue
    Test-Path -LiteralPath ([System.IO.Path]::GetDirectoryName($path)) | Should -BeTrue
}

function Test-ValidationRejectsAReparsePointAncestor {
    $root = Join-Path $TestDrive 'output-link-root'
    $outside = Join-Path $TestDrive 'output-link-outside'
    New-Item -Path $root -ItemType Directory -Force | Out-Null
    New-Item -Path $outside -ItemType Directory -Force | Out-Null
    $link = Join-Path $root 'link'
    try {
      New-Item -Path $link -ItemType SymbolicLink -Target $outside -ErrorAction Stop | Out-Null
    } catch {
      Set-ItResult -Skipped -Because 'Symbolic links are not available in this environment.'
      return
    }

    Test-SafeOutputFilePath -Path (Join-Path $link 'report.csv') | Should -BeFalse
}

function Test-ValidationReadsOrdinaryUTF8ContentAndExposesAStableContentHash {
    $path = Join-Path $TestDrive 'bounded.json'
    [System.IO.File]::WriteAllText($path, '{"value":1}', (New-Object System.Text.UTF8Encoding($false)))

    $text = Get-BoundedUtf8FileContent -Path $path -MaximumBytes 1024

    $text | Should -Be '{"value":1}'
    Get-TextSha256 -Text $text | Should -Match '^[A-F0-9]{64}$'
}

function Test-ValidationRejectsAnOversizedFileBeforeReadingIt {
    $path = Join-Path $TestDrive 'oversized.json'
    [System.IO.File]::WriteAllBytes($path, ([byte[]](1..32)))

    { Get-BoundedUtf8FileContent -Path $path -MaximumBytes 16 } | Should -Throw '*size limit*'
}

function Test-ValidationRejectsInvalidUTF8 {
    $path = Join-Path $TestDrive 'invalid-utf8.json'
    [System.IO.File]::WriteAllBytes($path, [byte[]](0xC3, 0x28))

    { Get-BoundedUtf8FileContent -Path $path -MaximumBytes 16 } | Should -Throw
  }

function New-ValidationReadOnlyAcl {
  param($administrators, $system, $users, $creatorOwner, $inheritance)
      $security = New-Object System.Security.AccessControl.DirectorySecurity
      $security.SetOwner($administrators)
      $security.SetAccessRuleProtection($true, $false)
      foreach ($sid in @($administrators, $system)) {
        [void]$security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
              $sid,
              [System.Security.AccessControl.FileSystemRights]::FullControl,
              $inheritance,
              [System.Security.AccessControl.PropagationFlags]::None,
              [System.Security.AccessControl.AccessControlType]::Allow)))
      }
      [void]$security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $creatorOwner,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::InheritOnly,
            [System.Security.AccessControl.AccessControlType]::Allow)))
      [void]$security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $users,
            ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
              [System.Security.AccessControl.FileSystemRights]::Synchronize),
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)))
  return $security
}
