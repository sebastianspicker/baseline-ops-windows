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

Describe 'Assert-NoPathTraversal' {
  It 'Does not throw for safe path' {
    { Assert-NoPathTraversal -Path 'C:\Temp\safe.txt' } | Should -Not -Throw
  }

  It 'Throws for traversal path' {
    { Assert-NoPathTraversal -Path '..\evil\file.txt' } | Should -Throw '*path traversal*'
  }

  It 'Throws with custom parameter name in message' {
    { Assert-NoPathTraversal -Path '..\escape' -ParameterName 'ConfigPath' } | Should -Throw '*ConfigPath*'
  }
}

Describe 'Test-PathUnderRoot' {
  It 'treats the root directory itself as contained' {
    Test-PathUnderRoot -Path $TestDrive -Root $TestDrive | Should -BeTrue
    Test-PathUnderRoot -Path ($TestDrive + [System.IO.Path]::DirectorySeparatorChar) -Root $TestDrive | Should -BeTrue
  }

  It 'Returns true when path is under root' { Test-ValidationReturnsTrueWhenPathIsUnderRoot }

  It 'Returns false when path escapes root' { Test-ValidationReturnsFalseWhenPathEscapesRoot }

  It 'Returns false for a sibling directory' { Test-ValidationReturnsFalseForASiblingDirectory }

  It 'does not collapse case distinctions on non-Windows hosts' -Skip:([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) { Test-ValidationDoesNotCollapseCaseDistinctionsOnNonWindowsHosts }
}

Describe 'Test-PathContainsReparsePoint' {
  It 'preserves the filesystem root while walking path components' { Test-ValidationPreservesTheFilesystemRootWhileWalkingPathComponents }

  It 'accepts an ordinary existing child path' { Test-ValidationAcceptsAnOrdinaryExistingChildPath }

  It 'fails closed for a missing or out-of-root path' { Test-ValidationFailsClosedForAMissingOrOutOfRootPath }

  It 'rejects an ancestor symbolic link' { Test-ValidationRejectsAnAncestorSymbolicLink }
}

Describe 'Test-SafeOutputFilePath' {
  It 'accepts a local output path without creating missing parents' { Test-ValidationAcceptsALocalOutputPathWithoutCreatingMissingParents }

  It 'creates missing parents through the explicit initializer' { Test-ValidationCreatesMissingParentsThroughTheExplicitInitializer }

  It 'rejects traversal and UNC output paths' {
    Test-SafeOutputFilePath -Path '../escape.csv' | Should -BeFalse
    Test-SafeOutputFilePath -Path '\\server\share\report.csv' | Should -BeFalse
  }

  It 'rejects a reparse-point ancestor' -Skip:([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { Test-ValidationRejectsAReparsePointAncestor }
}
