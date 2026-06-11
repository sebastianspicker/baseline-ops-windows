#requires -version 5.1
<#
.SYNOPSIS
Pester tests for Common.psm1 module

.DESCRIPTION
Unit tests for the Common module functions including:
- Test-IsAdmin
- Ensure-Directory
- Sanitize-Path
#>

[CmdletBinding()]
param()

BeforeAll {
  # Import the module
  $modulePath = Join-Path $PSScriptRoot '../../lib/Common.psm1'
  Import-Module $modulePath -Force -DisableNameChecking

  # Test directory
  $tempRoot = if ([string]::IsNullOrWhiteSpace($env:TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:TEMP }
  $script:TestDir = Join-Path $tempRoot 'CommonModuleTests'
  $script:TestJsonFile = Join-Path $script:TestDir 'test-config.json'
}

AfterAll {
  # Cleanup test directory
  if (-not [string]::IsNullOrWhiteSpace($script:TestDir) -and (Test-Path -LiteralPath $script:TestDir)) {
    Remove-Item -LiteralPath $script:TestDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Describe "Test-IsAdmin" {
  It "Returns a boolean" {
    $result = Test-IsAdmin
    $result | Should -BeOfType [bool]
  }

  It "Does not throw" {
    { Test-IsAdmin } | Should -Not -Throw
  }
}

Describe "Ensure-Directory" {
  BeforeEach {
    # Clean up
    if (Test-Path -LiteralPath $script:TestDir) {
      Remove-Item -LiteralPath $script:TestDir -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It "Creates a new directory" {
    Ensure-Directory -Path $script:TestDir | Should -BeTrue
    Test-Path -LiteralPath $script:TestDir | Should -Be $true
  }

  It "Does not throw when directory exists" {
    New-Item -Path $script:TestDir -ItemType Directory -Force | Out-Null
    Ensure-Directory -Path $script:TestDir | Should -BeTrue
  }

  It "Returns false for empty path" {
    Ensure-Directory -Path '' | Should -BeFalse
  }

  It "Creates nested directories" {
    $nestedPath = Join-Path $script:TestDir 'Level1\Level2\Level3'
    Ensure-Directory -Path $nestedPath | Should -BeTrue
    Test-Path -LiteralPath $nestedPath | Should -Be $true
  }

  It "Returns false when directory creation fails" {
    Mock -ModuleName Common -CommandName Test-Path -MockWith { $false }
    Mock -ModuleName Common -CommandName New-Item -MockWith { throw 'Access denied' }

    Ensure-Directory -Path (Join-Path $script:TestDir 'blocked') -ErrorAction SilentlyContinue |
      Should -BeFalse
  }
}

Describe "Ensure-DirectoryForFile" {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestDir) {
      Remove-Item -LiteralPath $script:TestDir -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It "Creates parent directory for file path" {
    $filePath = Join-Path $script:TestDir 'subdir\test.txt'
    Ensure-DirectoryForFile -FilePath $filePath | Should -BeTrue
    Test-Path -LiteralPath (Join-Path $script:TestDir 'subdir') | Should -Be $true
  }

  It "Returns false when file path has no parent directory" {
    Ensure-DirectoryForFile -FilePath 'file.txt' | Should -BeFalse
  }
}

Describe "Sanitize-Path" {
  It "Returns null for whitespace path" {
    $result = Sanitize-Path -Path '   '
    $result | Should -BeNullOrEmpty
  }

  It "Expands environment variables" {
    $tempRoot = if ([string]::IsNullOrWhiteSpace($env:TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:TEMP }
    $env:COMMON_TEST_TMP = $tempRoot
    $result = Sanitize-Path -Path '%COMMON_TEST_TMP%'
    $result | Should -Not -BeNullOrEmpty
  }

  It "Rejects traversal after expanding environment variables" {
    $previousWindir = $env:WINDIR
    $previousTemp = $env:TEMP
    $previousSystemRoot = $env:SYSTEMROOT

    try {
      $safeRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'CommonModuleEnvRoot'
      $env:WINDIR = $safeRoot
      $env:TEMP = $safeRoot
      $env:SYSTEMROOT = $safeRoot

      Sanitize-Path -Path '%WINDIR%\..\..' | Should -BeNullOrEmpty
      Sanitize-Path -Path '%TEMP%\..\..\Windows' | Should -BeNullOrEmpty
      Sanitize-Path -Path '%SYSTEMROOT%\..\Windows\System32' | Should -BeNullOrEmpty
      Sanitize-Path -Path '%WINDIR%\System32' | Should -Not -BeNullOrEmpty
    } finally {
      $env:WINDIR = $previousWindir
      $env:TEMP = $previousTemp
      $env:SYSTEMROOT = $previousSystemRoot
    }
  }

  It "Returns null for path traversal attempt" {
    $result = Sanitize-Path -Path 'C:\Test\..\..\Windows\System32'
    # Note: The function may normalize this, but should warn
    # The actual behavior depends on implementation
    $result | Should -BeNullOrEmpty
  }

  It "Returns normalized path for valid path" {
    $tempRoot = if ([string]::IsNullOrWhiteSpace($env:TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:TEMP }
    $result = Sanitize-Path -Path $tempRoot
    $result | Should -Not -BeNullOrEmpty
  }

  It "Returns null for non-existent path with MustExist" {
    $result = Sanitize-Path -Path 'C:\NonExistentPath12345' -MustExist
    $result | Should -BeNullOrEmpty
  }

  It "Returns path for existing path with MustExist" {
    $tempRoot = if ([string]::IsNullOrWhiteSpace($env:TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:TEMP }
    $result = Sanitize-Path -Path $tempRoot -MustExist
    $result | Should -Not -BeNullOrEmpty
  }

  It "Rejects forward-slash traversal" {
    $result = Sanitize-Path -Path '/tmp/../etc/passwd'
    $result | Should -BeNullOrEmpty
  }

  It "Returns a full path for a relative safe path" {
    $result = Sanitize-Path -Path 'some-folder'
    $result | Should -Not -BeNullOrEmpty
    # Should be an absolute path
    [System.IO.Path]::IsPathRooted($result) | Should -Be $true
  }
}

Describe "Require-Admin" {
  It "Does not throw on non-Windows (warns instead)" -Skip:$IsWindows {
    { Require-Admin } | Should -Not -Throw
  }

  It "Accepts a custom message parameter" {
    if ($IsWindows -and -not (Test-IsAdmin)) {
      { Require-Admin -Message 'Custom admin message' } | Should -Throw 'Custom admin message'
    } else {
      { Require-Admin -Message 'Custom admin message' } | Should -Not -Throw
    }
  }
}

Describe "Ensure-Directory path traversal guard" {
  It "Does not create directory when path contains .." {
    $traversalPath = Join-Path ([System.IO.Path]::GetTempPath()) "test-ensure-dir/../../../should-not-create"
    Ensure-Directory -Path $traversalPath | Should -BeFalse
    Test-Path -LiteralPath $traversalPath | Should -Be $false
  }
}

Describe "Get-CallerValue" {
  It "Returns null when variable is not found in any scope" {
    $result = Get-CallerValue -Name 'VariableThatDoesNotExist_12345XYZ'
    $result | Should -BeNullOrEmpty
  }

  It "Does not throw when looking up any variable name" {
    # Get-CallerValue should never throw, even when variable does not exist
    { Get-CallerValue -Name 'PATH' } | Should -Not -Throw
  }
}

Describe "Get-SafeFileName" {
  It "Passes through a valid filename unchanged" {
    Get-SafeFileName -Name 'report-2025.json' | Should -Be 'report-2025.json'
  }

  It "Replaces special characters with underscores" {
    Get-SafeFileName -Name 'file<>:"/\|?*name.txt' | Should -Be 'file_________name.txt'
  }

  It "Replaces control characters with underscores" {
    $rawFileName = "file$([char]0x00)$([char]0x1F)name"
    $result = Get-SafeFileName -Name $rawFileName
    $result | Should -Be 'file__name'
  }

  It "Handles a name with no special characters" {
    Get-SafeFileName -Name 'simple-file_name.log' | Should -Be 'simple-file_name.log'
  }

  It "Throws on null input" {
    { Get-SafeFileName -Name $null } | Should -Throw
  }

  It "Throws on empty string (Mandatory parameter)" {
    { Get-SafeFileName -Name '' } | Should -Throw
  }
}

# Read-JsonConfig was removed in Phase 4.1 dedup. JSON reading is now handled by
# Read-JsonFileSafe (JsonCatalog.psm1) for simple reads, and
# Read-ConfigWithDefaults (Config.psm1) for config loading with defaults.
