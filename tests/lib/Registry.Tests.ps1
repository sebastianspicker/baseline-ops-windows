#requires -version 5.1
<#
.SYNOPSIS
Pester tests for Registry.psm1 module

.DESCRIPTION
Unit tests for the Registry module functions including:
- Ensure-RegistryKey
- Get-RegValue
- Set-RegDword
- Set-RegString
- Get-RegKeyExists
- Get-RegValueExists
#>

[CmdletBinding()]
param()

$script:SkipRegistryTests = (-not $IsWindows) -or (-not (Get-PSDrive -Name HKCU -ErrorAction SilentlyContinue))

BeforeAll {
  # Import the module
  $modulePath = Join-Path $PSScriptRoot '../../lib/Registry.psm1'
  Import-Module $modulePath -Force

  # Test registry path (safe location in HKCU)
  $script:TestKeyPath = 'HKCU:\Software\RegistryModuleTests'
  $script:TestKeyPath2 = 'HKCU:\Software\RegistryModuleTests\SubKey'
}

AfterAll {
  # Cleanup test keys
  if (Test-Path -LiteralPath $script:TestKeyPath) {
    Remove-Item -LiteralPath $script:TestKeyPath -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Describe "Ensure-RegistryKey" -Skip:$script:SkipRegistryTests {
  BeforeEach {
    # Ensure clean state
    if (Test-Path -LiteralPath $script:TestKeyPath) {
      Remove-Item -LiteralPath $script:TestKeyPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It "Creates a new registry key" {
    Ensure-RegistryKey -Path $script:TestKeyPath
    Test-Path -LiteralPath $script:TestKeyPath | Should -Be $true
  }

  It "Does not throw when key already exists" {
    Ensure-RegistryKey -Path $script:TestKeyPath
    { Ensure-RegistryKey -Path $script:TestKeyPath } | Should -Not -Throw
  }

  It "Creates nested keys" {
    Ensure-RegistryKey -Path $script:TestKeyPath2
    Test-Path -LiteralPath $script:TestKeyPath2 | Should -Be $true
  }
}

Describe "Get-RegValue" -Skip:$script:SkipRegistryTests {
  BeforeEach {
    # Setup test key with values
    if (Test-Path -LiteralPath $script:TestKeyPath) {
      Remove-Item -LiteralPath $script:TestKeyPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -Path $script:TestKeyPath -Force | Out-Null
    New-ItemProperty -Path $script:TestKeyPath -Name 'TestDword' -Value 1 -PropertyType DWord | Out-Null
    New-ItemProperty -Path $script:TestKeyPath -Name 'TestString' -Value 'Hello' -PropertyType String | Out-Null
  }

  It "Returns correct DWORD value" {
    $result = Get-RegValue -Path $script:TestKeyPath -Name 'TestDword'
    $result | Should -Be 1
  }

  It "Returns correct String value" {
    $result = Get-RegValue -Path $script:TestKeyPath -Name 'TestString'
    $result | Should -Be 'Hello'
  }

  It "Returns null for non-existent value" {
    $result = Get-RegValue -Path $script:TestKeyPath -Name 'NonExistent'
    $result | Should -BeNullOrEmpty
  }

  It "Returns null for non-existent key" {
    $result = Get-RegValue -Path 'HKCU:\Software\NonExistentKey12345' -Name 'Value'
    $result | Should -BeNullOrEmpty
  }
}

Describe "Set-RegDword" -Skip:$script:SkipRegistryTests {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestKeyPath) {
      Remove-Item -LiteralPath $script:TestKeyPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It "Creates key and sets DWORD value" {
    $result = Set-RegDword -Path $script:TestKeyPath -Name 'MyDword' -Value 42
    $result | Should -Be $true
    
    $value = Get-ItemProperty -Path $script:TestKeyPath -Name 'MyDword'
    $value.MyDword | Should -Be 42
  }

  It "Updates existing DWORD value" {
    Set-RegDword -Path $script:TestKeyPath -Name 'MyDword' -Value 1
    $result = Set-RegDword -Path $script:TestKeyPath -Name 'MyDword' -Value 99
    $result | Should -Be $true
    
    $value = Get-ItemProperty -Path $script:TestKeyPath -Name 'MyDword'
    $value.MyDword | Should -Be 99
  }

  It "Throws for empty name" {
    { Set-RegDword -Path $script:TestKeyPath -Name '' -Value 1 } | Should -Throw
  }
}

Describe "Set-RegString" -Skip:$script:SkipRegistryTests {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestKeyPath) {
      Remove-Item -LiteralPath $script:TestKeyPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It "Creates key and sets String value" {
    $result = Set-RegString -Path $script:TestKeyPath -Name 'MyString' -Value 'TestValue'
    $result | Should -Be $true
    
    $value = Get-ItemProperty -Path $script:TestKeyPath -Name 'MyString'
    $value.MyString | Should -Be 'TestValue'
  }
}

Describe "Get-RegKeyExists" -Skip:$script:SkipRegistryTests {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestKeyPath) {
      Remove-Item -LiteralPath $script:TestKeyPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It "Returns true for existing key" {
    New-Item -Path $script:TestKeyPath -Force | Out-Null
    Get-RegKeyExists -Path $script:TestKeyPath | Should -Be $true
  }

  It "Returns false for non-existent key" {
    Get-RegKeyExists -Path 'HKCU:\Software\NonExistentKey12345' | Should -Be $false
  }
}

Describe "Get-RegValueExists" -Skip:$script:SkipRegistryTests {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestKeyPath) {
      Remove-Item -LiteralPath $script:TestKeyPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -Path $script:TestKeyPath -Force | Out-Null
    New-ItemProperty -Path $script:TestKeyPath -Name 'ExistingValue' -Value 1 -PropertyType DWord | Out-Null
  }

  It "Returns true for existing value" {
    Get-RegValueExists -Path $script:TestKeyPath -Name 'ExistingValue' | Should -Be $true
  }

  It "Returns false for non-existent value" {
    Get-RegValueExists -Path $script:TestKeyPath -Name 'NonExistent' | Should -Be $false
  }

  It "Returns false for non-existent key" {
    Get-RegValueExists -Path 'HKCU:\Software\NonExistentKey12345' -Name 'Value' | Should -Be $false
  }
}

Describe "Remove-RegValueIfExists" -Skip:$script:SkipRegistryTests {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestKeyPath) {
      Remove-Item -LiteralPath $script:TestKeyPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -Path $script:TestKeyPath -Force | Out-Null
    New-ItemProperty -Path $script:TestKeyPath -Name 'ToRemove' -Value 1 -PropertyType DWord | Out-Null
  }

  It "Removes existing value and returns true" {
    $result = Remove-RegValueIfExists -Path $script:TestKeyPath -Name 'ToRemove'
    $result | Should -Be $true
    Get-RegValueExists -Path $script:TestKeyPath -Name 'ToRemove' | Should -Be $false
  }

  It "Returns false for non-existent value" {
    $result = Remove-RegValueIfExists -Path $script:TestKeyPath -Name 'NonExistent'
    $result | Should -Be $false
  }

  It "Returns false for non-existent key" {
    $result = Remove-RegValueIfExists -Path 'HKCU:\Software\NonExistentKey12345' -Name 'Value'
    $result | Should -Be $false
  }
}

Describe "Get-RegDword" -Skip:$script:SkipRegistryTests {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestKeyPath) {
      Remove-Item -LiteralPath $script:TestKeyPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -Path $script:TestKeyPath -Force | Out-Null
    New-ItemProperty -Path $script:TestKeyPath -Name 'MyDword' -Value 42 -PropertyType DWord | Out-Null
  }

  It "Returns correct value" {
    $result = Get-RegDword -Path $script:TestKeyPath -Name 'MyDword'
    $result | Should -Be 42
  }

  It "Returns default for non-existent value" {
    $result = Get-RegDword -Path $script:TestKeyPath -Name 'NonExistent' -DefaultValue 99
    $result | Should -Be 99
  }

  It "Returns 0 as default when not specified" {
    $result = Get-RegDword -Path $script:TestKeyPath -Name 'NonExistent'
    $result | Should -Be 0
  }
}

Describe "Get-RegString" -Skip:$script:SkipRegistryTests {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestKeyPath) {
      Remove-Item -LiteralPath $script:TestKeyPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -Path $script:TestKeyPath -Force | Out-Null
    New-ItemProperty -Path $script:TestKeyPath -Name 'MyString' -Value 'Hello' -PropertyType String | Out-Null
  }

  It "Returns correct value" {
    $result = Get-RegString -Path $script:TestKeyPath -Name 'MyString'
    $result | Should -Be 'Hello'
  }

  It "Returns default for non-existent value" {
    $result = Get-RegString -Path $script:TestKeyPath -Name 'NonExistent' -DefaultValue 'Default'
    $result | Should -Be 'Default'
  }
}

Describe "Set-RegQword" -Skip:$script:SkipRegistryTests {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestKeyPath) {
      Remove-Item -LiteralPath $script:TestKeyPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It "Creates key and sets QWORD value" {
    $result = Set-RegQword -Path $script:TestKeyPath -Name 'MyQword' -Value 123456789012345
    $result | Should -Be $true
    $value = Get-ItemProperty -Path $script:TestKeyPath -Name 'MyQword'
    $value.MyQword | Should -Be 123456789012345
  }

  It "Throws for empty name" {
    { Set-RegQword -Path $script:TestKeyPath -Name '' -Value 1 } | Should -Throw
  }
}

Describe "Set-RegExpandString" -Skip:$script:SkipRegistryTests {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestKeyPath) {
      Remove-Item -LiteralPath $script:TestKeyPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It "Creates key and sets ExpandString value" {
    $result = Set-RegExpandString -Path $script:TestKeyPath -Name 'MyExpand' -Value '%SystemRoot%\test'
    $result | Should -Be $true
    $value = Get-ItemProperty -Path $script:TestKeyPath -Name 'MyExpand'
    $value.MyExpand | Should -Match 'test'
  }

  It "Throws for empty name" {
    { Set-RegExpandString -Path $script:TestKeyPath -Name '' -Value 'val' } | Should -Throw
  }
}

Describe "Set-RegMultiString" -Skip:$script:SkipRegistryTests {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestKeyPath) {
      Remove-Item -LiteralPath $script:TestKeyPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It "Creates key and sets MultiString value" {
    $result = Set-RegMultiString -Path $script:TestKeyPath -Name 'MyMulti' -Value @('one', 'two', 'three')
    $result | Should -Be $true
    $value = Get-ItemProperty -Path $script:TestKeyPath -Name 'MyMulti'
    @($value.MyMulti).Count | Should -Be 3
  }

  It "Throws for empty name" {
    { Set-RegMultiString -Path $script:TestKeyPath -Name '' -Value @('a') } | Should -Throw
  }
}

Describe "Set-RegBinary" -Skip:$script:SkipRegistryTests {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestKeyPath) {
      Remove-Item -LiteralPath $script:TestKeyPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It "Creates key and sets Binary value" {
    $result = Set-RegBinary -Path $script:TestKeyPath -Name 'MyBinary' -Value @([byte]0x01, [byte]0x02, [byte]0xFF)
    $result | Should -Be $true
    $value = Get-ItemProperty -Path $script:TestKeyPath -Name 'MyBinary'
    $value.MyBinary[0] | Should -Be 0x01
    $value.MyBinary[2] | Should -Be 0xFF
  }

  It "Throws for empty name" {
    { Set-RegBinary -Path $script:TestKeyPath -Name '' -Value @([byte]0x00) } | Should -Throw
  }
}

Describe "Get-RegDwordOrNull" -Skip:$script:SkipRegistryTests {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestKeyPath) {
      Remove-Item -LiteralPath $script:TestKeyPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -Path $script:TestKeyPath -Force | Out-Null
    New-ItemProperty -Path $script:TestKeyPath -Name 'MyDword' -Value 42 -PropertyType DWord | Out-Null
  }

  It "Returns correct value when exists" {
    $result = Get-RegDwordOrNull -Path $script:TestKeyPath -Name 'MyDword'
    $result | Should -Be 42
  }

  It "Returns null for non-existent value" {
    $result = Get-RegDwordOrNull -Path $script:TestKeyPath -Name 'NonExistent'
    $result | Should -BeNullOrEmpty
  }

  It "Returns null for non-existent key" {
    $result = Get-RegDwordOrNull -Path 'HKCU:\Software\NonExistentKey12345' -Name 'Value'
    $result | Should -BeNullOrEmpty
  }
}

Describe "Remove-RegistryKeyIfExists" -Skip:$script:SkipRegistryTests {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestKeyPath) {
      Remove-Item -LiteralPath $script:TestKeyPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It "Removes existing key and returns true" {
    New-Item -Path $script:TestKeyPath -Force | Out-Null
    $result = Remove-RegistryKeyIfExists -Path $script:TestKeyPath
    $result | Should -Be $true
    Test-Path -LiteralPath $script:TestKeyPath | Should -Be $false
  }

  It "Returns false for non-existent key" {
    $result = Remove-RegistryKeyIfExists -Path 'HKCU:\Software\NonExistentKey12345'
    $result | Should -Be $false
  }

  It "Removes key with subkeys when Recurse is specified" {
    New-Item -Path $script:TestKeyPath2 -Force | Out-Null
    $result = Remove-RegistryKeyIfExists -Path $script:TestKeyPath -Recurse
    $result | Should -Be $true
    Test-Path -LiteralPath $script:TestKeyPath | Should -Be $false
  }
}

Describe "Set-RegString empty name" -Skip:$script:SkipRegistryTests {
  It "Throws for empty name" {
    { Set-RegString -Path $script:TestKeyPath -Name '' -Value 'val' } | Should -Throw
  }
}
