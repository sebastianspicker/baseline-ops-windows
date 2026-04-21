#requires -version 5.1
<#
.SYNOPSIS
Pester tests for sanitization helpers in Common.psm1 and Config.psm1.

.DESCRIPTION
Unit tests covering:
- Sanitize-Path  (Common.psm1)
- Read-ConfigWithDefaults (Config.psm1)
- ConvertTo-Hashtable (Config.psm1)

Converted from tests/Verify-Sanitization.ps1 to be automatically discovered by
Invoke-Pester.
#>

[CmdletBinding()]
param()

BeforeAll {
  $script:LibPath = Join-Path $PSScriptRoot '../../lib'
  Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
  Import-Module (Join-Path $script:LibPath 'Config.psm1')  -Force

  $script:TempDir  = Join-Path ([System.IO.Path]::GetTempPath()) 'SanitizationTests'
  $script:CfgFile  = Join-Path $script:TempDir 'test_config.json'
}

AfterAll {
  if (-not [string]::IsNullOrWhiteSpace($script:TempDir) -and (Test-Path -LiteralPath $script:TempDir)) {
    Remove-Item -LiteralPath $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Describe "Sanitize-Path" {
  It "Returns a value for a valid existing path" {
    $result = Sanitize-Path -Path ([System.IO.Path]::GetTempPath())
    $result | Should -Not -BeNullOrEmpty
  }

  It "Returns null for path traversal attempt (..)" {
    $result = Sanitize-Path -Path '../../Windows/System32'
    $result | Should -BeNullOrEmpty
  }
}

Describe "Read-ConfigWithDefaults" {
  BeforeAll {
    if (-not (Test-Path -LiteralPath $script:TempDir)) {
      New-Item -Path $script:TempDir -ItemType Directory -Force | Out-Null
    }
    @'
{
    "TestKey": "TestValue",
    "Nested": { "Sub": 123 }
}
'@ | Out-File -FilePath $script:CfgFile -Encoding UTF8
  }

  It "Overrides a default value with the file value" {
    $res = Read-ConfigWithDefaults -Path $script:CfgFile -Defaults @{ TestKey = 'ShouldOverride'; DefaultKey = 'DefaultValue' }
    $res.Config.TestKey | Should -Be 'TestValue'
  }

  It "Keeps default values not present in the file" {
    $res = Read-ConfigWithDefaults -Path $script:CfgFile -Defaults @{ TestKey = 'ShouldOverride'; DefaultKey = 'DefaultValue' }
    $res.Config.DefaultKey | Should -Be 'DefaultValue'
  }

  It "Returns Meta.Loaded = true on success" {
    $res = Read-ConfigWithDefaults -Path $script:CfgFile -Defaults @{ TestKey = 'ShouldOverride' }
    $res.Meta.Loaded | Should -Be $true
  }
}

Describe "ConvertTo-Hashtable" {
  It "Converts a PSCustomObject to a hashtable" {
    $obj = [pscustomobject]@{ A = 1; B = 2 }
    $result = ConvertTo-Hashtable -Object $obj
    $result | Should -BeOfType [hashtable]
  }

  It "Preserves key A with correct value" {
    $obj = [pscustomobject]@{ A = 1; B = 2 }
    $result = ConvertTo-Hashtable -Object $obj
    $result.A | Should -Be 1
  }

  It "Preserves key B with correct value" {
    $obj = [pscustomobject]@{ A = 1; B = 2 }
    $result = ConvertTo-Hashtable -Object $obj
    $result.B | Should -Be 2
  }
}
