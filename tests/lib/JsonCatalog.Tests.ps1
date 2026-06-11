#requires -version 5.1
<#
.SYNOPSIS
Pester tests for JsonCatalog.psm1 module

.DESCRIPTION
Unit tests for Read-JsonFileSafe.
Write-JsonToFile was removed in Phase 4.1; JSON writing is handled by Save-Json (Serialization.psm1).
#>

[CmdletBinding()]
param()

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../lib/JsonCatalog.psm1') -Force

  $tempRoot = if ([string]::IsNullOrWhiteSpace($env:TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:TEMP }
  $script:TestDir = Join-Path $tempRoot 'JsonCatalogModuleTests'
  $script:TestJsonFile = Join-Path $script:TestDir 'test.json'
}

AfterAll {
  if (-not [string]::IsNullOrWhiteSpace($script:TestDir) -and (Test-Path -LiteralPath $script:TestDir)) {
    Remove-Item -LiteralPath $script:TestDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Describe 'Read-JsonFileSafe' {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestDir) {
      Remove-Item -LiteralPath $script:TestDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -Path $script:TestDir -ItemType Directory -Force | Out-Null
  }

  It 'Returns null for missing file' {
    $result = Read-JsonFileSafe -Path (Join-Path $script:TestDir 'nonexistent.json')
    $result | Should -BeNullOrEmpty
  }

  It 'Returns null for empty path' {
    $result = Read-JsonFileSafe -Path ''
    $result | Should -BeNullOrEmpty
  }

  It 'Returns null for empty file' {
    '' | Out-File -FilePath $script:TestJsonFile -Encoding UTF8
    $result = Read-JsonFileSafe -Path $script:TestJsonFile
    $result | Should -BeNullOrEmpty
  }

  It 'Returns null for invalid JSON' {
    'not valid json {{{' | Out-File -FilePath $script:TestJsonFile -Encoding UTF8
    $result = Read-JsonFileSafe -Path $script:TestJsonFile
    $result | Should -BeNullOrEmpty
  }

  It 'Parses valid JSON file' {
    '{"Name": "Test", "Value": 42}' | Out-File -FilePath $script:TestJsonFile -Encoding UTF8
    $result = Read-JsonFileSafe -Path $script:TestJsonFile
    $result.Name | Should -Be 'Test'
    $result.Value | Should -Be 42
  }
}

Describe 'Read-JsonFileWithStatus' -Tag 'Config' {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestDir) {
      Remove-Item -LiteralPath $script:TestDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -Path $script:TestDir -ItemType Directory -Force | Out-Null
  }

  It 'Distinguishes a missing explicit file from an omitted path' {
    $omitted = Read-JsonFileWithStatus -Path ''
    $missing = Read-JsonFileWithStatus -Path (Join-Path $script:TestDir 'missing.json')

    $omitted.Meta.Status | Should -Be 'NotProvided'
    $omitted.Meta.Provided | Should -BeFalse
    $missing.Meta.Status | Should -Be 'Missing'
    $missing.Meta.Provided | Should -BeTrue
    $missing.Meta.Error | Should -Not -BeNullOrEmpty
  }

  It 'Reports invalid JSON with an explicit status and error' {
    'not valid json {{{' | Out-File -FilePath $script:TestJsonFile -Encoding UTF8

    $result = Read-JsonFileWithStatus -Path $script:TestJsonFile

    $result.Data | Should -BeNullOrEmpty
    $result.Meta.Loaded | Should -BeFalse
    $result.Meta.Status | Should -Be 'Invalid'
    $result.Meta.Error | Should -Not -BeNullOrEmpty
  }
}
