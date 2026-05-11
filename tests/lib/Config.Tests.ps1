#requires -version 5.1
<#
.SYNOPSIS
Pester tests for Config.psm1 module

.DESCRIPTION
Unit tests for ConvertTo-Hashtable and Read-ConfigWithDefaults.
#>

[CmdletBinding()]
param()

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force -DisableNameChecking
  Import-Module (Join-Path $PSScriptRoot '../../lib/Config.psm1') -Force

  $tempRoot = if ([string]::IsNullOrWhiteSpace($env:TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:TEMP }
  $script:TestDir = Join-Path $tempRoot 'ConfigModuleTests'
  $script:TestConfigFile = Join-Path $script:TestDir 'test-config.json'
}

AfterAll {
  if (-not [string]::IsNullOrWhiteSpace($script:TestDir) -and (Test-Path -LiteralPath $script:TestDir)) {
    Remove-Item -LiteralPath $script:TestDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Describe 'ConvertTo-Hashtable' {
  It 'Returns empty hashtable for null input' {
    $result = ConvertTo-Hashtable -Object $null
    $result | Should -BeOfType [hashtable]
    $result.Count | Should -Be 0
  }

  It 'Returns same hashtable when given a hashtable' {
    $ht = @{ Key = 'Value' }
    $result = ConvertTo-Hashtable -Object $ht
    $result | Should -BeOfType [hashtable]
    $result.Key | Should -Be 'Value'
  }

  It 'Converts PSCustomObject to hashtable' {
    $obj = [pscustomobject]@{ Name = 'Test'; Count = 42 }
    $result = ConvertTo-Hashtable -Object $obj
    $result | Should -BeOfType [hashtable]
    $result.Name | Should -Be 'Test'
    $result.Count | Should -Be 42
  }

  It 'Converts nested PSCustomObject properties' {
    $obj = [pscustomobject]@{ Outer = 'Value'; Inner = [pscustomobject]@{ Deep = 1 } }
    $result = ConvertTo-Hashtable -Object $obj
    $result | Should -BeOfType [hashtable]
    $result.Outer | Should -Be 'Value'
    # Inner is still a PSCustomObject (shallow conversion)
    $result.Inner.Deep | Should -Be 1
  }

  It 'Preserves array values' {
    $obj = [pscustomobject]@{ Items = @(1, 2, 3) }
    $result = ConvertTo-Hashtable -Object $obj
    $result.Items.Count | Should -Be 3
    $result.Items[1] | Should -Be 2
  }
}

Describe 'Read-ConfigWithDefaults' {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestDir) {
      Remove-Item -LiteralPath $script:TestDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -Path $script:TestDir -ItemType Directory -Force | Out-Null
  }

  It 'Returns defaults when path points to nonexistent file' {
    $defaults = @{ Timeout = 30; Enabled = $true }
    $fakePath = Join-Path $script:TestDir 'does-not-exist-12345.json'
    $result = Read-ConfigWithDefaults -Path $fakePath -Defaults $defaults -AsHashtable
    $result.Config.Timeout | Should -Be 30
    $result.Config.Enabled | Should -Be $true
    $result.Meta.UsedDefaults | Should -Be $true
    $result.Meta.Loaded | Should -Be $false
  }

  It 'Returns defaults when file is missing' {
    $defaults = @{ Timeout = 30 }
    $result = Read-ConfigWithDefaults -Path (Join-Path $script:TestDir 'nonexistent.json') -Defaults $defaults -AsHashtable
    $result.Config.Timeout | Should -Be 30
    $result.Meta.UsedDefaults | Should -Be $true
    $result.Meta.Error | Should -Not -BeNullOrEmpty
  }

  It 'Loads valid JSON and merges with defaults' {
    $defaults = @{ Timeout = 30; Enabled = $true; Custom = $null }
    $json = '{"Timeout": 60, "Custom": "value"}'
    $json | Out-File -FilePath $script:TestConfigFile -Encoding UTF8

    $result = Read-ConfigWithDefaults -Path $script:TestConfigFile -Defaults $defaults -AsHashtable
    $result.Config.Timeout | Should -Be 60
    $result.Config.Enabled | Should -Be $true
    $result.Config.Custom | Should -Be 'value'
    $result.Meta.Loaded | Should -Be $true
    $result.Meta.UsedDefaults | Should -Be $false
  }

  It 'Returns null config with ReturnNullWhenMissing when file is missing' {
    $fakePath = Join-Path $script:TestDir 'missing-for-null-test.json'
    $result = Read-ConfigWithDefaults -Path $fakePath -ReturnNullWhenMissing
    $result.Config | Should -BeNullOrEmpty
    $result.Meta.UsedDefaults | Should -Be $true
  }

  It 'Returns null config with ReturnNullOnError when file is empty' {
    '' | Out-File -FilePath $script:TestConfigFile -Encoding UTF8
    $result = Read-ConfigWithDefaults -Path $script:TestConfigFile -ReturnNullOnError
    $result.Config | Should -BeNullOrEmpty
    $result.Meta.Error | Should -Not -BeNullOrEmpty
  }

  It 'Invokes OnWarning callback when file is missing' {
    $warningMsg = $null
    $callback = { param($m) $script:warningMsg = $m }
    $result = Read-ConfigWithDefaults -Path (Join-Path $script:TestDir 'missing.json') -OnWarning $callback
    $script:warningMsg | Should -Not -BeNullOrEmpty
  }

  It 'Returns PSCustomObject config by default (not hashtable)' {
    $json = '{"Key": "Value"}'
    $json | Out-File -FilePath $script:TestConfigFile -Encoding UTF8

    $result = Read-ConfigWithDefaults -Path $script:TestConfigFile -Defaults @{ Key = $null }
    $result.Config | Should -BeOfType [pscustomobject]
    $result.Config.Key | Should -Be 'Value'
  }

  It 'Returns hashtable config when AsHashtable is set' {
    $json = '{"Key": "Value"}'
    $json | Out-File -FilePath $script:TestConfigFile -Encoding UTF8

    $result = Read-ConfigWithDefaults -Path $script:TestConfigFile -Defaults @{ Key = $null } -AsHashtable
    $result.Config | Should -BeOfType [hashtable]
    $result.Config.Key | Should -Be 'Value'
  }
}
