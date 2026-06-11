#requires -version 5.1
<#
.SYNOPSIS
Pester tests for Evidence.psm1 module

.DESCRIPTION
Unit tests for Expand-Env, Get-FileSha256, and Copy-ToEvidence.
#>

[CmdletBinding()]
param()

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../lib/Evidence.psm1') -Force

  $tempRoot = if ([string]::IsNullOrWhiteSpace($env:TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:TEMP }
  $script:TestDir = Join-Path $tempRoot 'EvidenceModuleTests'
  $script:SourceDir = Join-Path $script:TestDir 'source'
  $script:EvidenceDir = Join-Path $script:TestDir 'evidence'
  $script:TestFile = Join-Path $script:SourceDir 'testfile.txt'
}

AfterAll {
  if (-not [string]::IsNullOrWhiteSpace($script:TestDir) -and (Test-Path -LiteralPath $script:TestDir)) {
    Remove-Item -LiteralPath $script:TestDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Describe 'Expand-Env' {
  It 'Returns empty/null for null input' {
    $result = Expand-Env -Path $null
    $result | Should -BeNullOrEmpty
  }

  It 'Returns empty for empty string' {
    $result = Expand-Env -Path ''
    $result | Should -BeNullOrEmpty
  }

  It 'Expands a known environment variable' {
    $env:EVIDENCE_TEST_VAR = 'hello'
    try {
      $result = Expand-Env -Path '%EVIDENCE_TEST_VAR%/sub'
      $result | Should -Be 'hello/sub'
    } finally {
      Remove-Item Env:EVIDENCE_TEST_VAR -ErrorAction SilentlyContinue
    }
  }

  It 'Returns path unchanged when no env vars present' {
    $result = Expand-Env -Path '/some/plain/path'
    $result | Should -Be '/some/plain/path'
  }
}

Describe 'Get-FileSha256' {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestDir) {
      Remove-Item -LiteralPath $script:TestDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -Path $script:SourceDir -ItemType Directory -Force | Out-Null
  }

  It 'Returns the correct SHA256 hash for known content' {
    [System.IO.File]::WriteAllBytes($script:TestFile, [System.Text.Encoding]::UTF8.GetBytes('hello world'))
    $result = Get-FileSha256 -Path $script:TestFile
    $result | Should -Be 'B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9'
  }

  It 'Returns null for missing file' {
    $result = Get-FileSha256 -Path (Join-Path $script:SourceDir 'nonexistent.txt')
    $result | Should -BeNullOrEmpty
  }

  It 'Returns null when hash computation fails' {
    'locked content' | Out-File -FilePath $script:TestFile -Encoding UTF8
    Mock -CommandName Get-FileHash -ModuleName Evidence -MockWith { throw 'Access denied' }

    Get-FileSha256 -Path $script:TestFile | Should -BeNullOrEmpty
  }

  It 'Returns consistent hash for same content' {
    'consistent content' | Out-File -FilePath $script:TestFile -Encoding UTF8
    $hash1 = Get-FileSha256 -Path $script:TestFile
    $hash2 = Get-FileSha256 -Path $script:TestFile
    $hash1 | Should -Be $hash2
  }
}

Describe 'Copy-ToEvidence' {
  BeforeEach {
    if (Test-Path -LiteralPath $script:TestDir) {
      Remove-Item -LiteralPath $script:TestDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -Path $script:SourceDir -ItemType Directory -Force | Out-Null
    New-Item -Path $script:EvidenceDir -ItemType Directory -Force | Out-Null
    'evidence content' | Out-File -FilePath $script:TestFile -Encoding UTF8
  }

  It 'Copies file to evidence directory' {
    $success, $dest = Copy-ToEvidence -SourcePath $script:TestFile -EvidenceBaseDir $script:EvidenceDir
    $success | Should -Be $true
    Test-Path -LiteralPath $dest | Should -Be $true
  }

  It 'Rejects path traversal in source path' {
    $traversalPath = Join-Path $script:SourceDir '../../etc/passwd'
    $success, $reason = Copy-ToEvidence -SourcePath $traversalPath -EvidenceBaseDir $script:EvidenceDir
    $success | Should -Be $false
    $reason | Should -Be 'path-traversal-not-allowed'
  }

  It 'Rejects path traversal in evidence base dir' {
    $traversalBase = Join-Path $script:EvidenceDir '../../escape'
    $success, $reason = Copy-ToEvidence -SourcePath $script:TestFile -EvidenceBaseDir $traversalBase
    $success | Should -Be $false
    $reason | Should -Be 'path-traversal-not-allowed'
  }

  It 'Returns false for missing source file' {
    $success, $reason = Copy-ToEvidence -SourcePath (Join-Path $script:SourceDir 'ghost.txt') -EvidenceBaseDir $script:EvidenceDir
    $success | Should -Be $false
    $reason | Should -Be 'missing'
  }

  It 'Returns false for directory source' {
    $success, $reason = Copy-ToEvidence -SourcePath $script:SourceDir -EvidenceBaseDir $script:EvidenceDir
    $success | Should -Be $false
    $reason | Should -Be 'is-directory'
  }

  It 'Rejects file exceeding MaxFileSizeMB' {
    $largeFile = Join-Path $script:SourceDir 'large.bin'
    [System.IO.File]::WriteAllBytes($largeFile, (New-Object byte[] ((1MB) + 1)))
    $total = [ref][int64]123

    $success, $reason = Copy-ToEvidence -SourcePath $largeFile -EvidenceBaseDir $script:EvidenceDir -MaxFileSizeMB 1 -RunningTotalBytes $total

    $success | Should -Be $false
    $reason | Should -Be 'file-too-large'
    $total.Value | Should -Be 123
    @(Get-ChildItem -LiteralPath $script:EvidenceDir -File -Recurse -ErrorAction SilentlyContinue).Count | Should -Be 0
  }

  It 'Enforces quota with RunningTotalBytes' {
    $total = [ref][int64](1MB)
    $success, $reason = Copy-ToEvidence -SourcePath $script:TestFile -EvidenceBaseDir $script:EvidenceDir -MaxTotalMB 1 -RunningTotalBytes $total

    $success | Should -Be $false
    $reason | Should -Be 'quota-exceeded'
    $total.Value | Should -Be (1MB)
    @(Get-ChildItem -LiteralPath $script:EvidenceDir -File -Recurse -ErrorAction SilentlyContinue).Count | Should -Be 0
  }

  It 'Treats MaxTotalMB 0 as unlimited' {
    $total = [ref][int64]0
    $success, $dest = Copy-ToEvidence -SourcePath $script:TestFile -EvidenceBaseDir $script:EvidenceDir -MaxTotalMB 0 -RunningTotalBytes $total

    $success | Should -Be $true
    Test-Path -LiteralPath $dest | Should -Be $true
  }
}
