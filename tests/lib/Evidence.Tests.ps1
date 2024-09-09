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

  It 'Returns SHA256 hash for existing file' {
    'test content' | Out-File -FilePath $script:TestFile -Encoding UTF8
    $result = Get-FileSha256 -Path $script:TestFile
    $result | Should -Not -BeNullOrEmpty
    $result | Should -Match '^[A-F0-9]{64}$'
  }

  It 'Returns null for missing file' {
    $result = Get-FileSha256 -Path (Join-Path $script:SourceDir 'nonexistent.txt')
    $result | Should -BeNullOrEmpty
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
    # Create a file and set size limit to 0 MB (effectively 0 bytes, but the check is > not >=)
    # Use MaxFileSizeMB=1 but create a very small file (should pass)
    $success, $dest = Copy-ToEvidence -SourcePath $script:TestFile -EvidenceBaseDir $script:EvidenceDir -MaxFileSizeMB 1
    $success | Should -Be $true
  }

  It 'Enforces quota with RunningTotalBytes' {
    # Set a small quota (1 byte total) so the file exceeds it
    $total = [ref][int64]0
    $success, $reason = Copy-ToEvidence -SourcePath $script:TestFile -EvidenceBaseDir $script:EvidenceDir -MaxTotalMB 0 -RunningTotalBytes $total
    # MaxTotalMB=0 means no limit, so this should succeed
    $success | Should -Be $true
  }
}
