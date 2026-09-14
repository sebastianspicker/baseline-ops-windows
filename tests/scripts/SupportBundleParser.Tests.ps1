#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

Describe '10-SupportBundle-Parser archive validation' -Tag 'SupportBundle', 'Security' {
  BeforeAll {
function Test-ParserDoesNotReuseAStaleExtractionDirectoryForTheSameArchive {
    $archivePath = Join-Path $TestDrive 'SupportBundle-stale.zip'
    $extractRoot = Join-Path $TestDrive 'extracted'
    New-ParserTestZip -Path $archivePath -Entries @(@{ Name = 'Summary.json'; Content = '{}' })
    Mock -CommandName Initialize-TrustedExtractRoot -MockWith {
      param($Path)
      [void][System.IO.Directory]::CreateDirectory($Path)
    }
    Mock -CommandName New-AdminOnlyDirectory -MockWith {
      param($Path)
      [void][System.IO.Directory]::CreateDirectory($Path)
    }
    Mock -CommandName Ensure-AdminOnlyDirectoryTree -MockWith {
      param($Path)
      [void][System.IO.Directory]::CreateDirectory($Path)
    }

    $first = Ensure-ExtractedWorkDir -ZipPath $archivePath -ExtractRoot $extractRoot
    Set-Content -LiteralPath (Join-Path $first 'stale.txt') -Value 'must not be reused'
    $second = Ensure-ExtractedWorkDir -ZipPath $archivePath -ExtractRoot $extractRoot

    $first | Should -Not -Be $second
    Test-Path -LiteralPath (Join-Path $second 'stale.txt') | Should -BeFalse
  }

function Test-ParserChecksCommonApplicationDataOnlyThroughAncestorReplacementRights {
    $source = Get-Content -LiteralPath $helperPath -Raw

    $source | Should -Match 'Assert-TrustedWindowsPathAcl -Path \$missing\[\$i\] -CheckAncestors'
    $source | Should -Match 'Assert-TrustedWindowsPathAcl -Path \$fullPath -CheckAncestors'
    $source | Should -Not -Match '\$protectedBranch'
  }

function Test-ParserCreatesAnACLProtectedExtractionBranchBelowActualCommonApplicationData {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
      Set-ItResult -Skipped -Because 'The current Windows test identity is not elevated.'
      return
    }
    $commonApplicationData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ([string]::IsNullOrWhiteSpace($commonApplicationData) -or -not (Test-Path -LiteralPath $commonApplicationData -PathType Container)) {
      throw 'CommonApplicationData is unavailable on this Windows host.'
    }

    $branch = Join-Path $commonApplicationData ('BaselineOpsForWindows-Pester-' + [guid]::NewGuid().ToString('N'))
    $extractRoot = Join-Path (Join-Path $branch 'SupportBundles') '_extracted'
    $probe = Join-Path $extractRoot 'acl-probe.txt'
    try {
      Initialize-TrustedExtractRoot -Path $extractRoot
      Test-NoReparsePointAncestor -Path $extractRoot
      { Assert-TrustedWindowsPathAcl -Path $extractRoot } | Should -Not -Throw
      Set-Content -LiteralPath $probe -Value 'protected read-write probe' -Encoding utf8 -ErrorAction Stop
      (Get-Content -LiteralPath $probe -Raw -ErrorAction Stop).TrimEnd("`r", "`n") | Should -Be 'protected read-write probe'
    } finally {
      Remove-Item -LiteralPath $branch -Recurse -Force -ErrorAction Stop
    }
    Test-Path -LiteralPath $branch | Should -BeFalse
  }

function Test-ParserRejectsTraversalPathsBeforeExtraction {
    $path = Join-Path $TestDrive 'traversal.zip'
    New-ParserTestZip -Path $path -Entries @(@{ Name = '../outside.txt'; Content = 'nope' })
    { Invoke-ParserZipValidation -Path $path } | Should -Throw '*traversal*'
  }

function Test-ParserRejectsDuplicateCanonicalPathsBeforeExtraction {
    $path = Join-Path $TestDrive 'duplicate.zip'
    New-ParserTestZip -Path $path -Entries @(@{ Name = 'nested\report.txt'; Content = 'one' }, @{ Name = 'nested/report.txt'; Content = 'two' })
    { Invoke-ParserZipValidation -Path $path } | Should -Throw '*duplicate canonical path*'
  }

function Test-ParserRejectsEntriesExceedingTheConfiguredUncompressedLimit {
    $path = Join-Path $TestDrive 'oversized.zip'
    New-ParserTestZip -Path $path -Entries @(@{ Name = 'report.txt'; Content = 'more than one byte' })
    { Invoke-ParserZipValidation -Path $path -MaxEntryBytes 1 } | Should -Throw '*exceeds*'
  }

function Test-ParserRejectsSuspiciousCompressionRatiosBeforeExtraction {
    $path = Join-Path $TestDrive 'ratio.zip'
    New-ParserTestZip -Path $path -Entries @(@{ Name = 'repeat.txt'; Content = ('A' * 8192) })
    { Invoke-ParserZipValidation -Path $path -MaxCompressionRatio 10 } | Should -Throw '*compression ratio*'
  }

function Test-ParserRejectsWindowsAmbiguousZIPComponentNamesBeforeExtraction {
    $path = Join-Path $TestDrive ("unsafe-{0}.zip" -f [guid]::NewGuid().ToString('N'))
    New-ParserTestZip -Path $path -Entries @(@{ Name = $Name; Content = 'nope' })
    { Invoke-ParserZipValidation -Path $path } | Should -Throw $Expected
  }


    $scriptPath = Join-Path $PSScriptRoot '../../scripts/10-SupportBundle-Parser.ps1'
    $helperPath = Join-Path $PSScriptRoot '../../scripts/internal/10-SupportBundle-Parser.helpers.ps1'
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    @($tokens).Count | Should -BeGreaterThan 0
    $helperAst = [System.Management.Automation.Language.Parser]::ParseFile($helperPath, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    @($tokens).Count | Should -BeGreaterThan 0
    Import-Module (Join-Path $PSScriptRoot '../../lib/Validation.psm1') -Force

    $required = @(
      'Ensure-ExtractedWorkDir', 'Test-NoReparsePointAncestor',
      'Set-AdminOnlyDirectoryAcl', 'New-AdminOnlyDirectorySecurity',
      'New-AdminOnlyDirectory', 'Initialize-TrustedExtractRoot',
      'Ensure-AdminOnlyDirectoryTree', 'Get-ValidatedZipEntries'
    )
    $definitions = @($helperAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $required -contains $node.Name }, $true) | Sort-Object { $_.Extent.StartOffset })
    $definitions.Count | Should -Be $required.Count
    foreach ($definition in $definitions) { . ([scriptblock]::Create($definition.Extent.Text)) }
    function ConvertTo-SafeDisplayPath { param([string]$Path) return $Path }

    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    function New-ParserTestZip {
      param([string]$Path, [hashtable[]]$Entries)
      $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
      try {
        $zip = New-Object -TypeName System.IO.Compression.ZipArchive -ArgumentList @($stream, [System.IO.Compression.ZipArchiveMode]::Create, $false)
        try {
          foreach ($spec in $Entries) {
            $entry = $zip.CreateEntry([string]$spec.Name)
            if ($null -ne $spec.Content) {
              $writer = New-Object System.IO.StreamWriter($entry.Open())
              try { $writer.Write([string]$spec.Content) } finally { $writer.Dispose() }
            }
          }
        } finally { $zip.Dispose() }
      } finally { $stream.Dispose() }
    }
    function Invoke-ParserZipValidation {
      param([string]$Path, [Int64]$MaxEntryBytes = 128MB, [Int64]$MaxTotalBytes = 512MB, [Int32]$MaxCompressionRatio = 100)
      $stream = [System.IO.File]::OpenRead($Path)
      try {
        $zip = New-Object -TypeName System.IO.Compression.ZipArchive -ArgumentList @($stream, [System.IO.Compression.ZipArchiveMode]::Read, $false)
        try { Get-ValidatedZipEntries -Archive $zip -MaxEntries 2048 -MaxEntryBytes $MaxEntryBytes -MaxTotalBytes $MaxTotalBytes -MaxCompressionRatio $MaxCompressionRatio }
        finally { $zip.Dispose() }
      } finally { $stream.Dispose() }
    }

  }



  It 'does not reuse a stale extraction directory for the same archive' { Test-ParserDoesNotReuseAStaleExtractionDirectoryForTheSameArchive }

  It 'checks CommonApplicationData only through ancestor replacement rights' { Test-ParserChecksCommonApplicationDataOnlyThroughAncestorReplacementRights }

  It 'creates an ACL-protected extraction branch below actual CommonApplicationData' -Skip:([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { Test-ParserCreatesAnACLProtectedExtractionBranchBelowActualCommonApplicationData }

  It 'rejects traversal paths before extraction' { Test-ParserRejectsTraversalPathsBeforeExtraction }

  It 'rejects duplicate canonical paths before extraction' { Test-ParserRejectsDuplicateCanonicalPathsBeforeExtraction }

  It 'rejects entries exceeding the configured uncompressed limit' { Test-ParserRejectsEntriesExceedingTheConfiguredUncompressedLimit }

  It 'rejects suspicious compression ratios before extraction' { Test-ParserRejectsSuspiciousCompressionRatiosBeforeExtraction }

  It 'rejects Windows-ambiguous ZIP component names before extraction' -ForEach @(
    @{ Name = 'logs/report.txt:payload'; Expected = '*unsafe Windows path component*' },
    @{ Name = 'logs/report. '; Expected = '*unsafe Windows path component*' },
    @{ Name = 'logs/CON.txt'; Expected = '*reserved Windows device name*' }
  ) { Test-ParserRejectsWindowsAmbiguousZIPComponentNamesBeforeExtraction }
}
