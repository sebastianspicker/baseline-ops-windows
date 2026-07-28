#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

Describe '10-SupportBundle-Parser archive validation' -Tag 'SupportBundle', 'Security' {
  BeforeAll {
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

  It 'does not reuse a stale extraction directory for the same archive' {
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
      param($Path, $Root)
      [void][System.IO.Directory]::CreateDirectory($Path)
    }

    $first = Ensure-ExtractedWorkDir -ZipPath $archivePath -ExtractRoot $extractRoot
    Set-Content -LiteralPath (Join-Path $first 'stale.txt') -Value 'must not be reused'
    $second = Ensure-ExtractedWorkDir -ZipPath $archivePath -ExtractRoot $extractRoot

    $first | Should -Not -Be $second
    Test-Path -LiteralPath (Join-Path $second 'stale.txt') | Should -BeFalse
  }

  It 'checks CommonApplicationData only through ancestor replacement rights' {
    $source = Get-Content -LiteralPath $helperPath -Raw

    $source | Should -Match 'Assert-TrustedWindowsPathAcl -Path \$missing\[\$i\] -CheckAncestors'
    $source | Should -Match 'Assert-TrustedWindowsPathAcl -Path \$fullPath -CheckAncestors'
    $source | Should -Not -Match '\$protectedBranch'
  }

  It 'creates an ACL-protected extraction branch below actual CommonApplicationData' -Skip:([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
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

  It 'rejects traversal paths before extraction' {
    $path = Join-Path $TestDrive 'traversal.zip'
    New-ParserTestZip -Path $path -Entries @(@{ Name = '../outside.txt'; Content = 'nope' })
    { Invoke-ParserZipValidation -Path $path } | Should -Throw '*traversal*'
  }

  It 'rejects duplicate canonical paths before extraction' {
    $path = Join-Path $TestDrive 'duplicate.zip'
    New-ParserTestZip -Path $path -Entries @(@{ Name = 'nested\report.txt'; Content = 'one' }, @{ Name = 'nested/report.txt'; Content = 'two' })
    { Invoke-ParserZipValidation -Path $path } | Should -Throw '*duplicate canonical path*'
  }

  It 'rejects entries exceeding the configured uncompressed limit' {
    $path = Join-Path $TestDrive 'oversized.zip'
    New-ParserTestZip -Path $path -Entries @(@{ Name = 'report.txt'; Content = 'more than one byte' })
    { Invoke-ParserZipValidation -Path $path -MaxEntryBytes 1 } | Should -Throw '*exceeds*'
  }

  It 'rejects suspicious compression ratios before extraction' {
    $path = Join-Path $TestDrive 'ratio.zip'
    New-ParserTestZip -Path $path -Entries @(@{ Name = 'repeat.txt'; Content = ('A' * 8192) })
    { Invoke-ParserZipValidation -Path $path -MaxCompressionRatio 10 } | Should -Throw '*compression ratio*'
  }

  It 'rejects Windows-ambiguous ZIP component names before extraction' -ForEach @(
    @{ Name = 'logs/report.txt:payload'; Expected = '*unsafe Windows path component*' },
    @{ Name = 'logs/report. '; Expected = '*unsafe Windows path component*' },
    @{ Name = 'logs/CON.txt'; Expected = '*reserved Windows device name*' }
  ) {
    $path = Join-Path $TestDrive ("unsafe-{0}.zip" -f [guid]::NewGuid().ToString('N'))
    New-ParserTestZip -Path $path -Entries @(@{ Name = $Name; Content = 'nope' })
    { Invoke-ParserZipValidation -Path $path } | Should -Throw $Expected
  }
}

Describe '10-SupportBundle-Parser terminal failures and defaults' -Tag 'SupportBundle', 'Security' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/10-SupportBundle-Parser.ps1'

    function Get-ParserTestCommonApplicationData {
      if ([Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
        return [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
      }
      return $TestDrive
    }

    function Get-ParserTestExtractRoot {
      $commonApplicationData = Get-ParserTestCommonApplicationData
      return (Join-Path (Join-Path (Join-Path $commonApplicationData 'BaselineOpsForWindows') 'SupportBundles') '_extracted')
    }

    function Test-ParserTestWindowsAdministrator {
      if ([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { return $true }
      $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
      $principal = New-Object Security.Principal.WindowsPrincipal($identity)
      return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Get-ParserExtractRunSnapshot {
      param([Parameter(Mandatory)][string]$ExtractRoot)
      if (-not (Test-Path -LiteralPath $ExtractRoot -PathType Container)) { return @() }
      return @((Get-ChildItem -LiteralPath $ExtractRoot -Directory -Force -ErrorAction Stop).FullName)
    }

    function Remove-NewParserExtractRuns {
      param(
        [Parameter(Mandatory)][string]$ExtractRoot,
        [AllowEmptyCollection()][string[]]$Before = @(),
        [Parameter(Mandatory)][string]$WorkDirectoryPrefix
      )
      if (-not (Test-Path -LiteralPath $ExtractRoot -PathType Container)) { return }
      foreach ($item in @(Get-ChildItem -LiteralPath $ExtractRoot -Directory -Force -ErrorAction Stop)) {
        if ($Before -contains $item.FullName -or -not $item.Name.StartsWith($WorkDirectoryPrefix, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
          throw "Refusing to remove reparse-point extraction test run: $($item.FullName)"
        }
        Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
      }
    }

    function New-SupportBundleParserFixture {
      param(
        [Parameter(Mandatory)][string]$Root,
        [AllowEmptyCollection()][string[]]$FailedRecordErrors = @(),
        [AllowEmptyCollection()][string[]]$LegacyErrors = @()
      )
      $supportDir = Join-Path $Root 'bundles'
      $extractRoot = Get-ParserTestExtractRoot
      $sourceDir = Join-Path $Root 'source'
      $proofSourceDir = Join-Path $sourceDir 'proofs'
      [void][System.IO.Directory]::CreateDirectory($supportDir)
      [void][System.IO.Directory]::CreateDirectory($sourceDir)
      [void][System.IO.Directory]::CreateDirectory($proofSourceDir)

      $summary = [ordered]@{
        Hostname = 'PARSER-TEST'
        Time = '2026-07-14T12:00:00'
        User = 'parser-test'
        Admin = $true
        Records = @(
          [ordered]@{
            Name = 'Config'
            Ok = $true
            ArtifactPath = $null
            Note = 'Config loaded and schema validated'
            Error = $null
            Time = '2026-07-14T12:00:00'
          }
        )
      }
      foreach ($producerError in $FailedRecordErrors) {
        $summary.Records += [ordered]@{
          Name = 'Collector'
          Ok = $false
          ArtifactPath = $null
          Note = $null
          Error = $producerError
          Time = '2026-07-14T12:00:01'
        }
      }
      if ($LegacyErrors.Count -gt 0) { $summary['Errors'] = @($LegacyErrors) }

      $proofNames = @(
        'SysmonState.json'
        'SysmonDriftState.json'
        'SoftwareInventory.json'
        'FirewallAudit.json'
        'HardwareAudit.json'
      )
      foreach ($proofName in $proofNames) {
        Set-Content -LiteralPath (Join-Path $proofSourceDir $proofName) -Value 'proof'
      }
      $summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $sourceDir 'Summary.json') -Encoding utf8

      $configPath = Join-Path $Root 'support-bundle.json'
      @{ Paths = @{ ProofDir = $proofSourceDir }; ProofOutFiles = @{
          SysmonState = (Join-Path $proofSourceDir 'SysmonState.json')
          SysmonDriftState = (Join-Path $proofSourceDir 'SysmonDriftState.json')
          SoftwareInventory = (Join-Path $proofSourceDir 'SoftwareInventory.json')
          FirewallAudit = (Join-Path $proofSourceDir 'FirewallAudit.json')
          HardwareAudit = (Join-Path $proofSourceDir 'HardwareAudit.json')
        } } |
        ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $configPath -Encoding utf8

      $archiveName = 'SupportBundle-parser-test-{0}.zip' -f [guid]::NewGuid().ToString('N')
      $archivePath = Join-Path $supportDir $archiveName
      [System.IO.Compression.ZipFile]::CreateFromDirectory($sourceDir, $archivePath)
      return [pscustomobject]@{
        SupportDir = $supportDir
        ExtractRoot = $extractRoot
        ConfigPath = $configPath
        WorkDirectoryPrefix = [System.IO.Path]::GetFileNameWithoutExtension($archiveName)
      }
    }

    function Invoke-SupportBundleParserFixture {
      param(
        [Parameter(Mandatory)]$Fixture
      )
      $testHostIsWindows = [Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
      $oldOS = $env:OS
      $oldProgramData = $env:ProgramData
      $before = Get-ParserExtractRunSnapshot -ExtractRoot $Fixture.ExtractRoot
      try {
        if (-not $testHostIsWindows) {
          $env:OS = 'Windows_NT'
          $env:ProgramData = $TestDrive
        }
        $output = @(& $scriptPath `
          -SupportDir $Fixture.SupportDir `
          -ExtractRoot $Fixture.ExtractRoot `
          -ConfigPath $Fixture.ConfigPath `
          -OutputFormat None `
          -PassThru `
          -Quiet `
          -NoColor `
          -Confirm:$false 6>$null)
        return [pscustomobject]@{ Output = $output; ExitCode = $LASTEXITCODE }
      } finally {
        Remove-NewParserExtractRuns -ExtractRoot $Fixture.ExtractRoot -Before $before -WorkDirectoryPrefix $Fixture.WorkDirectoryPrefix
        if (-not $testHostIsWindows) {
          if ($null -eq $oldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue } else { $env:OS = $oldOS }
          if ($null -eq $oldProgramData) { Remove-Item -LiteralPath Env:ProgramData -ErrorAction SilentlyContinue } else { $env:ProgramData = $oldProgramData }
        }
      }
    }
  }

  It 'emits exactly one V2 object for a successful PassThru parse' {
    if (-not (Test-ParserTestWindowsAdministrator)) {
      Set-ItResult -Skipped -Because 'The current Windows test identity is not elevated.'
      return
    }
    $fixture = New-SupportBundleParserFixture -Root (Join-Path $TestDrive 'success')
    $run = Invoke-SupportBundleParserFixture -Fixture $fixture

    $run.ExitCode | Should -Be 0
    @($run.Output).Count | Should -Be 1
    $run.Output[0].ScriptName | Should -Be '10-SupportBundle-Parser.ps1'
    $run.Output[0].Result | Should -Be 'OK'
    $run.Output[0].Summary.Hostname | Should -Be 'PARSER-TEST'
    $run.Output[0].Summary.BundleArchiveValidated | Should -BeTrue
    @($run.Output[0].Findings | Where-Object { $_.Code -eq 'SB-ZipMarker' }).Count | Should -Be 0
  }

  It 'turns failed producer Summary.Records into canonical findings and a non-OK result' {
    if (-not (Test-ParserTestWindowsAdministrator)) {
      Set-ItResult -Skipped -Because 'The current Windows test identity is not elevated.'
      return
    }
    $fixture = New-SupportBundleParserFixture -Root (Join-Path $TestDrive 'producer-error') -FailedRecordErrors @("collector failed`nwhile reading evidence")
    $run = Invoke-SupportBundleParserFixture -Fixture $fixture

    $run.ExitCode | Should -Be 2
    @($run.Output).Count | Should -Be 1
    $run.Output[0].Result | Should -Be 'WARN'
    @($run.Output[0].Summary.Errors).Count | Should -Be 1
    $finding = @($run.Output[0].Findings | Where-Object { $_.Code -eq 'SB-ProducerError' })
    $finding.Count | Should -Be 1
    $finding[0].Severity | Should -Be 'Medium'
    $finding[0].RecordName | Should -Be 'Collector'
    $finding[0].Message | Should -Be "SupportBundle producer record 'Collector' failed: collector failed while reading evidence"
  }

  It 'retains support for legacy Summary.Errors producer failures' {
    if (-not (Test-ParserTestWindowsAdministrator)) {
      Set-ItResult -Skipped -Because 'The current Windows test identity is not elevated.'
      return
    }
    $fixture = New-SupportBundleParserFixture -Root (Join-Path $TestDrive 'legacy-producer-error') -LegacyErrors @('legacy collector failed')
    $run = Invoke-SupportBundleParserFixture -Fixture $fixture

    $run.ExitCode | Should -Be 2
    $run.Output[0].Result | Should -Be 'WARN'
    $finding = @($run.Output[0].Findings | Where-Object { $_.Code -eq 'SB-ProducerError' })
    $finding.Count | Should -Be 1
    $finding[0].Message | Should -Be 'SupportBundle producer reported an error: legacy collector failed'
  }

  It 'uses the fixed ProgramData support-bundle root and terminates with V2 FAIL when no ZIP exists' {
    if (-not (Test-ParserTestWindowsAdministrator)) {
      Set-ItResult -Skipped -Because 'The current Windows test identity is not elevated.'
      return
    }
    $oldOS = $env:OS
    $oldProgramData = $env:ProgramData
    $commonApplicationData = Get-ParserTestCommonApplicationData
    $expectedSupportDir = Join-Path (Join-Path $commonApplicationData 'BaselineOpsForWindows') 'SupportBundles'
    if ([Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT -and
        (Test-Path -LiteralPath $expectedSupportDir -PathType Container) -and
        @(Get-ChildItem -LiteralPath $expectedSupportDir -Filter 'SupportBundle-*.zip' -File -Force).Count -gt 0) {
      Set-ItResult -Skipped -Because 'The shared CommonApplicationData support-bundle root already contains ZIP files.'
      return
    }
    try {
      if ([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        $env:OS = 'Windows_NT'
        $env:ProgramData = $TestDrive
      }
      $output = & $scriptPath -OutputFormat None -PassThru -Confirm:$false 6>$null
      $exitCode = $LASTEXITCODE
    } finally {
      if ([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        if ($null -eq $oldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue } else { $env:OS = $oldOS }
        if ($null -eq $oldProgramData) { Remove-Item -LiteralPath Env:ProgramData -ErrorAction SilentlyContinue } else { $env:ProgramData = $oldProgramData }
      }
    }
    $exitCode | Should -Be 1
    $result = @($output | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]
    $result.Result | Should -Be 'FAIL'
    $result.Summary.SupportDir | Should -Be $expectedSupportDir
  }

  It 'rejects an arbitrary extraction root before archive discovery or extraction' {
    $oldOS = $env:OS
    $oldProgramData = $env:ProgramData
    try {
      $env:OS = 'Windows_NT'
      $env:ProgramData = $TestDrive
      $output = & $scriptPath `
        -SupportDir (Join-Path $TestDrive 'missing-bundles') `
        -ExtractRoot (Join-Path $TestDrive 'attacker-controlled') `
        -OutputFormat None `
        -PassThru `
        -Confirm:$false 6>$null
      $exitCode = $LASTEXITCODE
    } finally {
      if ($null -eq $oldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue } else { $env:OS = $oldOS }
      if ($null -eq $oldProgramData) { Remove-Item -LiteralPath Env:ProgramData -ErrorAction SilentlyContinue } else { $env:ProgramData = $oldProgramData }
    }

    $exitCode | Should -Be 1
    $result = @($output | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]
    $result.Result | Should -Be 'FAIL'
    @($result.Findings | Where-Object Code -eq 'SB-UntrustedExtractRoot').Count | Should -Be 1
    Test-Path -LiteralPath (Join-Path $TestDrive 'attacker-controlled') | Should -BeFalse
  }

  It 'emits terminal V2 FAIL when the newest archive has no Summary.json' {
    if (-not (Test-ParserTestWindowsAdministrator)) {
      Set-ItResult -Skipped -Because 'The current Windows test identity is not elevated.'
      return
    }
    $supportDir = Join-Path $TestDrive 'bundles'
    $extractRoot = Get-ParserTestExtractRoot
    [void][System.IO.Directory]::CreateDirectory($supportDir)
    $archivePath = Join-Path $supportDir 'SupportBundle-no-summary.zip'
    $sourceDir = Join-Path $TestDrive 'empty-source'
    [void][System.IO.Directory]::CreateDirectory($sourceDir)
    [System.IO.Compression.ZipFile]::CreateFromDirectory($sourceDir, $archivePath)
    $testHostIsWindows = [Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
    $oldOS = $env:OS
    $oldProgramData = $env:ProgramData
    $before = Get-ParserExtractRunSnapshot -ExtractRoot $extractRoot
    $workDirectoryPrefix = [System.IO.Path]::GetFileNameWithoutExtension($archivePath)
    try {
      if (-not $testHostIsWindows) {
        $env:OS = 'Windows_NT'
        $env:ProgramData = $TestDrive
      }
      $output = & $scriptPath -SupportDir $supportDir -ExtractRoot $extractRoot -OutputFormat None -PassThru -Confirm:$false 6>$null
      $exitCode = $LASTEXITCODE
    } finally {
      Remove-NewParserExtractRuns -ExtractRoot $extractRoot -Before $before -WorkDirectoryPrefix $workDirectoryPrefix
      if (-not $testHostIsWindows) {
        if ($null -eq $oldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue } else { $env:OS = $oldOS }
        if ($null -eq $oldProgramData) { Remove-Item -LiteralPath Env:ProgramData -ErrorAction SilentlyContinue } else { $env:ProgramData = $oldProgramData }
      }
    }
    $exitCode | Should -Be 1
    $result = @($output | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]
    $result.Result | Should -Be 'FAIL'
    $result.Summary.Error | Should -Match 'valid Summary.json'
  }
}
