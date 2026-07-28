#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

BeforeAll {
  function Invoke-BashFileForTest {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory)][string]$Path,
      [string[]]$ArgumentList = @()
    )

    $previousErrorActionPreference = $ErrorActionPreference
    try {
      # Windows PowerShell promotes native stderr to ErrorRecord objects. Keep
      # expected failure output capturable instead of letting Pester stop early.
      $ErrorActionPreference = 'Continue'
      $output = @(& bash $Path @ArgumentList 2>&1)
      $exitCode = $LASTEXITCODE
    } finally {
      $ErrorActionPreference = $previousErrorActionPreference
    }

    return [pscustomobject]@{
      ExitCode = $exitCode
      Output   = $output
    }
  }

  function Invoke-BashScriptForTest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ScriptBody)

    $scriptPath = [System.IO.Path]::GetTempFileName()
    try {
      $portableBody = $ScriptBody.Replace("`r`n", "`n")
      [System.IO.File]::WriteAllText(
        $scriptPath,
        $portableBody,
        (New-Object System.Text.UTF8Encoding($false))
      )
      return (Invoke-BashFileForTest -Path $scriptPath)
    } finally {
      Remove-Item -LiteralPath $scriptPath -Force -ErrorAction SilentlyContinue
    }
  }

  function New-PortableZipForTest {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory)][string]$SourcePath,
      [Parameter(Mandatory)][string]$DestinationPath
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $sourceRoot = [System.IO.Path]::GetFullPath($SourcePath).TrimEnd([char[]]@([char]'/', [char]92))
    $archive = [System.IO.Compression.ZipFile]::Open(
      $DestinationPath,
      [System.IO.Compression.ZipArchiveMode]::Create
    )
    try {
      foreach ($file in Get-ChildItem -LiteralPath $sourceRoot -File -Recurse) {
        $entryName = $file.FullName.Substring($sourceRoot.Length + 1).Replace([char]92, [char]'/')
        [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
          $archive,
          $file.FullName,
          $entryName,
          [System.IO.Compression.CompressionLevel]::Optimal
        )
      }
    } finally {
      $archive.Dispose()
    }
  }
}

Describe 'scripts/ci-local.sh gate reporting' {
  BeforeAll {
    $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:CiLocal = Join-Path $script:RepoRoot 'scripts/ci-local.sh'

    function New-PwshRuntimeShim {
      param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$RuntimeIdentity
      )

      $content = @'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *'PSEdition'* ]]; then
  printf '%s\n' "${MOCK_PWSH_IDENTITY}"
  exit 0
fi
if [[ "${MOCK_PWSH_SUCCEED_GATES:-}" == '1' ]]; then
  exit 0
fi
exec "${REAL_PWSH}" "$@"
'@
      [System.IO.File]::WriteAllText($Path, $content, (New-Object System.Text.UTF8Encoding($false)))
      & chmod +x $Path
      $env:MOCK_PWSH_IDENTITY = $RuntimeIdentity
    }
  }

  It 'Reports skipped analyzer and tests as partial local CI' {
    if (-not (Get-Command -Name bash -ErrorAction SilentlyContinue)) {
      Set-ItResult -Skipped -Because 'bash is not available.'
      return
    }
    $pwsh = Get-Command -Name pwsh -ErrorAction SilentlyContinue
    if (-not $pwsh) {
      Set-ItResult -Skipped -Because 'pwsh is not available.'
      return
    }
    if (-not (Get-Command -Name chmod -ErrorAction SilentlyContinue)) {
      Set-ItResult -Skipped -Because 'chmod is not available.'
      return
    }

    $previous = @{
      CI_SKIP_ANALYZER = $env:CI_SKIP_ANALYZER
      CI_SKIP_TESTS = $env:CI_SKIP_TESTS
      PWSH_BIN = $env:PWSH_BIN
      REAL_PWSH = $env:REAL_PWSH
      MOCK_PWSH_IDENTITY = $env:MOCK_PWSH_IDENTITY
      MOCK_PWSH_SUCCEED_GATES = $env:MOCK_PWSH_SUCCEED_GATES
    }

    try {
      $shim = Join-Path $TestDrive 'pwsh-7.6.3'
      New-PwshRuntimeShim -Path $shim -RuntimeIdentity '7.6.3|Core'
      $env:CI_SKIP_ANALYZER = '1'
      $env:CI_SKIP_TESTS = '1'
      $env:PWSH_BIN = $shim
      $env:REAL_PWSH = $pwsh.Source
      $env:MOCK_PWSH_SUCCEED_GATES = '1'

      $run = Invoke-BashFileForTest -Path $script:CiLocal
      $output = $run.Output
      $exitCode = $run.ExitCode
    } finally {
      foreach ($name in $previous.Keys) {
        if ($null -eq $previous[$name]) {
          Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
        } else {
          Set-Item -LiteralPath "Env:$name" -Value $previous[$name]
        }
      }
    }

    $text = $output | Out-String
    $exitCode | Should -Be 0
    $text | Should -Match 'CI gate summary'
    $text | Should -Match 'Runtime.*PASS'
    $text | Should -Match 'Analyzer.*SKIPPED'
    $text | Should -Match 'Tests.*SKIPPED'
    $text | Should -Match 'Overall.*PARTIAL'
  }

  It 'Fails before repository gates when the PowerShell runtime drifts' {
    if (-not (Get-Command -Name bash -ErrorAction SilentlyContinue) -or
        -not (Get-Command -Name chmod -ErrorAction SilentlyContinue)) {
      Set-ItResult -Skipped -Because 'bash and chmod are required.'
      return
    }

    $previous = @{
      CI_SKIP_ANALYZER = $env:CI_SKIP_ANALYZER
      CI_SKIP_TESTS = $env:CI_SKIP_TESTS
      PWSH_BIN = $env:PWSH_BIN
      REAL_PWSH = $env:REAL_PWSH
      MOCK_PWSH_IDENTITY = $env:MOCK_PWSH_IDENTITY
    }
    try {
      $shim = Join-Path $TestDrive 'pwsh-7.6.2'
      New-PwshRuntimeShim -Path $shim -RuntimeIdentity '7.6.2|Core'
      $env:CI_SKIP_ANALYZER = '1'
      $env:CI_SKIP_TESTS = '1'
      $env:PWSH_BIN = $shim
      $env:REAL_PWSH = '/not-used'
      $run = Invoke-BashFileForTest -Path $script:CiLocal
      $output = $run.Output
      $exitCode = $run.ExitCode
    } finally {
      foreach ($name in $previous.Keys) {
        if ($null -eq $previous[$name]) {
          Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
        } else {
          Set-Item -LiteralPath "Env:$name" -Value $previous[$name]
        }
      }
    }

    $text = $output | Out-String
    $exitCode | Should -Be 1
    $text | Should -Match 'PowerShell runtime drift: expected 7\.6\.3\|Core, got 7\.6\.2\|Core'
    $text | Should -Match 'Runtime.*FAILED'
    $text | Should -Match 'SecretScan.*NOT_RUN'
  }
}

Describe 'PowerShell runtime and toolchain pins' {
  BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:CiWorkflowSource = Get-Content -LiteralPath (Join-Path $repoRoot '.github/workflows/ci.yml') -Raw
    $script:ReleaseWorkflowSource = Get-Content -LiteralPath (Join-Path $repoRoot '.github/workflows/release.yml') -Raw
    $script:CiLocalSource = Get-Content -LiteralPath (Join-Path $repoRoot 'scripts/ci-local.sh') -Raw
    $script:FuzzDockerfileSource = Get-Content -LiteralPath (Join-Path $repoRoot '.clusterfuzzlite/Dockerfile') -Raw
  }

  It 'Pins the requested runtime and module versions without a setup action' {
    foreach ($source in @($script:CiWorkflowSource, $script:ReleaseWorkflowSource)) {
      $source | Should -Match "POWERSHELL_VERSION: '7\.6\.3'"
      $source | Should -Match "PSSCRIPTANALYZER_VERSION: '1\.25\.0'"
      $source | Should -Match "PESTER_VERSION: '5\.8\.0'"
      $source | Should -Not -Match 'setup-powershell'
      $source | Should -Not -Match "'1\.24\.0'|'5\.7\.1'"
    }
    $script:CiLocalSource | Should -Match 'required_pwsh_version="7\.6\.3"'
    $script:CiLocalSource | Should -Match 'psa_version="1\.25\.0"'
    $script:CiLocalSource | Should -Match 'pester_version="5\.8\.0"'
  }

  It 'Verifies official PowerShell archives before exact-version execution' {
    $script:CiWorkflowSource | Should -Match 'PowerShell-\$env:POWERSHELL_VERSION-win-x64\.zip'
    $script:CiWorkflowSource | Should -Match '07ddb0d00b660459560ef82a9841da7705b27cd5dcca5a0d7b025a98eca29eca'
    $script:CiWorkflowSource | Should -Match 'powershell-\$\{POWERSHELL_VERSION\}-linux-x64\.tar\.gz'
    $script:CiWorkflowSource | Should -Match '856d0765d2332377f9d7a4aea76efdfde4de51446e7738dde2dfda41dba9e2a7'
    $script:CiWorkflowSource | Should -Match '(?m)^\s+check_name: Static checks$'
    $script:CiWorkflowSource | Should -Match '(?m)^\s+check_name: Pester \(Windows\)$'
    $script:CiWorkflowSource | Should -Match 'check_name: Static checks \(Windows PowerShell 5\.1\)'
    $script:CiWorkflowSource | Should -Match 'check_name: Pester \(Windows PowerShell 5\.1\)'
    $script:CiWorkflowSource | Should -Match "edition: Desktop"
    $script:CiWorkflowSource | Should -Match 'Expected PowerShell \$env:POWERSHELL_VERSION exactly'
    $script:ReleaseWorkflowSource | Should -Match 'sha256sum -c -'
    $script:ReleaseWorkflowSource | Should -Match 'Expected PowerShell %s exactly'
  }

  It 'uses atomic write capabilities for the trusted CI task ACL assertion' {
    $match = [regex]::Match(
      $script:CiWorkflowSource,
      '(?ms)^\s+\$trustedSids = @\{.*?^\s+Assert-TrustedCiTaskPath -Path \$pesterDestination'
    )
    $match.Success | Should -BeTrue
    $assertion = $match.Value

    $script:CiWorkflowSource | Should -Match 'FileSystemRights\]::ReadAndExecute'
    $assertion | Should -Not -Match 'FileSystemRights\]::(Write|Modify|FullControl)\s*-bor'
    $assertion | Should -Not -Match 'FileSystemRights\]::(ReadAndExecute|Synchronize)'
    foreach ($capability in @(
        'WriteData', 'AppendData', 'WriteAttributes', 'WriteExtendedAttributes',
        'Delete', 'DeleteSubdirectoriesAndFiles', 'ChangePermissions', 'TakeOwnership'
      )) {
      $assertion | Should -Match ("FileSystemRights\]::{0}" -f $capability)
    }
    $assertion | Should -Match 'foreach \(\$capability in \$effectiveCapabilities\)'
    $assertion | Should -Match '\$hasDangerousRights = \$true'

    $readExecute = [int64]([Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
      [Security.AccessControl.FileSystemRights]::Synchronize)
    foreach ($name in @(
        'WriteData', 'AppendData', 'WriteAttributes', 'WriteExtendedAttributes',
        'Delete', 'DeleteSubdirectoriesAndFiles', 'ChangePermissions', 'TakeOwnership'
      )) {
      $capability = [int64][Security.AccessControl.FileSystemRights]::$name
      (($readExecute -band $capability) -eq $capability) | Should -BeFalse
      (($capability -band $capability) -eq $capability) | Should -BeTrue
    }
  }

  It 'prints failed SYSTEM Pester test names and messages before reporting the task exit code' {
    $taskFailure = [regex]::Match(
      $script:CiWorkflowSource,
      '(?ms)if \(\$taskInfo\.LastTaskResult -ne 0\) \{(?<body>.*?)throw "The SYSTEM Pester task failed with exit code'
    )

    $taskFailure.Success | Should -BeTrue
    $body = $taskFailure.Groups['body'].Value
    $body | Should -Match '\[xml\]\(Get-Content -LiteralPath \$copiedResultPath -Raw -ErrorAction Stop\)'
    $body | Should -Match ([regex]::Escape('SelectNodes(''//test-case[@result="Failure"]'')'))
    $body | Should -Match ([regex]::Escape('SelectSingleNode(''./failure/message'')'))
    $body | Should -Match 'SYSTEM Pester failure:'
    $body | Should -Match 'produced invalid testResults\.xml'
    $taskFailure.Value.IndexOf('SYSTEM Pester failure:') |
      Should -BeLessThan $taskFailure.Value.IndexOf('The SYSTEM Pester task failed with exit code')
  }

  It 'Builds the fuzz image on a maintained digest-pinned Microsoft base with PowerShell 7.6.3' {
    $script:FuzzDockerfileSource | Should -Match 'mcr\.microsoft\.com/dotnet/runtime:10\.0-noble-amd64@sha256:567d204c2121716af76125c401f0684cfe06f8c6ba9a6783374464f625b79acb'
    $script:FuzzDockerfileSource | Should -Match 'releases/download/v7\.6\.3/powershell-7\.6\.3-linux-x64\.tar\.gz'
    $script:FuzzDockerfileSource | Should -Match '--checksum=sha256:856d0765d2332377f9d7a4aea76efdfde4de51446e7738dde2dfda41dba9e2a7'
    $script:FuzzDockerfileSource | Should -Match '\$PSVersionTable\.PSVersion\.ToString\(\)'
    $script:FuzzDockerfileSource | Should -Not -Match 'mcr\.microsoft\.com/powershell:7\.5'
  }
}

Describe 'release workflow dispatch tag contract' {
  BeforeAll {
    $script:ReleaseWorkflow = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path '.github/workflows/release.yml'
    $script:ReleaseSource = Get-Content -LiteralPath $script:ReleaseWorkflow -Raw

    function Get-ReleaseStepScript {
      param([Parameter(Mandatory)][string]$Name)

      $stepPattern = '(?ms)^      - name: ' + [regex]::Escape($Name) + '\r?\n(?<step>.*?)(?=^      - name: |\z)'
      $stepMatch = [regex]::Match($script:ReleaseSource, $stepPattern)
      if (-not $stepMatch.Success) { throw "Release workflow step not found: $Name" }
      $runMatch = [regex]::Match($stepMatch.Groups['step'].Value, '(?ms)^        run: \|\r?\n(?<body>.*)\z')
      if (-not $runMatch.Success) { throw "Release workflow step has no run block: $Name" }
      return (($runMatch.Groups['body'].Value -replace '(?m)^ {10}', '').TrimEnd())
    }
  }

  It 'validates and checks out the selected tag before archiving its resolved commit' {
    $script:ReleaseSource | Should -Match 'name: Resolve release tag'
    $script:ReleaseSource | Should -Match 'git show-ref --verify --quiet "refs/tags/\$\{RELEASE_TAG\}"'
    $script:ReleaseSource | Should -Not -Match 'git fetch --force origin'
    $script:ReleaseSource | Should -Match 'git checkout --detach "\$\{release_commit\}"'
    $script:ReleaseSource | Should -Match 'RELEASE_COMMIT: \$\{\{ steps\.release_ref\.outputs\.commit \}\}'
    $script:ReleaseSource | Should -Match 'git archive[\s\S]*"\$\{RELEASE_COMMIT\}"'
    $script:ReleaseSource | Should -Match "':\(exclude\)scripts/ci-local\.sh'"
    $script:ReleaseSource.IndexOf('name: Checkout resolved release tag') | Should -BeGreaterThan $script:ReleaseSource.IndexOf('name: Resolve release tag')
    $script:ReleaseSource.IndexOf('name: Run release static gates') | Should -BeGreaterThan $script:ReleaseSource.IndexOf('name: Checkout resolved release tag')
    $script:ReleaseSource.IndexOf('name: Run release Pester suite') | Should -BeGreaterThan $script:ReleaseSource.IndexOf('name: Checkout resolved release tag')
    $script:ReleaseSource.IndexOf('name: Run release Node suite') | Should -BeGreaterThan $script:ReleaseSource.IndexOf('name: Checkout resolved release tag')
    $script:ReleaseSource.IndexOf('name: Build package') | Should -BeGreaterThan $script:ReleaseSource.IndexOf('name: Checkout resolved release tag')
    $script:ReleaseSource.IndexOf('name: Build package') | Should -BeGreaterThan $script:ReleaseSource.IndexOf('name: Run release Node suite')
    $script:ReleaseSource.IndexOf('name: Run extracted operator-package gates') | Should -BeGreaterThan $script:ReleaseSource.IndexOf('name: Verify package inventory')
    $script:ReleaseSource | Should -Match 'profile_status=\$\?'
    $script:ReleaseSource | Should -Match '"\$\{profile_status\}" != 0 && "\$\{profile_status\}" != 2'
  }

  It 'accepts only SemVer-shaped release tags' {
    if (-not (Get-Command -Name bash -ErrorAction SilentlyContinue)) {
      Set-ItResult -Skipped -Because 'bash is required for the release tag contract test.'
      return
    }

    $scriptBody = Get-ReleaseStepScript -Name 'Resolve release tag'
    foreach ($tag in @('v0.1.0', 'v2.3.0-alpha.1')) {
      $outputPath = Join-Path $TestDrive ("accepted-{0}.txt" -f ($tag -replace '[^A-Za-z0-9]', '-'))
      $previous = @{
        GITHUB_EVENT_NAME = $env:GITHUB_EVENT_NAME
        GITHUB_REF_NAME   = $env:GITHUB_REF_NAME
        GITHUB_REF_TYPE   = $env:GITHUB_REF_TYPE
        GITHUB_OUTPUT     = $env:GITHUB_OUTPUT
      }
      try {
        $env:GITHUB_EVENT_NAME = 'workflow_dispatch'
        $env:GITHUB_REF_NAME = $tag
        $env:GITHUB_REF_TYPE = 'tag'
        $env:GITHUB_OUTPUT = $outputPath
        $run = Invoke-BashScriptForTest -ScriptBody $scriptBody
        $output = $run.Output
        $exitCode = $run.ExitCode
      } finally {
        foreach ($name in $previous.Keys) {
          if ($null -eq $previous[$name]) {
            Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
          } else {
            Set-Item -LiteralPath "Env:$name" -Value $previous[$name]
          }
        }
      }
      $exitCode | Should -Be 0 -Because ($output | Out-String)
      (Get-Content -LiteralPath $outputPath -Raw) | Should -Match ("tag={0}" -f [regex]::Escape($tag))
    }

    foreach ($tag in @(
        'vfoo', 'v2', 'v2.3', 'v01.2.3', 'v1.02.3', 'v1.2.03',
        'v1.2.3-01', 'v1.2.3-alpha.01', 'v1.2.3+build', 'v1.2.3/other',
        ('v1.2.3-' + ('a' * 128))
      )) {
      $outputPath = Join-Path $TestDrive ("rejected-{0}.txt" -f ($tag -replace '[^A-Za-z0-9]', '-'))
      $oldEvent = $env:GITHUB_EVENT_NAME
      $oldRef = $env:GITHUB_REF_NAME
      $oldRefType = $env:GITHUB_REF_TYPE
      $oldOutput = $env:GITHUB_OUTPUT
      try {
        $env:GITHUB_EVENT_NAME = 'workflow_dispatch'
        $env:GITHUB_REF_NAME = $tag
        $env:GITHUB_REF_TYPE = 'tag'
        $env:GITHUB_OUTPUT = $outputPath
        $run = Invoke-BashScriptForTest -ScriptBody $scriptBody
        $output = $run.Output
        $exitCode = $run.ExitCode
      } finally {
        if ($null -eq $oldEvent) { Remove-Item Env:GITHUB_EVENT_NAME -ErrorAction SilentlyContinue } else { $env:GITHUB_EVENT_NAME = $oldEvent }
        if ($null -eq $oldRef) { Remove-Item Env:GITHUB_REF_NAME -ErrorAction SilentlyContinue } else { $env:GITHUB_REF_NAME = $oldRef }
        if ($null -eq $oldRefType) { Remove-Item Env:GITHUB_REF_TYPE -ErrorAction SilentlyContinue } else { $env:GITHUB_REF_TYPE = $oldRefType }
        if ($null -eq $oldOutput) { Remove-Item Env:GITHUB_OUTPUT -ErrorAction SilentlyContinue } else { $env:GITHUB_OUTPUT = $oldOutput }
      }
      $exitCode | Should -Be 1
      ($output | Out-String) | Should -Match 'Invalid release tag'
    }
  }

  It 'rejects a manual release dispatched from a branch ref' {
    if (-not (Get-Command -Name bash -ErrorAction SilentlyContinue)) {
      Set-ItResult -Skipped -Because 'bash is required for the release tag contract test.'
      return
    }

    $oldRefName = $env:GITHUB_REF_NAME
    $oldRefType = $env:GITHUB_REF_TYPE
    $oldOutput = $env:GITHUB_OUTPUT
    try {
      $env:GITHUB_REF_NAME = 'main'
      $env:GITHUB_REF_TYPE = 'branch'
      $env:GITHUB_OUTPUT = Join-Path $TestDrive 'branch-dispatch.txt'
      $run = Invoke-BashScriptForTest -ScriptBody (Get-ReleaseStepScript -Name 'Resolve release tag')
      $output = $run.Output
      $exitCode = $run.ExitCode
    } finally {
      if ($null -eq $oldRefName) { Remove-Item Env:GITHUB_REF_NAME -ErrorAction SilentlyContinue } else { $env:GITHUB_REF_NAME = $oldRefName }
      if ($null -eq $oldRefType) { Remove-Item Env:GITHUB_REF_TYPE -ErrorAction SilentlyContinue } else { $env:GITHUB_REF_TYPE = $oldRefType }
      if ($null -eq $oldOutput) { Remove-Item Env:GITHUB_OUTPUT -ErrorAction SilentlyContinue } else { $env:GITHUB_OUTPUT = $oldOutput }
    }

    $exitCode | Should -Be 1
    ($output | Out-String) | Should -Match 'must be dispatched from the tag'
  }

  It 'generates a checksum that verifies beside the downloaded asset' {
    if (-not (Get-Command -Name bash -ErrorAction SilentlyContinue) -or
        -not (Get-Command -Name sha256sum -ErrorAction SilentlyContinue)) {
      Set-ItResult -Skipped -Because 'bash and sha256sum are required for the release checksum contract test.'
      return
    }

    $workRoot = Join-Path $TestDrive 'checksum-workflow'
    $dist = Join-Path $workRoot 'dist'
    [void][System.IO.Directory]::CreateDirectory($dist)
    [System.IO.File]::WriteAllText((Join-Path $dist 'release.zip'), 'release payload')
    $oldAsset = $env:RELEASE_ASSET
    Push-Location $workRoot
    try {
      $env:RELEASE_ASSET = 'release.zip'
      $run = Invoke-BashScriptForTest -ScriptBody (Get-ReleaseStepScript -Name 'Generate portable checksum')
      $output = $run.Output
      $exitCode = $run.ExitCode
    } finally {
      Pop-Location
      if ($null -eq $oldAsset) { Remove-Item -LiteralPath Env:RELEASE_ASSET -ErrorAction SilentlyContinue } else { $env:RELEASE_ASSET = $oldAsset }
    }

    $exitCode | Should -Be 0 -Because ($output | Out-String)
    $checksum = Get-Content -LiteralPath (Join-Path $dist 'release.zip.sha256') -Raw
    # GNU sha256sum uses a space plus mode marker: another space for text and
    # '*' for binary. Git for Windows selects the binary marker by default.
    $checksum | Should -Match '^[0-9a-f]{64} [ *]release\.zip\s*$'
    $checksum | Should -Not -Match 'dist/'
  }

  It 'generates and verifies a manifest for every packaged file' {
    if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT -or
        -not (Get-Command -Name bash -ErrorAction SilentlyContinue) -or
        -not (Get-Command -Name ln -ErrorAction SilentlyContinue) -or
        -not (Get-Command -Name sha256sum -ErrorAction SilentlyContinue) -or
        -not (Get-Command -Name unzip -ErrorAction SilentlyContinue) -or
        -not (Get-Command -Name zip -ErrorAction SilentlyContinue)) {
      Set-ItResult -Skipped -Because 'A POSIX environment with ln, sha256sum, unzip, and zip is required for the package manifest test.'
      return
    }

    $workRoot = Join-Path $TestDrive 'manifest-workflow'
    $payload = Join-Path $workRoot 'payload'
    $dist = Join-Path $workRoot 'dist'
    [void][System.IO.Directory]::CreateDirectory((Join-Path $payload 'docs'))
    [void][System.IO.Directory]::CreateDirectory($dist)
    [System.IO.File]::WriteAllText((Join-Path $payload 'README.md'), 'release readme')
    [System.IO.File]::WriteAllText((Join-Path $payload 'docs/guide.md'), 'release guide')
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($payload, (Join-Path $dist 'release.zip'))

    $oldAsset = $env:RELEASE_ASSET
    $oldWorkspace = $env:GITHUB_WORKSPACE
    Push-Location $workRoot
    try {
      $env:RELEASE_ASSET = 'release.zip'
      $env:GITHUB_WORKSPACE = $workRoot
      $run = Invoke-BashScriptForTest -ScriptBody (Get-ReleaseStepScript -Name 'Generate and verify package manifest')
      $output = $run.Output
      $exitCode = $run.ExitCode
    } finally {
      Pop-Location
      if ($null -eq $oldAsset) { Remove-Item Env:RELEASE_ASSET -ErrorAction SilentlyContinue } else { $env:RELEASE_ASSET = $oldAsset }
      if ($null -eq $oldWorkspace) { Remove-Item Env:GITHUB_WORKSPACE -ErrorAction SilentlyContinue } else { $env:GITHUB_WORKSPACE = $oldWorkspace }
    }

    $exitCode | Should -Be 0 -Because ($output | Out-String)
    $manifestPath = Join-Path $dist 'release.zip.manifest.sha256'
    Test-Path -LiteralPath $manifestPath -PathType Leaf | Should -BeTrue
    $manifest = Get-Content -LiteralPath $manifestPath -Raw
    $manifest | Should -Match '[0-9a-f]{64}\s+\./README\.md'
    $manifest | Should -Match '[0-9a-f]{64}\s+\./docs/guide\.md'

    $symlinkPayload = Join-Path $workRoot 'symlink-payload'
    [void][System.IO.Directory]::CreateDirectory($symlinkPayload)
    [System.IO.File]::WriteAllText((Join-Path $symlinkPayload 'target.txt'), 'target')
    & ln -s target.txt (Join-Path $symlinkPayload 'link.txt')
    Push-Location $symlinkPayload
    try {
      & zip -q -y -r (Join-Path $dist 'symlink.zip') .
    } finally {
      Pop-Location
    }

    $oldAsset = $env:RELEASE_ASSET
    $oldWorkspace = $env:GITHUB_WORKSPACE
    Push-Location $workRoot
    try {
      $env:RELEASE_ASSET = 'symlink.zip'
      $env:GITHUB_WORKSPACE = $workRoot
      $symlinkRun = Invoke-BashScriptForTest -ScriptBody (Get-ReleaseStepScript -Name 'Generate and verify package manifest')
      $symlinkOutput = $symlinkRun.Output
      $symlinkExitCode = $symlinkRun.ExitCode
    } finally {
      Pop-Location
      if ($null -eq $oldAsset) { Remove-Item Env:RELEASE_ASSET -ErrorAction SilentlyContinue } else { $env:RELEASE_ASSET = $oldAsset }
      if ($null -eq $oldWorkspace) { Remove-Item Env:GITHUB_WORKSPACE -ErrorAction SilentlyContinue } else { $env:GITHUB_WORKSPACE = $oldWorkspace }
    }

    $symlinkExitCode | Should -Be 1
    ($symlinkOutput | Out-String) | Should -Match 'Package contains a non-regular entry'
  }

  It 'enforces the exact public package inventory' {
    if (-not (Get-Command -Name bash -ErrorAction SilentlyContinue) -or
        -not (Get-Command -Name unzip -ErrorAction SilentlyContinue)) {
      Set-ItResult -Skipped -Because 'bash and unzip are required for the package inventory contract test.'
      return
    }

    $workRoot = Join-Path $TestDrive 'inventory-workflow'
    $payload = Join-Path $workRoot 'payload'
    $dist = Join-Path $workRoot 'dist'
    foreach ($directory in @(
        'scripts', 'examples/profiles', 'examples/configs', 'docs', 'tools'
      )) {
      [void][System.IO.Directory]::CreateDirectory((Join-Path $payload $directory))
    }
    [void][System.IO.Directory]::CreateDirectory($dist)

    1..52 | ForEach-Object {
      [System.IO.File]::WriteAllText((Join-Path $payload ("scripts/{0:D2}-Task.ps1" -f $_)), '# task')
    }
    1..6 | ForEach-Object {
      [System.IO.File]::WriteAllText((Join-Path $payload ("scripts/00-Orchestrator-{0}.ps1" -f $_)), '# orchestrator')
    }
    1..7 | ForEach-Object {
      [System.IO.File]::WriteAllText((Join-Path $payload ("examples/profiles/profile-{0}.json" -f $_)), '{}')
    }
    1..4 | ForEach-Object {
      [System.IO.File]::WriteAllText((Join-Path $payload ("examples/configs/config-{0}.json" -f $_)), '{}')
    }
    foreach ($required in @(
        'docs/alpha-release.md',
        'docs/launcher-gui.md',
        'tools/Launcher-GUI.ps1',
        'tools/Launcher-Worker.ps1',
        'tools/Launcher.Core.psm1'
      )) {
      [System.IO.File]::WriteAllText((Join-Path $payload $required), 'release file')
    }

    $assetPath = Join-Path $dist 'release.zip'
    New-PortableZipForTest -SourcePath $payload -DestinationPath $assetPath

    $oldAsset = $env:RELEASE_ASSET
    Push-Location $workRoot
    try {
      $env:RELEASE_ASSET = 'release.zip'
      $run = Invoke-BashScriptForTest -ScriptBody (Get-ReleaseStepScript -Name 'Verify package inventory')
      $output = $run.Output
      $exitCode = $run.ExitCode
    } finally {
      Pop-Location
      if ($null -eq $oldAsset) { Remove-Item Env:RELEASE_ASSET -ErrorAction SilentlyContinue } else { $env:RELEASE_ASSET = $oldAsset }
    }

    $exitCode | Should -Be 0 -Because ($output | Out-String)

    [void][System.IO.Directory]::CreateDirectory((Join-Path $payload 'tests'))
    [System.IO.File]::WriteAllText((Join-Path $payload 'tests/not-for-operators.ps1'), '# test')
    $prohibitedAsset = Join-Path $dist 'prohibited.zip'
    New-PortableZipForTest -SourcePath $payload -DestinationPath $prohibitedAsset
    $oldAsset = $env:RELEASE_ASSET
    Push-Location $workRoot
    try {
      $env:RELEASE_ASSET = 'prohibited.zip'
      $prohibitedRun = Invoke-BashScriptForTest -ScriptBody (Get-ReleaseStepScript -Name 'Verify package inventory')
      $prohibitedOutput = $prohibitedRun.Output
      $prohibitedExitCode = $prohibitedRun.ExitCode
    } finally {
      Pop-Location
      if ($null -eq $oldAsset) { Remove-Item Env:RELEASE_ASSET -ErrorAction SilentlyContinue } else { $env:RELEASE_ASSET = $oldAsset }
    }

    $prohibitedExitCode | Should -Be 1
    ($prohibitedOutput | Out-String) | Should -Match 'Prohibited release path: tests'

    Remove-Item -LiteralPath (Join-Path $payload 'tests') -Recurse -Force
    [System.IO.File]::WriteAllText((Join-Path $payload 'scripts/ci-local.sh'), '# local CI')
    $localCiAsset = Join-Path $dist 'local-ci.zip'
    New-PortableZipForTest -SourcePath $payload -DestinationPath $localCiAsset
    $oldAsset = $env:RELEASE_ASSET
    Push-Location $workRoot
    try {
      $env:RELEASE_ASSET = 'local-ci.zip'
      $localCiRun = Invoke-BashScriptForTest -ScriptBody (Get-ReleaseStepScript -Name 'Verify package inventory')
      $localCiOutput = $localCiRun.Output
      $localCiExitCode = $localCiRun.ExitCode
    } finally {
      Pop-Location
      if ($null -eq $oldAsset) { Remove-Item Env:RELEASE_ASSET -ErrorAction SilentlyContinue } else { $env:RELEASE_ASSET = $oldAsset }
    }

    $localCiExitCode | Should -Be 1
    ($localCiOutput | Out-String) | Should -Match 'Prohibited release path: scripts/ci-local\.sh'
  }

  It 'renames the single digest-named gh attestation bundle for release upload' {
    if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT -or
        -not (Get-Command -Name bash -ErrorAction SilentlyContinue) -or
        -not (Get-Command -Name chmod -ErrorAction SilentlyContinue)) {
      Set-ItResult -Skipped -Because 'A POSIX bash environment is required for the mocked gh attestation contract test.'
      return
    }

    $workRoot = Join-Path $TestDrive 'attestation-workflow'
    $dist = Join-Path $workRoot 'dist'
    $mockBin = Join-Path $workRoot 'mock-bin'
    [void][System.IO.Directory]::CreateDirectory($dist)
    [void][System.IO.Directory]::CreateDirectory($mockBin)
    [System.IO.File]::WriteAllText((Join-Path $dist 'release.zip'), 'release payload')
    $mockGh = Join-Path $mockBin 'gh'
    @'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == 'attestation' && "$2" == 'download' && "$3" == 'release.zip' && "$4" == '--repo' && "$5" == 'example/repo' ]]
for arg in "$@"; do
  [[ "$arg" != '--format' ]]
done
printf '{"bundle":true}\n' > 'sha256-deadbeef.jsonl'
'@ | Set-Content -LiteralPath $mockGh -Encoding utf8
    & chmod +x $mockGh
    $oldAsset = $env:RELEASE_ASSET
    $oldRepository = $env:GITHUB_REPOSITORY
    $oldPath = $env:PATH
    Push-Location $workRoot
    try {
      $env:RELEASE_ASSET = 'release.zip'
      $env:GITHUB_REPOSITORY = 'example/repo'
      $env:PATH = $mockBin + [System.IO.Path]::PathSeparator + $oldPath
      $run = Invoke-BashScriptForTest -ScriptBody (Get-ReleaseStepScript -Name 'Download attestation bundle')
      $output = $run.Output
      $exitCode = $run.ExitCode
    } finally {
      Pop-Location
      if ($null -eq $oldAsset) { Remove-Item -LiteralPath Env:RELEASE_ASSET -ErrorAction SilentlyContinue } else { $env:RELEASE_ASSET = $oldAsset }
      if ($null -eq $oldRepository) { Remove-Item -LiteralPath Env:GITHUB_REPOSITORY -ErrorAction SilentlyContinue } else { $env:GITHUB_REPOSITORY = $oldRepository }
      $env:PATH = $oldPath
    }

    $exitCode | Should -Be 0 -Because ($output | Out-String)
    $namedBundle = Join-Path $dist 'release.zip.intoto.jsonl'
    Test-Path -LiteralPath $namedBundle -PathType Leaf | Should -BeTrue
    (Get-Item -LiteralPath $namedBundle).Length | Should -BeGreaterThan 0
    Get-ChildItem -LiteralPath $dist -Filter 'sha256*.jsonl' -File | Should -BeNullOrEmpty
  }

  It 'separates unprivileged verification from protected publication' {
    $publishIndex = $script:ReleaseSource.IndexOf("`n  publish:")
    $publishIndex | Should -BeGreaterThan 0
    $verifySource = $script:ReleaseSource.Substring(0, $publishIndex)
    $publishSource = $script:ReleaseSource.Substring($publishIndex)

    $verifySource | Should -Match 'verify_package:[\s\S]*permissions:\s*\r?\n\s*contents: read'
    foreach ($permission in @('contents: write', ('id-' + 'token: write'), 'attestations: write')) {
      $verifySource | Should -Not -Match ([regex]::Escape($permission))
    }
    $verifySource | Should -Match 'release_commit="\$\(git rev-parse "refs/tags/\$\{RELEASE_TAG\}\^\{commit\}"\)"'
    $verifySource | Should -Match '"\$\{release_commit\}" != "\$\{GITHUB_SHA\}"'

    $publishSource | Should -Match 'environment:\s*\r?\n\s*name: alpha-release'
    $publishSource | Should -Match 'contents: write'
    $publishSource | Should -Match 'id-token: write'
    $publishSource | Should -Match 'attestations: write'
    $publishSource | Should -Not -Match 'actions/checkout@'
    $publishSource | Should -Not -Match 'Invoke-Pester|npm (ci|test)|\./tools/'
    $publishSource | Should -Match 'actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093'
  }

  It 'publishes immutable draft-first releases with all verification assets' {
    $script:ReleaseSource | Should -Match 'name: Create draft release'
    $script:ReleaseSource | Should -Match 'Refusing pre-existing GitHub release'
    $script:ReleaseSource | Should -Match 'release create[\s\S]*--verify-tag[\s\S]*--draft'
    $script:ReleaseSource | Should -Match ([regex]::Escape('Source commit: \`${RELEASE_COMMIT}\`'))
    $script:ReleaseSource | Should -Match '--title "BaselineOps for Windows \$\{RELEASE_TAG\}"'
    $script:ReleaseSource | Should -Match 'Known limitations:'
    $script:ReleaseSource | Should -Match 'name: Require immutable release setting'
    $script:ReleaseSource | Should -Match 'RELEASE_SETTINGS_READ_TOKEN'
    $script:ReleaseSource | Should -Match 'repos/\$\{GITHUB_REPOSITORY\}/immutable-releases'
    $script:ReleaseSource.IndexOf('name: Create draft release') | Should -BeGreaterThan $script:ReleaseSource.IndexOf('name: Require immutable release setting')
    $script:ReleaseSource | Should -Match 'name: Refuse mutable release assets'
    $script:ReleaseSource | Should -Match 'Refusing to replace existing release asset'
    $script:ReleaseSource | Should -Match '"dist/\$\{RELEASE_ASSET\}\.manifest\.sha256"'
    $script:ReleaseSource | Should -Not -Match '--clobber'
    $script:ReleaseSource | Should -Match 'name: Reverify remote release tag'
    $script:ReleaseSource | Should -Match 'name: Publish release'
    $script:ReleaseSource | Should -Match 'gh release edit[\s\S]*--draft=false'
    $script:ReleaseSource | Should -Match 'isImmutable'
  }
}
