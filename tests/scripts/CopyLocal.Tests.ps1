#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

$script:SkipNonSystemWindowsIntegration = $false
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
  try {
    $script:SkipNonSystemWindowsIntegration =
      [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'
  } catch {
    $script:SkipNonSystemWindowsIntegration = $true
  }
}

Describe '00-Copy-Local v2 terminal result contract' {
  BeforeAll {
    function Get-CopyLocalFunctionBody {
      param([Parameter(Mandatory)][string]$Name)

      $scriptPaths = @(
        (Join-Path $PSScriptRoot '../../scripts/00-Copy-Local.ps1'),
        (Join-Path $PSScriptRoot '../../scripts/internal/00-Copy-Local.helpers.ps1')
      )
      foreach ($scriptPath in $scriptPaths) {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
          (Resolve-Path -LiteralPath $scriptPath).ProviderPath,
          [ref]$tokens,
          [ref]$errors)
        if ($errors.Count -gt 0) { throw "CopyLocal parser errors prevent function extraction: $($errors[0])" }
        $functionAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name
          }, $true)
        if ($null -ne $functionAst) { return [scriptblock]::Create($functionAst.Extent.Text) }
      }
      throw "CopyLocal function '$Name' was not found."
    }
  }

  It 'uses bounded native execution for every Git command' {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/00-Copy-Local.ps1'
    $helperPath = Join-Path $PSScriptRoot '../../scripts/internal/00-Copy-Local.helpers.ps1'
    $entryText = Get-Content -LiteralPath $scriptPath -Raw -Encoding UTF8
    $scriptText = $entryText, (Get-Content -LiteralPath $helperPath -Raw -Encoding UTF8) -join [Environment]::NewLine

    $scriptText | Should -Match 'Invoke-NativeCommand\s+-Command\s+\$script:GitExecutablePath'
    $scriptText | Should -Match '-TimeoutSeconds\s+300'
    $scriptText | Should -Match '-MaxOutputBytes\s+1048576'
    $scriptText | Should -Match 'OutputTruncated.*StderrTruncated'
    $scriptText | Should -Match "'clone', '--no-checkout'"
    $scriptText | Should -Match 'core\.hooksPath='
    $scriptText | Should -Match 'GIT_CONFIG_NOSYSTEM'
    $scriptText | Should -Match "\(\?:GIT\|GCM\)_"
    $scriptText | Should -Match 'GIT_PROTOCOL_FROM_USER'
    $scriptText | Should -Match 'SSH_ASKPASS'
    $scriptText | Should -Match 'CURL_CA_BUNDLE'
    $scriptText | Should -Match 'Restore-CopyLocalGitEnvironment'
    $scriptText | Should -Match 'Fresh clone scripts/lib worktree is not clean'
    $scriptText | Should -Match 'RepoPath already exists; refusing to reuse or remove an existing clone'
    $scriptText | Should -Match 'Test-RepoPathOverlapsDeploymentTarget'
    $scriptText | Should -Match 'Existing deployment target.*contains a reparse point'
    $scriptText | Should -Match 'GetFolderPath\(\[Environment\+SpecialFolder\]::CommonApplicationData\)'
    $scriptText | Should -Match 'SetAccessRuleProtection\(\$true, \$false\)'
    $scriptText | Should -Match "@\('S-1-5-18', 'S-1-5-32-544'\)"
    $scriptText | Should -Match 'Assert-CopyLocalAclObjectTrust'
    $scriptText | Should -Match 'Assert-CopyLocalAncestorChainTrust'
    $scriptText | Should -Match '-ReplacementOnly'
    $scriptText | Should -Match 'GetAccessRules\(\$true, \$true, \[System\.Security\.Principal\.SecurityIdentifier\]\)'
    $scriptText | Should -Match "BoundaryLabel 'Git executable'"
    $scriptText | Should -Match 'if \(\[Environment\]::OSVersion\.Platform -eq \[System\.PlatformID\]::Win32NT\) \{[\s\S]*?BoundaryLabel ''Git executable'''
    $scriptText | Should -Not -Match 'if \(\$explicitGitPath -and \[Environment\]::OSVersion\.Platform'
    $scriptText | Should -Match 'Set-CopyLocalNewDestinationAcl'
    $scriptText | Should -Match 'SetOwner\(\$administrators\)'
    $scriptText | Should -Match 'Enter-CopyLocalDestinationLock'
    $scriptText | Should -Match '\[System\.IO\.FileShare\]::None'
    $scriptText | Should -Match 'COPY-LOCAL-BACKUP-CLEANUP-RESIDUE'
    $scriptText | Should -Match 'Restore-CopyLocalDeploymentSwaps'
    $scriptText | Should -Match '00-Copy-Local\.helpers\.ps1'
    $scriptText | Should -Match 'Assert-CopyLocalBootstrapPathTrust -Path \$bootstrapPath -CheckAncestors'
    $entryText | Should -Match '\$copyLocalCommonPath = \[IO\.Path\]::Combine\([^\r\n]+''Common\.psm1''\)'
    $entryText | Should -Match 'Microsoft\.PowerShell\.Core\\Import-Module \$copyLocalCommonPath -Force -Global'
    $entryText | Should -Match 'Microsoft\.PowerShell\.Security\\Get-Acl'
    $scriptText | Should -Match 'PropagationFlags\]::InheritOnly'
    $scriptText | Should -Match '\[System\.IO\.FileShare\]::Read'
    $scriptText | Should -Match 'COPY-LOCAL-DEPLOYMENT-ROLLBACK-RESIDUE'
    $scriptText | Should -Match 'RollbackResidue = \$rollbackResidue'
    $scriptText | Should -Match 'DeploymentCommitted = \$true'
    $scriptText | Should -Match '\$resultToken = if \(\$Strict\) \{ ''FAIL'' \} else \{ ''WARN'' \}'
    $scriptText | Should -Match 'Remove-CopyLocalEmptyCreatedDirectory'
    $scriptText | Should -Match 'core\.hooksPath='
    $scriptText | Should -Match 'Join-Path \$stagingRoot'
    $scriptText | Should -Not -Match "'fetch', '--all'|'pull', '--ff-only'"
    $scriptText | Should -Not -Match '&\s*git(\.exe)?\b'

    $lockIndex = $entryText.IndexOf('[IO.File]::Open($bootstrapPath')
    $aclIndex = $entryText.IndexOf('Assert-CopyLocalBootstrapPathTrust -Path $bootstrapPath -CheckAncestors')
    $firstLoadIndex = $entryText.IndexOf('. $copyLocalBootstrapPath')
    $lastLoadIndex = $entryText.IndexOf('. $copyLocalHelperPath')
    $disposeIndex = $entryText.IndexOf('foreach ($bootstrapLock in $copyLocalBootstrapLocks)')
    $executionIndex = $entryText.IndexOf('Set-StrictMode -Version Latest')
    $lockIndex | Should -BeGreaterOrEqual 0
    $lockIndex | Should -BeLessThan $aclIndex
    $aclIndex | Should -BeLessThan $firstLoadIndex
    $lastLoadIndex | Should -BeLessThan $disposeIndex
    $disposeIndex | Should -BeLessThan $executionIndex
    $entryText | Should -Match 'Release source handles before a same-root transaction renames scripts/lib'
  }

  It 'applies the staging ACL with exactly one Set-Acl call' {
    $functionText = (Get-CopyLocalFunctionBody -Name 'Set-CopyLocalStagingAcl').ToString()
    [regex]::Matches($functionText, 'Set-Acl\s+-LiteralPath\s+\$Path\s+-AclObject\s+\$acl').Count | Should -Be 1
  }

  It 'removes unknown hostile Git transport variables and restores their exact caller values' {
    . (Get-CopyLocalFunctionBody -Name 'Test-CopyLocalBlockedGitEnvironmentName')
    . (Get-CopyLocalFunctionBody -Name 'Get-CopyLocalSafeGitEnvironment')
    . (Get-CopyLocalFunctionBody -Name 'Enable-CopyLocalSafeGitEnvironment')
    . (Get-CopyLocalFunctionBody -Name 'Restore-CopyLocalGitEnvironment')

    $names = @('GIT_EXEC_PATH', 'GIT_FUTURE_UNKNOWN_OVERRIDE', 'GCM_TEST_OVERRIDE', 'SSH_ASKPASS', 'https_proxy', 'SSL_CERT_FILE')
    $original = @{}
    foreach ($name in $names) {
      $item = Get-Item -LiteralPath ("Env:{0}" -f $name) -ErrorAction SilentlyContinue
      $original[$name] = if ($null -eq $item) { $null } else { [string]$item.Value }
      Set-Item -LiteralPath ("Env:{0}" -f $name) -Value ("hostile-{0}" -f $name)
    }

    $snapshot = New-Object System.Collections.Generic.List[object]
    $restored = $false
    try {
      Enable-CopyLocalSafeGitEnvironment -Snapshot $snapshot

      foreach ($name in $names) {
        Test-Path -LiteralPath ("Env:{0}" -f $name) | Should -BeFalse
      }
      $env:GIT_CONFIG_NOSYSTEM | Should -Be '1'
      $env:GIT_ALLOW_PROTOCOL | Should -Be 'https'
      $env:GIT_PROTOCOL_FROM_USER | Should -Be '0'
      $env:GIT_TERMINAL_PROMPT | Should -Be '0'

      Restore-CopyLocalGitEnvironment -Snapshot $snapshot
      $restored = $true
      foreach ($name in $names) {
        (Get-Item -LiteralPath ("Env:{0}" -f $name) -ErrorAction Stop).Value | Should -Be ("hostile-{0}" -f $name)
      }
    } finally {
      if (-not $restored) { Restore-CopyLocalGitEnvironment -Snapshot $snapshot }
      foreach ($name in $names) {
        if ($null -eq $original[$name]) { Remove-Item -LiteralPath ("Env:{0}" -f $name) -ErrorAction SilentlyContinue }
        else { Set-Item -LiteralPath ("Env:{0}" -f $name) -Value $original[$name] }
      }
    }
  }

  It 'returns one FAIL result and the mapped exit code for an unsafe RepoUrl without invoking git' -Skip:$script:SkipNonSystemWindowsIntegration {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/00-Copy-Local.ps1'
    $hostPath = (Get-Process -Id $PID).Path
    $escapedScriptPath = $scriptPath.Replace("'", "''")
    $command = "& '$escapedScriptPath' -RepoUrl ' -option' -OutputFormat None -PassThru | ConvertTo-Json -Depth 10 -Compress"

    $json = & $hostPath -NoProfile -Command $command
    $exitCode = $LASTEXITCODE
    $result = @($json | ConvertFrom-Json)

    $exitCode | Should -Be 1
    $result.Count | Should -Be 1
    $result[0].Result | Should -Be 'FAIL'
    $result[0].ScriptName | Should -Be '00-Copy-Local.ps1'
    $result[0].Findings.Count | Should -Be 1
    $result[0].Findings[0].Message | Should -Be 'RepoUrl must not start with "-" or leading whitespace (option injection prevention).'
    $result[0].Summary.Error | Should -Be $result[0].Findings[0].Message
  }

  It 'returns WARN without touching the destination or invoking git under WhatIf' -Skip:$script:SkipNonSystemWindowsIntegration {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/00-Copy-Local.ps1'
    $destination = Join-Path ([System.IO.Path]::GetTempPath()) ("copy-local-whatif-{0}" -f [guid]::NewGuid().ToString('N'))

    try {
      $result = & $scriptPath -RepoUrl 'https://invalid.example/repo.git' -DestinationRoot $destination -OutputFormat None -PassThru -WhatIf

      $LASTEXITCODE | Should -Be 2
      $result.Result | Should -Be 'WARN'
      $result.Summary.Executed | Should -BeFalse
      Test-Path -LiteralPath $destination | Should -BeFalse
    } finally {
      if (Test-Path -LiteralPath $destination) {
        Remove-Item -LiteralPath $destination -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'fails before destination creation when the canonical destination lock is held by another process' -Skip:([Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    . (Get-CopyLocalFunctionBody -Name 'Get-CopyLocalDestinationLockPath')

    $scriptPath = Join-Path $PSScriptRoot '../../scripts/00-Copy-Local.ps1'
    $hostPath = (Get-Process -Id $PID).Path
    $tempRoot = Join-Path '/private/tmp' ("copy-local-lock-{0}" -f [guid]::NewGuid().ToString('N'))
    $destination = Join-Path $tempRoot 'destination'
    $stagingRoot = Join-Path $tempRoot 'baselineops-windows-copy-local-staging'
    $escapedScriptPath = $scriptPath.Replace("'", "''")
    $escapedDestination = $destination.Replace("'", "''")
    $escapedTempRoot = ($tempRoot + [System.IO.Path]::DirectorySeparatorChar).Replace("'", "''")
    $lockStream = $null

    try {
      [void][System.IO.Directory]::CreateDirectory($stagingRoot)
      $lockPath = Get-CopyLocalDestinationLockPath -DestinationRoot $destination -StagingRoot $stagingRoot
      $lockStream = [System.IO.File]::Open(
        $lockPath,
        [System.IO.FileMode]::OpenOrCreate,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None)
      $command = "`$env:TMPDIR = '$escapedTempRoot'; & '$escapedScriptPath' -RepoUrl 'https://invalid.example/repo.git' -DestinationRoot '$escapedDestination' -OutputFormat None -PassThru -Confirm:`$false | ConvertTo-Json -Depth 10 -Compress"

      $json = & $hostPath -NoProfile -Command $command
      $exitCode = $LASTEXITCODE
      $result = @($json | ConvertFrom-Json)

      $exitCode | Should -Be 1
      $result.Count | Should -Be 1
      $result[0].Result | Should -Be 'FAIL'
      $result[0].Summary.Error | Should -Match 'Another CopyLocal deployment is already active'
      Test-Path -LiteralPath $destination | Should -BeFalse
    } finally {
      if ($null -ne $lockStream) { $lockStream.Dispose() }
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'rejects the filesystem volume root as a destination' -Skip:$script:SkipNonSystemWindowsIntegration {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/00-Copy-Local.ps1'
    $volumeRoot = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetTempPath())

    $result = & $scriptPath -RepoUrl 'https://invalid.example/repo.git' -DestinationRoot $volumeRoot -OutputFormat None -PassThru -Confirm:$false

    $LASTEXITCODE | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    $result.Summary.Error | Should -Match 'subdirectory, not a volume root'
  }

  It 'rejects a RepoPath within deployed scripts before creating, deleting, or invoking Git' -Skip:$script:SkipNonSystemWindowsIntegration {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/00-Copy-Local.ps1'
    $hostPath = (Get-Process -Id $PID).Path
    $destination = Join-Path ([System.IO.Path]::GetTempPath()) ("copy-local-overlap-{0}" -f [guid]::NewGuid().ToString('N'))
    $repoPath = Join-Path $destination 'scripts/clone'
    $escapedScriptPath = $scriptPath.Replace("'", "''")
    $escapedDestination = $destination.Replace("'", "''")
    $escapedRepoPath = $repoPath.Replace("'", "''")
    $command = "& '$escapedScriptPath' -RepoUrl 'https://invalid.example/repo.git' -DestinationRoot '$escapedDestination' -RepoPath '$escapedRepoPath' -OutputFormat None -PassThru -Confirm:`$false | ConvertTo-Json -Depth 10 -Compress"

    try {
      $json = & $hostPath -NoProfile -Command $command
      $exitCode = $LASTEXITCODE
      $result = @($json | ConvertFrom-Json)

      $exitCode | Should -Be 1
      $result.Count | Should -Be 1
      $result[0].Result | Should -Be 'FAIL'
      $result[0].Summary.Error | Should -Match 'RepoPath must not equal or be contained by DestinationRoot'
      Test-Path -LiteralPath $destination | Should -BeFalse
    } finally {
      if (Test-Path -LiteralPath $destination) {
        Remove-Item -LiteralPath $destination -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'rejects an existing reparse-point deployment target before Git or deployment mutation' {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/00-Copy-Local.ps1'
    $hostPath = (Get-Process -Id $PID).Path
    $tempRoot = Join-Path '/private/tmp' ("copy-local-target-reparse-{0}" -f [guid]::NewGuid().ToString('N'))
    $destination = Join-Path $tempRoot 'destination'
    $outside = Join-Path $tempRoot 'outside'
    $target = Join-Path $destination 'scripts'
    $escapedScriptPath = $scriptPath.Replace("'", "''")
    $escapedDestination = $destination.Replace("'", "''")
    $command = "& '$escapedScriptPath' -RepoUrl 'https://invalid.example/repo.git' -DestinationRoot '$escapedDestination' -OutputFormat None -PassThru -Confirm:`$false | ConvertTo-Json -Depth 10 -Compress"

    try {
      New-Item -ItemType Directory -Path $destination, $outside -Force | Out-Null
      try {
        New-Item -ItemType SymbolicLink -Path $target -Target $outside -ErrorAction Stop | Out-Null
      } catch {
        Set-ItResult -Skipped -Because "The test host cannot create a symbolic link: $($_.Exception.Message)"
        return
      }

      $json = & $hostPath -NoProfile -Command $command
      $exitCode = $LASTEXITCODE
      $result = @($json | ConvertFrom-Json)

      $exitCode | Should -Be 1
      $result.Count | Should -Be 1
      $result[0].Result | Should -Be 'FAIL'
      $result[0].Summary.Error | Should -Match "Existing deployment target 'scripts' contains a reparse point"
      (Get-Item -LiteralPath $target -Force).Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint) | Should -BeTrue
      Test-Path -LiteralPath (Join-Path $destination '_repo') | Should -BeFalse
      @(Get-ChildItem -LiteralPath $destination -Force -Filter '.git-hooks-*').Count | Should -Be 0
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'does not remove a caller-supplied RepoPath that fails trusted-staging validation' -Skip:$script:SkipNonSystemWindowsIntegration {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/00-Copy-Local.ps1'
    $hostPath = (Get-Process -Id $PID).Path
    $tempRoot = Join-Path '/private/tmp' ("copy-local-untrusted-repo-{0}" -f [guid]::NewGuid().ToString('N'))
    $destination = Join-Path $tempRoot 'destination'
    $repoPath = Join-Path $tempRoot 'untrusted-existing-clone'
    $marker = Join-Path $repoPath 'must-remain.txt'
    $escapedScriptPath = $scriptPath.Replace("'", "''")
    $escapedDestination = $destination.Replace("'", "''")
    $escapedRepoPath = $repoPath.Replace("'", "''")
    $escapedTempRoot = ($tempRoot + [System.IO.Path]::DirectorySeparatorChar).Replace("'", "''")
    $command = "`$env:TMPDIR = '$escapedTempRoot'; & '$escapedScriptPath' -RepoUrl 'https://invalid.example/repo.git' -DestinationRoot '$escapedDestination' -RepoPath '$escapedRepoPath' -OutputFormat None -PassThru -Confirm:`$false | ConvertTo-Json -Depth 10 -Compress"

    try {
      New-Item -ItemType Directory -Path $repoPath -Force | Out-Null
      Set-Content -LiteralPath $marker -Value 'preserve this caller-owned path' -NoNewline

      $json = & $hostPath -NoProfile -Command $command
      $exitCode = $LASTEXITCODE
      $result = @($json | ConvertFrom-Json)

      $exitCode | Should -Be 1
      $result.Count | Should -Be 1
      $result[0].Summary.Error | Should -Match 'RepoPath must be within the fixed trusted staging root'
      Test-Path -LiteralPath $marker | Should -BeTrue
      (Get-Content -LiteralPath $marker -Raw) | Should -Be 'preserve this caller-owned path'
      Test-Path -LiteralPath $destination | Should -BeFalse
    } finally {
      if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 'contains the Windows-only protected staging ACL enforcement' -Skip:($env:OS -ne 'Windows_NT') {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/00-Copy-Local.ps1'
    $scriptText = Get-Content -LiteralPath $scriptPath -Raw -Encoding UTF8

    $scriptText | Should -Match 'if \(\[Environment\]::OSVersion\.Platform -ne \[System\.PlatformID\]::Win32NT\) \{ return \}'
    $scriptText | Should -Match 'Trusted staging root ACL is not restricted to Administrators and SYSTEM'
  }

  It 'rejects a weak explicit ACL on a bootstrap module before loading it' -Skip:([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    . (Get-CopyLocalFunctionBody -Name 'Assert-CopyLocalBootstrapPathTrust')
    $path = Join-Path $TestDrive 'Validation.psm1'
    Set-Content -LiteralPath $path -Value '# ACL fixture' -Encoding UTF8
    try {
      $administrators = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
      $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
      $users = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
      $acl = New-Object Security.AccessControl.FileSecurity
      $acl.SetOwner($administrators)
      $acl.SetAccessRuleProtection($true, $false)
      foreach ($sid in @($administrators, $system)) {
        [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
              $sid,
              [Security.AccessControl.FileSystemRights]::FullControl,
              [Security.AccessControl.AccessControlType]::Allow)))
      }
      Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
    } catch {
      Set-ItResult -Skipped -Because "The current Windows test identity cannot create the required ACL fixture: $($_.Exception.Message)"
      return
    }

    { Assert-CopyLocalBootstrapPathTrust -Path $path } | Should -Not -Throw
    $unsafe = Get-Acl -LiteralPath $path
    [void]$unsafe.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
          $users,
          [Security.AccessControl.FileSystemRights]::Modify,
          [Security.AccessControl.AccessControlType]::Allow)))
    Set-Acl -LiteralPath $path -AclObject $unsafe -ErrorAction Stop
    { Assert-CopyLocalBootstrapPathTrust -Path $path } | Should -Throw '*untrusted SID*'
  }

  It 'excludes inherit-only templates from current-object destination ACL rights' {
    (Get-CopyLocalFunctionBody -Name 'Assert-CopyLocalAclObjectTrust').ToString() |
      Should -Match 'PropagationFlags\]::InheritOnly'
  }

  It 'rejects Users and named-user write ACEs by SID' -Skip:([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    . (Get-CopyLocalFunctionBody -Name 'Get-CopyLocalTrustedWriterSid')
    . (Get-CopyLocalFunctionBody -Name 'Assert-CopyLocalAclObjectTrust')

    $administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    foreach ($untrustedSidValue in @('S-1-5-32-545', 'S-1-5-21-1000-1000-1000-1001')) {
      $acl = New-Object System.Security.AccessControl.DirectorySecurity
      $acl.SetOwner($administrators)
      $acl.SetAccessRuleProtection($true, $false)
      $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $administrators,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow)))
      $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier($untrustedSidValue)),
            [System.Security.AccessControl.FileSystemRights]::Modify,
            [System.Security.AccessControl.AccessControlType]::Allow)))

      { Assert-CopyLocalAclObjectTrust -Acl $acl -Path 'C:\install\mdm\ps1' -RequireProtected } |
        Should -Throw -ExpectedMessage "*untrusted SID '$untrustedSidValue'*"
    }
  }

  It 'rejects ancestor replacement and delete rights granted to an untrusted SID' -Skip:([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    . (Get-CopyLocalFunctionBody -Name 'Get-CopyLocalTrustedWriterSid')
    . (Get-CopyLocalFunctionBody -Name 'Assert-CopyLocalAclObjectTrust')

    $administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $users = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
    foreach ($right in @(
        [System.Security.AccessControl.FileSystemRights]::Delete,
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions,
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership)) {
      $acl = New-Object System.Security.AccessControl.DirectorySecurity
      $acl.SetOwner($administrators)
      $acl.SetAccessRuleProtection($true, $false)
      $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $users,
            $right,
            [System.Security.AccessControl.AccessControlType]::Allow)))

      { Assert-CopyLocalAclObjectTrust -Acl $acl -Path 'C:\install\mdm' `
          -BoundaryLabel 'Destination ancestor' -ReplacementOnly } |
        Should -Throw -ExpectedMessage "*replacement-capable*untrusted SID 'S-1-5-32-545'*"
    }
  }

  It 'ignores inherit-only ACL templates but still rejects effective replacement rights' -Skip:([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    . (Get-CopyLocalFunctionBody -Name 'Get-CopyLocalTrustedWriterSid')
    . (Get-CopyLocalFunctionBody -Name 'Assert-CopyLocalAclObjectTrust')

    $administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $creatorOwner = New-Object System.Security.Principal.SecurityIdentifier('S-1-3-0')
    $users = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
      [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetOwner($administrators)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
          $administrators,
          [System.Security.AccessControl.FileSystemRights]::FullControl,
          [System.Security.AccessControl.AccessControlType]::Allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
          $creatorOwner,
          [System.Security.AccessControl.FileSystemRights]::FullControl,
          $inheritance,
          [System.Security.AccessControl.PropagationFlags]::InheritOnly,
          [System.Security.AccessControl.AccessControlType]::Allow)))

    { Assert-CopyLocalAclObjectTrust -Acl $acl -Path 'C:\install\mdm' `
        -BoundaryLabel 'Destination ancestor' -ReplacementOnly -RequireProtected } |
      Should -Not -Throw

    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
          $users,
          [System.Security.AccessControl.FileSystemRights]::Delete,
          [System.Security.AccessControl.AccessControlType]::Allow)))
    { Assert-CopyLocalAclObjectTrust -Acl $acl -Path 'C:\install\mdm' `
        -BoundaryLabel 'Destination ancestor' -ReplacementOnly -RequireProtected } |
      Should -Throw -ExpectedMessage "*replacement-capable*untrusted SID 'S-1-5-32-545'*"
  }

  It 'builds a protected new-destination ACL owned by Administrators with only Admin and SYSTEM writers' -Skip:([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    . (Get-CopyLocalFunctionBody -Name 'Set-CopyLocalNewDestinationAcl')
    function Assert-CopyLocalDestinationAclTrust {
      param([string]$Path, [switch]$RequireProtected)
      $null = $Path
      $null = $RequireProtected
    }
    $script:capturedDestinationAcl = $null
    Mock Set-Acl { $script:capturedDestinationAcl = $AclObject }
    Mock Assert-CopyLocalDestinationAclTrust {}

    Set-CopyLocalNewDestinationAcl -Path 'C:\install\mdm\ps1' -Confirm:$false

    $script:capturedDestinationAcl | Should -Not -BeNullOrEmpty
    $script:capturedDestinationAcl.AreAccessRulesProtected | Should -BeTrue
    $script:capturedDestinationAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value |
      Should -Be 'S-1-5-32-544'
    $rules = @($script:capturedDestinationAcl.GetAccessRules(
        $true,
        $false,
        [System.Security.Principal.SecurityIdentifier]))
    @($rules.IdentityReference.Value | Sort-Object) | Should -Be @('S-1-5-18', 'S-1-5-32-544')
    @($rules | Where-Object {
        $_.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
        -not $_.FileSystemRights.HasFlag([System.Security.AccessControl.FileSystemRights]::FullControl)
      }).Count | Should -Be 0
  }

  It 'turns post-commit backup deletion faults into explicit residue instead of an exception' {
    . (Get-CopyLocalFunctionBody -Name 'Remove-CopyLocalCommittedBackup')

    Mock Test-Path { return $true } -ParameterFilter { $LiteralPath -eq '/protected/.scripts.previous-test' }
    Mock Remove-Item { throw 'simulated access denied' } -ParameterFilter { $LiteralPath -eq '/protected/.scripts.previous-test' }
    $swaps = @([pscustomobject]@{
        Target = '/protected/scripts'
        Backup = '/protected/.scripts.previous-test'
        HadExisting = $true
        Installed = $true
      })

    $residue = @(Remove-CopyLocalCommittedBackup -Swaps $swaps -Confirm:$false)

    $residue.Count | Should -Be 1
    $residue[0].Path | Should -Be '/protected/.scripts.previous-test'
    $residue[0].Error | Should -Match 'simulated access denied'
  }

  It 'retains the backup and records rollback residue when installed-target removal fails' {
    . (Get-CopyLocalFunctionBody -Name 'Restore-CopyLocalDeploymentSwaps')

    $target = '/protected/scripts'
    $backup = '/protected/.scripts.previous-test'
    Mock Test-Path { return $true }
    Mock Remove-Item { throw 'simulated target removal denied' } -ParameterFilter { $LiteralPath -eq $target }
    Mock Move-Item {} -ParameterFilter { $LiteralPath -eq $backup }
    $swaps = New-Object System.Collections.Generic.List[object]
    [void]$swaps.Add([pscustomobject]@{
        Target = $target
        Backup = $backup
        HadExisting = $true
        Installed = $true
      })

    $residue = @(Restore-CopyLocalDeploymentSwaps -Swaps $swaps)

    $residue.Count | Should -Be 1
    $residue[0].Target | Should -Be $target
    $residue[0].Backup | Should -Be $backup
    $residue[0].BackupExists | Should -BeTrue
    $residue[0].InvariantSatisfied | Should -BeFalse
    ($residue[0].Errors -join "`n") | Should -Match 'simulated target removal denied'
    ($residue[0].Errors -join "`n") | Should -Match 'replacement target remains'
    Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $LiteralPath -eq $target -and $ErrorAction -eq 'Stop' }
    Should -Invoke Move-Item -Times 0 -Exactly -ParameterFilter { $LiteralPath -eq $backup }
  }

  It 'retains the backup and records rollback residue when backup restore fails' {
    . (Get-CopyLocalFunctionBody -Name 'Restore-CopyLocalDeploymentSwaps')

    $target = '/protected/lib'
    $backup = '/protected/.lib.previous-test'
    $script:targetProbeCount = 0
    Mock Test-Path {
      if ($LiteralPath -eq $target) {
        $script:targetProbeCount++
        return $script:targetProbeCount -eq 1
      }
      return $LiteralPath -eq $backup
    }
    Mock Remove-Item {} -ParameterFilter { $LiteralPath -eq $target }
    Mock Move-Item { throw 'simulated backup restore denied' } -ParameterFilter { $LiteralPath -eq $backup }
    $swaps = New-Object System.Collections.Generic.List[object]
    [void]$swaps.Add([pscustomobject]@{
        Target = $target
        Backup = $backup
        HadExisting = $true
        Installed = $true
      })

    $residue = @(Restore-CopyLocalDeploymentSwaps -Swaps $swaps)

    $residue.Count | Should -Be 1
    $residue[0].Target | Should -Be $target
    $residue[0].Backup | Should -Be $backup
    $residue[0].TargetExists | Should -BeFalse
    $residue[0].BackupExists | Should -BeTrue
    $residue[0].InvariantSatisfied | Should -BeFalse
    ($residue[0].Errors -join "`n") | Should -Match 'simulated backup restore denied'
    Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $LiteralPath -eq $target -and $ErrorAction -eq 'Stop' }
    Should -Invoke Move-Item -Times 1 -Exactly -ParameterFilter { $LiteralPath -eq $backup -and $Destination -eq $target -and $ErrorAction -eq 'Stop' }
  }
}
