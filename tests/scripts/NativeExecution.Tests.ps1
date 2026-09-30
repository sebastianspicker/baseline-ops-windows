#requires -version 5.1
<#
.SYNOPSIS
  Verifies that scripts reach native executables only through External.psm1.
.DESCRIPTION
  Parses every maintained script and rejects bare native executable command invocations that bypass exact
  executable resolution, timeouts, and bounded output.
#>

Describe 'Script native execution boundary' -Tag 'Security' {
  BeforeAll {
    $script:RepositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).ProviderPath

    function Get-PlatformNativeExecutableName {
      $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
      $platformFiles = Get-ChildItem -LiteralPath (Join-Path $script:RepositoryRoot 'lib/platform') -Filter '*.ps1' -File
      foreach ($file in $platformFiles) {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
        $literals = $ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.StringConstantExpressionAst] -and
            $node.Value -match '^[A-Za-z0-9_-]+\.exe$'
          }, $true)
        foreach ($literal in $literals) {
          [void]$names.Add([IO.Path]::GetFileNameWithoutExtension($literal.Value))
        }
      }
      return , $names
    }

    function Test-BareNativeCommandName {
      param([string]$Name, [System.Collections.Generic.HashSet[string]]$NativeNames)

      return ($Name -match '\.exe$') -or $NativeNames.Contains($Name)
    }

    function Get-BareNativeInvocation {
      param([IO.FileInfo]$File, [System.Collections.Generic.HashSet[string]]$NativeNames)

      $tokens = $null
      $errors = $null
      $ast = [Management.Automation.Language.Parser]::ParseFile($File.FullName, [ref]$tokens, [ref]$errors)
      $relative = $File.FullName.Substring($script:RepositoryRoot.Length).TrimStart('\', '/')
      $commands = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true)
      foreach ($command in $commands) {
        $nameElement = $command.CommandElements[0]
        if ($nameElement -isnot [Management.Automation.Language.StringConstantExpressionAst]) { continue }
        if (Test-BareNativeCommandName -Name ([string]$nameElement.Value) -NativeNames $NativeNames) {
          '{0}:{1} {2}' -f $relative, $nameElement.Extent.StartLineNumber, $nameElement.Value
        }
      }
    }
  }

  It 'derives the native executable policy names from the platform implementation' {
    $names = Get-PlatformNativeExecutableName
    foreach ($expected in @('auditpol', 'certutil', 'dsregcmd', 'reg', 'schtasks', 'wevtutil', 'winget')) {
      $names.Contains($expected) | Should -BeTrue -Because "$expected must be resolved by lib/platform"
    }
  }

  It 'scripts do not invoke bare native executables outside Invoke-NativeCommand' {
    $nativeNames = Get-PlatformNativeExecutableName
    foreach ($known in @(
        'bcdedit', 'dsregcmd', 'gpresult', 'gpupdate', 'ipconfig', 'manage-bde', 'mpcmdrun', 'netsh',
        'nltest', 'sysmon', 'sysmon64', 'w32tm', 'whoami', 'wmic'
      )) {
      [void]$nativeNames.Add($known)
    }

    $scriptFiles = Get-ChildItem -LiteralPath (Join-Path $script:RepositoryRoot 'scripts') -Filter '*.ps1' -File -Recurse
    $violations = @($scriptFiles | ForEach-Object { Get-BareNativeInvocation -File $_ -NativeNames $nativeNames })

    $violations | Should -BeNullOrEmpty
  }
}
