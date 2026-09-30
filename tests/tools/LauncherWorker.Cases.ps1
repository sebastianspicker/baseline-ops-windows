#requires -Version 5.1
<#
.SYNOPSIS
Cases for the launcher worker and manifest trust boundary tests.
.DESCRIPTION
Holds the worker function extraction, kit fixtures, and Test-* behavior functions
invoked by LauncherWorker.Tests.ps1. Verifies worker command mapping, entry-point splatting and exit-code relay,
manifest validation, size caps, and launcher argument safety without the
Windows-only start gate, job object, or file locks.
#>

# Returns source text of the launcher worker functions under test, without running the worker.
function Get-LauncherWorkerFunctionSource {
  param([string]$Path)
  $tokens = $null
  $parseErrors = $null
  $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
  $parseErrors.Count | Should -Be 0
  $names = @(
    'Get-LauncherWorkerManifestJson', 'Get-LauncherWorkerManifestFileJson', 'Get-LauncherSelectedExecutionPath',
    'Get-LauncherWorkerCommand', 'Get-LauncherWorkerScriptCommand', 'Get-LauncherWorkerProfileCommand',
    'Invoke-LauncherEntryPoint'
  )
  $functionAsts = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $names
      }, $true))
  $functionAsts.Count | Should -Be $names.Count
  return (($functionAsts | ForEach-Object { $_.Extent.Text }) -join [Environment]::NewLine)
}

# Creates a stub kit with the three 00-* entry points and returns its path.
function New-LauncherTestKit {
  param([string]$Directory)
  $kit = Join-Path $Directory 'kit'
  New-Item -ItemType Directory -Path (Join-Path $kit 'scripts') -Force | Out-Null
  foreach ($name in @('00-Run-Local.ps1', '00-Run-Profile.ps1', '00-Validate-Profile.ps1')) {
    Set-Content -LiteralPath (Join-Path $kit "scripts/$name") -Value '# stub'
  }
  return $kit
}

# Creates the stub entry point script and returns its path.
function New-LauncherEntryPointStub {
  $stub = Join-Path $TestDrive 'stub.ps1'
  Set-Content -LiteralPath $stub -Value @'
param([string]$ProfilePath, [string]$Mode, [switch]$Strict, [int]$Code = 0)
"ProfilePath=$ProfilePath"
"Mode=$Mode"
"Strict=$($Strict.IsPresent)"
Write-Warning 'stub-warning'
exit $Code
'@
  return $stub
}

# Builds a manifest object from the test kit and profile; Override replaces fields.
function New-TestManifest {
  param([hashtable]$Override = @{})
  $manifest = [ordered]@{
    schemaVersion = 1; operation = 'run-profile'; root = $script:kit; target = $script:profilePath; mode = 'Audit'
    argumentTokens = @(); strict = $false; requireSigned = $false; expectedHash = ''
    hashAlgorithm = 'SHA256'; remediationApproved = $false
  }
  foreach ($key in $Override.Keys) { $manifest[$key] = $Override[$key] }
  return ([pscustomobject]$manifest | ConvertTo-Json -Depth 4 | ConvertFrom-Json)
}

function Test-EntryPointSplatsParameterTable {
  param([string]$Stub)
  $command = @{ Path = $Stub; Parameters = @{ ProfilePath = 'C:\p.json'; Mode = 'Audit'; Strict = $true } }
  $lines = @(Invoke-LauncherEntryPoint -Command $command)
  $lines | Should -Contain 'ProfilePath=C:\p.json'
  $lines | Should -Contain 'Mode=Audit'
  $lines | Should -Contain 'Strict=True'
  ($lines -join "`n") | Should -Not -Match 'System.Collections.Hashtable'
}

function Test-EntryPointRelaysStreamsAndExitCode {
  param([string]$Stub)
  $command = @{ Path = $Stub; Parameters = @{ Code = 7 } }
  $lines = @(Invoke-LauncherEntryPoint -Command $command)
  $lines | Should -Contain 'stub-warning'
  @($lines | Where-Object { $_ -isnot [string] }).Count | Should -Be 0
  $script:LauncherWorkerExitCode | Should -Be 7
}

function Test-EntryPointReportsZeroWithoutExitCode {
  $quiet = Join-Path $TestDrive 'quiet.ps1'
  Set-Content -LiteralPath $quiet -Value 'param() "ok"'
  $global:LASTEXITCODE = 9
  Invoke-LauncherEntryPoint -Command @{ Path = $quiet; Parameters = @{} } | Out-Null
  $script:LauncherWorkerExitCode | Should -Be 0
}

function Test-WorkerCommandMapsValidateProfile {
  $command = Get-LauncherWorkerCommand -Manifest (New-TestManifest @{ operation = 'validate-profile' })
  $command.Path | Should -Be (Join-Path (Join-Path $script:kit 'scripts') '00-Validate-Profile.ps1')
  ($command.Parameters.Keys | Sort-Object) | Should -Be @('OutputFormat', 'ProfilePath', 'RootPath')
  $command.Parameters.ProfilePath | Should -Be $script:profilePath
  $command.Parameters.RootPath | Should -Be $script:kit
  $command.Parameters.OutputFormat | Should -Be 'Console'
}

function Test-WorkerCommandMapsRunProfile {
  $plain = Get-LauncherWorkerCommand -Manifest (New-TestManifest @{ mode = 'Audit' })
  $plain.Path | Should -Be (Join-Path (Join-Path $script:kit 'scripts') '00-Run-Profile.ps1')
  ($plain.Parameters.Keys | Sort-Object) | Should -Be @('Confirm', 'Mode', 'OutputFormat', 'ProfilePath', 'RootPath')
  $plain.Parameters.Mode | Should -Be 'Audit'
  $plain.Parameters.Confirm | Should -BeFalse
  $strict = Get-LauncherWorkerCommand -Manifest (New-TestManifest @{ strict = $true; requireSigned = $true })
  $strict.Parameters.Strict | Should -BeTrue
  $strict.Parameters.RequireSigned | Should -BeTrue
}

function Test-WorkerCommandMapsRunScript {
  $manifest = New-TestManifest @{ operation = 'run-script'; target = '01-Test.ps1'; mode = 'Remediate'; remediationApproved = $true; argumentTokens = @('-Foo', 'bar'); strict = $true }
  $command = Get-LauncherWorkerCommand -Manifest $manifest
  $command.Path | Should -Be (Join-Path (Join-Path $script:kit 'scripts') '00-Run-Local.ps1')
  $command.Parameters.ScriptName | Should -Be '01-Test.ps1'
  $command.Parameters.ScriptArgs | Should -Be @('-Mode', 'Remediate', '-Foo', 'bar', '-Strict')
  $command.Parameters.ContainsKey('ExpectedHash') | Should -BeFalse
  $command.Parameters.ContainsKey('RequireSigned') | Should -BeFalse
}

function Test-WorkerCommandPassesExpectedHashWithAlgorithm {
  $hash = 'a' * 96
  $manifest = New-TestManifest @{ operation = 'run-script'; target = '01-Test.ps1'; expectedHash = $hash; hashAlgorithm = 'SHA384'; requireSigned = $true }
  $command = Get-LauncherWorkerCommand -Manifest $manifest
  $command.Parameters.ExpectedHash | Should -Be $hash
  $command.Parameters.HashAlgorithm | Should -Be 'SHA384'
  $command.Parameters.RequireSigned | Should -BeTrue
}

function Test-WorkerCommandRejectsUnsafeScriptTargets {
  { Get-LauncherWorkerCommand -Manifest (New-TestManifest @{ operation = 'run-script'; target = '..\evil.ps1' }) } | Should -Throw '*safe numbered script name*'
  { Get-LauncherWorkerCommand -Manifest (New-TestManifest @{ operation = 'run-script'; target = 'notnumbered.ps1' }) } | Should -Throw '*safe numbered script name*'
}

function Test-WorkerCommandRejectsUnknownOperations {
  { Get-LauncherWorkerCommand -Manifest (New-TestManifest @{ operation = 'format-disk' }) } | Should -Throw '*Unsupported launcher operation*'
}

function Test-SelectedExecutionPathResolvesTargets {
  Get-LauncherSelectedExecutionPath -Manifest (New-TestManifest @{ operation = 'run-script'; target = '01-Test.ps1' }) |
    Should -Be (Join-Path (Join-Path $script:kit 'scripts') '01-Test.ps1')
  Get-LauncherSelectedExecutionPath -Manifest (New-TestManifest) | Should -Be $script:profilePath
}

function Test-ManifestJsonDecodesInheritedBase64 {
  $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"a":1}'))
  Get-LauncherWorkerManifestJson -Base64 $b64 -Path '' | Should -Be '{"a":1}'
}

function Test-ManifestJsonRejectsOversizedOrMalformedBase64 {
  { Get-LauncherWorkerManifestJson -Base64 ('A' * 24001) -Path '' } | Should -Throw '*invalid or oversized*'
  { Get-LauncherWorkerManifestJson -Base64 'not base64!' -Path '' } | Should -Throw '*invalid or oversized*'
}

function Test-ManifestJsonAcceptsBase64AtCap {
  (Get-LauncherWorkerManifestJson -Base64 ('A' * 24000) -Path '').Length | Should -BeGreaterThan 0
}

function Test-ManifestJsonReadsFileWithinCap {
  $file = Join-Path $TestDrive 'ok.json'
  Set-Content -LiteralPath $file -Value '{"a":1}' -NoNewline
  (Get-LauncherWorkerManifestJson -Base64 '' -Path $file).Trim() | Should -Be '{"a":1}'
}

function Test-ManifestJsonRejectsOversizedFileDirectoryAndMissingPath {
  $big = Join-Path $TestDrive 'big.json'
  [IO.File]::WriteAllText($big, ('x' * 16385))
  { Get-LauncherWorkerManifestJson -Base64 '' -Path $big } | Should -Throw '*invalid or oversized*'
  { Get-LauncherWorkerManifestJson -Base64 '' -Path $TestDrive } | Should -Throw '*invalid or oversized*'
  { Get-LauncherWorkerManifestJson -Base64 '' -Path '' } | Should -Throw '*not provided*'
}

function Test-ManifestAcceptsValidOperations {
  { Assert-LauncherManifest -Manifest (New-TestManifest) } | Should -Not -Throw
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ operation = 'validate-profile' }) } | Should -Not -Throw
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ operation = 'run-script'; target = '01-Test.ps1'; argumentTokens = @('-Foo'); expectedHash = ('b' * 64) }) } | Should -Not -Throw
}

function Test-ManifestRejectsNonObjectRoot {
  { Assert-LauncherManifest -Manifest 'text' } | Should -Throw '*must be an object*'
  { Assert-LauncherManifest -Manifest @(1, 2) } | Should -Throw '*must be an object*'
}

function Test-ManifestRejectsUnknownAndMissingFields {
  $extra = New-TestManifest; $extra | Add-Member -NotePropertyName extra -NotePropertyValue 1
  { Assert-LauncherManifest -Manifest $extra } | Should -Throw "*unknown field 'extra'*"
  $missing = New-TestManifest; $missing.PSObject.Properties.Remove('mode')
  { Assert-LauncherManifest -Manifest $missing } | Should -Throw "*missing required field 'mode'*"
}

function Test-ManifestRejectsUnsupportedSchemaAndFieldTypes {
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ schemaVersion = 2 }) } | Should -Throw '*Unsupported launcher manifest schema version*'
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ schemaVersion = '1' }) } | Should -Throw '*schemaVersion must be an integer*'
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ strict = 'yes' }) } | Should -Throw "*'strict' must be a boolean*"
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ target = 5 }) } | Should -Throw "*'target' must be a string*"
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ argumentTokens = 'x' }) } | Should -Throw "*'argumentTokens' must be an array*"
}

function Test-ManifestRejectsUnsupportedOperationModeAndAlgorithm {
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ operation = 'format-disk' }) } | Should -Throw '*Unsupported launcher operation*'
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ mode = 'Destroy' }) } | Should -Throw '*Unsupported execution mode*'
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ hashAlgorithm = 'MD5' }) } | Should -Throw '*Unsupported hash algorithm*'
}

function Test-ManifestRequiresRemediationApproval {
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ mode = 'Remediate' }) } | Should -Throw '*remediation approval*'
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ mode = 'Remediate'; remediationApproved = $true }) } | Should -Not -Throw
}

function Test-ManifestRejectsInvalidRootTargetsAndHashLength {
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ root = (Join-Path $TestDrive 'nokit') }) } | Should -Throw '*kit root is invalid*'
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ operation = 'run-script'; target = '..\x.ps1' }) } | Should -Throw '*script target is invalid*'
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ target = (Join-Path $TestDrive 'missing.json') }) } | Should -Throw '*profile target is invalid*'
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ operation = 'run-script'; target = '01-Test.ps1'; expectedHash = 'abc' }) } | Should -Throw '*expected hash is invalid*'
}

function Test-ManifestRestrictsHashAndTokensToSingleScriptRuns {
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ expectedHash = ('b' * 64) }) } | Should -Throw '*only valid for a single-script run*'
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ argumentTokens = @('-Foo') }) } | Should -Throw '*only valid for a single-script run*'
}

function Test-ManifestRejectsLauncherOwnedArgumentTokens {
  { Assert-LauncherManifest -Manifest (New-TestManifest @{ operation = 'run-script'; target = '01-Test.ps1'; argumentTokens = @('-Mode', 'Remediate') }) } | Should -Throw '*controlled by the launcher*'
}

function Test-ArgumentsAllowedAcceptsOrdinaryArguments {
  (Assert-LauncherArgumentsAllowed -ArgumentTokens @('-Name', 'value', '--flag', '-Count:3', 'plain')) | Should -Be @('-Name', 'value', '--flag', '-Count:3', 'plain')
  @(Assert-LauncherArgumentsAllowed).Count | Should -Be 0
}

function Test-ArgumentsAllowedRejectsLauncherOwnedNames {
  foreach ($token in @('-Mode', '-rootpath:C:\x', '--ExpectedHash=abc', '-CONFIRM', '-WhatIf', '-Strict', '-ScriptArgs', '-OutputPath:x', '-ConfigPath')) {
    { Assert-LauncherArgumentsAllowed -ArgumentTokens @($token) } | Should -Throw '*controlled by the launcher*'
  }
}
