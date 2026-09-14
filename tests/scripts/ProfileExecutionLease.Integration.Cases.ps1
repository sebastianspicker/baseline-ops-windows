#requires -version 5.1
<#
.SYNOPSIS
Lease integration assertion cases.
.DESCRIPTION
Keeps source-contract checks in named functions used by the focused integration suite.
#>
function Test-RunnerLeaseImportsAndLifetime {
  param([string]$ProfileSource, [string]$LocalSource)

  $ProfileSource | Should -Match 'Import-Module \$leaseModulePath -DisableNameChecking'
  $LocalSource | Should -Match 'Import-Module \$bootstrap\.LeaseModulePath -DisableNameChecking'
  $ProfileSource | Should -Not -Match 'Import-Module \$leaseModulePath[^\r\n]*-Force'
  $LocalSource | Should -Not -Match 'Import-Module \$bootstrap\.LeaseModulePath[^\r\n]*-Force'
  $ProfileSource.LastIndexOf('Close-ProfileExecutionLease') |
    Should -BeGreaterThan $ProfileSource.LastIndexOf('Write-ResultObject')
  $LocalSource.LastIndexOf('Close-ProfileExecutionLease') |
    Should -BeGreaterThan $LocalSource.LastIndexOf('exit $terminal.ExitCode')
}

function Test-ProfileLeaseAcquisitionAndRoots {
  param([string]$Source)

  $openIndex = $Source.LastIndexOf('$profileExecutionLease = Open-ProfileExecutionLease')
  $dependencyIndex = $Source.LastIndexOf('. $bootstrap.DependencyPath')
  $openIndex | Should -BeGreaterThan -1
  $openIndex | Should -BeLessThan $dependencyIndex
  foreach ($required in @(
      'HelperPath',
      'ValidatorPath',
      'ValidatorHelperPath',
      'RunLocalPath',
      'RunLocalHelperPath',
      'ProfileExecutionLease.psm1')) {
    $Source | Should -Match ([regex]::Escape($required))
  }
  Test-RunnerLeaseClosureRoots -Source $Source
}

function Test-ProfilePublicInvocationFrames {
  param([string]$Source)

  $Source | Should -Match 'function Invoke-RunProfileValidator'
  $Source | Should -Match '& \$Context\.ValidatorPath'
  $Source | Should -Match 'function Invoke-RunProfileChild'
  $Source | Should -Match '& \$Context\.RunLocalPath @RunParameters'
}

function Test-RunLocalLeaseAndTargetHandle {
  param([string]$Source, [string]$RuntimeSource)

  $openIndex = $Source.LastIndexOf('$localExecutionLease = Open-ProfileExecutionLease')
  $dependencyIndex = $Source.LastIndexOf('. $bootstrap.DependencyPath')
  $openIndex | Should -BeGreaterThan -1
  $openIndex | Should -BeLessThan $dependencyIndex
  Test-RunnerLeaseClosureRoots -Source $Source
  $Source | Should -Match 'function Invoke-TargetScript'
  $Source | Should -Match '& \$Path @namedArguments'
  $RuntimeSource | Should -Match '\$maxScriptBytes\s*=\s*10MB'
  $RuntimeSource | Should -Match '\[System\.IO\.FileShare\]::Read'
  $RuntimeSource | Should -Match 'Assert-RunLocalTrustedWindowsAcl -Path \$Path'
  $RuntimeSource | Should -Match 'Get-AuthenticodeSignature -FilePath \$Path'
  $RuntimeSource | Should -Match 'Get-FileHash -InputStream \$Stream'
  ([regex]::Matches($RuntimeSource, 'Get-RunLocalLockedPathFailure \$Path \$scriptsRoot')).Count |
    Should -BeGreaterOrEqual 2
}

function Test-RunnerLeaseClosureRoots {
  param([string]$Source)

  foreach ($rootProperty in @('RunnerRoot', 'RootPath')) {
    foreach ($relativePath in @('scripts/_lib', 'scripts/internal', 'lib')) {
      $pattern = "Join-Path `$Context.$rootProperty '$relativePath'"
      $Source | Should -Match ([regex]::Escape($pattern))
    }
  }
}
