#requires -version 5.1
<#
.SYNOPSIS
Creates private fixtures for profile execution lease tests.
.DESCRIPTION
Builds exact-name runner harnesses used to exercise registered lease identity,
owner and borrower behavior, replacement denial, and terminal disposal.
#>

function New-LeaseFixture {
  param([string]$BasePath, [string]$Name = 'root')

  $root = Join-Path $BasePath $Name
  $closure = Join-Path $root 'closure'
  [void](New-Item -ItemType Directory -Path $closure -Force)
  $control = Join-Path $root 'control.ps1'
  [IO.File]::WriteAllText($control, 'control')
  [IO.File]::WriteAllText((Join-Path $closure 'helper.ps1'), 'helper')
  return [pscustomobject]@{ Root = $root; Closure = $closure; Control = $control }
}

function New-LeaseHarness {
  param([string]$BasePath)

  $scripts = Join-Path $BasePath 'scripts'
  [void](New-Item -ItemType Directory -Path $scripts -Force)
  $parent = Join-Path $scripts '00-Run-Profile.ps1'
  $child = Join-Path $scripts '00-Run-Local.ps1'
  $rogue = Join-Path $scripts 'rogue.ps1'
  $probe = Join-Path $scripts 'probe.ps1'
  [IO.File]::WriteAllText($child, @'
param($Module,$RunnerRoot,$TargetRoot,$Control,$Closure)
Import-Module $Module
$lease=Open-ProfileExecutionLease -RunnerRoot $RunnerRoot -TargetRoot $TargetRoot -ControlFiles @($Control) -ClosureRoots @($Closure)
try { Get-ProfileExecutionLeaseInfo -Lease $lease } finally { Close-ProfileExecutionLease -Lease $lease }
'@)
  [IO.File]::WriteAllText($rogue, @'
param($Module,$Lease)
Import-Module $Module
try{Close-ProfileExecutionLease -Lease $Lease;return $false}catch{return $true}
'@)
  [IO.File]::WriteAllText($probe, @'
param($Module,$Lease,[ValidateSet('Identity','ExclusiveWrite')][string]$Mode,[string[]]$Paths)
Import-Module $Module
if($Mode-eq'Identity'){try{[void](Get-ProfileExecutionLeaseInfo -Lease $Lease);return $true}catch{return $false}}
foreach($path in $Paths){try{$stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$stream.Dispose()}catch{return $false}}
return $true
'@)
  [IO.File]::WriteAllText($parent, @'
param($Module,$RunnerRoot,$TargetRoot,$Control,$Closure,$Child,$ChildTargetRoot,$ChildControl,$ChildClosure,$Rogue,$Probe,[string]$ProbeMode,[string[]]$ProbePaths,[switch]$DisposeBeforeChild,[switch]$CloseTwice,[switch]$TestDeny,[int]$MaximumItems=4096)
Import-Module $Module
$lease=Open-ProfileExecutionLease -RunnerRoot $RunnerRoot -TargetRoot $TargetRoot -ControlFiles @($Control) -ClosureRoots @($Closure) -MaximumItems $MaximumItems
if($Probe){
  try{$during=& $Probe -Module $Module -Lease $lease -Mode $ProbeMode -Paths $ProbePaths}finally{Close-ProfileExecutionLease -Lease $lease}
  $after=& $Probe -Module $Module -Lease $lease -Mode $ProbeMode -Paths $ProbePaths
  return [pscustomobject]@{During=$during;After=$after}
}
try {
  if($CloseTwice){Close-ProfileExecutionLease -Lease $lease;Close-ProfileExecutionLease -Lease $lease;return $lease}
  if($Rogue){return (& $Rogue -Module $Module -Lease $lease)}
  if($TestDeny){$writeDenied=try{[IO.File]::Open($Control,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::None).Dispose();$false}catch{$true};$deleteDenied=try{Remove-Item -LiteralPath $Control -Force -ErrorAction Stop;$false}catch{$true};$renameDenied=try{Rename-Item -LiteralPath $Control -NewName 'renamed.ps1' -ErrorAction Stop;$false}catch{$true};return [pscustomobject]@{WriteDenied=$writeDenied;DeleteDenied=$deleteDenied;RenameDenied=$renameDenied}}
  if($DisposeBeforeChild){Close-ProfileExecutionLease -Lease $lease}
  & $Child -Module $Module -RunnerRoot $RunnerRoot -TargetRoot $ChildTargetRoot -Control $ChildControl -Closure $ChildClosure
  if(-not $DisposeBeforeChild){Get-ProfileExecutionLeaseInfo -Lease $lease}
} finally { Close-ProfileExecutionLease -Lease $lease }
'@)
  return [pscustomobject]@{ Parent = $parent; Child = $child; Rogue = $rogue; Probe = $probe }
}
