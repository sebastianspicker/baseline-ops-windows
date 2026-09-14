<#
.SYNOPSIS
  Verifies bounded runtime optimization behavior.
.DESCRIPTION
  Checks output equivalence and resource limits with controlled fixtures.
#>
#requires -version 5.1
BeforeAll {
  $helperRoot = Join-Path $PSScriptRoot '../../scripts/internal'
  $paths = @(Join-Path $helperRoot '11-IOC-Sweep-Defender.helpers.ps1')
  $paths += Get-ChildItem -LiteralPath $helperRoot -Filter '11-IOC-Sweep-Defender.helpers.runtime-part*.ps1' | Sort-Object Name | ForEach-Object FullName
  $source = (@($paths | ForEach-Object { Get-Content -LiteralPath $_ -Raw }) -join "`n")
  $tokens = $null
  $errors = $null
  $ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
  @($errors) | Should -HaveCount 0
  $names=@('Get-ObjPropValue','Add-IocSourceStatus','New-IocMembershipSet','Get-IocDnsEntryName','New-IocDnsEntryIndex','Get-IocIndexedDomainMatches','Invoke-IocProcessRule');$text=(($ast.FindAll({param($node)$node-is[Management.Automation.Language.FunctionDefinitionAst]-and$node.Name-in$names},$true)|ForEach-Object{$_.Extent.Text})-join"`n")+@'
$script:HashCalls=0;$script:SignatureCalls=0
function Reset-IocTestState { $script:HashCalls=0;$script:SignatureCalls=0;$script:IocRun=[ordered]@{Proof=[ordered]@{SourceStatus=@{};Errors=[Collections.Generic.List[string]]::new();Findings=@{Processes=[Collections.Generic.List[object]]::new()}};Findings=[Collections.Generic.List[object]]::new();FoundAny=$false} }
function Get-ProcessImageSha256 { param([int]$ProcessId) $script:HashCalls++;return "hash-$ProcessId" }
function Get-FilePublisher { param([string]$File) $script:SignatureCalls++;return 'Publisher',$true }
function Add-Finding { param($FindingList,$Code,$Severity,$Message,$Extra) $FindingList.Add([pscustomobject]@{Code=$Code;Message=$Message}) }
function Get-IocTestState { [pscustomobject]@{HashCalls=$script:HashCalls;SignatureCalls=$script:SignatureCalls;Run=$script:IocRun} }
Export-ModuleMember -Function Reset-IocTestState,Get-IocTestState,Add-IocSourceStatus,New-IocMembershipSet,New-IocDnsEntryIndex,Get-IocIndexedDomainMatches,Get-IocDnsEntryName,Invoke-IocProcessRule
'@;$module=New-Module -Name IocOptimizationTests -ScriptBlock([scriptblock]::Create($text));Import-Module $module -Force
}

Describe 'IOC membership and accumulation optimization' {
  BeforeEach { Reset-IocTestState }

  It 'uses case-insensitive IP membership without duplicate-rule findings' {
    $set=New-IocMembershipSet -Values @('10.0.0.1','10.0.0.1','FE80::1');$connections=@('10.0.0.1','other','fe80::1','10.0.0.1')
    @($connections|Where-Object{$set.Contains($_)}) | Should -Be @('10.0.0.1','fe80::1','10.0.0.1');$set.Count | Should -Be 2
  }

  It 'preserves duplicate domain rules and rule-major DNS order' {
    $dns=@([pscustomobject]@{Id=1;Entry='a.test'},[pscustomobject]@{Id=2;Name='A.TEST'},[pscustomobject]@{Id=3;RecordName='b.test'});$index=New-IocDnsEntryIndex -DnsEntries $dns
    $domainMatches=@(Get-IocIndexedDomainMatches -Domains @('A.TEST','b.test','a.test') -DnsEntryIndex $index)
    @($domainMatches.Id) | Should -Be @(1,2,3,1,2)
  }

  It 'appends source errors in observation order' {
    Add-IocSourceStatus -Name 'First' -Attempted $true -Succeeded $false -ErrorMessage 'one';Add-IocSourceStatus -Name 'Second' -Attempted $true -Succeeded $false -ErrorMessage 'two';$state=Get-IocTestState
    @($state.Run.Proof.Errors) | Should -Be @('First source failed: one','Second source failed: two')
  }

  It 'takes fresh process hash and signature observations for every matching rule' {
    $regex=[regex]::new('tool');$rule=[pscustomobject]@{__IocImageRegex=$regex;Signer='';Action=''};$process=[pscustomobject]@{Name='tool';Id=7;Path='C:\tool.exe'}
    Invoke-IocProcessRule -Rule $rule -Process $process;Invoke-IocProcessRule -Rule $rule -Process $process;$state=Get-IocTestState
    $state.HashCalls | Should -Be 2;$state.SignatureCalls | Should -Be 2;@($state.Run.Proof.Findings.Processes).Count | Should -Be 2
  }
}
