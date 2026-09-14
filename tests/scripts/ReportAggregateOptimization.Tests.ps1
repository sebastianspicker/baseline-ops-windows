#requires -version 5.1
<#
.SYNOPSIS
  Verifies aggregation path caching and result selection.
.DESCRIPTION
  Checks duplicate inputs, output exclusion, ambiguous case, malformed results, and directory reuse.
#>
BeforeAll {
  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
  $helperPath = Join-Path $repoRoot 'scripts/internal/00-Report-Aggregate.helpers.ps1'
  $tokens = $null; $errors = $null; $ast = [Management.Automation.Language.Parser]::ParseFile($helperPath,[ref]$tokens,[ref]$errors)
  $names = @('New-ReportAggregateDirectoryNameCache','Get-ReportAggregateDirectoryChildren','Get-CanonicalResultFilePath','Get-ReportAggregateOutputPath','Add-ReportAggregateFile','Get-ReportAggregateInputFiles','Test-ReportAggregateResult','Read-ReportAggregateItems')
  $text = (($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $names },$true) | ForEach-Object { $_.Extent.Text }) -join "`n") + @'
$script:Enumerations = 0;$script:AmbiguousParent=$null
function Set-TestAmbiguousParent { param([string]$Path) $script:AmbiguousParent=$Path }
function Get-ChildItem { param([string]$LiteralPath,[string]$Filter,[switch]$File,[switch]$Force,[System.Management.Automation.ActionPreference]$ErrorAction) $script:Enumerations++; if($LiteralPath-eq$script:AmbiguousParent){return @([pscustomobject]@{Name='Case.json';FullName=(Join-Path $LiteralPath 'Case.json')},[pscustomobject]@{Name='case.json';FullName=(Join-Path $LiteralPath 'case.json')})};$childArguments = @{ LiteralPath=$LiteralPath }; if($Filter){$childArguments.Filter=$Filter};if($File){$childArguments.File=$true};if($Force){$childArguments.Force=$true};Microsoft.PowerShell.Management\Get-ChildItem @childArguments }
function Get-BoundedUtf8FileContent { param([string]$Path,[long]$MaximumBytes) [IO.File]::ReadAllText($Path) }
function Invoke-TestDiscovery { param([string[]]$Paths,[string]$Output) $script:Enumerations=0;$cache=New-ReportAggregateDirectoryNameCache;$canonical=Get-ReportAggregateOutputPath -OutputPath $Output -DirectoryNameCache $cache;$files=@(Get-ReportAggregateInputFiles -InputPath $Paths -OutputCanonicalPath $canonical -DirectoryNameCache $cache);[pscustomobject]@{Files=$files;Enumerations=$script:Enumerations;Parsed=(Read-ReportAggregateItems -Files $files -WarningAction SilentlyContinue)} }
Export-ModuleMember -Function Invoke-TestDiscovery,Get-CanonicalResultFilePath,New-ReportAggregateDirectoryNameCache,Set-TestAmbiguousParent
'@
  $module = New-Module -Name AggregateOptimizationTests -ScriptBlock ([scriptblock]::Create($text)); Import-Module $module -Force
}

Describe 'Report aggregation path and input optimization' {
  BeforeEach { $root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N')); $dir = Join-Path $root 'Results'; New-Item -ItemType Directory -Path $dir -Force | Out-Null }

  It 'deduplicates inputs, excludes the output, and validates malformed files independently' {
    $good = Join-Path $dir 'good.json'; $bad = Join-Path $dir 'bad.json'; $output = Join-Path $dir 'out.json'
    [IO.File]::WriteAllText($good,'{"ScriptName":"good.ps1","Result":"OK","Mode":"Audit"}'); [IO.File]::WriteAllText($bad,'{bad'); [IO.File]::WriteAllText($output,'{"ScriptName":"out.ps1","Result":"OK","Mode":"Audit"}')
    $result = Invoke-TestDiscovery -Paths @($good,$good,$bad,$output) -Output $output
    $result.Files.Count | Should -Be 2; @($result.Parsed.Items).Count | Should -Be 1; @($result.Parsed.Findings).Count | Should -Be 1
  }

  It 'prefers exact case and accepts one unique case-insensitive segment' {
    $exact = Join-Path $dir 'Case.json'; [IO.File]::WriteAllText($exact,'{}'); $cache = New-ReportAggregateDirectoryNameCache
    (Get-CanonicalResultFilePath -Path $exact -DirectoryNameCache $cache) | Should -Be $exact
    (Get-CanonicalResultFilePath -Path (Join-Path $dir 'CASE.json') -DirectoryNameCache $cache) | Should -Be $exact
  }

  It 'rejects an ambiguous case-insensitive segment' {
    Set-TestAmbiguousParent -Path $dir; $cache = New-ReportAggregateDirectoryNameCache
    { Get-CanonicalResultFilePath -Path (Join-Path $dir 'CASE.json') -DirectoryNameCache $cache } | Should -Throw
    Set-TestAmbiguousParent -Path $null
  }

  It 'reuses directory listings across repeated canonicalization' {
    $one = Join-Path $dir 'one.json'; $two = Join-Path $dir 'two.json'; [IO.File]::WriteAllText($one,'{}'); [IO.File]::WriteAllText($two,'{}')
    $result = Invoke-TestDiscovery -Paths @($one,$two,$one) -Output (Join-Path $dir 'new-output.json')
    $result.Files.Count | Should -Be 2; $result.Enumerations | Should -BeLessThan 15
  }
}
