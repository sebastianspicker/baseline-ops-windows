#requires -version 5.1
<#
.SYNOPSIS
Cases for the 00-Run-Batch.ps1 category mapping and generated profile tests.
.DESCRIPTION
Holds the AST extraction helpers and Test-* behavior functions invoked by
RunBatch.Tests.ps1. Extracts the batch selection functions from the public script by AST so no
capability or orchestration path executes. Pins the category to script-number
table against the categories documented in scripts/README.md and verifies the
generated temporary profile document is v2 and validates.
#>

# Returns source text of the named function definitions, without running the script.
function Get-FunctionDefinitionSource {
  param([string]$Path, [string[]]$Name)
  $tokens = $null; $errors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
  $errors | Should -HaveCount 0
  $definitions = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Name -contains $node.Name }, $true)
  $definitions.Count | Should -Be $Name.Count
  return ($definitions | ForEach-Object { $_.Extent.Text }) -join "`n"
}

# Expands a README cell such as '01-07, 09, 31-33' into two-digit prefixes.
function Expand-ReadmeScriptNumbers {
  param([string]$Cell)
  foreach ($part in ($Cell -split ',')) {
    $token = $part.Trim()
    if ($token -match '^(\d+)-(\d+)$') { [int]$Matches[1]..[int]$Matches[2] | ForEach-Object { '{0:D2}' -f $_ } }
    elseif ($token -match '^\d+$') { '{0:D2}' -f [int]$token }
  }
}

# Returns the category to script-number table documented in scripts/README.md.
function Get-BatchDocumentedCategories {
  param([string]$Root)
  $documented = @{}
  foreach ($line in (Get-Content -LiteralPath (Join-Path $Root 'scripts/README.md'))) {
    if ($line -match '^\| `(Audit|Remediation|Collection|Utility|Monitoring)` \| ([\d, -]+) \|$') {
      $documented[$Matches[1]] = @(Expand-ReadmeScriptNumbers -Cell $Matches[2])
    }
  }
  return $documented
}

function Test-BatchCategoryMapDefinesDocumentedCategories {
  @((Get-BatchCategoryMap).Keys | Sort-Object) | Should -Be @('Audit', 'Collection', 'Monitoring', 'Remediation', 'Utility')
}

function Test-BatchReadmeDocumentsSameFiveCategories {
  @($script:documented.Keys | Sort-Object) | Should -Be @('Audit', 'Collection', 'Monitoring', 'Remediation', 'Utility')
}

function Test-BatchCategoryMapMatchesReadme {
  param([string]$Category)
  @((Get-BatchCategoryMap)[$Category]) | Should -Be $script:documented[$Category]
}

function Test-BatchCategoryMapTableSizes {
  $map = Get-BatchCategoryMap
  $map.Audit.Count | Should -Be 46
  $map.Remediation.Count | Should -Be 22
  $map.Collection.Count | Should -Be 5
  $map.Utility.Count | Should -Be 2
  $map.Monitoring.Count | Should -Be 4
}

function Test-BatchCategoryMapReferencesShippedScripts {
  $numbers = @($script:available | ForEach-Object { $_.Substring(0, 2) })
  foreach ($category in (Get-BatchCategoryMap).Keys) {
    foreach ($prefix in (Get-BatchCategoryMap)[$category]) { $numbers | Should -Contain $prefix }
  }
}

function Test-BatchAvailableScriptsListsNumberedWorkloads {
  $script:available | Should -HaveCount 52
  @($script:available | Where-Object { $_ -match '^00-' }) | Should -HaveCount 0
}

function Test-BatchSelectionForAllIsSorted {
  $selected = @(Get-BatchSelectedScripts -Category 'All' -ScriptNames $script:available)
  $selected | Should -HaveCount 52
  $selected | Should -Be @($script:available | Sort-Object)
}

function Test-BatchSelectionMatchesCategoryMap {
  param([string]$Category, [int]$Count)
  $selected = @(Get-BatchSelectedScripts -Category $Category -ScriptNames $script:available)
  $selected | Should -HaveCount $Count
  $expected = @($script:available | Where-Object { (Get-BatchCategoryMap)[$Category] -contains $_.Substring(0, 2) } | Sort-Object)
  $selected | Should -Be $expected
}

function Test-BatchSelectionForUtility {
  $selected = @(Get-BatchSelectedScripts -Category 'Utility' -ScriptNames $script:available)
  @($selected | ForEach-Object { $_.Substring(0, 2) }) | Should -Be @('08', '25')
}

function Test-BatchProfileDocumentIsV2 {
  $selected = @(Get-BatchSelectedScripts -Category 'Utility' -ScriptNames $script:available)
  $doc = New-BatchProfileDocument -Category 'Utility' -Mode 'Audit' -Strict $true -RequireSigned $true -ContinueOnError $false -SelectedScripts $selected
  $doc.ProfileName | Should -Be 'batch-utility'
  $doc.Version | Should -Be '2.0'
  $doc.Defaults.Mode | Should -Be 'Audit'
  $doc.Defaults.Strict | Should -BeTrue
  $doc.Defaults.OutputFormat | Should -Be 'Console'
  $doc.Defaults.OutputPath | Should -BeNullOrEmpty
  $doc.Integrity.RequireSigned | Should -BeTrue
  @($doc.Integrity.ExpectedHashes.Keys) | Should -HaveCount 0
  @($doc.Steps) | Should -HaveCount 2
  @($doc.Steps.Script) | Should -Be $selected
  foreach ($step in $doc.Steps) {
    @($step.Args) | Should -HaveCount 0
    @($step.DependsOn) | Should -HaveCount 0
    $step.ContinueOnError | Should -BeFalse
  }
}

function Test-BatchProfileDocumentPropagatesContinueOnError {
  $doc = New-BatchProfileDocument -Category 'Collection' -Mode 'Audit' -Strict $false -RequireSigned $false -ContinueOnError $true -SelectedScripts @('09-Support-Bundle.ps1')
  $doc.Steps[0].ContinueOnError | Should -BeTrue
}

function Test-BatchProfileDocumentValidates {
  param([string]$Category)
  $selected = @(Get-BatchSelectedScripts -Category $Category -ScriptNames $script:available)
  $doc = New-BatchProfileDocument -Category $Category -Mode 'Audit' -Strict $false -RequireSigned $false -ContinueOnError $true -SelectedScripts $selected
  $r = Invoke-ProfileValidation -Directory $TestDrive -Document $doc
  $r.ExitCode | Should -Be 0
  $r.Codes | Should -HaveCount 0
}
