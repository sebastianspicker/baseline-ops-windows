#requires -version 5.1
<#
.SYNOPSIS
Characterizes the 00-Run-Batch.ps1 category mapping and generated profile.
.DESCRIPTION
Extracts the batch selection functions from the public script by AST so no
capability or orchestration path executes. Pins the category to script-number
table against the categories documented in scripts/README.md and verifies the
generated temporary profile document is v2 and validates.
#>

BeforeAll {
  $script:root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
  . (Join-Path $PSScriptRoot 'ProfileValidation.Cases.ps1')
  . (Join-Path $PSScriptRoot 'RunBatch.Cases.ps1')

  . ([scriptblock]::Create((Get-FunctionDefinitionSource -Path (Join-Path $script:root 'scripts/00-Run-Batch.ps1') -Name 'Get-BatchCategoryMap', 'Get-BatchSelectedScripts', 'New-BatchProfileDocument')))
  . ([scriptblock]::Create((Get-FunctionDefinitionSource -Path (Join-Path $script:root 'scripts/internal/00-Run-Batch.helpers.ps1') -Name 'Get-BatchAvailableScripts')))

  $script:available = @(Get-BatchAvailableScripts -ScriptsDirectory (Join-Path $script:root 'scripts'))
  $script:documented = Get-BatchDocumentedCategories -Root $script:root
}

Describe 'Get-BatchCategoryMap' {
  It 'defines exactly the documented categories other than All' { Test-BatchCategoryMapDefinesDocumentedCategories }

  It 'README documents the same five categories' { Test-BatchReadmeDocumentsSameFiveCategories }

  It '<Category> maps to the script numbers documented in scripts/README.md' -ForEach @(
    @{ Category = 'Audit' }, @{ Category = 'Remediation' }, @{ Category = 'Collection' }, @{ Category = 'Utility' }, @{ Category = 'Monitoring' }
  ) { Test-BatchCategoryMapMatchesReadme -Category $Category }

  It 'pins the current table sizes' { Test-BatchCategoryMapTableSizes }

  It 'only references numbers that have a shipped script' { Test-BatchCategoryMapReferencesShippedScripts }
}

Describe 'Get-BatchAvailableScripts' {
  It 'lists the 52 numbered workload scripts and excludes 00-* control-plane scripts' { Test-BatchAvailableScriptsListsNumberedWorkloads }
}

Describe 'Get-BatchSelectedScripts' {
  It 'selects every numbered script for All, sorted' { Test-BatchSelectionForAllIsSorted }

  It 'selects <Category> as the sorted scripts whose numbers are in the map' -ForEach @(
    @{ Category = 'Audit'; Count = 46 }, @{ Category = 'Remediation'; Count = 22 }, @{ Category = 'Collection'; Count = 5 }
    @{ Category = 'Utility'; Count = 2 }, @{ Category = 'Monitoring'; Count = 4 }
  ) { Test-BatchSelectionMatchesCategoryMap -Category $Category -Count $Count }

  It 'selects Utility as 08 and 25' { Test-BatchSelectionForUtility }
}

Describe 'New-BatchProfileDocument' {
  It 'builds a v2.0 profile named after the lower-cased category' { Test-BatchProfileDocumentIsV2 }

  It 'propagates ContinueOnError to every step' { Test-BatchProfileDocumentPropagatesContinueOnError }

  It 'produces a document that 00-Validate-Profile.ps1 accepts for <Category>' -ForEach @(
    @{ Category = 'Audit' }, @{ Category = 'Remediation' }, @{ Category = 'Collection' }, @{ Category = 'Utility' }, @{ Category = 'Monitoring' }, @{ Category = 'All' }
  ) { Test-BatchProfileDocumentValidates -Category $Category }
}
