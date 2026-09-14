<#
.SYNOPSIS
  Verifies bounded runtime optimization behavior.
.DESCRIPTION
  Checks output equivalence and resource limits with controlled fixtures.
#>
#requires -version 5.1
BeforeAll {
  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path; $path = Join-Path $repoRoot 'scripts/internal/19-Software-Audit.helpers.ps1'
  $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors);$names=@('Get-SoftwareRegistryString','Get-SoftwareRegistryInt','ConvertTo-SoftwareInventoryItem','Get-InstalledSoftware','Test-SoftwareRuleMatch','Test-SoftwareCompliance','Get-SoftwareCatalogRuleArray','Get-CatalogWrapper','Get-AuditStatus','Get-SummaryLines','Get-SoftwareCatalogFindings','New-SoftwareAuditResult','Invoke-SoftwareAudit','Write-SoftwareAuditFailure','New-SoftwareAuditCompletion')
  $text=(($ast.FindAll({param($node)$node-is[Management.Automation.Language.FunctionDefinitionAst]-and$node.Name-in$names},$true)|ForEach-Object{$_.Extent.Text})-join"`n")+@'
$script:Rows=@{};$script:Values=@{};$script:EventSourceName='Software-Audit'
function Ensure-EventSource { return $true }
function Load-Catalog { return (Get-CatalogWrapper -Source 'fixture' -Loaded $true -CatalogObject ([pscustomobject]@{})) }
function Write-HealthEvent { }
function Write-ConsoleBanner { }
function Write-UiLine { }
function Set-TestRows { param($Rows) $script:Rows=$Rows;$script:Values=@{};foreach($map in $Rows.Values){foreach($key in $map.Keys){$script:Values[$key]=$map[$key]}} }
function Get-ChildItem { param([string]$Path,[System.Management.Automation.ActionPreference]$ErrorAction) @($script:Rows[$Path].Keys|Sort-Object|ForEach-Object{[pscustomobject]@{PSPath=$_;PSChildName=(Split-Path $_ -Leaf)}}) }
function Get-ItemProperty { param([string]$Path,[System.Management.Automation.ActionPreference]$ErrorAction) $script:Values[$Path] }
Export-ModuleMember -Function Set-TestRows,Get-InstalledSoftware,Test-SoftwareCompliance,Get-CatalogWrapper,New-SoftwareAuditResult,Invoke-SoftwareAudit
'@
  $module=New-Module -Name SoftwareOptimizationTests -ScriptBlock([scriptblock]::Create($text));Import-Module $module -Force
}

Describe 'Software inventory collection optimization' {
  BeforeAll {
function Test-SoftwareOptimizationPreservesRegistryFilteringFirstHiveDeduplicationAndFinalSortOrder {
    $paths=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall');$rows=@{}
    foreach($path in $paths){$rows[$path]=[ordered]@{}}
    $rows[$paths[0]]['first']=[pscustomobject]@{DisplayName='Zulu';DisplayVersion='1';Publisher='Vendor';SystemComponent=0;ParentKeyName='';ReleaseType=''}
    $rows[$paths[1]]['duplicate']=[pscustomobject]@{DisplayName='Zulu';DisplayVersion='1';Publisher='Vendor';SystemComponent=0;ParentKeyName='';ReleaseType=''}
    $rows[$paths[2]]['alpha']=[pscustomobject]@{DisplayName='Alpha';DisplayVersion='2';Publisher='Vendor';SystemComponent=0;ParentKeyName='';ReleaseType=''}
    $rows[$paths[0]]['system']=[pscustomobject]@{DisplayName='System';SystemComponent=1};$rows[$paths[0]]['parent']=[pscustomobject]@{DisplayName='Parent';ParentKeyName='x'};$rows[$paths[0]]['update']=[pscustomobject]@{DisplayName='Patch';ReleaseType='Security Update'};$rows[$paths[0]]['blank']=[pscustomobject]@{DisplayName=' '}
    Set-TestRows -Rows $rows; $inventory=@(Get-InstalledSoftware)
    @($inventory.Name) | Should -Be @('Alpha','Zulu'); $inventory[1].HivePath | Should -Be $paths[0]
  }

function Test-SoftwareOptimizationPreservesBlacklistPrecedenceAndInventoryOrderWithinClassifications {
    $inventory=@([pscustomobject]@{Name='Both';Publisher='Vendor'},[pscustomobject]@{Name='Allowed';Publisher='Vendor'},[pscustomobject]@{Name='Unknown';Publisher='Other'})
    $catalog=[pscustomobject]@{Whitelist=@([pscustomobject]@{NameRegex='Both|Allowed';VendorRegex=''});Blacklist=@([pscustomobject]@{NameRegex='Both';VendorRegex=''})}
    $audit=Test-SoftwareCompliance -Inventory $inventory -Catalog $catalog
    @($audit.Blacklisted.Name) | Should -Be @('Both'); @($audit.Whitelisted.Name) | Should -Be @('Allowed'); @($audit.Unknown.Name) | Should -Be @('Unknown')
  }
  }

  It 'preserves registry filtering, first-hive deduplication, and final sort order' { Test-SoftwareOptimizationPreservesRegistryFilteringFirstHiveDeduplicationAndFinalSortOrder }

  It 'preserves blacklist precedence and inventory order within classifications' { Test-SoftwareOptimizationPreservesBlacklistPrecedenceAndInventoryOrderWithinClassifications }
}

Describe 'Software catalog empty rule compatibility' {
  BeforeAll {
function Test-SoftwareOptimizationKeepsFalseyPropertyEntriesOutOfClassificationForLabel {
    $source = [pscustomobject]@{ Whitelist = @(); Blacklist = @() }
    $source.$Property = $Value
    $catalog = Get-CatalogWrapper -Source 'fixture' -Loaded $true -CatalogObject $source
    $inventory = @([pscustomobject]@{ Name = 'Unlisted'; Publisher = 'Vendor' })
    $audit = Test-SoftwareCompliance -Inventory $inventory -Catalog $catalog
    @($audit.Whitelisted) | Should -HaveCount 0
    @($audit.Blacklisted) | Should -HaveCount 0
    @($audit.Unknown.Name) | Should -Be @('Unlisted')
  }
  }

  It 'keeps falsey <Property> entries out of classification for <Label>' -ForEach @(
    @{ Property = 'Whitelist'; Value = $false; Label = 'false' }
    @{ Property = 'Whitelist'; Value = ''; Label = 'empty string' }
    @{ Property = 'Whitelist'; Value = 0; Label = 'zero' }
    @{ Property = 'Blacklist'; Value = $false; Label = 'false' }
    @{ Property = 'Blacklist'; Value = ''; Label = 'empty string' }
    @{ Property = 'Blacklist'; Value = 0; Label = 'zero' }
  ) { Test-SoftwareOptimizationKeepsFalseyPropertyEntriesOutOfClassificationForLabel }
}

Describe 'Software result finding shape' {
  BeforeAll {
function Test-SoftwareOptimizationKeepsACleanEmptyInventoryResultFreeOfFindings {
    $catalog = Get-CatalogWrapper -Source 'fixture' -Loaded $true -CatalogObject ([pscustomobject]@{})
    $audit = Test-SoftwareCompliance -Inventory @() -Catalog $catalog
    $result = New-SoftwareAuditResult -Inventory @() -Audit $audit -Catalog $catalog -EventSourceReady $true
    $result.Total | Should -Be 0
    $result.Status.EventId | Should -Be 4900
    @($result.Findings) | Should -HaveCount 0
  }

function Test-SoftwareOptimizationKeepsConfigurationFindingsFlatAndOrdered {
    $issues = @(
      [pscustomobject]@{ Kind = 'First'; Status = 'Missing'; Path = 'a'; Error = '' }
      [pscustomobject]@{ Kind = 'Second'; Status = 'Invalid'; Path = 'b'; Error = '' }
    )
    $catalog = Get-CatalogWrapper -Source 'fixture' -Loaded $true -CatalogObject ([pscustomobject]@{}) -Issues $issues
    $audit = Test-SoftwareCompliance -Inventory @() -Catalog $catalog
    $result = New-SoftwareAuditResult -Inventory @() -Audit $audit -Catalog $catalog -EventSourceReady $true
    @($result.Findings) | Should -HaveCount 2
    $result.Findings[0].Kind | Should -Be 'First'
    $result.Findings[1].Kind | Should -Be 'Second'
  }
  }

  It 'keeps a clean empty inventory result free of findings' { Test-SoftwareOptimizationKeepsACleanEmptyInventoryResultFreeOfFindings }

  It 'keeps configuration findings flat and ordered' { Test-SoftwareOptimizationKeepsConfigurationFindingsFlatAndOrdered }
}

Describe 'Software empty endpoint compatibility' {
  It 'retains the terminal failure for a registry inventory with no records' {
    $rows = @{}
    foreach ($path in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')) { $rows[$path] = @{} }
    Set-TestRows -Rows $rows
    $completion = Invoke-SoftwareAudit -CatalogPathProvided $false -ConfigPathProvided $false
    $completion.ResultToken | Should -Be 'FAIL'
    $completion.Findings[0].Code | Should -Be 'SW-AuditFailed'
  }
}
