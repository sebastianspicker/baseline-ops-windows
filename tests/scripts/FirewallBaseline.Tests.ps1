#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

Describe '18-Firewall-Baseline helper boundary' -Tag 'FirewallBaseline' {
  BeforeAll {
    $path = Join-Path $PSScriptRoot '../../scripts/18-Firewall-Baseline.ps1'
    $helperPath = Join-Path $PSScriptRoot '../../scripts/internal/18-Firewall-Baseline.helpers.ps1'
    $source = (Get-Content -LiteralPath $path -Raw) -replace "`r`n", "`n"
    $helperSource = (Get-Content -LiteralPath $helperPath -Raw) -replace "`r`n", "`n"
    $start = $source.IndexOf('function Ensure-Profile')
    $end = $source.IndexOf("# -------------------------`n# Main")
    $testSource = $helperSource + "`n" + $source.Substring($start, $end - $start)
    $script:FirewallBaselineModule = New-Module -Name FirewallBaselineTest -ScriptBlock ([scriptblock]::Create($testSource))
    Import-Module $script:FirewallBaselineModule -Force
    $script:CreatedRules = 0
    $script:ExistingFirewallRule = $null
    $script:UpdatedRules = 0
    function global:Get-NetFirewallRule { if ($script:ExistingFirewallRule) { $script:ExistingFirewallRule } else { @() } }
    function global:New-NetFirewallRule { $script:CreatedRules++; [pscustomobject]@{} }
    function global:Get-NetFirewallPortFilter { [pscustomobject]@{ Protocol = 'UDP'; LocalPort = 53; RemotePort = 'Any' } }
    function global:Set-NetFirewallRule { $script:UpdatedRules++; [pscustomobject]@{} }
    function global:Set-NetFirewallPortFilter { $script:UpdatedRules++; [pscustomobject]@{} }
  }

  AfterAll {
    Remove-Module $script:FirewallBaselineModule -Force -ErrorAction SilentlyContinue
    Remove-Item Function:\Get-NetFirewallRule -ErrorAction SilentlyContinue
    Remove-Item Function:\New-NetFirewallRule -ErrorAction SilentlyContinue
    Remove-Item Function:\Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    Remove-Item Function:\Set-NetFirewallRule -ErrorAction SilentlyContinue
    Remove-Item Function:\Set-NetFirewallPortFilter -ErrorAction SilentlyContinue
  }

  It 'dot-sources the parseable configuration helper from the main script' {
    $mainPath = Join-Path $PSScriptRoot '../../scripts/18-Firewall-Baseline.ps1'
    $helperPath = Join-Path $PSScriptRoot '../../scripts/internal/18-Firewall-Baseline.helpers.ps1'
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($helperPath, [ref]$tokens, [ref]$errors)

    $errors | Should -BeNullOrEmpty
    (Get-Content -LiteralPath $mainPath -Raw -Encoding UTF8) |
      Should -Match ([regex]::Escape('18-Firewall-Baseline.helpers.ps1'))
  }

  It 'normalizes catalog values without loading firewall cmdlets' {
    $result = & $script:FirewallBaselineModule {
      [pscustomobject]@{
        Profiles = @(Normalize-ProfileValue -ProfileValue 'Public, Domain, Public')
        Enabled  = Normalize-EnabledValue -Value 'Enabled'
        Disabled = Normalize-EnabledValue -Value 0
        Missing  = Get-ObjProp -Object @{ Present = 'value' } -Name 'Missing' -Default 'fallback'
      }
    }

    @($result.Profiles) | Should -Be @('Domain','Public')
    $result.Enabled | Should -BeExactly 'True'
    $result.Disabled | Should -BeExactly 'False'
    $result.Missing | Should -BeExactly 'fallback'
  }

  It 'fills omitted catalog sections from explicit defaults' {
    $defaults = [pscustomobject]@{
      Profiles = [pscustomobject]@{
        Domain  = [pscustomobject]@{ Enabled = $true }
        Private = [pscustomobject]@{ Enabled = $true }
        Public  = [pscustomobject]@{ Enabled = $true }
      }
    }
    $catalog = [pscustomobject]@{
      Profiles = [pscustomobject]@{
        Domain = [pscustomobject]@{ Enabled = $false }
      }
    }

    $result = & $script:FirewallBaselineModule {
      param($Catalog, $Defaults)
      Ensure-CatalogDefaults -Catalog $Catalog -DefaultCatalog $Defaults
    } $catalog $defaults

    $result.Profiles.Domain.Enabled | Should -BeFalse
    $result.Profiles.Private.Enabled | Should -BeTrue
    $result.Profiles.Public.Enabled | Should -BeTrue
    @($result.DisableInboundByNameLike).Count | Should -Be 0
    @($result.EnsureRules).Count | Should -Be 0
  }

  It 'reports a missing rule in Audit mode without creating it' {
    $script:CreatedRules = 0
    $result = & $script:FirewallBaselineModule {
      $script:Remediate = $false
      Ensure-FwRule -Spec ([pscustomobject]@{ Name = 'baseline-test'; Direction = 'Inbound'; Action = 'Block'; Protocol = 'TCP'; Enabled = $true }) -LocalPolicyStore PersistentStore
    }

    @($result | Where-Object Status -eq 'Drift').Count | Should -Be 1
    $script:CreatedRules | Should -Be 0
  }

  It 'creates a missing rule only in Remediate mode' {
    $script:CreatedRules = 0
    $result = & $script:FirewallBaselineModule {
      $script:Remediate = $true
      Ensure-FwRule -Spec ([pscustomobject]@{ Name = 'baseline-test'; Direction = 'Inbound'; Action = 'Block'; Protocol = 'TCP'; Enabled = $true }) -LocalPolicyStore PersistentStore
    }

    @($result | Where-Object Status -eq 'Changed').Count | Should -Be 1
    $script:CreatedRules | Should -Be 1
  }

  It 'honors WhatIf for a missing rule in Remediate mode' {
    $script:CreatedRules = 0
    $result = & $script:FirewallBaselineModule {
      $script:Remediate = $true
      Ensure-FwRule -Spec ([pscustomobject]@{ Name = 'baseline-test'; Direction = 'Inbound'; Action = 'Block'; Protocol = 'TCP'; Enabled = $true }) -LocalPolicyStore PersistentStore -WhatIf
    }

    @($result | Where-Object Status -eq 'Note').Count | Should -Be 1
    $script:CreatedRules | Should -Be 0
  }

  It 'plans drift in Audit mode and applies it only in Remediate mode' {
    $script:ExistingFirewallRule = [pscustomobject]@{ Name = 'baseline-existing'; DisplayName = 'baseline-existing'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'False'; Group = ''; Profile = @('Domain') }
    $script:UpdatedRules = 0
    $spec = [pscustomobject]@{ Name = 'baseline-existing'; Direction = 'Inbound'; Action = 'Block'; Protocol = 'TCP'; LocalPort = 443; Enabled = $true }
    $audit = & $script:FirewallBaselineModule { param($RuleSpec) $script:Remediate = $false; Ensure-FwRule -Spec $RuleSpec -LocalPolicyStore PersistentStore } $spec
    @($audit | Where-Object Status -eq 'Drift').Count | Should -Be 1
    $script:UpdatedRules | Should -Be 0

    $remediate = & $script:FirewallBaselineModule { param($RuleSpec) $script:Remediate = $true; Ensure-FwRule -Spec $RuleSpec -LocalPolicyStore PersistentStore } $spec
    @($remediate | Where-Object Status -eq 'Changed').Count | Should -Be 1
    $script:UpdatedRules | Should -BeGreaterThan 0
    $script:ExistingFirewallRule = $null
  }
}
