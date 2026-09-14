#requires -version 5.1
<#
.SYNOPSIS
Loads Sysmon updater dependencies.
.DESCRIPTION
Imports shared services and dot-sources the updater's cohesive private helper files into the public script scope.
#>
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Evidence.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
. (Join-Path $PSScriptRoot '16-Sysmon-Config-Updater.helpers.ps1')
. (Join-Path $PSScriptRoot '16-Sysmon-Config-Updater.manifest.ps1')
. (Join-Path $PSScriptRoot '16-Sysmon-Config-Updater.trust.ps1')
. (Join-Path $PSScriptRoot '16-Sysmon-Config-Updater.presentation.ps1')
. (Join-Path $PSScriptRoot '16-Sysmon-Config-Updater.runtime.ps1')
