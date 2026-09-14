#requires -version 5.1
<#
.SYNOPSIS
Loads Run-Profile dependencies.
.DESCRIPTION
Imports shared services and loads the profile runner's private runtime after the public entry point acquires its execution lease.
#>
. $bootstrap.BootstrapPath
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force
. $bootstrap.HelperPath
. $bootstrap.RuntimePath
. $bootstrap.SchedulerPath
. $bootstrap.PresentationPath
