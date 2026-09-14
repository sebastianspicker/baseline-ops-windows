#requires -version 5.1
<#
.SYNOPSIS
Loads Run-Local dependencies.
.DESCRIPTION
Imports shared validation, output, execution, and serialization services and loads the runner's private implementation.
#>
. (Join-Path $PSScriptRoot '../_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Execution.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force
. (Join-Path $PSScriptRoot '00-Run-Local.helpers.ps1')
. (Join-Path $PSScriptRoot '00-Run-Local.runtime.ps1')
