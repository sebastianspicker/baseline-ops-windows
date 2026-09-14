#requires -version 5.1
<#
.SYNOPSIS
  Provides private hardware compliance audit phases.
.DESCRIPTION
  Keeps hardware observations, policy decisions, proof output, and failure classification local to the hardware capability.
#>

. (Join-Path $PSScriptRoot '15-HardwareTPM-Audit.catalog.ps1')
. (Join-Path $PSScriptRoot '15-HardwareTPM-Audit.observations.ps1')
. (Join-Path $PSScriptRoot '15-HardwareTPM-Audit.presentation.ps1')
. (Join-Path $PSScriptRoot '15-HardwareTPM-Audit.runtime.ps1')
