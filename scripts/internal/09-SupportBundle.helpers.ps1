<#
.SYNOPSIS
Loads support bundle capability helpers.

.DESCRIPTION
Keeps the private helper entry point stable while loading the cohesive core,
configuration, trust-boundary, and collection implementations.
#>

. (Join-Path $PSScriptRoot '09-SupportBundle.core.ps1')
. (Join-Path $PSScriptRoot '09-SupportBundle.config.ps1')
. (Join-Path $PSScriptRoot '09-SupportBundle.collection.ps1')