#requires -version 5.1
<#
.SYNOPSIS
  Provides private hardware compliance audit phases.
.DESCRIPTION
  Keeps hardware observations, policy decisions, proof output, and failure classification local to the hardware capability.
#>

function Read-HardwareTpm {
  param($RunState)
  $tpm = $null
  try {
    $tpm = Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftTpm" -ClassName "Win32_Tpm" -ErrorAction Stop
  }
  catch {
    Add-ListItem -List ([ref]$RunState.notes) -Text ("TPM query failed: " + $_.Exception.Message)
  }

  $RunState.proof.Results.TPM = [ordered]@{
    Present = [bool]$tpm
    SpecVersion = $null
    Manufacturer = $null
    IsOwned = $null
    Enabled = $null
    Activated = $null
    Ready = $null
    FirmwareHint = $null
    PCRBanks = $null
  }

  if (-not $tpm) {
    $RunState.ok = $false
    $RunState.fatalComplianceFailure = $true
    Add-ListItem -List ([ref]$RunState.drifts) -Text "TPM not present or not accessible"
  }
  else {
    $RunState.proof.Results.TPM.SpecVersion = [string](Get-CimPropValue -Object $tpm -Name 'SpecVersion')
    $RunState.proof.Results.TPM.Manufacturer = Get-CimPropValue -Object $tpm -Name 'ManufacturerID'
    $RunState.proof.Results.TPM.PCRBanks = Get-CimPropValue -Object $tpm -Name 'PCRBanks'
    $RunState.proof.Results.TPM.FirmwareHint = $(if ($tpm.PSObject.Properties.Name -contains 'IsFirmware') {
        [bool]$tpm.IsFirmware
      }
      else {
        $null
      })

    $RunState.proof.Results.TPM.IsOwned = Invoke-TpmBoolMethod -Tpm $tpm -MethodName "IsOwned"     -ReturnPropertyName "IsOwned"
    $RunState.proof.Results.TPM.Enabled = Invoke-TpmBoolMethod -Tpm $tpm -MethodName "IsEnabled"   -ReturnPropertyName "IsEnabled"
    $RunState.proof.Results.TPM.Activated = Invoke-TpmBoolMethod -Tpm $tpm -MethodName "IsActivated" -ReturnPropertyName "IsActivated"
    $RunState.proof.Results.TPM.Ready = Invoke-TpmBoolMethod -Tpm $tpm -MethodName "IsReady"     -ReturnPropertyName "IsReady"

    Test-HardwareTpmPolicy -RunState $RunState
  }


}

function Test-HardwareTpmPolicy {
  param($RunState)
  Test-HardwareTpmVersion -RunState $RunState

  if ($RunState.cat.TPM.OwnerRequired -and ($RunState.proof.Results.TPM.IsOwned -ne $true)) {
    $RunState.ok = $false
    Add-ListItem -List ([ref]$RunState.drifts) -Text "TPM not owned"
  }

  Test-HardwareTpmReadiness -RunState $RunState
  if (($RunState.cat.TPM.AllowFirmware -eq $false) -and ($RunState.proof.Results.TPM.FirmwareHint -eq $true)) {
    $RunState.ok = $false
    Add-ListItem -List ([ref]$RunState.drifts) -Text "Firmware TPM found; HW TPM required by catalog"
  }

  if ($RunState.cat.TPM.PCRsRequired) {
    Add-ListItem -List ([ref]$RunState.notes) -Text "PCR compliance not implemented: PCRBanks (if available) reports hash banks, not PCR indices."
  }

}

function Test-HardwareTpmReadiness {
  param($RunState)
  if ($RunState.proof.Results.TPM.Enabled -eq $false) {
    $RunState.ok = $false
    Add-ListItem -List ([ref]$RunState.drifts) -Text "TPM not enabled"
  }

  if ($RunState.proof.Results.TPM.Activated -eq $false) {
    $RunState.ok = $false
    Add-ListItem -List ([ref]$RunState.drifts) -Text "TPM not activated"
  }

  if ($RunState.proof.Results.TPM.Ready -eq $false) {
    $RunState.ok = $false
    Add-ListItem -List ([ref]$RunState.drifts) -Text "TPM not ready"
  }


}

function Read-HardwareSecureBoot {
  param($RunState)
  $sb = $false
  try {
    $sb = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
  }
  catch {
    Add-ListItem -List ([ref]$RunState.notes) -Text ("Confirm-SecureBootUEFI failed: " + $_.Exception.Message)
  }
  $RunState.proof.Results.SecureBoot = $sb

  if ($RunState.cat.TPM.SecureBootRequired -and -not $sb) {
    $RunState.ok = $false
    Add-ListItem -List ([ref]$RunState.drifts) -Text "Secure Boot not enabled"
  }


}

function Read-HardwareBitLocker {
  param($RunState)
  $bitOsProtected = $false
  $volsOut = @()
  $osVolDiag = $null

  try {
    $drvs = Get-BitLockerVolume -ErrorAction Stop
    foreach ($d in $drvs) {
      if ($d.VolumeType -eq "OperatingSystem") {
        $bitOsProtected = ($d.ProtectionStatus -eq 1)
        $osVolDiag = [pscustomobject]@{
          MountPoint = $d.MountPoint
          ProtectionStatus = $d.ProtectionStatus
          VolumeStatus = $d.VolumeStatus
          EncryptionPercentage = $d.EncryptionPercentage
          EncryptionMethod = $d.EncryptionMethod
        }
      }

      $volsOut += [pscustomobject]@{
        MountPoint = $d.MountPoint
        VolumeType = $d.VolumeType
        ProtectionStatus = $d.ProtectionStatus
        VolumeStatus = $d.VolumeStatus
        EncryptionPercentage = $d.EncryptionPercentage
        EncryptionMethod = $d.EncryptionMethod
      }
    }
  }
  catch {
    Add-ListItem -List ([ref]$RunState.notes) -Text ("Get-BitLockerVolume failed: " + $_.Exception.Message)
  }

  $RunState.proof.Results.BitLocker = $volsOut
  $RunState.proof.Results.BitLockerOsProtected = $bitOsProtected
  $RunState.proof.Results.BitLockerOsVolume = $osVolDiag

  if ($RunState.cat.TPM.BitLockerRequired -and -not $bitOsProtected) {
    $RunState.ok = $false
    Add-ListItem -List ([ref]$RunState.drifts) -Text "BitLocker not active on OS volume"
    if ($osVolDiag) {
      Add-ListItem -List ([ref]$RunState.notes) -Text ("BitLocker OS diagnostics: VolumeStatus={0}, EncryptionPercentage={1}, ProtectionStatus={2}" -f $osVolDiag.VolumeStatus, $osVolDiag.EncryptionPercentage, $osVolDiag.ProtectionStatus)
    }
  }


}

function Read-HardwareBios {
  param($RunState)
  try {
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    $RunState.proof.Results.BIOS = [ordered]@{
      SerialNumber = $bios.SerialNumber
      SMBIOSBIOSVersion = $bios.SMBIOSBIOSVersion
      Manufacturer = $bios.Manufacturer
      Name = $bios.Name
      ReleaseDate = $bios.ReleaseDate
    }
  }
  catch {
    Add-ListItem -List ([ref]$RunState.notes) -Text ("BIOS query failed: " + $_.Exception.Message)
    $RunState.proof.Results.BIOS = $null
  }


}

function Test-HardwareTpmVersion {
  param($RunState)
  if ($RunState.cat.TPM.MinVersion -and $RunState.proof.Results.TPM.SpecVersion) {
    if (-not (Test-TpmMinVersion -SpecVersion $RunState.proof.Results.TPM.SpecVersion -MinVersion ([string]$RunState.cat.TPM.MinVersion))) {
      $RunState.ok = $false
      Add-ListItem -List ([ref]$RunState.drifts) -Text ("TPM SpecVersion '{0}' does not satisfy MinVersion '{1}'" -f $RunState.proof.Results.TPM.SpecVersion, [string]$RunState.cat.TPM.MinVersion)
    }
  }

}
