Set-StrictMode -Version Latest

function Test-IsAdmin {
  [CmdletBinding()]
  param()
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

function Test-IsAdministrator {
  [CmdletBinding()]
  param()
  return (Test-IsAdmin)
}

function Ensure-Directory {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return }
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -Path $Path -ItemType Directory -Force | Out-Null
  }
}

function Ensure-DirectoryForFile {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$FilePath)

  $dir = Split-Path -Path $FilePath -Parent
  if ([string]::IsNullOrWhiteSpace($dir)) { return }
  Ensure-Directory -Path $dir
}

function Ensure-Dir {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)
  Ensure-Directory -Path $Path
}

function Read-JsonConfig {
  [CmdletBinding()]
  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  if (-not (Test-Path -LiteralPath $Path)) { return $null }

  try {
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return ($raw | ConvertFrom-Json)
  } catch {
    return $null
  }
}

Export-ModuleMember -Function Test-IsAdmin,Test-IsAdministrator,Ensure-Directory,Ensure-DirectoryForFile,Ensure-Dir,Read-JsonConfig
