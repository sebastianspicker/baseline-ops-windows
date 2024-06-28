#requires -version 5.1

<#
.SYNOPSIS
  Meta-test: verifies that every script declaring SupportsShouldProcess wraps
  all Set-Reg* and Remove-Reg* calls inside a ShouldProcess guard.

.DESCRIPTION
  Reads the raw text of each script that declares SupportsShouldProcess=$true
  AND contains at least one Set-Reg* or Remove-Reg* call, then scans for
  unguarded registry-write calls. Scripts that declare ShouldProcess but do
  not directly invoke registry-write functions are skipped.

  The detection is heuristic (text-based), not AST-based, but catches the
  common pattern where a registry-write call sits outside any ShouldProcess
  guard within the same remediation block.
#>

BeforeDiscovery {
  $scriptsDir = Join-Path $PSScriptRoot '../../scripts'
  $scriptFiles = Get-ChildItem -LiteralPath $scriptsDir -Filter '*.ps1' -File |
    Where-Object { $_.Name -match '^\d{2}-' }

  # Registry-modifying function patterns to look for
  $regWritePatternDisc = '(Set-RegDword|Set-RegString|Set-RegQword|Set-RegExpandString|Set-RegMultiString|Set-RegBinary|Remove-RegValueIfExists|Remove-RegistryKeyIfExists)\s'

  # Filter to scripts that BOTH declare SupportsShouldProcess AND contain
  # registry-write calls. Scripts that only declare ShouldProcess for
  # non-registry operations (e.g., file copies, profile orchestration) are
  # excluded because this meta-test is specifically about registry guards.
  $script:shouldProcessScripts = @()
  foreach ($file in $scriptFiles) {
    $content = Get-Content -LiteralPath $file.FullName -Raw
    if ($content -match 'SupportsShouldProcess\s*=\s*\$true' -and $content -match $regWritePatternDisc) {
      $script:shouldProcessScripts += [pscustomobject]@{ Name = $file.Name; FullName = $file.FullName; Content = $content }
    }
  }
}

Describe 'ShouldProcess guards for registry-write calls' {

  # Registry-modifying function patterns to look for
  BeforeAll {
    $script:regWritePattern = '(Set-RegDword|Set-RegString|Set-RegQword|Set-RegExpandString|Set-RegMultiString|Set-RegBinary|Remove-RegValueIfExists|Remove-RegistryKeyIfExists)\s'
  }

  It '<_.Name> wraps all registry-write calls in ShouldProcess guards' -ForEach $shouldProcessScripts {
    $file = $_
    $lines = $file.Content -split "`n"
    $unguarded = @()

    for ($i = 0; $i -lt $lines.Count; $i++) {
      $line = $lines[$i]

      # Skip comment lines
      if ($line -match '^\s*#') { continue }

      # Check if this line contains a registry-write call
      if ($line -match $script:regWritePattern) {
        # Look backwards from this line to find the nearest enclosing
        # ShouldProcess guard. We check a window of preceding lines
        # for an open if-ShouldProcess block (brace counting).
        $foundGuard = $false
        $braceDepth = 0

        for ($j = $i; $j -ge 0 -and $j -ge ($i - 30); $j--) {
          $checkLine = $lines[$j]

          # Count closing braces (going backwards, these are "openings")
          $braceDepth += ([regex]::Matches($checkLine, '\}')).Count
          $braceDepth -= ([regex]::Matches($checkLine, '\{')).Count

          if ($checkLine -match 'ShouldProcess') {
            # The ShouldProcess guard should be at the same or enclosing scope
            if ($braceDepth -le 0) {
              $foundGuard = $true
              break
            }
          }
        }

        if (-not $foundGuard) {
          $lineNum = $i + 1
          $trimmed = $line.Trim()
          $unguarded += "Line ${lineNum}: $trimmed"
        }
      }
    }

    $unguarded | Should -BeNullOrEmpty -Because "All Set-Reg*/Remove-Reg* calls must be wrapped in `$PSCmdlet.ShouldProcess() guards"
  }
}
