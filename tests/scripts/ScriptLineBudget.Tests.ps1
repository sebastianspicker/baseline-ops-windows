#requires -version 5.1

Describe 'numbered script line budget' {
  It 'keeps every numbered script below 800 lines' {
    $scriptsDir = Join-Path $PSScriptRoot '../../scripts'
    $budget = 800

    $oversized = Get-ChildItem -LiteralPath $scriptsDir -Filter '*.ps1' -File |
      Where-Object { $_.Name -match '^\d{2}-' } |
      ForEach-Object {
        $lineCount = (Get-Content -LiteralPath $_.FullName).Count
        if ($lineCount -ge $budget) {
          [pscustomobject]@{
            Name = $_.Name
            Lines = $lineCount
          }
        }
      } |
      Where-Object { $null -ne $_ }

    if ($oversized.Count -gt 0) {
      $details = @($oversized | ForEach-Object { "$($_.Name): $($_.Lines)" }) -join ', '
      throw "Line budget exceeded (>= $budget): $details"
    }
  }
}
