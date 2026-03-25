#requires -version 5.1

Describe 'v2 parameter contract' {
  $scriptFiles = Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '../../scripts') -Filter '*.ps1' -File |
    Where-Object { $_.Name -match '^\d{2}-' }
  $cases = @($scriptFiles | ForEach-Object { [pscustomobject]@{ Name = $_.Name; FullName = $_.FullName } })

  $requiredParams = @(
    'Mode',
    'ConfigPath',
    'OutputFormat',
    'OutputPath',
    'PassThru',
    'Strict',
    'Quiet',
    'NoColor'
  )

  It '<_.Name> exposes required v2 params' -ForEach $cases {
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    $ast.ParamBlock | Should -Not -BeNullOrEmpty

    $paramNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    foreach ($required in $requiredParams) {
      ($paramNames -contains $required) | Should -BeTrue
    }
  }

  It '<_.Name> does not expose legacy Remediate parameter' -ForEach $cases {
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    $paramNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    ($paramNames -contains 'Remediate') | Should -BeFalse
  }

  It '<_.Name> does not use legacy AuditOnly mode value' -ForEach $cases {
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    $modeParameter = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Mode' } | Select-Object -First 1
    $modeValidateSet = $modeParameter.Attributes |
      Where-Object { $_.TypeName.FullName -eq 'ValidateSet' } |
      Select-Object -First 1
    ($null -eq $modeValidateSet -or (@($modeValidateSet.PositionalArguments.Value) -notcontains 'AuditOnly')) | Should -BeTrue
  }

  It '<_.Name> enforces ShouldProcess when Mode supports Remediate' -ForEach $cases {
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    $paramNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    if (-not ($paramNames -contains 'Mode')) {
      Set-ItResult -Skipped -Because 'Script has no Mode parameter.'
      return
    }

    $modeParameter = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Mode' } | Select-Object -First 1
    $modeValidateSet = $modeParameter.Attributes |
      Where-Object { $_.TypeName.FullName -eq 'ValidateSet' } |
      Select-Object -First 1

    $supportsRemediate = $false
    if ($modeValidateSet) {
      $supportsRemediate = @($modeValidateSet.PositionalArguments.Value) -contains 'Remediate'
    }

    if (-not $supportsRemediate) {
      Set-ItResult -Skipped -Because 'Mode does not support Remediate.'
      return
    }

    $content = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
    ($content -match 'SupportsShouldProcess\s*=\s*\$true') | Should -BeTrue
  }
}
