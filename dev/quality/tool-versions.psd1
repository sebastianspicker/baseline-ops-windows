# Single manifest of locked versions for the PowerShell runtime, test runner,
# and repository-local code-quality analyzers. Workflows repeat these values
# literally; tests/dev/ToolVersions.Tests.ps1 keeps them equal.
@{
  SchemaVersion = 1
  PowerShell = '7.6.3'
  Pester = '5.8.0'
  PSScriptAnalyzer = '1.25.0'
  Lizard = '1.21.2'
  Jscpd = '5.1.2'
}
