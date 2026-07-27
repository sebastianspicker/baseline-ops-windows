# Defines the repository-wide analyzer policy. Exclusions below preserve stable
# operational command names while retaining error- and warning-level checks.
@{
  Severity = @('Error','Warning')
  ExcludeRules = @(
    # Repo intentionally favors descriptive helper names over approved verbs.
    # Non-standard verb mappings: Ensure-* -> Assert-*/Initialize-*, Has-Property -> Test-HasProperty,
    # Sanitize-Path -> ConvertTo-SafePath, Schedule-AutoRollback -> Register-AutoRollback.
    # These are kept for API stability and readability in operational scripts.
    'PSUseApprovedVerbs',
    # Repo uses plural helper names for collections.
    'PSUseSingularNouns',
    # Keep helpers lightweight; not all state-changing helpers expose ShouldProcess.
    'PSUseShouldProcessForStateChangingFunctions',
    'PSShouldProcess',
    # Encoding is managed by repo conventions; avoid noisy BOM warnings.
    'PSUseBOMForUnicodeEncodedFile'
  )
}
