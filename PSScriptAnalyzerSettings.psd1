@{
  Severity = @('Error','Warning')
  ExcludeRules = @(
    # Many scripts intentionally use console summaries; exclude this rule repo-wide.
    'PSAvoidUsingWriteHost',
    # Repo intentionally favors descriptive helper names over approved verbs.
    'PSUseApprovedVerbs',
    # Repo uses plural helper names for collections.
    'PSUseSingularNouns',
    # Keep helpers lightweight; not all state-changing helpers expose ShouldProcess.
    'PSUseShouldProcessForStateChangingFunctions',
    'PSShouldProcess',
    # Legacy and operational scripts sometimes use empty catch blocks by design.
    'PSAvoidUsingEmptyCatchBlock',
    # Allow default values on switch params for explicit behavior.
    'PSAvoidDefaultValueSwitchParameter',
    # Encoding is managed by repo conventions; avoid noisy BOM warnings.
    'PSUseBOMForUnicodeEncodedFile',
    # Some scripts use legacy WMI for compatibility fallbacks.
    'PSAvoidUsingWMICmdlet'
  )
}
