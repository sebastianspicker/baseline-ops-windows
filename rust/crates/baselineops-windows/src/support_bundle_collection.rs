//! Fail-closed acquisition seam for capability 09 support-bundle collection.
//!
//! No archive, directory, path, command, or network target is accepted here.
//! A fixed native collector requires independent Windows evidence before it may
//! replace this explicit unavailable result.

use crate::PlatformError;
use baselineops_capabilities::SupportBundleCollectionObservation;

/// Acquires fixed support-bundle evidence when a sealed native collector exists.
///
/// # Errors
///
/// Always returns an unsupported-host error until the fixed collector and its
/// protected output/digest contract have Windows-oracle evidence.
pub fn audit_support_bundle_collection() -> Result<SupportBundleCollectionObservation, PlatformError>
{
    Err(PlatformError::UnsupportedHost(
        "support-bundle collection has no verified fixed native acquisition".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_does_not_fall_back_to_caller_selected_paths() {
        assert!(matches!(
            audit_support_bundle_collection(),
            Err(PlatformError::UnsupportedHost(_))
        ));
    }
}
