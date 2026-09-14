//! Fail-closed acquisition seam for capability 12 incident artifacts.
//!
//! This contains no sample copying, archive writing, arbitrary filesystem path,
//! process command line, or user-controlled collection selector.

use crate::PlatformError;
use baselineops_capabilities::IncidentArtifactGrabberObservation;

/// Acquires fixed incident-artifact metadata when a sealed collector exists.
///
/// # Errors
///
/// Always returns an explicit unavailable error pending fixed Windows evidence.
pub fn audit_incident_artifact_grabber() -> Result<IncidentArtifactGrabberObservation, PlatformError>
{
    Err(PlatformError::UnsupportedHost(
        "incident artifact collection has no verified fixed native acquisition".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_collection_cannot_select_paths_or_samples() {
        assert!(matches!(
            audit_incident_artifact_grabber(),
            Err(PlatformError::UnsupportedHost(_))
        ));
    }
}
