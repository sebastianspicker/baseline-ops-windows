//! Fail-closed acquisition seam for capability 11 Defender IOC sweep.
//!
//! The legacy `MpCmdRun` invocation, custom scan paths, and catalog locations
//! are not runtime dependencies and are deliberately not accepted here.

use crate::PlatformError;
use baselineops_capabilities::DefenderIocSweepObservation;

/// Acquires a fixed digest-bound Defender IOC-sweep observation.
///
/// # Errors
///
/// Always fails closed until the native Defender API and sealed catalog contract
/// are independently verified on supported Windows hosts.
pub fn audit_defender_ioc_sweep() -> Result<DefenderIocSweepObservation, PlatformError> {
    Err(PlatformError::UnsupportedHost(
        "Defender IOC sweep has no verified fixed native acquisition".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_command_or_custom_scan_path_is_available() {
        assert!(matches!(
            audit_defender_ioc_sweep(),
            Err(PlatformError::UnsupportedHost(_))
        ));
    }
}
