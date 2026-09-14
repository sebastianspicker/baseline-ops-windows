use crate::PlatformError;
use std::path::PathBuf;

#[cfg(test)]
use std::path::Path;

#[cfg(any(windows, test))]
pub(crate) const PRODUCT_DIRECTORY: &str = "BaselineOps";
#[cfg(any(windows, test))]
pub(crate) const RUNS_DIRECTORY: &str = "Runs";
pub(super) const EVIDENCE_FILE: &str = "evidence.json";
pub(super) const RECOVERY_FILE: &str = "recovery.json";
pub(super) const RESULT_FILE: &str = "result.json";
#[cfg(any(windows, test))]
pub(crate) const JOURNAL_FILE: &str = "journal.v2";
/// Maximum size of each one-shot run artifact.
pub const MAX_EVIDENCE_BYTES: usize = 1024 * 1024;
/// Maximum total bytes accepted by one protected journal handle.
pub const MAX_JOURNAL_BYTES: usize = 8 * 1024 * 1024;

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtectedRunReadKind {
    Journal,
    Result,
}

#[cfg(any(windows, test))]
impl ProtectedRunReadKind {
    pub(crate) const fn file_name(self) -> &'static str {
        match self {
            Self::Journal => JOURNAL_FILE,
            Self::Result => RESULT_FILE,
        }
    }

    pub(crate) const fn maximum_bytes(self) -> usize {
        match self {
            Self::Journal => MAX_JOURNAL_BYTES,
            Self::Result => MAX_EVIDENCE_BYTES,
        }
    }
}

#[cfg(any(windows, test))]
pub(crate) fn validate_read_size(
    kind: ProtectedRunReadKind,
    size: u64,
) -> Result<usize, PlatformError> {
    let maximum = kind.maximum_bytes();
    let size = usize::try_from(size).map_err(|_| read_too_large(kind))?;
    if size > maximum {
        return Err(read_too_large(kind));
    }
    Ok(size)
}

#[cfg(any(windows, test))]
fn read_too_large(kind: ProtectedRunReadKind) -> PlatformError {
    PlatformError::InputTooLarge {
        path: PathBuf::from(kind.file_name()),
        limit: kind.maximum_bytes() as u64,
    }
}

/// Finite one-shot artifacts permitted under a protected run directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedRunArtifactKind {
    /// Canonical execution evidence document.
    Evidence,
    /// Pre-mutation recovery snapshot.
    RecoverySnapshot,
    /// Terminal execution result document.
    Result,
}

impl ProtectedRunArtifactKind {
    #[cfg(test)]
    const ALL: [Self; 3] = [Self::Evidence, Self::RecoverySnapshot, Self::Result];

    pub(super) const fn file_name(self) -> &'static str {
        match self {
            Self::Evidence => EVIDENCE_FILE,
            Self::RecoverySnapshot => RECOVERY_FILE,
            Self::Result => RESULT_FILE,
        }
    }

    pub(super) const fn maximum_bytes(self) -> usize {
        match self {
            Self::Evidence | Self::RecoverySnapshot | Self::Result => MAX_EVIDENCE_BYTES,
        }
    }
}

pub(super) fn validate_artifact(
    kind: ProtectedRunArtifactKind,
    bytes: &[u8],
) -> Result<(), PlatformError> {
    let limit = kind.maximum_bytes();
    if bytes.len() > limit {
        return Err(PlatformError::InputTooLarge {
            path: PathBuf::from(kind.file_name()),
            limit: limit as u64,
        });
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn relative_run_path(run_id: baselineops_domain::RunId) -> PathBuf {
    Path::new(PRODUCT_DIRECTORY)
        .join(RUNS_DIRECTORY)
        .join(run_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::fs::OpenOptions;

    #[test]
    fn run_path_is_fixed_and_server_identifier_is_one_component() {
        let run_id = baselineops_domain::RunId::default();
        let path = relative_run_path(run_id);
        assert_eq!(
            path,
            Path::new("BaselineOps/Runs/00000000-0000-0000-0000-000000000000")
        );
        assert_eq!(path.components().count(), 3);
    }

    #[test]
    fn artifact_names_and_limits_are_finite() {
        let names = ProtectedRunArtifactKind::ALL
            .map(ProtectedRunArtifactKind::file_name)
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names,
            BTreeSet::from([EVIDENCE_FILE, RECOVERY_FILE, RESULT_FILE])
        );
        assert_eq!(JOURNAL_FILE, "journal.v2");
    }

    #[test]
    fn every_artifact_enforces_the_one_mebibyte_preflight() {
        for kind in ProtectedRunArtifactKind::ALL {
            assert!(validate_artifact(kind, &vec![0; MAX_EVIDENCE_BYTES]).is_ok());
            assert!(validate_artifact(kind, &vec![0; MAX_EVIDENCE_BYTES + 1]).is_err());
        }
    }

    #[test]
    fn every_artifact_name_uses_exclusive_os_creation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        for kind in ProtectedRunArtifactKind::ALL {
            let path = directory.path().join(kind.file_name());
            let first = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .expect("first exclusive create");
            assert!(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .is_err()
            );
            drop(first);
        }
    }

    #[test]
    fn protected_reads_have_finite_names_and_distinct_bounds() {
        assert_eq!(ProtectedRunReadKind::Journal.file_name(), "journal.v2");
        assert_eq!(ProtectedRunReadKind::Result.file_name(), "result.json");
        assert_eq!(
            validate_read_size(
                ProtectedRunReadKind::Journal,
                u64::try_from(MAX_JOURNAL_BYTES).expect("limit fits u64")
            )
            .expect("exact limit is accepted"),
            MAX_JOURNAL_BYTES
        );
        assert!(matches!(
            validate_read_size(
                ProtectedRunReadKind::Result,
                u64::try_from(MAX_EVIDENCE_BYTES + 1).expect("limit fits u64")
            ),
            Err(PlatformError::InputTooLarge { path, limit })
                if path == Path::new("result.json") && limit == MAX_EVIDENCE_BYTES as u64
        ));
    }
}
