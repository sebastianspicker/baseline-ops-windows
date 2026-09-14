//! Protected, server-owned output directories for one worker run.
//!
//! The caller supplies no filesystem path or leaf name. Windows resolves the
//! machine `ProgramData` known folder, the server creates a fresh UUID run
//! directory, and only the finite evidence, recovery, result, and journal
//! artifacts can be written. Handles retained by this value deny rename and
//! deletion while the run is active.

pub(crate) mod policy;

pub use policy::{MAX_EVIDENCE_BYTES, MAX_JOURNAL_BYTES, ProtectedRunArtifactKind};

use crate::PlatformError;
use baselineops_domain::RunId;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Opaque authority for one protected worker run directory.
pub struct ProtectedRunDirectory {
    run_id: RunId,
    path: PathBuf,
    #[cfg(windows)]
    inner: crate::trust::ProtectedRunDirectory,
}

/// Immutable bounded bytes read from one protected completed-run directory.
///
/// This value is evidence only. Its identifier and bytes grant no filesystem
/// or execution authority.
pub struct ProtectedRunArtifacts {
    run_id: RunId,
    journal_bytes: Vec<u8>,
    result_bytes: Vec<u8>,
}

impl ProtectedRunArtifacts {
    /// Returns the requested protected storage run identifier.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the bounded bytes read from the fixed `journal.v2` artifact.
    #[must_use]
    pub fn journal_bytes(&self) -> &[u8] {
        &self.journal_bytes
    }

    /// Returns the bounded bytes read from the fixed `result.json` artifact.
    #[must_use]
    pub fn result_bytes(&self) -> &[u8] {
        &self.result_bytes
    }
}

/// Bounded writable handle for the fixed `journal.v2` run artifact.
pub struct ProtectedJournalFile {
    file: File,
    path: PathBuf,
    bytes_written: usize,
    #[cfg(windows)]
    _lease: crate::trust::ProtectedRunLease,
}

impl ProtectedJournalFile {
    /// Returns the verified final journal path for evidence binding.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Flushes file content and metadata to the underlying storage device.
    ///
    /// # Errors
    ///
    /// Returns the operating-system synchronization error.
    pub fn sync_all(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}

impl Write for ProtectedJournalFile {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = MAX_JOURNAL_BYTES.saturating_sub(self.bytes_written);
        if buffer.len() > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "protected journal exceeded its byte limit",
            ));
        }
        let written = self.file.write(buffer)?;
        self.bytes_written += written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl ProtectedRunDirectory {
    /// Returns the server-generated run identifier.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the verified final path for reporting and evidence binding.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Creates and writes one finite, size-bounded run artifact.
    ///
    /// The artifact uses an exclusive create and an explicit protected DACL.
    /// Existing files are never overwritten or repaired.
    ///
    /// # Errors
    ///
    /// Returns an error when the artifact is oversized, already exists, or its
    /// final handle identity and ACL cannot be verified.
    pub fn write_artifact(
        &mut self,
        kind: ProtectedRunArtifactKind,
        bytes: &[u8],
    ) -> Result<PathBuf, PlatformError> {
        policy::validate_artifact(kind, bytes)?;
        #[cfg(windows)]
        {
            self.inner
                .write_artifact(kind.file_name(), bytes, kind.maximum_bytes())
        }
        #[cfg(not(windows))]
        {
            let _ = bytes;
            Err(PlatformError::UnsupportedPlatform)
        }
    }

    /// Exclusively creates the fixed `journal.v2` file and returns its owned
    /// write handle.
    ///
    /// The handle denies delete sharing and therefore prevents replacement
    /// while it remains open. This object enforces the 8 MiB byte quota; the
    /// journal layer enforces binary framing and record-count limits.
    ///
    /// # Errors
    ///
    /// Returns an error when the journal already exists or its explicit DACL,
    /// final handle identity, or non-reparse status cannot be proved.
    pub fn create_journal(&mut self) -> Result<ProtectedJournalFile, PlatformError> {
        #[cfg(windows)]
        {
            let (file, path, lease) = self.inner.create_journal()?;
            Ok(ProtectedJournalFile {
                file,
                path,
                bytes_written: 0,
                _lease: lease,
            })
        }
        #[cfg(not(windows))]
        {
            Err(PlatformError::UnsupportedPlatform)
        }
    }
}

/// Creates a protected directory for one server-generated worker run.
///
/// No client path is accepted. Existing product roots are validated without
/// ACL repair, and non-Windows hosts fail closed.
///
/// # Errors
///
/// Returns an error when the platform is unsupported or any known-folder,
/// ancestor, ACL, reparse-point, creation, or handle-identity check fails.
pub fn create_protected_run_directory() -> Result<ProtectedRunDirectory, PlatformError> {
    #[cfg(windows)]
    {
        let run_id = RunId::new();
        let inner = crate::trust::create_protected_run_directory(run_id)?;
        let path = inner.path().to_path_buf();
        Ok(ProtectedRunDirectory {
            run_id,
            path,
            inner,
        })
    }
    #[cfg(not(windows))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
}

/// Reads the fixed result and journal artifacts from an existing protected run.
///
/// Windows resolves `ProgramData` internally and treats `run_id` only as one
/// UUID directory component. Every existing ancestor, run directory, and file
/// is opened without following reparse points and validated through retained
/// handles. Artifact handles allow read sharing only, are held throughout both
/// bounded reads, and are revalidated before return. No ACL is changed or
/// repaired, so callers without access to the private run directory fail
/// closed. Consumers must validate journal lifecycle and bind the terminal
/// `RunFinished` digest to the result bytes before accepting the result.
///
/// # Errors
///
/// Returns an error on unsupported platforms, access denial, a missing or
/// oversized artifact, or any path, owner, ACL, reparse, hard-link, or handle
/// identity validation failure.
pub fn read_protected_run_artifacts(run_id: RunId) -> Result<ProtectedRunArtifacts, PlatformError> {
    #[cfg(windows)]
    {
        let (journal_bytes, result_bytes) = crate::trust::read_protected_run_artifacts(run_id)?;
        Ok(ProtectedRunArtifacts {
            run_id,
            journal_bytes,
            result_bytes,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = run_id;
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn creation_fails_closed_off_windows() {
        assert!(matches!(
            create_protected_run_directory(),
            Err(PlatformError::UnsupportedPlatform)
        ));
    }

    #[test]
    fn protected_read_fails_closed_off_windows() {
        assert!(matches!(
            read_protected_run_artifacts(RunId::default()),
            Err(PlatformError::UnsupportedPlatform)
        ));
    }

    #[test]
    fn artifact_bundle_exposes_only_immutable_fixed_bytes() {
        let run_id = RunId::default();
        let artifacts = ProtectedRunArtifacts {
            run_id,
            journal_bytes: vec![1, 2],
            result_bytes: vec![3, 4],
        };
        assert_eq!(artifacts.run_id(), run_id);
        assert_eq!(artifacts.journal_bytes(), &[1, 2]);
        assert_eq!(artifacts.result_bytes(), &[3, 4]);
    }

    #[test]
    fn journal_limit_accepts_the_exact_boundary_then_rejects_more() {
        let file = tempfile::tempfile().expect("temporary file");
        let mut journal = ProtectedJournalFile {
            file,
            path: PathBuf::from("journal.v2"),
            bytes_written: MAX_JOURNAL_BYTES - 2,
        };
        journal.write_all(&[1, 2]).expect("boundary write");
        assert!(journal.write(&[1]).is_err());
        assert_eq!(journal.path(), Path::new("journal.v2"));
    }
}
