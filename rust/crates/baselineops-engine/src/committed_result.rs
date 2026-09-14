//! Read-only reconciliation of protected result documents and committed journals.

mod document;
mod verify;

use baselineops_domain::{ArtifactKind, ArtifactV3, ResultId, RunId, WorkerResultV3};
pub(crate) use document::ResultDocument;

/// A committed result document whose bytes match the supplied authenticated broker result.
/// This object grants no execution or recovery authority. Referenced artifacts have not
/// been opened or independently read by this verification.
#[derive(Debug)]
pub struct CommittedWorkerResult {
    document: ResultDocument,
    bytes: Vec<u8>,
}

impl CommittedWorkerResult {
    /// Identifier matched to the terminal journal event.
    #[must_use]
    pub const fn result_id(&self) -> ResultId {
        self.document.result_id
    }

    /// Whether the committed action reported a possible reboot requirement.
    #[must_use]
    pub const fn reboot_possible(&self) -> bool {
        self.document.reboot_possible
    }

    /// Canonical UTF-8 JSON suitable for a bounded, read-only viewer.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Read the fixed protected result and journal, requiring a matching durable commit.
///
/// `expected` must come from an independently authenticated worker exchange. This
/// function cannot authenticate caller-supplied JSON. It accepts no filesystem path,
/// changes no ACL, and may fail for a standard user without access to the private run.
///
/// # Errors
/// Rejects missing commits, substitutions, partial journals, mismatched receipts or
/// bindings, unsupported document schemas, and inaccessible/unprotected files.
pub fn read_committed_worker_result(
    expected: &WorkerResultV3,
) -> Result<CommittedWorkerResult, CommittedResultError> {
    expected.validate()?;
    let (storage_id, _) = report_artifact(expected)?;
    let retained = baselineops_windows::read_protected_run_artifacts(storage_id)?;
    verify::reconcile(expected, retained.result_bytes(), retained.journal_bytes())
}

fn report_artifact(
    expected: &WorkerResultV3,
) -> Result<(RunId, &ArtifactV3), CommittedResultError> {
    let artifact = expected
        .artifact_manifest
        .last()
        .ok_or(CommittedResultError::Mismatch(
            "result has no committed report artifact",
        ))?;
    if (artifact.kind, artifact.media_type.as_str()) != (ArtifactKind::Report, "application/json") {
        return Err(CommittedResultError::Mismatch(
            "terminal artifact is not a JSON report",
        ));
    }
    let (directory, leaf) =
        artifact
            .locator
            .split_once('/')
            .ok_or(CommittedResultError::Mismatch(
                "report locator is not a fixed run artifact",
            ))?;
    let storage_id = storage_identifier(directory, leaf)?;
    for entry in &expected.artifact_manifest {
        verify::artifact_scope(entry, directory)?;
    }
    Ok((storage_id, artifact))
}

fn storage_identifier(directory: &str, leaf: &str) -> Result<RunId, CommittedResultError> {
    let storage_id: RunId = directory
        .parse()
        .map_err(|_| CommittedResultError::Mismatch("report directory is not a run identifier"))?;
    if directory != storage_id.to_string() || leaf != "result.json" {
        return Err(CommittedResultError::Mismatch(
            "report locator is not canonical",
        ));
    }
    Ok(storage_id)
}

/// Read or integrity failure; no error grants permission to repair or resume a run.
#[derive(Debug, thiserror::Error)]
pub enum CommittedResultError {
    /// The protected Windows read failed.
    #[error(transparent)]
    Platform(#[from] baselineops_windows::PlatformError),
    /// The bounded typed document or envelope is invalid.
    #[error(transparent)]
    Domain(#[from] baselineops_domain::DomainError),
    /// Journal framing, lifecycle, or integrity is invalid.
    #[error(transparent)]
    Journal(#[from] crate::JournalError),
    /// A retained object does not match its authenticated binding.
    #[error("committed result rejected: {0}")]
    Mismatch(&'static str),
}

#[cfg(test)]
mod tests;
