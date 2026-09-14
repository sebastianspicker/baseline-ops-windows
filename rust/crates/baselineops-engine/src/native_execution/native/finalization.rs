//! Result-document commit ordering.
//!
//! A written `result.json` is only pending until a durable `RunFinished` event
//! binds its result identifier and canonical digest. Future readers must
//! require that matching terminal event before accepting the file.

use super::NativeExecutionError;
use crate::{Journal, JournalEvent};
use baselineops_domain::{ArtifactV3, ResultId, Sha256Digest};
use chrono::Utc;

pub(super) trait FinalizationPort {
    fn write_pending_result(&mut self, bytes: &[u8]) -> Result<ArtifactV3, NativeExecutionError>;

    fn commit_result(
        &mut self,
        result_id: ResultId,
        digest: Sha256Digest,
    ) -> Result<(), NativeExecutionError>;
}

pub(super) fn finalize_result(
    port: &mut impl FinalizationPort,
    result_id: ResultId,
    bytes: &[u8],
) -> Result<ArtifactV3, NativeExecutionError> {
    let expected_digest = Sha256Digest::of_bytes(bytes);
    let artifact = port.write_pending_result(bytes)?;
    verify_artifact(&artifact, expected_digest, bytes.len())?;
    port.commit_result(result_id, expected_digest)?;
    Ok(artifact)
}

pub(super) fn append_run_finished(
    journal: &mut Journal,
    result_id: ResultId,
    digest: Sha256Digest,
) -> Result<(), NativeExecutionError> {
    journal.append(
        Utc::now(),
        JournalEvent::RunFinished {
            result_id,
            result_digest: digest,
        },
    )?;
    Ok(())
}

fn verify_artifact(
    artifact: &ArtifactV3,
    expected_digest: Sha256Digest,
    expected_size: usize,
) -> Result<(), NativeExecutionError> {
    let size = u64::try_from(expected_size)
        .map_err(|_| NativeExecutionError::Rejected("result document size is not representable"))?;
    if artifact.digest != expected_digest || artifact.size_bytes != size {
        return Err(NativeExecutionError::Rejected(
            "pending result artifact does not match its canonical document",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "finalization_tests.rs"]
mod tests;
