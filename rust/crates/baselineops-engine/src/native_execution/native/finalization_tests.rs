use super::*;
use crate::{Journal, JournalEvent, JournalLimits};
use baselineops_domain::{ArtifactId, ArtifactKind, JsonMap, PlanId};
use chrono::Utc;
use std::fs;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailureStage {
    ArtifactWrite,
    JournalWrite,
    JournalFlush,
    JournalSync,
}

struct MockPort {
    fail_at: Option<FailureStage>,
    committed: Option<(ResultId, Sha256Digest)>,
}

struct JournalPort {
    journal: Journal,
    result_path: std::path::PathBuf,
}

impl FinalizationPort for JournalPort {
    fn write_pending_result(&mut self, bytes: &[u8]) -> Result<ArtifactV3, NativeExecutionError> {
        fs::write(&self.result_path, bytes).map_err(crate::JournalError::from)?;
        Ok(artifact(bytes))
    }

    fn commit_result(
        &mut self,
        result_id: ResultId,
        digest: Sha256Digest,
    ) -> Result<(), NativeExecutionError> {
        append_run_finished(&mut self.journal, result_id, digest)
    }
}

impl MockPort {
    const fn new(fail_at: Option<FailureStage>) -> Self {
        Self {
            fail_at,
            committed: None,
        }
    }
}

impl FinalizationPort for MockPort {
    fn write_pending_result(&mut self, bytes: &[u8]) -> Result<ArtifactV3, NativeExecutionError> {
        if self.fail_at == Some(FailureStage::ArtifactWrite) {
            return Err(injected_failure());
        }
        Ok(artifact(bytes))
    }

    fn commit_result(
        &mut self,
        result_id: ResultId,
        digest: Sha256Digest,
    ) -> Result<(), NativeExecutionError> {
        if matches!(
            self.fail_at,
            Some(
                FailureStage::JournalWrite | FailureStage::JournalFlush | FailureStage::JournalSync
            )
        ) {
            return Err(injected_failure());
        }
        self.committed = Some((result_id, digest));
        Ok(())
    }
}

fn artifact(bytes: &[u8]) -> ArtifactV3 {
    ArtifactV3 {
        id: ArtifactId::new(),
        kind: ArtifactKind::Report,
        media_type: "application/json".into(),
        locator: "run/result.json".into(),
        digest: Sha256Digest::of_bytes(bytes),
        size_bytes: bytes.len() as u64,
        created_at: Utc::now(),
        metadata: JsonMap::new(),
    }
}

fn injected_failure() -> NativeExecutionError {
    NativeExecutionError::Rejected("injected finalization failure")
}

#[test]
fn success_returns_only_the_artifact_bound_by_the_terminal_digest() {
    let bytes = br#"{"result":"complete"}"#;
    let result_id = ResultId::new();
    let mut port = MockPort::new(None);

    let retained = finalize_result(&mut port, result_id, bytes).unwrap();

    assert_eq!(retained.digest, Sha256Digest::of_bytes(bytes));
    assert_eq!(
        port.committed,
        Some((result_id, Sha256Digest::of_bytes(bytes)))
    );
}

#[test]
fn write_flush_and_sync_failures_never_return_an_advertisable_artifact() {
    for stage in [
        FailureStage::ArtifactWrite,
        FailureStage::JournalWrite,
        FailureStage::JournalFlush,
        FailureStage::JournalSync,
    ] {
        let mut port = MockPort::new(Some(stage));
        let mut manifest = Vec::new();
        if let Ok(retained) = finalize_result(&mut port, ResultId::new(), b"result") {
            manifest.push(retained);
        }
        assert!(manifest.is_empty(), "failure at {stage:?}");
        assert!(port.committed.is_none(), "failure at {stage:?}");
    }
}

#[test]
fn mismatched_pending_artifact_is_not_committed_or_returned() {
    struct MismatchPort(bool);
    impl FinalizationPort for MismatchPort {
        fn write_pending_result(
            &mut self,
            _bytes: &[u8],
        ) -> Result<ArtifactV3, NativeExecutionError> {
            Ok(artifact(b"different"))
        }

        fn commit_result(
            &mut self,
            _result_id: ResultId,
            _digest: Sha256Digest,
        ) -> Result<(), NativeExecutionError> {
            self.0 = true;
            Ok(())
        }
    }

    let mut port = MismatchPort(false);
    assert!(finalize_result(&mut port, ResultId::new(), b"result").is_err());
    assert!(!port.0);
}

#[test]
fn actual_journal_quota_failure_keeps_written_result_pending() {
    let root = tempfile::tempdir().unwrap();
    let journal_path = root.path().join("journal");
    let mut journal =
        Journal::create_with_limits(&journal_path, JournalLimits::new(1024 * 1024, 1)).unwrap();
    journal
        .append(
            Utc::now(),
            JournalEvent::PlanApproved {
                plan_id: PlanId::new(),
                plan_digest: Sha256Digest::of_bytes(b"plan"),
            },
        )
        .unwrap();
    let result_path = root.path().join("result.json");
    let mut port = JournalPort {
        journal,
        result_path: result_path.clone(),
    };

    assert!(finalize_result(&mut port, ResultId::new(), b"result").is_err());
    assert_eq!(fs::read(result_path).unwrap(), b"result");
    assert_eq!(Journal::read(journal_path).unwrap().records.len(), 1);
}
