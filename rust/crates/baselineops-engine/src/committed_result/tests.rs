use super::*;
use crate::{Journal, JournalEvent, JournalLimits};
use baselineops_domain::{
    ActionId, ActionReceiptV3, ActionStatus, ArtifactId, CapabilityId, ExitCode, JsonMap, PlanId,
    ResultStatus, SchemaVersion, Sha256Digest, canonical_json_bytes, canonical_json_digest,
};
use chrono::Utc;

struct Fixture {
    expected: WorkerResultV3,
    document: ResultDocument,
    journal: Journal,
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = Journal::create(directory.path().join("journal")).unwrap();
        let plan_id = PlanId::new();
        let plan_digest = Sha256Digest::of_bytes(b"approved-plan");
        journal
            .append(
                Utc::now(),
                JournalEvent::PlanApproved {
                    plan_id,
                    plan_digest,
                },
            )
            .unwrap();
        let receipt = append_action(&mut journal);
        let expected = WorkerResultV3 {
            schema_version: SchemaVersion::V3,
            plan_id,
            run_id: RunId::new(),
            plan_digest,
            journal_terminal_hash: None,
            receipts: vec![receipt],
            artifact_manifest: vec![],
            final_status: ResultStatus::Completed,
            reason: None,
            exit_code: ExitCode::Completed.as_i32(),
        };
        let document = ResultDocument {
            schema_version: "1.0".into(),
            result_id: ResultId::new(),
            plan_id,
            run_id: expected.run_id,
            plan_digest,
            journal_prefix_hash: journal.terminal_hash(),
            receipts: expected.receipts.clone(),
            status: expected.final_status,
            reason: None,
            reboot_possible: true,
            artifacts: vec![],
        };
        Self {
            expected,
            document,
            journal,
            directory,
        }
    }

    fn finish(&mut self, commit: bool) -> (Vec<u8>, Vec<u8>) {
        let bytes = canonical_json_bytes(&self.document).unwrap();
        let digest = Sha256Digest::of_bytes(&bytes);
        if commit {
            self.journal
                .append(
                    Utc::now(),
                    JournalEvent::RunFinished {
                        result_id: self.document.result_id,
                        result_digest: digest,
                    },
                )
                .unwrap();
        }
        self.expected.journal_terminal_hash = Some(self.journal.terminal_hash());
        self.expected.artifact_manifest.push(ArtifactV3 {
            id: ArtifactId::new(),
            kind: ArtifactKind::Report,
            media_type: "application/json".into(),
            locator: format!("{}/result.json", RunId::new()),
            digest,
            size_bytes: bytes.len() as u64,
            created_at: Utc::now(),
            metadata: JsonMap::new(),
        });
        let journal_bytes = std::fs::read(self.directory.path().join("journal")).unwrap();
        (bytes, journal_bytes)
    }
}

fn append_action(journal: &mut Journal) -> ActionReceiptV3 {
    let receipt = ActionReceiptV3 {
        action_id: ActionId::new(),
        capability: CapabilityId::new("v3.windows-update.policy").unwrap(),
        pre_state_digest: Sha256Digest::of_bytes(b"before"),
        post_state_digest: Sha256Digest::of_bytes(b"after"),
        status: ActionStatus::Succeeded,
    };
    journal
        .append(
            Utc::now(),
            JournalEvent::ActionStarted {
                action_id: receipt.action_id.to_string(),
                pre_state_digest: receipt.pre_state_digest,
            },
        )
        .unwrap();
    journal
        .append(
            Utc::now(),
            JournalEvent::ActionFinished {
                action_id: receipt.action_id.to_string(),
                status: receipt.status,
                receipt_digest: canonical_json_digest(&receipt).unwrap(),
            },
        )
        .unwrap();
    receipt
}

#[test]
fn accepts_only_document_bound_to_a_durable_terminal_commit() {
    let mut fixture = Fixture::new();
    let (bytes, journal) = fixture.finish(true);
    let verified = verify::reconcile(&fixture.expected, &bytes, &journal).unwrap();
    assert_eq!(verified.result_id(), fixture.document.result_id);
    assert!(verified.reboot_possible());
    assert_eq!(verified.bytes(), bytes);
}

#[test]
fn pending_result_without_commit_is_never_accepted() {
    let mut fixture = Fixture::new();
    let (bytes, journal) = fixture.finish(false);
    assert!(verify::reconcile(&fixture.expected, &bytes, &journal).is_err());
}

#[test]
fn substitutions_and_partial_journals_are_rejected() {
    let mut fixture = Fixture::new();
    let (bytes, journal) = fixture.finish(true);
    let mut substituted = bytes.clone();
    substituted[0] = b' ';
    assert!(verify::reconcile(&fixture.expected, &substituted, &journal).is_err());
    for altered in [
        &journal[..journal.len() - 1],
        &[journal.as_slice(), &[0]].concat(),
    ] {
        assert!(verify::reconcile(&fixture.expected, &bytes, altered).is_err());
    }
    fixture.expected.journal_terminal_hash = Some(Sha256Digest::of_bytes(b"other-run"));
    assert!(verify::reconcile(&fixture.expected, &bytes, &journal).is_err());
}

#[test]
fn document_identity_and_receipts_must_match_the_broker() {
    let mut fixture = Fixture::new();
    let (bytes, journal) = fixture.finish(true);
    let original = fixture.expected.clone();
    fixture.expected.plan_id = PlanId::new();
    assert!(verify::reconcile(&fixture.expected, &bytes, &journal).is_err());
    fixture.expected = original.clone();
    fixture.expected.run_id = RunId::new();
    assert!(verify::reconcile(&fixture.expected, &bytes, &journal).is_err());
    fixture.expected = original;
    fixture.expected.receipts[0].post_state_digest = Sha256Digest::of_bytes(b"different-post");
    assert!(verify::reconcile(&fixture.expected, &bytes, &journal).is_err());
}

#[test]
fn self_consistent_envelope_and_document_cannot_replace_journal_receipt() {
    let mut fixture = Fixture::new();
    fixture.document.receipts[0].post_state_digest = Sha256Digest::of_bytes(b"forged-post");
    fixture.expected.receipts = fixture.document.receipts.clone();
    let (bytes, journal) = fixture.finish(true);
    assert!(verify::reconcile(&fixture.expected, &bytes, &journal).is_err());
}

#[test]
fn schema_and_prefix_are_independently_checked() {
    for invalid_schema in [false, true] {
        let mut fixture = Fixture::new();
        if invalid_schema {
            fixture.document.schema_version = "2.0".into();
        } else {
            fixture.document.journal_prefix_hash = Sha256Digest::of_bytes(b"wrong-prefix");
        }
        let (bytes, journal) = fixture.finish(true);
        assert!(verify::reconcile(&fixture.expected, &bytes, &journal).is_err());
    }
}

#[test]
fn report_locator_cannot_select_an_arbitrary_file() {
    let mut fixture = Fixture::new();
    let (bytes, journal) = fixture.finish(true);
    for locator in [
        "../result.json",
        "C:/result.json",
        "run/result.json",
        "00000000-0000-0000-0000-000000000000/../result.json",
    ] {
        fixture.expected.artifact_manifest[0].locator = locator.into();
        assert!(verify::reconcile(&fixture.expected, &bytes, &journal).is_err());
    }
}

#[test]
fn byte_reader_enforces_size_and_record_limits_before_acceptance() {
    let mut fixture = Fixture::new();
    let (_, journal) = fixture.finish(true);
    assert!(
        Journal::read_bytes(&journal, JournalLimits::new(journal.len() as u64 - 1, 4096)).is_err()
    );
    assert!(Journal::read_bytes(&journal, JournalLimits::new(journal.len() as u64, 3)).is_err());
    assert!(Journal::read_bytes(&journal, JournalLimits::new(journal.len() as u64, 4)).is_ok());
}

#[test]
fn equivalent_noncanonical_journal_encoding_cannot_preserve_acceptance() {
    let mut fixture = Fixture::new();
    let (bytes, journal) = fixture.finish(true);
    let start = b"BASELINEOPS-JOURNAL-V2\n".len();
    let length = u32::from_le_bytes(journal[start..start + 4].try_into().unwrap()) as usize;
    let mut altered = journal[..start].to_vec();
    altered.extend_from_slice(&u32::try_from(length + 1).unwrap().to_le_bytes());
    altered.push(b' ');
    altered.extend_from_slice(&journal[start + 4..]);
    assert!(matches!(
        verify::reconcile(&fixture.expected, &bytes, &altered),
        Err(CommittedResultError::Journal(
            crate::JournalError::NonCanonicalRecord
        ))
    ));
}

#[test]
fn manifest_scope_and_empty_manifest_are_rejected_before_file_access() {
    let mut fixture = Fixture::new();
    let (bytes, journal) = fixture.finish(true);
    let original = fixture.expected.clone();
    let mut other_run = fixture.expected.artifact_manifest[0].clone();
    other_run.id = ArtifactId::new();
    other_run.kind = ArtifactKind::Evidence;
    other_run.locator = format!("{}/evidence.json", RunId::new());
    fixture.expected.artifact_manifest.insert(0, other_run);
    assert!(verify::reconcile(&fixture.expected, &bytes, &journal).is_err());
    fixture.expected = original;
    fixture.expected.artifact_manifest.clear();
    assert!(verify::reconcile(&fixture.expected, &bytes, &journal).is_err());
}
