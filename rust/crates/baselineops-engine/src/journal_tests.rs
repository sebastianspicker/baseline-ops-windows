use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use chrono::{DateTime, Utc};

use super::*;

fn timestamp() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
        .expect("timestamp")
        .with_timezone(&Utc)
}

fn plan_approved() -> JournalEvent {
    JournalEvent::PlanApproved {
        plan_id: PlanId::new(),
        plan_digest: Sha256Digest::of_bytes(b"plan"),
    }
}

fn append_plan_approved(journal: &mut Journal) {
    journal
        .append(timestamp(), plan_approved())
        .expect("append plan approval");
}

#[test]
fn default_limits_are_64_mib_and_4096_records() {
    assert_eq!(
        JournalLimits::default(),
        JournalLimits::new(64 * 1024 * 1024, 4096)
    );
}

#[test]
fn journal_hash_chain_advances_and_file_is_nonempty() {
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("apply.journal");
    let mut journal = Journal::create(&path).expect("journal");
    let initial = journal.terminal_hash();
    let record = journal
        .append(timestamp(), plan_approved())
        .expect("append");

    assert_eq!(record.previous_hash, initial);
    assert_eq!(journal.terminal_hash(), record.record_hash);
    assert!(fs::metadata(path).expect("metadata").len() > JOURNAL_MAGIC.len() as u64);
}

#[test]
fn append_enforces_record_quota_before_writing() {
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("records.journal");
    let limits = JournalLimits::new(1024 * 1024, 1);
    let mut journal = Journal::create_with_limits(&path, limits).expect("journal");
    append_plan_approved(&mut journal);
    let bytes_before = fs::read(&path).expect("bytes");
    let terminal_before = journal.terminal_hash();

    let error = journal
        .append(timestamp(), plan_approved())
        .expect_err("second record exceeds quota");

    assert!(matches!(
        error,
        JournalError::JournalRecordLimitExceeded { limit: 1 }
    ));
    assert_eq!(journal.terminal_hash(), terminal_before);
    assert_eq!(fs::read(path).expect("bytes"), bytes_before);
}

#[test]
fn exact_byte_quota_is_accepted_and_growth_is_rejected() {
    let root = tempfile::tempdir().expect("root");
    let probe = root.path().join("probe.journal");
    let mut probe_journal = Journal::create(&probe).expect("probe");
    append_plan_approved(&mut probe_journal);
    let exact_size = fs::metadata(probe).expect("metadata").len();

    let path = root.path().join("bounded.journal");
    let limits = JournalLimits::new(exact_size, 2);
    let mut journal = Journal::create_with_limits(&path, limits).expect("bounded journal");
    append_plan_approved(&mut journal);
    Journal::read_with_limits(&path, limits).expect("exact byte quota");
    let bytes_before = fs::read(&path).expect("bytes");

    assert!(matches!(
        journal.append(timestamp(), plan_approved()),
        Err(JournalError::JournalSizeLimitExceeded { limit }) if limit == exact_size
    ));
    assert_eq!(fs::read(path).expect("bytes"), bytes_before);
}

#[test]
fn readers_enforce_byte_and_record_quotas() {
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("limits.journal");
    let mut journal = Journal::create(&path).expect("journal");
    append_plan_approved(&mut journal);
    let size = fs::metadata(&path).expect("metadata").len();

    assert!(matches!(
        Journal::read_with_limits(&path, JournalLimits::new(size - 1, 1)),
        Err(JournalError::JournalSizeLimitExceeded { .. })
    ));
    assert!(matches!(
        Journal::read_with_limits(&path, JournalLimits::new(size, 0)),
        Err(JournalError::JournalRecordLimitExceeded { limit: 0 })
    ));
}

#[test]
fn fixed_frame_limit_is_checked_before_append() {
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("large.journal");
    let mut journal = Journal::create_with_limits(&path, JournalLimits::new(16 * 1024 * 1024, 1))
        .expect("journal");
    let initial = fs::read(&path).expect("initial bytes");

    let error = journal
        .append(
            timestamp(),
            JournalEvent::ActionStarted {
                action_id: "x".repeat(MAX_RECORD_BYTES),
                pre_state_digest: Sha256Digest::of_bytes(b"state"),
            },
        )
        .expect_err("record exceeds frame limit");

    assert!(matches!(error, JournalError::RecordTooLarge));
    assert_eq!(fs::read(path).expect("bytes"), initial);
}

#[test]
fn malformed_oversized_length_is_never_recovered() {
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("oversized.journal");
    let mut bytes = JOURNAL_MAGIC.to_vec();
    bytes.extend_from_slice(
        &u32::try_from(MAX_RECORD_BYTES + 1)
            .expect("length")
            .to_le_bytes(),
    );
    fs::write(&path, &bytes).expect("write malformed journal");

    assert!(matches!(
        Journal::read(&path),
        Err(JournalError::RecordTooLarge)
    ));
    assert!(matches!(
        Journal::recover(&path),
        Err(JournalError::RecordTooLarge)
    ));
    assert_eq!(fs::read(path).expect("bytes"), bytes);
}

#[test]
fn complete_invalid_frame_is_never_recovered() {
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("invalid.journal");
    let mut bytes = JOURNAL_MAGIC.to_vec();
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.push(b'{');
    fs::write(&path, &bytes).expect("write malformed journal");

    assert!(matches!(
        Journal::recover(&path),
        Err(JournalError::InvalidRecord(_))
    ));
    assert_eq!(fs::read(path).expect("bytes"), bytes);
}

#[test]
fn verification_detects_reordered_records() {
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("apply.journal");
    let terminal = two_action_journal(&path);
    Journal::verify(&path, terminal).expect("valid journal");
    let original = fs::read(&path).expect("bytes");
    let first_length = u32::from_le_bytes(
        original[JOURNAL_MAGIC.len()..JOURNAL_MAGIC.len() + 4]
            .try_into()
            .expect("first length"),
    );
    let first_end = JOURNAL_MAGIC.len() + 4 + usize::try_from(first_length).expect("length");
    let mut reordered = JOURNAL_MAGIC.to_vec();
    reordered.extend_from_slice(&original[first_end..]);
    reordered.extend_from_slice(&original[JOURNAL_MAGIC.len()..first_end]);
    let reordered_path = root.path().join("reordered.journal");
    fs::write(&reordered_path, reordered).expect("reorder");

    assert!(matches!(
        Journal::read(reordered_path),
        Err(JournalError::SequenceMismatch)
    ));
}

#[test]
fn verification_detects_record_edits() {
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("edited.journal");
    two_action_journal(&path);
    let mut bytes = fs::read(&path).expect("bytes");
    *bytes.last_mut().expect("last") ^= 1;
    fs::write(&path, bytes).expect("edit");

    assert!(matches!(
        Journal::read(&path),
        Err(JournalError::InvalidRecord(_) | JournalError::RecordHashMismatch)
    ));
}

#[test]
fn verification_detects_prefix_truncation() {
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("truncated.journal");
    let mut journal = Journal::create(&path).expect("journal");
    append_plan_approved(&mut journal);
    let expected = journal.terminal_hash();
    let bytes = fs::read(&path).expect("bytes");
    fs::write(&path, &bytes[..JOURNAL_MAGIC.len()]).expect("truncate");

    assert!(matches!(
        Journal::verify(&path, expected),
        Err(JournalError::TerminalHashMismatch)
    ));
}

#[test]
fn recovery_only_removes_an_incomplete_last_frame() {
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("recover.journal");
    let mut journal = Journal::create(&path).expect("journal");
    append_plan_approved(&mut journal);
    let length_before = fs::metadata(&path).expect("metadata").len();
    let mut file = OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("append file");
    file.write_all(&[5, 0, 0, 0, 1, 2]).expect("partial frame");
    file.sync_all().expect("sync");

    assert!(matches!(
        Journal::read(&path),
        Err(JournalError::IncompleteFrame)
    ));
    let (_, recovery) = Journal::recover(&path).expect("recovered");
    assert_eq!(recovery.truncated_bytes, 6);
    assert_eq!(fs::metadata(path).expect("metadata").len(), length_before);
}

#[test]
fn recovery_accepts_incomplete_tail_at_record_quota() {
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("record-boundary.journal");
    let limits = JournalLimits::new(1024 * 1024, 1);
    let mut journal = Journal::create_with_limits(&path, limits).expect("journal");
    append_plan_approved(&mut journal);
    drop(journal);
    let length_before = fs::metadata(&path).expect("metadata").len();
    let mut file = OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("append file");
    file.write_all(&[5, 0, 0, 0, 1, 2]).expect("partial frame");
    file.sync_all().expect("sync");
    drop(file);

    let (mut recovered, recovery) = Journal::recover_with_limits(&path, limits).expect("recovered");

    assert_eq!(recovery.truncated_bytes, 6);
    assert_eq!(fs::metadata(&path).expect("metadata").len(), length_before);
    assert!(matches!(
        recovered.append(timestamp(), plan_approved()),
        Err(JournalError::JournalRecordLimitExceeded { limit: 1 })
    ));
}

#[test]
fn recovery_accepts_incomplete_tail_at_byte_quota() {
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("byte-boundary.journal");
    let mut journal = Journal::create(&path).expect("journal");
    append_plan_approved(&mut journal);
    drop(journal);
    let length_before = fs::metadata(&path).expect("metadata").len();
    let mut bytes = fs::read(&path).expect("bytes");
    bytes.extend_from_slice(&[5, 0, 0, 0, 1, 2]);
    fs::write(&path, bytes).expect("partial frame");
    let limits = JournalLimits::new(length_before + 6, 1);

    let (_, recovery) = Journal::recover_with_limits(&path, limits).expect("recovered");

    assert_eq!(recovery.truncated_bytes, 6);
    assert_eq!(fs::metadata(path).expect("metadata").len(), length_before);
}

fn two_action_journal(path: &Path) -> Sha256Digest {
    let mut journal = Journal::create(path).expect("journal");
    append_plan_approved(&mut journal);
    for label in ["first", "second"] {
        journal
            .append(
                timestamp(),
                JournalEvent::ActionStarted {
                    action_id: label.into(),
                    pre_state_digest: Sha256Digest::of_bytes(label),
                },
            )
            .expect("append");
        journal
            .append(
                timestamp(),
                JournalEvent::ActionFinished {
                    action_id: label.into(),
                    status: ActionStatus::Succeeded,
                    receipt_digest: Sha256Digest::of_bytes(label),
                },
            )
            .expect("finish action");
    }
    journal.terminal_hash()
}

#[path = "journal/lifecycle_tests.rs"]
mod lifecycle_tests;

#[path = "journal/durability_tests.rs"]
mod durability_tests;
