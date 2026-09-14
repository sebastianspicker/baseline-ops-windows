use super::*;

fn start(action: &str) -> JournalEvent {
    JournalEvent::ActionStarted {
        action_id: action.into(),
        pre_state_digest: Sha256Digest::of_bytes(action),
    }
}

fn finish(action: &str) -> JournalEvent {
    JournalEvent::ActionFinished {
        action_id: action.into(),
        status: ActionStatus::Succeeded,
        receipt_digest: Sha256Digest::of_bytes(action),
    }
}

fn end() -> JournalEvent {
    JournalEvent::RunFinished {
        result_id: ResultId::new(),
        result_digest: Sha256Digest::of_bytes(b"result"),
    }
}

fn rejects_without_writing(journal: &mut Journal, events: Vec<JournalEvent>) {
    let before = fs::read(journal.path()).unwrap();
    let hash = journal.terminal_hash();
    for event in events {
        assert!(matches!(
            journal.append(timestamp(), event),
            Err(JournalError::InvalidLifecycle(_))
        ));
        assert_eq!(journal.terminal_hash(), hash);
        assert_eq!(fs::read(journal.path()).unwrap(), before);
    }
}

#[test]
fn approval_sequential_actions_and_terminal_run_are_enforced() {
    let root = tempfile::tempdir().unwrap();
    let mut journal = Journal::create(root.path().join("lifecycle")).unwrap();
    rejects_without_writing(&mut journal, vec![start("a"), finish("a"), end()]);
    append_plan_approved(&mut journal);
    rejects_without_writing(&mut journal, vec![plan_approved(), start("")]);
    journal.append(timestamp(), start("a")).unwrap();
    rejects_without_writing(&mut journal, vec![start("b"), finish("b"), end()]);
    journal.append(timestamp(), finish("a")).unwrap();
    rejects_without_writing(&mut journal, vec![start("a"), finish("a")]);
    journal.append(timestamp(), end()).unwrap();
    rejects_without_writing(&mut journal, vec![plan_approved(), start("b"), end()]);
}

#[test]
fn an_unmatched_durable_start_requires_explicit_action_recovery() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("interrupted");
    let mut journal = Journal::create(&path).unwrap();
    append_plan_approved(&mut journal);
    journal.append(timestamp(), start("a")).unwrap();
    drop(journal);
    assert!(matches!(
        Journal::open(&path),
        Err(JournalError::ActionRecoveryRequired(action)) if action == "a"
    ));
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(&[5, 0, 0, 0, 1]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        Journal::recover(&path),
        Err(JournalError::ActionRecoveryRequired(action)) if action == "a"
    ));
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn completed_actions_cannot_be_replayed_after_reopening() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("complete");
    let mut journal = Journal::create(&path).unwrap();
    append_plan_approved(&mut journal);
    journal.append(timestamp(), start("a")).unwrap();
    journal.append(timestamp(), finish("a")).unwrap();
    drop(journal);
    let mut reopened = Journal::open(path).unwrap();
    rejects_without_writing(&mut reopened, vec![plan_approved(), start("a")]);
    reopened.append(timestamp(), start("b")).unwrap();
    reopened.append(timestamp(), finish("b")).unwrap();
}

#[test]
fn incomplete_data_after_terminal_run_is_preserved_as_corruption() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("terminal-tail");
    let mut journal = Journal::create(&path).unwrap();
    append_plan_approved(&mut journal);
    journal.append(timestamp(), end()).unwrap();
    drop(journal);
    let mut bytes = fs::read(&path).unwrap();
    bytes.extend_from_slice(&[5, 0, 0, 0, 1]);
    fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        Journal::recover(&path),
        Err(JournalError::InvalidLifecycle(_))
    ));
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn older_journals_are_never_reinterpreted_or_repaired() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("legacy-format");
    let bytes = b"BASELINEOPS-JOURNAL-V1\n";
    fs::write(&path, bytes).unwrap();
    assert!(matches!(Journal::read(&path), Err(JournalError::BadMagic)));
    assert!(matches!(
        Journal::recover(&path),
        Err(JournalError::BadMagic)
    ));
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn a_failed_write_poisoned_writer_cannot_append_again() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("failed-write");
    let mut journal = Journal::create(&path).unwrap();
    append_plan_approved(&mut journal);
    let before = fs::read(&path).unwrap();
    let hash = journal.terminal_hash();
    journal.file = File::open(&path).unwrap().into();
    assert!(matches!(
        journal.append(timestamp(), start("a")),
        Err(JournalError::Io(_))
    ));
    journal.file = OpenOptions::new().append(true).open(&path).unwrap().into();
    assert!(matches!(
        journal.append(timestamp(), start("a")),
        Err(JournalError::WriteFailed)
    ));
    assert_eq!(journal.terminal_hash(), hash);
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn a_valid_hash_does_not_legalize_an_invalid_execution_sequence() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("invalid-sequence");
    let record = journal_record(0, Sha256Digest::of_bytes([]), timestamp(), start("a")).unwrap();
    let mut file = File::create(&path).unwrap();
    file.write_all(JOURNAL_MAGIC).unwrap();
    write_record(&mut file, &canonical_json_bytes(&record).unwrap()).unwrap();
    drop(file);
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        Journal::read(&path),
        Err(JournalError::InvalidLifecycle(_))
    ));
    assert!(matches!(
        Journal::recover(&path),
        Err(JournalError::InvalidLifecycle(_))
    ));
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn unsuccessful_actions_stop_execution_even_after_reopening() {
    for status in [
        ActionStatus::Failed,
        ActionStatus::Blocked,
        ActionStatus::Findings,
        ActionStatus::Skipped,
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("stopped");
        let mut journal = Journal::create(&path).unwrap();
        append_plan_approved(&mut journal);
        journal.append(timestamp(), start("a")).unwrap();
        journal
            .append(
                timestamp(),
                JournalEvent::ActionFinished {
                    action_id: "a".into(),
                    status,
                    receipt_digest: Sha256Digest::of_bytes(b"failure"),
                },
            )
            .unwrap();
        rejects_without_writing(&mut journal, vec![start("b")]);
        drop(journal);
        let mut reopened = Journal::open(path).unwrap();
        rejects_without_writing(&mut reopened, vec![start("b")]);
        reopened.append(timestamp(), end()).unwrap();
    }
}
