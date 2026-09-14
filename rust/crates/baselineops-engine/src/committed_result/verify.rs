use super::{CommittedResultError, CommittedWorkerResult, ResultDocument};
use crate::{Journal, JournalEvent, JournalLimits, JournalRecord, JournalSnapshot};
use CommittedResultError::Mismatch;
use baselineops_domain::{
    ActionStatus, ArtifactKind, ArtifactV3, JsonLoadLimits, ResultStatus, Sha256Digest,
    WorkerResultV3, canonical_json_bytes, canonical_json_digest, load_json,
};

pub(super) fn reconcile(
    expected: &WorkerResultV3,
    result_bytes: &[u8],
    journal_bytes: &[u8],
) -> Result<CommittedWorkerResult, CommittedResultError> {
    expected.validate()?;
    let (_, artifact) = super::report_artifact(expected)?;
    let document = decode_document(artifact, result_bytes)?;
    document_binding(&document, expected)?;
    let snapshot = Journal::read_bytes(
        journal_bytes,
        JournalLimits::new(baselineops_windows::MAX_JOURNAL_BYTES as u64, 4096),
    )?;
    journal_binding(&document, expected, artifact.digest, &snapshot)?;
    Ok(CommittedWorkerResult {
        document,
        bytes: result_bytes.to_vec(),
    })
}

fn decode_document(
    artifact: &ArtifactV3,
    result_bytes: &[u8],
) -> Result<ResultDocument, CommittedResultError> {
    if result_bytes.len() as u64 != artifact.size_bytes
        || Sha256Digest::of_bytes(result_bytes) != artifact.digest
    {
        return Err(Mismatch(
            "result bytes differ from the authenticated manifest",
        ));
    }
    let document: ResultDocument = load_json(result_bytes, JsonLoadLimits::default())?;
    if document.schema_version != "1.0" || canonical_json_bytes(&document)? != result_bytes {
        return Err(Mismatch(
            "result document schema or canonical encoding differs",
        ));
    }
    Ok(document)
}

pub(super) fn artifact_scope(
    artifact: &ArtifactV3,
    directory: &str,
) -> Result<(), CommittedResultError> {
    let (actual_directory, leaf) = artifact
        .locator
        .split_once('/')
        .ok_or(Mismatch("artifact locator is outside the fixed run"))?;
    let kind = match leaf {
        "result.json" => ArtifactKind::Report,
        "recovery.json" => ArtifactKind::RollbackState,
        "evidence.json" => ArtifactKind::Evidence,
        _ => return Err(Mismatch("artifact name is not a fixed run artifact")),
    };
    if actual_directory != directory
        || artifact.kind != kind
        || artifact.media_type != "application/json"
        || artifact.size_bytes > baselineops_windows::MAX_EVIDENCE_BYTES as u64
    {
        return Err(Mismatch(
            "artifact scope, kind, media type, or size differs",
        ));
    }
    Ok(())
}

fn document_binding(
    document: &ResultDocument,
    expected: &WorkerResultV3,
) -> Result<(), CommittedResultError> {
    let expected_identity = (expected.plan_id, expected.run_id, expected.plan_digest);
    if (document.plan_id, document.run_id, document.plan_digest) != expected_identity {
        return Err(Mismatch(
            "result document identity differs from the authenticated envelope",
        ));
    }
    document_outcome(document, expected)?;
    if document.status == ResultStatus::Completed
        && document
            .receipts
            .iter()
            .any(|receipt| receipt.status != ActionStatus::Succeeded)
    {
        return Err(Mismatch("completed result contains an unsuccessful action"));
    }
    Ok(())
}

fn document_outcome(
    document: &ResultDocument,
    expected: &WorkerResultV3,
) -> Result<(), CommittedResultError> {
    let expected_outcome = (expected.final_status, &expected.reason, &expected.receipts);
    if (document.status, &document.reason, &document.receipts) != expected_outcome
        || document.artifacts != expected.artifact_manifest[..expected.artifact_manifest.len() - 1]
    {
        return Err(Mismatch(
            "result document outcome differs from the authenticated envelope",
        ));
    }
    Ok(())
}

fn journal_binding(
    document: &ResultDocument,
    expected: &WorkerResultV3,
    digest: Sha256Digest,
    snapshot: &JournalSnapshot,
) -> Result<(), CommittedResultError> {
    if Some(snapshot.terminal_hash) != expected.journal_terminal_hash {
        return Err(Mismatch(
            "journal differs from the authenticated terminal anchor",
        ));
    }
    let records = &snapshot.records;
    let Some((first, remainder)) = records.split_first() else {
        return Err(Mismatch("journal has no approval"));
    };
    let Some((last, actions)) = remainder.split_last() else {
        return Err(Mismatch("journal has no terminal commit"));
    };
    commit_binding(document, digest, first, last)?;
    receipt_binding(document, actions)
}

fn commit_binding(
    document: &ResultDocument,
    digest: Sha256Digest,
    first: &JournalRecord,
    last: &JournalRecord,
) -> Result<(), CommittedResultError> {
    if !matches!(first.payload, JournalEvent::PlanApproved { plan_id, plan_digest }
        if (plan_id, plan_digest) == (document.plan_id, document.plan_digest))
    {
        return Err(Mismatch("journal approval differs from the result"));
    }
    if last.previous_hash != document.journal_prefix_hash
        || !matches!(last.payload, JournalEvent::RunFinished { result_id, result_digest }
            if (result_id, result_digest) == (document.result_id, digest))
    {
        return Err(Mismatch("result has no matching terminal commit"));
    }
    Ok(())
}

fn receipt_binding(
    document: &ResultDocument,
    records: &[JournalRecord],
) -> Result<(), CommittedResultError> {
    if records.len() != document.receipts.len() * 2 {
        return Err(Mismatch("journal action count differs from the receipts"));
    }
    for (receipt, records) in document.receipts.iter().zip(records.chunks_exact(2)) {
        receipt_pair(receipt, records)?;
    }
    Ok(())
}

fn receipt_pair(
    receipt: &baselineops_domain::ActionReceiptV3,
    records: &[JournalRecord],
) -> Result<(), CommittedResultError> {
    let id = receipt.action_id.to_string();
    if !matches!(&records[0].payload, JournalEvent::ActionStarted { action_id, pre_state_digest }
        if (action_id, *pre_state_digest) == (&id, receipt.pre_state_digest))
    {
        return Err(Mismatch("journal start differs from the receipt"));
    }
    let digest = canonical_json_digest(receipt)?;
    if !matches!(&records[1].payload, JournalEvent::ActionFinished { action_id, status, receipt_digest }
        if (action_id, *status, *receipt_digest) == (&id, receipt.status, digest))
    {
        return Err(Mismatch("journal completion differs from the receipt"));
    }
    Ok(())
}
