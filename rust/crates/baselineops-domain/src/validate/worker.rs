use std::collections::BTreeSet;

use crate::{DomainError, DomainResult, ResultStatus, WorkerResultV3};

use super::{validate_artifacts, validate_nonempty, validation};

const MAX_RECEIPTS: usize = 512;
const MAX_ARTIFACTS: usize = 1_024;
const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;

pub(crate) fn validate_worker_result(result: &WorkerResultV3) -> DomainResult<()> {
    validate_worker_preconditions(result)?;
    validate_worker_evidence(result)?;
    Ok(())
}

fn validate_worker_preconditions(result: &WorkerResultV3) -> DomainResult<()> {
    validate_exit_code(result)?;
    validate_reason(result)?;
    validate_unsupported_evidence(result)?;
    validate_completed_journal(result)?;
    validate_evidence_journal(result)?;
    Ok(())
}

fn validate_worker_evidence(result: &WorkerResultV3) -> DomainResult<()> {
    validate_entry_counts(result)?;
    validate_receipt_ids(result)?;
    validate_artifacts(&result.artifact_manifest)?;
    validate_artifact_locations(result)?;
    Ok(())
}

fn validate_exit_code(result: &WorkerResultV3) -> DomainResult<()> {
    if result.exit_code != crate::ExitCode::for_status(result.final_status).as_i32() {
        return validation("worker result status and exit code disagree");
    }
    Ok(())
}

fn validate_reason(result: &WorkerResultV3) -> DomainResult<()> {
    validate_optional_reason(result)?;
    validate_required_reason(result)
}

fn validate_optional_reason(result: &WorkerResultV3) -> DomainResult<()> {
    if let Some(reason) = &result.reason {
        validate_nonempty("worker result reason", reason, 4096)?;
    }
    Ok(())
}

fn validate_required_reason(result: &WorkerResultV3) -> DomainResult<()> {
    if requires_reason(result.final_status) && result.reason.is_none() {
        return validation("non-success worker result must explain its terminal status");
    }
    Ok(())
}

fn requires_reason(status: ResultStatus) -> bool {
    const REASON_REQUIRED: [ResultStatus; 4] = [
        ResultStatus::ExecutionFailed,
        ResultStatus::Unsupported,
        ResultStatus::Rejected,
        ResultStatus::Cancelled,
    ];
    REASON_REQUIRED.contains(&status)
}

fn validate_unsupported_evidence(result: &WorkerResultV3) -> DomainResult<()> {
    if result.final_status == ResultStatus::Unsupported && has_mutation_evidence(result) {
        return validation("unsupported worker result must not carry mutation evidence");
    }
    Ok(())
}

fn has_mutation_evidence(result: &WorkerResultV3) -> bool {
    result.journal_terminal_hash.is_some()
        || !result.receipts.is_empty()
        || !result.artifact_manifest.is_empty()
}

fn validate_completed_journal(result: &WorkerResultV3) -> DomainResult<()> {
    if journal_required(result.final_status) && result.journal_terminal_hash.is_none() {
        return validation("completed worker result requires an anchored journal terminal hash");
    }
    Ok(())
}

fn journal_required(status: ResultStatus) -> bool {
    const JOURNAL_REQUIRED: [ResultStatus; 2] = [ResultStatus::Completed, ResultStatus::Warnings];
    JOURNAL_REQUIRED.contains(&status)
}

fn validate_evidence_journal(result: &WorkerResultV3) -> DomainResult<()> {
    if has_receipts_or_artifacts(result) && result.journal_terminal_hash.is_none() {
        return validation("worker receipts and artifacts require an anchored journal");
    }
    Ok(())
}

fn has_receipts_or_artifacts(result: &WorkerResultV3) -> bool {
    !result.receipts.is_empty() || !result.artifact_manifest.is_empty()
}

fn validate_entry_counts(result: &WorkerResultV3) -> DomainResult<()> {
    if result.receipts.len() > MAX_RECEIPTS || result.artifact_manifest.len() > MAX_ARTIFACTS {
        return validation("worker result exceeds receipt or artifact count limits");
    }
    Ok(())
}

fn validate_receipt_ids(result: &WorkerResultV3) -> DomainResult<()> {
    let mut receipt_ids = BTreeSet::new();
    for receipt in &result.receipts {
        validate_receipt_id(&mut receipt_ids, receipt.action_id)?;
    }
    Ok(())
}

fn validate_receipt_id(
    receipt_ids: &mut BTreeSet<crate::ActionId>,
    receipt_id: crate::ActionId,
) -> DomainResult<()> {
    if !receipt_ids.insert(receipt_id) {
        return validation("worker result contains duplicate action receipts");
    }
    Ok(())
}

fn validate_artifact_locations(result: &WorkerResultV3) -> DomainResult<()> {
    let mut locators = BTreeSet::new();
    let total = sum_artifact_sizes(&result.artifact_manifest, &mut locators)?;
    if total > MAX_ARTIFACT_BYTES {
        return validation("worker artifact manifest exceeds its byte limit");
    }
    Ok(())
}

fn sum_artifact_sizes<'a>(
    artifacts: &'a [crate::ArtifactV3],
    locators: &mut BTreeSet<&'a str>,
) -> DomainResult<u64> {
    let mut total = 0_u64;
    for artifact in artifacts {
        validate_artifact_locator(locators, &artifact.locator)?;
        total = total
            .checked_add(artifact.size_bytes)
            .ok_or_else(|| DomainError::Validation("worker artifact size overflowed".into()))?;
    }
    Ok(total)
}

fn validate_artifact_locator<'a>(
    locators: &mut BTreeSet<&'a str>,
    locator: &'a str,
) -> DomainResult<()> {
    if !locators.insert(locator) {
        return validation("worker artifact locators must be unique");
    }
    Ok(())
}
