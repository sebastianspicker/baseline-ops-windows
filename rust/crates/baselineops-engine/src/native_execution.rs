//! Sealed native worker dispatch. Review metadata is never executable input.

mod action;
mod native;

use crate::{ApprovedWorkerApply, CancellationToken, VerifiedPlan};
use baselineops_domain::{ActionId, ExitCode, ResultStatus, SchemaVersion, WorkerResultV3};
use baselineops_windows::TrustedInstallation;
use std::sync::mpsc::SyncSender;

/// Durable action stage emitted as bounded, non-authoritative progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeActionPhase {
    /// The start record is durable.
    Started,
    /// A terminal receipt is durable.
    Finished,
}

/// Action progress without values, paths, or executable input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeActionProgress {
    /// Exact action identifier retained by worker approval.
    pub action_id: ActionId,
    /// Last durable stage.
    pub phase: NativeActionPhase,
}

/// Consume the worker's opaque approval through the fixed native dispatcher.
///
/// The first supported execution slice contains one Windows Update action. Registry and
/// evidence eligibility remain separate gates; this function cannot manufacture approval.
/// The token retains the installation proof for the duration of synchronous execution.
///
/// ```compile_fail
/// use baselineops_domain::PlanV4;
/// use baselineops_engine::{CancellationToken, execute_approved_worker_apply};
/// fn raw_plan_cannot_dispatch(plan: PlanV4) {
///     execute_approved_worker_apply(plan, &CancellationToken::default());
/// }
/// ```
///
/// ```compile_fail
/// use baselineops_engine::{ApprovedWorkerApply, CancellationToken, execute_approved_worker_apply};
/// fn approval_cannot_be_replayed(token: ApprovedWorkerApply<'_>) {
///     let cancellation = CancellationToken::default();
///     execute_approved_worker_apply(token, &cancellation);
///     execute_approved_worker_apply(token, &cancellation);
/// }
/// ```
///
/// # Errors
///
/// Returns an error when authority, host, freshness, typed admission, or final result validation
/// fails. Action failures return a structured failed result with the last durable journal anchor
/// whenever a trustworthy result can be assembled.
pub fn execute_approved_worker_apply(
    approved: ApprovedWorkerApply<'_>,
    cancellation: &CancellationToken,
) -> Result<WorkerResultV3, NativeExecutionError> {
    dispatch(approved, cancellation, None)
}

/// Consume approval while reporting durable action stages through a bounded channel.
/// A slow or disconnected progress consumer cannot interrupt an action or grant authority.
///
/// # Errors
/// Returns the same authority and result-validation failures as `execute_approved_worker_apply`.
pub fn execute_approved_worker_apply_with_progress(
    approved: ApprovedWorkerApply<'_>,
    cancellation: &CancellationToken,
    progress: SyncSender<NativeActionProgress>,
) -> Result<WorkerResultV3, NativeExecutionError> {
    dispatch(approved, cancellation, Some(progress))
}

fn dispatch(
    approved: ApprovedWorkerApply<'_>,
    cancellation: &CancellationToken,
    progress: Option<SyncSender<NativeActionProgress>>,
) -> Result<WorkerResultV3, NativeExecutionError> {
    let (verified, intents, installation) = approved.into_parts();
    require_boundary(&verified, installation)?;
    let (action_id, capability, plan) = intents.into_windows_update()?;
    let mut port = match native::NativeActionPort::create(&verified, progress) {
        Ok(port) => port,
        Err(error) => return Ok(setup_failure(&verified, &error)),
    };
    if cancellation.is_cancelled() {
        let result = result_base(
            &verified,
            ResultStatus::Cancelled,
            Some("Cancelled before action execution.".into()),
        );
        return port.finish(result, true, false);
    }
    let outcome = action::execute_windows_update(action_id, capability, &plan, &mut port);
    let mut result = action_result(&verified, &outcome);
    result.receipts.extend(outcome.receipt);
    port.finish(result, outcome.may_finish_run, outcome.reboot_possible)
}

fn require_boundary(
    verified: &VerifiedPlan,
    installation: &TrustedInstallation,
) -> Result<(), NativeExecutionError> {
    if chrono::Utc::now() >= verified.plan().expires_at {
        return Err(NativeExecutionError::Rejected(
            "approval expired before dispatch",
        ));
    }
    if installation.root() != verified.trusted_root() || verified.plan().actions.len() != 1 {
        return Err(NativeExecutionError::Rejected(
            "installation or action scope differs from approval",
        ));
    }
    if baselineops_windows::collect_host_identity()
        .map_err(|_| NativeExecutionError::Rejected("host identity could not be revalidated"))?
        != verified.plan().host
    {
        return Err(NativeExecutionError::Rejected(
            "host identity changed before dispatch",
        ));
    }
    Ok(())
}

fn action_result(verified: &VerifiedPlan, outcome: &action::ActionOutcome) -> WorkerResultV3 {
    if let Some(failure) = &outcome.failure {
        let detail = bounded_detail(&failure.detail);
        let recovery = if failure.mutation_attempted {
            " Changes may have occurred. Review recovery.json and independently restore captured values; no automatic rollback was performed. A reboot may be required."
        } else {
            " No native mutation was attempted."
        };
        return result_base(
            verified,
            failure_status(failure.phase),
            Some(format!("{:?} failed: {detail}.{recovery}", failure.phase)),
        );
    }
    let reason = outcome
        .reboot_possible
        .then(|| "Policy changes verified. A reboot may be required.".into());
    result_base(verified, ResultStatus::Completed, reason)
}

fn failure_status(phase: action::FailurePhase) -> ResultStatus {
    match phase {
        action::FailurePhase::Precondition => ResultStatus::Rejected,
        action::FailurePhase::RecoveryEvidence
        | action::FailurePhase::Journal
        | action::FailurePhase::Mutation
        | action::FailurePhase::Postcondition => ResultStatus::ExecutionFailed,
    }
}

fn setup_failure(verified: &VerifiedPlan, error: &NativeExecutionError) -> WorkerResultV3 {
    result_base(
        verified,
        ResultStatus::ExecutionFailed,
        Some(format!(
            "Protected run setup failed before action execution: {}",
            bounded_detail(&error.to_string())
        )),
    )
}

fn result_base(
    verified: &VerifiedPlan,
    status: ResultStatus,
    reason: Option<String>,
) -> WorkerResultV3 {
    let plan = verified.plan();
    WorkerResultV3 {
        schema_version: SchemaVersion::V3,
        plan_id: plan.id,
        run_id: plan.run_id,
        plan_digest: verified.digest(),
        journal_terminal_hash: None,
        receipts: Vec::new(),
        artifact_manifest: Vec::new(),
        final_status: status,
        reason,
        exit_code: ExitCode::for_status(status).as_i32(),
    }
}

fn bounded_detail(detail: &str) -> String {
    detail.chars().take(512).collect()
}

/// Failure to admit or prepare native dispatch, distinct from a structured action failure.
#[derive(Debug, thiserror::Error)]
pub enum NativeExecutionError {
    /// Typed authority or live bindings failed before dispatch.
    #[error("native dispatch rejected: {0}")]
    Rejected(&'static str),
    /// The approval proof failed its retained action binding.
    #[error(transparent)]
    Approval(#[from] crate::ApprovalError),
    /// The Windows trust or output boundary failed.
    #[error(transparent)]
    Platform(#[from] baselineops_windows::PlatformError),
    /// Journal initialization or durability failed.
    #[error(transparent)]
    Journal(#[from] crate::JournalError),
    /// A canonical result or recovery document could not be validated.
    #[error(transparent)]
    Domain(#[from] baselineops_domain::DomainError),
}

impl NativeExecutionError {
    /// Result classification when dispatch cannot assemble a structured result.
    pub const fn result_status(&self) -> ResultStatus {
        match self {
            Self::Rejected(_) | Self::Approval(_) => ResultStatus::Rejected,
            Self::Platform(_) | Self::Journal(_) | Self::Domain(_) => ResultStatus::ExecutionFailed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_and_execution_failures_keep_distinct_statuses() {
        assert_eq!(
            failure_status(action::FailurePhase::Precondition),
            ResultStatus::Rejected
        );
        for phase in [
            action::FailurePhase::RecoveryEvidence,
            action::FailurePhase::Journal,
            action::FailurePhase::Mutation,
            action::FailurePhase::Postcondition,
        ] {
            assert_eq!(failure_status(phase), ResultStatus::ExecutionFailed);
        }
        assert_eq!(
            NativeExecutionError::Rejected("expired").result_status(),
            ResultStatus::Rejected
        );
        assert_eq!(
            NativeExecutionError::Approval(crate::ApprovalError::DigestMismatch).result_status(),
            ResultStatus::Rejected
        );
        assert_eq!(
            NativeExecutionError::Journal(crate::JournalError::WriteFailed).result_status(),
            ResultStatus::ExecutionFailed
        );
    }
}
