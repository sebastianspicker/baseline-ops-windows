//! Pure validation for authenticated worker replies.

use anyhow::{Result, bail};
use baselineops_domain::{ActionId, ExitCode, PlanId, RunId, Sha256Digest, WorkerResultV3};
use baselineops_windows::{
    BrokerMessage, ElevatedLaunchResult, ElevatedLaunchStatus, PlatformError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApprovalSend {
    Approval,
    Cancellation,
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn send_approval_with_cancellation(
    mut is_cancelled: impl FnMut() -> bool,
    mut send: impl FnMut(ApprovalSend) -> Result<()>,
) -> Result<bool> {
    if is_cancelled() {
        return Err(PlatformError::ElevationCancelled.into());
    }
    send(ApprovalSend::Approval)?;
    if !is_cancelled() {
        return Ok(false);
    }
    send(ApprovalSend::Cancellation)?;
    Ok(true)
}

pub(crate) enum StartupPoll<C, E> {
    Connected(C),
    LauncherFinished,
    Retry,
    ConnectionFailed(E),
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn select_startup_poll<C, E>(
    connection: std::result::Result<C, E>,
    launcher_finished: bool,
    before_deadline: bool,
) -> StartupPoll<C, E> {
    match connection {
        Ok(connection) => StartupPoll::Connected(connection),
        Err(_) if launcher_finished => StartupPoll::LauncherFinished,
        Err(_) if before_deadline => StartupPoll::Retry,
        Err(error) => StartupPoll::ConnectionFailed(error),
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn early_worker_completion_error(
    completion: std::thread::Result<std::result::Result<ElevatedLaunchResult, PlatformError>>,
) -> anyhow::Error {
    match completion {
        Ok(Err(error)) => error.into(),
        Err(_) => anyhow::anyhow!("elevation launcher panicked before pipe connection"),
        Ok(Ok(result)) => early_launch_status_error(&result.status),
    }
}

fn early_launch_status_error(status: &ElevatedLaunchStatus) -> anyhow::Error {
    match status {
        ElevatedLaunchStatus::Cancelled => PlatformError::ElevationCancelled.into(),
        ElevatedLaunchStatus::TimedOut => {
            anyhow::anyhow!("elevated worker timed out before authenticated pipe connection")
        }
        ElevatedLaunchStatus::Exited(code) => anyhow::anyhow!(
            "elevated worker exited with code {code} before authenticated pipe connection"
        ),
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const fn map_worker_exit_status(status: &ElevatedLaunchStatus) -> ExitCode {
    match status {
        ElevatedLaunchStatus::Exited(code) if *code == ExitCode::Completed.as_i32() => {
            ExitCode::Completed
        }
        ElevatedLaunchStatus::Exited(code) if *code == ExitCode::Warnings.as_i32() => {
            ExitCode::Warnings
        }
        ElevatedLaunchStatus::Exited(code) if *code == ExitCode::Unsupported.as_i32() => {
            ExitCode::Unsupported
        }
        ElevatedLaunchStatus::Exited(code) if *code == ExitCode::Rejected.as_i32() => {
            ExitCode::Rejected
        }
        ElevatedLaunchStatus::Exited(code) if *code == ExitCode::Cancelled.as_i32() => {
            ExitCode::Cancelled
        }
        ElevatedLaunchStatus::Exited(_) | ElevatedLaunchStatus::TimedOut => {
            ExitCode::ExecutionFailure
        }
        ElevatedLaunchStatus::Cancelled => ExitCode::Cancelled,
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn progress_action_belongs_to_plan(
    action_id: Option<ActionId>,
    mut proposed: impl Iterator<Item = ActionId>,
) -> bool {
    action_id.is_none_or(|action_id| proposed.any(|candidate| candidate == action_id))
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn parse_worker_result(
    reply: &BrokerMessage,
    expected_plan_id: PlanId,
    expected_run_id: RunId,
    expected_digest: Sha256Digest,
) -> Result<WorkerResultV3> {
    if reply.kind != "plan.result" {
        bail!("worker did not return the required plan.result reply kind");
    }
    let result: WorkerResultV3 = serde_json::from_value(reply.payload.clone())?;
    result.validate()?;
    if result.plan_id != expected_plan_id
        || result.run_id != expected_run_id
        || result.plan_digest != expected_digest
    {
        bail!("worker result payload is not bound to the approved plan and run");
    }
    Ok(result)
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn reconcile_worker_exit(result: &WorkerResultV3, exit: ExitCode) -> Result<()> {
    if exit != ExitCode::for_status(result.final_status) {
        bail!("worker process exit disagrees with its authenticated plan.result payload");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use baselineops_domain::{ResultStatus, SchemaVersion};
    use baselineops_windows::{BrokerBinding, PROTOCOL_VERSION};

    fn fixture() -> (BrokerMessage, PlanId, RunId, Sha256Digest) {
        let plan_id = PlanId::new();
        let run_id = RunId::new();
        let digest = Sha256Digest::of_bytes(b"plan");
        let result = WorkerResultV3 {
            schema_version: SchemaVersion::V3,
            plan_id,
            run_id,
            plan_digest: digest,
            journal_terminal_hash: None,
            receipts: Vec::new(),
            artifact_manifest: Vec::new(),
            final_status: ResultStatus::Unsupported,
            reason: Some("evidence gate is open".into()),
            exit_code: ExitCode::Unsupported.as_i32(),
        };
        (
            BrokerMessage {
                version: PROTOCOL_VERSION,
                binding: BrokerBinding {
                    session_id: "0123456789abcdef0123456789abcdef".into(),
                    plan_id: plan_id.to_string(),
                    plan_digest: digest.to_hex(),
                    reply_to: Some("fedcba9876543210fedcba9876543210".into()),
                },
                nonce: "11111111111111111111111111111111".into(),
                kind: "plan.result".into(),
                payload: serde_json::to_value(result).expect("result"),
            },
            plan_id,
            run_id,
            digest,
        )
    }

    #[test]
    fn exact_result_kind_schema_and_bindings_are_required() {
        let (message, plan_id, run_id, digest) = fixture();
        parse_worker_result(&message, plan_id, run_id, digest).expect("valid result");

        for field in ["kind", "plan", "run", "digest", "extra"] {
            let (mut altered, plan_id, run_id, digest) = fixture();
            match field {
                "kind" => altered.kind = "plan.proposal".into(),
                "plan" => altered.payload["plan_id"] = serde_json::json!(PlanId::new()),
                "run" => altered.payload["run_id"] = serde_json::json!(RunId::new()),
                "digest" => {
                    altered.payload["plan_digest"] =
                        serde_json::json!(Sha256Digest::of_bytes(b"other"));
                }
                "extra" => altered.payload["unexpected"] = serde_json::json!(true),
                _ => unreachable!(),
            }
            assert!(
                parse_worker_result(&altered, plan_id, run_id, digest).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn process_exit_must_agree_with_authenticated_status() {
        let (message, plan_id, run_id, digest) = fixture();
        let result = parse_worker_result(&message, plan_id, run_id, digest).expect("result");
        reconcile_worker_exit(&result, ExitCode::Unsupported).expect("matching exit");
        assert!(reconcile_worker_exit(&result, ExitCode::Completed).is_err());
    }

    #[test]
    fn every_stable_worker_process_exit_is_preserved() {
        for expected in [
            ExitCode::Completed,
            ExitCode::ExecutionFailure,
            ExitCode::Warnings,
            ExitCode::Unsupported,
            ExitCode::Rejected,
            ExitCode::Cancelled,
        ] {
            assert_eq!(
                map_worker_exit_status(&ElevatedLaunchStatus::Exited(expected.as_i32())),
                expected
            );
        }
        assert_eq!(
            map_worker_exit_status(&ElevatedLaunchStatus::Exited(99)),
            ExitCode::ExecutionFailure
        );
        assert_eq!(
            map_worker_exit_status(&ElevatedLaunchStatus::TimedOut),
            ExitCode::ExecutionFailure
        );
        assert_eq!(
            map_worker_exit_status(&ElevatedLaunchStatus::Cancelled),
            ExitCode::Cancelled
        );
    }

    #[test]
    fn progress_action_must_belong_to_the_worker_proposal() {
        let first = ActionId::new();
        let second = ActionId::new();
        assert!(progress_action_belongs_to_plan(None, [first].into_iter()));
        assert!(progress_action_belongs_to_plan(
            Some(first),
            [first, second].into_iter()
        ));
        assert!(!progress_action_belongs_to_plan(
            Some(ActionId::new()),
            [first, second].into_iter()
        ));
    }

    #[test]
    fn cancellation_before_approval_grants_no_authority() {
        let mut sent = Vec::new();
        let error = send_approval_with_cancellation(
            || true,
            |message| {
                sent.push(message);
                Ok(())
            },
        )
        .expect_err("cancelled before approval");
        assert!(sent.is_empty());
        assert_eq!(crate::classify_error(&error), ExitCode::Cancelled);
    }

    #[test]
    fn cancellation_during_approval_is_the_next_write() {
        let mut observations = [false, true].into_iter();
        let mut sent = Vec::new();
        let cancellation_sent = send_approval_with_cancellation(
            || observations.next().expect("bounded observation"),
            |message| {
                sent.push(message);
                Ok(())
            },
        )
        .expect("approval and cancellation writes");
        assert!(cancellation_sent);
        assert_eq!(sent, [ApprovalSend::Approval, ApprovalSend::Cancellation]);
    }

    #[test]
    fn connected_pipe_wins_without_consuming_the_launcher() {
        let selected = select_startup_poll::<_, &str>(Ok(7_u8), true, false);
        assert!(matches!(selected, StartupPoll::Connected(7)));
    }

    #[test]
    fn early_launcher_outcomes_never_claim_unauthenticated_success() {
        for code in [
            ExitCode::Completed,
            ExitCode::ExecutionFailure,
            ExitCode::Warnings,
            ExitCode::Unsupported,
            ExitCode::Rejected,
            ExitCode::Cancelled,
        ] {
            let result = ElevatedLaunchResult {
                executable: "worker.exe".into(),
                status: ElevatedLaunchStatus::Exited(code.as_i32()),
            };
            let error = early_worker_completion_error(Ok(Ok(result)));
            assert_eq!(crate::classify_error(&error), ExitCode::ExecutionFailure);
            assert!(error.to_string().contains(&code.as_i32().to_string()));
        }
    }

    #[test]
    fn early_cancel_timeout_error_and_panic_are_distinct() {
        for completion in [
            Ok(Err(PlatformError::ElevationCancelled)),
            Ok(Ok(ElevatedLaunchResult {
                executable: "worker.exe".into(),
                status: ElevatedLaunchStatus::Cancelled,
            })),
        ] {
            let error = early_worker_completion_error(completion);
            assert_eq!(crate::classify_error(&error), ExitCode::Cancelled);
        }
        let timeout = early_worker_completion_error(Ok(Ok(ElevatedLaunchResult {
            executable: "worker.exe".into(),
            status: ElevatedLaunchStatus::TimedOut,
        })));
        assert_eq!(crate::classify_error(&timeout), ExitCode::ExecutionFailure);
        let rejected = early_worker_completion_error(Ok(Err(PlatformError::TrustFailure(
            "bad signer".into(),
        ))));
        assert_eq!(crate::classify_error(&rejected), ExitCode::Rejected);
        let panic = early_worker_completion_error(Err(Box::new("panic")));
        assert_eq!(crate::classify_error(&panic), ExitCode::ExecutionFailure);
    }
}
