use super::{ProposalRequest, apply_result, trust};
use crate::control::{self, ControlTransport};
use anyhow::Result;
use baselineops_domain::WorkerResultV3;
use baselineops_engine::{CancellationToken, WorkerApplyAuthority};
use baselineops_windows::ipc::NamedPipeClient;
use baselineops_windows::{BrokerMessage, FrameCodec, TrustedInstallation};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub(super) fn execute_session(
    client: &mut NamedPipeClient,
    authority: WorkerApplyAuthority,
    request: &ProposalRequest,
    approval: &BrokerMessage,
    trust: &TrustedInstallation,
    signer: &trust::ReleaseSignerIdentity,
    deadline: Instant,
) -> Result<WorkerResultV3> {
    let cancellation = CancellationToken::default();
    let (result_tx, result_rx) = mpsc::channel();
    let (progress_tx, progress_rx) = mpsc::sync_channel(4);
    std::thread::scope(|scope| {
        let token = &cancellation;
        scope.spawn(move || {
            let result = apply_result(
                authority,
                request,
                approval,
                trust,
                signer,
                token,
                progress_tx,
            );
            let _ = result_tx.send(result);
        });
        control::run(
            &mut PipeTransport(client),
            approval,
            &cancellation,
            &result_rx,
            &progress_rx,
            deadline,
        )
    })
}

pub(super) fn send_result(
    client: &mut NamedPipeClient,
    proposal: &BrokerMessage,
    approval_nonce: String,
    result: WorkerResultV3,
    deadline: Instant,
) -> Result<()> {
    control::send_terminal(
        &mut PipeTransport(client),
        proposal,
        approval_nonce,
        result,
        deadline,
    )
}

struct PipeTransport<'a>(&'a mut NamedPipeClient);

impl ControlTransport for PipeTransport<'_> {
    fn receive(&mut self, timeout: Duration) -> Result<Option<BrokerMessage>> {
        self.0
            .receive_timeout(timeout)?
            .map(|frame| FrameCodec::decode(&frame.0).map_err(Into::into))
            .transpose()
    }

    fn send(&mut self, message: &BrokerMessage, timeout: Duration) -> Result<()> {
        message.validate()?;
        self.0
            .send_timeout(&FrameCodec::encode(message)?, timeout)?;
        Ok(())
    }
}
