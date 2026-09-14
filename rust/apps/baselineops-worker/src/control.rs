//! Single-owner transport pump while the sealed executor runs on a scoped thread.

use anyhow::{Result, bail};
use baselineops_domain::WorkerResultV3;
use baselineops_engine::{CancellationToken, NativeActionPhase, NativeActionProgress};
use baselineops_windows::BrokerMessage;
use baselineops_windows::ipc::{ApprovalControl, ProgressPhase, WorkerProgress};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

pub(super) trait ControlTransport {
    fn receive(&mut self, timeout: Duration) -> Result<Option<BrokerMessage>>;
    fn send(&mut self, message: &BrokerMessage, timeout: Duration) -> Result<()>;
}

pub(super) fn run(
    transport: &mut impl ControlTransport,
    approval: &BrokerMessage,
    cancellation: &CancellationToken,
    results: &Receiver<Result<WorkerResultV3>>,
    progress: &Receiver<NativeActionProgress>,
    deadline: Instant,
) -> Result<WorkerResultV3> {
    let result = (|| {
        let now = Instant::now();
        let mut binding = ApprovalControl::new(approval, now)?;
        report(
            transport,
            &binding,
            ProgressPhase::Preparing,
            None,
            deadline,
        )?;
        pump(
            transport,
            &mut binding,
            cancellation,
            results,
            progress,
            deadline,
        )
    })();
    if result.is_err() {
        cancellation.cancel();
    }
    result
}

pub(super) fn send_terminal(
    transport: &mut impl ControlTransport,
    proposal: &BrokerMessage,
    approval_nonce: String,
    result: WorkerResultV3,
    deadline: Instant,
) -> Result<()> {
    require_time(deadline)?;
    let reply = crate::responses::result_message(proposal, approval_nonce, result)?;
    transport.send(&reply, require_time(deadline)?)
}

fn pump(
    transport: &mut impl ControlTransport,
    binding: &mut ApprovalControl,
    cancellation: &CancellationToken,
    results: &Receiver<Result<WorkerResultV3>>,
    progress: &Receiver<NativeActionProgress>,
    deadline: Instant,
) -> Result<WorkerResultV3> {
    loop {
        require_time(deadline)?;
        forward_progress(transport, binding, progress, deadline)?;
        if let Some(result) = take_finished(transport, binding, results, progress, deadline)? {
            return Ok(result);
        }
        receive_cancellation(transport, binding, cancellation, deadline)?;
    }
}

fn take_finished(
    transport: &mut impl ControlTransport,
    binding: &ApprovalControl,
    results: &Receiver<Result<WorkerResultV3>>,
    progress: &Receiver<NativeActionProgress>,
    deadline: Instant,
) -> Result<Option<WorkerResultV3>> {
    match results.try_recv() {
        Ok(result) => {
            forward_progress(transport, binding, progress, deadline)?;
            require_time(deadline)?;
            result.map(Some)
        }
        Err(TryRecvError::Empty) => Ok(None),
        Err(TryRecvError::Disconnected) => bail!("sealed executor closed without a result"),
    }
}

fn receive_cancellation(
    transport: &mut impl ControlTransport,
    binding: &mut ApprovalControl,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<()> {
    let remaining = require_time(deadline)?;
    let Some(message) = transport.receive(remaining.min(Duration::from_millis(50)))? else {
        return Ok(());
    };
    require_time(deadline)?;
    binding.accept_cancellation(&message, Instant::now())?;
    cancellation.cancel();
    report(
        transport,
        binding,
        ProgressPhase::CancellationPending,
        None,
        deadline,
    )
}

fn forward_progress(
    transport: &mut impl ControlTransport,
    binding: &ApprovalControl,
    progress: &Receiver<NativeActionProgress>,
    deadline: Instant,
) -> Result<()> {
    // The producer uses a four-entry nonblocking channel. Drain only that bound per turn.
    for item in progress.try_iter().take(4) {
        let phase = match item.phase {
            NativeActionPhase::Started => ProgressPhase::ActionStarted,
            NativeActionPhase::Finished => ProgressPhase::ActionFinished,
        };
        report(transport, binding, phase, Some(item.action_id), deadline)?;
    }
    Ok(())
}

fn report(
    transport: &mut impl ControlTransport,
    binding: &ApprovalControl,
    phase: ProgressPhase,
    action_id: Option<baselineops_domain::ActionId>,
    deadline: Instant,
) -> Result<()> {
    let message = binding.progress(
        WorkerProgress { phase, action_id },
        uuid::Uuid::new_v4().simple().to_string(),
    )?;
    transport.send(&message, require_time(deadline)?)
}

fn require_time(deadline: Instant) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        bail!("worker control session exceeded its deadline");
    }
    Ok(remaining)
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;
