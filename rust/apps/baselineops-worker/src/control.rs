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
            // The result has left the channel: a deadline while flushing the last progress must
            // not discard it. Delivery gets its own bounded deadline in `recover_finished`.
            if let Err(error) = forward_progress(transport, binding, progress, deadline)
                && error.downcast_ref::<DeadlineExceeded>().is_none()
            {
                return Err(error);
            }
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

/// Typed so [`recover_finished`] can tell a plain deadline from a protocol failure.
#[derive(Debug)]
pub(super) struct DeadlineExceeded;

impl std::fmt::Display for DeadlineExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("worker control session exceeded its deadline")
    }
}

impl std::error::Error for DeadlineExceeded {}

const RESULT_DELIVERY: Duration = Duration::from_secs(10);

/// After the executor thread has joined, every finished apply result may use up to
/// [`RESULT_DELIVERY`] past the session deadline for its final send. A deadline-only control
/// failure keeps a result that already finished; every other failure, or no finished
/// result, stays an error.
pub(super) fn recover_finished(
    outcome: Result<WorkerResultV3>,
    results: &Receiver<Result<WorkerResultV3>>,
    deadline: Instant,
) -> Result<(WorkerResultV3, Instant)> {
    let delivery = deadline.max(Instant::now() + RESULT_DELIVERY);
    match outcome {
        Ok(result) => Ok((result, delivery)),
        Err(error) if error.downcast_ref::<DeadlineExceeded>().is_some() => {
            match results.try_recv() {
                Ok(Ok(result)) => Ok((result, delivery)),
                _ => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

fn require_time(deadline: Instant) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(DeadlineExceeded.into());
    }
    Ok(remaining)
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;
