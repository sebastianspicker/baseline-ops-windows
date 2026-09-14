use super::{WorkerExchange, WorkerProposal, input};
use crate::protocol::ApprovalSend;
use anyhow::{Result, anyhow, bail};
use baselineops_domain::{ExitCode, PlanV3, Sha256Digest, WorkerResultV3, canonical_json_digest};
use baselineops_windows::console_cancellation::ConsoleCancellation;
use baselineops_windows::ipc::{ApprovalControl, ProgressPhase, WorkerProgress};
use baselineops_windows::{BrokerBinding, BrokerMessage, FrameCodec, PROTOCOL_VERSION};
use std::io::Write as _;
use std::time::{Duration, Instant};

const CONTROL_POLL: Duration = Duration::from_millis(50);
const CONTROL_LIFETIME: Duration = Duration::from_mins(2);

pub(super) fn propose(
    exchange: &mut WorkerExchange,
    plan: &PlanV3,
) -> Result<(WorkerProposal, String)> {
    let request = proposal_request(plan, &exchange.pipe_name)?;
    send_message(&mut exchange.client, &request)?;
    receive_proposal(exchange, &request)
}

pub(super) fn approval_request(
    pipe_name: &str,
    response: &WorkerProposal,
    proposal_nonce: String,
    operator_digest: &str,
) -> Result<BrokerMessage> {
    if operator_digest != response.digest {
        bail!("--approve-digest does not match the worker proposal");
    }
    Ok(BrokerMessage {
        version: PROTOCOL_VERSION,
        binding: BrokerBinding {
            session_id: pipe_name.into(),
            plan_id: response.plan.id.to_string(),
            plan_digest: response.digest.clone(),
            reply_to: Some(proposal_nonce),
        },
        nonce: uuid::Uuid::new_v4().simple().to_string(),
        kind: "plan.approve".into(),
        payload: serde_json::json!({"approvedDigest": operator_digest}),
    })
}

pub(super) fn finish(
    mut exchange: WorkerExchange,
    response: &WorkerProposal,
    approval: &BrokerMessage,
) -> Result<ExitCode> {
    let (mut control, cancellation, deadline) = start_control(approval)?;
    let cancellation_sent = authorize_control(
        &mut exchange.client,
        approval,
        &control,
        &cancellation,
        deadline,
    )?;
    let result = receive_result(
        &mut exchange,
        response,
        &mut control,
        &cancellation,
        cancellation_sent,
        deadline,
    )?;
    let exit = exchange.worker_exit()?;
    crate::protocol::reconcile_worker_exit(&result, exit)?;
    super::super::print_json(&result)?;
    Ok(exit)
}

fn authorize_control(
    client: &mut baselineops_windows::ipc::NamedPipeClient,
    approval: &BrokerMessage,
    control: &ApprovalControl,
    cancellation: &ConsoleCancellation,
    deadline: Instant,
) -> Result<bool> {
    crate::protocol::send_approval_with_cancellation(
        || cancellation.is_cancelled(),
        |outbound| match outbound {
            ApprovalSend::Approval => send_control_message(client, approval, deadline),
            ApprovalSend::Cancellation => {
                let message = control.cancellation(uuid::Uuid::new_v4().simple().to_string())?;
                send_control_message(client, &message, deadline)
            }
        },
    )
}

fn start_control(
    approval: &BrokerMessage,
) -> Result<(ApprovalControl, ConsoleCancellation, Instant)> {
    let started = Instant::now();
    let control = ApprovalControl::new(approval, started)?;
    let cancellation = ConsoleCancellation::install()?;
    Ok((control, cancellation, started + CONTROL_LIFETIME))
}

fn proposal_request(plan: &PlanV3, pipe_name: &str) -> Result<BrokerMessage> {
    let profile_source = input::load_profile_source(plan)?;
    Ok(BrokerMessage {
        version: PROTOCOL_VERSION,
        binding: BrokerBinding {
            session_id: pipe_name.into(),
            plan_id: plan.id.to_string(),
            plan_digest: canonical_json_digest(plan)?.to_hex(),
            reply_to: None,
        },
        nonce: uuid::Uuid::new_v4().simple().to_string(),
        kind: "plan.propose".into(),
        payload: serde_json::json!({"plan": plan, "profileSource": profile_source}),
    })
}

fn send_message(
    client: &mut baselineops_windows::ipc::NamedPipeClient,
    message: &BrokerMessage,
) -> Result<()> {
    message.validate()?;
    client.send(&FrameCodec::encode(message)?)?;
    Ok(())
}

fn receive_result(
    exchange: &mut WorkerExchange,
    response: &WorkerProposal,
    control: &mut ApprovalControl,
    cancellation: &ConsoleCancellation,
    mut cancellation_sent: bool,
    deadline: Instant,
) -> Result<WorkerResultV3> {
    loop {
        if let Some(reply) = receive_control_message(&mut exchange.client, deadline)?
            && let Some(result) = accept_control_message(control, &reply, response)?
        {
            return Ok(result);
        }
        cancellation_sent = send_requested_cancellation(
            &mut exchange.client,
            control,
            cancellation,
            cancellation_sent,
            deadline,
        )?;
    }
}

fn receive_control_message(
    client: &mut baselineops_windows::ipc::NamedPipeClient,
    deadline: Instant,
) -> Result<Option<BrokerMessage>> {
    let remaining = remaining_control_time(deadline)?;
    let Some(frame) = client.receive_timeout(CONTROL_POLL.min(remaining))? else {
        return Ok(None);
    };
    remaining_control_time(deadline)?;
    Ok(Some(FrameCodec::decode(&frame.0)?))
}

fn accept_control_message(
    control: &mut ApprovalControl,
    reply: &BrokerMessage,
    response: &WorkerProposal,
) -> Result<Option<WorkerResultV3>> {
    if let Some(progress) = control.accept_worker_message(reply, Instant::now())? {
        validate_progress_action(&progress, &response.plan)?;
        write_progress(&progress);
        return Ok(None);
    }
    Ok(Some(parse_worker_result(reply, response)?))
}

fn send_requested_cancellation(
    client: &mut baselineops_windows::ipc::NamedPipeClient,
    control: &ApprovalControl,
    cancellation: &ConsoleCancellation,
    sent: bool,
    deadline: Instant,
) -> Result<bool> {
    if sent || !cancellation.is_cancelled() {
        return Ok(sent);
    }
    let message = control.cancellation(uuid::Uuid::new_v4().simple().to_string())?;
    send_control_message(client, &message, deadline)?;
    Ok(true)
}

fn send_control_message(
    client: &mut baselineops_windows::ipc::NamedPipeClient,
    message: &BrokerMessage,
    deadline: Instant,
) -> Result<()> {
    let timeout = remaining_control_time(deadline)?;
    message.validate()?;
    client.send_timeout(&FrameCodec::encode(message)?, timeout)?;
    Ok(())
}

fn remaining_control_time(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| anyhow!("worker control exchange exceeded its two-minute deadline"))
}

fn validate_progress_action(progress: &WorkerProgress, plan: &PlanV3) -> Result<()> {
    let Some(action_id) = progress.action_id else {
        return Ok(());
    };
    if !crate::protocol::progress_action_belongs_to_plan(
        Some(action_id),
        plan.actions.iter().map(|action| action.id),
    ) {
        bail!("worker progress names an action outside the approved proposal");
    }
    Ok(())
}

fn write_progress(progress: &WorkerProgress) {
    let phase = match progress.phase {
        ProgressPhase::Preparing => "preparing",
        ProgressPhase::ActionStarted => "action_started",
        ProgressPhase::ActionFinished => "action_finished",
        ProgressPhase::CancellationPending => "cancellation_pending",
    };
    let mut stderr = std::io::stderr().lock();
    if let Some(action_id) = progress.action_id {
        let _ = writeln!(stderr, "worker progress: {phase} action={action_id}");
    } else {
        let _ = writeln!(stderr, "worker progress: {phase}");
    }
}

fn receive_proposal(
    exchange: &mut WorkerExchange,
    request: &BrokerMessage,
) -> Result<(WorkerProposal, String)> {
    let proposal = receive_message(exchange)?;
    if proposal.kind != "plan.proposal" {
        bail!("worker did not return a plan proposal");
    }
    let response: WorkerProposal = serde_json::from_value(proposal.payload.clone())?;
    verify_proposal_binding(&proposal, &response, &exchange.pipe_name, request)?;
    Ok((response, proposal.nonce))
}

fn receive_message(exchange: &mut WorkerExchange) -> Result<BrokerMessage> {
    let message: BrokerMessage = FrameCodec::decode(&exchange.client.receive()?.0)?;
    message.validate()?;
    exchange.replays.accept(&message.nonce, Instant::now())?;
    Ok(message)
}

fn verify_proposal_binding(
    proposal: &BrokerMessage,
    response: &WorkerProposal,
    pipe_name: &str,
    request: &BrokerMessage,
) -> Result<()> {
    verify_proposal_digest(response)?;
    verify_proposal_request_binding(proposal, response, pipe_name, request)
}

fn verify_proposal_digest(response: &WorkerProposal) -> Result<()> {
    response.plan.validate_structure()?;
    let declared_digest = response
        .digest
        .parse::<Sha256Digest>()
        .map_err(|error| anyhow!(error))?;
    if canonical_json_digest(&response.plan)? != declared_digest {
        bail!("worker proposal is not bound to this exact pipe session and request");
    }
    Ok(())
}

fn verify_proposal_request_binding(
    proposal: &BrokerMessage,
    response: &WorkerProposal,
    pipe_name: &str,
    request: &BrokerMessage,
) -> Result<()> {
    if proposal.binding.session_id != pipe_name
        || proposal.binding.plan_id != response.plan.id.to_string()
        || proposal.binding.plan_digest != response.digest
        || proposal.binding.reply_to.as_deref() != Some(&request.nonce)
    {
        bail!("worker proposal is not bound to this exact pipe session and request");
    }
    Ok(())
}

fn parse_worker_result(reply: &BrokerMessage, proposal: &WorkerProposal) -> Result<WorkerResultV3> {
    let digest = proposal
        .digest
        .parse::<Sha256Digest>()
        .map_err(|error| anyhow!(error))?;
    crate::protocol::parse_worker_result(reply, proposal.plan.id, proposal.plan.run_id, digest)
}
