use super::*;
use baselineops_domain::{PlanId, ResultStatus, RunId, Sha256Digest};
use baselineops_windows::{BrokerBinding, PROTOCOL_VERSION};
use std::collections::VecDeque;
use std::sync::mpsc::{self, Sender};

struct Transport {
    incoming: VecDeque<BrokerMessage>,
    sent: Vec<BrokerMessage>,
    result_sender: Option<Sender<Result<WorkerResultV3>>>,
    result: Option<WorkerResultV3>,
    fail_send: bool,
}

impl ControlTransport for Transport {
    fn receive(&mut self, _timeout: Duration) -> Result<Option<BrokerMessage>> {
        if let Some(sender) = self.result_sender.take() {
            sender.send(Ok(self.result.take().unwrap())).unwrap();
        }
        Ok(self.incoming.pop_front())
    }
    fn send(&mut self, message: &BrokerMessage, _timeout: Duration) -> Result<()> {
        if self.fail_send {
            bail!("disconnected")
        }
        self.sent.push(message.clone());
        Ok(())
    }
}

fn reported_progress(transport: &Transport) -> Vec<WorkerProgress> {
    transport
        .sent
        .iter()
        .map(|message| serde_json::from_value(message.payload.clone()).unwrap())
        .collect()
}

fn fixture() -> (Transport, BrokerMessage, Receiver<Result<WorkerResultV3>>) {
    let plan_id = PlanId::new();
    let digest = Sha256Digest::of_bytes(b"worker");
    let approval = BrokerMessage {
        version: PROTOCOL_VERSION,
        binding: BrokerBinding {
            session_id: "11".repeat(16),
            plan_id: plan_id.to_string(),
            plan_digest: digest.to_hex(),
            reply_to: Some("22".repeat(16)),
        },
        nonce: "33".repeat(16),
        kind: "plan.approve".into(),
        payload: serde_json::json!({}),
    };
    let result = crate::responses::ResultBinding::new(plan_id, RunId::new(), digest)
        .failure(ResultStatus::Unsupported, "production gate remains closed")
        .unwrap();
    let (sender, receiver) = mpsc::channel();
    (
        Transport {
            incoming: VecDeque::new(),
            sent: Vec::new(),
            result_sender: Some(sender),
            result: Some(result),
            fail_send: false,
        },
        approval,
        receiver,
    )
}

#[test]
fn accepted_cancellation_signals_shared_executor_token_and_waits_for_result() {
    let (mut transport, approval, results) = fixture();
    let binding = ApprovalControl::new(&approval, Instant::now()).unwrap();
    transport
        .incoming
        .push_back(binding.cancellation("44".repeat(16)).unwrap());
    let cancellation = CancellationToken::default();
    let (_sender, progress) = mpsc::sync_channel(4);
    let result = run(
        &mut transport,
        &approval,
        &cancellation,
        &results,
        &progress,
        Instant::now() + Duration::from_mins(2),
    )
    .unwrap();
    assert!(cancellation.is_cancelled());
    assert_eq!(result.final_status, ResultStatus::Unsupported);
    let phases = reported_progress(&transport);
    assert_eq!(
        phases.iter().map(|p| p.phase).collect::<Vec<_>>(),
        [ProgressPhase::Preparing, ProgressPhase::CancellationPending]
    );
}

#[test]
fn durable_progress_precedes_returning_terminal_result() {
    let (mut transport, approval, results) = fixture();
    let (sender, progress) = mpsc::sync_channel(4);
    let action_id = baselineops_domain::ActionId::new();
    for phase in [NativeActionPhase::Started, NativeActionPhase::Finished] {
        sender
            .send(NativeActionProgress { action_id, phase })
            .unwrap();
    }
    let result = run(
        &mut transport,
        &approval,
        &CancellationToken::default(),
        &results,
        &progress,
        Instant::now() + Duration::from_mins(2),
    )
    .unwrap();
    assert_eq!(result.final_status, ResultStatus::Unsupported);
    let phases = reported_progress(&transport);
    assert_eq!(phases[1].phase, ProgressPhase::ActionStarted);
    assert_eq!(phases[2].phase, ProgressPhase::ActionFinished);
    assert_eq!(phases[2].action_id, Some(action_id));
}

#[test]
fn invalid_control_aborts_without_acknowledging_cancellation() {
    let (mut transport, approval, results) = fixture();
    let mut forged = ApprovalControl::new(&approval, Instant::now())
        .unwrap()
        .cancellation("44".repeat(16))
        .unwrap();
    forged.binding.plan_digest = "ff".repeat(32);
    transport.incoming.push_back(forged);
    let (_sender, progress) = mpsc::sync_channel(4);
    assert!(
        run(
            &mut transport,
            &approval,
            &CancellationToken::default(),
            &results,
            &progress,
            Instant::now() + Duration::from_mins(2),
        )
        .is_err()
    );
    assert_eq!(transport.sent.len(), 1, "no cancellation acknowledgement");
}

#[test]
fn failed_transport_requests_cooperative_stop_without_waiting_on_a_bounded_sender() {
    let (mut transport, approval, results) = fixture();
    transport.fail_send = true;
    let cancellation = CancellationToken::default();
    let (_sender, progress) = mpsc::sync_channel(4);
    assert!(
        run(
            &mut transport,
            &approval,
            &cancellation,
            &results,
            &progress,
            Instant::now() + Duration::from_mins(2),
        )
        .is_err()
    );
    assert!(cancellation.is_cancelled());
}

#[test]
fn expired_pump_neither_forwards_progress_nor_accepts_a_queued_result() {
    let (mut transport, approval, results) = fixture();
    let result = transport.result.take().unwrap();
    transport
        .result_sender
        .take()
        .unwrap()
        .send(Ok(result))
        .unwrap();
    let (sender, progress) = mpsc::sync_channel(4);
    sender
        .send(NativeActionProgress {
            action_id: baselineops_domain::ActionId::new(),
            phase: NativeActionPhase::Started,
        })
        .unwrap();
    let mut binding = ApprovalControl::new(&approval, Instant::now()).unwrap();
    assert!(
        pump(
            &mut transport,
            &mut binding,
            &CancellationToken::default(),
            &results,
            &progress,
            Instant::now()
        )
        .is_err()
    );
    assert!(transport.sent.is_empty());
    assert!(
        results.try_recv().is_ok(),
        "expired pump must not accept result"
    );
    assert!(
        progress.try_recv().is_ok(),
        "expired pump must not accept progress"
    );
}

#[path = "control_ordering_tests.rs"]
mod ordering;

#[test]
fn expired_terminal_send_never_calls_transport() {
    let (mut transport, proposal, _) = fixture();
    let result = transport.result.take().unwrap();
    assert!(
        send_terminal(
            &mut transport,
            &proposal,
            "44".repeat(16),
            result,
            Instant::now()
        )
        .is_err()
    );
    assert!(transport.sent.is_empty());
}
