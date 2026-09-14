use super::*;
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Eq, PartialEq)]
enum Call {
    Observe,
    Recovery,
    Start,
    Finish,
    Mutate(WindowsUpdateField),
}

struct MockPort {
    observations: VecDeque<Result<WindowsUpdateObservation, String>>,
    calls: Vec<Call>,
    events: Vec<JournalEvent>,
    writes: Vec<(WindowsUpdateField, PolicyValueSnapshot, PolicyValueSnapshot)>,
    recovery: Option<(WindowsUpdateObservation, WindowsUpdateObservation)>,
    fail_recovery: bool,
    fail_start: bool,
    fail_finish: bool,
    fail_mutation: Option<usize>,
    wrong_mutation_result: Option<usize>,
}

impl MockPort {
    fn new(
        observations: impl IntoIterator<Item = Result<WindowsUpdateObservation, String>>,
    ) -> Self {
        Self {
            observations: observations.into_iter().collect(),
            calls: Vec::new(),
            events: Vec::new(),
            writes: Vec::new(),
            recovery: None,
            fail_recovery: false,
            fail_start: false,
            fail_finish: false,
            fail_mutation: None,
            wrong_mutation_result: None,
        }
    }
}

impl ActionPort for MockPort {
    fn observe(&mut self) -> Result<WindowsUpdateObservation, String> {
        self.calls.push(Call::Observe);
        self.observations
            .pop_front()
            .expect("test supplied every expected observation")
    }

    fn persist_recovery(
        &mut self,
        _action_id: ActionId,
        pre: &WindowsUpdateObservation,
        expected_post: &WindowsUpdateObservation,
    ) -> Result<(), String> {
        self.calls.push(Call::Recovery);
        if self.fail_recovery {
            return Err("recovery failure".into());
        }
        self.recovery = Some((pre.clone(), expected_post.clone()));
        Ok(())
    }

    fn append(&mut self, event: JournalEvent) -> Result<(), String> {
        let (call, fail) = match event {
            JournalEvent::ActionStarted { .. } => (Call::Start, self.fail_start),
            JournalEvent::ActionFinished { .. } => (Call::Finish, self.fail_finish),
            _ => panic!("action executor emitted an unrelated journal event"),
        };
        self.calls.push(call);
        if fail {
            return Err("journal failure".into());
        }
        self.events.push(event);
        Ok(())
    }

    fn mutate(
        &mut self,
        field: WindowsUpdateField,
        expected: &PolicyValueSnapshot,
        desired: &PolicyValueSnapshot,
    ) -> Result<PolicyValueSnapshot, String> {
        let index = self.writes.len();
        self.calls.push(Call::Mutate(field));
        self.writes.push((field, expected.clone(), desired.clone()));
        if self.fail_mutation == Some(index) {
            return Err("mutation failure".into());
        }
        if self.wrong_mutation_result == Some(index) {
            return Ok(expected.clone());
        }
        Ok(desired.clone())
    }
}

fn capability() -> CapabilityId {
    CapabilityId::new(WINDOWS_UPDATE_CAPABILITY).unwrap()
}

fn complete_missing() -> WindowsUpdateObservation {
    WindowsUpdateObservation {
        values: WINDOWS_UPDATE_FIELDS
            .into_iter()
            .map(|field| (field, PolicyValueSnapshot::Missing))
            .collect::<BTreeMap<_, _>>(),
    }
}

fn changed_plan() -> WindowsUpdatePlan {
    build_windows_update_plan(
        complete_missing(),
        resolve_windows_update_desired_state(&WindowsUpdateParameters::default()).unwrap(),
    )
}

fn expected_post(plan: &WindowsUpdatePlan) -> WindowsUpdateObservation {
    expected_post_state(plan)
}

fn no_op_plan() -> WindowsUpdatePlan {
    let first = changed_plan();
    build_windows_update_plan(expected_post(&first), first.desired)
}

fn execute(plan: &WindowsUpdatePlan, port: &mut MockPort) -> ActionOutcome {
    execute_windows_update(ActionId::new(), capability(), plan, port)
}

fn assert_failure(outcome: &ActionOutcome, phase: FailurePhase, attempted: bool, may_finish: bool) {
    let failure = outcome.failure.as_ref().expect("expected failure");
    assert_eq!(failure.phase, phase);
    assert_eq!(failure.mutation_attempted, attempted);
    assert_eq!(outcome.reboot_possible, attempted);
    assert_eq!(outcome.may_finish_run, may_finish);
}

#[test]
fn rejects_noncanonical_or_incomplete_plans_without_io() {
    let mut noncanonical = changed_plan();
    noncanonical.mutations.reverse();
    let mut port = MockPort::new([]);
    let outcome = execute(&noncanonical, &mut port);
    assert_failure(&outcome, FailurePhase::Precondition, false, true);
    assert!(port.calls.is_empty());

    let mut incomplete = changed_plan();
    incomplete
        .observation
        .values
        .remove(&WindowsUpdateField::UseWsus);
    let outcome = execute(&incomplete, &mut port);
    assert_failure(&outcome, FailurePhase::Precondition, false, true);
    assert!(port.calls.is_empty());
}

fn assert_live_precondition_rejected(live: WindowsUpdateObservation) {
    let plan = changed_plan();
    let mut port = MockPort::new([Ok(live)]);
    let outcome = execute(&plan, &mut port);
    assert_failure(&outcome, FailurePhase::Precondition, false, true);
    assert_eq!(port.calls, [Call::Observe]);
}

#[test]
fn rejects_mismatched_and_incomplete_live_observations() {
    let plan = changed_plan();
    let mut mismatch = plan.observation.clone();
    mismatch.values.insert(
        WindowsUpdateField::AllowMicrosoftUpdate,
        PolicyValueSnapshot::Dword(1),
    );
    assert_live_precondition_rejected(mismatch);
    let mut incomplete = plan.observation;
    incomplete.values.remove(&WindowsUpdateField::UseWsus);
    assert_live_precondition_rejected(incomplete);
}

#[test]
fn compliant_plan_records_durable_no_op_receipt() {
    let plan = no_op_plan();
    let pre = plan.observation.clone();
    let mut port = MockPort::new([Ok(pre.clone()), Ok(pre.clone())]);
    let outcome = execute(&plan, &mut port);

    assert!(outcome.failure.is_none());
    assert!(!outcome.reboot_possible);
    assert!(outcome.may_finish_run);
    assert_eq!(
        port.calls,
        [
            Call::Observe,
            Call::Recovery,
            Call::Start,
            Call::Observe,
            Call::Finish
        ]
    );
    assert!(port.writes.is_empty());
    assert_eq!(port.recovery, Some((pre.clone(), pre)));
    let receipt = outcome.receipt.as_ref().expect("durable receipt");
    assert_eq!(receipt.status, ActionStatus::Succeeded);
    match port.events.last().unwrap() {
        JournalEvent::ActionFinished { receipt_digest, .. } => {
            assert_eq!(*receipt_digest, canonical_json_digest(receipt).unwrap());
        }
        _ => panic!("expected terminal journal event"),
    }
}

#[test]
fn mutations_follow_canonical_order_and_exact_expected_values() {
    let plan = changed_plan();
    let observed_post = expected_post(&plan);
    let mut port = MockPort::new([Ok(plan.observation.clone()), Ok(observed_post.clone())]);
    let outcome = execute(&plan, &mut port);

    assert!(outcome.failure.is_none());
    assert!(outcome.reboot_possible);
    assert_eq!(outcome.receipt.unwrap().status, ActionStatus::Succeeded);
    let expected_writes = plan
        .mutations
        .iter()
        .map(|mutation| {
            (
                mutation.field,
                plan.observation.values[&mutation.field].clone(),
                mutation.desired.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(port.writes, expected_writes);
    assert_eq!(
        port.recovery,
        Some((plan.observation.clone(), observed_post))
    );
}

#[test]
fn recovery_failure_stops_before_journal_and_mutation() {
    let plan = changed_plan();
    let mut port = MockPort::new([Ok(plan.observation.clone())]);
    port.fail_recovery = true;
    let outcome = execute(&plan, &mut port);
    assert_failure(&outcome, FailurePhase::RecoveryEvidence, false, true);
    assert!(outcome.receipt.is_none());
    assert_eq!(port.calls, [Call::Observe, Call::Recovery]);
}

#[test]
fn start_journal_failure_stops_all_subsequent_io() {
    let plan = changed_plan();
    let mut port = MockPort::new([Ok(plan.observation.clone())]);
    port.fail_start = true;
    let outcome = execute(&plan, &mut port);
    assert_failure(&outcome, FailurePhase::Journal, false, false);
    assert!(outcome.receipt.is_none());
    assert_eq!(port.calls, [Call::Observe, Call::Recovery, Call::Start]);
}

#[test]
fn completion_journal_failure_never_returns_an_unrecorded_receipt() {
    let plan = no_op_plan();
    let pre = plan.observation.clone();
    let mut port = MockPort::new([Ok(pre.clone()), Ok(pre)]);
    port.fail_finish = true;
    let outcome = execute(&plan, &mut port);
    assert_failure(&outcome, FailurePhase::Journal, false, false);
    assert!(outcome.receipt.is_none());
    assert_eq!(port.events.len(), 1);
    assert_eq!(port.calls.last(), Some(&Call::Finish));
}

#[test]
fn mutation_failure_stops_writes_and_records_observed_failure() {
    let plan = changed_plan();
    let failure_post = plan.observation.clone();
    let mut port = MockPort::new([Ok(plan.observation.clone()), Ok(failure_post)]);
    port.fail_mutation = Some(1);
    let outcome = execute(&plan, &mut port);

    assert_failure(&outcome, FailurePhase::Mutation, true, true);
    assert_eq!(outcome.receipt.unwrap().status, ActionStatus::Failed);
    assert_eq!(port.writes.len(), 2);
    assert_eq!(port.calls.last(), Some(&Call::Finish));
}

#[test]
fn unexpected_mutation_readback_is_a_mutation_failure() {
    let plan = changed_plan();
    let mut port = MockPort::new([Ok(plan.observation.clone()), Ok(plan.observation.clone())]);
    port.wrong_mutation_result = Some(0);
    let outcome = execute(&plan, &mut port);
    assert_failure(&outcome, FailurePhase::Mutation, true, true);
    assert_eq!(port.writes.len(), 1);
    assert_eq!(outcome.receipt.unwrap().status, ActionStatus::Failed);
}

#[test]
fn unavailable_failure_observation_leaves_unmatched_start() {
    let plan = changed_plan();
    let mut port = MockPort::new([Ok(plan.observation.clone()), Err("readback failure".into())]);
    port.fail_mutation = Some(0);
    let outcome = execute(&plan, &mut port);
    assert_failure(&outcome, FailurePhase::Postcondition, true, false);
    assert!(outcome.receipt.is_none());
    assert_eq!(port.events.len(), 1);
    assert_eq!(port.writes.len(), 1);
}

#[test]
fn mismatched_poststate_records_a_failed_receipt() {
    let plan = changed_plan();
    let mut port = MockPort::new([Ok(plan.observation.clone()), Ok(plan.observation.clone())]);
    let outcome = execute(&plan, &mut port);
    assert_failure(&outcome, FailurePhase::Postcondition, true, true);
    assert_eq!(outcome.receipt.unwrap().status, ActionStatus::Failed);
    assert_eq!(port.events.len(), 2);
}

#[test]
fn unavailable_success_readback_leaves_unmatched_start() {
    let plan = no_op_plan();
    let mut port = MockPort::new([Ok(plan.observation.clone()), Err("readback failure".into())]);
    let outcome = execute(&plan, &mut port);
    assert_failure(&outcome, FailurePhase::Postcondition, false, false);
    assert!(outcome.receipt.is_none());
    assert_eq!(port.events.len(), 1);
}
