use baselineops_capabilities::{
    PolicyValueSnapshot, WindowsUpdateField, WindowsUpdateMutation, WindowsUpdateObservation,
    WindowsUpdateParameters, WindowsUpdatePlan, build_windows_update_plan,
    resolve_windows_update_desired_state,
};
use baselineops_domain::{
    ActionId, ActionReceiptV3, ActionStatus, CapabilityId, canonical_json_digest,
};

use crate::JournalEvent;

const WINDOWS_UPDATE_CAPABILITY: &str = "v3.windows-update.policy";
const WINDOWS_UPDATE_FIELDS: [WindowsUpdateField; 12] = [
    WindowsUpdateField::UseWsus,
    WindowsUpdateField::WsusServer,
    WindowsUpdateField::WsusStatusServer,
    WindowsUpdateField::AllowMicrosoftUpdate,
    WindowsUpdateField::DeferFeatureUpdates,
    WindowsUpdateField::DeferFeatureDays,
    WindowsUpdateField::DeferQualityUpdates,
    WindowsUpdateField::DeferQualityDays,
    WindowsUpdateField::TargetReleaseVersion,
    WindowsUpdateField::ProductVersion,
    WindowsUpdateField::TargetReleaseVersionInfo,
    WindowsUpdateField::DeliveryOptimizationMode,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FailurePhase {
    Precondition,
    RecoveryEvidence,
    Journal,
    Mutation,
    Postcondition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ActionFailure {
    pub(super) phase: FailurePhase,
    pub(super) detail: String,
    pub(super) mutation_attempted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ActionOutcome {
    pub(super) receipt: Option<ActionReceiptV3>,
    pub(super) failure: Option<ActionFailure>,
    pub(super) reboot_possible: bool,
    pub(super) may_finish_run: bool,
}

pub(super) trait ActionPort {
    fn observe(&mut self) -> Result<WindowsUpdateObservation, String>;

    fn persist_recovery(
        &mut self,
        action_id: ActionId,
        pre: &WindowsUpdateObservation,
        expected_post: &WindowsUpdateObservation,
    ) -> Result<(), String>;

    fn append(&mut self, event: JournalEvent) -> Result<(), String>;

    fn mutate(
        &mut self,
        field: WindowsUpdateField,
        expected: &PolicyValueSnapshot,
        desired: &PolicyValueSnapshot,
    ) -> Result<PolicyValueSnapshot, String>;
}

pub(super) fn execute_windows_update(
    action_id: ActionId,
    capability: CapabilityId,
    plan: &WindowsUpdatePlan,
    port: &mut impl ActionPort,
) -> ActionOutcome {
    let prepared = match prepare_action(action_id, &capability, plan, port) {
        Preparation::Ready(prepared) => prepared,
        Preparation::Failed(outcome) => return outcome,
    };
    mutate_then_observe(
        action_id,
        capability,
        plan,
        port,
        &prepared.pre,
        &prepared.expected_post,
    )
}

struct PreparedAction {
    pre: WindowsUpdateObservation,
    expected_post: WindowsUpdateObservation,
}

enum Preparation {
    Ready(PreparedAction),
    Failed(ActionOutcome),
}

fn prepare_action(
    action_id: ActionId,
    capability: &CapabilityId,
    plan: &WindowsUpdatePlan,
    port: &mut impl ActionPort,
) -> Preparation {
    let expected_post = match validate_plan(capability, plan) {
        Ok(expected) => expected,
        Err(detail) => {
            return Preparation::Failed(failed_before_start(FailurePhase::Precondition, detail));
        }
    };
    let pre = match observe_complete(port, "pre-state") {
        Ok(observation) => observation,
        Err(detail) => {
            return Preparation::Failed(failed_before_start(FailurePhase::Precondition, detail));
        }
    };
    if pre != plan.observation {
        return Preparation::Failed(failed_before_start(
            FailurePhase::Precondition,
            "Windows Update pre-state does not exactly match the trusted plan".into(),
        ));
    }
    let pre_digest = match canonical_json_digest(&pre) {
        Ok(digest) => digest,
        Err(error) => {
            return Preparation::Failed(failed_before_start(
                FailurePhase::Precondition,
                format!("could not digest Windows Update pre-state: {error}"),
            ));
        }
    };
    if let Err(error) = port.persist_recovery(action_id, &pre, &expected_post) {
        return Preparation::Failed(failed_before_start(
            FailurePhase::RecoveryEvidence,
            format!("could not persist manual recovery evidence: {error}"),
        ));
    }
    if let Err(error) = port.append(JournalEvent::ActionStarted {
        action_id: action_id.to_string(),
        pre_state_digest: pre_digest,
    }) {
        return Preparation::Failed(journal_failure(false, &error));
    }
    Preparation::Ready(PreparedAction { pre, expected_post })
}

fn validate_plan(
    capability: &CapabilityId,
    plan: &WindowsUpdatePlan,
) -> Result<WindowsUpdateObservation, String> {
    if capability.as_str() != WINDOWS_UPDATE_CAPABILITY {
        return Err("action capability is not the fixed Windows Update capability".into());
    }
    require_complete(&plan.observation, "planned pre-state")?;
    require_complete(&plan.rollback, "rollback pre-state")?;
    let desired = resolve_windows_update_desired_state(&WindowsUpdateParameters {
        config: None,
        desired: Some(plan.desired.clone()),
    })?;
    let canonical = build_windows_update_plan(plan.observation.clone(), desired);
    if canonical != *plan {
        return Err("Windows Update plan is not the canonical typed mutation list".into());
    }
    Ok(expected_post_state(plan))
}

fn require_complete(observation: &WindowsUpdateObservation, label: &str) -> Result<(), String> {
    if observation.values.len() == WINDOWS_UPDATE_FIELDS.len()
        && WINDOWS_UPDATE_FIELDS
            .iter()
            .all(|field| observation.values.contains_key(field))
    {
        return Ok(());
    }
    Err(format!("Windows Update {label} is incomplete"))
}

fn expected_post_state(plan: &WindowsUpdatePlan) -> WindowsUpdateObservation {
    let mut expected = plan.observation.clone();
    for mutation in &plan.mutations {
        expected
            .values
            .insert(mutation.field, mutation.desired.clone());
    }
    expected
}

fn observe_complete(
    port: &mut impl ActionPort,
    label: &str,
) -> Result<WindowsUpdateObservation, String> {
    let observation = port
        .observe()
        .map_err(|error| format!("could not observe Windows Update {label}: {error}"))?;
    require_complete(&observation, label)?;
    Ok(observation)
}

fn mutate_then_observe(
    action_id: ActionId,
    capability: CapabilityId,
    plan: &WindowsUpdatePlan,
    port: &mut impl ActionPort,
    pre: &WindowsUpdateObservation,
    expected_post: &WindowsUpdateObservation,
) -> ActionOutcome {
    for mutation in &plan.mutations {
        let expected = pre
            .values
            .get(&mutation.field)
            .expect("validated complete pre-state contains every mutation field");
        match apply_mutation(port, mutation, expected) {
            Ok(()) => {}
            Err(detail) => {
                return finish_failure(
                    action_id,
                    capability,
                    port,
                    pre,
                    FailurePhase::Mutation,
                    detail,
                    true,
                );
            }
        }
    }
    finish_after_mutations(
        action_id,
        capability,
        port,
        pre,
        expected_post,
        !plan.mutations.is_empty(),
    )
}

fn apply_mutation(
    action_port: &mut impl ActionPort,
    mutation: &WindowsUpdateMutation,
    expected: &PolicyValueSnapshot,
) -> Result<(), String> {
    let observed = action_port
        .mutate(mutation.field, expected, &mutation.desired)
        .map_err(|error| {
            format!(
                "Windows Update {:?} mutation failed: {error}",
                mutation.field
            )
        })?;
    if observed != mutation.desired {
        return Err(format!(
            "Windows Update {:?} mutation returned an unexpected value",
            mutation.field
        ));
    }
    Ok(())
}

fn finish_after_mutations(
    action_id: ActionId,
    capability: CapabilityId,
    action_port: &mut impl ActionPort,
    pre: &WindowsUpdateObservation,
    expected_post: &WindowsUpdateObservation,
    mutation_attempted: bool,
) -> ActionOutcome {
    let observed_post = match observe_complete(action_port, "post-state") {
        Ok(observation) => observation,
        Err(detail) => {
            return unmatched_start(FailurePhase::Postcondition, detail, mutation_attempted);
        }
    };
    if &observed_post != expected_post {
        return record_terminal(
            action_port,
            TerminalContext {
                action_id,
                capability,
                pre,
                mutation_attempted,
            },
            &observed_post,
            ActionStatus::Failed,
            Some((
                FailurePhase::Postcondition,
                "Windows Update post-state does not match the canonical expected state".into(),
            )),
        );
    }
    record_terminal(
        action_port,
        TerminalContext {
            action_id,
            capability,
            pre,
            mutation_attempted,
        },
        &observed_post,
        ActionStatus::Succeeded,
        None,
    )
}

fn finish_failure(
    action_id: ActionId,
    capability: CapabilityId,
    action_port: &mut impl ActionPort,
    pre: &WindowsUpdateObservation,
    phase: FailurePhase,
    detail: String,
    mutation_attempted: bool,
) -> ActionOutcome {
    let observed_post = match observe_complete(action_port, "failure post-state") {
        Ok(observation) => observation,
        Err(observation_error) => {
            return unmatched_start(
                FailurePhase::Postcondition,
                format!("{detail}; {observation_error}"),
                mutation_attempted,
            );
        }
    };
    record_terminal(
        action_port,
        TerminalContext {
            action_id,
            capability,
            pre,
            mutation_attempted,
        },
        &observed_post,
        ActionStatus::Failed,
        Some((phase, detail)),
    )
}

struct TerminalContext<'a> {
    action_id: ActionId,
    capability: CapabilityId,
    pre: &'a WindowsUpdateObservation,
    mutation_attempted: bool,
}

fn record_terminal(
    action_port: &mut impl ActionPort,
    context: TerminalContext<'_>,
    observed_post: &WindowsUpdateObservation,
    status: ActionStatus,
    failure: Option<(FailurePhase, String)>,
) -> ActionOutcome {
    let receipt = match build_receipt(
        context.action_id,
        context.capability,
        context.pre,
        observed_post,
        status,
    ) {
        Ok(receipt) => receipt,
        Err(detail) => return journal_failure(context.mutation_attempted, &detail),
    };
    let receipt_digest = match canonical_json_digest(&receipt) {
        Ok(digest) => digest,
        Err(error) => {
            return journal_failure(
                context.mutation_attempted,
                &format!("could not digest action receipt: {error}"),
            );
        }
    };
    if let Err(error) = action_port.append(JournalEvent::ActionFinished {
        action_id: context.action_id.to_string(),
        status,
        receipt_digest,
    }) {
        return journal_failure(context.mutation_attempted, &error);
    }
    ActionOutcome {
        receipt: Some(receipt),
        failure: failure.map(|(phase, detail)| ActionFailure {
            phase,
            detail,
            mutation_attempted: context.mutation_attempted,
        }),
        reboot_possible: context.mutation_attempted,
        may_finish_run: true,
    }
}

fn build_receipt(
    action_id: ActionId,
    capability: CapabilityId,
    pre: &WindowsUpdateObservation,
    post: &WindowsUpdateObservation,
    status: ActionStatus,
) -> Result<ActionReceiptV3, String> {
    Ok(ActionReceiptV3 {
        action_id,
        capability,
        pre_state_digest: canonical_json_digest(pre)
            .map_err(|error| format!("could not digest receipt pre-state: {error}"))?,
        post_state_digest: canonical_json_digest(post)
            .map_err(|error| format!("could not digest receipt post-state: {error}"))?,
        status,
    })
}

fn failed_before_start(phase: FailurePhase, detail: String) -> ActionOutcome {
    ActionOutcome {
        receipt: None,
        failure: Some(ActionFailure {
            phase,
            detail,
            mutation_attempted: false,
        }),
        reboot_possible: false,
        may_finish_run: true,
    }
}

fn unmatched_start(phase: FailurePhase, detail: String, mutation_attempted: bool) -> ActionOutcome {
    ActionOutcome {
        receipt: None,
        failure: Some(ActionFailure {
            phase,
            detail,
            mutation_attempted,
        }),
        reboot_possible: mutation_attempted,
        may_finish_run: false,
    }
}

fn journal_failure(mutation_attempted: bool, detail: &str) -> ActionOutcome {
    unmatched_start(
        FailurePhase::Journal,
        format!("could not append durable action journal event: {detail}"),
        mutation_attempted,
    )
}

#[cfg(test)]
#[path = "action_tests.rs"]
mod tests;
