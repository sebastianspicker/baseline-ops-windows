//! Worker-retained typed proposals. Wire metadata is compared, never executed.

use crate::{ApprovalError, PlanningError, planner::WorkerPlan};
use baselineops_capabilities::{NativeHandler, SemanticPlan, plan_observed};
use baselineops_domain::{ActionId, CapabilityId, PlanV3};

pub(crate) struct RetainedIntents(Vec<RetainedIntent>);

struct RetainedIntent {
    action_id: ActionId,
    capability: CapabilityId,
    semantic: SemanticPlan,
}

impl RetainedIntents {
    pub(crate) fn into_windows_update(
        self,
    ) -> Result<
        (
            ActionId,
            CapabilityId,
            baselineops_capabilities::WindowsUpdatePlan,
        ),
        ApprovalError,
    > {
        let [intent]: [RetainedIntent; 1] = self
            .0
            .try_into()
            .map_err(|_| ApprovalError::DigestMismatch)?;
        if intent.capability.as_str() != "v3.windows-update.policy" {
            return Err(ineligible(
                &intent.capability,
                "the dispatcher accepts only Windows Update",
            ));
        }
        let SemanticPlan::WindowsUpdate(plan) = intent.semantic else {
            return Err(ApprovalError::DigestMismatch);
        };
        Ok((intent.action_id, intent.capability, plan))
    }

    pub(crate) fn from_worker_plan(worker: &WorkerPlan) -> Result<Self, PlanningError> {
        let plan = worker.proposal();
        plan.actions
            .iter()
            .map(|action| {
                retain_intent(
                    action,
                    &plan.observed_state.values[&action.source_step].facts,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    pub(crate) fn validate_execution(&self, approved: &PlanV3) -> Result<(), ApprovalError> {
        if !approved.resources.is_empty() || self.0.len() != approved.actions.len() {
            return Err(ApprovalError::DigestMismatch);
        }
        for (intent, action) in self.0.iter().zip(&approved.actions) {
            if intent.action_id != action.id || intent.capability != action.capability {
                return Err(ApprovalError::DigestMismatch);
            }
            validate_native_semantic(&intent.capability, &intent.semantic)?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn empty_for_test() -> Self {
        Self(Vec::new())
    }
}

fn retain_intent(
    action: &baselineops_domain::PlannedActionV3,
    facts: &baselineops_domain::JsonMap,
) -> Result<RetainedIntent, PlanningError> {
    let native = facts
        .get("native_result")
        .ok_or_else(|| PlanningError::Derivation("worker native observation is absent".into()))?;
    let parameters = serde_json::to_value(&action.parameters)
        .map_err(|error| PlanningError::Derivation(error.to_string()))?;
    let semantic = plan_observed(action.capability.as_str(), &parameters, native)
        .map_err(PlanningError::Derivation)?;
    let serialized = serde_json::to_value(&semantic)
        .map_err(|error| PlanningError::Derivation(error.to_string()))?;
    if action.metadata.get("semantic_plan") != Some(&serialized) {
        return Err(PlanningError::Derivation(
            "worker typed proposal differs from review metadata".into(),
        ));
    }
    Ok(RetainedIntent {
        action_id: action.id,
        capability: action.capability.clone(),
        semantic,
    })
}

fn validate_native_semantic(
    capability: &CapabilityId,
    semantic: &SemanticPlan,
) -> Result<(), ApprovalError> {
    let descriptor = baselineops_capabilities::lookup(capability.as_str())
        .ok_or_else(|| ineligible(capability, "typed intent is not registered"))?;
    if descriptor.handler != NativeHandler::WindowsUpdate
        || capability.as_str() != "v3.windows-update.policy"
    {
        return Err(ineligible(
            capability,
            "a typed native execution and recovery contract is not implemented",
        ));
    }
    let SemanticPlan::WindowsUpdate(plan) = semantic else {
        return Err(ineligible(
            capability,
            "semantic variant does not match the registered native handler",
        ));
    };
    if plan.rollback != plan.observation {
        return Err(ineligible(
            capability,
            "typed intent lacks exact recovery pre-state",
        ));
    }
    // The sealed action core does not establish shipping recovery or Windows runtime proof.
    // Registering a handler or closing Windows evidence alone cannot bypass this gate.
    Err(ineligible(
        capability,
        "Windows Update requires verified containment, shipping recovery, and Windows execution evidence",
    ))
}

fn ineligible(capability: &CapabilityId, reason: &'static str) -> ApprovalError {
    ApprovalError::ApplyIneligible {
        capability_id: capability.to_string(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn read_only_or_mismatched_variants_cannot_gain_authority_from_registry_flags() {
        let semantic = SemanticPlan::Observation {
            result: json!({"healthy":true}),
            reason: "read-only",
        };
        for capability in ["v3.windows-update.policy", "v3.doh.audit"] {
            let error =
                validate_native_semantic(&CapabilityId::new(capability).unwrap(), &semantic)
                    .unwrap_err();
            assert!(matches!(error, ApprovalError::ApplyIneligible { .. }));
        }
    }

    fn mutation_plan() -> baselineops_capabilities::WindowsUpdatePlan {
        use baselineops_capabilities::{
            PolicyValueSnapshot, WindowsUpdateObservation, WindowsUpdateParameters,
        };
        let desired = baselineops_capabilities::resolve_windows_update_desired_state(
            &WindowsUpdateParameters::default(),
        )
        .unwrap();
        let seed = baselineops_capabilities::build_windows_update_plan(
            WindowsUpdateObservation {
                values: std::collections::BTreeMap::default(),
            },
            desired.clone(),
        );
        let observation = WindowsUpdateObservation {
            values: seed
                .mutations
                .iter()
                .map(|change| (change.field, PolicyValueSnapshot::Missing))
                .collect(),
        };
        baselineops_capabilities::build_windows_update_plan(observation, desired)
    }

    fn rejection(plan: baselineops_capabilities::WindowsUpdatePlan) -> String {
        validate_native_semantic(
            &CapabilityId::new("v3.windows-update.policy").unwrap(),
            &SemanticPlan::WindowsUpdate(plan),
        )
        .unwrap_err()
        .to_string()
    }

    #[test]
    fn typed_mutations_remain_locked_until_shipping_recovery_and_windows_evidence() {
        assert!(
            rejection(mutation_plan())
                .contains("shipping recovery, and Windows execution evidence")
        );
    }

    #[test]
    fn compliant_no_op_remains_locked_and_tampered_recovery_is_rejected() {
        let plan = mutation_plan();
        let mut compliant = plan.observation.clone();
        for mutation in &plan.mutations {
            compliant
                .values
                .insert(mutation.field, mutation.desired.clone());
        }
        let mut no_op =
            baselineops_capabilities::build_windows_update_plan(compliant, plan.desired);
        assert!(no_op.mutations.is_empty());
        assert!(
            rejection(no_op.clone()).contains("shipping recovery, and Windows execution evidence")
        );
        no_op.rollback.values.clear();
        assert!(rejection(no_op).contains("lacks exact recovery pre-state"));
    }
}
