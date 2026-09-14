//! Step-specific observation bindings retained in approved plans.

use super::{
    BTreeSet, DomainResult, PlanV3, PlannedActionV3, Sha256Digest, canonical_json_digest,
    validation,
};

pub(super) fn validate_plan_observation_bindings(plan: &PlanV3) -> DomainResult<()> {
    if plan.observed_state.values.len() != plan.actions.len() {
        return validation("plan must retain one observation for every source step");
    }
    let mut source_steps = BTreeSet::new();
    for action in &plan.actions {
        if !source_steps.insert(action.source_step) {
            return validation("planned source steps must be unique");
        }
        let Some(observed) = plan.observed_state.values.get(&action.source_step) else {
            return validation("planned action has no step-bound observation");
        };
        validate_action_observation(action, plan.observed_state.digest, observed)?;
    }
    Ok(())
}

fn validate_action_observation(
    action: &PlannedActionV3,
    digest: Sha256Digest,
    observed: &crate::ObservedValueV3,
) -> DomainResult<()> {
    if action.facts_digest != digest
        || observed.capability != action.capability
        || observed.parameters_digest != canonical_json_digest(&action.parameters)?
    {
        return validation("planned action does not match its step observation binding");
    }
    Ok(())
}
