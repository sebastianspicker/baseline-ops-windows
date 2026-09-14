//! Capability-registry action derivation with exhaustive domain mappings.

use crate::TrustedActionDeriver;
#[cfg(test)]
use baselineops_capabilities::Reversibility as RegistryReversibility;
use baselineops_capabilities::{
    ImplementationMaturity, Operation as RegistryOperation, Privilege as RegistryPrivilege,
    Reboot as RegistryReboot, Risk as RegistryRisk, lookup,
};
use baselineops_domain::{
    ExecutionIntent, ObservedStateV3, PlannedActionV3, PreconditionV3, Privilege, ProfileStepV3,
    RebootRequirement, Reversibility, RiskLevel,
};
use std::collections::BTreeMap;

/// Trusted derivation backed only by the compile-time capability registry.
pub struct RegistryActionDeriver;

impl TrustedActionDeriver for RegistryActionDeriver {
    fn derive(
        &self,
        step: &ProfileStepV3,
        intent: ExecutionIntent,
        observed_state: &ObservedStateV3,
    ) -> Result<PlannedActionV3, String> {
        let descriptor = supported_descriptor(step, intent)?;
        let observed = observed_state.values.get(&step.step_id).ok_or_else(|| {
            format!(
                "trusted observation is absent for capability {}",
                descriptor.id
            )
        })?;
        if observed.capability != step.capability_id
            || observed.parameters_digest
                != baselineops_domain::canonical_json_digest(&step.parameters)
                    .map_err(|error| error.to_string())?
        {
            return Err(
                "observation does not match the profile step capability and parameters".into(),
            );
        }
        planned_action(step, intent, observed_state, &observed.facts, descriptor)
    }
}

fn supported_descriptor(
    step: &ProfileStepV3,
    intent: ExecutionIntent,
) -> Result<&'static baselineops_capabilities::CapabilityDescriptor, String> {
    let descriptor = lookup(step.capability_id.as_str())
        .ok_or_else(|| format!("unknown capability {}", step.capability_id))?;
    if !descriptor.operations.audit {
        return Err(format!(
            "capability {} does not support {:?}",
            descriptor.id,
            registry_operation(intent)
        ));
    }
    if !matches!(
        descriptor.maturity,
        ImplementationMaturity::CodeComplete | ImplementationMaturity::Implemented
    ) {
        return Err(format!(
            "capability {} has no code-complete native planner",
            descriptor.id
        ));
    }
    Ok(descriptor)
}

fn planned_action(
    step: &ProfileStepV3,
    intent: ExecutionIntent,
    observed_state: &ObservedStateV3,
    facts: &baselineops_domain::JsonMap,
    descriptor: &baselineops_capabilities::CapabilityDescriptor,
) -> Result<PlannedActionV3, String> {
    let native = facts
        .get("native_result")
        .ok_or("captured native result is absent")?;
    let semantic = baselineops_capabilities::plan_observed(
        descriptor.id,
        &serde_json::to_value(&step.parameters).map_err(|error| error.to_string())?,
        native,
    )?;
    let changes = semantic.proposes_changes();
    let privilege = proposal_privilege(descriptor.privilege, changes, intent);
    let metadata = proposal_metadata(facts, &semantic, descriptor)?;
    Ok(PlannedActionV3 {
        // Reusing the validated source-step ID makes independent derivation deterministic.
        id: step.step_id,
        source_step: step.step_id,
        capability: step.capability_id.clone(),
        operation: intent.into(),
        parameters: step.parameters.clone(),
        depends_on: step.depends_on.clone(),
        continue_on_error: step.continue_on_error,
        facts_digest: observed_state.digest,
        preconditions: preconditions(step, observed_state.digest, privilege),
        risk: domain_risk(descriptor.risk),
        reversibility: if changes {
            // Until native recovery is implemented, retaining a snapshot does not
            // promise an executable rollback path.
            Reversibility::Irreversible
        } else {
            Reversibility::NotApplicable
        },
        reboot: if changes {
            domain_reboot(descriptor.reboot)
        } else {
            RebootRequirement::NotRequired
        },
        privileges: vec![privilege],
        metadata,
    })
}

fn proposal_privilege(
    registry: RegistryPrivilege,
    changes: bool,
    intent: ExecutionIntent,
) -> Privilege {
    if changes && intent == ExecutionIntent::Apply {
        Privilege::Administrator
    } else {
        domain_privilege(registry, ExecutionIntent::Audit)
    }
}

fn proposal_metadata(
    facts: &baselineops_domain::JsonMap,
    semantic: &baselineops_capabilities::SemanticPlan,
    descriptor: &baselineops_capabilities::CapabilityDescriptor,
) -> Result<baselineops_domain::JsonMap, String> {
    Ok(BTreeMap::from([
        (
            "pre_state".into(),
            serde_json::to_value(facts).map_err(|error| error.to_string())?,
        ),
        (
            "semantic_plan".into(),
            serde_json::to_value(semantic).map_err(|error| error.to_string())?,
        ),
        (
            "apply_eligibility".into(),
            serde_json::to_value(descriptor.apply_eligibility)
                .map_err(|error| error.to_string())?,
        ),
    ]))
}

fn preconditions(
    step: &ProfileStepV3,
    digest: baselineops_domain::Sha256Digest,
    privilege: Privilege,
) -> Vec<PreconditionV3> {
    let mut values = vec![
        PreconditionV3::CapabilityAvailable {
            capability: step.capability_id.clone(),
        },
        PreconditionV3::ObservedStateDigest { digest },
    ];
    if privilege == Privilege::Administrator {
        values.push(PreconditionV3::Elevation { required: true });
    }
    values
}

const fn registry_operation(intent: ExecutionIntent) -> RegistryOperation {
    match intent {
        ExecutionIntent::Audit => RegistryOperation::Audit,
        // An Apply command first derives and displays a semantic proposal. The
        // separate worker eligibility gate decides whether that proposal may
        // ever reach a mutator.
        ExecutionIntent::Plan | ExecutionIntent::Apply => RegistryOperation::Plan,
    }
}

const fn domain_privilege(value: RegistryPrivilege, intent: ExecutionIntent) -> Privilege {
    match value {
        RegistryPrivilege::ElevatedForApply if matches!(intent, ExecutionIntent::Apply) => {
            Privilege::Administrator
        }
        RegistryPrivilege::StandardUser | RegistryPrivilege::ElevatedForApply => Privilege::User,
        RegistryPrivilege::AdministratorRequired => Privilege::Administrator,
    }
}

const fn domain_risk(value: RegistryRisk) -> RiskLevel {
    match value {
        RegistryRisk::Low => RiskLevel::Low,
        RegistryRisk::Medium => RiskLevel::Moderate,
        RegistryRisk::High => RiskLevel::High,
        RegistryRisk::Critical => RiskLevel::Critical,
    }
}

#[cfg(test)]
const fn domain_reversibility(value: RegistryReversibility) -> Reversibility {
    match value {
        RegistryReversibility::NotApplicable => Reversibility::NotApplicable,
        RegistryReversibility::Reversible => Reversibility::Reversible,
        RegistryReversibility::ManualRecovery | RegistryReversibility::NotReversible => {
            Reversibility::Irreversible
        }
    }
}

const fn domain_reboot(value: RegistryReboot) -> RebootRequirement {
    match value {
        RegistryReboot::No => RebootRequirement::NotRequired,
        RegistryReboot::Possible => RebootRequirement::Recommended,
        RegistryReboot::Required => RebootRequirement::Required,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use baselineops_domain::{ActionId, CapabilityId, JsonMap, Sha256Digest};

    #[test]
    fn all_registry_vocabularies_have_explicit_domain_mappings() {
        assert_eq!(domain_risk(RegistryRisk::Medium), RiskLevel::Moderate);
        assert_eq!(
            domain_reversibility(RegistryReversibility::ManualRecovery),
            Reversibility::Irreversible
        );
        assert_eq!(
            domain_reboot(RegistryReboot::Possible),
            RebootRequirement::Recommended
        );
        assert_eq!(
            domain_privilege(RegistryPrivilege::ElevatedForApply, ExecutionIntent::Apply),
            Privilege::Administrator
        );
    }

    #[test]
    fn code_complete_capability_can_mint_a_reviewable_action() {
        let capability = CapabilityId::new("v3.doh.audit").expect("capability");
        let step = ProfileStepV3 {
            step_id: ActionId::new(),
            capability_id: capability.clone(),
            parameters: JsonMap::new(),
            depends_on: Vec::new(),
            continue_on_error: false,
        };
        let mut state = ObservedStateV3 {
            captured_at: chrono::Utc::now(),
            digest: Sha256Digest::of_bytes(b"placeholder"),
            values: BTreeMap::default(),
        };
        state.values.insert(
            step.step_id,
            baselineops_domain::ObservedValueV3 {
                capability,
                parameters_digest: baselineops_domain::canonical_json_digest(&step.parameters)
                    .unwrap(),
                observed_at: chrono::Utc::now(),
                facts: BTreeMap::from([(
                    "native_result".into(),
                    serde_json::json!({"observed":true}),
                )]),
            },
        );
        state.digest = state.calculated_digest().expect("facts digest");
        let result = RegistryActionDeriver.derive(&step, ExecutionIntent::Audit, &state);
        let action = result.expect("code-complete planner");
        assert_eq!(
            action.capability,
            CapabilityId::new("v3.doh.audit").expect("capability")
        );
        assert_eq!(action.metadata["apply_eligibility"], "evidence_required");
    }
}
