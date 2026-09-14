use baselineops_domain::{
    ActionId, CapabilityId, DomainError, ExecutionIntent, HostIdentityV3, InputIdentityV3,
    ObservedStateV3, PlanId, PlanV3, PlannedActionV3, ProfileStepV3, ProfileV3, ResourceBindingV3,
    RunId, Sha256Digest, SourceIdentityV3, ToolIdentityV3, canonical_json_digest,
};
use chrono::{DateTime, Duration, Utc};
use std::collections::{BTreeMap, HashMap};

/// Worker-derived values needed to bind a plan to one host and input closure.
#[derive(Clone, Debug)]
pub struct PlanBuildContext {
    /// Intent authorized by the command boundary.
    pub intent: ExecutionIntent,
    /// Trusted current host identity.
    pub host: HostIdentityV3,
    /// Exact worker/package version.
    pub tool: ToolIdentityV3,
    /// Digest of the verified package closure.
    pub package_digest: Sha256Digest,
    /// Re-read operator-writable profile source, bound by exact digest.
    pub source: SourceIdentityV3,
    /// Digest and size of all plan-affecting input.
    pub input: InputIdentityV3,
    /// Standard-user-opened external resources reduced to path-free digests.
    pub resources: Vec<ResourceBindingV3>,
    /// Capability observations used to derive actions.
    pub observed_state: ObservedStateV3,
    /// Maximum plan lifetime.
    pub lifetime: Duration,
}

/// A plan produced by the trusted planner and eligible for approval.
///
/// This typestate deliberately has no deserializer and can only be minted by
/// [`build_plan`]. It prevents a raw plan document from entering the approval
/// path as though it had been produced by the trusted registry.
#[derive(Debug)]
pub struct WorkerPlan {
    plan: PlanV3,
    digest: Sha256Digest,
}

impl WorkerPlan {
    /// Returns the worker-derived proposal for read-only operator review.
    #[must_use]
    pub const fn proposal(&self) -> &PlanV3 {
        &self.plan
    }

    /// Returns the canonical proposal digest presented for approval.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    pub(crate) fn into_parts(self) -> (PlanV3, Sha256Digest) {
        (self.plan, self.digest)
    }
}

/// Trusted capability-registry port that derives executable actions from profile requests.
///
/// Implementations belong to the worker-side capability registry. Profile JSON
/// is deliberately not a valid implementation of this port: the registry owns
/// operation, safety metadata, and the facts binding for every planned action.
pub trait TrustedActionDeriver {
    /// Derive one action from a validated profile step and trusted observations.
    ///
    /// # Errors
    ///
    /// Returns an error when the registered capability cannot derive a safe action.
    fn derive(
        &self,
        step: &ProfileStepV3,
        intent: ExecutionIntent,
        observed_state: &ObservedStateV3,
    ) -> Result<PlannedActionV3, String>;
}

/// Errors produced while constructing an authoritative plan.
#[derive(Debug, thiserror::Error)]
pub enum PlanningError {
    /// Domain validation rejected the profile, host, or observed state.
    #[error(transparent)]
    Domain(#[from] DomainError),
    /// The requested lifetime is empty or unreasonably long.
    #[error("plan lifetime must be between one second and 24 hours")]
    InvalidLifetime,
    /// A timestamp overflowed.
    #[error("plan expiry overflowed the supported timestamp range")]
    ExpiryOverflow,
    /// The selected profile is no longer usable.
    #[error("profile has expired")]
    ExpiredProfile,
    /// A registry-derived action did not retain the requested step identity.
    #[error("derived action does not match its source profile step")]
    SourceStepMismatch,
    /// A registry-derived action does not use the command-bound operation.
    #[error("derived action operation does not match the requested execution intent")]
    IntentMismatch,
    /// A registry-derived action has not bound the trusted observed facts.
    #[error("derived action facts digest does not match the observed facts")]
    FactsMismatch,
    /// A trusted capability registry could not derive an executable action.
    #[error("capability action derivation failed: {0}")]
    Derivation(String),
    /// A reviewed plan envelope differs from fresh worker authority.
    #[error("reviewed plan envelope does not match fresh worker authority")]
    ReviewedEnvelopeMismatch,
}

/// Build the worker-authoritative proposal in deterministic dependency order.
///
/// # Errors
///
/// Returns an error when the profile, host, or observed state is invalid; when
/// the lifetime is outside one second through 24 hours; or when canonical plan
/// construction fails.
///
pub fn build_plan(
    profile: &ProfileV3,
    context: PlanBuildContext,
    deriver: &dyn TrustedActionDeriver,
    now: DateTime<Utc>,
) -> Result<WorkerPlan, PlanningError> {
    let (order, expires_at) = validate_build_inputs(profile, &context, now)?;
    let index = PlanningIndex::from_validated(profile);
    let actions = derive_actions(profile, &index, &order, &context, deriver)?;
    build_worker_plan(profile, context, now, expires_at, actions)
}

struct PlanningIndex {
    capability_by_step: HashMap<ActionId, CapabilityId>,
    steps_by_capability: HashMap<CapabilityId, HashMap<ActionId, usize>>,
}

impl PlanningIndex {
    fn from_validated(profile: &ProfileV3) -> Self {
        let mut capability_by_step = HashMap::with_capacity(profile.steps.len());
        let mut steps_by_capability = HashMap::<_, HashMap<_, _>>::new();
        for (position, step) in profile.steps.iter().enumerate() {
            capability_by_step.insert(step.step_id, step.capability_id.clone());
            steps_by_capability
                .entry(step.capability_id.clone())
                .or_default()
                .insert(step.step_id, position);
        }
        Self {
            capability_by_step,
            steps_by_capability,
        }
    }

    fn step<'a>(&self, profile: &'a ProfileV3, step_id: &ActionId) -> Option<&'a ProfileStepV3> {
        let capability = self.capability_by_step.get(step_id)?;
        let position = self.steps_by_capability.get(capability)?.get(step_id)?;
        profile.steps.get(*position)
    }
}

fn validate_build_inputs(
    profile: &ProfileV3,
    context: &PlanBuildContext,
    now: DateTime<Utc>,
) -> Result<(Vec<ActionId>, DateTime<Utc>), PlanningError> {
    let validation = profile.validate()?;
    context.host.validate()?;
    context.observed_state.validate()?;
    if profile
        .expires_at
        .is_some_and(|expires_at| now >= expires_at)
    {
        return Err(PlanningError::ExpiredProfile);
    }
    if !(Duration::seconds(1)..=Duration::hours(24)).contains(&context.lifetime) {
        return Err(PlanningError::InvalidLifetime);
    }
    Ok((
        validation.topological_order.as_slice().to_vec(),
        now.checked_add_signed(context.lifetime)
            .ok_or(PlanningError::ExpiryOverflow)?,
    ))
}

fn build_worker_plan(
    profile: &ProfileV3,
    context: PlanBuildContext,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    actions: Vec<PlannedActionV3>,
) -> Result<WorkerPlan, PlanningError> {
    let plan = PlanV3 {
        schema_version: baselineops_domain::PlanSchemaVersion::V4,
        id: PlanId::new(),
        run_id: RunId::new(),
        intent: context.intent,
        profile_id: profile.id,
        profile_digest: canonical_json_digest(profile)?,
        host: context.host,
        tool: context.tool,
        package_digest: context.package_digest,
        source: context.source,
        input: context.input,
        resources: context.resources,
        observed_state: context.observed_state,
        issued_at: now,
        expires_at,
        actions,
        metadata: BTreeMap::default(),
    };
    plan.validate_structure()?;
    let digest = canonical_json_digest(&plan)?;
    Ok(WorkerPlan { plan, digest })
}

fn derive_actions(
    profile: &ProfileV3,
    index: &PlanningIndex,
    order: &[ActionId],
    context: &PlanBuildContext,
    deriver: &dyn TrustedActionDeriver,
) -> Result<Vec<PlannedActionV3>, PlanningError> {
    let mut actions = Vec::with_capacity(profile.steps.len());
    for step_id in order {
        let step = index
            .step(profile, step_id)
            .ok_or(PlanningError::SourceStepMismatch)?;
        let action = deriver
            .derive(step, context.intent, &context.observed_state)
            .map_err(PlanningError::Derivation)?;
        validate_derived_action(&action, step, context)?;
        actions.push(action);
    }
    Ok(actions)
}

fn validate_derived_action(
    action: &PlannedActionV3,
    step: &ProfileStepV3,
    context: &PlanBuildContext,
) -> Result<(), PlanningError> {
    if action.source_step != step.step_id || action.capability != step.capability_id {
        return Err(PlanningError::SourceStepMismatch);
    }
    if action.operation != context.intent.into() {
        return Err(PlanningError::IntentMismatch);
    }
    if action.facts_digest != context.observed_state.digest {
        return Err(PlanningError::FactsMismatch);
    }
    Ok(())
}

/// Rebuild a worker plan using a reviewed envelope without extending authority.
///
/// # Errors
///
/// Returns an error when the reviewed envelope is stale, would extend expiry,
/// or differs from fresh worker-derived bindings or actions.
pub(crate) fn rebuild_reviewed_apply_plan(
    reviewed: &PlanV3,
    profile: &ProfileV3,
    context: PlanBuildContext,
    deriver: &dyn TrustedActionDeriver,
    now: DateTime<Utc>,
) -> Result<WorkerPlan, PlanningError> {
    if reviewed.intent != ExecutionIntent::Apply {
        return Err(PlanningError::ReviewedEnvelopeMismatch);
    }
    reviewed.validate_at(now)?;
    let fresh = build_plan(profile, context, deriver, now)?.into_parts().0;
    validate_reviewed_authority(reviewed, &fresh)?;
    let plan = PlanV3 {
        schema_version: fresh.schema_version,
        id: reviewed.id,
        run_id: reviewed.run_id,
        intent: fresh.intent,
        profile_id: fresh.profile_id,
        profile_digest: fresh.profile_digest,
        host: fresh.host,
        tool: fresh.tool,
        package_digest: fresh.package_digest,
        source: fresh.source,
        input: fresh.input,
        resources: fresh.resources,
        observed_state: reviewed.observed_state.clone(),
        issued_at: reviewed.issued_at,
        expires_at: reviewed.expires_at,
        actions: fresh.actions,
        metadata: reviewed.metadata.clone(),
    };
    plan.validate_structure()?;
    Ok(WorkerPlan {
        digest: canonical_json_digest(&plan)?,
        plan,
    })
}

fn validate_reviewed_authority(reviewed: &PlanV3, fresh: &PlanV3) -> Result<(), PlanningError> {
    if reviewed.expires_at > fresh.expires_at || !same_reviewed_bindings(reviewed, fresh) {
        return Err(PlanningError::ReviewedEnvelopeMismatch);
    }
    Ok(())
}

fn same_reviewed_bindings(reviewed: &PlanV3, fresh: &PlanV3) -> bool {
    (
        reviewed.profile_id,
        reviewed.profile_digest,
        &reviewed.host,
        &reviewed.tool,
        reviewed.package_digest,
        &reviewed.source,
        &reviewed.input,
        &reviewed.resources,
        reviewed.observed_state.digest,
        &reviewed.actions,
    ) == (
        fresh.profile_id,
        fresh.profile_digest,
        &fresh.host,
        &fresh.tool,
        fresh.package_digest,
        &fresh.source,
        &fresh.input,
        &fresh.resources,
        fresh.observed_state.digest,
        &fresh.actions,
    )
}

#[cfg(test)]
#[path = "planner_tests.rs"]
mod tests;
