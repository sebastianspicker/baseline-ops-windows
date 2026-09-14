//! Worker-side recomputation gate for apply authority.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityOutcome, Operation as CapabilityOperation, lookup,
};
use baselineops_domain::{
    ObservedStateV3, ObservedValueV3, ProfileStepV3, ProfileV3, Sha256Digest,
};
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;

use crate::{
    ApprovalError, PlanBuildContext, PlanningError, RegistryActionDeriver, VerifiedPlan,
    approval::PlanApprovalSession, planner::rebuild_reviewed_apply_plan,
};
use baselineops_domain::{PlanV3, PlanValidationContext};
use baselineops_windows::TrustedInstallation;

/// Fixed-registry production authority retained by the elevated worker.
pub struct WorkerApplyAuthority {
    session: PlanApprovalSession,
    intents: crate::native_intents::RetainedIntents,
}

/// Opaque proof that the production worker approved its retained proposal.
///
/// This token exposes no plan or scheduler access. It borrows the retained installation
/// proof until the sealed native dispatcher consumes it exactly once.
///
/// ```compile_fail
/// use baselineops_engine::ApprovedWorkerApply;
/// fn cannot_outlive_installation(token: ApprovedWorkerApply<'_>) -> ApprovedWorkerApply<'static> {
///     token
/// }
/// ```
pub struct ApprovedWorkerApply<'installation> {
    verified: VerifiedPlan,
    intents: crate::native_intents::RetainedIntents,
    installation: &'installation TrustedInstallation,
}

impl<'installation> ApprovedWorkerApply<'installation> {
    pub(crate) fn into_parts(
        self,
    ) -> (
        VerifiedPlan,
        crate::native_intents::RetainedIntents,
        &'installation TrustedInstallation,
    ) {
        (self.verified, self.intents, self.installation)
    }
}

impl WorkerApplyAuthority {
    /// Exact worker proposal for operator review.
    #[must_use]
    pub const fn proposal(&self) -> &PlanV3 {
        self.session.proposal()
    }
    /// Exact canonical digest requiring operator approval.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.session.digest()
    }
    /// Mint authority only after worker-collected live bindings are revalidated.
    ///
    /// # Errors
    ///
    /// Returns an error when the digest or live bindings fail worker approval.
    pub fn approve<'installation>(
        self,
        digest: Sha256Digest,
        live: &PlanValidationContext,
        installation: &'installation TrustedInstallation,
    ) -> Result<ApprovedWorkerApply<'installation>, ApprovalError> {
        let verified = self.session.approve(digest, live, installation)?;
        validate_apply_eligibility(verified.plan())?;
        self.intents.validate_execution(verified.plan())?;
        Ok(ApprovedWorkerApply {
            verified,
            intents: self.intents,
            installation,
        })
    }

    #[cfg(test)]
    fn approve_at_root(
        self,
        digest: Sha256Digest,
        live: &PlanValidationContext,
        trusted_root: &std::path::Path,
    ) -> Result<(), ApprovalError> {
        let verified = self.session.approve_at_root(digest, live, trusted_root)?;
        validate_apply_eligibility(verified.plan())?;
        self.intents.validate_execution(verified.plan())?;
        Ok(())
    }
}

fn validate_apply_eligibility(plan: &PlanV3) -> Result<(), ApprovalError> {
    for action in &plan.actions {
        validate_action_eligibility(&action.capability)?;
    }
    Ok(())
}

fn validate_action_eligibility(
    capability: &baselineops_domain::CapabilityId,
) -> Result<(), ApprovalError> {
    let descriptor = lookup(capability.as_str()).ok_or_else(|| {
        ineligible(
            capability,
            "the action is absent from the compile-time capability registry",
        )
    })?;
    if descriptor.maturity != baselineops_capabilities::ImplementationMaturity::Implemented {
        return Err(ineligible(
            capability,
            "capability maturity is code_complete; reviewed Windows evidence is open",
        ));
    }
    if !descriptor.apply_eligibility.is_enabled() || !descriptor.operations.apply {
        return Err(ineligible(
            capability,
            "compiled production Apply eligibility is disabled",
        ));
    }
    if descriptor.apply_handler.is_none() {
        return Err(ineligible(
            capability,
            "the sealed worker mutation handler is absent",
        ));
    }
    Ok(())
}

fn ineligible(
    capability: &baselineops_domain::CapabilityId,
    reason: &'static str,
) -> ApprovalError {
    ApprovalError::ApplyIneligible {
        capability_id: capability.to_string(),
        reason,
    }
}

/// Build retained apply authority using the fixed compile-time registry and worker clock.
///
/// This accepts no caller-supplied action derivation or approval session.
///
/// # Errors
///
/// Returns an error when the reviewed apply plan cannot be rebuilt and validated.
pub fn prepare_worker_apply(
    reviewed: &PlanV3,
    profile: &ProfileV3,
    context: PlanBuildContext,
) -> Result<WorkerApplyAuthority, PlanningError> {
    let plan = rebuild_reviewed_apply_plan(
        reviewed,
        profile,
        context,
        &RegistryActionDeriver,
        Utc::now(),
    )?;
    let intents = crate::native_intents::RetainedIntents::from_worker_plan(&plan)?;
    Ok(WorkerApplyAuthority {
        session: PlanApprovalSession::from_worker_plan(plan),
        intents,
    })
}

/// Worker observation port used by the authority gate before every apply.
pub trait TrustedObservationSource {
    /// Read current capability facts for a validated profile step.
    ///
    /// # Errors
    ///
    /// Returns an error when the native capability facts cannot be observed.
    fn observe(&self, step: &ProfileStepV3) -> Result<serde_json::Value, String>;
}

/// Re-observe every profile capability and bind the exact fresh facts digest.
///
/// # Errors
///
/// Returns an error if any capability cannot supply trustworthy native facts.
pub fn reobserve_profile(
    profile: &ProfileV3,
    observer: &dyn TrustedObservationSource,
    now: DateTime<Utc>,
) -> Result<ObservedStateV3, String> {
    profile.validate().map_err(|error| error.to_string())?;
    let mut values = BTreeMap::new();
    for step in &profile.steps {
        values.insert(
            step.step_id,
            ObservedValueV3 {
                capability: step.capability_id.clone(),
                parameters_digest: baselineops_domain::canonical_json_digest(&step.parameters)
                    .map_err(|error| error.to_string())?,
                observed_at: now,
                facts: BTreeMap::from([("native_result".into(), observer.observe(step)?)]),
            },
        );
    }
    let mut observed_state = ObservedStateV3 {
        captured_at: now,
        digest: Sha256Digest::of_bytes([]),
        values,
    };
    observed_state.digest = observed_state
        .calculated_digest()
        .map_err(|error| error.to_string())?;
    Ok(observed_state)
}

/// Native, read-only observation implementation compiled into the protected worker.
pub struct NativeObservationSource;

impl TrustedObservationSource for NativeObservationSource {
    fn observe(&self, step: &ProfileStepV3) -> Result<serde_json::Value, String> {
        let descriptor = lookup(step.capability_id.as_str())
            .ok_or_else(|| format!("unknown capability {}", step.capability_id))?;
        let parameters =
            serde_json::to_value(&step.parameters).map_err(|error| error.to_string())?;
        match native_audit(descriptor, &parameters) {
            CapabilityOutcome::Completed { result } => Ok(result),
            CapabilityOutcome::Unsupported { reason } => {
                Err(format!("native observation unavailable: {reason:?}"))
            }
            CapabilityOutcome::Failed { message, .. } => {
                Err(format!("native observation failed: {message}"))
            }
        }
    }
}

fn native_audit(
    descriptor: &'static CapabilityDescriptor,
    parameters: &serde_json::Value,
) -> CapabilityOutcome {
    crate::dispatch_native(descriptor, CapabilityOperation::Audit, parameters)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PlanBuildContext, TrustedActionDeriver, approval::PlanApprovalSession, build_plan,
    };
    use baselineops_domain::{
        ActionId, CapabilityId, ExecutionIntent, InputIdentityV3, JsonMap, ObservedStateV3,
        ObservedValueV3, PlanValidationContext, PlannedActionV3, ProfileDefaultsV3, ProfileId,
        ProfileStepV3, RebootRequirement, Reversibility, RiskLevel, SchemaVersion,
        SourceIdentityV3, SourceKind, ToolIdentityV3,
    };
    use chrono::Duration;
    use std::collections::BTreeMap;

    fn capability() -> CapabilityId {
        CapabilityId::new("v3.test.authority").expect("capability")
    }

    fn fixture() -> (
        ProfileV3,
        PlanBuildContext,
        DeterministicDeriver,
        DateTime<Utc>,
    ) {
        let now = Utc::now();
        let capability = capability();
        let profile = fixture_profile(now, &capability);
        let context = fixture_context(now, &profile.steps[0]);
        (profile, context, DeterministicDeriver, now)
    }

    fn fixture_profile(now: DateTime<Utc>, capability: &CapabilityId) -> ProfileV3 {
        ProfileV3 {
            schema_version: SchemaVersion::V3,
            id: ProfileId::new(),
            name: "authority test".into(),
            version: "1".into(),
            description: None,
            created_at: now - Duration::minutes(1),
            expires_at: None,
            defaults: ProfileDefaultsV3::default(),
            steps: vec![ProfileStepV3 {
                step_id: ActionId::new(),
                capability_id: capability.clone(),
                parameters: JsonMap::new(),
                depends_on: Vec::new(),
                continue_on_error: false,
            }],
            metadata: JsonMap::new(),
        }
    }

    fn fixture_context(now: DateTime<Utc>, step: &ProfileStepV3) -> PlanBuildContext {
        let package_digest = Sha256Digest::of_bytes(b"package");
        let host = crate::test_support::host("11");
        let observed = fixture_observation(now, step);
        PlanBuildContext {
            intent: ExecutionIntent::Apply,
            host,
            tool: ToolIdentityV3 {
                name: "baselineops".into(),
                version: "3".into(),
                build_digest: Some(package_digest),
            },
            package_digest,
            source: SourceIdentityV3 {
                kind: SourceKind::LocalFile,
                locator: "C:\\profiles\\test.json".into(),
                digest: Sha256Digest::of_bytes(b"profile"),
            },
            input: InputIdentityV3 {
                digest: Sha256Digest::of_bytes(b"profile"),
                size_bytes: 7,
            },
            resources: Vec::new(),
            observed_state: observed,
            lifetime: Duration::minutes(5),
        }
    }

    fn fixture_observation(now: DateTime<Utc>, step: &ProfileStepV3) -> ObservedStateV3 {
        let mut observed = ObservedStateV3 {
            captured_at: now,
            digest: Sha256Digest::of_bytes([]),
            values: BTreeMap::from([(
                step.step_id,
                ObservedValueV3 {
                    capability: step.capability_id.clone(),
                    parameters_digest: baselineops_domain::canonical_json_digest(&step.parameters)
                        .unwrap(),
                    observed_at: now,
                    facts: BTreeMap::from([("fresh".into(), serde_json::json!(true))]),
                },
            )]),
        };
        observed.digest = observed.calculated_digest().expect("observation");
        observed
    }

    struct DeterministicDeriver;
    impl TrustedActionDeriver for DeterministicDeriver {
        fn derive(
            &self,
            step: &ProfileStepV3,
            intent: ExecutionIntent,
            observed: &ObservedStateV3,
        ) -> Result<PlannedActionV3, String> {
            Ok(PlannedActionV3 {
                id: step.step_id,
                source_step: step.step_id,
                capability: step.capability_id.clone(),
                operation: intent.into(),
                parameters: step.parameters.clone(),
                depends_on: step.depends_on.clone(),
                continue_on_error: step.continue_on_error,
                facts_digest: observed.digest,
                preconditions: vec![],
                risk: RiskLevel::High,
                reversibility: Reversibility::Reversible,
                reboot: RebootRequirement::NotRequired,
                privileges: vec![],
                metadata: BTreeMap::new(),
            })
        }
    }

    fn live_context(context: &PlanBuildContext, now: DateTime<Utc>) -> PlanValidationContext {
        PlanValidationContext {
            now,
            intent: context.intent,
            host: context.host.clone(),
            tool: context.tool.clone(),
            package_digest: context.package_digest,
            source: context.source.clone(),
            input: context.input.clone(),
            observed_state_digest: context.observed_state.digest,
        }
    }

    #[test]
    fn retained_worker_proposal_uses_its_exact_canonical_digest() {
        let (profile, context, deriver, now) = fixture();
        let plan = build_plan(&profile, context.clone(), &deriver, now).expect("worker plan");
        let digest = plan.digest();
        assert_eq!(
            digest,
            baselineops_domain::canonical_json_digest(plan.proposal()).expect("digest")
        );
        let session = PlanApprovalSession::from_worker_plan(plan);
        let verified = session
            .approve_at_root(
                digest,
                &live_context(&context, now),
                std::path::Path::new("C:\\trusted"),
            )
            .expect("verified");
        assert_eq!(verified.digest(), digest);
        assert_eq!(verified.plan().intent, ExecutionIntent::Apply);
    }

    #[test]
    fn wrong_digest_and_live_binding_changes_are_rejected() {
        let (profile, context, deriver, now) = fixture();
        let seed = build_plan(&profile, context.clone(), &deriver, now).expect("worker plan");
        let digest = seed.digest();
        let contexts = [
            ("host", {
                let mut live = live_context(&context, now);
                live.host.boot_id = "rebooted".into();
                live
            }),
            ("package", {
                let mut live = live_context(&context, now);
                live.package_digest = Sha256Digest::of_bytes(b"other");
                live
            }),
            ("input", {
                let mut live = live_context(&context, now);
                live.input.size_bytes += 1;
                live
            }),
            ("source", {
                let mut live = live_context(&context, now);
                live.source.locator = "C:\\other.json".into();
                live
            }),
            ("facts", {
                let mut live = live_context(&context, now);
                live.observed_state_digest = Sha256Digest::of_bytes(b"edited");
                live
            }),
            (
                "expired",
                live_context(&context, now + Duration::minutes(6)),
            ),
        ];
        assert_rejects_live_changes(&profile, &context, &deriver, now, digest, contexts);
        let session = PlanApprovalSession::from_worker_plan(seed);
        assert!(
            session
                .approve_at_root(
                    Sha256Digest::of_bytes(b"self-approved"),
                    &live_context(&context, now),
                    std::path::Path::new("C:\\trusted")
                )
                .is_err()
        );
    }

    fn assert_rejects_live_changes(
        profile: &ProfileV3,
        context: &PlanBuildContext,
        deriver: &DeterministicDeriver,
        now: DateTime<Utc>,
        digest: Sha256Digest,
        contexts: [(&str, PlanValidationContext); 6],
    ) {
        for (name, live) in contexts {
            let session = PlanApprovalSession::from_worker_plan(
                build_plan(profile, context.clone(), deriver, now).expect("worker plan"),
            );
            assert!(
                session
                    .approve_at_root(digest, &live, std::path::Path::new("C:\\trusted"))
                    .is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn worker_authority_validates_digest_before_apply_eligibility() {
        let (profile, context, deriver, now) = fixture();
        let plan = build_plan(&profile, context.clone(), &deriver, now).expect("worker plan");
        let live = live_context(&context, now);
        let authority = WorkerApplyAuthority {
            session: PlanApprovalSession::from_worker_plan(plan),
            intents: crate::native_intents::RetainedIntents::empty_for_test(),
        };
        assert!(matches!(
            authority.approve_at_root(
                Sha256Digest::of_bytes(b"wrong"),
                &live,
                std::path::Path::new("C:\\trusted")
            ),
            Err(ApprovalError::DigestMismatch)
        ));

        let plan = build_plan(&profile, context, &deriver, now).expect("worker plan");
        let digest = plan.digest();
        let authority = WorkerApplyAuthority {
            session: PlanApprovalSession::from_worker_plan(plan),
            intents: crate::native_intents::RetainedIntents::empty_for_test(),
        };
        assert!(matches!(
            authority.approve_at_root(digest, &live, std::path::Path::new("C:\\trusted")),
            Err(ApprovalError::ApplyIneligible { .. })
        ));
    }

    struct FixedObserver;
    impl TrustedObservationSource for FixedObserver {
        fn observe(&self, _step: &ProfileStepV3) -> Result<serde_json::Value, String> {
            Ok(serde_json::json!({"fresh": true}))
        }
    }

    #[test]
    fn injected_observer_controls_the_fresh_facts_binding() {
        let (profile, _context, _deriver, now) = fixture();
        let observed = reobserve_profile(&profile, &FixedObserver, now).expect("observed");
        assert_eq!(observed.values.len(), 1);
        assert_ne!(observed.digest, Sha256Digest::of_bytes([]));
    }
}

#[cfg(test)]
#[path = "apply_authority/observation_tests.rs"]
mod observation_binding_tests;
