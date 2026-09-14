use std::cell::{Cell, RefCell};

use super::*;
use baselineops_domain::{
    ActionId, CapabilityId, JsonMap, Operation, PlannedActionV3, PreconditionV3, Privilege,
    ProfileDefaultsV3, ProfileId, ProfileStepV3, RebootRequirement, Reversibility, RiskLevel,
    SchemaVersion, SourceKind,
};

fn capability() -> CapabilityId {
    CapabilityId::new("v3.test.capability").expect("capability")
}

fn profile(expires_at: Option<DateTime<Utc>>) -> ProfileV3 {
    ProfileV3 {
        schema_version: SchemaVersion::V3,
        id: ProfileId::new(),
        name: "test profile".into(),
        version: "1.0.0".into(),
        description: None,
        created_at: Utc::now() - Duration::minutes(1),
        expires_at,
        defaults: ProfileDefaultsV3::default(),
        steps: vec![ProfileStepV3 {
            step_id: ActionId::new(),
            capability_id: capability(),
            parameters: JsonMap::default(),
            depends_on: Vec::new(),
            continue_on_error: false,
        }],
        metadata: JsonMap::default(),
    }
}

fn observed_state(profile: &ProfileV3) -> ObservedStateV3 {
    crate::reobserve_profile(profile, &TestObserver, Utc::now()).expect("observations")
}
struct TestObserver;
impl crate::TrustedObservationSource for TestObserver {
    fn observe(&self, _: &ProfileStepV3) -> Result<serde_json::Value, String> {
        Ok(serde_json::json!({"enabled":true}))
    }
}

fn context(observed_state: ObservedStateV3) -> PlanBuildContext {
    let package_digest = Sha256Digest::of_bytes(b"package");
    let host = crate::test_support::host("10.0");
    PlanBuildContext {
        intent: ExecutionIntent::Apply,
        host,
        tool: ToolIdentityV3 {
            name: "baselineops".into(),
            version: "3.0.0".into(),
            build_digest: Some(package_digest),
        },
        package_digest,
        source: SourceIdentityV3 {
            kind: SourceKind::LocalFile,
            locator: "profile.json".into(),
            digest: Sha256Digest::of_bytes(b"profile"),
        },
        input: InputIdentityV3 {
            digest: Sha256Digest::of_bytes(b"input"),
            size_bytes: 5,
        },
        resources: Vec::new(),
        observed_state,
        lifetime: Duration::minutes(5),
    }
}

struct TestRegistry {
    operation: Operation,
}

struct FailingRegistry {
    calls: Cell<usize>,
    seen: RefCell<Vec<ActionId>>,
}

impl TrustedActionDeriver for FailingRegistry {
    fn derive(
        &self,
        step: &ProfileStepV3,
        intent: ExecutionIntent,
        observed_state: &ObservedStateV3,
    ) -> Result<PlannedActionV3, String> {
        self.seen.borrow_mut().push(step.step_id);
        let call = self.calls.get() + 1;
        self.calls.set(call);
        if call == 2 {
            return Err("second step failed".into());
        }
        TestRegistry {
            operation: intent.into(),
        }
        .derive(step, intent, observed_state)
    }
}

impl TrustedActionDeriver for TestRegistry {
    fn derive(
        &self,
        step: &ProfileStepV3,
        _intent: ExecutionIntent,
        observed_state: &ObservedStateV3,
    ) -> Result<PlannedActionV3, String> {
        Ok(PlannedActionV3 {
            id: step.step_id,
            source_step: step.step_id,
            capability: step.capability_id.clone(),
            operation: self.operation,
            parameters: step.parameters.clone(),
            depends_on: step.depends_on.clone(),
            continue_on_error: step.continue_on_error,
            facts_digest: observed_state.digest,
            preconditions: vec![PreconditionV3::Elevation { required: true }],
            risk: RiskLevel::High,
            reversibility: Reversibility::ConditionallyReversible,
            reboot: RebootRequirement::Recommended,
            privileges: vec![Privilege::Administrator],
            metadata: BTreeMap::from([("registry".into(), serde_json::json!(true))]),
        })
    }
}

#[test]
fn trusted_registry_derives_worker_owned_safety_metadata() {
    let profile = profile(None);
    let state = observed_state(&profile);
    let plan = build_plan(
        &profile,
        context(state.clone()),
        &TestRegistry {
            operation: Operation::Apply,
        },
        Utc::now(),
    )
    .expect("plan");
    let action = &plan.proposal().actions[0];
    assert_eq!(action.source_step, profile.steps[0].step_id);
    assert_eq!(action.operation, Operation::Apply);
    assert_eq!(action.risk, RiskLevel::High);
    assert_eq!(action.facts_digest, state.digest);
    assert_eq!(action.privileges, vec![Privilege::Administrator]);
}

#[test]
fn planner_rejects_expired_profiles_and_mismatched_intent() {
    let now = Utc::now();
    let expired = profile(Some(now - Duration::seconds(1)));
    let error = build_plan(
        &expired,
        context(observed_state(&expired)),
        &TestRegistry {
            operation: Operation::Apply,
        },
        now,
    )
    .expect_err("expired profile");
    assert!(matches!(error, PlanningError::ExpiredProfile));

    let current = profile(None);
    let error = build_plan(
        &current,
        context(observed_state(&current)),
        &TestRegistry {
            operation: Operation::Audit,
        },
        Utc::now(),
    )
    .expect_err("registry action must match command intent");
    assert!(matches!(error, PlanningError::IntentMismatch));
}

#[test]
fn indexed_planning_preserves_topological_derivation_error_order() {
    let mut profile = profile(None);
    let first = profile.steps[0].step_id;
    let second = ActionId::new();
    let third = ActionId::new();
    profile.steps.push(ProfileStepV3 {
        step_id: second,
        capability_id: capability(),
        parameters: JsonMap::default(),
        depends_on: vec![first],
        continue_on_error: false,
    });
    profile.steps.push(ProfileStepV3 {
        step_id: third,
        capability_id: capability(),
        parameters: JsonMap::default(),
        depends_on: vec![second],
        continue_on_error: false,
    });
    let registry = FailingRegistry {
        calls: Cell::new(0),
        seen: RefCell::new(Vec::new()),
    };

    let error = build_plan(
        &profile,
        context(observed_state(&profile)),
        &registry,
        Utc::now(),
    )
    .expect_err("second derivation must fail");

    assert!(matches!(error, PlanningError::Derivation(message) if message == "second step failed"));
    assert_eq!(*registry.seen.borrow(), vec![first, second]);
}

#[test]
fn reviewed_apply_envelope_keeps_digest_without_extending_expiry() {
    let now = Utc::now();
    let profile = profile(None);
    let plan_context = context(observed_state(&profile));
    let reviewed = build_plan(
        &profile,
        plan_context.clone(),
        &TestRegistry {
            operation: Operation::Apply,
        },
        now,
    )
    .expect("reviewed")
    .proposal()
    .clone();
    let rebuilt = rebuild_reviewed_apply_plan(
        &reviewed,
        &profile,
        plan_context,
        &TestRegistry {
            operation: Operation::Apply,
        },
        now + Duration::seconds(1),
    )
    .expect("rebuilt");
    assert_eq!(
        rebuilt.digest(),
        canonical_json_digest(&reviewed).expect("digest")
    );
    assert_eq!(rebuilt.proposal().expires_at, reviewed.expires_at);

    let mut extended = reviewed;
    extended.expires_at += Duration::hours(1);
    assert!(matches!(
        rebuild_reviewed_apply_plan(
            &extended,
            &profile,
            context(observed_state(&profile)),
            &TestRegistry {
                operation: Operation::Apply,
            },
            now + Duration::seconds(1),
        ),
        Err(PlanningError::ReviewedEnvelopeMismatch)
    ));
}
