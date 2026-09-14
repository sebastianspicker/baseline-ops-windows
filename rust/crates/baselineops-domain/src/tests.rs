use std::collections::BTreeMap;

use chrono::{Duration, Utc};
use schemars::schema_for;
use serde_json::{Value, json};

use crate::{
    ActionId, ActionReceiptV3, ActionStatus, ArtifactId, ArtifactKind, ArtifactV3, CapabilityId,
    DomainError, ExecutionIntent, ExitCode, HostIdentityV3, InputIdentityV3, JsonLoadLimits,
    ObservedStateV3, ObservedValueV3, Operation, PlanId, PlanV3, PlanValidationContext,
    PlannedActionV3, Privilege, ProfileDefaultsV3, ProfileId, ProfileStepV3, ProfileV3,
    RebootRequirement, ResultStatus, Reversibility, RiskLevel, RunId, SchemaVersion, Sha256Digest,
    SourceIdentityV3, SourceKind, ToolIdentityV3, WorkerResultV3, canonical_json_bytes,
    canonical_json_digest, load_profile_json,
};

fn capability() -> CapabilityId {
    CapabilityId::new("defender.health").expect("valid test capability")
}

fn step(step_id: ActionId, depends_on: Vec<ActionId>) -> ProfileStepV3 {
    ProfileStepV3 {
        step_id,
        capability_id: capability(),
        parameters: BTreeMap::new(),
        depends_on,
        continue_on_error: false,
    }
}

fn planned_action(
    id: ActionId,
    source_step: ActionId,
    dependencies: Vec<ActionId>,
    facts_digest: Sha256Digest,
) -> PlannedActionV3 {
    PlannedActionV3 {
        id,
        source_step,
        capability: capability(),
        operation: Operation::Apply,
        parameters: BTreeMap::new(),
        depends_on: dependencies,
        continue_on_error: false,
        facts_digest,
        preconditions: Vec::new(),
        risk: RiskLevel::Moderate,
        reversibility: Reversibility::Reversible,
        reboot: RebootRequirement::NotRequired,
        privileges: vec![Privilege::Administrator],
        metadata: BTreeMap::new(),
    }
}

fn profile(steps: Vec<ProfileStepV3>) -> ProfileV3 {
    ProfileV3 {
        schema_version: SchemaVersion::V3,
        id: ProfileId::new(),
        name: "test profile".into(),
        version: "1.0.0".into(),
        description: None,
        created_at: Utc::now(),
        expires_at: None,
        defaults: ProfileDefaultsV3::default(),
        steps,
        metadata: BTreeMap::new(),
    }
}

fn host() -> HostIdentityV3 {
    let mut host = HostIdentityV3 {
        host_id: "host-1".into(),
        boot_id: "boot-1".into(),
        session_id: "session-1".into(),
        hostname: "endpoint-1".into(),
        os_family: crate::OsFamily::Windows,
        os_version: "10.0.26100".into(),
        architecture: "x86_64".into(),
        fingerprint: Sha256Digest::of_bytes(b"placeholder"),
    };
    host.fingerprint = host.calculated_fingerprint().expect("host fingerprint");
    host
}

fn observed_state(step_id: ActionId) -> ObservedStateV3 {
    let mut values = BTreeMap::new();
    values.insert(
        step_id,
        ObservedValueV3 {
            capability: capability(),
            parameters_digest: canonical_json_digest(&crate::JsonMap::new()).unwrap(),
            observed_at: Utc::now(),
            facts: BTreeMap::from([("enabled".into(), json!(true))]),
        },
    );
    let mut state = ObservedStateV3 {
        captured_at: Utc::now(),
        digest: Sha256Digest::of_bytes(b"placeholder"),
        values,
    };
    state.digest = state.calculated_digest().expect("state digest");
    state
}

fn plan() -> (PlanV3, PlanValidationContext) {
    let step = step(ActionId::new(), Vec::new());
    let profile = profile(vec![step.clone()]);
    let source_digest = Sha256Digest::of_bytes(b"profile source");
    let package_digest = Sha256Digest::of_bytes(b"verified package");
    let tool = ToolIdentityV3 {
        name: "baselineops".into(),
        version: "3.0.0".into(),
        build_digest: Some(package_digest),
    };
    let source = SourceIdentityV3 {
        kind: SourceKind::LocalFile,
        locator: "profile.json".into(),
        digest: source_digest,
    };
    let input = InputIdentityV3 {
        digest: source_digest,
        size_bytes: 14,
    };
    let host = host();
    let observed_state = observed_state(step.step_id);
    let now = Utc::now();
    let context = PlanValidationContext {
        now: now + Duration::seconds(1),
        intent: ExecutionIntent::Apply,
        host: host.clone(),
        tool: tool.clone(),
        package_digest,
        source: source.clone(),
        input: input.clone(),
        observed_state_digest: observed_state.digest,
    };
    let plan = plan_document(&profile, &step, &observed_state, now, &context);
    (plan, context)
}

fn plan_document(
    profile: &ProfileV3,
    step: &ProfileStepV3,
    observed_state: &ObservedStateV3,
    now: chrono::DateTime<Utc>,
    context: &PlanValidationContext,
) -> PlanV3 {
    PlanV3 {
        schema_version: crate::PlanSchemaVersion::V4,
        id: PlanId::new(),
        run_id: RunId::new(),
        intent: ExecutionIntent::Apply,
        profile_id: profile.id,
        profile_digest: canonical_json_digest(profile).expect("profile digest"),
        host: context.host.clone(),
        tool: context.tool.clone(),
        package_digest: context.package_digest,
        source: context.source.clone(),
        input: context.input.clone(),
        resources: Vec::new(),
        observed_state: observed_state.clone(),
        issued_at: now,
        expires_at: now + Duration::minutes(5),
        actions: vec![planned_action(
            ActionId::new(),
            step.step_id,
            Vec::new(),
            observed_state.digest,
        )],
        metadata: BTreeMap::new(),
    }
}

#[test]
fn canonical_json_is_key_order_independent() {
    let first = json!({"z": [2, 1], "a": {"y": true, "b": false}});
    let second = json!({"a": {"b": false, "y": true}, "z": [2, 1]});
    assert_eq!(
        canonical_json_bytes(&first).unwrap(),
        canonical_json_bytes(&second).unwrap()
    );
    assert_eq!(
        canonical_json_digest(&first).unwrap(),
        canonical_json_digest(&second).unwrap()
    );
}

#[test]
fn strict_loader_rejects_unknown_fields_and_size_overflow() {
    let valid_profile = profile(vec![step(ActionId::new(), Vec::new())]);
    let mut document = serde_json::to_value(valid_profile).unwrap();
    document
        .as_object_mut()
        .expect("profile object")
        .insert("unexpected".into(), Value::Null);
    let error = load_profile_json(
        &serde_json::to_vec(&document).unwrap(),
        JsonLoadLimits::default(),
    )
    .expect_err("unknown fields must fail");
    assert!(matches!(error, DomainError::Json(_)));

    let mut invalid_capability =
        serde_json::to_value(profile(vec![step(ActionId::new(), Vec::new())])).unwrap();
    invalid_capability["steps"][0]["capability_id"] = Value::String("invalid/capability".into());
    let error = load_profile_json(
        &serde_json::to_vec(&invalid_capability).unwrap(),
        JsonLoadLimits::default(),
    )
    .expect_err("typed IDs must be validated during decoding");
    assert!(matches!(error, DomainError::Json(_)));

    let error = load_profile_json(
        b"{}",
        JsonLoadLimits {
            max_bytes: 1,
            ..JsonLoadLimits::default()
        },
    )
    .expect_err("bounded loader must reject oversized input");
    assert!(matches!(error, DomainError::LimitExceeded { .. }));
}

#[test]
fn profile_json_rejects_worker_authority_fields() {
    for field in [
        "operation",
        "preconditions",
        "risk",
        "reversibility",
        "reboot",
        "privileges",
        "artifacts",
    ] {
        let mut document = serde_json::to_value(profile(vec![step(ActionId::new(), Vec::new())]))
            .expect("profile JSON");
        document["steps"][0][field] = Value::Null;
        let error = load_profile_json(
            &serde_json::to_vec(&document).expect("serialized profile"),
            JsonLoadLimits::default(),
        )
        .expect_err("profiles must not carry worker authority");
        assert!(matches!(error, DomainError::Json(_)), "field {field}");
    }
}

#[test]
fn observed_facts_digest_ignores_capture_timestamps() {
    let first = observed_state(ActionId::new());
    let mut second = first.clone();
    second.captured_at += Duration::hours(1);
    second
        .values
        .values_mut()
        .next()
        .expect("facts")
        .observed_at += Duration::hours(1);

    assert_eq!(
        first.calculated_digest().expect("first digest"),
        second.calculated_digest().expect("second digest")
    );
}

#[test]
fn profile_validation_rejects_duplicate_unknown_and_cyclic_dependencies() {
    let shared = ActionId::new();
    let duplicate = profile(vec![step(shared, Vec::new()), step(shared, Vec::new())]);
    assert!(duplicate.validate().is_err());

    let unknown = profile(vec![step(ActionId::new(), vec![ActionId::new()])]);
    assert!(unknown.validate().is_err());

    let first = ActionId::new();
    let second = ActionId::new();
    let cycle = profile(vec![step(first, vec![second]), step(second, vec![first])]);
    assert!(cycle.validate().is_err());
}

#[test]
fn profile_topological_order_is_stable() {
    let first = ActionId::new();
    let second = ActionId::new();
    let third = ActionId::new();
    let profile = profile(vec![
        step(first, Vec::new()),
        step(second, vec![first]),
        step(third, vec![second]),
    ]);
    assert_eq!(
        profile.topological_order().unwrap().as_slice(),
        &[first, second, third]
    );
}

#[test]
fn plan_requires_fresh_matching_live_bindings_before_typestate_approval() {
    let (plan, context) = plan();
    assert!(plan.validate_against(&context).is_ok());
    assert!(plan.clone().verify_for_execution(&context).is_ok());

    let mut mismatched_facts = plan.clone();
    mismatched_facts.actions[0].facts_digest = Sha256Digest::of_bytes(b"different facts");
    assert!(mismatched_facts.validate_structure().is_err());

    let expired = PlanValidationContext {
        now: plan.expires_at,
        ..context.clone()
    };
    assert!(plan.validate_against(&expired).is_err());

    let mut mismatched = context;
    mismatched.package_digest = Sha256Digest::of_bytes(b"different package");
    assert!(plan.validate_against(&mismatched).is_err());
}

#[test]
fn result_statuses_have_the_documented_process_exit_mapping() {
    assert_eq!(ExitCode::for_status(ResultStatus::Completed).as_i32(), 0);
    assert_eq!(
        ExitCode::for_status(ResultStatus::ExecutionFailed).as_i32(),
        1
    );
    assert_eq!(ExitCode::for_status(ResultStatus::Warnings).as_i32(), 2);
    assert_eq!(ExitCode::for_status(ResultStatus::Unsupported).as_i32(), 3);
    assert_eq!(ExitCode::for_status(ResultStatus::Rejected).as_i32(), 4);
    assert_eq!(ExitCode::for_status(ResultStatus::Cancelled).as_i32(), 5);
}

#[test]
fn worker_result_rejects_schema_confusion_and_status_mismatch() {
    let (plan, _) = plan();
    let result = unsupported_worker_result(&plan);
    result.validate().expect("valid unsupported result");

    let mut mismatched = result.clone();
    mismatched.exit_code = ExitCode::Completed.as_i32();
    assert!(mismatched.validate().is_err());

    let mut unanchored = result.clone();
    unanchored.final_status = ResultStatus::Completed;
    unanchored.reason = None;
    unanchored.exit_code = ExitCode::Completed.as_i32();
    assert!(unanchored.validate().is_err());

    let receipt = receipt();
    let mut duplicate_receipts = unanchored.clone();
    duplicate_receipts.journal_terminal_hash = Some(Sha256Digest::of_bytes(b"journal"));
    duplicate_receipts.receipts = vec![receipt.clone(), receipt];
    assert!(duplicate_receipts.validate().is_err());

    let mut traversal = unanchored;
    traversal.journal_terminal_hash = Some(Sha256Digest::of_bytes(b"journal"));
    traversal.artifact_manifest.push(ArtifactV3 {
        id: ArtifactId::new(),
        kind: ArtifactKind::Evidence,
        media_type: "application/json".into(),
        locator: "../outside.json".into(),
        digest: Sha256Digest::of_bytes(b"artifact"),
        size_bytes: 8,
        created_at: Utc::now(),
        metadata: BTreeMap::new(),
    });
    assert!(traversal.validate().is_err());

    let mut payload = serde_json::to_value(result).expect("payload");
    payload["unexpected"] = json!(true);
    assert!(serde_json::from_value::<WorkerResultV3>(payload).is_err());
}

fn unsupported_worker_result(plan: &PlanV3) -> WorkerResultV3 {
    WorkerResultV3 {
        schema_version: SchemaVersion::V3,
        plan_id: plan.id,
        run_id: plan.run_id,
        plan_digest: canonical_json_digest(plan).expect("digest"),
        journal_terminal_hash: None,
        receipts: Vec::new(),
        artifact_manifest: Vec::new(),
        final_status: ResultStatus::Unsupported,
        reason: Some("evidence is open".into()),
        exit_code: ExitCode::Unsupported.as_i32(),
    }
}

fn receipt() -> ActionReceiptV3 {
    ActionReceiptV3 {
        action_id: ActionId::new(),
        capability: capability(),
        pre_state_digest: Sha256Digest::of_bytes(b"before"),
        post_state_digest: Sha256Digest::of_bytes(b"after"),
        status: ActionStatus::Succeeded,
    }
}

#[test]
fn worker_result_validation_preserves_error_order() {
    let (plan, _) = plan();
    let mut result = unsupported_worker_result(&plan);
    result.exit_code = ExitCode::Completed.as_i32();
    assert_validation_message(
        result.validate(),
        "worker result status and exit code disagree",
    );

    result.exit_code = ExitCode::Unsupported.as_i32();
    result.reason = None;
    result.journal_terminal_hash = Some(Sha256Digest::of_bytes(b"journal"));
    assert_validation_message(
        result.validate(),
        "non-success worker result must explain its terminal status",
    );

    result.reason = Some("evidence is open".into());
    assert_validation_message(
        result.validate(),
        "unsupported worker result must not carry mutation evidence",
    );
}

fn assert_validation_message(result: Result<(), DomainError>, expected: &str) {
    match result.expect_err("validation must fail") {
        DomainError::Validation(message) => assert_eq!(message, expected),
        other => panic!("expected validation error, received {other}"),
    }
}

#[test]
fn profile_schema_is_closed_and_exposes_v3_contract_fields() {
    let schema = serde_json::to_value(schema_for!(ProfileV3)).unwrap();
    let object = schema.as_object().unwrap();
    let properties = object
        .get("properties")
        .and_then(Value::as_object)
        .expect("profile schema properties");
    assert!(properties.contains_key("schema_version"));
    assert!(properties.contains_key("profile_id"));
    assert!(properties.contains_key("defaults"));
    assert!(properties.contains_key("steps"));
    assert_eq!(
        object.get("additionalProperties"),
        Some(&Value::Bool(false))
    );
}

#[test]
fn obsolete_saved_plan_requires_regeneration() {
    let (plan, _) = plan();
    let mut value = serde_json::to_value(plan).unwrap();
    value["schema_version"] = json!("3.0");
    let error = crate::load_plan_json(
        &serde_json::to_vec(&value).unwrap(),
        JsonLoadLimits::default(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("regenerate"));
}

#[test]
fn plan_rejects_substituted_step_observations() {
    let (plan, _) = plan();
    for change in ["step", "capability", "parameters"] {
        let mut tampered = plan.clone();
        let (key, mut value) = tampered.observed_state.values.pop_first().unwrap();
        let key = match change {
            "step" => ActionId::new(),
            "capability" => {
                value.capability = CapabilityId::new("v3.other.audit").unwrap();
                key
            }
            _ => {
                value.parameters_digest = Sha256Digest::of_bytes(b"different parameters");
                key
            }
        };
        tampered.observed_state.values.insert(key, value);
        tampered.observed_state.digest = tampered.observed_state.calculated_digest().unwrap();
        tampered.actions[0].facts_digest = tampered.observed_state.digest;
        assert!(tampered.validate_structure().is_err(), "{change}");
    }
}
