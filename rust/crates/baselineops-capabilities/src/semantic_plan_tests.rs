use super::*;
use serde_json::json;

#[test]
fn windows_update_proposal_uses_typed_defaults_and_exact_rollback() {
    let desired =
        policy::resolve_windows_update_desired_state(&policy::WindowsUpdateParameters::default())
            .unwrap();
    let fields = policy::build_windows_update_plan(
        policy::WindowsUpdateObservation {
            values: std::collections::BTreeMap::default(),
        },
        desired,
    )
    .mutations;
    let observation = policy::WindowsUpdateObservation {
        values: fields
            .iter()
            .map(|mutation| (mutation.field, policy::PolicyValueSnapshot::Missing))
            .collect(),
    };
    let observed = serde_json::to_value(&observation).unwrap();
    let SemanticPlan::WindowsUpdate(plan) =
        plan_observed("v3.windows-update.policy", &json!({}), &observed).unwrap()
    else {
        panic!("typed update proposal")
    };
    assert!(!plan.mutations.is_empty());
    assert_eq!(plan.rollback, observation);
    assert!(plan.requires_administrator);
    let mut compliant = observation.clone();
    for mutation in &plan.mutations {
        compliant
            .values
            .insert(mutation.field, mutation.desired.clone());
    }
    let SemanticPlan::WindowsUpdate(second) = plan_observed(
        "v3.windows-update.policy",
        &json!({}),
        &serde_json::to_value(compliant).unwrap(),
    )
    .unwrap() else {
        panic!("typed update proposal")
    };
    assert!(
        second.mutations.is_empty(),
        "compliant state must be idempotent"
    );
}

#[test]
fn incomplete_policy_maps_never_authorize_assumed_prestate() {
    for id in ["v3.office-browser.hardening", "v3.windows-update.policy"] {
        assert!(plan_observed(id, &json!({}), &json!({"values":{}})).is_err());
        assert!(plan_observed(id, &json!({"command":"reg.exe"}), &json!({"values":{}})).is_err());
    }
    assert!(
        plan_observed(
            "v3.security-options.drift",
            &json!({}),
            &json!({"observation":{"values":{}}})
        )
        .is_err()
    );
}

#[test]
fn read_only_capabilities_have_explicit_observation_proposals() {
    let result = json!({"provider_error":"access denied"});
    let SemanticPlan::Observation {
        result: retained,
        reason,
    } = plan_observed("v3.doh.audit", &json!({}), &result).unwrap()
    else {
        panic!("observation")
    };
    assert_eq!(retained, result);
    assert!(reason.contains("read-only"));
}

#[test]
fn malformed_observations_fail_for_every_capability() {
    for descriptor in policy::list() {
        for malformed in [Value::Null, json!([]), json!({}), json!(true)] {
            assert!(
                plan_observed(descriptor.id, &json!({}), &malformed).is_err(),
                "{}",
                descriptor.id
            );
        }
    }
}

#[test]
fn old_or_unknown_observation_fields_are_rejected() {
    assert!(
        plan_observed(
            "v3.windows-update.policy",
            &json!({}),
            &json!({"values":{}, "command":"reg.exe"})
        )
        .is_err()
    );
    assert!(
        plan_observed(
            "v3.sysmon.rule-drift",
            &json!({}),
            &json!({"observation":{}})
        )
        .is_err()
    );
}
