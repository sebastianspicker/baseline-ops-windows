use super::*;

fn complete() -> EmergencyIsolationObservation {
    EmergencyIsolationObservation {
        profiles: fixed_profiles()
            .into_iter()
            .map(|profile| IsolationProfileSnapshot {
                profile,
                inbound: Observation::Present(IsolationDefaultAction::Allow),
                outbound: Observation::Present(IsolationDefaultAction::Block),
            })
            .collect(),
        break_glass_profile_sha256: Observation::Present([1; 32]),
        managed_isolation_active: Observation::Present(false),
    }
}

fn assert_blocked(observation: &EmergencyIsolationObservation, policy: &EmergencyIsolationPolicy) {
    let plan = build_emergency_isolation_plan(observation.clone(), policy);
    assert!(plan.actions.is_empty());
    assert!(!plan.audit.plan_blockers.is_empty());
    assert_eq!(plan.rollback, observation.profiles);
    assert!(validate_emergency_isolation_preflight(observation, policy).is_err());
    let captured = serde_json::json!({"observation": observation});
    assert!(
        crate::plan_observed(
            "v3.network.emergency-isolation",
            &serde_json::to_value(policy).unwrap(),
            &captured,
        )
        .is_err()
    );
}

#[test]
fn duplicates_missing_profiles_and_incomplete_fields_block_shared_planning() {
    let mut duplicate = complete();
    duplicate.profiles[2].profile = IsolationFirewallProfile::Domain;
    assert_blocked(&duplicate, &EmergencyIsolationPolicy::default());
    let mut missing = complete();
    missing.profiles.pop();
    assert_blocked(&missing, &EmergencyIsolationPolicy::default());
    for evidence in [
        Observation::Missing,
        Observation::AccessDenied,
        Observation::Unparsed,
        Observation::NotRun,
    ] {
        let mut observation = complete();
        observation.profiles[0].outbound = evidence;
        assert_blocked(&observation, &EmergencyIsolationPolicy::default());
    }
}

#[test]
fn active_or_unknown_managed_state_never_generates_actions() {
    for state in [
        Observation::Present(true),
        Observation::NotRun,
        Observation::Missing,
        Observation::AccessDenied,
    ] {
        let mut observation = complete();
        observation.managed_isolation_active = state;
        assert_blocked(&observation, &EmergencyIsolationPolicy::default());
    }
}

#[test]
fn required_break_glass_must_be_observed_before_any_action_proposal() {
    let policy = EmergencyIsolationPolicy {
        require_preprovisioned_break_glass: true,
    };
    for evidence in [
        Observation::NotRun,
        Observation::Missing,
        Observation::AccessDenied,
    ] {
        let mut observation = complete();
        observation.break_glass_profile_sha256 = evidence;
        assert_blocked(&observation, &policy);
    }
}

#[test]
fn deltas_have_fixed_order_and_compliant_defaults_produce_a_noop() {
    let policy = EmergencyIsolationPolicy {
        require_preprovisioned_break_glass: true,
    };
    let mut observation = complete();
    observation.profiles.reverse();
    let plan = build_emergency_isolation_plan(observation.clone(), &policy);
    assert_eq!(
        plan.actions,
        vec![
            EmergencyIsolationAction::BlockInbound(IsolationFirewallProfile::Domain),
            EmergencyIsolationAction::BlockInbound(IsolationFirewallProfile::Private),
            EmergencyIsolationAction::BlockInbound(IsolationFirewallProfile::Public),
            EmergencyIsolationAction::PreservePreprovisionedBreakGlass,
        ]
    );
    for profile in &mut observation.profiles {
        profile.inbound = Observation::Present(IsolationDefaultAction::Block);
    }
    let plan = build_emergency_isolation_plan(observation.clone(), &policy);
    assert!(plan.actions.is_empty());
    assert!(plan.audit.plan_blockers.is_empty());
    let semantic = crate::plan_observed(
        "v3.network.emergency-isolation",
        &serde_json::to_value(policy).unwrap(),
        &serde_json::json!({"observation": observation}),
    )
    .unwrap();
    assert!(!semantic.proposes_changes());
}
