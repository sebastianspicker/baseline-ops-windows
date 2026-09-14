use super::*;
use baselineops_capabilities::{
    EmergencyIsolationPolicy, FirewallBaselineProfileObservations, FirewallPolicyModifyState,
    evaluate_emergency_isolation,
};

fn profile(
    inbound: FirewallEvidence<FirewallDefaultAction>,
    outbound: FirewallEvidence<FirewallDefaultAction>,
) -> FirewallBaselineProfileObservation {
    FirewallBaselineProfileObservation {
        enabled: FirewallEvidence::Present(true),
        default_inbound_action: inbound,
        default_outbound_action: outbound,
        notify_on_listen: FirewallEvidence::Present(false),
    }
}

#[test]
fn native_mapping_preserves_each_fixed_profile_without_inferring_managed_isolation() {
    let allow = FirewallEvidence::Present(FirewallDefaultAction::Allow);
    let block = FirewallEvidence::Present(FirewallDefaultAction::Block);
    let source = FirewallBaselineObservation {
        profiles: FirewallBaselineProfileObservations {
            domain: profile(allow.clone(), block.clone()),
            private: profile(block.clone(), allow),
            public: profile(block.clone(), block),
        },
        local_policy_modify_state: FirewallPolicyModifyState::GroupPolicyOverride,
    };
    let actual = map_observation(&source).unwrap();
    assert_eq!(
        actual
            .profiles
            .iter()
            .map(|value| value.profile)
            .collect::<Vec<_>>(),
        vec![
            IsolationFirewallProfile::Domain,
            IsolationFirewallProfile::Private,
            IsolationFirewallProfile::Public,
        ]
    );
    assert_eq!(
        actual.profiles[0].inbound,
        Observation::Present(IsolationDefaultAction::Allow)
    );
    assert_eq!(
        actual.profiles[1].outbound,
        Observation::Present(IsolationDefaultAction::Allow)
    );
    assert_eq!(
        actual.profiles[2].outbound,
        Observation::Present(IsolationDefaultAction::Block)
    );
    assert_eq!(actual.managed_isolation_active, Observation::NotRun);
    assert_eq!(actual.break_glass_profile_sha256, Observation::NotRun);
    let audit = evaluate_emergency_isolation(actual, &EmergencyIsolationPolicy::default());
    assert!(
        audit
            .findings
            .iter()
            .any(|value| value.code == "ISO-ManagedStateUnknown")
    );
}

#[test]
fn missing_denied_and_malformed_evidence_never_becomes_a_default() {
    for (evidence, expected) in [
        (FirewallEvidence::Missing, Observation::Missing),
        (FirewallEvidence::AccessDenied, Observation::AccessDenied),
        (FirewallEvidence::Unparsed, Observation::Unparsed),
    ] {
        assert_eq!(map_action(&evidence).unwrap(), expected);
    }
    assert!(map_action(&FirewallEvidence::Unavailable).is_err());
}

#[cfg(not(windows))]
#[test]
fn unsupported_host_cannot_obtain_or_mutate_native_firewall_state() {
    assert!(matches!(
        audit_emergency_isolation(),
        Err(PlatformError::UnsupportedPlatform)
    ));
}
