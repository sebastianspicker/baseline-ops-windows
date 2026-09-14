//! Tests for the fixed remote-access guardrail policy.

use super::*;
use crate::{ServiceObservation, ServiceStartMode, ServiceState, TcpListenerObservation};

fn service() -> Observation<ServiceObservation> {
    Observation::Present(ServiceObservation {
        name: "TermService".into(),
        state: ServiceState::Running,
        start_mode: ServiceStartMode::Automatic,
    })
}

fn complete_observation() -> RemoteGuardrailsObservation {
    RemoteGuardrailsObservation {
        remote_surface: RemoteSurfaceObservation {
            winrm_service: service(),
            winrm_listener_configured: Observation::Present(false),
            sshd_service: Observation::Missing,
            rdp_enabled: Observation::Present(false),
            rdp_service: service(),
            smb_server_service: service(),
            tcp_listeners: Observation::Present(vec![TcpListenerObservation {
                port: 3389,
                endpoint_count: 1,
            }]),
        },
        network_level_authentication: Observation::Present(1),
        security_layer: Observation::Present(2),
        minimum_encryption: Observation::Present(3),
        disable_restricted_admin: Observation::Present(0),
        disable_password_saving: Observation::Present(1),
        allow_solicited_remote_assistance: Observation::Present(0),
        allow_unsolicited_remote_assistance: Observation::Present(0),
        remote_assistance_ticket_lifetime: Observation::Present(60),
    }
}

#[test]
fn policy_rejects_dynamic_legacy_authority() {
    for value in [
        serde_json::json!({"rdp_port": 3389}),
        serde_json::json!({"firewall_rule": "Remote Desktop"}),
        serde_json::json!({"allowed_groups": ["DOMAIN\\RDP-Admins"]}),
        serde_json::json!({"remote_host": "host.example"}),
        serde_json::json!({"command": "netsh"}),
        serde_json::json!({"disable_password_saving": true}),
    ] {
        assert!(serde_json::from_value::<RemoteGuardrailsPolicy>(value).is_err());
    }
}

#[test]
fn complete_fixed_evidence_produces_read_only_plan() {
    let plan =
        build_remote_guardrails_plan(complete_observation(), &RemoteGuardrailsPolicy::default())
            .expect("complete fixed evidence");
    assert!(!plan.apply_available);
    assert!(plan.proposed_changes.is_empty());
    assert!(plan.audit.findings.iter().any(|item| {
        item.message
            .contains("does not test or claim remote reachability")
    }));
}

#[test]
fn denied_or_unparsed_evidence_cannot_produce_plan() {
    let mut observation = complete_observation();
    observation.network_level_authentication = Observation::AccessDenied;
    observation.minimum_encryption = Observation::Unparsed;
    let audit = evaluate_remote_guardrails(observation.clone(), &RemoteGuardrailsPolicy::default());
    assert!(
        audit
            .findings
            .iter()
            .any(|item| item.code == "REMOTE-GUARDRAILS-IncompleteEvidence")
    );
    assert!(build_remote_guardrails_plan(observation, &RemoteGuardrailsPolicy::default()).is_err());
}
