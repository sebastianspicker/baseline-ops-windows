//! Semantic-only emergency-isolation model for capability 21.
//!
//! Dynamic break-glass addresses, ports, adapter selection, task names, and
//! registry locations from the legacy script are excluded. No mutation code is
//! represented or reachable through this foundation.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;

/// Fixed built-in Windows Firewall profiles.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum IsolationFirewallProfile {
    /// Domain-authenticated network profile.
    Domain,
    /// Private network profile.
    Private,
    /// Public network profile.
    Public,
}

/// Fixed firewall default disposition used by the semantic isolation plan.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum IsolationDefaultAction {
    /// Permit traffic by default.
    Allow,
    /// Block traffic by default.
    Block,
}

/// Snapshot for one fixed firewall profile before an unavailable future apply.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct IsolationProfileSnapshot {
    /// Fixed profile identity.
    pub profile: IsolationFirewallProfile,
    /// Effective inbound default.
    pub inbound: Observation<IsolationDefaultAction>,
    /// Effective outbound default.
    pub outbound: Observation<IsolationDefaultAction>,
}

/// Strict policy with no address, port, adapter, or rollback-duration authority.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct EmergencyIsolationPolicy {
    /// Require a pre-provisioned, digest-bound break-glass profile before planning.
    pub require_preprovisioned_break_glass: bool,
}

/// Read-only isolation state needed to prevent unsafe false-positive planning.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EmergencyIsolationObservation {
    /// Fixed profile rollback evidence.
    pub profiles: Vec<IsolationProfileSnapshot>,
    /// Pre-provisioned break-glass profile digest, if independently verified.
    pub break_glass_profile_sha256: Observation<[u8; 32]>,
    /// Whether an existing managed isolation is active.
    pub managed_isolation_active: Observation<bool>,
}

/// Fixed semantic actions, intentionally not executable commands.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum EmergencyIsolationAction {
    /// Block inbound traffic on a fixed built-in profile.
    BlockInbound(IsolationFirewallProfile),
    /// Block outbound traffic on a fixed built-in profile.
    BlockOutbound(IsolationFirewallProfile),
    /// Preserve the separately provisioned break-glass profile.
    PreservePreprovisionedBreakGlass,
}

/// Typed reason that prevents an emergency-isolation action proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyIsolationPlanBlocker {
    /// The three unique fixed profiles do not all have typed default actions.
    IncompleteRollbackEvidence,
    /// Policy requires a break-glass profile whose digest has not been verified.
    BreakGlassUnverified,
    /// A managed isolation is already active.
    ManagedIsolationActive,
    /// The managed-isolation marker was not read successfully.
    ManagedIsolationUnknown,
}

/// Pure emergency-isolation audit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct EmergencyIsolationAudit {
    /// Fixed rollback and preflight evidence.
    pub observation: EmergencyIsolationObservation,
    /// Applied strict policy.
    pub policy: EmergencyIsolationPolicy,
    /// Evidence gaps and activation blockers.
    pub findings: Vec<PolicyFinding>,
    /// Typed reasons that prevent action proposal derivation.
    pub plan_blockers: Vec<EmergencyIsolationPlanBlocker>,
}

/// A semantic plan with complete rollback snapshot retained for future review.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct EmergencyIsolationPlan {
    /// Audit that bound the proposal to observed state.
    pub audit: EmergencyIsolationAudit,
    /// Fixed profile operations only.
    pub actions: Vec<EmergencyIsolationAction>,
    /// Exact pre-state for an independently authorized rollback route.
    pub rollback: Vec<IsolationProfileSnapshot>,
    /// No production Apply exists.
    pub apply_available: bool,
    /// A reboot is not claimed by this semantic model.
    pub reboot_required: bool,
}

/// Evaluates fixed preflight state without firewall, scheduler, registry, or adapter access.
#[must_use]
pub fn evaluate_emergency_isolation(
    observation: EmergencyIsolationObservation,
    policy: &EmergencyIsolationPolicy,
) -> EmergencyIsolationAudit {
    let plan_blockers = preflight_blockers(&observation, policy);
    let mut findings = Vec::new();
    if plan_blockers.contains(&EmergencyIsolationPlanBlocker::IncompleteRollbackEvidence) {
        findings.push(finding("ISO-RollbackIncomplete", Severity::Critical, "All three fixed firewall profiles need complete rollback evidence before isolation can be proposed."));
    }
    if plan_blockers.contains(&EmergencyIsolationPlanBlocker::BreakGlassUnverified) {
        findings.push(finding(
            "ISO-BreakGlassUnverified",
            Severity::Critical,
            "The required pre-provisioned break-glass profile is not digest-bound.",
        ));
    }
    if plan_blockers.contains(&EmergencyIsolationPlanBlocker::ManagedIsolationActive) {
        findings.push(finding(
            "ISO-AlreadyActive",
            Severity::High,
            "An existing managed isolation is active; overlapping activation is forbidden.",
        ));
    }
    if plan_blockers.contains(&EmergencyIsolationPlanBlocker::ManagedIsolationUnknown) {
        findings.push(finding(
            "ISO-ManagedStateUnknown",
            Severity::Critical,
            "The managed-isolation marker is unavailable; activation state cannot be inferred from firewall defaults.",
        ));
    }
    findings.push(finding("ISO-ApplyUnavailable", Severity::High, "Raw Apply, adapter disablement, dynamic firewall rules, and scheduled rollback remain unavailable."));
    EmergencyIsolationAudit {
        observation,
        policy: policy.clone(),
        findings,
        plan_blockers,
    }
}

/// Validates whether complete preflight evidence permits semantic action derivation.
///
/// # Errors
///
/// Returns an error naming every typed blocker when rollback, break-glass, or
/// managed-isolation evidence is incomplete or prohibits activation.
pub fn validate_emergency_isolation_preflight(
    observation: &EmergencyIsolationObservation,
    policy: &EmergencyIsolationPolicy,
) -> Result<(), String> {
    let blockers = preflight_blockers(observation, policy);
    if blockers.is_empty() {
        return Ok(());
    }
    Err(format!(
        "emergency-isolation preflight is incomplete or unsafe: {blockers:?}"
    ))
}

/// Builds fixed semantic actions and retains the exact rollback observation.
#[must_use]
pub fn build_emergency_isolation_plan(
    observation: EmergencyIsolationObservation,
    policy: &EmergencyIsolationPolicy,
) -> EmergencyIsolationPlan {
    let audit = evaluate_emergency_isolation(observation, policy);
    let mut actions = vec![];
    if audit.plan_blockers.is_empty() {
        add_action_deltas(&audit.observation.profiles, &mut actions);
        if policy.require_preprovisioned_break_glass && !actions.is_empty() {
            actions.push(EmergencyIsolationAction::PreservePreprovisionedBreakGlass);
        }
    }
    EmergencyIsolationPlan {
        rollback: audit.observation.profiles.clone(),
        audit,
        actions,
        apply_available: false,
        reboot_required: false,
    }
}

fn preflight_blockers(
    observation: &EmergencyIsolationObservation,
    policy: &EmergencyIsolationPolicy,
) -> Vec<EmergencyIsolationPlanBlocker> {
    let mut blockers = Vec::new();
    if !profiles_are_complete(&observation.profiles) {
        blockers.push(EmergencyIsolationPlanBlocker::IncompleteRollbackEvidence);
    }
    if policy.require_preprovisioned_break_glass
        && !matches!(
            observation.break_glass_profile_sha256,
            Observation::Present(_)
        )
    {
        blockers.push(EmergencyIsolationPlanBlocker::BreakGlassUnverified);
    }
    match observation.managed_isolation_active {
        Observation::Present(false) => {}
        Observation::Present(true) => {
            blockers.push(EmergencyIsolationPlanBlocker::ManagedIsolationActive);
        }
        _ => blockers.push(EmergencyIsolationPlanBlocker::ManagedIsolationUnknown),
    }
    blockers
}

fn profiles_are_complete(profiles: &[IsolationProfileSnapshot]) -> bool {
    let identities = profiles
        .iter()
        .map(|snapshot| snapshot.profile)
        .collect::<BTreeSet<_>>();
    profiles.len() == 3
        && identities == fixed_profiles().into_iter().collect()
        && profiles.iter().all(|snapshot| {
            matches!(snapshot.inbound, Observation::Present(_))
                && matches!(snapshot.outbound, Observation::Present(_))
        })
}

fn add_action_deltas(
    profiles: &[IsolationProfileSnapshot],
    actions: &mut Vec<EmergencyIsolationAction>,
) {
    for profile in fixed_profiles() {
        let snapshot = profiles
            .iter()
            .find(|snapshot| snapshot.profile == profile)
            .expect("complete profiles were validated before action derivation");
        if snapshot.inbound == Observation::Present(IsolationDefaultAction::Allow) {
            actions.push(EmergencyIsolationAction::BlockInbound(profile));
        }
        if snapshot.outbound == Observation::Present(IsolationDefaultAction::Allow) {
            actions.push(EmergencyIsolationAction::BlockOutbound(profile));
        }
    }
}

const fn fixed_profiles() -> [IsolationFirewallProfile; 3] {
    [
        IsolationFirewallProfile::Domain,
        IsolationFirewallProfile::Private,
        IsolationFirewallProfile::Public,
    ]
}

fn finding(code: &'static str, severity: Severity, message: &str) -> PolicyFinding {
    PolicyFinding {
        code,
        status: FindingStatus::Warning,
        severity,
        message: message.into(),
        evidence: JsonMap::from([("semantic_plan_only".into(), json!(true))]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(profile: IsolationFirewallProfile) -> IsolationProfileSnapshot {
        IsolationProfileSnapshot {
            profile,
            inbound: Observation::Present(IsolationDefaultAction::Allow),
            outbound: Observation::Present(IsolationDefaultAction::Allow),
        }
    }

    #[test]
    fn plan_keeps_exact_rollback_and_is_idempotent() {
        let observation = EmergencyIsolationObservation {
            profiles: vec![
                snapshot(IsolationFirewallProfile::Domain),
                snapshot(IsolationFirewallProfile::Private),
                snapshot(IsolationFirewallProfile::Public),
            ],
            break_glass_profile_sha256: Observation::Present([9; 32]),
            managed_isolation_active: Observation::Present(false),
        };
        let policy = EmergencyIsolationPolicy {
            require_preprovisioned_break_glass: true,
        };
        let first = build_emergency_isolation_plan(observation.clone(), &policy);
        assert_eq!(first.rollback, observation.profiles);
        assert_eq!(first, build_emergency_isolation_plan(observation, &policy));
        assert!(!first.apply_available);
    }

    #[test]
    fn incomplete_rollback_blocks_a_safe_activation_claim() {
        let audit = evaluate_emergency_isolation(
            EmergencyIsolationObservation {
                profiles: vec![],
                break_glass_profile_sha256: Observation::Missing,
                managed_isolation_active: Observation::NotRun,
            },
            &EmergencyIsolationPolicy {
                require_preprovisioned_break_glass: true,
            },
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|item| item.code == "ISO-RollbackIncomplete")
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|item| item.code == "ISO-BreakGlassUnverified")
        );
    }
}

#[cfg(test)]
#[path = "emergency_isolation_preflight_tests.rs"]
mod preflight_tests;
