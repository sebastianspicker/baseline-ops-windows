//! Read-only fixed firewall preflight for capability 21.
//!
//! Managed-isolation and protected break-glass evidence remain unavailable. This
//! module exposes no firewall, adapter, registry, or scheduled-task mutation.

use crate::PlatformError;
use baselineops_capabilities::{
    EmergencyIsolationObservation, FirewallBaselineObservation, FirewallBaselineProfileObservation,
    FirewallDefaultAction, FirewallEvidence, IsolationDefaultAction, IsolationFirewallProfile,
    IsolationProfileSnapshot, Observation,
};

/// Reads default actions for the three fixed built-in Windows Firewall profiles.
///
/// The resulting audit always retains explicit gaps for the managed-isolation
/// marker and protected break-glass source; defaults do not establish isolation.
///
/// # Errors
/// Returns unsupported-platform off Windows, or a provider failure when COM
/// cannot establish any requested default action. Missing, denied, and malformed
/// field evidence remains typed and cannot authorize a mutation proposal.
pub fn audit_emergency_isolation() -> Result<EmergencyIsolationObservation, PlatformError> {
    map_observation(&crate::observe_firewall_baseline()?)
}

fn map_observation(
    source: &FirewallBaselineObservation,
) -> Result<EmergencyIsolationObservation, PlatformError> {
    let profiles = [
        (IsolationFirewallProfile::Domain, &source.profiles.domain),
        (IsolationFirewallProfile::Private, &source.profiles.private),
        (IsolationFirewallProfile::Public, &source.profiles.public),
    ]
    .into_iter()
    .map(|(profile, evidence)| map_profile(profile, evidence))
    .collect::<Result<Vec<_>, _>>()?;
    Ok(EmergencyIsolationObservation {
        profiles,
        break_glass_profile_sha256: Observation::NotRun,
        managed_isolation_active: Observation::NotRun,
    })
}

fn map_profile(
    profile: IsolationFirewallProfile,
    evidence: &FirewallBaselineProfileObservation,
) -> Result<IsolationProfileSnapshot, PlatformError> {
    Ok(IsolationProfileSnapshot {
        profile,
        inbound: map_action(&evidence.default_inbound_action)?,
        outbound: map_action(&evidence.default_outbound_action)?,
    })
}

fn map_action(
    evidence: &FirewallEvidence<FirewallDefaultAction>,
) -> Result<Observation<IsolationDefaultAction>, PlatformError> {
    match evidence {
        FirewallEvidence::Present(FirewallDefaultAction::Allow) => {
            Ok(Observation::Present(IsolationDefaultAction::Allow))
        }
        FirewallEvidence::Present(FirewallDefaultAction::Block) => {
            Ok(Observation::Present(IsolationDefaultAction::Block))
        }
        FirewallEvidence::Missing => Ok(Observation::Missing),
        FirewallEvidence::AccessDenied => Ok(Observation::AccessDenied),
        FirewallEvidence::Unparsed => Ok(Observation::Unparsed),
        FirewallEvidence::Unavailable => Err(PlatformError::UnsupportedHost(
            "Windows Firewall provider could not establish isolation preflight defaults".into(),
        )),
    }
}

#[cfg(test)]
#[path = "emergency_isolation_tests.rs"]
mod tests;
