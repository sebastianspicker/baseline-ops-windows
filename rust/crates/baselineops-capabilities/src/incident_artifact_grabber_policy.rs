//! Bounded incident-artifact collection model for capability 12.
//!
//! This excludes legacy caller-provided catalogs, trigger files, sample paths,
//! process hashes, and output roots. A future worker may collect only the
//! finite logical resources below and must bind its output to a digest.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Fixed incident-response resource categories.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentArtifactResource {
    /// Bounded process inventory metadata.
    ProcessInventory,
    /// Bounded network connection metadata.
    NetworkConnections,
    /// Bounded scheduled-task metadata.
    ScheduledTasks,
    /// WMI subscription persistence metadata.
    WmiPersistence,
    /// Fixed `Run` and `RunOnce` autorun metadata.
    Autoruns,
}

/// Strict artifact policy; bulk samples and raw paths are excluded.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct IncidentArtifactGrabberPolicy {
    /// Include bounded network metadata.
    pub include_network_connections: bool,
}

/// Observation for one finite incident artifact category.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct IncidentArtifactObservation {
    /// Fixed resource identity.
    pub resource: IncidentArtifactResource,
    /// Number of bounded records retained by the observer.
    pub state: Observation<u32>,
}

/// Complete fixed incident-response observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct IncidentArtifactGrabberObservation {
    /// Evidence for each requested fixed resource.
    pub artifacts: Vec<IncidentArtifactObservation>,
}

/// SHA-256 binding for a sealed logical incident bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct IncidentBundleDigest {
    /// SHA-256 bytes for the future sealed incident bundle.
    pub sha256: [u8; 32],
}

/// Deterministic assessment of fixed incident evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct IncidentArtifactGrabberAudit {
    /// Native evidence.
    pub observation: IncidentArtifactGrabberObservation,
    /// Applied finite policy.
    pub policy: IncidentArtifactGrabberPolicy,
    /// Completeness findings.
    pub findings: Vec<PolicyFinding>,
}

/// Zero-mutation plan for a future sealed collection worker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct IncidentArtifactGrabberPlan {
    /// Assessment used to derive the proposal.
    pub audit: IncidentArtifactGrabberAudit,
    /// Fixed resource set.
    pub resources: Vec<IncidentArtifactResource>,
    /// Logical output kind; no filesystem authority is represented.
    pub output: &'static str,
    /// Production Apply is unavailable.
    pub apply_available: bool,
}

/// Returns the finite resource set chosen by this policy.
#[must_use]
pub fn selected_incident_artifact_resources(
    policy: &IncidentArtifactGrabberPolicy,
) -> Vec<IncidentArtifactResource> {
    let mut resources = vec![
        IncidentArtifactResource::ProcessInventory,
        IncidentArtifactResource::ScheduledTasks,
        IncidentArtifactResource::WmiPersistence,
        IncidentArtifactResource::Autoruns,
    ];
    if policy.include_network_connections {
        resources.push(IncidentArtifactResource::NetworkConnections);
    }
    resources
}

/// Evaluates fixed artifact evidence without filesystem, process, or network access.
#[must_use]
pub fn evaluate_incident_artifact_grabber(
    observation: IncidentArtifactGrabberObservation,
    policy: &IncidentArtifactGrabberPolicy,
) -> IncidentArtifactGrabberAudit {
    let mut findings = Vec::new();
    for resource in selected_incident_artifact_resources(policy) {
        let observed = observation
            .artifacts
            .iter()
            .find(|item| item.resource == resource)
            .map(|item| &item.state);
        if !matches!(observed, Some(Observation::Present(_))) {
            findings.push(finding(
                "IR-ArtifactIncomplete",
                Severity::High,
                format!("Fixed incident resource {resource:?} lacks complete evidence."),
            ));
        }
    }
    findings.push(finding("IR-SamplesExcluded", Severity::Low, "Raw sample paths, executable copies, and arbitrary output roots are excluded from this foundation.".into()));
    IncidentArtifactGrabberAudit {
        observation,
        policy: policy.clone(),
        findings,
    }
}

/// Builds a sealed-worker semantic plan without mutating the endpoint.
#[must_use]
pub fn build_incident_artifact_grabber_plan(
    observation: IncidentArtifactGrabberObservation,
    policy: &IncidentArtifactGrabberPolicy,
) -> IncidentArtifactGrabberPlan {
    IncidentArtifactGrabberPlan {
        audit: evaluate_incident_artifact_grabber(observation, policy),
        resources: selected_incident_artifact_resources(policy),
        output: "incident_artifact_bundle",
        apply_available: false,
    }
}

fn finding(code: &'static str, severity: Severity, message: String) -> PolicyFinding {
    PolicyFinding {
        code,
        status: FindingStatus::Warning,
        severity,
        message,
        evidence: JsonMap::from([("fixed_logical_resources_only".into(), json!(true))]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_fake_observation_is_idempotent() {
        let policy = IncidentArtifactGrabberPolicy {
            include_network_connections: true,
        };
        let observation = IncidentArtifactGrabberObservation {
            artifacts: selected_incident_artifact_resources(&policy)
                .into_iter()
                .map(|resource| IncidentArtifactObservation {
                    resource,
                    state: Observation::Present(0),
                })
                .collect(),
        };
        let first = build_incident_artifact_grabber_plan(observation.clone(), &policy);
        assert_eq!(
            first,
            build_incident_artifact_grabber_plan(observation, &policy)
        );
        assert!(!first.apply_available);
    }

    #[test]
    fn access_denied_is_a_failure_signal() {
        let audit = evaluate_incident_artifact_grabber(
            IncidentArtifactGrabberObservation {
                artifacts: vec![IncidentArtifactObservation {
                    resource: IncidentArtifactResource::ProcessInventory,
                    state: Observation::AccessDenied,
                }],
            },
            &IncidentArtifactGrabberPolicy::default(),
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|item| item.code == "IR-ArtifactIncomplete")
        );
    }
}
