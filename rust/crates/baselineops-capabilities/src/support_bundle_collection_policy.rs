//! Bounded, side-effect-free support-bundle collection model for capability 09.
//!
//! The legacy script selects paths, days, and optional outputs at runtime. This
//! foundation accepts none of those authorities: it describes only fixed logical
//! resources and a digest-bound result that a future sealed worker may produce.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Fixed logical resources allowed in a support bundle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportBundleResource {
    /// Bounded operating-system configuration summary.
    SystemSummary,
    /// Bounded installed-hotfix inventory.
    InstalledHotfixes,
    /// Application event-log export.
    ApplicationEventLog,
    /// System event-log export.
    SystemEventLog,
    /// Setup event-log export.
    SetupEventLog,
    /// Security event-log export, when privileged access is available.
    SecurityEventLog,
    /// Fixed Microsoft Defender status evidence.
    DefenderStatus,
}

/// Fixed support-bundle profile; no output path, reason text, or time range is accepted.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct SupportBundleCollectionPolicy {
    /// Include the fixed Security event-log resource.
    pub include_security_event_log: bool,
    /// Include the fixed Defender-status resource.
    pub include_defender_status: bool,
}

/// Native evidence for one fixed collection resource.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SupportBundleResourceObservation {
    /// Fixed identity, never a caller path.
    pub resource: SupportBundleResource,
    /// Bounded collector result.
    pub state: Observation<u64>,
}

/// Complete read-only collection observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SupportBundleCollectionObservation {
    /// Evidence per fixed, requested logical resource.
    pub resources: Vec<SupportBundleResourceObservation>,
}

/// SHA-256 binding for an output logical resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct BundleDigest {
    /// SHA-256 bytes for the sealed logical bundle.
    pub sha256: [u8; 32],
}

/// Pure support-bundle assessment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SupportBundleCollectionAudit {
    /// Fixed source evidence.
    pub observation: SupportBundleCollectionObservation,
    /// Resolved finite policy.
    pub policy: SupportBundleCollectionPolicy,
    /// Incomplete collection evidence and declared limitations.
    pub findings: Vec<PolicyFinding>,
}

/// Semantic proposal for a future sealed worker, never a path or command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SupportBundleCollectionPlan {
    /// Evaluation from which this proposal was derived.
    pub audit: SupportBundleCollectionAudit,
    /// Finite logical resources to collect.
    pub resources: Vec<SupportBundleResource>,
    /// Future output identity is logical and must be digest-bound after collection.
    pub output: &'static str,
    /// Production mutation is unavailable.
    pub apply_available: bool,
}

/// Returns the finite resources selected by a policy.
#[must_use]
pub fn selected_support_bundle_resources(
    policy: &SupportBundleCollectionPolicy,
) -> Vec<SupportBundleResource> {
    let mut resources = vec![
        SupportBundleResource::SystemSummary,
        SupportBundleResource::InstalledHotfixes,
        SupportBundleResource::ApplicationEventLog,
        SupportBundleResource::SystemEventLog,
        SupportBundleResource::SetupEventLog,
    ];
    if policy.include_security_event_log {
        resources.push(SupportBundleResource::SecurityEventLog);
    }
    if policy.include_defender_status {
        resources.push(SupportBundleResource::DefenderStatus);
    }
    resources
}

/// Evaluates only fixed resource evidence; no I/O or archive creation occurs.
#[must_use]
pub fn evaluate_support_bundle_collection(
    observation: SupportBundleCollectionObservation,
    policy: &SupportBundleCollectionPolicy,
) -> SupportBundleCollectionAudit {
    let expected = selected_support_bundle_resources(policy);
    let mut findings = Vec::new();
    for resource in &expected {
        let state = observation
            .resources
            .iter()
            .find(|item| item.resource == *resource)
            .map(|item| &item.state);
        if !matches!(state, Some(Observation::Present(_))) {
            findings.push(finding(
                "SB-CollectionIncomplete",
                Severity::High,
                format!("Fixed resource {resource:?} lacks complete collection evidence."),
            ));
        }
    }
    findings.push(finding("SB-OutputUnbound", Severity::Low, "No archive path, URL, or caller-selected output is accepted; a future output must carry a SHA-256 binding.".into()));
    SupportBundleCollectionAudit {
        observation,
        policy: policy.clone(),
        findings,
    }
}

/// Builds a zero-mutation semantic plan from a fixed observation.
#[must_use]
pub fn build_support_bundle_collection_plan(
    observation: SupportBundleCollectionObservation,
    policy: &SupportBundleCollectionPolicy,
) -> SupportBundleCollectionPlan {
    SupportBundleCollectionPlan {
        audit: evaluate_support_bundle_collection(observation, policy),
        resources: selected_support_bundle_resources(policy),
        output: "support_bundle_zip",
        apply_available: false,
    }
}

fn finding(code: &'static str, severity: Severity, message: String) -> PolicyFinding {
    PolicyFinding {
        code,
        status: FindingStatus::Warning,
        severity,
        message,
        evidence: JsonMap::from([("fixed_resources_only".into(), json!(true))]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_is_idempotent_and_never_exposes_an_output_path() {
        let observation = SupportBundleCollectionObservation {
            resources: selected_support_bundle_resources(&SupportBundleCollectionPolicy::default())
                .into_iter()
                .map(|resource| SupportBundleResourceObservation {
                    resource,
                    state: Observation::Present(1),
                })
                .collect(),
        };
        let first = build_support_bundle_collection_plan(
            observation.clone(),
            &SupportBundleCollectionPolicy::default(),
        );
        assert_eq!(
            first,
            build_support_bundle_collection_plan(
                observation,
                &SupportBundleCollectionPolicy::default()
            )
        );
        assert!(!first.apply_available);
        assert_eq!(first.output, "support_bundle_zip");
    }

    #[test]
    fn missing_evidence_is_not_a_successful_collection() {
        let audit = evaluate_support_bundle_collection(
            SupportBundleCollectionObservation { resources: vec![] },
            &SupportBundleCollectionPolicy::default(),
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|item| item.code == "SB-CollectionIncomplete")
        );
    }
}
