//! Bounded Defender IOC-sweep model for capability 11.
//!
//! Arbitrary IOC catalog files, custom paths, executable selection, and
//! containment actions from the legacy script are intentionally excluded.

use crate::{Observation, PolicyFinding};
use baselineops_domain::{FindingStatus, JsonMap, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Only scan scopes that a future native observer may implement.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefenderSweepScope {
    /// Fixed Defender quick scan.
    Quick,
    /// Fixed Defender full scan.
    #[default]
    Full,
}

/// Digest-bound, pre-provisioned logical IOC catalog identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct IocCatalogBinding {
    /// Fixed catalog role; its location is intentionally undisclosed here.
    pub logical_resource: &'static str,
    /// Required SHA-256 digest.
    pub sha256: [u8; 32],
}

/// Strict sweep request with no catalog path, custom path, or containment switch.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct DefenderIocSweepPolicy {
    /// Finite native Defender scan scope.
    pub scope: DefenderSweepScope,
}

/// Observation returned by a fixed Defender acquisition adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DefenderIocSweepObservation {
    /// Verified IOC catalog identity.
    pub catalog: Observation<IocCatalogBinding>,
    /// Scan completion state and bounded detection count.
    pub detections: Observation<u32>,
}

/// Read-only evaluation of one fixed sweep.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DefenderIocSweepAudit {
    /// Native evidence retained for post-audit comparison.
    pub observation: DefenderIocSweepObservation,
    /// Fixed policy used for this assessment.
    pub policy: DefenderIocSweepPolicy,
    /// Detection and incomplete-evidence findings.
    pub findings: Vec<PolicyFinding>,
}

/// Semantic scan proposal; it never contains a command, path, or remediation action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DefenderIocSweepPlan {
    /// Audit from which this plan is derived.
    pub audit: DefenderIocSweepAudit,
    /// Fixed scan scope.
    pub scope: DefenderSweepScope,
    /// Production Apply and containment are unavailable.
    pub apply_available: bool,
}

/// Evaluates a digest-bound catalog and fixed scan observation without I/O.
#[must_use]
pub fn evaluate_defender_ioc_sweep(
    observation: DefenderIocSweepObservation,
    policy: &DefenderIocSweepPolicy,
) -> DefenderIocSweepAudit {
    let mut findings = Vec::new();
    if !matches!(&observation.catalog, Observation::Present(_)) {
        findings.push(finding(
            "IOC-CatalogUnavailable",
            Severity::High,
            "The pre-provisioned digest-bound IOC catalog was not verified.",
        ));
    }
    match &observation.detections {
        Observation::Present(0) => {}
        Observation::Present(_) => findings.push(finding("IOC-Detection", Severity::Critical, "The fixed Defender sweep reported one or more detections; containment remains a separate approved action.")),
        _ => findings.push(finding("IOC-SweepIncomplete", Severity::High, "The fixed Defender sweep did not provide complete bounded evidence.")),
    }
    DefenderIocSweepAudit {
        observation,
        policy: policy.clone(),
        findings,
    }
}

/// Builds a non-mutating semantic sweep plan.
#[must_use]
pub fn build_defender_ioc_sweep_plan(
    observation: DefenderIocSweepObservation,
    policy: &DefenderIocSweepPolicy,
) -> DefenderIocSweepPlan {
    DefenderIocSweepPlan {
        audit: evaluate_defender_ioc_sweep(observation, policy),
        scope: policy.scope,
        apply_available: false,
    }
}

fn finding(code: &'static str, severity: Severity, message: &str) -> PolicyFinding {
    PolicyFinding {
        code,
        status: FindingStatus::Warning,
        severity,
        message: message.into(),
        evidence: JsonMap::from([("no_containment_authority".into(), json!(true))]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_is_reported_without_granting_containment_authority() {
        let audit = evaluate_defender_ioc_sweep(
            DefenderIocSweepObservation {
                catalog: Observation::Present(IocCatalogBinding {
                    logical_resource: "sealed_ioc_catalog",
                    sha256: [7; 32],
                }),
                detections: Observation::Present(1),
            },
            &DefenderIocSweepPolicy::default(),
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|item| item.code == "IOC-Detection")
        );
        assert!(!build_defender_ioc_sweep_plan(audit.observation, &audit.policy).apply_available);
    }

    #[test]
    fn failed_scan_is_not_silently_healthy() {
        let audit = evaluate_defender_ioc_sweep(
            DefenderIocSweepObservation {
                catalog: Observation::Missing,
                detections: Observation::TimedOut,
            },
            &DefenderIocSweepPolicy::default(),
        );
        assert!(
            audit
                .findings
                .iter()
                .any(|item| item.code == "IOC-SweepIncomplete")
        );
    }
}
