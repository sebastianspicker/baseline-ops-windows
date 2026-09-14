//! Executor seams for capabilities 09, 11, 12, and 21.
//!
//! These handlers admit only strict finite policy documents. They deliberately
//! reject raw Apply before platform access. Isolation has fixed read-only firewall
//! preflight acquisition; the other collectors remain unavailable. Windows runtime
//! evidence and complete acquisition contracts remain open.

use baselineops_capabilities::{
    CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest,
    DefenderIocSweepPolicy, EmergencyIsolationPolicy, IncidentArtifactGrabberPolicy, Operation,
    SupportBundleCollectionPolicy, Unsupported, build_defender_ioc_sweep_plan,
    build_emergency_isolation_plan, build_incident_artifact_grabber_plan,
    build_support_bundle_collection_plan, evaluate_defender_ioc_sweep,
    evaluate_emergency_isolation, evaluate_incident_artifact_grabber,
    evaluate_support_bundle_collection,
};
use baselineops_windows::{
    PlatformError, audit_defender_ioc_sweep, audit_emergency_isolation,
    audit_incident_artifact_grabber, audit_support_bundle_collection,
};

/// Strict, raw-request executor for capability 09.
pub struct WaveSupportBundleCollectionWindowsExecutor;
/// Strict, raw-request executor for capability 11.
pub struct WaveDefenderIocSweepWindowsExecutor;
/// Strict, raw-request executor for capability 12.
pub struct WaveIncidentArtifactGrabberWindowsExecutor;
/// Strict, raw-request executor for capability 21.
pub struct WaveEmergencyIsolationWindowsExecutor;

impl CapabilityExecutor for WaveSupportBundleCollectionWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        execute_support_bundle(descriptor, request)
    }
}
impl CapabilityExecutor for WaveDefenderIocSweepWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        execute_ioc_sweep(descriptor, request)
    }
}
impl CapabilityExecutor for WaveIncidentArtifactGrabberWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        execute_artifact_grabber(descriptor, request)
    }
}
impl CapabilityExecutor for WaveEmergencyIsolationWindowsExecutor {
    fn execute(
        &self,
        descriptor: &'static CapabilityDescriptor,
        request: CapabilityRequest<'_>,
    ) -> CapabilityOutcome {
        execute_emergency_isolation(descriptor, request)
    }
}

fn execute_support_bundle(
    descriptor: &'static CapabilityDescriptor,
    request: CapabilityRequest<'_>,
) -> CapabilityOutcome {
    if descriptor.id != "v3.support-bundle.collect" {
        return failed(
            descriptor,
            "capability is not implemented by the support-bundle foundation",
        );
    }
    if request.operation == Operation::Apply {
        return apply_unavailable();
    }
    let result = parse::<SupportBundleCollectionPolicy>(request.parameters, "support-bundle")
        .and_then(|policy| {
            audit_support_bundle_collection().and_then(|observation| match request.operation {
                Operation::Audit => {
                    serialize(evaluate_support_bundle_collection(observation, &policy))
                }
                Operation::Plan => {
                    serialize(build_support_bundle_collection_plan(observation, &policy))
                }
                Operation::Apply => unreachable!("Apply returned Unsupported above"),
            })
        });
    outcome(descriptor, result)
}

fn execute_ioc_sweep(
    descriptor: &'static CapabilityDescriptor,
    request: CapabilityRequest<'_>,
) -> CapabilityOutcome {
    if descriptor.id != "v3.defender.ioc-sweep" {
        return failed(
            descriptor,
            "capability is not implemented by the Defender IOC foundation",
        );
    }
    if request.operation == Operation::Apply {
        return apply_unavailable();
    }
    let result = parse::<DefenderIocSweepPolicy>(request.parameters, "Defender IOC sweep")
        .and_then(|policy| {
            audit_defender_ioc_sweep().and_then(|observation| match request.operation {
                Operation::Audit => serialize(evaluate_defender_ioc_sweep(observation, &policy)),
                Operation::Plan => serialize(build_defender_ioc_sweep_plan(observation, &policy)),
                Operation::Apply => unreachable!("Apply returned Unsupported above"),
            })
        });
    outcome(descriptor, result)
}

fn execute_artifact_grabber(
    descriptor: &'static CapabilityDescriptor,
    request: CapabilityRequest<'_>,
) -> CapabilityOutcome {
    if descriptor.id != "v3.ir.artifact-grabber" {
        return failed(
            descriptor,
            "capability is not implemented by the incident-artifact foundation",
        );
    }
    if request.operation == Operation::Apply {
        return apply_unavailable();
    }
    let result = parse::<IncidentArtifactGrabberPolicy>(request.parameters, "incident artifact")
        .and_then(|policy| {
            audit_incident_artifact_grabber().and_then(|observation| match request.operation {
                Operation::Audit => {
                    serialize(evaluate_incident_artifact_grabber(observation, &policy))
                }
                Operation::Plan => {
                    serialize(build_incident_artifact_grabber_plan(observation, &policy))
                }
                Operation::Apply => unreachable!("Apply returned Unsupported above"),
            })
        });
    outcome(descriptor, result)
}

fn execute_emergency_isolation(
    descriptor: &'static CapabilityDescriptor,
    request: CapabilityRequest<'_>,
) -> CapabilityOutcome {
    if descriptor.id != "v3.network.emergency-isolation" {
        return failed(
            descriptor,
            "capability is not implemented by the emergency-isolation foundation",
        );
    }
    if request.operation == Operation::Apply {
        return apply_unavailable();
    }
    let result = parse::<EmergencyIsolationPolicy>(request.parameters, "emergency isolation")
        .and_then(|policy| {
            audit_emergency_isolation().and_then(|observation| match request.operation {
                Operation::Audit => serialize(evaluate_emergency_isolation(observation, &policy)),
                Operation::Plan => serialize(build_emergency_isolation_plan(observation, &policy)),
                Operation::Apply => unreachable!("Apply returned Unsupported above"),
            })
        });
    outcome(descriptor, result)
}

fn parse<T: serde::de::DeserializeOwned>(
    value: &serde_json::Value,
    name: &str,
) -> Result<T, PlatformError> {
    serde_json::from_value(value.clone())
        .map_err(|error| PlatformError::TrustFailure(format!("invalid {name} parameters: {error}")))
}

fn serialize(value: impl serde::Serialize) -> Result<serde_json::Value, PlatformError> {
    serde_json::to_value(value).map_err(|error| PlatformError::TrustFailure(error.to_string()))
}

fn apply_unavailable() -> CapabilityOutcome {
    CapabilityOutcome::Unsupported {
        reason: Unsupported::OperationUnavailable {
            operation: Operation::Apply,
        },
    }
}

fn outcome(
    descriptor: &'static CapabilityDescriptor,
    result: Result<serde_json::Value, PlatformError>,
) -> CapabilityOutcome {
    result.map_or_else(
        |error| failed(descriptor, &error.to_string()),
        |result| CapabilityOutcome::Completed { result },
    )
}

fn failed(descriptor: &'static CapabilityDescriptor, message: &str) -> CapabilityOutcome {
    CapabilityOutcome::Failed {
        capability_id: descriptor.id.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use baselineops_capabilities::{
        DefenderIocSweepObservation, EmergencyIsolationObservation,
        IncidentArtifactGrabberObservation, IsolationDefaultAction, IsolationFirewallProfile,
        IsolationProfileSnapshot, Observation, SupportBundleCollectionObservation, lookup,
    };

    #[test]
    fn every_foundation_rejects_raw_apply_before_windows_access() {
        for (id, executor) in [
            (
                "v3.support-bundle.collect",
                &WaveSupportBundleCollectionWindowsExecutor as &dyn CapabilityExecutor,
            ),
            (
                "v3.defender.ioc-sweep",
                &WaveDefenderIocSweepWindowsExecutor as &dyn CapabilityExecutor,
            ),
            (
                "v3.ir.artifact-grabber",
                &WaveIncidentArtifactGrabberWindowsExecutor as &dyn CapabilityExecutor,
            ),
            (
                "v3.network.emergency-isolation",
                &WaveEmergencyIsolationWindowsExecutor as &dyn CapabilityExecutor,
            ),
        ] {
            let descriptor = lookup(id).expect("legacy descriptor");
            assert!(matches!(
                executor.execute(
                    descriptor,
                    CapabilityRequest {
                        operation: Operation::Apply,
                        parameters: &serde_json::json!({})
                    }
                ),
                CapabilityOutcome::Unsupported {
                    reason: Unsupported::OperationUnavailable {
                        operation: Operation::Apply
                    }
                }
            ));
        }
    }

    #[test]
    fn dynamic_authority_is_rejected_before_windows_access() {
        let descriptor = lookup("v3.defender.ioc-sweep").expect("legacy descriptor");
        let result = WaveDefenderIocSweepWindowsExecutor.execute(descriptor, CapabilityRequest { operation: Operation::Audit, parameters: &serde_json::json!({"catalog_path":"C:\\\\untrusted.json", "custom_scan_paths":["C:\\\\"]}) });
        assert!(matches!(result, CapabilityOutcome::Failed { .. }));
    }

    #[test]
    fn isolation_rejects_dynamic_authority_before_native_observation() {
        let descriptor = lookup("v3.network.emergency-isolation").expect("isolation descriptor");
        let result = WaveEmergencyIsolationWindowsExecutor.execute(descriptor, CapabilityRequest {
            operation: Operation::Audit,
            parameters: &serde_json::json!({"adapter": "Ethernet", "rollback_task": "caller-task"}),
        });
        let CapabilityOutcome::Failed { message, .. } = result else {
            panic!("untrusted isolation parameters must be rejected");
        };
        assert!(message.contains("invalid emergency isolation parameters"));
    }

    #[test]
    fn fake_post_audits_retain_failure_and_rollback_semantics() {
        let ioc = evaluate_defender_ioc_sweep(
            DefenderIocSweepObservation {
                catalog: Observation::Missing,
                detections: Observation::Failed { exit_code: 1 },
            },
            &DefenderIocSweepPolicy::default(),
        );
        assert!(
            ioc.findings
                .iter()
                .any(|item| item.code == "IOC-SweepIncomplete")
        );
        let profile = IsolationProfileSnapshot {
            profile: IsolationFirewallProfile::Domain,
            inbound: Observation::Present(IsolationDefaultAction::Allow),
            outbound: Observation::Present(IsolationDefaultAction::Allow),
        };
        let plan = build_emergency_isolation_plan(
            EmergencyIsolationObservation {
                profiles: vec![profile.clone()],
                break_glass_profile_sha256: Observation::Missing,
                managed_isolation_active: Observation::Present(false),
            },
            &EmergencyIsolationPolicy::default(),
        );
        assert_eq!(plan.rollback, vec![profile]);
        let artifacts = evaluate_incident_artifact_grabber(
            IncidentArtifactGrabberObservation { artifacts: vec![] },
            &IncidentArtifactGrabberPolicy::default(),
        );
        assert!(
            artifacts
                .findings
                .iter()
                .any(|item| item.code == "IR-ArtifactIncomplete")
        );
        let bundle = evaluate_support_bundle_collection(
            SupportBundleCollectionObservation { resources: vec![] },
            &SupportBundleCollectionPolicy::default(),
        );
        assert!(
            bundle
                .findings
                .iter()
                .any(|item| item.code == "SB-CollectionIncomplete")
        );
    }
}
