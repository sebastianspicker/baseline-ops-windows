//! Read-only native audit composition and `ResultV3` normalization.

use crate::{Selection, resolve_selection, unsupported_response};
use anyhow::{Result, anyhow};
use baselineops_capabilities::{CapabilityDescriptor, CapabilityOutcome, Operation};
use baselineops_domain::{
    ActionId, ActionResultV3, ActionStatus, ExitCode, FindingId, FindingStatus, PlanId, ProfileId,
    ResultId, ResultStatus, ResultV3, RunId, SchemaVersion, Severity,
};
use chrono::Utc;
use std::collections::BTreeMap;

pub(crate) fn run(selection: &Selection) -> Result<ExitCode> {
    let (targets, profile_id) = resolve_targets(selection)?;
    reject_unsupported_targets(&targets)?;
    let host = baselineops_windows::collect_host_identity().map_err(|error| anyhow!(error))?;
    let started_at = Utc::now();
    let accumulated = collect_outcomes(targets, started_at)?;
    let result = audit_result(profile_id, host, started_at, accumulated);
    result.validate()?;
    crate::print_json(&result)?;
    Ok(result.exit_code())
}

fn reject_unsupported_targets(targets: &[AuditTarget]) -> Result<()> {
    let unsupported = targets
        .iter()
        .filter(|target| !native_audit_supported(target.descriptor))
        .map(|target| target.descriptor.id)
        .collect::<Vec<_>>();
    if unsupported.is_empty() {
        Ok(())
    } else {
        unsupported_response("audit", &unsupported).map(|_| ())
    }
}

fn collect_outcomes(
    targets: Vec<AuditTarget>,
    started_at: chrono::DateTime<Utc>,
) -> Result<AuditAccumulator> {
    let mut accumulated = AuditAccumulator::new(targets.len());
    for target in targets {
        record_outcome(
            dispatch_native_audit(target.descriptor, &target.parameters),
            target.descriptor,
            ActionId::new(),
            started_at,
            Utc::now(),
            &mut accumulated,
        )?;
    }
    Ok(accumulated)
}

fn audit_result(
    profile_id: Option<ProfileId>,
    host: baselineops_domain::HostIdentity,
    started_at: chrono::DateTime<Utc>,
    accumulated: AuditAccumulator,
) -> ResultV3 {
    let capability_id =
        (accumulated.actions.len() == 1).then(|| accumulated.actions[0].capability.clone());
    ResultV3 {
        schema_version: SchemaVersion::V3,
        id: ResultId::new(),
        run_id: RunId::new(),
        plan_id: PlanId::new(),
        profile_id: match profile_id {
            Some(id) => id,
            None => ProfileId::new(),
        },
        capability_id,
        operation: baselineops_domain::Operation::Audit,
        host,
        status: accumulated.status,
        started_at,
        completed_at: Utc::now(),
        actions: accumulated.actions,
        findings: accumulated.findings,
        summary: "standard-user native audit completed without mutation".into(),
        artifacts: Vec::new(),
        metadata: BTreeMap::new(),
    }
}

struct AuditTarget {
    descriptor: &'static CapabilityDescriptor,
    parameters: serde_json::Value,
}

struct AuditAccumulator {
    status: ResultStatus,
    findings: Vec<baselineops_domain::FindingV3>,
    actions: Vec<ActionResultV3>,
}

impl AuditAccumulator {
    fn new(capacity: usize) -> Self {
        Self {
            actions: Vec::with_capacity(capacity),
            findings: Vec::new(),
            status: ResultStatus::Completed,
        }
    }
}

fn record_outcome(
    outcome: CapabilityOutcome,
    descriptor: &'static CapabilityDescriptor,
    action_id: ActionId,
    started_at: chrono::DateTime<Utc>,
    completed_at: chrono::DateTime<Utc>,
    accumulated: &mut AuditAccumulator,
) -> Result<()> {
    match outcome {
        CapabilityOutcome::Completed { result } => {
            record_completed(
                result,
                descriptor,
                action_id,
                started_at,
                completed_at,
                accumulated,
            );
        }
        CapabilityOutcome::Unsupported { reason } => {
            record_unsupported(
                reason,
                descriptor,
                action_id,
                started_at,
                completed_at,
                accumulated,
            )?;
        }
        CapabilityOutcome::Failed { message, .. } => {
            record_failure(
                &message,
                descriptor,
                action_id,
                started_at,
                completed_at,
                accumulated,
            );
        }
    }
    Ok(())
}

fn record_completed(
    result: serde_json::Value,
    descriptor: &'static CapabilityDescriptor,
    action_id: ActionId,
    started_at: chrono::DateTime<Utc>,
    completed_at: chrono::DateTime<Utc>,
    accumulated: &mut AuditAccumulator,
) {
    let has_findings = result
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|items| !items.is_empty());
    let (finding_status, severity, message, action_status) = completed_status(has_findings);
    if has_findings {
        raise_status(&mut accumulated.status, ResultStatus::Warnings);
    }
    accumulated.findings.push(finding(
        descriptor,
        action_id,
        finding_status,
        severity,
        message,
        result.clone(),
    ));
    accumulated.actions.push(action_result(
        descriptor,
        action_id,
        action_status,
        started_at,
        completed_at,
        result,
    ));
}

fn completed_status(has_findings: bool) -> (FindingStatus, Severity, &'static str, ActionStatus) {
    if has_findings {
        (
            FindingStatus::Warning,
            Severity::Medium,
            "audit completed with incomplete or adverse evidence",
            ActionStatus::Findings,
        )
    } else {
        (
            FindingStatus::Info,
            Severity::Info,
            "audit observation collected",
            ActionStatus::Succeeded,
        )
    }
}

fn record_unsupported(
    reason: baselineops_capabilities::Unsupported,
    descriptor: &'static CapabilityDescriptor,
    action_id: ActionId,
    started_at: chrono::DateTime<Utc>,
    completed_at: chrono::DateTime<Utc>,
    accumulated: &mut AuditAccumulator,
) -> Result<()> {
    raise_status(&mut accumulated.status, ResultStatus::Unsupported);
    accumulated.findings.push(finding(
        descriptor,
        action_id,
        FindingStatus::Skipped,
        Severity::Info,
        "native audit is unavailable",
        serde_json::to_value(reason)?,
    ));
    accumulated.actions.push(action_result(
        descriptor,
        action_id,
        ActionStatus::Blocked,
        started_at,
        completed_at,
        serde_json::json!({}),
    ));
    Ok(())
}

fn record_failure(
    message: &str,
    descriptor: &'static CapabilityDescriptor,
    action_id: ActionId,
    started_at: chrono::DateTime<Utc>,
    completed_at: chrono::DateTime<Utc>,
    accumulated: &mut AuditAccumulator,
) {
    raise_status(&mut accumulated.status, ResultStatus::ExecutionFailed);
    accumulated.findings.push(finding(
        descriptor,
        action_id,
        FindingStatus::Error,
        Severity::High,
        "native audit failed",
        serde_json::json!({"error": message}),
    ));
    accumulated.actions.push(action_result(
        descriptor,
        action_id,
        ActionStatus::Failed,
        started_at,
        completed_at,
        serde_json::json!({}),
    ));
}

fn raise_status(current: &mut ResultStatus, candidate: ResultStatus) {
    fn priority(status: ResultStatus) -> u8 {
        match status {
            ResultStatus::Completed => 0,
            ResultStatus::Warnings => 1,
            ResultStatus::Unsupported => 2,
            ResultStatus::ExecutionFailed => 3,
            ResultStatus::Cancelled => 4,
            ResultStatus::Rejected => 5,
        }
    }
    if priority(candidate) > priority(*current) {
        *current = candidate;
    }
}

fn resolve_targets(selection: &Selection) -> Result<(Vec<AuditTarget>, Option<ProfileId>)> {
    if let Some(path) = &selection.profile {
        return profile_targets(path);
    }
    direct_targets(selection)
}

fn profile_targets(path: &std::path::Path) -> Result<(Vec<AuditTarget>, Option<ProfileId>)> {
    let profile: baselineops_domain::ProfileV3 =
        baselineops_domain::load_json_file(path, baselineops_domain::JsonLoadLimits::default())?;
    let validation = profile.validate()?;
    let targets = validation
        .topological_order
        .as_slice()
        .iter()
        .map(|id| profile_target(&profile, &id.to_string()))
        .collect::<Result<Vec<_>>>()?;
    Ok((targets, Some(profile.id)))
}

fn profile_target(profile: &baselineops_domain::ProfileV3, step_id: &str) -> Result<AuditTarget> {
    let step = profile
        .steps
        .iter()
        .find(|step| step.step_id.to_string() == step_id)
        .ok_or_else(|| anyhow!("validated profile step is unavailable"))?;
    let descriptor =
        baselineops_capabilities::lookup(step.capability_id.as_str()).ok_or_else(|| {
            anyhow!(
                "profile references unknown capability: {}",
                step.capability_id
            )
        })?;
    Ok(AuditTarget {
        descriptor,
        parameters: serde_json::to_value(&step.parameters)?,
    })
}

fn direct_targets(selection: &Selection) -> Result<(Vec<AuditTarget>, Option<ProfileId>)> {
    let (descriptors, profile_id) = resolve_selection(selection)?;
    let targets = descriptors
        .into_iter()
        .map(|descriptor| {
            Ok(AuditTarget {
                descriptor,
                parameters: direct_parameters(descriptor, selection)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((targets, profile_id))
}

fn direct_parameters(
    descriptor: &CapabilityDescriptor,
    selection: &Selection,
) -> Result<serde_json::Value> {
    if descriptor.id != "v3.support-bundle.parse" {
        return Ok(serde_json::json!({}));
    }
    let support_dir = selection.support_dir.as_deref().or_else(|| {
        selection
            .resources
            .iter()
            .find(|resource| resource.logical_id().as_str() == "support_bundle")
            .map(super::resources::ResourceArgument::path)
    }).ok_or_else(|| anyhow!("v3.support-bundle.parse requires --resource support_bundle=DIR or --support-dir DIR"))?;
    Ok(serde_json::json!({"support_dir": support_dir}))
}

pub(crate) fn native_audit_supported(descriptor: &CapabilityDescriptor) -> bool {
    descriptor.operations.supports(Operation::Audit)
        && baselineops_engine::has_native_handler(descriptor)
}

pub(crate) fn dispatch_native_audit(
    descriptor: &'static CapabilityDescriptor,
    parameters: &serde_json::Value,
) -> CapabilityOutcome {
    baselineops_engine::dispatch_native(descriptor, Operation::Audit, parameters)
}

fn action_result(
    descriptor: &CapabilityDescriptor,
    action_id: ActionId,
    status: ActionStatus,
    started_at: chrono::DateTime<Utc>,
    completed_at: chrono::DateTime<Utc>,
    result: serde_json::Value,
) -> ActionResultV3 {
    ActionResultV3 {
        action_id,
        capability: baselineops_domain::CapabilityId::try_from(descriptor.id)
            .expect("catalog IDs are valid"),
        status,
        started_at,
        completed_at,
        metadata: BTreeMap::from([("native_result".into(), result)]),
    }
}
fn finding(
    descriptor: &CapabilityDescriptor,
    action_id: ActionId,
    status: FindingStatus,
    severity: Severity,
    message: &str,
    evidence: serde_json::Value,
) -> baselineops_domain::FindingV3 {
    baselineops_domain::FindingV3 {
        id: FindingId::new(),
        capability: baselineops_domain::CapabilityId::try_from(descriptor.id)
            .expect("catalog IDs are valid"),
        action_id: Some(action_id),
        code: format!("{}.observation", descriptor.id),
        status,
        severity,
        message: message.into(),
        observed_at: Utc::now(),
        evidence: BTreeMap::from([("result".into(), evidence)]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn profile_targets_preserve_topological_order_and_typed_parameters() {
        let selection = Selection {
            capability: None,
            profile: Some(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../examples/profiles/inventory-patch-events.v3.json"),
            ),
            batch: None,
            support_dir: None,
            resources: Vec::new(),
        };
        let (targets, profile_id) = resolve_targets(&selection).expect("resolve audit profile");
        assert!(profile_id.is_some());
        assert_eq!(
            targets
                .iter()
                .map(|target| target.descriptor.id)
                .collect::<Vec<_>>(),
            vec![
                "v3.software.inventory",
                "v3.patch.missing",
                "v3.eventlog.fast-triage"
            ]
        );
        assert_eq!(targets[1].parameters["entries"][0]["kb"], "KB5030219");
        assert_eq!(targets[2].parameters["channel"], "System");
    }

    #[test]
    fn later_findings_cannot_downgrade_terminal_status() {
        let mut status = ResultStatus::ExecutionFailed;
        raise_status(&mut status, ResultStatus::Warnings);
        assert_eq!(status, ResultStatus::ExecutionFailed);

        let mut status = ResultStatus::Warnings;
        raise_status(&mut status, ResultStatus::Unsupported);
        assert_eq!(status, ResultStatus::Unsupported);
    }
}
