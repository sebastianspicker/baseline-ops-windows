//! Typed profile loading, review, and read-only audit sequencing.

use super::{
    APPLY_LOCK_REASON, AuditReport, AuditState, MAX_PROFILE_BYTES, audit_supported,
    cancelled_profile_report, invalid_profile_report, unsupported,
};
use baselineops_capabilities::{CapabilityDescriptor, CapabilityOutcome, Operation, lookup};
use baselineops_domain::{JsonLoadLimits, ProfileStepV3, ProfileV3};
use chrono::Utc;
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone, Debug)]
pub(super) struct ProfileWorkflow {
    pub(super) path: PathBuf,
    pub(super) profile: ProfileV3,
    pub(super) ordered_steps: Vec<ProfileAuditStep>,
}

#[derive(Clone, Debug)]
pub(super) struct ProfileAuditStep {
    pub(super) step: ProfileStepV3,
    pub(super) descriptor: &'static CapabilityDescriptor,
}

pub(super) fn validate(path: &Path) -> AuditReport {
    match load(path) {
        Ok(workflow) => AuditReport {
            state: AuditState::Completed,
            status: format!(
                "Validated profile {} with {} dependency-ordered capability steps. {APPLY_LOCK_REASON}",
                workflow.profile.name,
                workflow.ordered_steps.len()
            ),
            result: format_validation(&workflow),
            error: None,
            artifact: None,
        },
        Err(error) => invalid_profile_report(error),
    }
}

pub(super) fn audit(
    path: &Path,
    cancelled: &Arc<AtomicBool>,
    progress: &mut impl FnMut(AuditReport),
) -> AuditReport {
    let workflow = match load(path) {
        Ok(workflow) => workflow,
        Err(error) => return invalid_profile_report(error),
    };
    if cancelled.load(Ordering::Acquire) {
        return cancelled_profile_report();
    }
    if let Err(error) = baselineops_windows::collect_host_identity() {
        return unsupported(error.to_string());
    }
    audit_loaded(&workflow, cancelled, progress)
}

fn audit_loaded(
    workflow: &ProfileWorkflow,
    cancelled: &Arc<AtomicBool>,
    progress: &mut impl FnMut(AuditReport),
) -> AuditReport {
    let total = workflow.ordered_steps.len();
    let mut results = ProfileResults::new(total);
    for (offset, target) in workflow.ordered_steps.iter().enumerate() {
        if cancelled.load(Ordering::Acquire) {
            return cancelled_profile_report();
        }
        progress(AuditReport::profile_progress(
            offset + 1,
            total,
            target.descriptor.id,
        ));
        let outcome = dispatch(target);
        if cancelled.load(Ordering::Acquire) {
            return cancelled_profile_report();
        }
        results.record(target, outcome);
    }
    results.report(workflow)
}

fn dispatch(target: &ProfileAuditStep) -> Result<CapabilityOutcome, String> {
    let parameters =
        serde_json::to_value(&target.step.parameters).map_err(|error| error.to_string())?;
    Ok(baselineops_engine::dispatch_native(
        target.descriptor,
        Operation::Audit,
        &parameters,
    ))
}

struct ProfileResults {
    rendered: Vec<String>,
    completed: usize,
    unavailable: usize,
    failed: usize,
}

impl ProfileResults {
    fn new(capacity: usize) -> Self {
        Self {
            rendered: Vec::with_capacity(capacity),
            completed: 0,
            unavailable: 0,
            failed: 0,
        }
    }

    fn record(&mut self, target: &ProfileAuditStep, outcome: Result<CapabilityOutcome, String>) {
        match outcome {
            Ok(CapabilityOutcome::Completed { result }) => {
                self.completed += 1;
                self.rendered.push(format_completed(target, &result));
            }
            Ok(CapabilityOutcome::Unsupported { reason }) => {
                self.unavailable += 1;
                self.rendered.push(format_unsupported(target, &reason));
            }
            Ok(CapabilityOutcome::Failed { message, .. }) | Err(message) => {
                self.failed += 1;
                self.rendered.push(format_failure(target, &message));
            }
        }
    }

    fn report(self, workflow: &ProfileWorkflow) -> AuditReport {
        AuditReport {
            state: AuditState::Completed,
            status: format!(
                "Profile audit completed in dependency order: {} completed, {} unavailable, {} failed. {APPLY_LOCK_REASON}",
                self.completed, self.unavailable, self.failed
            ),
            result: format!(
                "Profile audit: {}\nProfile ID: {}\nOrder: {}\n\n{}",
                workflow.profile.name,
                workflow.profile.id,
                ordered_ids(workflow),
                self.rendered.join("\n\n")
            ),
            error: None,
            artifact: None,
        }
    }
}

pub(super) fn load(path: &Path) -> Result<ProfileWorkflow, String> {
    validate_selection(path)?;
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve selected profile: {error}"))?;
    let profile = read_profile(&canonical)?;
    let ordered_steps = resolve_steps(&profile)?;
    Ok(ProfileWorkflow {
        path: canonical,
        profile,
        ordered_steps,
    })
}

fn validate_selection(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("select a profile JSON file before continuing".into());
    }
    if path
        .extension()
        .is_none_or(|extension| !extension.eq_ignore_ascii_case("json"))
    {
        return Err("profile selection must name a .json file".into());
    }
    Ok(())
}

fn read_profile(path: &Path) -> Result<ProfileV3, String> {
    let bytes = baselineops_windows::read_bounded_utf8_no_follow(path, MAX_PROFILE_BYTES)
        .map_err(|error| format!("cannot read bounded profile: {error}"))?;
    let profile =
        baselineops_domain::load_profile_json(bytes.as_bytes(), JsonLoadLimits::default())
            .map_err(|error| format!("profile is invalid: {error}"))?;
    if profile
        .expires_at
        .is_some_and(|expiry| expiry <= Utc::now())
    {
        return Err("profile is expired and cannot be audited or reviewed".into());
    }
    Ok(profile)
}

fn resolve_steps(profile: &ProfileV3) -> Result<Vec<ProfileAuditStep>, String> {
    let validation = profile
        .validate()
        .map_err(|error| format!("profile is invalid: {error}"))?;
    let mut ordered = Vec::with_capacity(profile.steps.len());
    for step_id in validation.topological_order.as_slice() {
        ordered.push(resolve_step(profile, step_id)?);
    }
    Ok(ordered)
}

fn resolve_step(
    profile: &ProfileV3,
    step_id: &baselineops_domain::ActionId,
) -> Result<ProfileAuditStep, String> {
    let step = profile
        .steps
        .iter()
        .find(|step| &step.step_id == step_id)
        .ok_or_else(|| "validated profile step is unavailable".to_owned())?;
    let descriptor = lookup(step.capability_id.as_str()).ok_or_else(|| {
        format!(
            "profile references unknown capability: {}",
            step.capability_id
        )
    })?;
    if !audit_supported(descriptor) {
        return Err(format!(
            "profile capability {} is unavailable for read-only native audit",
            descriptor.id
        ));
    }
    Ok(ProfileAuditStep {
        step: step.clone(),
        descriptor,
    })
}

fn format_validation(workflow: &ProfileWorkflow) -> String {
    let steps = workflow
        .ordered_steps
        .iter()
        .enumerate()
        .map(|(index, target)| {
            format!(
                "{}. {} ({}) parameters: {}",
                index + 1,
                target.descriptor.id,
                target.step.step_id,
                pretty_parameters(&target.step)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "Profile: {}\nProfile ID: {}\nPath: {}\nSteps: {}\nTopological order:\n{}\n\n{}",
        workflow.profile.name,
        workflow.profile.id,
        workflow.path.display(),
        workflow.ordered_steps.len(),
        steps,
        APPLY_LOCK_REASON
    )
}

fn ordered_ids(workflow: &ProfileWorkflow) -> String {
    workflow
        .ordered_steps
        .iter()
        .map(|target| target.descriptor.id)
        .collect::<Vec<_>>()
        .join(" -> ")
}

fn pretty_parameters(step: &ProfileStepV3) -> String {
    serde_json::to_string(&step.parameters)
        .unwrap_or_else(|error| format!("parameter rendering failed: {error}"))
}

fn format_completed(target: &ProfileAuditStep, result: &serde_json::Value) -> String {
    format!(
        "{}\nParameters: {}\nResult:\n{}",
        target.descriptor.id,
        pretty_parameters(&target.step),
        serde_json::to_string_pretty(result)
            .unwrap_or_else(|error| format!("result rendering failed: {error}"))
    )
}

fn format_unsupported(
    target: &ProfileAuditStep,
    reason: &baselineops_capabilities::Unsupported,
) -> String {
    format!(
        "{}\nParameters: {}\nUnavailable: {}",
        target.descriptor.id,
        pretty_parameters(&target.step),
        serde_json::to_string(reason)
            .unwrap_or_else(|error| format!("unsupported state could not be rendered: {error}"))
    )
}

fn format_failure(target: &ProfileAuditStep, error: &str) -> String {
    format!(
        "{}\nParameters: {}\nFailed: {error}",
        target.descriptor.id,
        pretty_parameters(&target.step)
    )
}
