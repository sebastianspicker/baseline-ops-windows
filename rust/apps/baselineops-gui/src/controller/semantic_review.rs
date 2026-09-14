//! Read-only native proposal review using the same derivation as CLI and worker.

use super::{
    APPLY_LOCK_REASON, AuditReport, AuditState, cancelled_profile_report, invalid_profile_report,
};
use baselineops_domain::{ExecutionIntent, ProfileStepV3};
use baselineops_engine::{
    NativeObservationSource, RegistryActionDeriver, TrustedActionDeriver, TrustedObservationSource,
};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

struct ReviewObserver<'a>(&'a AtomicBool);
impl TrustedObservationSource for ReviewObserver<'_> {
    fn observe(&self, step: &ProfileStepV3) -> Result<serde_json::Value, String> {
        if self.0.load(Ordering::Acquire) {
            return Err("review cancelled".into());
        }
        NativeObservationSource.observe(step)
    }
}

pub(super) fn review(path: &Path, cancelled: &Arc<AtomicBool>) -> AuditReport {
    let workflow = match super::profile::load(path) {
        Ok(workflow) => workflow,
        Err(error) => return invalid_profile_report(error),
    };
    if cancelled.load(Ordering::Acquire) {
        return cancelled_profile_report();
    }
    let result = derive(&workflow.profile, cancelled);
    if cancelled.load(Ordering::Acquire) {
        return cancelled_profile_report();
    }
    match result {
        Ok(result) => AuditReport {
            state: AuditState::Completed,
            status: format!("Native proposal review complete. {APPLY_LOCK_REASON}"),
            result,
            error: None,
            artifact: None,
        },
        Err(error) => AuditReport {
            state: AuditState::Failed,
            status: "Native proposal review could not complete.".into(),
            result: String::new(),
            error: Some(error),
            artifact: None,
        },
    }
}

fn derive(
    profile: &baselineops_domain::ProfileV3,
    cancelled: &AtomicBool,
) -> Result<String, String> {
    let observations = baselineops_engine::reobserve_profile(
        profile,
        &ReviewObserver(cancelled),
        chrono::Utc::now(),
    )?;
    let order = profile
        .topological_order()
        .map_err(|error| error.to_string())?;
    let by_id = profile
        .steps
        .iter()
        .map(|step| (step.step_id, step))
        .collect::<std::collections::BTreeMap<_, _>>();
    let actions = order
        .as_slice()
        .iter()
        .map(|id| RegistryActionDeriver.derive(by_id[id], ExecutionIntent::Apply, &observations))
        .collect::<Result<Vec<_>, _>>()?;
    let rendered = serde_json::to_string_pretty(&actions).map_err(|error| error.to_string())?;
    Ok(format!(
        "Profile: {}\nObservation digest: {}\n\n{}\n\nThis preview is not an approved saved plan. Package binding and authenticated worker approval are still required.\n{}",
        profile.name, observations.digest, rendered, APPLY_LOCK_REASON
    ))
}
