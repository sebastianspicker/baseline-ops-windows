//! Shell-free controller for the native, read-only GUI workflow.

use std::{
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, TryRecvError},
    },
};

use baselineops_capabilities::{CapabilityDescriptor, CapabilityOutcome, Operation, lookup};
use baselineops_domain::Sha256Digest;

mod profile;
mod semantic_review;

/// The GUI accepts at most the domain's standard bounded profile input.
pub const MAX_PROFILE_BYTES: u64 = baselineops_windows::MAX_INPUT_BYTES;

/// Precise reason that the GUI never exposes a production mutation path.
pub const APPLY_LOCK_REASON: &str = "Apply is disabled: this standard-user GUI never starts the protected worker, and production eligibility remains evidence-locked.";

/// A selectable capability from the native audit catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogItem {
    /// Stable registry identifier.
    pub id: &'static str,
    /// Legacy script number retained for operator orientation.
    pub number: u8,
    /// Human-readable registry name.
    pub name: &'static str,
    /// Human-readable registry description.
    pub description: &'static str,
}

/// A retained viewer reference authenticated by a capability-supplied digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedArtifact {
    /// Existing artifact selected by a native executor.
    pub path: PathBuf,
    /// Digest that the executor returned with the artifact reference.
    pub digest: Sha256Digest,
}

/// UI-friendly terminal state of an audit attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditState {
    /// No audit has started.
    Ready,
    /// A read-only platform observation is in progress.
    Running,
    /// Cancellation was requested; the current native observation is allowed to finish safely.
    Cancelling,
    /// The request was cancelled and its result deliberately discarded.
    Cancelled,
    /// The native executor returned structured, trustworthy output.
    Completed,
    /// Registry dispatch intentionally did not run.
    Unsupported,
    /// The executor could not produce a trustworthy result.
    Failed,
}

/// Renderable result returned from a direct native executor invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditReport {
    /// Terminal or progress state.
    pub state: AuditState,
    /// One-line status for the UI status bar.
    pub status: String,
    /// Pretty-printed structured result when one exists.
    pub result: String,
    /// Bounded diagnostic shown separately from a successful result.
    pub error: Option<String>,
    /// A digest-bound artifact that a future native executor explicitly returns.
    pub artifact: Option<AuthenticatedArtifact>,
}

/// Events emitted by a background audit without granting the worker UI access.
pub(crate) enum WorkerMessage {
    /// A profile reached a safe cancellation boundary.
    Progress(AuditReport),
    /// The requested audit completed or was cancelled.
    Finished(AuditReport),
}

/// Coalesced result of draining the worker channel once.
pub(crate) enum WorkerUpdate {
    /// No event is currently queued.
    Idle,
    /// The newest progress event from the drained burst.
    Progress(AuditReport),
    /// A terminal event was queued and must be rendered immediately.
    Finished(AuditReport),
    /// Every sender exited without a terminal event.
    Disconnected,
}

/// Drain all currently queued worker events, retaining only the newest progress.
pub(crate) fn drain_worker_messages(receiver: &Receiver<WorkerMessage>) -> WorkerUpdate {
    let mut newest_progress = None;
    loop {
        match receiver.try_recv() {
            Ok(WorkerMessage::Progress(report)) => newest_progress = Some(report),
            Ok(WorkerMessage::Finished(report)) => return WorkerUpdate::Finished(report),
            Err(TryRecvError::Empty) => {
                return newest_progress.map_or(WorkerUpdate::Idle, WorkerUpdate::Progress);
            }
            Err(TryRecvError::Disconnected) => return WorkerUpdate::Disconnected,
        }
    }
}

impl AuditReport {
    /// Initial state before a capability is selected or audited.
    #[must_use]
    pub fn ready() -> Self {
        Self {
            state: AuditState::Ready,
            status: format!(
                "Ready. Select a bounded v3 profile to Validate, Audit, or Review. {APPLY_LOCK_REASON}"
            ),
            result: String::new(),
            error: None,
            artifact: None,
        }
    }

    /// Progress state that communicates the cancellation boundary honestly.
    #[must_use]
    pub fn running() -> Self {
        Self {
            state: AuditState::Running,
            status: "Running a read-only native audit. No changes can be applied.".into(),
            result: String::new(),
            error: None,
            artifact: None,
        }
    }

    /// Progress state at a capability boundary in a profile audit.
    #[must_use]
    pub fn profile_progress(index: usize, total: usize, capability_id: &str) -> Self {
        Self {
            state: AuditState::Running,
            status: format!(
                "Profile audit progress: capability {index}/{total} ({capability_id}). Cancellation takes effect before the next capability."
            ),
            result: String::new(),
            error: None,
            artifact: None,
        }
    }

    /// Cancellation progress where a platform call cannot safely be interrupted.
    #[must_use]
    pub fn cancelling() -> Self {
        Self {
            state: AuditState::Cancelling,
            status: "Cancellation requested. The current observation will finish, then its result is discarded.".into(),
            result: String::new(),
            error: None,
            artifact: None,
        }
    }
}

/// Lists all 52 catalog entries; the default operation remains a single-capability audit.
#[must_use]
pub fn catalog() -> Vec<CatalogItem> {
    baselineops_capabilities::list()
        .iter()
        .map(|descriptor| CatalogItem {
            id: descriptor.id,
            number: descriptor.legacy_number,
            name: descriptor.display_name,
            description: descriptor.description,
        })
        .collect()
}

/// Returns an accessible description for a selected catalog item.
#[must_use]
pub fn selection_summary(item: CatalogItem) -> String {
    format!(
        "{:02} {}. {}. Select Audit selected capability for one read-only observation. {APPLY_LOCK_REASON}",
        item.number, item.name, item.description
    )
}

/// Validates a standard-user-selected profile and reports its dependency-safe order.
#[must_use]
pub fn validate_profile(path: &Path) -> AuditReport {
    profile::validate(path)
}

/// Runs a profile in validated topological order with typed parameters and cooperative cancellation.
/// The progress callback fires before every capability boundary.
#[must_use]
pub fn audit_profile(
    path: &Path,
    cancelled: &Arc<AtomicBool>,
    mut progress: impl FnMut(AuditReport),
) -> AuditReport {
    profile::audit(path, cancelled, &mut progress)
}

/// Runs one allowlisted native audit without starting a shell or compatibility runner.
#[must_use]
pub fn audit(id: &str, cancelled: &Arc<AtomicBool>) -> AuditReport {
    if cancelled.load(Ordering::Acquire) {
        return cancelled_report();
    }
    let Some(descriptor) = lookup(id) else {
        return unsupported(format!(
            "{id} is absent from the compiled capability registry."
        ));
    };
    if !audit_supported(descriptor) {
        return unsupported(format!("{id} is not exposed by the native read-only GUI."));
    }
    if let Err(error) = baselineops_windows::collect_host_identity() {
        return unsupported(error.to_string());
    }
    let outcome =
        baselineops_engine::dispatch_native(descriptor, Operation::Audit, &serde_json::json!({}));
    if cancelled.load(Ordering::Acquire) {
        return cancelled_report();
    }
    report_outcome(outcome)
}

fn audit_supported(descriptor: &CapabilityDescriptor) -> bool {
    descriptor.operations.supports(Operation::Audit)
        && baselineops_engine::has_native_handler(descriptor)
}

fn report_outcome(outcome: CapabilityOutcome) -> AuditReport {
    match outcome {
        CapabilityOutcome::Completed { result } => AuditReport {
            state: AuditState::Completed,
            status: format!("Native audit finished. {APPLY_LOCK_REASON}"),
            result: format!(
                "Native audit evidence; capability completion requires its verification ledger\nApply: locked\n\n{}",
                serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|error| format!("Result rendering failed: {error}"))
            ),
            error: None,
            artifact: existing_artifact(&result),
        },
        CapabilityOutcome::Unsupported { reason } => {
            unsupported(serde_json::to_string(&reason).unwrap_or_else(|error| {
                format!("unsupported state could not be rendered: {error}")
            }))
        }
        CapabilityOutcome::Failed {
            capability_id,
            message,
        } => AuditReport {
            state: AuditState::Failed,
            status: format!("Native audit failed for {capability_id}."),
            result: String::new(),
            error: Some(message),
            artifact: None,
        },
    }
}

fn existing_artifact(result: &serde_json::Value) -> Option<AuthenticatedArtifact> {
    let path = PathBuf::from(result.get("artifact_path")?.as_str()?);
    let digest = Sha256Digest::from_str(result.get("artifact_sha256")?.as_str()?).ok()?;
    path.is_file()
        .then_some(AuthenticatedArtifact { path, digest })
}

fn invalid_profile_report(error: String) -> AuditReport {
    AuditReport {
        state: AuditState::Unsupported,
        status: "Profile validation failed before any native operation started.".into(),
        result: String::new(),
        error: Some(error),
        artifact: None,
    }
}

fn unsupported(reason: String) -> AuditReport {
    AuditReport {
        state: AuditState::Unsupported,
        status: "Native audit is unsupported on this host or build.".into(),
        result: String::new(),
        error: Some(reason),
        artifact: None,
    }
}

fn cancelled_report() -> AuditReport {
    AuditReport {
        state: AuditState::Cancelled,
        status: "Native audit cancelled. No result was retained.".into(),
        result: String::new(),
        error: None,
        artifact: None,
    }
}

fn cancelled_profile_report() -> AuditReport {
    AuditReport {
        state: AuditState::Cancelled,
        status: "Profile audit cancelled at a capability boundary. No partial result was retained."
            .into(),
        result: String::new(),
        error: None,
        artifact: None,
    }
}

#[cfg(test)]
#[path = "controller_tests.rs"]
mod tests;

/// Observe a profile and review capability proposals without granting Apply authority.
/// The native UI invokes this on its background worker; cancellation is checked
/// between observations and before retaining results.
#[must_use]
pub fn review_profile_native(path: &Path, cancelled: &Arc<AtomicBool>) -> AuditReport {
    semantic_review::review(path, cancelled)
}
