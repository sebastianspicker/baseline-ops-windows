use super::*;
use std::{
    fs,
    sync::{Mutex, mpsc::channel},
};

static TEMP_LOCK: Mutex<()> = Mutex::new(());

fn profile_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "baselineops-gui-{name}-{}-{}.json",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ))
}

#[allow(clippy::needless_pass_by_value)]
fn write_profile(path: &Path, body: serde_json::Value) {
    fs::write(path, serde_json::to_vec(&body).expect("serialize profile")).expect("write profile");
}

#[allow(clippy::needless_pass_by_value)]
fn profile(steps: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "schema_version": "3.0",
        "profile_id": "11111111-1111-4111-8111-111111111111",
        "name": "GUI test profile",
        "version": "1.0.0",
        "created_at": "2026-01-01T00:00:00Z",
        "steps": steps
    })
}

#[test]
fn catalog_preserves_the_52_item_default_single_capability_audit() {
    let entries = catalog();
    assert_eq!(entries.len(), 52);
    assert_eq!(
        entries.iter().map(|entry| entry.number).collect::<Vec<_>>(),
        (1..=52).collect::<Vec<_>>()
    );
}

#[test]
fn selection_copy_never_advertises_apply() {
    assert!(selection_summary(catalog()[0]).contains("Apply is disabled"));
}

#[test]
fn invalid_profile_is_rejected_before_audit() {
    let _guard = TEMP_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let path = profile_path("invalid");
    write_profile(&path, serde_json::json!({"not": "a profile"}));
    let report = validate_profile(&path);
    fs::remove_file(path).expect("remove profile");
    assert_eq!(report.state, AuditState::Unsupported);
    assert!(
        report
            .error
            .as_deref()
            .is_some_and(|error| error.contains("invalid"))
    );
}

#[test]
fn unknown_profile_capability_is_rejected_before_audit() {
    let _guard = TEMP_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let path = profile_path("unknown");
    write_profile(
        &path,
        profile(serde_json::json!([{
            "step_id": "22222222-2222-4222-8222-222222222222",
            "capability_id": "v3.not-a-capability"
        }])),
    );
    let report = validate_profile(&path);
    fs::remove_file(path).expect("remove profile");
    assert_eq!(report.state, AuditState::Unsupported);
    assert!(
        report
            .error
            .as_deref()
            .is_some_and(|error| error.contains("unknown capability"))
    );
}

#[test]
fn expired_profile_is_rejected_before_audit_or_review() {
    let _guard = TEMP_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let path = profile_path("expired");
    let mut body = profile(serde_json::json!([{
        "step_id": "22222222-2222-4222-8222-222222222222",
        "capability_id": "v3.software.inventory"
    }]));
    body["expires_at"] = serde_json::json!("2026-01-02T00:00:00Z");
    write_profile(&path, body);
    let report = review_profile_native(&path, &Arc::new(AtomicBool::new(false)));
    fs::remove_file(path).expect("remove profile");
    assert_eq!(report.state, AuditState::Unsupported);
    assert!(
        report
            .error
            .as_deref()
            .is_some_and(|error| error.contains("expired"))
    );
}

#[test]
fn validated_profile_preserves_order_and_typed_parameters() {
    let _guard = TEMP_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let path = profile_path("ordering");
    write_profile(
        &path,
        profile(serde_json::json!([
            {
                "step_id": "33333333-3333-4333-8333-333333333333",
                "capability_id": "v3.patch.missing",
                "depends_on": ["22222222-2222-4222-8222-222222222222"],
                "parameters": {"entries": [{"kb": "KB5030219", "title": "Test", "is_zero_day": false, "severity": "high"}]}
            },
            {
                "step_id": "22222222-2222-4222-8222-222222222222",
                "capability_id": "v3.software.inventory"
            }
        ])),
    );
    let workflow = profile::load(&path).expect("valid profile");
    fs::remove_file(path).expect("remove profile");
    assert_eq!(
        workflow
            .ordered_steps
            .iter()
            .map(|step| step.descriptor.id)
            .collect::<Vec<_>>(),
        vec!["v3.software.inventory", "v3.patch.missing"]
    );
    assert_eq!(
        workflow.ordered_steps[1].step.parameters["entries"][0]["kb"],
        "KB5030219"
    );
}

#[test]
fn cancellation_prevents_profile_native_dispatch() {
    let _guard = TEMP_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let path = profile_path("cancelled");
    write_profile(
        &path,
        profile(serde_json::json!([{
            "step_id": "22222222-2222-4222-8222-222222222222",
            "capability_id": "v3.software.inventory"
        }])),
    );
    let cancelled = Arc::new(AtomicBool::new(true));
    let report = audit_profile(&path, &cancelled, |_| {
        panic!("no progress after cancellation")
    });
    fs::remove_file(path).expect("remove profile");
    assert_eq!(report.state, AuditState::Cancelled);
    assert!(report.result.is_empty());
}

#[test]
fn cancellation_prevents_native_dispatch() {
    let cancelled = Arc::new(AtomicBool::new(true));
    let report = audit("v3.defender.health", &cancelled);
    assert_eq!(report.state, AuditState::Cancelled);
    assert!(report.result.is_empty());
}

#[test]
fn progress_reports_are_explicitly_read_only() {
    assert_eq!(AuditReport::ready().state, AuditState::Ready);
    assert_eq!(AuditReport::running().state, AuditState::Running);
    assert_eq!(AuditReport::cancelling().state, AuditState::Cancelling);
}

#[test]
fn unknown_capability_remains_unsupported() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let report = audit("v3.not-a-capability", &cancelled);
    assert_eq!(report.state, AuditState::Unsupported);
    assert!(report.error.is_some());
}

#[cfg(not(windows))]
#[test]
fn unsupported_host_preflight_prevents_native_dispatch() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let report = audit("v3.defender.health", &cancelled);
    assert_eq!(report.state, AuditState::Unsupported);
    assert!(
        report
            .error
            .as_deref()
            .is_some_and(|error| error.contains("unsupported"))
    );
}

#[test]
fn artifact_requires_a_digest_bound_reference() {
    let result = serde_json::json!({ "artifact_path": "/path/that/does/not/exist" });
    assert_eq!(existing_artifact(&result), None);
}

#[test]
fn progress_bursts_render_only_the_newest_queued_progress() {
    let (sender, receiver) = channel();
    for index in 1..=100 {
        sender
            .send(WorkerMessage::Progress(AuditReport::profile_progress(
                index,
                100,
                "v3.software.inventory",
            )))
            .expect("queue progress");
    }
    let WorkerUpdate::Progress(report) = drain_worker_messages(&receiver) else {
        panic!("expected coalesced progress");
    };
    assert!(report.status.contains("capability 100/100"));
}

#[test]
fn queued_completion_bypasses_a_progress_burst_in_one_drain() {
    let (sender, receiver) = channel();
    for index in 1..=100 {
        sender
            .send(WorkerMessage::Progress(AuditReport::profile_progress(
                index,
                100,
                "v3.software.inventory",
            )))
            .expect("queue progress");
    }
    let mut completed = AuditReport::ready();
    completed.state = AuditState::Completed;
    completed.status = "finished".into();
    sender
        .send(WorkerMessage::Finished(completed))
        .expect("queue completion");
    let WorkerUpdate::Finished(report) = drain_worker_messages(&receiver) else {
        panic!("expected immediate completion");
    };
    assert_eq!(report.status, "finished");
}

#[test]
fn worker_disconnect_remains_a_terminal_ui_event() {
    let (sender, receiver) = channel::<WorkerMessage>();
    drop(sender);
    assert!(matches!(
        drain_worker_messages(&receiver),
        WorkerUpdate::Disconnected
    ));
}

#[test]
fn native_review_honors_cancellation_before_observation() {
    let path = profile_path("native-review-cancelled");
    write_profile(
        &path,
        profile(serde_json::json!([{
            "step_id":"22222222-2222-4222-8222-222222222222",
            "capability_id":"v3.software.inventory"
        }])),
    );
    let report = review_profile_native(&path, &Arc::new(AtomicBool::new(true)));
    fs::remove_file(path).unwrap();
    assert_eq!(report.state, AuditState::Cancelled);
    assert!(report.result.is_empty());
}

#[test]
fn partial_isolation_audit_is_available_without_promoting_apply() {
    let descriptor = lookup("v3.network.emergency-isolation").unwrap();
    assert!(audit_supported(descriptor));
    assert_eq!(
        descriptor.maturity,
        baselineops_capabilities::ImplementationMaturity::InDevelopment
    );
    assert!(descriptor.apply_handler.is_none());
    assert_ne!(
        descriptor.apply_eligibility,
        baselineops_capabilities::ApplyEligibility::Enabled
    );
    for number in [9, 11, 12] {
        assert!(!audit_supported(
            baselineops_capabilities::lookup_legacy(number).unwrap()
        ));
    }
}
