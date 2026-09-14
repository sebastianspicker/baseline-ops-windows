use super::*;

fn running(name: &str) -> Observation<ServiceObservation> {
    Observation::Present(ServiceObservation {
        name: name.into(),
        state: ServiceState::Running,
        start_mode: ServiceStartMode::Automatic,
    })
}

#[test]
fn time_evaluator_does_not_treat_incomplete_evidence_as_healthy() {
    let audit = evaluate_time_sync(
        TimeSyncObservation {
            service: running("w32time"),
            time_type: Observation::Present("NTP".into()),
            ntp_server: Observation::Present("pool.ntp.org,0x9".into()),
            ntp_client_enabled: Observation::Present(1),
            source: Observation::Unparsed,
            root_dispersion_ms: Observation::Truncated,
            phase_offset_ms: Observation::TimedOut,
        },
        &TimeSyncPolicy::default(),
    );
    assert!(
        audit
            .findings
            .iter()
            .all(|finding| finding.status != FindingStatus::Pass)
    );
    assert!(
        audit
            .findings
            .iter()
            .any(|finding| finding.code == "TIME-RootDispersionIncomplete")
    );
}

#[test]
fn wef_service_and_policy_failures_remain_distinct() {
    let audit = evaluate_wef_readiness(WefReadinessObservation {
        winrm: Observation::Present(ServiceObservation {
            name: "WinRM".into(),
            state: ServiceState::Stopped,
            start_mode: ServiceStartMode::Disabled,
        }),
        subscription_managers: Observation::AccessDenied,
        wecutil_qc: Observation::Present(parse_wecutil_qc("Fehler: access denied")),
    });
    for code in [
        "WEF-WinRMNotRunning",
        "WEF-SubscriptionManagerIncomplete",
        "WEF-WecutilQcReportedFailure",
    ] {
        assert!(audit.findings.iter().any(|finding| finding.code == code));
    }
}
