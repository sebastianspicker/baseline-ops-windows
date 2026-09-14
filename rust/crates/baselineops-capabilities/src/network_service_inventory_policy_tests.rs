use super::*;

fn interface(dns: Vec<&str>, gateways: Vec<&str>) -> NetworkInterfaceObservation {
    NetworkInterfaceObservation {
        interface_index: 7,
        interface_alias: "Ethernet".into(),
        ipv4_addresses: vec!["10.0.0.2".into()],
        ipv6_addresses: vec![],
        ipv4_gateways: gateways.into_iter().map(str::to_owned).collect(),
        ipv6_gateways: vec![],
        dns_servers: dns.into_iter().map(str::to_owned).collect(),
    }
}

#[test]
fn legacy_network_issue_fixture_is_stable() {
    let audit = evaluate_network_inventory(NetworkInventoryObservation {
        interfaces: vec![Observation::Present(interface(vec![], vec![]))],
        enumeration_complete: true,
    });
    assert_eq!(audit.findings[0].code, "NET-InterfaceIssue");
    assert!(
        audit.findings[0]
            .message
            .contains("missing DNS and missing gateway")
    );
}

#[test]
fn access_denied_record_is_incomplete_not_healthy() {
    let audit = evaluate_network_inventory(NetworkInventoryObservation {
        interfaces: vec![Observation::AccessDenied],
        enumeration_complete: true,
    });
    assert_eq!(audit.findings[0].code, "NET-InterfaceIncomplete");
}

fn mixed_service_process_observation() -> ServiceProcessInventoryObservation {
    ServiceProcessInventoryObservation {
        processes: mixed_processes(),
        services: mixed_services(),
        process_enumeration_complete: false,
        service_enumeration_complete: true,
    }
}

fn mixed_processes() -> Vec<ProcessInventoryRecord> {
    vec![
        ProcessInventoryRecord {
            process_id: 41,
            name: "collector.exe".into(),
            cpu_time_100ns: Observation::TimedOut,
            working_set_bytes: Observation::Missing,
            image_path: Observation::AccessDenied,
        },
        ProcessInventoryRecord {
            process_id: 42,
            name: "parser.exe".into(),
            cpu_time_100ns: Observation::Failed { exit_code: 87 },
            working_set_bytes: Observation::Truncated,
            image_path: Observation::Unparsed,
        },
    ]
}

fn mixed_services() -> Vec<Observation<ServiceInventoryRecord>> {
    vec![
        Observation::Present(ServiceInventoryRecord {
            name: "BaselineCollector".into(),
            display_name: "Baseline Collector".into(),
            state: 4,
            process_id: 41,
            start_mode: Observation::Unparsed,
            image_path: Observation::AccessDenied,
            start_name: Observation::Missing,
        }),
        Observation::AccessDenied,
        Observation::Present(ServiceInventoryRecord {
            name: "BaselineParser".into(),
            display_name: "Baseline Parser".into(),
            state: 0,
            process_id: 0,
            start_mode: Observation::TimedOut,
            image_path: Observation::Truncated,
            start_name: Observation::Failed { exit_code: 5 },
        }),
        Observation::Present(ServiceInventoryRecord {
            name: "BaselineReporter".into(),
            display_name: "Baseline Reporter".into(),
            state: 5,
            process_id: 43,
            start_mode: Observation::Missing,
            image_path: Observation::Unparsed,
            start_name: Observation::NotRun,
        }),
    ]
}

fn incomplete_finding(
    code: &'static str,
    subject: &'static str,
    observation_status: &'static str,
) -> PolicyFinding {
    PolicyFinding {
        code,
        status: FindingStatus::Warning,
        severity: Severity::Medium,
        message: format!("{subject} observation is incomplete: {observation_status}."),
        evidence: JsonMap::from([("observation_status".into(), json!(observation_status))]),
    }
}

fn enumeration_incomplete_finding() -> PolicyFinding {
    PolicyFinding {
        code: "INV-EnumerationIncomplete",
        status: FindingStatus::Warning,
        severity: Severity::Medium,
        message: "Process or service enumeration did not complete within its bounded record limit."
            .into(),
        evidence: JsonMap::new(),
    }
}

fn complete_process() -> ProcessInventoryRecord {
    ProcessInventoryRecord {
        process_id: 70,
        name: "complete.exe".into(),
        cpu_time_100ns: Observation::Present(4),
        working_set_bytes: Observation::Present(8),
        image_path: Observation::Present("C:\\complete.exe".into()),
    }
}

fn complete_service() -> ServiceInventoryRecord {
    ServiceInventoryRecord {
        name: "CompleteService".into(),
        display_name: "Complete Service".into(),
        state: 4,
        process_id: 70,
        start_mode: Observation::Present(2),
        image_path: Observation::Present("C:\\complete.exe".into()),
        start_name: Observation::Present("LocalSystem".into()),
    }
}

#[test]
fn service_process_findings_keep_record_and_pass_order() {
    let observation = mixed_service_process_observation();

    let audit = evaluate_service_process_inventory(observation.clone());

    assert_eq!(audit.observation, observation);
    assert_eq!(audit.process_count, 2);
    assert_eq!(audit.service_count, 4);
    assert_eq!(audit.running_services, 1);
    assert_eq!(audit.findings, expected_mixed_inventory_findings());
}

fn expected_mixed_inventory_findings() -> Vec<PolicyFinding> {
    let mut findings = incomplete_findings(&[
        (
            "INV-ProcessImageIncomplete",
            "process image",
            "access_denied",
        ),
        ("INV-ProcessCpuIncomplete", "process CPU", "timed_out"),
        ("INV-ProcessMemoryIncomplete", "process memory", "missing"),
        ("INV-ProcessImageIncomplete", "process image", "unparsed"),
        ("INV-ProcessCpuIncomplete", "process CPU", "failed"),
        ("INV-ProcessMemoryIncomplete", "process memory", "truncated"),
        (
            "INV-ServiceConfigIncomplete",
            "service configuration",
            "unparsed",
        ),
        (
            "INV-ServiceImageIncomplete",
            "service image",
            "access_denied",
        ),
        ("INV-ServiceAccountIncomplete", "service account", "missing"),
        ("INV-ServiceIncomplete", "service", "access_denied"),
        (
            "INV-ServiceConfigIncomplete",
            "service configuration",
            "timed_out",
        ),
        ("INV-ServiceImageIncomplete", "service image", "truncated"),
        ("INV-ServiceAccountIncomplete", "service account", "failed"),
        (
            "INV-ServiceConfigIncomplete",
            "service configuration",
            "missing",
        ),
        ("INV-ServiceImageIncomplete", "service image", "unparsed"),
        ("INV-ServiceAccountIncomplete", "service account", "not_run"),
    ]);
    findings.push(enumeration_incomplete_finding());
    findings
}

fn incomplete_findings(
    entries: &[(&'static str, &'static str, &'static str)],
) -> Vec<PolicyFinding> {
    entries
        .iter()
        .map(|&(code, subject, status)| incomplete_finding(code, subject, status))
        .collect()
}

#[test]
fn oversized_process_or_service_inventory_is_incomplete_after_the_retained_bound() {
    for (process_len, service_len, expected_process_count, expected_service_count, warning) in [
        (4_096, 4_096, 4_096, 4_096, false),
        (4_097, 4_096, 4_096, 4_096, true),
        (4_096, 4_097, 4_096, 4_096, true),
    ] {
        let mut processes = vec![complete_process(); process_len];
        if process_len == 4_097 {
            processes
                .last_mut()
                .expect("oversized process fixture has a final record")
                .image_path = Observation::AccessDenied;
        }
        let mut services = vec![Observation::Present(complete_service()); service_len];
        if service_len == 4_097 {
            *services
                .last_mut()
                .expect("oversized service fixture has a final record") = Observation::AccessDenied;
        }
        let observation = ServiceProcessInventoryObservation {
            processes,
            services,
            process_enumeration_complete: true,
            service_enumeration_complete: true,
        };
        let audit = evaluate_service_process_inventory(observation.clone());

        assert_eq!(audit.observation, observation);
        assert_eq!(audit.process_count, expected_process_count);
        assert_eq!(audit.service_count, expected_service_count);
        assert_eq!(audit.running_services, expected_service_count);
        assert_eq!(
            audit.findings,
            if warning {
                vec![enumeration_incomplete_finding()]
            } else {
                vec![]
            }
        );
    }
}
