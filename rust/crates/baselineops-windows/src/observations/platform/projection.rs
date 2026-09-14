use super::{DefenderHealthObservation, SERVICE_RUNNING, SERVICE_STATUS_PROCESS};

#[derive(Clone, Debug)]
pub(super) struct DefenderProviderEvidence {
    pub(super) antivirus_enabled: Option<bool>,
    pub(super) antispyware_enabled: Option<bool>,
    pub(super) behavior_monitor_enabled: Option<bool>,
    pub(super) real_time_protection_enabled: Option<bool>,
    pub(super) signatures_out_of_date: Option<bool>,
    pub(super) antivirus_signature_age_days: Option<u32>,
    pub(super) quick_scan_age_days: Option<u32>,
    pub(super) full_scan_age_days: Option<u32>,
    pub(super) tamper_protected: Option<bool>,
    pub(super) reboot_required: Option<bool>,
}

pub(super) fn defender_observation(
    status: SERVICE_STATUS_PROCESS,
    evidence: &Result<DefenderProviderEvidence, String>,
) -> DefenderHealthObservation {
    let provider = evidence.as_ref().ok();
    DefenderHealthObservation {
        provider: "wmi_msft_mpcomputerstatus".into(),
        provider_error: evidence.as_ref().err().cloned(),
        service_running: status.dwCurrentState == SERVICE_RUNNING,
        service_state: status.dwCurrentState.0,
        process_id: status.dwProcessId,
        win32_exit_code: status.dwWin32ExitCode,
        antivirus_enabled: provider.and_then(|item| item.antivirus_enabled),
        antispyware_enabled: provider.and_then(|item| item.antispyware_enabled),
        behavior_monitor_enabled: provider.and_then(|item| item.behavior_monitor_enabled),
        real_time_protection_enabled: provider.and_then(|item| item.real_time_protection_enabled),
        signatures_out_of_date: provider.and_then(|item| item.signatures_out_of_date),
        antivirus_signature_age_days: provider.and_then(|item| item.antivirus_signature_age_days),
        quick_scan_age_days: provider.and_then(|item| item.quick_scan_age_days),
        full_scan_age_days: provider.and_then(|item| item.full_scan_age_days),
        tamper_protected: provider.and_then(|item| item.tamper_protected),
        reboot_required: provider.and_then(|item| item.reboot_required),
    }
}
