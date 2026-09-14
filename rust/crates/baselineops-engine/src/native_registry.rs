//! Single native dispatch boundary shared by the CLI, GUI, and worker.

use baselineops_capabilities::{
    Capability, CapabilityDescriptor, CapabilityExecutor, CapabilityOutcome, CapabilityRequest,
    ExecutionEnvironment, NativeHandler, Operation, Unsupported, adapter_for,
};

/// Returns whether a descriptor has native acquisition code, including explicitly partial
/// observations. This does not establish complete capability behavior or Apply eligibility.
#[must_use]
pub const fn has_native_handler(descriptor: &CapabilityDescriptor) -> bool {
    !matches!(
        descriptor.handler,
        NativeHandler::SupportBundleCollect
            | NativeHandler::DefenderIocSweep
            | NativeHandler::ArtifactGrabber
    )
}

/// Dispatch through the handler selected by the compile-time capability registry.
#[must_use]
pub fn dispatch_native(
    descriptor: &'static CapabilityDescriptor,
    operation: Operation,
    parameters: &serde_json::Value,
) -> CapabilityOutcome {
    let environment = ExecutionEnvironment {
        is_windows: cfg!(windows),
        available_requirements: descriptor.requirements,
    };
    let request = CapabilityRequest {
        operation,
        parameters,
    };
    let Some(adapter) = adapter_for(descriptor.id) else {
        return CapabilityOutcome::Unsupported {
            reason: Unsupported::ExecutorUnavailable {
                capability_id: descriptor.id.into(),
            },
        };
    };
    adapter.execute(environment, request, Some(executor(descriptor.handler)))
}

fn executor(handler: NativeHandler) -> &'static dyn CapabilityExecutor {
    match handler {
        NativeHandler::DefenderAsrAllowlist => &crate::WaveDefenderAsrAllowlistWindowsExecutor,
        NativeHandler::LapsHygiene => &crate::WaveLapsHygieneWindowsExecutor,
        NativeHandler::LocalAdmins => &crate::WaveLocalAdminsWindowsExecutor,
        NativeHandler::OfficeBrowser => &crate::WaveOfficeBrowserWindowsExecutor,
        NativeHandler::WindowsUpdate => &crate::WaveWindowsUpdateWindowsExecutor,
        NativeHandler::UpdateHealth => &crate::WaveUpdateHealthWindowsExecutor,
        NativeHandler::ScheduledTasks => &crate::WaveScheduledTasksWindowsExecutor,
        NativeHandler::Winget => &crate::WaveWingetWindowsExecutor,
        NativeHandler::SupportBundleCollect => &crate::WaveSupportBundleCollectionWindowsExecutor,
        NativeHandler::SupportBundleParse => &crate::SupportBundleParserExecutor,
        NativeHandler::DefenderIocSweep => &crate::WaveDefenderIocSweepWindowsExecutor,
        NativeHandler::ArtifactGrabber => &crate::WaveIncidentArtifactGrabberWindowsExecutor,
        NativeHandler::BootSecurity => &crate::WaveBootSecurityWindowsExecutor,
        NativeHandler::RemoteGuardrails => &crate::WaveRemoteGuardrailsWindowsExecutor,
        NativeHandler::HardwareTrust => &crate::WaveHardwareTrustWindowsExecutor,
        NativeHandler::Sysmon => &crate::WaveSysmonWindowsExecutor,
        NativeHandler::FirewallBaseline => &crate::WaveFirewallBaselineWindowsExecutor,
        NativeHandler::Inventory => &crate::WaveInventoryWindowsExecutor,
        NativeHandler::EmergencyIsolation => &crate::WaveEmergencyIsolationWindowsExecutor,
        NativeHandler::SmbEncryption => &crate::WaveSmbEncryptionWindowsExecutor,
        NativeHandler::CertHealth => &crate::WaveCertHealthWindowsExecutor,
        NativeHandler::WaveOne => &crate::WaveOneWindowsExecutor,
        NativeHandler::NetworkServices => &crate::WaveNetworkServicesWindowsExecutor,
        NativeHandler::PowerShellLogging => &crate::WavePowerShellLoggingWindowsExecutor,
        NativeHandler::FirewallLogging => &crate::WaveFirewallLoggingWindowsExecutor,
        NativeHandler::AdvancedAudit => &crate::WaveAdvancedAuditWindowsExecutor,
        NativeHandler::WefTime => &crate::WaveWefTimeWindowsExecutor,
        NativeHandler::StorageBackup => &crate::WaveStorageBackupWindowsExecutor,
        NativeHandler::RemoteWdag => &crate::WaveRemoteWdagWindowsExecutor,
        NativeHandler::SecurityOptions => &crate::WaveSecurityOptionsWindowsExecutor,
        NativeHandler::WaveTwo => &crate::WaveTwoWindowsExecutor,
        NativeHandler::ApplicationControl => &crate::WaveApplicationControlWindowsExecutor,
        NativeHandler::AppControl => &crate::AppControlWindowsExecutor,
        NativeHandler::DefenderRansomware => &crate::WaveDefenderRansomwareWindowsExecutor,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registry_entry_has_exactly_one_handler_identity() {
        let handlers = baselineops_capabilities::list()
            .iter()
            .map(|descriptor| descriptor.handler)
            .collect::<Vec<_>>();
        assert_eq!(handlers.len(), 52);
        for descriptor in baselineops_capabilities::list() {
            assert_eq!(
                has_native_handler(descriptor),
                !matches!(descriptor.legacy_number, 9 | 11 | 12)
            );
        }
    }
}
