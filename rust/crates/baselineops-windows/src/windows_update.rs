//! Bounded HKLM observation adapter for the native capability 05 subset.

use crate::{PlatformError, policy_registry};
use baselineops_capabilities::{PolicyValueSnapshot, WindowsUpdateField, WindowsUpdateObservation};
use std::collections::BTreeMap;

#[path = "windows_update/mutation.rs"]
mod mutation;
#[cfg(windows)]
#[path = "windows_update/native.rs"]
mod native;
#[cfg(any(windows, test))]
#[path = "windows_update/registry_name.rs"]
mod registry_name;
#[cfg(any(windows, test))]
#[path = "windows_update/registry_security.rs"]
mod registry_security;

pub(super) const MAX_POLICY_STRING_BYTES: usize = 128;

/// Observes every v3 allowlisted `WUfB` registry value. Legacy active-hours
/// metadata is intentionally excluded because the script never mutates it.
///
/// # Errors
///
/// Returns an error for an unavailable platform, denied registry access, or a
/// present value whose Windows registry type does not match its allowlisted
/// policy field.
pub fn observe_windows_update_policy() -> Result<WindowsUpdateObservation, PlatformError> {
    let mut values = BTreeMap::new();
    for spec in FIELDS {
        values.insert(
            spec.field,
            if spec.kind == ValueKind::Dword {
                policy_registry::read_dword(spec.path, spec.name)?
            } else {
                policy_registry::read_string(spec.path, spec.name)?
            },
        );
    }
    Ok(WindowsUpdateObservation { values })
}

/// Compare and durably mutate one fixed Windows Update policy value.
///
/// The exact pre-state is reread before the native write. A missing key and a
/// missing value both map to [`PolicyValueSnapshot::Missing`]. Deleting either
/// is idempotent and never removes an empty key. Setting a missing value requires
/// the fixed policy key to exist; key creation fails closed because the Windows
/// API cannot atomically create it while proving that a concurrently created
/// registry symbolic link was not followed. Every existing path segment is
/// retained and checked for its exact native name, trusted owner, and DACL before
/// use. Those controls are checked again before the write and after its flush.
/// Callers must retain `expected` as recovery evidence because a write can
/// succeed before a later flush, retained-handle read-back, or independent
/// name-based reobservation reports failure.
///
/// # Errors
///
/// Returns an error for an unsupported platform, invalid value type or bound,
/// stale pre-state, native write or flush failure, or mismatched read-back.
pub fn apply_windows_update_mutation(
    field: WindowsUpdateField,
    expected: &PolicyValueSnapshot,
    desired: &PolicyValueSnapshot,
) -> Result<PolicyValueSnapshot, PlatformError> {
    #[cfg(windows)]
    {
        mutation::apply_with(
            &mut native::NativeRegistry::default(),
            field,
            expected,
            desired,
        )
    }
    #[cfg(not(windows))]
    {
        mutation::validate_request(field, expected, desired)?;
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ValueKind {
    Dword,
    String,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct FieldSpec {
    pub(super) field: WindowsUpdateField,
    pub(super) path: &'static str,
    pub(super) name: &'static str,
    pub(super) kind: ValueKind,
}

pub(super) fn field_spec(field: WindowsUpdateField) -> &'static FieldSpec {
    FIELDS
        .iter()
        .find(|spec| spec.field == field)
        .expect("every finite Windows Update field has one registry mapping")
}

const WU: &str = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
const AU: &str = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
const DO: &str = r"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization";
const FIELDS: [FieldSpec; 12] = [
    spec(
        WindowsUpdateField::UseWsus,
        AU,
        "UseWUServer",
        ValueKind::Dword,
    ),
    spec(
        WindowsUpdateField::WsusServer,
        WU,
        "WUServer",
        ValueKind::String,
    ),
    spec(
        WindowsUpdateField::WsusStatusServer,
        WU,
        "WUStatusServer",
        ValueKind::String,
    ),
    spec(
        WindowsUpdateField::AllowMicrosoftUpdate,
        AU,
        "AllowMUUpdateService",
        ValueKind::Dword,
    ),
    spec(
        WindowsUpdateField::DeferFeatureUpdates,
        WU,
        "DeferFeatureUpdates",
        ValueKind::Dword,
    ),
    spec(
        WindowsUpdateField::DeferFeatureDays,
        WU,
        "DeferFeatureUpdatesPeriodInDays",
        ValueKind::Dword,
    ),
    spec(
        WindowsUpdateField::DeferQualityUpdates,
        WU,
        "DeferQualityUpdates",
        ValueKind::Dword,
    ),
    spec(
        WindowsUpdateField::DeferQualityDays,
        WU,
        "DeferQualityUpdatesPeriodInDays",
        ValueKind::Dword,
    ),
    spec(
        WindowsUpdateField::TargetReleaseVersion,
        WU,
        "TargetReleaseVersion",
        ValueKind::Dword,
    ),
    spec(
        WindowsUpdateField::ProductVersion,
        WU,
        "ProductVersion",
        ValueKind::String,
    ),
    spec(
        WindowsUpdateField::TargetReleaseVersionInfo,
        WU,
        "TargetReleaseVersionInfo",
        ValueKind::String,
    ),
    spec(
        WindowsUpdateField::DeliveryOptimizationMode,
        DO,
        "DODownloadMode",
        ValueKind::Dword,
    ),
];

const fn spec(
    field: WindowsUpdateField,
    path: &'static str,
    name: &'static str,
    kind: ValueKind,
) -> FieldSpec {
    FieldSpec {
        field,
        path,
        name,
        kind,
    }
}
