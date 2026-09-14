use super::{FieldSpec, MAX_POLICY_STRING_BYTES, ValueKind, field_spec};
use crate::PlatformError;
use baselineops_capabilities::{PolicyValueSnapshot, WindowsUpdateField};

#[cfg(any(windows, test))]
pub(super) trait RegistryReader {
    fn read(&mut self, spec: &FieldSpec) -> Result<PolicyValueSnapshot, PlatformError>;
}

#[cfg(any(windows, test))]
pub(super) trait RegistryWriter {
    fn write(
        &mut self,
        spec: &FieldSpec,
        expected: &PolicyValueSnapshot,
        desired: &PolicyValueSnapshot,
    ) -> Result<(), PlatformError>;
}

#[cfg(any(windows, test))]
pub(super) trait RegistryFlusher {
    fn flush_and_read_retained(
        &mut self,
        spec: &FieldSpec,
    ) -> Result<PolicyValueSnapshot, PlatformError>;
}

#[cfg(any(windows, test))]
pub(super) trait RegistryPort: RegistryReader + RegistryWriter + RegistryFlusher {}

#[cfg(any(windows, test))]
impl<T: RegistryReader + RegistryWriter + RegistryFlusher> RegistryPort for T {}

#[cfg(any(windows, test))]
pub(super) fn apply_with(
    port: &mut impl RegistryPort,
    field: WindowsUpdateField,
    expected: &PolicyValueSnapshot,
    desired: &PolicyValueSnapshot,
) -> Result<PolicyValueSnapshot, PlatformError> {
    let spec = validate_request(field, expected, desired)?;
    let before = compare_prestate(port, spec, expected)?;
    if &before == desired {
        return Ok(before);
    }
    mutate_and_verify(port, spec, expected, desired)
}

#[cfg(any(windows, test))]
fn compare_prestate(
    port: &mut impl RegistryReader,
    spec: &FieldSpec,
    expected: &PolicyValueSnapshot,
) -> Result<PolicyValueSnapshot, PlatformError> {
    let before = port.read(spec)?;
    if &before != expected {
        return Err(stale_state());
    }
    Ok(before)
}

#[cfg(any(windows, test))]
fn mutate_and_verify(
    port: &mut impl RegistryPort,
    spec: &FieldSpec,
    expected: &PolicyValueSnapshot,
    desired: &PolicyValueSnapshot,
) -> Result<PolicyValueSnapshot, PlatformError> {
    port.write(spec, expected, desired)?;
    let retained = port.flush_and_read_retained(spec)?;
    verify_readback(&retained, desired)?;
    let reobserved = port.read(spec)?;
    verify_readback(&reobserved, desired)?;
    Ok(reobserved)
}

#[cfg(any(windows, test))]
fn verify_readback(
    actual: &PolicyValueSnapshot,
    desired: &PolicyValueSnapshot,
) -> Result<(), PlatformError> {
    if actual != desired {
        return Err(PlatformError::TrustFailure(
            "Windows Update registry read-back did not match the requested value".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_request(
    field: WindowsUpdateField,
    expected: &PolicyValueSnapshot,
    desired: &PolicyValueSnapshot,
) -> Result<&'static FieldSpec, PlatformError> {
    if field == WindowsUpdateField::AllowMicrosoftUpdate {
        return Err(PlatformError::ProcessRejected(
            "AllowMicrosoftUpdate is observation-only for v2 behavior parity".into(),
        ));
    }
    let spec = field_spec(field);
    validate_snapshot(spec, expected)?;
    validate_snapshot(spec, desired)?;
    validate_dword_bound(field, desired)?;
    Ok(spec)
}

fn validate_snapshot(spec: &FieldSpec, value: &PolicyValueSnapshot) -> Result<(), PlatformError> {
    match (spec.kind, value) {
        (_, PolicyValueSnapshot::Missing) | (ValueKind::Dword, PolicyValueSnapshot::Dword(_)) => {
            Ok(())
        }
        (ValueKind::String, PolicyValueSnapshot::String(value)) => validate_string(value),
        _ => Err(PlatformError::TrustFailure(
            "Windows Update value type does not match its fixed field".into(),
        )),
    }
}

fn validate_string(value: &str) -> Result<(), PlatformError> {
    if value.len() > MAX_POLICY_STRING_BYTES || value.contains('\0') {
        return Err(PlatformError::TrustFailure(
            "Windows Update string exceeds its bound or contains NUL".into(),
        ));
    }
    Ok(())
}

fn validate_dword_bound(
    field: WindowsUpdateField,
    desired: &PolicyValueSnapshot,
) -> Result<(), PlatformError> {
    let PolicyValueSnapshot::Dword(value) = desired else {
        return Ok(());
    };
    if dword_within_bound(field, *value) {
        Ok(())
    } else {
        Err(PlatformError::TrustFailure(
            "Windows Update DWORD is outside its fixed field bound".into(),
        ))
    }
}

fn dword_within_bound(field: WindowsUpdateField, value: u32) -> bool {
    const BOOLEAN_FIELDS: [WindowsUpdateField; 5] = [
        WindowsUpdateField::UseWsus,
        WindowsUpdateField::AllowMicrosoftUpdate,
        WindowsUpdateField::DeferFeatureUpdates,
        WindowsUpdateField::DeferQualityUpdates,
        WindowsUpdateField::TargetReleaseVersion,
    ];
    if BOOLEAN_FIELDS.contains(&field) {
        return value <= 1;
    }
    match field {
        WindowsUpdateField::DeferFeatureDays => value <= 365,
        WindowsUpdateField::DeferQualityDays => value <= 35,
        WindowsUpdateField::DeliveryOptimizationMode => matches!(value, 0..=3 | 99),
        _ => false,
    }
}

#[cfg(any(windows, test))]
pub(super) fn stale_state() -> PlatformError {
    PlatformError::TrustFailure("Windows Update registry pre-state changed before mutation".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Failure {
        None,
        InitialRead,
        Write,
        Flush,
        RetainedRead,
        RetainedMismatch,
        Reread,
        RereadMismatch,
    }

    struct MockRegistry {
        state: PolicyValueSnapshot,
        failure: Failure,
        reads: usize,
        events: Vec<&'static str>,
    }

    impl MockRegistry {
        fn new(state: PolicyValueSnapshot, failure: Failure) -> Self {
            Self {
                state,
                failure,
                reads: 0,
                events: Vec::new(),
            }
        }

        fn failed(&self, failure: Failure) -> Result<(), PlatformError> {
            if self.failure == failure {
                Err(PlatformError::TrustFailure(
                    "injected registry failure".into(),
                ))
            } else {
                Ok(())
            }
        }
    }

    impl RegistryReader for MockRegistry {
        fn read(&mut self, _: &FieldSpec) -> Result<PolicyValueSnapshot, PlatformError> {
            self.events.push("read");
            self.reads += 1;
            self.failed(if self.reads == 1 {
                Failure::InitialRead
            } else {
                Failure::Reread
            })?;
            if self.reads > 1 && self.failure == Failure::RereadMismatch {
                return Ok(PolicyValueSnapshot::Missing);
            }
            Ok(self.state.clone())
        }
    }

    impl RegistryWriter for MockRegistry {
        fn write(
            &mut self,
            _: &FieldSpec,
            expected: &PolicyValueSnapshot,
            desired: &PolicyValueSnapshot,
        ) -> Result<(), PlatformError> {
            self.events.push("write");
            self.failed(Failure::Write)?;
            if &self.state != expected {
                return Err(stale_state());
            }
            self.state = desired.clone();
            Ok(())
        }
    }

    impl RegistryFlusher for MockRegistry {
        fn flush_and_read_retained(
            &mut self,
            _: &FieldSpec,
        ) -> Result<PolicyValueSnapshot, PlatformError> {
            self.events.push("flush");
            self.failed(Failure::Flush)?;
            self.events.push("read_retained");
            self.failed(Failure::RetainedRead)?;
            if self.failure == Failure::RetainedMismatch {
                return Ok(PolicyValueSnapshot::Missing);
            }
            Ok(self.state.clone())
        }
    }

    fn apply(
        registry: &mut MockRegistry,
        expected: &PolicyValueSnapshot,
        desired: &PolicyValueSnapshot,
    ) -> Result<PolicyValueSnapshot, PlatformError> {
        apply_with(registry, WindowsUpdateField::UseWsus, expected, desired)
    }

    fn assert_failure_events(failure: Failure, events: &[&str]) {
        let mut registry = MockRegistry::new(PolicyValueSnapshot::Dword(0), failure);
        assert!(
            apply(
                &mut registry,
                &PolicyValueSnapshot::Dword(0),
                &PolicyValueSnapshot::Dword(1)
            )
            .is_err()
        );
        assert_eq!(registry.events, events);
    }

    #[test]
    fn stale_prestate_and_idempotence_never_write() {
        let mut stale = MockRegistry::new(PolicyValueSnapshot::Dword(1), Failure::None);
        assert!(
            apply(
                &mut stale,
                &PolicyValueSnapshot::Dword(0),
                &PolicyValueSnapshot::Dword(1)
            )
            .is_err()
        );
        assert_eq!(stale.events, ["read"]);
        let mut same = MockRegistry::new(PolicyValueSnapshot::Dword(0), Failure::None);
        assert_eq!(
            apply(
                &mut same,
                &PolicyValueSnapshot::Dword(0),
                &PolicyValueSnapshot::Dword(0)
            )
            .unwrap(),
            PolicyValueSnapshot::Dword(0)
        );
        assert_eq!(same.events, ["read"]);
    }

    #[test]
    fn successful_write_flushes_then_rereads_independently() {
        let mut registry = MockRegistry::new(PolicyValueSnapshot::Dword(0), Failure::None);
        assert_eq!(
            apply(
                &mut registry,
                &PolicyValueSnapshot::Dword(0),
                &PolicyValueSnapshot::Dword(1)
            )
            .unwrap(),
            PolicyValueSnapshot::Dword(1)
        );
        assert_eq!(
            registry.events,
            ["read", "write", "flush", "read_retained", "read"]
        );
    }

    #[test]
    fn deletion_is_precise_and_durable() {
        let mut registry = MockRegistry::new(PolicyValueSnapshot::Dword(1), Failure::None);
        assert_eq!(
            apply(
                &mut registry,
                &PolicyValueSnapshot::Dword(1),
                &PolicyValueSnapshot::Missing
            )
            .unwrap(),
            PolicyValueSnapshot::Missing
        );
        assert_eq!(
            registry.events,
            ["read", "write", "flush", "read_retained", "read"]
        );
    }

    #[test]
    fn write_flush_and_reread_failures_stop_at_the_failing_stage() {
        for (failure, events) in [
            (Failure::Write, &["read", "write"][..]),
            (Failure::Flush, &["read", "write", "flush"]),
            (
                Failure::RetainedRead,
                &["read", "write", "flush", "read_retained"],
            ),
            (
                Failure::Reread,
                &["read", "write", "flush", "read_retained", "read"],
            ),
        ] {
            assert_failure_events(failure, events);
        }
    }

    #[test]
    fn mismatched_readbacks_fail_at_their_exact_stage() {
        for (failure, events) in [
            (
                Failure::RetainedMismatch,
                &["read", "write", "flush", "read_retained"][..],
            ),
            (
                Failure::RereadMismatch,
                &["read", "write", "flush", "read_retained", "read"],
            ),
        ] {
            assert_failure_events(failure, events);
        }
    }

    #[test]
    fn field_types_and_bounds_fail_before_registry_access() {
        let mut registry = MockRegistry::new(PolicyValueSnapshot::Missing, Failure::None);
        assert!(
            apply_with(
                &mut registry,
                WindowsUpdateField::ProductVersion,
                &PolicyValueSnapshot::Missing,
                &PolicyValueSnapshot::Dword(1)
            )
            .is_err()
        );
        assert!(
            apply_with(
                &mut registry,
                WindowsUpdateField::ProductVersion,
                &PolicyValueSnapshot::Missing,
                &PolicyValueSnapshot::String("Windows\0redirect".into())
            )
            .is_err()
        );
        assert!(
            apply_with(
                &mut registry,
                WindowsUpdateField::ProductVersion,
                &PolicyValueSnapshot::Missing,
                &PolicyValueSnapshot::String("x".repeat(MAX_POLICY_STRING_BYTES + 1))
            )
            .is_err()
        );
        assert!(
            apply_with(
                &mut registry,
                WindowsUpdateField::DeferQualityDays,
                &PolicyValueSnapshot::Missing,
                &PolicyValueSnapshot::Dword(36)
            )
            .is_err()
        );
        assert!(registry.events.is_empty());
    }

    #[test]
    fn observation_only_field_is_rejected_without_registry_access() {
        let mut registry = MockRegistry::new(PolicyValueSnapshot::Missing, Failure::None);
        assert!(
            apply_with(
                &mut registry,
                WindowsUpdateField::AllowMicrosoftUpdate,
                &PolicyValueSnapshot::Missing,
                &PolicyValueSnapshot::Dword(1)
            )
            .is_err()
        );
        assert!(registry.events.is_empty());
    }
}
