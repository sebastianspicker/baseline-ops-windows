#![allow(unsafe_code)]

use super::{
    FieldSpec, MAX_POLICY_STRING_BYTES, ValueKind, mutation, registry_name, registry_security,
};
use crate::{PlatformError, native_values::check_status};
use baselineops_capabilities::PolicyValueSnapshot;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, WIN32_ERROR};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD,
    REG_OPTION_OPEN_LINK, REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegDeleteValueW,
    RegFlushKey, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};
use windows::core::PCWSTR;

#[derive(Default)]
pub(super) struct NativeRegistry {
    pending: Option<KeyPath>,
}

impl mutation::RegistryReader for NativeRegistry {
    fn read(&mut self, spec: &FieldSpec) -> Result<PolicyValueSnapshot, PlatformError> {
        read_snapshot(spec)
    }
}

impl mutation::RegistryWriter for NativeRegistry {
    fn write(
        &mut self,
        spec: &FieldSpec,
        expected: &PolicyValueSnapshot,
        desired: &PolicyValueSnapshot,
    ) -> Result<(), PlatformError> {
        let path = open_mutation_path(spec)?;
        path.verify_controls()?;
        if read_leaf(&path, spec)? != *expected {
            return Err(mutation::stale_state());
        }
        write_leaf(&path, spec, desired)?;
        self.pending = Some(path);
        Ok(())
    }
}

impl mutation::RegistryFlusher for NativeRegistry {
    fn flush_and_read_retained(
        &mut self,
        spec: &FieldSpec,
    ) -> Result<PolicyValueSnapshot, PlatformError> {
        let path = self.pending.as_ref().ok_or_else(|| {
            PlatformError::TrustFailure("Windows Update mutation has no pending key".into())
        })?;
        check_status(unsafe { RegFlushKey(path.leaf().raw) })?;
        path.verify_controls()?;
        let snapshot = read_leaf(path, spec)?;
        let _ = self.pending.take();
        Ok(snapshot)
    }
}

fn read_snapshot(spec: &FieldSpec) -> Result<PolicyValueSnapshot, PlatformError> {
    let Some(path) = open_existing_path(spec, false)? else {
        return Ok(PolicyValueSnapshot::Missing);
    };
    read_leaf(&path, spec)
}

fn open_mutation_path(spec: &FieldSpec) -> Result<KeyPath, PlatformError> {
    if let Some(path) = open_existing_path(spec, true)? {
        return Ok(path);
    }
    Err(PlatformError::TrustFailure(
        "fixed Windows Update registry key is missing; key creation refused".into(),
    ))
}

fn open_existing_path(spec: &FieldSpec, writable: bool) -> Result<Option<KeyPath>, PlatformError> {
    let segments = path_segments(spec.path)?;
    registry_security::verify_hive_root()?;
    let mut handles = Vec::with_capacity(segments.len());
    let mut expected_name = String::from(registry_name::NATIVE_MACHINE_ROOT);
    for (index, segment) in segments.iter().enumerate() {
        let parent = handles
            .last()
            .map_or(HKEY_LOCAL_MACHINE, |key: &Key| key.raw);
        let final_segment = index + 1 == segments.len();
        let access = segment_access(final_segment, writable);
        expected_name.push('\\');
        expected_name.push_str(segment);
        let Some(key) = open_segment(parent, segment, access, expected_name.clone())? else {
            return Ok(None);
        };
        key.verify_controls()?;
        handles.push(key);
    }
    Ok(Some(KeyPath { handles }))
}

fn segment_access(
    final_segment: bool,
    writable: bool,
) -> windows::Win32::System::Registry::REG_SAM_FLAGS {
    const READ_CONTROL_ACCESS: REG_SAM_FLAGS = REG_SAM_FLAGS(0x0002_0000);
    let mut access = KEY_QUERY_VALUE | READ_CONTROL_ACCESS;
    if !final_segment {
        access |= KEY_ENUMERATE_SUB_KEYS;
    } else if writable {
        access |= KEY_SET_VALUE;
    }
    access
}

fn open_segment(
    parent: HKEY,
    segment: &str,
    access: windows::Win32::System::Registry::REG_SAM_FLAGS,
    expected_name: String,
) -> Result<Option<Key>, PlatformError> {
    let segment = wide(segment);
    let mut raw = HKEY::default();
    let status = unsafe {
        RegOpenKeyExW(
            parent,
            PCWSTR(segment.as_ptr()),
            Some(REG_OPTION_OPEN_LINK.0),
            access,
            &raw mut raw,
        )
    };
    if missing(status) {
        return Ok(None);
    }
    check_status(status)?;
    Ok(Some(Key { raw, expected_name }))
}

fn reject_symbolic_link(key: &Key) -> Result<(), PlatformError> {
    let link_name = wide("SymbolicLinkValue");
    let status =
        unsafe { RegQueryValueExW(key.raw, PCWSTR(link_name.as_ptr()), None, None, None, None) };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    check_status(status)?;
    Err(PlatformError::TrustFailure(
        "Windows Update registry path contains a symbolic-link marker".into(),
    ))
}

fn read_leaf(path: &KeyPath, spec: &FieldSpec) -> Result<PolicyValueSnapshot, PlatformError> {
    let name = wide(spec.name);
    let mut kind = REG_VALUE_TYPE::default();
    let mut size = 0_u32;
    let status = unsafe {
        RegQueryValueExW(
            path.leaf().raw,
            PCWSTR(name.as_ptr()),
            None,
            Some(&raw mut kind),
            None,
            Some(&raw mut size),
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(PolicyValueSnapshot::Missing);
    }
    check_status(status)?;
    let mut bytes = bounded_buffer(spec.kind, size)?;
    check_status(unsafe {
        RegQueryValueExW(
            path.leaf().raw,
            PCWSTR(name.as_ptr()),
            None,
            Some(&raw mut kind),
            Some(bytes.as_mut_ptr()),
            Some(&raw mut size),
        )
    })?;
    bytes.truncate(usize::try_from(size).map_err(|_| invalid_registry_value())?);
    decode_value(spec.kind, kind, &bytes)
}

fn bounded_buffer(kind: ValueKind, size: u32) -> Result<Vec<u8>, PlatformError> {
    let maximum = match kind {
        ValueKind::Dword => 4,
        ValueKind::String => (MAX_POLICY_STRING_BYTES + 1) * 2,
    };
    let size = usize::try_from(size).map_err(|_| invalid_registry_value())?;
    if size > maximum {
        return Err(invalid_registry_value());
    }
    Ok(vec![0; size])
}

fn decode_value(
    expected: ValueKind,
    actual: REG_VALUE_TYPE,
    bytes: &[u8],
) -> Result<PolicyValueSnapshot, PlatformError> {
    match expected {
        ValueKind::Dword if actual == REG_DWORD && bytes.len() == 4 => Ok(
            PolicyValueSnapshot::Dword(u32::from_le_bytes(bytes.try_into().expect("four bytes"))),
        ),
        ValueKind::String if actual == REG_SZ => decode_string(bytes),
        ValueKind::Dword | ValueKind::String => Err(invalid_registry_value()),
    }
}

fn decode_string(bytes: &[u8]) -> Result<PolicyValueSnapshot, PlatformError> {
    validate_utf16_bytes(bytes)?;
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        units.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    validate_utf16_terminator(&mut units)?;
    let value = String::from_utf16(&units).map_err(|_| invalid_registry_value())?;
    validate_string_size(&value)?;
    Ok(PolicyValueSnapshot::String(value))
}

fn validate_utf16_bytes(bytes: &[u8]) -> Result<(), PlatformError> {
    if bytes.is_empty() {
        return Err(invalid_registry_value());
    }
    if !bytes.len().is_multiple_of(2) {
        return Err(invalid_registry_value());
    }
    Ok(())
}

fn validate_utf16_terminator(units: &mut Vec<u16>) -> Result<(), PlatformError> {
    if units.pop() != Some(0) {
        return Err(invalid_registry_value());
    }
    if units.contains(&0) {
        return Err(invalid_registry_value());
    }
    Ok(())
}

fn validate_string_size(value: &str) -> Result<(), PlatformError> {
    if value.len() > MAX_POLICY_STRING_BYTES {
        return Err(invalid_registry_value());
    }
    Ok(())
}

fn write_leaf(
    path: &KeyPath,
    spec: &FieldSpec,
    desired: &PolicyValueSnapshot,
) -> Result<(), PlatformError> {
    let name = wide(spec.name);
    let status = match desired {
        PolicyValueSnapshot::Missing => unsafe {
            RegDeleteValueW(path.leaf().raw, PCWSTR(name.as_ptr()))
        },
        PolicyValueSnapshot::Dword(value) => unsafe {
            RegSetValueExW(
                path.leaf().raw,
                PCWSTR(name.as_ptr()),
                None,
                REG_DWORD,
                Some(&value.to_le_bytes()),
            )
        },
        PolicyValueSnapshot::String(value) => {
            let bytes = encode_string(value);
            unsafe {
                RegSetValueExW(
                    path.leaf().raw,
                    PCWSTR(name.as_ptr()),
                    None,
                    REG_SZ,
                    Some(&bytes),
                )
            }
        }
    };
    check_status(status)
}

fn encode_string(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn path_segments(path: &'static str) -> Result<Vec<&'static str>, PlatformError> {
    let segments = path.split('\\').collect::<Vec<_>>();
    if segments.is_empty() || segments.len() > 16 || segments.iter().any(|part| part.is_empty()) {
        return Err(invalid_fixed_path());
    }
    Ok(segments)
}

fn missing(status: WIN32_ERROR) -> bool {
    status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND
}

fn invalid_fixed_path() -> PlatformError {
    PlatformError::TrustFailure("fixed Windows Update registry path is invalid".into())
}

fn invalid_registry_value() -> PlatformError {
    PlatformError::TrustFailure("Windows Update registry value has an invalid type or size".into())
}

pub(super) struct Key {
    raw: HKEY,
    expected_name: String,
}

impl Key {
    pub(super) fn raw(&self) -> HKEY {
        self.raw
    }

    fn verify_controls(&self) -> Result<(), PlatformError> {
        reject_symbolic_link(self)?;
        registry_name::verify_key_name(self, &self.expected_name)?;
        registry_security::verify_key(self)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.raw);
        }
    }
}

struct KeyPath {
    handles: Vec<Key>,
}

impl KeyPath {
    fn leaf(&self) -> &Key {
        self.handles
            .last()
            .expect("a verified registry path always retains its leaf")
    }

    fn verify_controls(&self) -> Result<(), PlatformError> {
        registry_security::verify_hive_root()?;
        for handle in &self.handles {
            handle.verify_controls()?;
        }
        Ok(())
    }
}
