#![allow(unsafe_code)]

#[cfg(windows)]
use {
    super::native::Key,
    crate::{PlatformError, native_values::check_status},
    std::ffi::c_void,
    windows::Win32::Foundation::{
        HANDLE, NTSTATUS, RtlNtStatusToDosError, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL,
        WIN32_ERROR,
    },
};

#[cfg(windows)]
pub(super) const NATIVE_MACHINE_ROOT: &str = r"\REGISTRY\MACHINE";
#[cfg(windows)]
const KEY_NAME_INFORMATION_CLASS: i32 = 3;
#[cfg(windows)]
const KEY_NAME_HEADER_BYTES: usize = 4;
#[cfg(windows)]
const MAX_KEY_NAME_BYTES: usize = 1_024;

#[cfg(windows)]
#[link(name = "ntdll")]
unsafe extern "system" {
    #[link_name = "NtQueryKey"]
    fn nt_query_key(
        key_handle: HANDLE,
        information_class: i32,
        information: *mut c_void,
        length: u32,
        result_length: *mut u32,
    ) -> NTSTATUS;
}

#[cfg(windows)]
pub(super) fn verify_key_name(key: &Key, expected: &str) -> Result<(), PlatformError> {
    let actual = query_key_name(key)?;
    if registry_names_match(&actual, expected) {
        return Ok(());
    }
    Err(name_error(
        "opened registry handle resolved to an unexpected key",
    ))
}

#[cfg(windows)]
fn query_key_name(key: &Key) -> Result<String, PlatformError> {
    let required = required_name_bytes(key)?;
    let words = required.div_ceil(size_of::<u32>());
    let mut buffer = vec![0_u32; words];
    let mut returned = 0_u32;
    let status = unsafe {
        nt_query_key(
            HANDLE(key.raw().0),
            KEY_NAME_INFORMATION_CLASS,
            buffer.as_mut_ptr().cast(),
            u32::try_from(required).map_err(|_| invalid_name())?,
            &raw mut returned,
        )
    };
    check_nt_status(status)?;
    decode_key_name(&buffer, returned)
}

#[cfg(windows)]
fn required_name_bytes(key: &Key) -> Result<usize, PlatformError> {
    let mut required = 0_u32;
    let status = unsafe {
        nt_query_key(
            HANDLE(key.raw().0),
            KEY_NAME_INFORMATION_CLASS,
            std::ptr::null_mut(),
            0,
            &raw mut required,
        )
    };
    if status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW {
        check_nt_status(status)?;
    }
    let required = usize::try_from(required).map_err(|_| invalid_name())?;
    if !(KEY_NAME_HEADER_BYTES..=MAX_KEY_NAME_BYTES).contains(&required) {
        return Err(invalid_name());
    }
    Ok(required)
}

#[cfg(windows)]
fn decode_key_name(buffer: &[u32], returned: u32) -> Result<String, PlatformError> {
    let bytes = returned_buffer(buffer, returned)?;
    let name = name_bytes(bytes)?;
    decode_name_units(name)
}

#[cfg(windows)]
fn returned_buffer(buffer: &[u32], returned: u32) -> Result<&[u8], PlatformError> {
    let returned = usize::try_from(returned).map_err(|_| invalid_name())?;
    let bytes = unsafe {
        std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), std::mem::size_of_val(buffer))
    };
    if returned > bytes.len() {
        return Err(invalid_name());
    }
    Ok(&bytes[..returned])
}

#[cfg(windows)]
fn name_bytes(bytes: &[u8]) -> Result<&[u8], PlatformError> {
    let header = bytes
        .get(..KEY_NAME_HEADER_BYTES)
        .ok_or_else(invalid_name)?;
    let name_bytes = usize::try_from(u32::from_le_bytes(
        header.try_into().expect("key name header is four bytes"),
    ))
    .map_err(|_| invalid_name())?;
    let end = KEY_NAME_HEADER_BYTES
        .checked_add(name_bytes)
        .ok_or_else(invalid_name)?;
    if name_bytes % 2 != 0 || end > bytes.len() {
        return Err(invalid_name());
    }
    Ok(&bytes[KEY_NAME_HEADER_BYTES..end])
}

#[cfg(windows)]
fn decode_name_units(bytes: &[u8]) -> Result<String, PlatformError> {
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let value = String::from_utf16(&units).map_err(|_| invalid_name())?;
    if value.contains('\0') {
        return Err(invalid_name());
    }
    Ok(value)
}

#[cfg(windows)]
fn check_nt_status(status: NTSTATUS) -> Result<(), PlatformError> {
    if status.0 >= 0 {
        return Ok(());
    }
    check_status(WIN32_ERROR(unsafe { RtlNtStatusToDosError(status) }))
}

fn registry_names_match(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(expected)
}

#[cfg(windows)]
fn invalid_name() -> PlatformError {
    name_error("Windows returned an invalid registry handle name")
}

#[cfg(windows)]
fn name_error(reason: &str) -> PlatformError {
    PlatformError::TrustFailure(reason.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_name_policy_is_case_insensitive_but_exact() {
        let expected = r"\REGISTRY\MACHINE\SOFTWARE\Policies";
        assert!(registry_names_match(
            r"\Registry\Machine\Software\Policies",
            expected
        ));
        assert!(!registry_names_match(
            r"\REGISTRY\MACHINE\SOFTWARE\Elsewhere",
            expected
        ));
        assert!(!registry_names_match(
            r"\REGISTRY\MACHINE\SOFTWARE\Policies\Child",
            expected
        ));
    }
}
