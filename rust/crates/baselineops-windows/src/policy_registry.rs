//! Private bounded registry reader shared by the Office and `WUfB` adapters.
//!
//! Paths and value names enter only as compile-time constants in sibling
//! adapters. This module has no public raw-registry API and no mutation API.

use crate::PlatformError;
use baselineops_capabilities::{Observation, PolicyValueSnapshot};

pub(crate) fn read_dword(
    path: &'static str,
    name: &'static str,
) -> Result<PolicyValueSnapshot, PlatformError> {
    platform::read(path, name, true)
}
pub(crate) fn read_string(
    path: &'static str,
    name: &'static str,
) -> Result<PolicyValueSnapshot, PlatformError> {
    platform::read(path, name, false)
}
pub(crate) fn read_hkcu_dword(
    path: &'static str,
    name: &'static str,
) -> Result<PolicyValueSnapshot, PlatformError> {
    platform::read_hkcu(path, name, true)
}

pub(crate) fn subkeys_hklm(
    path: &'static str,
    max_subkeys: u32,
) -> Result<Observation<Vec<String>>, PlatformError> {
    if max_subkeys == 0 || max_subkeys > 4096 {
        return Err(PlatformError::TrustFailure(
            "registry subkey bound is outside the internal policy".into(),
        ));
    }
    platform::subkeys_hklm(path, max_subkeys)
}

#[cfg(not(windows))]
mod platform {
    use super::{Observation, PlatformError, PolicyValueSnapshot};
    pub(super) fn read(
        _: &'static str,
        _: &'static str,
        _: bool,
    ) -> Result<PolicyValueSnapshot, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
    pub(super) fn read_hkcu(
        _: &'static str,
        _: &'static str,
        _: bool,
    ) -> Result<PolicyValueSnapshot, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
    pub(super) fn subkeys_hklm(
        _: &'static str,
        _: u32,
    ) -> Result<Observation<Vec<String>>, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]
    use super::{Observation, PlatformError, PolicyValueSnapshot};
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS,
    };
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_SZ, REG_VALUE_TYPE,
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW,
    };
    use windows::core::{PCWSTR, PWSTR};
    const MAX_BYTES: u32 = 512;
    pub(super) fn read(
        path: &'static str,
        name: &'static str,
        dword: bool,
    ) -> Result<PolicyValueSnapshot, PlatformError> {
        read_from(HKEY_LOCAL_MACHINE, path, name, dword)
    }
    pub(super) fn read_hkcu(
        path: &'static str,
        name: &'static str,
        dword: bool,
    ) -> Result<PolicyValueSnapshot, PlatformError> {
        read_from(HKEY_CURRENT_USER, path, name, dword)
    }
    pub(super) fn subkeys_hklm(
        path: &'static str,
        max_subkeys: u32,
    ) -> Result<Observation<Vec<String>>, PlatformError> {
        unsafe {
            let path = wide(path);
            let mut raw = HKEY::default();
            let status = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(path.as_ptr()),
                None,
                KEY_READ,
                &raw mut raw,
            );
            if status == ERROR_FILE_NOT_FOUND {
                return Ok(Observation::Missing);
            }
            if status == ERROR_ACCESS_DENIED {
                return Ok(Observation::AccessDenied);
            }
            status_ok(status)?;
            enumerate_subkeys(&Key(raw), max_subkeys)
        }
    }

    unsafe fn enumerate_subkeys(
        key: &Key,
        max_subkeys: u32,
    ) -> Result<Observation<Vec<String>>, PlatformError> {
        let mut values = Vec::new();
        for index in 0..=max_subkeys {
            match subkey_name(key, index)? {
                SubkeyRead::Name(value) if index < max_subkeys => values.push(value),
                SubkeyRead::Name(_) | SubkeyRead::Truncated => return Ok(Observation::Truncated),
                SubkeyRead::Complete => return Ok(Observation::Present(values)),
                SubkeyRead::AccessDenied => return Ok(Observation::AccessDenied),
            }
        }
        Ok(Observation::Truncated)
    }

    enum SubkeyRead {
        Name(String),
        Complete,
        Truncated,
        AccessDenied,
    }

    unsafe fn subkey_name(key: &Key, index: u32) -> Result<SubkeyRead, PlatformError> {
        let mut name = vec![0_u16; 512];
        let mut length = u32::try_from(name.len()).expect("bounded key name buffer");
        let status = RegEnumKeyExW(
            key.0,
            index,
            Some(PWSTR(name.as_mut_ptr())),
            &raw mut length,
            None,
            None,
            None,
            None,
        );
        if status == ERROR_NO_MORE_ITEMS {
            return Ok(SubkeyRead::Complete);
        }
        if status == ERROR_MORE_DATA {
            return Ok(SubkeyRead::Truncated);
        }
        if status == ERROR_ACCESS_DENIED {
            return Ok(SubkeyRead::AccessDenied);
        }
        status_ok(status)?;
        name.truncate(
            usize::try_from(length).map_err(|_| {
                PlatformError::TrustFailure("registry subkey length overflow".into())
            })?,
        );
        String::from_utf16(&name)
            .map(SubkeyRead::Name)
            .map_err(|_| PlatformError::TrustFailure("registry subkey is not valid UTF-16".into()))
    }
    fn read_from(
        root: HKEY,
        path: &'static str,
        name: &'static str,
        dword: bool,
    ) -> Result<PolicyValueSnapshot, PlatformError> {
        unsafe {
            read_policy_bytes(root, path, name)?
                .map_or(Ok(PolicyValueSnapshot::Missing), |(kind, bytes)| {
                    decode_policy_value(kind, bytes, dword)
                })
        }
    }

    unsafe fn read_policy_bytes(
        root: HKEY,
        path: &'static str,
        name: &'static str,
    ) -> Result<Option<(REG_VALUE_TYPE, Vec<u8>)>, PlatformError> {
        let Some(key) = policy_key(root, path)? else {
            return Ok(None);
        };
        read_policy_value(&key, name)
    }

    unsafe fn policy_key(root: HKEY, path: &'static str) -> Result<Option<Key>, PlatformError> {
        let path = wide(path);
        let mut raw = HKEY::default();
        let status = RegOpenKeyExW(root, PCWSTR(path.as_ptr()), None, KEY_READ, &raw mut raw);
        if status == ERROR_FILE_NOT_FOUND {
            Ok(None)
        } else {
            status_ok(status)?;
            Ok(Some(Key(raw)))
        }
    }

    unsafe fn read_policy_value(
        key: &Key,
        name: &'static str,
    ) -> Result<Option<(REG_VALUE_TYPE, Vec<u8>)>, PlatformError> {
        let name = wide(name);
        let mut kind = REG_VALUE_TYPE::default();
        let mut size = 0_u32;
        let status = RegQueryValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            Some(&raw mut kind),
            None,
            Some(&raw mut size),
        );
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        status_ok(status)?;
        if size > MAX_BYTES {
            return Err(PlatformError::TrustFailure(
                "policy registry value exceeds the bounded reader limit".into(),
            ));
        }
        let mut bytes = vec![
            0;
            usize::try_from(size).map_err(|_| PlatformError::TrustFailure(
                "registry length overflow".into()
            ))?
        ];
        status_ok(RegQueryValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            Some(&raw mut kind),
            Some(bytes.as_mut_ptr()),
            Some(&raw mut size),
        ))?;
        bytes.truncate(
            usize::try_from(size)
                .map_err(|_| PlatformError::TrustFailure("registry length overflow".into()))?,
        );
        Ok(Some((kind, bytes)))
    }

    fn decode_policy_value(
        kind: REG_VALUE_TYPE,
        bytes: Vec<u8>,
        dword: bool,
    ) -> Result<PolicyValueSnapshot, PlatformError> {
        if dword {
            return if kind == REG_DWORD && bytes.len() == 4 {
                Ok(PolicyValueSnapshot::Dword(u32::from_le_bytes(
                    bytes.try_into().expect("four bytes"),
                )))
            } else {
                Err(PlatformError::TrustFailure(
                    "policy registry value has an unexpected type".into(),
                ))
            };
        }
        if kind != REG_SZ || !bytes.len().is_multiple_of(2) {
            return Err(PlatformError::TrustFailure(
                "policy registry value has an unexpected type".into(),
            ));
        }
        let units = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let end = units
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(units.len());
        String::from_utf16(&units[..end])
            .map(PolicyValueSnapshot::String)
            .map_err(|error| PlatformError::TrustFailure(error.to_string()))
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
    use crate::native_values::check_status as status_ok;

    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
}
