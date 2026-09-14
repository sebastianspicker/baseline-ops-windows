#![allow(unsafe_code)]

#[cfg(windows)]
use {
    crate::{PlatformError, native_values::check_status},
    std::ffi::c_void,
    windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree},
    windows::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GetExplicitEntriesFromAclW, GetSecurityInfo, SE_REGISTRY_KEY,
    },
    windows::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, IsValidSecurityDescriptor, IsValidSid,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    },
    windows::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE},
    windows::core::PCWSTR,
};

const KEY_SET_VALUE: u32 = 0x0000_0002;
const KEY_CREATE_SUB_KEY: u32 = 0x0000_0004;
const KEY_CREATE_LINK: u32 = 0x0000_0020;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const MUTATION_RIGHTS: u32 = KEY_SET_VALUE
    | KEY_CREATE_SUB_KEY
    | KEY_CREATE_LINK
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;
#[cfg(windows)]
const MAX_EXPLICIT_ENTRIES: usize = 1_024;
const TRUSTED_SIDS: [&str; 3] = [
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryMode {
    Allow,
    Deny,
    Unsupported,
}

#[cfg(windows)]
pub(super) fn verify_hive_root() -> Result<(), PlatformError> {
    verify_key_security(HKEY_LOCAL_MACHINE)
}

#[cfg(windows)]
pub(super) fn verify_key(key: &super::native::Key) -> Result<(), PlatformError> {
    verify_key_security(key.raw())
}

#[cfg(windows)]
fn verify_key_security(key: HKEY) -> Result<(), PlatformError> {
    let descriptor = KeySecurity::read(key)?;
    if !sid_is_trusted(descriptor.owner)? {
        return Err(security_error(
            "registry key owner is not SYSTEM, Administrators, or TrustedInstaller",
        ));
    }
    reject_untrusted_writers(descriptor.dacl)
}

#[cfg(windows)]
struct KeySecurity {
    owner: PSID,
    dacl: *mut ACL,
    _allocation: LocalAllocation,
}

#[cfg(windows)]
impl KeySecurity {
    fn read(key: HKEY) -> Result<Self, PlatformError> {
        let mut owner = PSID::default();
        let mut dacl = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let status = unsafe {
            GetSecurityInfo(
                HANDLE(key.0),
                SE_REGISTRY_KEY,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&raw mut owner),
                None,
                Some(&raw mut dacl),
                None,
                Some(&raw mut descriptor),
            )
        };
        check_status(status)?;
        let allocation = LocalAllocation(descriptor.0);
        validate_descriptor(owner, dacl, descriptor)?;
        Ok(Self {
            owner,
            dacl,
            _allocation: allocation,
        })
    }
}

#[cfg(windows)]
fn validate_descriptor(
    owner: PSID,
    dacl: *mut ACL,
    descriptor: PSECURITY_DESCRIPTOR,
) -> Result<(), PlatformError> {
    if descriptor.is_invalid() || owner.is_invalid() || dacl.is_null() {
        return Err(security_error(
            "registry key has no explicit owner or discretionary ACL",
        ));
    }
    if !unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool() {
        return Err(security_error(
            "Windows returned an invalid registry security descriptor",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn reject_untrusted_writers(dacl: *mut ACL) -> Result<(), PlatformError> {
    let entries = ExplicitEntries::read(dacl)?;
    for entry in entries.as_slice() {
        verify_entry(entry)?;
    }
    Ok(())
}

#[cfg(windows)]
struct ExplicitEntries {
    entries: *mut EXPLICIT_ACCESS_W,
    count: usize,
    _allocation: LocalAllocation,
}

#[cfg(windows)]
impl ExplicitEntries {
    fn read(dacl: *mut ACL) -> Result<Self, PlatformError> {
        let mut count = 0_u32;
        let mut entries = std::ptr::null_mut();
        check_status(unsafe {
            GetExplicitEntriesFromAclW(dacl, &raw mut count, &raw mut entries)
        })?;
        let allocation = LocalAllocation(entries.cast());
        let count = usize::try_from(count).map_err(|_| invalid_entries())?;
        if count > MAX_EXPLICIT_ENTRIES {
            return Err(invalid_entries());
        }
        if count == 0 {
            return Ok(Self {
                entries,
                count,
                _allocation: allocation,
            });
        }
        if entries.is_null() {
            return Err(invalid_entries());
        }
        Ok(Self {
            entries,
            count,
            _allocation: allocation,
        })
    }

    fn as_slice(&self) -> &[EXPLICIT_ACCESS_W] {
        if self.count == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.entries, self.count) }
    }
}

#[cfg(windows)]
fn verify_entry(entry: &EXPLICIT_ACCESS_W) -> Result<(), PlatformError> {
    let mode = entry_mode(entry.grfAccessMode.0);
    // Treat INHERIT_ONLY grants as effective here. This can reject a safe ancestor,
    // but never lets a writable descendant pass without its own independent check.
    let trusted = if mode == EntryMode::Allow && has_mutation_rights(entry.grfAccessPermissions) {
        Some(entry_sid_is_trusted(entry)?)
    } else {
        None
    };
    enforce_entry_policy(mode, entry.grfAccessPermissions, trusted).map_err(security_error)
}

#[cfg(windows)]
fn entry_sid_is_trusted(
    entry: &windows::Win32::Security::Authorization::EXPLICIT_ACCESS_W,
) -> Result<bool, PlatformError> {
    let trustee = &entry.Trustee;
    if !trustee.pMultipleTrustee.is_null()
        || trustee.TrusteeForm != windows::Win32::Security::Authorization::TRUSTEE_IS_SID
        || trustee.ptstrName.is_null()
    {
        return Err(security_error(
            "registry DACL has an unsupported mutating trustee",
        ));
    }
    sid_is_trusted(PSID(trustee.ptstrName.0.cast()))
}

#[cfg(windows)]
fn sid_is_trusted(sid: PSID) -> Result<bool, PlatformError> {
    if !unsafe { IsValidSid(sid) }.as_bool() {
        return Err(security_error(
            "registry security descriptor has an invalid SID",
        ));
    }
    let mut text = windows::core::PWSTR::null();
    unsafe { windows::Win32::Security::Authorization::ConvertSidToStringSidW(sid, &raw mut text) }
        .map_err(|error| security_error(&format!("could not read registry SID: {error}")))?;
    let allocation = LocalAllocation(text.0.cast());
    if text.is_null() {
        return Err(security_error(
            "Windows returned a null registry SID string",
        ));
    }
    let text = unsafe { PCWSTR(text.0).to_string() }
        .map_err(|error| security_error(&format!("registry SID text is invalid: {error}")))?;
    drop(allocation);
    Ok(sid_text_is_trusted(&text))
}

fn sid_text_is_trusted(value: &str) -> bool {
    TRUSTED_SIDS.contains(&value)
}

fn entry_mode(mode: i32) -> EntryMode {
    match mode {
        1 => EntryMode::Allow,
        3 => EntryMode::Deny,
        _ => EntryMode::Unsupported,
    }
}

fn has_mutation_rights(mask: u32) -> bool {
    mask & MUTATION_RIGHTS != 0
}

fn enforce_entry_policy(
    mode: EntryMode,
    mask: u32,
    trustee_is_trusted: Option<bool>,
) -> Result<(), &'static str> {
    if mode == EntryMode::Unsupported {
        return Err("registry DACL contains an unsupported access mode");
    }
    if mode == EntryMode::Deny || !has_mutation_rights(mask) {
        return Ok(());
    }
    if trustee_is_trusted == Some(true) {
        return Ok(());
    }
    Err("registry DACL grants mutation rights to an untrusted trustee")
}

#[cfg(windows)]
struct LocalAllocation(*mut c_void);

#[cfg(windows)]
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0))) };
        }
    }
}

#[cfg(windows)]
fn invalid_entries() -> PlatformError {
    security_error("Windows returned an invalid registry DACL entry list")
}

#[cfg(windows)]
fn security_error(reason: &str) -> PlatformError {
    PlatformError::TrustFailure(reason.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_mask_covers_registry_content_replacement_and_security() {
        for right in [
            KEY_SET_VALUE,
            KEY_CREATE_SUB_KEY,
            KEY_CREATE_LINK,
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
            GENERIC_WRITE,
            GENERIC_ALL,
        ] {
            assert!(has_mutation_rights(right));
        }
        for right in [0x0000_0001, 0x0000_0008, 0x0000_0010, 0x0002_0000] {
            assert!(!has_mutation_rights(right));
        }
    }

    #[test]
    fn only_trusted_allow_entries_may_hold_mutation_rights() {
        assert!(enforce_entry_policy(EntryMode::Deny, GENERIC_ALL, None).is_ok());
        assert!(enforce_entry_policy(EntryMode::Allow, 0x0002_0000, None).is_ok());
        assert!(enforce_entry_policy(EntryMode::Allow, KEY_SET_VALUE, Some(true)).is_ok());
        assert!(enforce_entry_policy(EntryMode::Allow, KEY_SET_VALUE, Some(false)).is_err());
        assert!(enforce_entry_policy(EntryMode::Allow, KEY_SET_VALUE, None).is_err());
        assert!(enforce_entry_policy(EntryMode::Unsupported, 0, None).is_err());
    }

    #[test]
    fn access_modes_are_classified_fail_closed() {
        assert_eq!(entry_mode(1), EntryMode::Allow);
        assert_eq!(entry_mode(3), EntryMode::Deny);
        assert_eq!(entry_mode(2), EntryMode::Unsupported);
    }

    #[test]
    fn owner_policy_accepts_only_the_three_fixed_privileged_sids() {
        for sid in TRUSTED_SIDS {
            assert!(sid_text_is_trusted(sid));
        }
        assert!(!sid_text_is_trusted("S-1-5-11"));
        assert!(!sid_text_is_trusted("S-1-5-32-545"));
    }
}
