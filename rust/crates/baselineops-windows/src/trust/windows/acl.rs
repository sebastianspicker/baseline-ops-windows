use super::handle_path::OpenedPath;
use crate::PlatformError;
use std::ffi::c_void;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetSecurityDescriptorControl, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED,
};
use windows::core::{PCWSTR, w};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const WRITE_OR_REPLACE_MASK: u32 = 0x000f_0176 | GENERIC_ALL | GENERIC_WRITE;

pub(super) struct TrustedSids {
    system: SidAllocation,
    administrators: SidAllocation,
    trusted_installer: SidAllocation,
}

impl TrustedSids {
    pub(super) fn new() -> Result<Self, PlatformError> {
        Ok(Self {
            system: SidAllocation::from_sddl(w!("S-1-5-18"))?,
            administrators: SidAllocation::from_sddl(w!("S-1-5-32-544"))?,
            trusted_installer: SidAllocation::from_text(TRUSTED_INSTALLER_SID)?,
        })
    }

    fn contains(&self, sid: PSID) -> bool {
        for trusted in [&self.system, &self.administrators, &self.trusted_installer] {
            if unsafe { EqualSid(sid, trusted.sid) }.is_ok() {
                return true;
            }
        }
        false
    }
}

struct SidAllocation {
    sid: PSID,
}

impl SidAllocation {
    fn from_sddl(value: PCWSTR) -> Result<Self, PlatformError> {
        let mut sid = PSID::default();
        unsafe {
            windows::Win32::Security::Authorization::ConvertStringSidToSidW(value, &raw mut sid)
        }
        .map_err(|error| {
            PlatformError::TrustFailure(format!("could not build trusted SID: {error}"))
        })?;
        if sid.is_invalid() {
            return Err(PlatformError::TrustFailure(
                "trusted SID allocation was null".into(),
            ));
        }
        Ok(Self { sid })
    }

    fn from_text(value: &str) -> Result<Self, PlatformError> {
        let mut wide: Vec<u16> = value.encode_utf16().collect();
        wide.push(0);
        Self::from_sddl(PCWSTR(wide.as_ptr()))
    }
}

impl Drop for SidAllocation {
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(Some(HLOCAL(self.sid.0))) };
    }
}

pub(super) fn verify_object_acl(
    object: &OpenedPath,
    trusted_sids: &TrustedSids,
    require_protected_dacl: bool,
) -> Result<(), PlatformError> {
    let descriptor = SecurityDescriptor::for_handle(object.handle())?;
    if !trusted_sids.contains(descriptor.owner) {
        return Err(trust_error(
            "protected path owner is not SYSTEM, Administrators, or TrustedInstaller",
        ));
    }
    if require_protected_dacl && !descriptor.dacl_protected()? {
        return Err(trust_error(
            "protected root DACL is not protected from inheritance",
        ));
    }
    descriptor.reject_untrusted_writers(trusted_sids)
}

struct SecurityDescriptor {
    owner: PSID,
    dacl: *mut windows::Win32::Security::ACL,
    descriptor: PSECURITY_DESCRIPTOR,
}

impl SecurityDescriptor {
    fn for_handle(handle: windows::Win32::Foundation::HANDLE) -> Result<Self, PlatformError> {
        let mut owner = PSID::default();
        let mut dacl = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&raw mut owner),
                None,
                Some(&raw mut dacl),
                None,
                Some(&raw mut descriptor),
            )
        };
        if status.0 != 0 || owner.is_invalid() || dacl.is_null() || descriptor.is_invalid() {
            return Err(trust_error("could not obtain an explicit owner and DACL"));
        }
        Ok(Self {
            owner,
            dacl,
            descriptor,
        })
    }

    fn dacl_protected(&self) -> Result<bool, PlatformError> {
        let mut control = 0_u16;
        let mut revision = 0_u32;
        unsafe {
            GetSecurityDescriptorControl(self.descriptor, &raw mut control, &raw mut revision)
        }
        .map_err(|error| trust_error(&format!("could not read DACL control: {error}")))?;
        Ok(control & SE_DACL_PROTECTED.0 != 0)
    }

    fn reject_untrusted_writers(&self, trusted_sids: &TrustedSids) -> Result<(), PlatformError> {
        let count = unsafe { (*self.dacl).AceCount };
        for index in 0..u32::from(count) {
            let mut raw_ace = std::ptr::null_mut();
            unsafe { GetAce(self.dacl, index, &raw mut raw_ace) }
                .map_err(|error| trust_error(&format!("could not inspect DACL ACE: {error}")))?;
            let header = unsafe { &*(raw_ace.cast::<ACE_HEADER>()) };
            match header.AceType {
                ACCESS_DENIED_ACE_TYPE => {}
                ACCESS_ALLOWED_ACE_TYPE => {
                    let allowed = unsafe { &*(raw_ace.cast::<ACCESS_ALLOWED_ACE>()) };
                    if allowed.Mask & WRITE_OR_REPLACE_MASK != 0 {
                        let sid = PSID((&raw const allowed.SidStart).cast_mut().cast::<c_void>());
                        if !trusted_sids.contains(sid) {
                            return Err(trust_error(
                                "DACL grants write or replacement rights to an untrusted SID",
                            ));
                        }
                    }
                }
                _ => {
                    return Err(trust_error(
                        "DACL contains an unsupported ACE type; cannot prove writer policy",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(Some(HLOCAL(self.descriptor.0))) };
    }
}

fn trust_error(reason: &str) -> PlatformError {
    PlatformError::TrustFailure(reason.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_mask_covers_content_and_security_descriptor_replacement() {
        assert_ne!(WRITE_OR_REPLACE_MASK & 0x0000_0002, 0);
        assert_ne!(WRITE_OR_REPLACE_MASK & 0x0001_0000, 0);
        assert_ne!(WRITE_OR_REPLACE_MASK & 0x0004_0000, 0);
        assert_ne!(WRITE_OR_REPLACE_MASK & 0x0008_0000, 0);
        assert_ne!(WRITE_OR_REPLACE_MASK & GENERIC_WRITE, 0);
        assert_ne!(WRITE_OR_REPLACE_MASK & GENERIC_ALL, 0);
    }

    #[test]
    fn trustedinstaller_sid_is_fixed_service_identity() {
        assert!(TRUSTED_INSTALLER_SID.starts_with("S-1-5-80-"));
    }
}
