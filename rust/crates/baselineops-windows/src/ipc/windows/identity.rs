use super::transfer::native_error;
use crate::PlatformError;
use crate::ipc::{PeerIdentity, validation::valid_sid_text};
use std::ffi::{OsStr, c_void};
use std::os::windows::ffi::OsStrExt;

pub(super) struct SecurityDescriptor(*mut c_void);

impl SecurityDescriptor {
    pub(super) fn for_client_logon_sid(logon_sid: &str) -> Result<Self, PlatformError> {
        if !valid_sid_text(logon_sid) {
            return Err(PlatformError::ProtocolRejected(
                "logon SID is invalid".into(),
            ));
        }
        let sddl = format!("D:P(A;;GRGW;;;{logon_sid})(A;;GRGW;;;SY)(A;;GRGW;;;BA)");
        let text = OsStr::new(&sddl)
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut descriptor = std::ptr::null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &raw mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if converted == 0 || descriptor.is_null() {
            return Err(last_error(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            ));
        }
        Ok(Self(descriptor))
    }

    pub(super) const fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let _ = unsafe { LocalFree(self.0) };
        }
    }
}

pub(super) fn pipe_name(name: &str) -> Result<Vec<u16>, PlatformError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(PlatformError::ProtocolRejected(
            "pipe name is outside the BaselineOps namespace".into(),
        ));
    }
    Ok(OsStr::new(&format!("\\\\.\\pipe\\BaselineOps-{name}"))
        .encode_wide()
        .chain(Some(0))
        .collect())
}

pub(super) fn pipe_peer_identity(pipe: isize, client: bool) -> Result<PeerIdentity, PlatformError> {
    let mut process_id = 0_u32;
    let result = unsafe {
        if client {
            GetNamedPipeClientProcessId(pipe, &raw mut process_id)
        } else {
            GetNamedPipeServerProcessId(pipe, &raw mut process_id)
        }
    };
    if result == 0 || process_id == 0 {
        let operation = if client {
            "GetNamedPipeClientProcessId"
        } else {
            "GetNamedPipeServerProcessId"
        };
        return Err(last_error(operation));
    }
    let mut session_id = 0_u32;
    if unsafe { ProcessIdToSessionId(process_id, &raw mut session_id) } == 0 {
        return Err(last_error("ProcessIdToSessionId"));
    }
    Ok(PeerIdentity {
        process_id,
        session_id,
        user_sid: String::new(),
        integrity_rid: 0,
        image_path: String::new(),
    })
}

fn last_error(operation: &str) -> PlatformError {
    native_error(operation, unsafe { GetLastError() })
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLastError() -> u32;
    fn GetNamedPipeClientProcessId(pipe: isize, process_id: *mut u32) -> i32;
    fn GetNamedPipeServerProcessId(pipe: isize, process_id: *mut u32) -> i32;
    fn ProcessIdToSessionId(process_id: u32, session_id: *mut u32) -> i32;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        descriptor_size: *mut u32,
    ) -> i32;
}
