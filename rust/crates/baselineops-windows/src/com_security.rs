//! Fixed COM security initialization for read-only WMI adapters.

#![allow(unsafe_code)]

use windows::Win32::Foundation::RPC_E_TOO_LATE;
use windows::Win32::System::Com::{
    CoInitializeSecurity, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
};

/// Initialize the existing fixed security settings on a COM-initialized thread.
/// The caller retains apartment lifetime and capability-specific error mapping.
pub(crate) unsafe fn initialize_wmi_security() -> windows::core::Result<()> {
    // SAFETY: the caller initialized COM; all security parameters are fixed and
    // no caller-provided namespace, query, identity, or permission is accepted.
    let result = unsafe {
        CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        )
    };
    match result {
        Err(error) if error.code() == RPC_E_TOO_LATE => Ok(()),
        result => result,
    }
}
