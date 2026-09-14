//! Value-only Win32 status and service configuration conversions.

use crate::PlatformError;
use baselineops_capabilities::ServiceStartMode;
use windows::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Services::{
    SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_DISABLED,
};

pub(crate) fn check_status(status: WIN32_ERROR) -> Result<(), PlatformError> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(PlatformError::Io(std::io::Error::from_raw_os_error(
            i32::try_from(status.0).unwrap_or(i32::MAX),
        )))
    }
}

pub(crate) fn service_start_mode(value: u32) -> ServiceStartMode {
    if value == SERVICE_AUTO_START.0 {
        ServiceStartMode::Automatic
    } else if value == SERVICE_DEMAND_START.0 {
        ServiceStartMode::Manual
    } else if value == SERVICE_DISABLED.0 {
        ServiceStartMode::Disabled
    } else {
        ServiceStartMode::Other(value)
    }
}
