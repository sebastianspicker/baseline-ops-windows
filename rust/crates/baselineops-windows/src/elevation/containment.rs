use crate::PlatformError;
use std::time::Duration;

#[cfg(any(windows, test))]
const JOB_OBJECT_LIMIT_BREAKAWAY_OK: u32 = 0x0000_0800;
#[cfg(any(windows, test))]
const JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK: u32 = 0x0000_1000;
#[cfg(any(windows, test))]
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;

#[cfg(any(windows, test))]
fn limits_satisfy(limit_flags: u32) -> bool {
    limit_flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0
        && limit_flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) == 0
}

#[cfg(not(windows))]
pub(super) fn wait(_timeout: Duration) -> Result<(), PlatformError> {
    Err(PlatformError::UnsupportedPlatform)
}

#[cfg(windows)]
mod windows {
    #![allow(unsafe_code)]

    use super::{Duration, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, PlatformError, limits_satisfy};
    use crate::elevation::last_error;
    use std::time::Instant;

    type RawHandle = isize;

    const INVALID_HANDLE_VALUE: RawHandle = -1;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: u32 = 9;
    const POLL_INTERVAL: Duration = Duration::from_millis(10);

    #[derive(Default)]
    #[repr(C)]
    struct JobObjectBasicLimitInformation {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    #[derive(Default)]
    #[repr(C)]
    #[allow(clippy::struct_field_names)]
    struct IoCounters {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[derive(Default)]
    #[repr(C)]
    struct JobObjectExtendedLimitInformation {
        basic_limit_information: JobObjectBasicLimitInformation,
        io_info: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn AssignProcessToJobObject(job: RawHandle, process: RawHandle) -> i32;
        fn CloseHandle(handle: RawHandle) -> i32;
        fn CreateJobObjectW(attributes: *const core::ffi::c_void, name: *const u16) -> RawHandle;
        fn GetCurrentProcess() -> RawHandle;
        fn IsProcessInJob(process: RawHandle, job: RawHandle, result: *mut i32) -> i32;
        fn QueryInformationJobObject(
            job: RawHandle,
            class: u32,
            information: *mut core::ffi::c_void,
            length: u32,
            return_length: *mut u32,
        ) -> i32;
        fn SetInformationJobObject(
            job: RawHandle,
            class: u32,
            information: *const core::ffi::c_void,
            length: u32,
        ) -> i32;
        fn TerminateJobObject(job: RawHandle, exit_code: u32) -> i32;
    }

    pub(in crate::elevation) struct Job(RawHandle);

    impl Job {
        pub(in crate::elevation) fn create() -> Result<Self, PlatformError> {
            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if job == 0 || job == INVALID_HANDLE_VALUE {
                return Err(last_error("CreateJobObjectW"));
            }
            let mut limits = empty_job_limits();
            limits.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if unsafe {
                SetInformationJobObject(
                    job,
                    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    (&raw const limits).cast(),
                    u32::try_from(std::mem::size_of_val(&limits)).expect("job limit size"),
                )
            } == 0
            {
                let error = last_error("SetInformationJobObject");
                let _ = unsafe { CloseHandle(job) };
                return Err(error);
            }
            Ok(Self(job))
        }

        pub(in crate::elevation) fn assign(
            &self,
            process: windows::Win32::Foundation::HANDLE,
        ) -> Result<(), PlatformError> {
            if unsafe { AssignProcessToJobObject(self.0, process.0 as RawHandle) } == 0 {
                return Err(last_error("AssignProcessToJobObject"));
            }
            Ok(())
        }

        pub(in crate::elevation) fn terminate(&self) -> Result<(), PlatformError> {
            if unsafe { TerminateJobObject(self.0, 1) } == 0 {
                return Err(last_error("TerminateJobObject"));
            }
            Ok(())
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    pub(super) fn wait(timeout: Duration) -> Result<(), PlatformError> {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            PlatformError::ProcessRejected("containment deadline overflowed".into())
        })?;
        loop {
            if current_process_is_in_job()? {
                return verify_current_job_limits();
            }
            if Instant::now() >= deadline {
                return Err(PlatformError::TrustFailure(
                    "elevated worker was not assigned to a job before bootstrap timeout".into(),
                ));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn current_process_is_in_job() -> Result<bool, PlatformError> {
        let mut in_job = 0_i32;
        if unsafe { IsProcessInJob(GetCurrentProcess(), 0, &raw mut in_job) } == 0 {
            return Err(last_error("IsProcessInJob"));
        }
        Ok(in_job != 0)
    }

    fn verify_current_job_limits() -> Result<(), PlatformError> {
        let mut limits = empty_job_limits();
        if unsafe {
            QueryInformationJobObject(
                0,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                (&raw mut limits).cast(),
                u32::try_from(std::mem::size_of_val(&limits)).expect("job limit size"),
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(last_error("QueryInformationJobObject"));
        }
        if !limits_satisfy(limits.basic_limit_information.limit_flags) {
            return Err(PlatformError::TrustFailure(
                "elevated worker job lacks kill-on-close or permits breakaway".into(),
            ));
        }
        Ok(())
    }

    fn empty_job_limits() -> JobObjectExtendedLimitInformation {
        JobObjectExtendedLimitInformation::default()
    }
}

#[cfg(windows)]
pub(super) use windows::Job;

#[cfg(windows)]
pub(super) fn wait(timeout: Duration) -> Result<(), PlatformError> {
    windows::wait(timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_kill_on_close_without_breakaway() {
        assert!(limits_satisfy(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE));
        assert!(!limits_satisfy(0));
        assert!(!limits_satisfy(
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK
        ));
        assert!(!limits_satisfy(
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
        ));
    }
}
