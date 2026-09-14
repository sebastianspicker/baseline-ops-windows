//! UAC elevation launcher for the trusted worker executable.

use crate::{PlatformError, TrustedInstallation};
use std::path::PathBuf;
use std::time::Duration;

#[path = "elevation/containment.rs"]
mod containment;

/// Preconditions and resource bounds for one UAC worker launch.
#[derive(Clone, Debug)]
pub struct ElevatedLaunchPolicy {
    /// Arguments passed as direct worker tokens, never through a command shell.
    pub arguments: Vec<String>,
    /// Maximum wall-clock wait for the worker process.
    pub timeout: Duration,
}

/// Terminal interpretation of an elevated worker process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ElevatedLaunchStatus {
    /// The worker exited and returned its process exit code.
    Exited(i32),
    /// UAC was declined before process creation.
    Cancelled,
    /// The worker did not finish before the policy deadline.
    TimedOut,
}

/// Result of launching the trusted worker through the `runas` verb.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElevatedLaunchResult {
    /// The signed worker executable selected by protected-install verification.
    pub executable: PathBuf,
    /// UAC/process terminal state.
    pub status: ElevatedLaunchStatus,
}

/// Launch a previously verified worker with UAC elevation and wait up to policy timeout.
///
/// The executable path cannot be supplied independently: the caller must first
/// pass [`crate::verify_protected_install`] and provide that resulting authority.
///
/// # Errors
///
/// Returns a fail-closed error for malformed tokens, unsupported platforms,
/// UAC cancellation, timeout, or Win32 failures.
pub fn launch_elevated(
    installation: &TrustedInstallation,
    policy: &ElevatedLaunchPolicy,
) -> Result<ElevatedLaunchResult, PlatformError> {
    validate_policy(policy)?;
    platform::launch(installation, policy)
}

/// Wait until the current worker is assigned to a non-breakaway kill-on-close job.
///
/// This is intended as the elevated worker's first bootstrap gate. It closes the
/// `ShellExecuteExW` assignment race by preventing worker initialization from
/// proceeding until the launcher containment policy is observable in-process.
///
/// # Errors
///
/// Returns an error when the timeout is invalid, job membership is not observed
/// in time, the effective job permits breakaway, or native inspection fails.
pub fn wait_for_worker_containment(timeout: Duration) -> Result<(), PlatformError> {
    validate_containment_timeout(timeout)?;
    containment::wait(timeout)
}

fn validate_policy(policy: &ElevatedLaunchPolicy) -> Result<(), PlatformError> {
    validate_timeout(policy.timeout)?;
    validate_arguments(&policy.arguments)
}

fn validate_timeout(timeout: Duration) -> Result<(), PlatformError> {
    if timeout.is_zero() || timeout > Duration::from_hours(1) {
        return Err(PlatformError::ProcessRejected(
            "elevation timeout is outside the one-hour ceiling".into(),
        ));
    }
    if timeout.as_millis() >= u128::from(u32::MAX) {
        return Err(PlatformError::ProcessRejected(
            "elevation timeout must remain below the Win32 INFINITE sentinel".into(),
        ));
    }
    Ok(())
}

fn validate_containment_timeout(timeout: Duration) -> Result<(), PlatformError> {
    if timeout.is_zero() || timeout > Duration::from_secs(30) {
        return Err(PlatformError::ProcessRejected(
            "worker containment timeout is outside the 30-second ceiling".into(),
        ));
    }
    Ok(())
}

fn validate_arguments(arguments: &[String]) -> Result<(), PlatformError> {
    if arguments.len() > 64
        || arguments.iter().any(|argument| {
            argument.is_empty() || argument.len() > 4096 || argument.contains(['\0', '\r', '\n'])
        })
    {
        return Err(PlatformError::ProcessRejected(
            "elevation arguments violate fixed bounds".into(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn last_error(operation: &str) -> PlatformError {
    PlatformError::Io(std::io::Error::other(format!(
        "{operation}: {}",
        std::io::Error::last_os_error()
    )))
}

#[cfg(not(windows))]
mod platform {
    use super::{ElevatedLaunchPolicy, ElevatedLaunchResult, PlatformError, TrustedInstallation};

    pub fn launch(
        _installation: &TrustedInstallation,
        _policy: &ElevatedLaunchPolicy,
    ) -> Result<ElevatedLaunchResult, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code)]

    use super::{
        ElevatedLaunchPolicy, ElevatedLaunchResult, ElevatedLaunchStatus, PlatformError,
        TrustedInstallation, containment::Job, last_error,
    };
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::time::Duration;
    use windows::Win32::Foundation::{
        CloseHandle as CloseProcessHandle, ERROR_CANCELLED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
    };
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::core::{PCWSTR, w};

    const CLEANUP_WAIT_MILLISECONDS: u32 = 5_000;

    struct OwnedProcess(Option<windows::Win32::Foundation::HANDLE>);

    impl OwnedProcess {
        fn from_shell(handle: windows::Win32::Foundation::HANDLE) -> Result<Self, PlatformError> {
            if handle.is_invalid() {
                return Err(PlatformError::TrustFailure(
                    "ShellExecuteExW did not return a process handle".into(),
                ));
            }
            Ok(Self(Some(handle)))
        }

        fn raw(&self) -> windows::Win32::Foundation::HANDLE {
            self.0.expect("owned process handle is present until close")
        }

        fn close(mut self) -> Result<(), PlatformError> {
            let handle = self.0.take().expect("owned process handle is present");
            unsafe { CloseProcessHandle(handle) }.map_err(|error| {
                PlatformError::TrustFailure(format!("CloseHandle failed: {error}"))
            })
        }
    }

    impl Drop for OwnedProcess {
        fn drop(&mut self) {
            if let Some(handle) = self.0.take() {
                let _ = unsafe { CloseProcessHandle(handle) };
            }
        }
    }

    pub fn launch(
        installation: &TrustedInstallation,
        policy: &ElevatedLaunchPolicy,
    ) -> Result<ElevatedLaunchResult, PlatformError> {
        // The Job is fully configured before the UAC launch. ShellExecute itself cannot
        // create a `runas` process suspended, so assignment immediately follows its handle.
        let job = Job::create()?;
        let process = launch_worker(installation, policy)?;
        let status = wait_for_worker(&job, &process, policy.timeout)?;
        process.close()?;
        Ok(ElevatedLaunchResult {
            executable: installation.executable().to_path_buf(),
            status,
        })
    }

    fn launch_worker(
        installation: &TrustedInstallation,
        policy: &ElevatedLaunchPolicy,
    ) -> Result<OwnedProcess, PlatformError> {
        let executable = wide(installation.executable().as_os_str());
        let directory = installation.executable().parent().ok_or_else(|| {
            PlatformError::TrustFailure("trusted worker has no parent directory".into())
        })?;
        let directory = wide(directory.as_os_str());
        let parameters = wide(OsStr::new(&quote_arguments(&policy.arguments)));
        let mut execute = SHELLEXECUTEINFOW {
            cbSize: u32::try_from(std::mem::size_of::<SHELLEXECUTEINFOW>())
                .expect("SHELLEXECUTEINFOW size"),
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: w!("runas"),
            lpFile: PCWSTR(executable.as_ptr()),
            lpParameters: PCWSTR(parameters.as_ptr()),
            lpDirectory: PCWSTR(directory.as_ptr()),
            nShow: 0,
            ..Default::default()
        };
        unsafe { ShellExecuteExW(&raw mut execute) }.map_err(|error| elevation_error(&error))?;
        // `hProcess` is owned by this structure immediately after ShellExecuteExW.
        // Its Drop implementation closes it on every early-return path exactly once.
        OwnedProcess::from_shell(execute.hProcess)
    }

    fn elevation_error(error: &windows::core::Error) -> PlatformError {
        if error.code().0 == i32::try_from(ERROR_CANCELLED.0).expect("Win32 error code") {
            PlatformError::ElevationCancelled
        } else {
            PlatformError::TrustFailure(format!("ShellExecuteExW failed: {error}"))
        }
    }

    fn wait_for_worker(
        job: &Job,
        process: &OwnedProcess,
        timeout: Duration,
    ) -> Result<ElevatedLaunchStatus, PlatformError> {
        assign_worker(job, process)?;
        let milliseconds = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        let wait = unsafe { WaitForSingleObject(process.raw(), milliseconds) };
        interpret_worker_wait(job, process, wait)
    }

    fn assign_worker(job: &Job, process: &OwnedProcess) -> Result<(), PlatformError> {
        if let Err(error) = job.assign(process.raw()) {
            terminate_process_and_wait(process.raw())?;
            return Err(error);
        }
        Ok(())
    }

    fn interpret_worker_wait(
        job: &Job,
        process: &OwnedProcess,
        wait: windows::Win32::Foundation::WAIT_EVENT,
    ) -> Result<ElevatedLaunchStatus, PlatformError> {
        if wait == WAIT_TIMEOUT {
            return timed_out_worker(job, process);
        }
        if wait == WAIT_OBJECT_0 {
            return exited_worker(job, process);
        }
        terminate_job_and_wait(job, process.raw())?;
        Err(PlatformError::TrustFailure(
            "unexpected elevated process wait state".into(),
        ))
    }

    fn timed_out_worker(
        job: &Job,
        process: &OwnedProcess,
    ) -> Result<ElevatedLaunchStatus, PlatformError> {
        terminate_job_and_wait(job, process.raw())?;
        Ok(ElevatedLaunchStatus::TimedOut)
    }

    fn exited_worker(
        job: &Job,
        process: &OwnedProcess,
    ) -> Result<ElevatedLaunchStatus, PlatformError> {
        let mut exit_code = 0_u32;
        if let Err(error) = unsafe { GetExitCodeProcess(process.raw(), &raw mut exit_code) } {
            terminate_job_and_wait(job, process.raw())?;
            return Err(PlatformError::TrustFailure(format!(
                "GetExitCodeProcess failed: {error}"
            )));
        }
        Ok(ElevatedLaunchStatus::Exited(
            i32::try_from(exit_code).unwrap_or(-1),
        ))
    }

    fn terminate_process_and_wait(
        process: windows::Win32::Foundation::HANDLE,
    ) -> Result<(), PlatformError> {
        unsafe { TerminateProcess(process, 1) }.map_err(|error| {
            PlatformError::TrustFailure(format!("TerminateProcess failed: {error}"))
        })?;
        wait_for_cleanup(process)
    }

    fn terminate_job_and_wait(
        job: &Job,
        process: windows::Win32::Foundation::HANDLE,
    ) -> Result<(), PlatformError> {
        job.terminate()?;
        wait_for_cleanup(process)
    }

    fn wait_for_cleanup(process: windows::Win32::Foundation::HANDLE) -> Result<(), PlatformError> {
        match unsafe { WaitForSingleObject(process, CLEANUP_WAIT_MILLISECONDS) } {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => Err(PlatformError::TrustFailure(
                "elevated worker did not exit inside the bounded cleanup wait".into(),
            )),
            _ => Err(last_error("WaitForSingleObject cleanup")),
        }
    }

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }

    use crate::command_line::quote_argument;

    fn quote_arguments(arguments: &[String]) -> String {
        arguments
            .iter()
            .map(|argument| quote_argument(argument))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_launcher_bounds_fail_before_platform_dispatch() {
        assert!(
            validate_policy(&ElevatedLaunchPolicy {
                arguments: vec!["\n".into()],
                timeout: Duration::from_secs(1)
            })
            .is_err()
        );
        assert!(
            validate_policy(&ElevatedLaunchPolicy {
                arguments: vec![],
                timeout: Duration::ZERO
            })
            .is_err()
        );
    }

    #[test]
    fn containment_wait_has_a_small_fixed_ceiling() {
        assert!(validate_containment_timeout(Duration::from_millis(1)).is_ok());
        assert!(validate_containment_timeout(Duration::ZERO).is_err());
        assert!(validate_containment_timeout(Duration::from_secs(31)).is_err());
    }
}
