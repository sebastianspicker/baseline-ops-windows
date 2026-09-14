//! Suspended Windows native-process launcher with explicit handle inheritance.

#![allow(unsafe_code)]

use super::{
    ContainmentState, NativeExecutableTrust, NativeProcessPolicy, NativeProcessResult,
    NativeProcessSpec, ValidatedRequest, read_capped,
};
use crate::PlatformError;
use crate::command_line::quote_argument;
#[path = "windows/api.rs"]
mod api;
#[path = "windows/containment.rs"]
mod containment;
#[path = "windows/stdio.rs"]
mod stdio;
#[allow(clippy::wildcard_imports)]
use api::*;
use containment::{AttributeList, Job};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::ptr;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;
use stdio::child_stdio;

const CLEANUP_WAIT: Duration = Duration::from_secs(5);

pub(super) fn run(
    validated: &ValidatedRequest,
    policy: &NativeProcessPolicy,
    spec: &NativeProcessSpec,
) -> Result<NativeProcessResult, PlatformError> {
    let mut child = start_child(validated, policy, spec)?;
    let (stdout_reader, stderr_reader) = start_readers(&mut child, spec.output_limit)?;
    finish_child(&mut child, stdout_reader, stderr_reader, spec.timeout)
}

fn start_child(
    validated: &ValidatedRequest,
    policy: &NativeProcessPolicy,
    spec: &NativeProcessSpec,
) -> Result<ContainedProcess, PlatformError> {
    if matches!(
        &policy.executable_trust,
        NativeExecutableTrust::ExactDigest(_)
    ) {
        return Err(PlatformError::ProcessRejected(
            "ExactDigest launch is disabled until execution can retain the verified file identity"
                .into(),
        ));
    }
    let mut child = ContainedProcess::create(validated, policy, spec)?;
    child.resume()?;
    Ok(child)
}

fn start_readers(
    child: &mut ContainedProcess,
    limit: usize,
) -> Result<(Reader, Reader), PlatformError> {
    let stdout = match child.take_stdout() {
        Ok(stdout) => stdout,
        Err(error) => {
            child.terminate_and_wait()?;
            return Err(error);
        }
    };
    let stderr = match child.take_stderr() {
        Ok(stderr) => stderr,
        Err(error) => {
            child.terminate_and_wait()?;
            return Err(error);
        }
    };
    Ok((
        spawn_reader(stdout, limit, "stdout"),
        spawn_reader(stderr, limit, "stderr"),
    ))
}

fn finish_child(
    child: &mut ContainedProcess,
    stdout_reader: Reader,
    stderr_reader: Reader,
    timeout: Duration,
) -> Result<NativeProcessResult, PlatformError> {
    let exit_code = match wait_for_child_exit(child, timeout) {
        Ok(code) => code,
        Err(error) => return discard_after_failure(child, stdout_reader, stderr_reader, error),
    };
    // The primary process may exit while descendants still own the pipe writers.
    // End the entire Job before awaiting reader completion.
    child.terminate_and_wait()?;
    let stdout = join_reader(stdout_reader, "stdout")?;
    let stderr = join_reader(stderr_reader, "stderr")?;
    Ok(NativeProcessResult {
        exit_code,
        stdout,
        stderr,
    })
}

fn wait_for_child_exit(child: &ContainedProcess, timeout: Duration) -> Result<i32, PlatformError> {
    match child.wait(timeout)? {
        Some(exit_code) => Ok(exit_code),
        None => Err(PlatformError::ProcessTimeout {
            seconds: timeout.as_secs(),
        }),
    }
}

fn discard_after_failure(
    child: &mut ContainedProcess,
    stdout: Reader,
    stderr: Reader,
    error: PlatformError,
) -> Result<NativeProcessResult, PlatformError> {
    child.terminate_and_wait()?;
    discard_reader(stdout, "stdout")?;
    discard_reader(stderr, "stderr")?;
    Err(error)
}

struct Reader {
    receiver: Receiver<Result<Vec<u8>, PlatformError>>,
    handle: thread::JoinHandle<()>,
}

fn spawn_reader(file: File, limit: usize, stream: &'static str) -> Reader {
    let (sender, receiver) = mpsc::sync_channel(1);
    let handle = thread::spawn(move || {
        let _ = sender.send(read_capped(file, limit, stream));
    });
    Reader { receiver, handle }
}

fn await_reader(
    reader: Reader,
    stream: &'static str,
) -> Result<Result<Vec<u8>, PlatformError>, PlatformError> {
    let result = reader.receiver.recv_timeout(CLEANUP_WAIT).map_err(|_| {
        PlatformError::ProcessRejected(format!("{stream} reader did not finish after cleanup"))
    })?;
    reader
        .handle
        .join()
        .map_err(|_| PlatformError::ProcessRejected(format!("{stream} reader panicked")))?;
    Ok(result)
}

fn join_reader(reader: Reader, stream: &'static str) -> Result<Vec<u8>, PlatformError> {
    await_reader(reader, stream)?
}

fn discard_reader(reader: Reader, stream: &'static str) -> Result<(), PlatformError> {
    let _ = await_reader(reader, stream)?;
    Ok(())
}

struct OwnedHandle(Handle);

impl OwnedHandle {
    fn new(handle: Handle, operation: &str) -> Result<Self, PlatformError> {
        if handle == 0 || handle == INVALID_HANDLE_VALUE {
            return Err(last_error(operation));
        }
        Ok(Self(handle))
    }

    fn raw(&self) -> Handle {
        self.0
    }

    fn into_file(self) -> File {
        let raw = self.0;
        std::mem::forget(self);
        // The handle is a parent-owned synchronous anonymous-pipe endpoint.
        unsafe { File::from_raw_handle(raw as _) }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // Closing handles is best effort during stack unwinding and cleanup.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct ContainedProcess {
    job: Job,
    process: OwnedHandle,
    thread: OwnedHandle,
    stdout: Option<OwnedHandle>,
    stderr: Option<OwnedHandle>,
    state: ContainmentState,
}

impl ContainedProcess {
    fn create(
        validated: &ValidatedRequest,
        policy: &NativeProcessPolicy,
        spec: &NativeProcessSpec,
    ) -> Result<Self, PlatformError> {
        let job = Job::create()?;
        let (stdin, stdout, stderr) = child_stdio()?;
        let (process, thread) =
            Self::create_suspended(validated, policy, spec, &stdin, &stdout.0, &stderr.0)?;
        Self::assign_or_terminate(&job, process.raw())?;
        drop(stdin);
        drop(stdout.0);
        drop(stderr.0);
        Ok(Self {
            job,
            process,
            thread,
            stdout: Some(stdout.1),
            stderr: Some(stderr.1),
            state: ContainmentState::Assigned,
        })
    }

    fn create_suspended(
        validated: &ValidatedRequest,
        policy: &NativeProcessPolicy,
        spec: &NativeProcessSpec,
        stdin: &OwnedHandle,
        stdout: &OwnedHandle,
        stderr: &OwnedHandle,
    ) -> Result<(OwnedHandle, OwnedHandle), PlatformError> {
        let inherited = [stdin.raw(), stdout.raw(), stderr.raw()];
        let mut attributes = AttributeList::for_handles(&inherited)?;
        let mut command_line = wide(OsStr::new(&command_line(&validated.executable, &spec.args)));
        let startup = Self::startup_info(stdin.raw(), stdout.raw(), stderr.raw(), attributes.raw());
        let information =
            Self::create_process_information(validated, policy, &mut command_line, &startup)?;
        information.into_owned_handles()
    }

    fn assign_or_terminate(job: &Job, process: Handle) -> Result<(), PlatformError> {
        if let Err(error) = job.assign(process) {
            terminate_process_and_wait(process)?;
            return Err(error);
        }
        Ok(())
    }

    fn startup_info(
        stdin: Handle,
        stdout: Handle,
        stderr: Handle,
        attributes: *mut core::ffi::c_void,
    ) -> StartupInfoExW {
        StartupInfoExW {
            startup_info: StartupInfoW {
                cb: u32::try_from(size_of::<StartupInfoExW>()).expect("STARTUPINFOEXW size"),
                reserved: ptr::null_mut(),
                desktop: ptr::null_mut(),
                title: ptr::null_mut(),
                x: 0,
                y: 0,
                x_size: 0,
                y_size: 0,
                x_count_chars: 0,
                y_count_chars: 0,
                fill_attribute: 0,
                flags: STARTF_USESTDHANDLES,
                show_window: 0,
                reserved2_count: 0,
                reserved2: ptr::null_mut(),
                stdin,
                stdout,
                stderr,
            },
            attributes,
        }
    }

    fn create_process_information(
        validated: &ValidatedRequest,
        policy: &NativeProcessPolicy,
        command_line: &mut [u16],
        startup: &StartupInfoExW,
    ) -> Result<ProcessInformation, PlatformError> {
        let executable = wide(validated.executable.as_os_str());
        let working_directory = wide(validated.working_directory.as_os_str());
        let environment = environment_block(&policy.environment)?;
        let mut information = MaybeUninit::<ProcessInformation>::zeroed();
        if unsafe {
            CreateProcessW(
                executable.as_ptr(),
                command_line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast(),
                working_directory.as_ptr(),
                (&raw const startup.startup_info),
                information.as_mut_ptr(),
            )
        } == 0
        {
            return Err(last_error("CreateProcessW"));
        }
        Ok(unsafe { information.assume_init() })
    }

    fn resume(&mut self) -> Result<(), PlatformError> {
        if !self.state.may_resume() {
            self.terminate_and_wait()?;
            return Err(PlatformError::ProcessRejected(
                "attempted to resume a child outside the assigned containment state".into(),
            ));
        }
        if unsafe { ResumeThread(self.thread.raw()) } == u32::MAX {
            self.terminate_and_wait()?;
            return Err(last_error("ResumeThread"));
        }
        self.state = ContainmentState::Running;
        Ok(())
    }

    fn take_stdout(&mut self) -> Result<File, PlatformError> {
        self.stdout
            .take()
            .map(OwnedHandle::into_file)
            .ok_or_else(|| {
                PlatformError::ProcessRejected("stdout capture was not established".into())
            })
    }

    fn take_stderr(&mut self) -> Result<File, PlatformError> {
        self.stderr
            .take()
            .map(OwnedHandle::into_file)
            .ok_or_else(|| {
                PlatformError::ProcessRejected("stderr capture was not established".into())
            })
    }

    fn wait(&self, timeout: Duration) -> Result<Option<i32>, PlatformError> {
        let wait = unsafe { WaitForSingleObject(self.process.raw(), duration_millis(timeout)?) };
        if wait == WAIT_OBJECT_0 {
            let mut exit_code = 0_u32;
            if unsafe { GetExitCodeProcess(self.process.raw(), &raw mut exit_code) } == 0 {
                return Err(last_error("GetExitCodeProcess"));
            }
            return Ok(Some(i32::try_from(exit_code).unwrap_or(-1)));
        }
        if wait == WAIT_TIMEOUT {
            return Ok(None);
        }
        debug_assert_eq!(wait, WAIT_FAILED);
        Err(last_error("WaitForSingleObject"))
    }

    fn terminate_and_wait(&mut self) -> Result<(), PlatformError> {
        if self.state != ContainmentState::Reaped {
            terminate_job_and_wait(&self.job, self.process.raw())?;
            self.state = ContainmentState::Reaped;
        }
        Ok(())
    }
}

impl Drop for ContainedProcess {
    fn drop(&mut self) {
        if self.state != ContainmentState::Reaped {
            let _ = terminate_job_and_wait(&self.job, self.process.raw());
            self.state = ContainmentState::Reaped;
        }
    }
}

fn terminate_process_and_wait(process: Handle) -> Result<(), PlatformError> {
    if unsafe { TerminateProcess(process, 1) } == 0 {
        return Err(last_error("TerminateProcess"));
    }
    wait_for_exit(process, "TerminateProcess cleanup")
}

fn terminate_job_and_wait(job: &Job, process: Handle) -> Result<(), PlatformError> {
    job.terminate()?;
    wait_for_exit(process, "TerminateJobObject cleanup")
}

fn wait_for_exit(process: Handle, operation: &str) -> Result<(), PlatformError> {
    match unsafe { WaitForSingleObject(process, duration_millis(CLEANUP_WAIT)?) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(PlatformError::ProcessRejected(format!(
            "{operation} did not finish inside the bounded cleanup wait"
        ))),
        _ => Err(last_error("WaitForSingleObject cleanup")),
    }
}

fn duration_millis(duration: Duration) -> Result<u32, PlatformError> {
    let milliseconds = duration.as_millis();
    if milliseconds >= u128::from(u32::MAX) {
        return Err(PlatformError::ProcessRejected(
            "Windows wait duration must remain below INFINITE".into(),
        ));
    }
    Ok(u32::try_from(milliseconds).expect("bounded Win32 duration"))
}

fn environment_block(
    environment: &std::collections::BTreeMap<OsString, OsString>,
) -> Result<Vec<u16>, PlatformError> {
    let mut entries = Vec::with_capacity(environment.len());
    for (name, value) in environment {
        let name = wide(name.as_os_str());
        let value = wide(value.as_os_str());
        if name[..name.len() - 1].contains(&0)
            || value[..value.len() - 1].contains(&0)
            || name[..name.len() - 1].contains(&u16::from(b'='))
        {
            return Err(PlatformError::ProcessRejected(
                "environment contains an invalid Windows name or value".into(),
            ));
        }
        let sort_key = String::from_utf16_lossy(&name[..name.len() - 1]).to_uppercase();
        entries.push((sort_key, name, value));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut output = Vec::new();
    for (_, name, value) in entries {
        output.extend_from_slice(&name[..name.len() - 1]);
        output.push(u16::from(b'='));
        output.extend_from_slice(&value[..value.len() - 1]);
        output.push(0);
    }
    if output.is_empty() {
        output.extend([0, 0]);
    } else {
        output.push(0);
    }
    Ok(output)
}

fn command_line(executable: &std::path::Path, args: &[String]) -> String {
    let mut tokens = Vec::with_capacity(args.len() + 1);
    tokens.push(executable.as_os_str().to_string_lossy().into_owned());
    tokens.extend(args.iter().cloned());
    tokens
        .into_iter()
        .map(|token| quote_argument(&token))
        .collect::<Vec<_>>()
        .join(" ")
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn last_error(operation: &str) -> PlatformError {
    PlatformError::Io(io::Error::other(format!(
        "{operation}: Win32 error {}",
        unsafe { GetLastError() }
    )))
}

impl ProcessInformation {
    fn into_owned_handles(self) -> Result<(OwnedHandle, OwnedHandle), PlatformError> {
        let process = OwnedHandle::new(self.process, "CreateProcessW process")?;
        match OwnedHandle::new(self.thread, "CreateProcessW thread") {
            Ok(thread) => Ok((process, thread)),
            Err(error) => {
                terminate_process_and_wait(process.raw())?;
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_quotes_spaces_and_trailing_backslashes() {
        assert_eq!(
            quote_argument(r"C:\\Program Files\\"),
            r#""C:\\Program Files\\\\""#
        );
        assert_eq!(quote_argument(r#"say \"hi\""#), r#""say \\\"hi\\\"""#);
    }

    #[test]
    fn infinite_deadlines_are_rejected() {
        assert!(duration_millis(Duration::MAX).is_err());
    }
}
