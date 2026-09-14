use super::transfer::{ERROR_MORE_DATA, TransferStatus, native_error};
use crate::PlatformError;
use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::pin::Pin;
use std::time::Duration;

const ERROR_IO_PENDING: u32 = 997;
const ERROR_NOT_FOUND: u32 = 1168;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;

#[repr(C)]
union OffsetOrPointer {
    offset: [u32; 2],
    pointer: *mut c_void,
}

#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset_or_pointer: OffsetOrPointer,
    event: isize,
}

struct PendingOperation {
    overlapped: Overlapped,
    _event: EventHandle,
}

impl PendingOperation {
    fn new() -> Result<Pin<Box<Self>>, PlatformError> {
        let event = EventHandle::create()?;
        Ok(Box::pin(Self {
            overlapped: Overlapped {
                internal: 0,
                internal_high: 0,
                offset_or_pointer: OffsetOrPointer { offset: [0; 2] },
                event: event.raw(),
            },
            _event: event,
        }))
    }

    fn pointer(operation: &mut Pin<Box<Self>>) -> *mut Overlapped {
        let operation = unsafe { operation.as_mut().get_unchecked_mut() };
        &raw mut operation.overlapped
    }

    fn event(&self) -> isize {
        self.overlapped.event
    }
}

pub(super) fn connect(handle: isize, timeout: Duration) -> Result<(), PlatformError> {
    let timeout = timeout_milliseconds(timeout)?;
    let mut operation = PendingOperation::new()?;
    match begin_connect(handle, &mut operation)? {
        ConnectStart::Connected => return Ok(()),
        ConnectStart::Pending => {}
    }
    let status = wait_pending(handle, &mut operation, timeout)?;
    classify_connect(status)
}

fn classify_connect(status: TransferStatus) -> Result<(), PlatformError> {
    if status.timed_out {
        Err(timeout_error("ConnectNamedPipe"))
    } else if status.succeeded {
        Ok(())
    } else {
        Err(native_error("ConnectNamedPipe", status.error))
    }
}

enum ConnectStart {
    Connected,
    Pending,
}

fn begin_connect(
    handle: isize,
    operation: &mut Pin<Box<PendingOperation>>,
) -> Result<ConnectStart, PlatformError> {
    if unsafe { ConnectNamedPipe(handle, PendingOperation::pointer(operation)) } != 0 {
        return Ok(ConnectStart::Connected);
    }
    match unsafe { GetLastError() } {
        super::ERROR_PIPE_CONNECTED => Ok(ConnectStart::Connected),
        ERROR_IO_PENDING => Ok(ConnectStart::Pending),
        error => Err(native_error("ConnectNamedPipe", error)),
    }
}

pub(super) fn read(
    handle: isize,
    bytes: &mut [u8],
    timeout: Duration,
) -> Result<TransferStatus, PlatformError> {
    let count = transfer_count(bytes.len(), "pipe read exceeds Win32 bound")?;
    transfer(handle, timeout, |operation| unsafe {
        ReadFile(
            handle,
            bytes.as_mut_ptr().cast(),
            count,
            std::ptr::null_mut(),
            operation,
        )
    })
}

pub(super) fn write(
    handle: isize,
    bytes: &[u8],
    timeout: Duration,
) -> Result<TransferStatus, PlatformError> {
    let count = transfer_count(bytes.len(), "pipe write exceeds Win32 bound")?;
    transfer(handle, timeout, |operation| unsafe {
        WriteFile(
            handle,
            bytes.as_ptr().cast(),
            count,
            std::ptr::null_mut(),
            operation,
        )
    })
}

fn transfer(
    handle: isize,
    timeout: Duration,
    start: impl FnOnce(*mut Overlapped) -> i32,
) -> Result<TransferStatus, PlatformError> {
    let timeout = timeout_milliseconds(timeout)?;
    let mut operation = PendingOperation::new()?;
    let succeeded = start(PendingOperation::pointer(&mut operation)) != 0;
    let error = if succeeded {
        0
    } else {
        unsafe { GetLastError() }
    };
    finish_or_wait(handle, operation, succeeded, error, timeout)
}

fn finish_or_wait(
    handle: isize,
    mut operation: Pin<Box<PendingOperation>>,
    succeeded: bool,
    error: u32,
    timeout: u32,
) -> Result<TransferStatus, PlatformError> {
    if succeeded || error == ERROR_MORE_DATA {
        return Ok(completed_status(handle, &mut operation, false));
    }
    if error != ERROR_IO_PENDING {
        return Ok(status(false, error, 0, false));
    }
    wait_pending(handle, &mut operation, timeout)
}

fn wait_pending(
    handle: isize,
    operation: &mut Pin<Box<PendingOperation>>,
    timeout: u32,
) -> Result<TransferStatus, PlatformError> {
    match unsafe { WaitForSingleObject(operation.event(), timeout) } {
        WAIT_OBJECT_0 => Ok(completed_status(handle, operation, false)),
        WAIT_TIMEOUT => cancel_and_drain(handle, operation),
        code => {
            let wait_error = if code == u32::MAX {
                unsafe { GetLastError() }
            } else {
                code
            };
            let _ = cancel_and_drain(handle, operation)?;
            Err(native_error("WaitForSingleObject", wait_error))
        }
    }
}

fn cancel_and_drain(
    handle: isize,
    operation: &mut Pin<Box<PendingOperation>>,
) -> Result<TransferStatus, PlatformError> {
    let cancelled = unsafe { CancelIoEx(handle, PendingOperation::pointer(operation)) } != 0;
    let cancel_error = if cancelled {
        0
    } else {
        unsafe { GetLastError() }
    };
    let mut drained = completed_status(handle, operation, true);
    drained.timed_out = true;
    if !cancelled && cancel_error != ERROR_NOT_FOUND {
        return Err(native_error("CancelIoEx", cancel_error));
    }
    Ok(drained)
}

fn completed_status(
    handle: isize,
    operation: &mut Pin<Box<PendingOperation>>,
    wait: bool,
) -> TransferStatus {
    let mut actual = 0_u32;
    let succeeded = unsafe {
        GetOverlappedResult(
            handle,
            PendingOperation::pointer(operation),
            &raw mut actual,
            i32::from(wait),
        )
    } != 0;
    let error = if succeeded {
        0
    } else {
        unsafe { GetLastError() }
    };
    status(succeeded, error, actual, false)
}

fn status(succeeded: bool, error: u32, actual: u32, timed_out: bool) -> TransferStatus {
    TransferStatus {
        succeeded,
        error,
        actual: usize::try_from(actual).expect("u32 fits usize"),
        timed_out,
    }
}

fn timeout_milliseconds(timeout: Duration) -> Result<u32, PlatformError> {
    let milliseconds = u32::try_from(timeout.as_millis()).map_err(|_| {
        PlatformError::ProtocolRejected("pipe timeout exceeds the finite Win32 bound".into())
    })?;
    if milliseconds == u32::MAX {
        return Err(PlatformError::ProtocolRejected(
            "pipe timeout cannot select the infinite Win32 wait".into(),
        ));
    }
    Ok(milliseconds)
}

fn transfer_count(length: usize, detail: &str) -> Result<u32, PlatformError> {
    u32::try_from(length).map_err(|_| PlatformError::ProtocolRejected(detail.into()))
}

fn timeout_error(operation: &str) -> PlatformError {
    PlatformError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("{operation} exceeded its finite timeout"),
    ))
}

struct EventHandle(OwnedHandle);

impl EventHandle {
    fn create() -> Result<Self, PlatformError> {
        let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if handle == 0 {
            return Err(native_error("CreateEventW", unsafe { GetLastError() }));
        }
        let owned = unsafe { OwnedHandle::from_raw_handle(handle as _) };
        Ok(Self(owned))
    }

    fn raw(&self) -> isize {
        self.0.as_raw_handle() as isize
    }
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn ConnectNamedPipe(pipe: isize, overlapped: *mut Overlapped) -> i32;
    fn ReadFile(
        handle: isize,
        buffer: *mut c_void,
        bytes_to_read: u32,
        bytes_read: *mut u32,
        overlapped: *mut Overlapped,
    ) -> i32;
    fn WriteFile(
        handle: isize,
        buffer: *const c_void,
        bytes_to_write: u32,
        bytes_written: *mut u32,
        overlapped: *mut Overlapped,
    ) -> i32;
    fn CreateEventW(
        attributes: *const c_void,
        manual_reset: i32,
        initial_state: i32,
        name: *const u16,
    ) -> isize;
    fn WaitForSingleObject(handle: isize, milliseconds: u32) -> u32;
    fn CancelIoEx(handle: isize, overlapped: *const Overlapped) -> i32;
    fn GetOverlappedResult(
        handle: isize,
        overlapped: *mut Overlapped,
        transferred: *mut u32,
        wait: i32,
    ) -> i32;
    fn GetLastError() -> u32;
}
