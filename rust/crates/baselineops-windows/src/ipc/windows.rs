//! Windows named-pipe transport and authenticated process inspection.

#![allow(unsafe_code)]

use super::{BrokerFrame, FrameCodec, PeerIdentity};
use crate::PlatformError;
use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::{Duration, Instant};

mod identity;
mod overlapped;
mod transfer;

use identity::{SecurityDescriptor, pipe_name, pipe_peer_identity};
use transfer::{ReadOutcome, ReadStage, classify_read, native_error};

const INVALID_HANDLE_VALUE: isize = -1;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const PIPE_ACCESS_DUPLEX: u32 = 3;
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
const PIPE_TYPE_MESSAGE: u32 = 4;
const PIPE_READMODE_MESSAGE: u32 = 2;
const PIPE_WAIT: u32 = 0;
const PIPE_REJECT_REMOTE_CLIENTS: u32 = 8;
const ERROR_PIPE_CONNECTED: u32 = 535;
const DEFAULT_IO_TIMEOUT: Duration = Duration::from_mins(2);

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    security_descriptor: *mut c_void,
    inherit_handle: i32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateNamedPipeW(
        name: *const u16,
        open_mode: u32,
        pipe_mode: u32,
        maximum_instances: u32,
        output_buffer_size: u32,
        input_buffer_size: u32,
        default_timeout: u32,
        security_attributes: *const SecurityAttributes,
    ) -> isize;
    fn CreateFileW(
        name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *const c_void,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: isize,
    ) -> isize;
    fn DisconnectNamedPipe(pipe: isize) -> i32;
    fn SetNamedPipeHandleState(
        pipe: isize,
        mode: *mut u32,
        maximum_collection_count: *mut u32,
        collection_data_timeout: *mut u32,
    ) -> i32;
    fn GetLastError() -> u32;
}

/// Verifies Windows peer credentials after the pipe supplies its process ID.
pub trait PipePeerVerifier: Send + Sync {
    /// Fail closed unless the peer is authorized for this one broker operation.
    ///
    /// # Errors
    ///
    /// Returns an error whenever the peer is not authorized.
    fn verify(&self, peer: &PeerIdentity) -> Result<(), PlatformError>;
}

/// First-instance, local-only Windows message-mode pipe listener.
pub struct NamedPipeServer {
    handle: OwnedHandle,
}

/// Connected broker pipe client or accepted server connection.
pub struct NamedPipeClient {
    handle: OwnedHandle,
    poisoned: bool,
}

impl NamedPipeServer {
    /// Bind a pipe for exactly the launched client's logon SID, SYSTEM, and Administrators.
    ///
    /// # Errors
    ///
    /// Returns an error when the name or SID is invalid, another first instance
    /// exists, or Windows rejects the restrictive security descriptor.
    pub fn bind(name: &str, expected_logon_sid: &str) -> Result<Self, PlatformError> {
        let name = pipe_name(name)?;
        let descriptor = SecurityDescriptor::for_client_logon_sid(expected_logon_sid)?;
        let attributes = SecurityAttributes {
            length: u32::try_from(std::mem::size_of::<SecurityAttributes>()).map_err(|_| {
                PlatformError::ProtocolRejected("security attributes size overflow".into())
            })?,
            security_descriptor: descriptor.as_ptr(),
            inherit_handle: 0,
        };
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                64 * 1024,
                64 * 1024,
                0,
                &raw const attributes,
            )
        };
        owned_handle(handle).map(|handle| Self { handle })
    }

    /// Wait for one client and run the caller verifier against its OS PID/session.
    ///
    /// # Errors
    ///
    /// Returns an error when connection, identity collection, or verification fails.
    pub fn accept(self, verifier: &dyn PipePeerVerifier) -> Result<NamedPipeClient, PlatformError> {
        self.accept_timeout(verifier, DEFAULT_IO_TIMEOUT)
    }

    /// Wait for one client for at most `timeout` and verify its OS PID/session.
    ///
    /// # Errors
    ///
    /// Returns an error after safely cancelling and draining a timed-out accept,
    /// or when identity collection or verification fails.
    pub fn accept_timeout(
        self,
        verifier: &dyn PipePeerVerifier,
        timeout: Duration,
    ) -> Result<NamedPipeClient, PlatformError> {
        overlapped::connect(raw_handle(&self.handle), timeout)?;
        let peer = pipe_peer_identity(raw_handle(&self.handle), true)?;
        verifier.verify(&peer)?;
        let server = std::mem::ManuallyDrop::new(self);
        let handle = unsafe { std::ptr::read(&raw const server.handle) };
        Ok(NamedPipeClient {
            handle,
            poisoned: false,
        })
    }
}

impl NamedPipeClient {
    /// Connect to an existing local broker pipe. No remote pipe path is accepted.
    ///
    /// # Errors
    ///
    /// Returns an error when the pipe is absent, busy, or cannot be opened.
    pub fn connect(name: &str) -> Result<Self, PlatformError> {
        let name = pipe_name(name)?;
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                0,
            )
        };
        let handle = owned_handle(handle)?;
        set_message_read_mode(raw_handle(&handle))?;
        Ok(Self {
            handle,
            poisoned: false,
        })
    }

    /// Return the server PID/session before the client sends any broker bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when Windows cannot identify the pipe server.
    pub fn server_peer_identity(&self) -> Result<PeerIdentity, PlatformError> {
        pipe_peer_identity(raw_handle(&self.handle), false)
    }

    /// Send one already-encoded bounded frame.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame cannot be written in full.
    pub fn send(&mut self, frame: &BrokerFrame) -> Result<(), PlatformError> {
        self.send_timeout(frame, DEFAULT_IO_TIMEOUT)
    }

    /// Send one bounded frame within `timeout`.
    ///
    /// # Errors
    ///
    /// Returns an error and poisons the connection when a started transfer does
    /// not complete exactly within the deadline.
    pub fn send_timeout(
        &mut self,
        frame: &BrokerFrame,
        timeout: Duration,
    ) -> Result<(), PlatformError> {
        if frame.0.len() < 4 || frame.0.len() > super::MAX_FRAME_BYTES.saturating_add(4) {
            return Err(PlatformError::ProtocolRejected(
                "pipe frame is outside explicit bounds".into(),
            ));
        }
        let _: serde_json::Value = FrameCodec::decode(&frame.0)?;
        self.require_usable()?;
        let result = write_message(raw_handle(&self.handle), &frame.0, timeout);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Receive one bounded frame after validating its length and JSON shape.
    ///
    /// # Errors
    ///
    /// Returns an error when the peer closes or sends an invalid bounded frame.
    pub fn receive(&mut self) -> Result<BrokerFrame, PlatformError> {
        self.receive_timeout(DEFAULT_IO_TIMEOUT)?.ok_or_else(|| {
            PlatformError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "pipe receive exceeded its finite timeout",
            ))
        })
    }

    /// Receive one bounded frame within `timeout`.
    ///
    /// `None` means the prefix read timed out without consuming any bytes. The
    /// cancelled operation has been drained and the pipe remains reusable.
    ///
    /// # Errors
    ///
    /// Returns an error and poisons the pipe after any partial prefix, body
    /// timeout, malformed message, or native transfer failure.
    pub fn receive_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<BrokerFrame>, PlatformError> {
        self.require_usable()?;
        let result = receive_message(raw_handle(&self.handle), timeout);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn require_usable(&self) -> Result<(), PlatformError> {
        if self.poisoned {
            return Err(PlatformError::ProtocolRejected(
                "pipe connection is unusable after an incomplete transfer".into(),
            ));
        }
        Ok(())
    }
}

fn receive_message(handle: isize, timeout: Duration) -> Result<Option<BrokerFrame>, PlatformError> {
    let started = Instant::now();
    let mut prefix = [0_u8; 4];
    let prefix_more_data = match read_message_part(handle, &mut prefix, timeout, ReadStage::Prefix)?
    {
        ReadOutcome::Complete { more_data } => more_data,
        ReadOutcome::CleanTimeout => return Ok(None),
    };
    let body = declared_body_length(prefix, prefix_more_data)?;
    let remaining = timeout.saturating_sub(started.elapsed());
    let frame = read_declared_body(handle, prefix, body, remaining)?;
    let _: serde_json::Value = FrameCodec::decode(&frame)?;
    Ok(Some(BrokerFrame(frame)))
}

fn declared_body_length(prefix: [u8; 4], prefix_more_data: bool) -> Result<usize, PlatformError> {
    let body = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| PlatformError::ProtocolRejected("pipe frame length is invalid".into()))?;
    if body > super::MAX_FRAME_BYTES {
        return Err(PlatformError::ProtocolRejected(
            "pipe frame exceeds maximum size".into(),
        ));
    }
    if !prefix_has_expected_boundary(body, prefix_more_data) {
        return Err(PlatformError::ProtocolRejected(
            "pipe message disagrees with its declared frame body".into(),
        ));
    }
    Ok(body)
}

fn read_declared_body(
    handle: isize,
    prefix: [u8; 4],
    body: usize,
    timeout: Duration,
) -> Result<Vec<u8>, PlatformError> {
    let mut frame = Vec::with_capacity(body.saturating_add(4));
    frame.extend_from_slice(&prefix);
    frame.resize(body.saturating_add(4), 0);
    if body != 0 {
        match read_message_part(handle, &mut frame[4..], timeout, ReadStage::Body)? {
            ReadOutcome::Complete { more_data: false } => {}
            ReadOutcome::Complete { more_data: true } => {
                return Err(PlatformError::ProtocolRejected(
                    "pipe message contains bytes after its bounded frame".into(),
                ));
            }
            ReadOutcome::CleanTimeout => {
                return Err(PlatformError::ProtocolRejected(
                    "pipe body unexpectedly reported a clean timeout".into(),
                ));
            }
        }
    }
    Ok(frame)
}

impl Drop for NamedPipeServer {
    fn drop(&mut self) {
        let _ = unsafe { DisconnectNamedPipe(raw_handle(&self.handle)) };
    }
}

fn owned_handle(handle: isize) -> Result<OwnedHandle, PlatformError> {
    if handle == INVALID_HANDLE_VALUE || handle == 0 {
        return Err(last_error("Windows handle creation"));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as _) })
}

fn raw_handle(handle: &OwnedHandle) -> isize {
    handle.as_raw_handle() as isize
}

fn set_message_read_mode(handle: isize) -> Result<(), PlatformError> {
    let mut mode = PIPE_READMODE_MESSAGE;
    if unsafe {
        SetNamedPipeHandleState(
            handle,
            &raw mut mode,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(last_error("SetNamedPipeHandleState"));
    }
    Ok(())
}

/// Read exactly one known-sized portion of the current message.
///
/// In message-read mode, a short buffer returns `ERROR_MORE_DATA` after
/// copying valid bytes. The prefix intentionally uses that behavior to learn
/// the bounded body length. A later `ERROR_MORE_DATA` means the peer appended
/// bytes beyond the declared frame and is rejected by `receive`.
fn read_message_part(
    handle: isize,
    bytes: &mut [u8],
    timeout: Duration,
    stage: ReadStage,
) -> Result<ReadOutcome, PlatformError> {
    if bytes.is_empty() {
        return Ok(ReadOutcome::Complete { more_data: false });
    }
    let status = overlapped::read(handle, bytes, timeout)?;
    classify_read(status, bytes.len(), stage)
}

fn prefix_has_expected_boundary(body: usize, prefix_more_data: bool) -> bool {
    (body == 0) != prefix_more_data
}

/// Preserve the frame-to-message boundary: a retry would create a new pipe
/// message and let a receiver desynchronize its length-prefix state.
fn write_message(handle: isize, bytes: &[u8], timeout: Duration) -> Result<(), PlatformError> {
    let status = overlapped::write(handle, bytes, timeout)?;
    if status.timed_out {
        return Err(PlatformError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "pipe send exceeded its finite timeout",
        )));
    }
    if !status.succeeded {
        return Err(native_error("WriteFile", status.error));
    }
    if status.actual != bytes.len() {
        return Err(PlatformError::ProtocolRejected(
            "pipe write completed without the exact frame".into(),
        ));
    }
    Ok(())
}

fn last_error(operation: &str) -> PlatformError {
    last_error_code(operation, unsafe { GetLastError() })
}

fn last_error_code(operation: &str, code: u32) -> PlatformError {
    native_error(operation, code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_state_cannot_cross_pipe_message_boundaries() {
        assert!(prefix_has_expected_boundary(0, false));
        assert!(prefix_has_expected_boundary(1, true));
        assert!(!prefix_has_expected_boundary(0, true));
        assert!(!prefix_has_expected_boundary(1, false));
    }
}
