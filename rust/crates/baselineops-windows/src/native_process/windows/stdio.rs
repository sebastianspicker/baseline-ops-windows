use super::{
    OwnedHandle,
    api::{
        CreateFileW, CreatePipe, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GENERIC_READ, HANDLE_FLAG_INHERIT, Handle, OPEN_EXISTING, SecurityAttributes,
        SetHandleInformation,
    },
    last_error,
};
use crate::PlatformError;
use std::mem::size_of;
use std::ptr;

pub(super) type ChildStdio = (
    OwnedHandle,
    (OwnedHandle, OwnedHandle),
    (OwnedHandle, OwnedHandle),
);

pub(super) fn child_stdio() -> Result<ChildStdio, PlatformError> {
    let inherit = inheritable_security_attributes();
    let stdin = nul_input(&inherit)?;
    Ok((stdin, pipe(&inherit)?, pipe(&inherit)?))
}

fn inheritable_security_attributes() -> SecurityAttributes {
    SecurityAttributes {
        length: u32::try_from(size_of::<SecurityAttributes>()).expect("SECURITY_ATTRIBUTES size"),
        security_descriptor: ptr::null_mut(),
        inherit_handle: 1,
    }
}

fn nul_input(attributes: &SecurityAttributes) -> Result<OwnedHandle, PlatformError> {
    let nul = [u16::from(b'N'), u16::from(b'U'), u16::from(b'L'), 0];
    let handle = unsafe {
        CreateFileW(
            nul.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::from_ref(attributes).cast(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0,
        )
    };
    OwnedHandle::new(handle, "CreateFileW NUL")
}

fn pipe(attributes: &SecurityAttributes) -> Result<(OwnedHandle, OwnedHandle), PlatformError> {
    let (read, write) = create_pipe(attributes)?;
    let read = OwnedHandle::new(read, "CreatePipe read")?;
    let write = OwnedHandle::new(write, "CreatePipe write")?;
    if unsafe { SetHandleInformation(read.raw(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(last_error("SetHandleInformation"));
    }
    Ok((write, read))
}

fn create_pipe(attributes: &SecurityAttributes) -> Result<(Handle, Handle), PlatformError> {
    let mut read = 0;
    let mut write = 0;
    if unsafe {
        CreatePipe(
            &raw mut read,
            &raw mut write,
            ptr::from_ref(attributes).cast(),
            0,
        )
    } == 0
    {
        return Err(last_error("CreatePipe"));
    }
    Ok((read, write))
}
