use super::{acl, file_information, handle_path, raw_file, validate_artifact_identity, wide_path};
use crate::PlatformError;
use crate::protected_run::policy::{ProtectedRunReadKind, validate_read_size};
use std::fs::File;
use std::io::Read;
use std::os::windows::io::AsRawHandle;
use windows::Win32::Foundation::{GENERIC_READ, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows::core::PCWSTR;

pub(super) fn read(parent: &handle_path::OpenedPath) -> Result<(Vec<u8>, Vec<u8>), PlatformError> {
    let (mut journal, mut result) = open_readers(parent)?;
    let bytes = read_artifacts(&mut journal, &mut result)?;
    verify_readers(parent, &journal, &result)?;
    Ok(bytes)
}

fn open_readers(parent: &handle_path::OpenedPath) -> Result<(File, File), PlatformError> {
    let journal = open_verified(parent, ProtectedRunReadKind::Journal)?;
    let result = open_verified(parent, ProtectedRunReadKind::Result)?;
    Ok((journal, result))
}

fn read_artifacts(
    journal: &mut File,
    result: &mut File,
) -> Result<(Vec<u8>, Vec<u8>), PlatformError> {
    let journal_bytes = read_bounded(journal, ProtectedRunReadKind::Journal)?;
    let result_bytes = read_bounded(result, ProtectedRunReadKind::Result)?;
    Ok((journal_bytes, result_bytes))
}

fn verify_readers(
    parent: &handle_path::OpenedPath,
    journal: &File,
    result: &File,
) -> Result<(), PlatformError> {
    verify(journal, parent, ProtectedRunReadKind::Journal)?;
    verify(result, parent, ProtectedRunReadKind::Result)
}

fn open_verified(
    parent: &handle_path::OpenedPath,
    kind: ProtectedRunReadKind,
) -> Result<File, PlatformError> {
    let path = parent.final_path().join(kind.file_name());
    let wide = wide_path(&path)?;
    let raw = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|error| read_error("open", &error))?;
    let file = raw_file(raw);
    verify(&file, parent, kind)?;
    Ok(file)
}

fn verify(
    file: &File,
    parent: &handle_path::OpenedPath,
    kind: ProtectedRunReadKind,
) -> Result<(), PlatformError> {
    let expected = parent.final_path().join(kind.file_name());
    let handle = HANDLE(file.as_raw_handle());
    validate_artifact_identity(handle, parent, &expected)?;
    let trusted_sids = acl::TrustedSids::new()?;
    acl::verify_handle_acl(handle, &trusted_sids, true)
}

fn read_bounded(file: &mut File, kind: ProtectedRunReadKind) -> Result<Vec<u8>, PlatformError> {
    let information = file_information(HANDLE(file.as_raw_handle()))?;
    let size = u64::from(information.nFileSizeLow) | (u64::from(information.nFileSizeHigh) << 32);
    let expected = validate_read_size(kind, size)?;
    let maximum = u64::try_from(kind.maximum_bytes()).expect("artifact limit fits u64");
    let mut bytes = Vec::with_capacity(expected);
    (&mut *file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| read_error("read", &error))?;
    validate_read_size(
        kind,
        u64::try_from(bytes.len()).expect("buffer length fits u64"),
    )?;
    reject_changed_length(kind, bytes.len(), expected)?;
    Ok(bytes)
}

fn reject_changed_length(
    kind: ProtectedRunReadKind,
    actual: usize,
    expected: usize,
) -> Result<(), PlatformError> {
    if actual == expected {
        return Ok(());
    }
    Err(PlatformError::TrustFailure(format!(
        "protected {} changed while it was read",
        kind.file_name()
    )))
}

fn read_error(operation: &str, error: &impl std::fmt::Display) -> PlatformError {
    PlatformError::TrustFailure(format!(
        "could not {operation} protected run artifact: {error}"
    ))
}
