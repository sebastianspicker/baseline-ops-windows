use super::acl::{self, TrustedSids};
use crate::PlatformError;
use std::mem::MaybeUninit;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, GetFileInformationByHandle,
    GetFinalPathNameByHandleW, OPEN_EXISTING, READ_CONTROL,
};
use windows::core::PCWSTR;

pub(super) struct OpenedPath {
    handle: PendingHandle,
    final_path: PathBuf,
    information: BY_HANDLE_FILE_INFORMATION,
}

struct PendingHandle(OwnedHandle);

impl PendingHandle {
    fn raw(&self) -> HANDLE {
        HANDLE(self.0.as_raw_handle())
    }
}

impl OpenedPath {
    pub(super) fn handle(&self) -> HANDLE {
        self.handle.raw()
    }

    pub(super) fn final_path(&self) -> &Path {
        &self.final_path
    }

    fn information(&self) -> &BY_HANDLE_FILE_INFORMATION {
        &self.information
    }
}

pub(super) fn open_directory(path: &Path) -> Result<OpenedPath, PlatformError> {
    let opened = open_no_reparse(path, true)?;
    if opened.information().dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
        return Err(untrusted(path, "protected root is not a directory"));
    }
    Ok(opened)
}

pub(super) fn open_regular_file(path: &Path) -> Result<OpenedPath, PlatformError> {
    let opened = open_no_reparse(path, false)?;
    let attributes = opened.information().dwFileAttributes;
    if attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
        return Err(untrusted(path, "protected executable is a directory"));
    }
    Ok(opened)
}

pub(super) fn verify_containment(
    root: &OpenedPath,
    executable: &OpenedPath,
) -> Result<(), PlatformError> {
    if !path_is_within(executable.final_path(), root.final_path()) {
        return Err(untrusted(
            executable.final_path(),
            "executable final handle path escaped the protected root",
        ));
    }
    Ok(())
}

pub(super) fn verify_single_link(executable: &OpenedPath) -> Result<(), PlatformError> {
    if executable.information().nNumberOfLinks != 1 {
        return Err(untrusted(
            executable.final_path(),
            "protected executable must have exactly one hard link",
        ));
    }
    Ok(())
}

pub(super) fn verify_ancestors(
    root: &OpenedPath,
    trusted_sids: &TrustedSids,
) -> Result<Vec<OpenedPath>, PlatformError> {
    let mut child = root.final_path().to_path_buf();
    let mut current = child.parent().map(Path::to_path_buf);
    let mut retained = Vec::new();
    while let Some(path) = current {
        if is_volume_root(&path) {
            break;
        }
        let opened = open_directory(&path)?;
        if !paths_equal(opened.final_path(), &path) || !path_is_within(&child, opened.final_path())
        {
            return Err(untrusted(
                &path,
                "ancestor handle identity does not contain the protected child",
            ));
        }
        acl::verify_object_acl(&opened, trusted_sids, false)?;
        child = opened.final_path().to_path_buf();
        current = child.parent().map(Path::to_path_buf);
        retained.push(opened);
    }
    Ok(retained)
}

pub(super) fn verify_descendant_directories(
    root: &OpenedPath,
    executable: &OpenedPath,
    trusted_sids: &TrustedSids,
) -> Result<Vec<OpenedPath>, PlatformError> {
    let paths = descendant_directory_paths(root, executable)?;
    let mut parent = root.final_path().to_path_buf();
    let mut retained = Vec::with_capacity(paths.len());
    for path in paths {
        let opened = verified_descendant_directory(&path, &parent, trusted_sids)?;
        parent = opened.final_path().to_path_buf();
        retained.push(opened);
    }
    verify_executable_parent(executable, &parent)?;
    Ok(retained)
}

fn descendant_directory_paths(
    root: &OpenedPath,
    executable: &OpenedPath,
) -> Result<Vec<PathBuf>, PlatformError> {
    super::super::protected_descendant_directories(root.final_path(), executable.final_path())
        .ok_or_else(|| {
            untrusted(
                executable.final_path(),
                "could not derive protected executable directory chain",
            )
        })
}

fn verified_descendant_directory(
    path: &Path,
    expected_parent: &Path,
    trusted_sids: &TrustedSids,
) -> Result<OpenedPath, PlatformError> {
    let opened = open_directory(path)?;
    let opened_parent = opened
        .final_path()
        .parent()
        .ok_or_else(|| untrusted(opened.final_path(), "protected directory has no parent"))?;
    if !paths_equal(opened.final_path(), path) || !paths_equal(opened_parent, expected_parent) {
        return Err(untrusted(
            path,
            "protected directory handle identity differs from its expected parent chain",
        ));
    }
    acl::verify_object_acl(&opened, trusted_sids, false)?;
    Ok(opened)
}

fn verify_executable_parent(
    executable: &OpenedPath,
    expected_parent: &Path,
) -> Result<(), PlatformError> {
    if executable
        .final_path()
        .parent()
        .is_some_and(|path| paths_equal(path, expected_parent))
    {
        return Ok(());
    }
    Err(untrusted(
        executable.final_path(),
        "protected executable is not a direct child of its verified directory chain",
    ))
}

fn open_no_reparse(path: &Path, directory: bool) -> Result<OpenedPath, PlatformError> {
    reject_lexical_escape(path)?;
    reject_unc(path)?;
    let handle = open_handle(path, directory)?;
    let information = file_information(handle.raw())?;
    reject_reparse_path(path, &information)?;
    let final_path = final_path(handle.raw())?;
    Ok(OpenedPath {
        handle,
        final_path,
        information,
    })
}

fn open_handle(path: &Path, directory: bool) -> Result<PendingHandle, PlatformError> {
    let wide = wide_path(path)?;
    let flags = open_flags(directory);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            (FILE_READ_ATTRIBUTES | READ_CONTROL).0,
            // Retained protected-install handles allow readers but deny later
            // content replacement, rename, and deletion until the authority drops.
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .map_err(|error| {
        PlatformError::TrustFailure(format!("could not open protected path: {error}"))
    })?;
    // SAFETY: successful CreateFileW returns one owned real handle; ownership
    // transfers exactly once to std's thread-safe RAII handle wrapper.
    Ok(PendingHandle(unsafe {
        OwnedHandle::from_raw_handle(handle.0)
    }))
}

fn open_flags(directory: bool) -> windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES {
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
    if directory {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
    }
    flags
}

fn reject_reparse_path(
    path: &Path,
    information: &BY_HANDLE_FILE_INFORMATION,
) -> Result<(), PlatformError> {
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(untrusted(path, "reparse points are forbidden"));
    }
    Ok(())
}

fn file_information(handle: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION, PlatformError> {
    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    unsafe { GetFileInformationByHandle(handle, information.as_mut_ptr()) }.map_err(|error| {
        PlatformError::TrustFailure(format!("could not read file identity: {error}"))
    })?;
    Ok(unsafe { information.assume_init() })
}

fn final_path(handle: HANDLE) -> Result<PathBuf, PlatformError> {
    let required = unsafe { GetFinalPathNameByHandleW(handle, &mut [], FILE_NAME_NORMALIZED) };
    if required == 0 {
        return Err(PlatformError::TrustFailure(
            "could not resolve final handle path".into(),
        ));
    }
    let mut buffer = vec![0_u16; usize::try_from(required).expect("final path length") + 1];
    let written = unsafe { GetFinalPathNameByHandleW(handle, &mut buffer, FILE_NAME_NORMALIZED) };
    if written == 0 || written >= u32::try_from(buffer.len()).expect("buffer length") {
        return Err(PlatformError::TrustFailure(
            "could not read final handle path".into(),
        ));
    }
    buffer.truncate(usize::try_from(written).expect("written length"));
    Ok(PathBuf::from(String::from_utf16(&buffer).map_err(
        |_| PlatformError::TrustFailure("final handle path is not valid UTF-16".into()),
    )?))
}

fn path_is_within(candidate: &Path, root: &Path) -> bool {
    let candidate = candidate.as_os_str().to_string_lossy();
    let root = root.as_os_str().to_string_lossy();
    if candidate.len() <= root.len() || !candidate[..root.len()].eq_ignore_ascii_case(&root) {
        return false;
    }
    matches!(candidate.as_bytes().get(root.len()), Some(b'\\' | b'/'))
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    left.as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
}

fn is_volume_root(path: &Path) -> bool {
    path.parent().is_none() || path.components().count() <= 2
}

fn reject_lexical_escape(path: &Path) -> Result<(), PlatformError> {
    if path
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(untrusted(path, "parent traversal is forbidden"));
    }
    Ok(())
}

fn reject_unc(path: &Path) -> Result<(), PlatformError> {
    if super::super::is_forbidden_protected_path_namespace(path) {
        return Err(untrusted(
            path,
            "UNC and device protected-install paths are forbidden",
        ));
    }
    Ok(())
}

fn wide_path(path: &Path) -> Result<Vec<u16>, PlatformError> {
    let mut value = encoded_wide_path(path);
    if value.is_empty() || value.contains(&0) {
        return Err(untrusted(path, "path contains an interior NUL or is empty"));
    }
    value.push(0);
    Ok(value)
}

pub(super) fn encoded_wide_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str().encode_wide().collect()
}

pub(super) fn untrusted(path: &Path, reason: &str) -> PlatformError {
    PlatformError::UntrustedPath {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn containment_requires_a_component_boundary() {
        assert!(path_is_within(
            Path::new(r"\\?\C:\Program Files\BaselineOps\worker.exe"),
            Path::new(r"\\?\C:\Program Files\BaselineOps")
        ));
        assert!(!path_is_within(
            Path::new(r"\\?\C:\Program Files\BaselineOps-old\worker.exe"),
            Path::new(r"\\?\C:\Program Files\BaselineOps")
        ));
    }

    #[test]
    fn lexical_parent_traversal_is_rejected() {
        assert!(reject_lexical_escape(Path::new(r"C:\safe\..\worker.exe")).is_err());
    }
}
