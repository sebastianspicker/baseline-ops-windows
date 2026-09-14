use super::{
    acl,
    handle_path::{self, untrusted},
};
use crate::PlatformError;
use crate::protected_run::policy::{JOURNAL_FILE, PRODUCT_DIRECTORY, RUNS_DIRECTORY};
use baselineops_domain::RunId;
use std::fs::File;
use std::io::Write;
use std::mem::{MaybeUninit, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use windows::Win32::Foundation::{GENERIC_WRITE, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED, FILE_SHARE_READ,
    GetFileInformationByHandle, GetFinalPathNameByHandleW, OPEN_EXISTING,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
use windows::core::{PCWSTR, PWSTR};

const PRIVATE_DACL: &str = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";

mod reader;

pub(crate) struct ProtectedRunDirectory {
    lease: ProtectedRunLease,
    artifacts: Vec<handle_path::OpenedPath>,
}

#[derive(Clone)]
pub(crate) struct ProtectedRunLease(Arc<ProtectedRunLeaseInner>);

struct ProtectedRunLeaseInner {
    run: handle_path::OpenedPath,
    _runs: handle_path::OpenedPath,
    _product: handle_path::OpenedPath,
    _program_data: handle_path::OpenedPath,
    _ancestors: Vec<handle_path::OpenedPath>,
}

impl ProtectedRunDirectory {
    pub(crate) fn path(&self) -> &Path {
        self.lease.0.run.final_path()
    }

    pub(crate) fn write_artifact(
        &mut self,
        name: &str,
        bytes: &[u8],
        maximum_bytes: usize,
    ) -> Result<PathBuf, PlatformError> {
        if bytes.len() > maximum_bytes {
            return Err(PlatformError::InputTooLarge {
                path: PathBuf::from(name),
                limit: maximum_bytes as u64,
            });
        }
        let artifact = create_private_file(&self.lease.0.run, name, bytes)?;
        let path = artifact.final_path().to_path_buf();
        self.artifacts.push(artifact);
        Ok(path)
    }

    pub(crate) fn create_journal(
        &mut self,
    ) -> Result<(File, PathBuf, ProtectedRunLease), PlatformError> {
        let path = self.lease.0.run.final_path().join(JOURNAL_FILE);
        create_empty_verified_file(&self.lease.0.run, JOURNAL_FILE)?;
        let file = open_verified_writer(&self.lease.0.run, &path)?;
        Ok((file, path, self.lease.clone()))
    }
}

pub(crate) fn create_protected_run_directory(
    run_id: RunId,
) -> Result<ProtectedRunDirectory, PlatformError> {
    let base = acquire_base_trust()?;
    let product =
        open_or_create_private_child(&base.program_data, PRODUCT_DIRECTORY, &base.trusted_sids)?;
    let runs = open_or_create_private_child(&product, RUNS_DIRECTORY, &base.trusted_sids)?;
    let run = create_private_child(&runs, &run_id.to_string(), &base.trusted_sids)?;
    let lease = ProtectedRunLease(Arc::new(ProtectedRunLeaseInner {
        run,
        _runs: runs,
        _product: product,
        _program_data: base.program_data,
        _ancestors: base.ancestors,
    }));
    Ok(ProtectedRunDirectory {
        lease,
        artifacts: Vec::new(),
    })
}

pub(crate) fn read_protected_run_artifacts(
    run_id: RunId,
) -> Result<(Vec<u8>, Vec<u8>), PlatformError> {
    let lease = open_existing_run(run_id)?;
    reader::read(&lease.0.run)
}

fn open_existing_run(run_id: RunId) -> Result<ProtectedRunLease, PlatformError> {
    let base = acquire_base_trust()?;
    let product_path = base.program_data.final_path().join(PRODUCT_DIRECTORY);
    let product = open_private_child(&base.program_data, &product_path, &base.trusted_sids)?;
    let runs_path = product.final_path().join(RUNS_DIRECTORY);
    let runs = open_private_child(&product, &runs_path, &base.trusted_sids)?;
    let run_path = runs.final_path().join(run_id.to_string());
    let run = open_private_child(&runs, &run_path, &base.trusted_sids)?;
    Ok(ProtectedRunLease(Arc::new(ProtectedRunLeaseInner {
        run,
        _runs: runs,
        _product: product,
        _program_data: base.program_data,
        _ancestors: base.ancestors,
    })))
}

struct BaseTrust {
    program_data: handle_path::OpenedPath,
    ancestors: Vec<handle_path::OpenedPath>,
    trusted_sids: acl::TrustedSids,
}

fn acquire_base_trust() -> Result<BaseTrust, PlatformError> {
    let requested_program_data = program_data_path()?;
    let program_data = open_known_directory(&requested_program_data)?;
    let trusted_sids = acl::TrustedSids::new()?;
    acl::verify_object_acl(&program_data, &trusted_sids, false)?;
    let ancestors = retain_ancestor_identities(&program_data, &trusted_sids)?;
    Ok(BaseTrust {
        program_data,
        ancestors,
        trusted_sids,
    })
}

fn program_data_path() -> Result<PathBuf, PlatformError> {
    let allocation = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None) }
        .map_err(|error| known_folder_error(&error))?;
    ProgramDataAllocation(allocation).to_path()
}

struct ProgramDataAllocation(PWSTR);

impl ProgramDataAllocation {
    fn to_path(&self) -> Result<PathBuf, PlatformError> {
        let value = unsafe { self.0.to_string() }
            .map_err(|_| PlatformError::TrustFailure("ProgramData is not valid UTF-16".into()))?;
        if value.is_empty() {
            return Err(PlatformError::TrustFailure(
                "Windows returned an empty ProgramData path".into(),
            ));
        }
        Ok(PathBuf::from(value))
    }
}

impl Drop for ProgramDataAllocation {
    fn drop(&mut self) {
        unsafe { CoTaskMemFree(Some(self.0.0.cast())) };
    }
}

fn open_known_directory(path: &Path) -> Result<handle_path::OpenedPath, PlatformError> {
    let opened = handle_path::open_directory(path)?;
    verify_same_path(
        opened.final_path(),
        path,
        "ProgramData handle identity changed",
    )?;
    Ok(opened)
}

fn retain_ancestor_identities(
    directory: &handle_path::OpenedPath,
    trusted_sids: &acl::TrustedSids,
) -> Result<Vec<handle_path::OpenedPath>, PlatformError> {
    let mut current = directory.final_path().parent().map(Path::to_path_buf);
    let mut retained = Vec::new();
    while let Some(path) = current {
        if path.components().count() <= 2 {
            break;
        }
        let opened = handle_path::open_directory(&path)?;
        verify_same_path(
            opened.final_path(),
            &path,
            "ancestor handle identity changed",
        )?;
        acl::verify_object_acl(&opened, trusted_sids, false)?;
        current = opened.final_path().parent().map(Path::to_path_buf);
        retained.push(opened);
    }
    Ok(retained)
}

fn open_or_create_private_child(
    parent: &handle_path::OpenedPath,
    name: &str,
    trusted_sids: &acl::TrustedSids,
) -> Result<handle_path::OpenedPath, PlatformError> {
    let path = parent.final_path().join(name);
    if path.try_exists()? {
        return open_private_child(parent, &path, trusted_sids);
    }
    if create_directory_with_dacl(&path).is_err() {
        return open_private_child(parent, &path, trusted_sids);
    }
    open_private_child(parent, &path, trusted_sids)
}

fn create_private_child(
    parent: &handle_path::OpenedPath,
    name: &str,
    trusted_sids: &acl::TrustedSids,
) -> Result<handle_path::OpenedPath, PlatformError> {
    let path = parent.final_path().join(name);
    create_directory_with_dacl(&path)?;
    open_private_child(parent, &path, trusted_sids)
}

fn open_private_child(
    parent: &handle_path::OpenedPath,
    path: &Path,
    trusted_sids: &acl::TrustedSids,
) -> Result<handle_path::OpenedPath, PlatformError> {
    let opened = handle_path::open_directory(path)?;
    verify_direct_child(parent, &opened)?;
    acl::verify_object_acl(&opened, trusted_sids, true)?;
    Ok(opened)
}

fn create_directory_with_dacl(path: &Path) -> Result<(), PlatformError> {
    let descriptor = PrivateSecurityDescriptor::new()?;
    let attributes = descriptor.attributes();
    let wide = wide_path(path)?;
    unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(&raw const attributes)) }
        .map_err(|error| creation_error("directory", &error))
}

fn create_private_file(
    parent: &handle_path::OpenedPath,
    name: &str,
    bytes: &[u8],
) -> Result<handle_path::OpenedPath, PlatformError> {
    let path = parent.final_path().join(name);
    create_empty_verified_file(parent, name)?;
    let mut file = open_verified_writer(parent, &path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    verify_private_file(parent, &path)
}

fn create_empty_verified_file(
    parent: &handle_path::OpenedPath,
    name: &str,
) -> Result<(), PlatformError> {
    let path = parent.final_path().join(name);
    let descriptor = PrivateSecurityDescriptor::new()?;
    let attributes = descriptor.attributes();
    let wide = wide_path(&path)?;
    let raw = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_READ,
            Some(&raw const attributes),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|error| creation_error("artifact", &error))?;
    drop(raw_file(raw));
    drop(verify_private_file(parent, &path)?);
    Ok(())
}

fn verify_private_file(
    parent: &handle_path::OpenedPath,
    path: &Path,
) -> Result<handle_path::OpenedPath, PlatformError> {
    let opened = handle_path::open_regular_file(path)?;
    verify_direct_child(parent, &opened)?;
    handle_path::verify_single_link(&opened)?;
    let trusted_sids = acl::TrustedSids::new()?;
    acl::verify_object_acl(&opened, &trusted_sids, true)?;
    Ok(opened)
}

fn open_verified_writer(
    parent: &handle_path::OpenedPath,
    path: &Path,
) -> Result<File, PlatformError> {
    let wide = wide_path(path)?;
    let raw = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|error| creation_error("artifact writer", &error))?;
    let file = raw_file(raw);
    let handle = HANDLE(file.as_raw_handle());
    validate_artifact_identity(handle, parent, path)?;
    let trusted_sids = acl::TrustedSids::new()?;
    acl::verify_handle_acl(handle, &trusted_sids, true)?;
    Ok(file)
}

fn validate_artifact_identity(
    raw: HANDLE,
    parent: &handle_path::OpenedPath,
    expected: &Path,
) -> Result<(), PlatformError> {
    let information = file_information(raw)?;
    reject_artifact_attributes(&information, expected)?;
    let actual = final_path(raw)?;
    verify_same_path(&actual, expected, "artifact handle identity changed")?;
    let actual_parent = actual
        .parent()
        .ok_or_else(|| untrusted(&actual, "artifact has no parent"))?;
    verify_same_path(
        actual_parent,
        parent.final_path(),
        "artifact escaped run directory",
    )
}

fn reject_artifact_attributes(
    information: &BY_HANDLE_FILE_INFORMATION,
    expected: &Path,
) -> Result<(), PlatformError> {
    if information.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT.0 | FILE_ATTRIBUTE_DIRECTORY.0)
        != 0
    {
        return Err(untrusted(
            expected,
            "artifact is not a regular non-reparse file",
        ));
    }
    if information.nNumberOfLinks != 1 {
        return Err(untrusted(
            expected,
            "artifact must have exactly one hard link",
        ));
    }
    Ok(())
}

fn file_information(raw: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION, PlatformError> {
    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    unsafe { GetFileInformationByHandle(raw, information.as_mut_ptr()) }
        .map_err(|error| creation_error("artifact identity", &error))?;
    Ok(unsafe { information.assume_init() })
}

fn final_path(raw: HANDLE) -> Result<PathBuf, PlatformError> {
    let required = unsafe { GetFinalPathNameByHandleW(raw, &mut [], FILE_NAME_NORMALIZED) };
    if required == 0 {
        return Err(PlatformError::TrustFailure(
            "could not resolve artifact path".into(),
        ));
    }
    let mut buffer = vec![0_u16; usize::try_from(required).expect("path length") + 1];
    let written = unsafe { GetFinalPathNameByHandleW(raw, &mut buffer, FILE_NAME_NORMALIZED) };
    if written == 0 || written >= u32::try_from(buffer.len()).expect("buffer length") {
        return Err(PlatformError::TrustFailure(
            "could not read artifact path".into(),
        ));
    }
    buffer.truncate(usize::try_from(written).expect("path length"));
    String::from_utf16(&buffer)
        .map(PathBuf::from)
        .map_err(|_| PlatformError::TrustFailure("artifact path is not UTF-16".into()))
}

fn raw_file(raw: HANDLE) -> File {
    let owned = unsafe { OwnedHandle::from_raw_handle(raw.0) };
    File::from(owned)
}

fn verify_direct_child(
    parent: &handle_path::OpenedPath,
    child: &handle_path::OpenedPath,
) -> Result<(), PlatformError> {
    let actual_parent = child
        .final_path()
        .parent()
        .ok_or_else(|| untrusted(child.final_path(), "protected child has no parent"))?;
    verify_same_path(
        actual_parent,
        parent.final_path(),
        "protected child escaped its retained parent",
    )
}

fn verify_same_path(actual: &Path, expected: &Path, reason: &str) -> Result<(), PlatformError> {
    if comparable_path(actual).eq_ignore_ascii_case(&comparable_path(expected)) {
        return Ok(());
    }
    Err(untrusted(actual, reason))
}

fn comparable_path(path: &Path) -> String {
    let path = path.as_os_str().to_string_lossy();
    path.strip_prefix("\\\\?\\")
        .unwrap_or(&path)
        .trim_end_matches(['\\', '/'])
        .to_owned()
}

fn wide_path(path: &Path) -> Result<Vec<u16>, PlatformError> {
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.is_empty() || wide.contains(&0) {
        return Err(untrusted(path, "protected path is empty or contains NUL"));
    }
    wide.push(0);
    Ok(wide)
}

struct PrivateSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl PrivateSecurityDescriptor {
    fn new() -> Result<Self, PlatformError> {
        let mut wide = PRIVATE_DACL.encode_utf16().collect::<Vec<_>>();
        wide.push(0);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
        }
        .map_err(|error| creation_error("security descriptor", &error))?;
        if descriptor.is_invalid() {
            return Err(PlatformError::TrustFailure(
                "private security descriptor allocation was null".into(),
            ));
        }
        Ok(Self(descriptor))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                .expect("SECURITY_ATTRIBUTES size fits u32"),
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: false.into(),
        }
    }
}

impl Drop for PrivateSecurityDescriptor {
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

fn creation_error(kind: &str, error: &windows::core::Error) -> PlatformError {
    PlatformError::TrustFailure(format!("could not create protected {kind}: {error}"))
}

fn known_folder_error(error: &windows::core::Error) -> PlatformError {
    PlatformError::TrustFailure(format!(
        "could not resolve ProgramData known folder: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparable_paths_accept_extended_prefix_only() {
        assert_eq!(
            comparable_path(Path::new(r"\\?\C:\ProgramData\BaselineOps\")),
            comparable_path(Path::new(r"C:\ProgramData\BaselineOps"))
        );
    }

    #[test]
    fn private_descriptor_names_only_system_and_administrators() {
        assert_eq!(PRIVATE_DACL, "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)");
    }
}
