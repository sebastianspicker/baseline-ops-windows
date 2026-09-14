//! Windows-only Authenticode and protected-install verification.

#![allow(unsafe_code)] // Windows FFI is isolated to this cfg(windows) module tree.

mod acl;
mod authenticode;
mod handle_path;
mod protected_directory;
pub(super) mod signer;

pub(crate) use protected_directory::{
    ProtectedRunDirectory, ProtectedRunLease, create_protected_run_directory,
    read_protected_run_artifacts,
};

use super::{InstallationTrustPolicy, PlatformError};
use std::path::{Path, PathBuf};
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

const WINDOWS_SYSTEM_PUBLISHER: &str =
    "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";

pub(super) struct VerifiedInstallPaths {
    executable: handle_path::OpenedPath,
    root: handle_path::OpenedPath,
    _directories: Vec<handle_path::OpenedPath>,
}

impl VerifiedInstallPaths {
    pub(super) fn executable(&self) -> &Path {
        self.executable.final_path()
    }

    pub(super) fn root(&self) -> &Path {
        self.root.final_path()
    }
}

pub(super) fn verify_authenticode_subject(
    executable: &Path,
    expected_subject: &str,
) -> Result<(), PlatformError> {
    let executable = handle_path::open_regular_file(executable)?;
    authenticode::verify_subject(
        executable.handle(),
        executable.final_path(),
        expected_subject,
    )
}

pub(super) fn verify_authenticode(
    executable: &Path,
    expected_subject: &str,
    expected_spki_sha256: &super::SignerSpkiSha256,
) -> Result<(), PlatformError> {
    let executable = handle_path::open_regular_file(executable)?;
    authenticode::verify(
        executable.handle(),
        executable.final_path(),
        expected_subject,
        expected_spki_sha256,
    )
}

pub(super) fn verify_protected_install(
    policy: &InstallationTrustPolicy,
    executable: &Path,
) -> Result<VerifiedInstallPaths, PlatformError> {
    let root = handle_path::open_directory(&policy.root)?;
    let executable = handle_path::open_regular_file(executable)?;
    let directories = verify_path_controls(&root, &executable, true, policy.validate_ancestors)?;
    authenticode::verify(
        executable.handle(),
        executable.final_path(),
        &policy.publisher_subject,
        &policy.publisher_spki_sha256,
    )?;
    Ok(VerifiedInstallPaths {
        executable,
        root,
        _directories: directories,
    })
}

pub(super) fn verify_windows_system_executable(path: &Path) -> Result<PathBuf, PlatformError> {
    let root = handle_path::open_directory(&system32_directory()?)?;
    let executable = handle_path::open_regular_file(path)?;
    let _ancestors = verify_path_controls(&root, &executable, false, true)?;
    authenticode::verify_subject(
        executable.handle(),
        executable.final_path(),
        WINDOWS_SYSTEM_PUBLISHER,
    )?;
    Ok(executable.final_path().to_path_buf())
}

pub(super) fn resolve_regular_executable(path: &Path) -> Result<PathBuf, PlatformError> {
    let executable = handle_path::open_regular_file(path)?;
    handle_path::verify_single_link(&executable)?;
    Ok(executable.final_path().to_path_buf())
}

fn verify_path_controls(
    root: &handle_path::OpenedPath,
    executable: &handle_path::OpenedPath,
    require_protected_root_dacl: bool,
    validate_ancestors: bool,
) -> Result<Vec<handle_path::OpenedPath>, PlatformError> {
    verify_handle_invariants(root, executable)?;
    let trusted_sids = acl::TrustedSids::new()?;
    verify_acls(root, executable, &trusted_sids, require_protected_root_dacl)?;
    let mut directories =
        handle_path::verify_descendant_directories(root, executable, &trusted_sids)?;
    if validate_ancestors {
        directories.extend(handle_path::verify_ancestors(root, &trusted_sids)?);
    }
    Ok(directories)
}

fn verify_handle_invariants(
    root: &handle_path::OpenedPath,
    executable: &handle_path::OpenedPath,
) -> Result<(), PlatformError> {
    handle_path::verify_containment(root, executable)?;
    handle_path::verify_single_link(executable)
}

fn verify_acls(
    root: &handle_path::OpenedPath,
    executable: &handle_path::OpenedPath,
    trusted_sids: &acl::TrustedSids,
    require_protected_root_dacl: bool,
) -> Result<(), PlatformError> {
    acl::verify_object_acl(root, trusted_sids, require_protected_root_dacl)?;
    acl::verify_object_acl(executable, trusted_sids, false)
}

pub(super) fn system32_directory() -> Result<PathBuf, PlatformError> {
    let mut buffer = vec![0_u16; 32_768];
    let length = unsafe { GetSystemDirectoryW(Some(&mut buffer)) };
    let length = usize::try_from(length).map_err(|_| {
        PlatformError::TrustFailure("System32 path length does not fit this process".into())
    })?;
    if length == 0 || length >= buffer.len() {
        return Err(PlatformError::TrustFailure(
            "Windows did not return a bounded System32 directory".into(),
        ));
    }
    buffer.truncate(length);
    Ok(PathBuf::from(String::from_utf16(&buffer).map_err(
        |_| PlatformError::TrustFailure("System32 directory is not valid UTF-16".into()),
    )?))
}
