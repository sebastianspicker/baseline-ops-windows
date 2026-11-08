use crate::PlatformError;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
pub(super) enum PathKind {
    File,
    Directory,
}

pub(super) fn existing(
    root: &Path,
    reject_reparse_points: bool,
    candidate: &Path,
    expected_kind: PathKind,
) -> Result<PathBuf, PlatformError> {
    reject_lexical_escape(candidate)?;
    reject_unc(candidate)?;
    let joined = joined_candidate(root, candidate);
    if reject_reparse_points {
        reject_reparse_chain(&joined)?;
    }
    let canonical = canonical_existing(root, &joined)?;
    verify_kind(&canonical, expected_kind)?;
    Ok(canonical)
}

fn canonical_existing(root: &Path, joined: &Path) -> Result<PathBuf, PlatformError> {
    let canonical = fs::canonicalize(joined)?;
    verify_containment(root, joined, &canonical)?;
    Ok(canonical)
}

fn joined_candidate(root: &Path, candidate: &Path) -> PathBuf {
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.join(candidate)
    }
}

pub(super) fn reject_reparse_chain(path: &Path) -> Result<(), PlatformError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || has_windows_reparse_attribute(&metadata) {
            return Err(PlatformError::UntrustedPath {
                path: current,
                reason: "reparse points and symbolic links are forbidden".into(),
            });
        }
    }
    Ok(())
}

pub(super) fn reject_lexical_escape(path: &Path) -> Result<(), PlatformError> {
    if path
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(PlatformError::UntrustedPath {
            path: path.to_path_buf(),
            reason: "parent traversal is forbidden".into(),
        });
    }
    Ok(())
}

pub(super) fn reject_unc(path: &Path) -> Result<(), PlatformError> {
    let text = path.as_os_str().to_string_lossy();
    if text.starts_with("\\\\") || text.starts_with("//") {
        return Err(PlatformError::UntrustedPath {
            path: path.to_path_buf(),
            reason: "UNC paths are forbidden".into(),
        });
    }
    Ok(())
}

fn verify_containment(root: &Path, joined: &Path, canonical: &Path) -> Result<(), PlatformError> {
    if !canonical.starts_with(root) {
        return Err(PlatformError::UntrustedPath {
            path: joined.to_path_buf(),
            reason: "canonical path escaped the trusted root".into(),
        });
    }
    Ok(())
}

fn verify_kind(path: &Path, expected_kind: PathKind) -> Result<(), PlatformError> {
    let valid = match expected_kind {
        PathKind::File => path.is_file(),
        PathKind::Directory => path.is_dir(),
    };
    if !valid {
        let reason = match expected_kind {
            PathKind::File => "expected a regular file",
            PathKind::Directory => "expected a directory",
        };
        return Err(PlatformError::UntrustedPath {
            path: path.to_path_buf(),
            reason: reason.into(),
        });
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn has_windows_reparse_attribute(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
pub(super) const fn has_windows_reparse_attribute(_metadata: &fs::Metadata) -> bool {
    false
}
