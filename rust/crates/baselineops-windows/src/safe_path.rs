#![cfg_attr(windows, allow(unsafe_code))]

use crate::PlatformError;
use baselineops_domain::Sha256Digest;
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod resolve;

/// Default upper bound for operator-supplied JSON documents.
pub const MAX_INPUT_BYTES: u64 = 1024 * 1024;

const HASH_BUFFER_BYTES: usize = 64 * 1024;

/// Digest and exact byte count read from one retained file handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedFileHash {
    /// SHA-256 digest of the exact bytes read from the retained handle.
    pub digest: Sha256Digest,
    /// Number of bytes that contributed to `digest`.
    pub size_bytes: u64,
}

/// Containment requirements for an untrusted path.
#[derive(Clone, Debug)]
pub struct PathPolicy {
    root: PathBuf,
    allow_unc: bool,
    reject_reparse_points: bool,
}

impl PathPolicy {
    /// Create a fail-closed policy rooted at an existing directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the root cannot be canonicalized or is not a directory.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, PlatformError> {
        let root = fs::canonicalize(root.as_ref())?;
        if !root.is_dir() {
            return Err(PlatformError::UntrustedPath {
                path: root,
                reason: "policy root is not a directory".into(),
            });
        }
        Ok(Self {
            root,
            allow_unc: false,
            reject_reparse_points: true,
        })
    }

    /// Permit UNC paths. Disabled by default and never used for protected installs.
    #[must_use]
    pub fn with_unc(mut self, allow_unc: bool) -> Self {
        self.allow_unc = allow_unc;
        self
    }

    /// Return the canonical policy root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve an existing file and prove that every component stays under the root.
    ///
    /// # Errors
    ///
    /// Returns an error when the path escapes the root, traverses a reparse point,
    /// is an unapproved UNC path, or does not name a regular file.
    pub fn existing_file(&self, candidate: impl AsRef<Path>) -> Result<PathBuf, PlatformError> {
        resolve::existing(
            &self.root,
            self.allow_unc,
            self.reject_reparse_points,
            candidate.as_ref(),
            resolve::PathKind::File,
        )
    }

    /// Resolve an existing directory and prove that every component stays under the root.
    ///
    /// # Errors
    ///
    /// Returns an error when the path escapes the root, traverses a reparse point,
    /// is an unapproved UNC path, or does not name a directory.
    pub fn existing_directory(
        &self,
        candidate: impl AsRef<Path>,
    ) -> Result<PathBuf, PlatformError> {
        resolve::existing(
            &self.root,
            self.allow_unc,
            self.reject_reparse_points,
            candidate.as_ref(),
            resolve::PathKind::Directory,
        )
    }

    /// Resolve a future output path while proving its parent is trusted.
    ///
    /// # Errors
    ///
    /// Returns an error when the path or its parent violates containment, reparse,
    /// UNC, or file-name policy.
    pub fn output_file(&self, candidate: impl AsRef<Path>) -> Result<PathBuf, PlatformError> {
        resolve::output(&self.root, self.allow_unc, candidate.as_ref())
    }
}

/// Read bounded UTF-8 from an already validated file.
///
/// # Errors
///
/// Returns an error when the file is not regular, exceeds the byte limit, cannot
/// be read, or is not valid UTF-8.
pub fn read_bounded_utf8(path: impl AsRef<Path>, limit: u64) -> Result<String, PlatformError> {
    let path = path.as_ref();
    let file = File::open(path)?;
    read_bounded_utf8_from_file(file, path, limit)
}

/// Read bounded UTF-8 through one retained, non-reparse file handle.
///
/// Callers must first establish parent containment with [`PathPolicy`]. On
/// Windows this rejects a leaf reparse point and reads the same handle whose
/// final identity was resolved, closing the validation/read reopen window.
///
/// # Errors
///
/// Returns an error when the file is a reparse point, exceeds the bound, is not
/// regular UTF-8 input, or its retained handle cannot be resolved.
pub fn read_bounded_utf8_no_follow(
    path: impl AsRef<Path>,
    limit: u64,
) -> Result<String, PlatformError> {
    #[cfg(windows)]
    {
        read_bounded_utf8_windows_no_follow(path.as_ref(), limit)
    }
    #[cfg(not(windows))]
    {
        read_bounded_utf8(path, limit)
    }
}

/// Stream SHA-256 from one retained regular-file handle with a fixed 64 KiB buffer.
///
/// The byte limit is checked before opening and after every read, so a file that
/// grows after validation cannot bypass the bound. On Windows, the leaf is opened
/// without following a reparse point and its final handle path must match `path`.
///
/// # Errors
///
/// Returns an error when the path is a reparse point or symbolic link, does not
/// name a regular file, exceeds `limit`, changes identity on Windows, or cannot
/// be read.
pub fn hash_bounded_file_no_follow(
    path: impl AsRef<Path>,
    limit: u64,
) -> Result<BoundedFileHash, PlatformError> {
    let path = path.as_ref();
    let file = open_regular_file_no_follow(path)?;
    hash_bounded_file_from_handle(file, path, limit)
}

fn open_regular_file_no_follow(path: &Path) -> Result<File, PlatformError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || resolve::has_windows_reparse_attribute(&metadata) {
        return Err(PlatformError::UntrustedPath {
            path: path.to_path_buf(),
            reason: "retained input handle is not a regular non-reparse file".into(),
        });
    }
    open_regular_file(path)
}

#[cfg(not(windows))]
fn open_regular_file(path: &Path) -> Result<File, PlatformError> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(PlatformError::UntrustedPath {
            path: path.to_path_buf(),
            reason: "expected a regular file".into(),
        });
    }
    Ok(file)
}

#[cfg(windows)]
fn open_regular_file(path: &Path) -> Result<File, PlatformError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
        return Err(PlatformError::UntrustedPath {
            path: path.to_path_buf(),
            reason: "retained input handle is not a regular non-reparse file".into(),
        });
    }
    let final_path = final_handle_path(&file)?;
    validate_retained_identity(path, &final_path)?;
    Ok(file)
}

fn hash_bounded_file_from_handle(
    mut file: File,
    path: &Path,
    limit: u64,
) -> Result<BoundedFileHash, PlatformError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(PlatformError::UntrustedPath {
            path: path.to_path_buf(),
            reason: "expected a regular file".into(),
        });
    }
    reject_oversized(path, metadata.len(), limit)?;
    let mut digest = Sha256::new();
    let mut size_bytes = 0_u64;
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES].into_boxed_slice();
    while let Some(count) = read_hash_chunk(&mut file, &mut buffer)? {
        size_bytes = bounded_size_after_read(path, size_bytes, count, limit)?;
        digest.update(&buffer[..count]);
    }
    Ok(BoundedFileHash {
        digest: Sha256Digest::from_digest_bytes(digest.finalize().into()),
        size_bytes,
    })
}

fn read_hash_chunk(file: &mut File, buffer: &mut [u8]) -> Result<Option<usize>, PlatformError> {
    let count = file.read(buffer)?;
    Ok((count != 0).then_some(count))
}

fn bounded_size_after_read(
    path: &Path,
    size: u64,
    count: usize,
    limit: u64,
) -> Result<u64, PlatformError> {
    let count = u64::try_from(count).expect("64 KiB read count fits u64");
    let size = size
        .checked_add(count)
        .ok_or_else(|| PlatformError::InputTooLarge {
            path: path.to_path_buf(),
            limit,
        })?;
    reject_oversized(path, size, limit)?;
    Ok(size)
}

fn reject_oversized(path: &Path, size: u64, limit: u64) -> Result<(), PlatformError> {
    if size > limit {
        return Err(PlatformError::InputTooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }
    Ok(())
}

#[cfg(windows)]
fn read_bounded_utf8_windows_no_follow(path: &Path, limit: u64) -> Result<String, PlatformError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
        return Err(PlatformError::UntrustedPath {
            path: path.to_path_buf(),
            reason: "retained input handle is not a regular non-reparse file".into(),
        });
    }
    let final_path = final_handle_path(&file)?;
    validate_retained_identity(path, &final_path)?;
    read_bounded_utf8_from_file(file, path, limit)
}

#[cfg(any(windows, test))]
fn validate_retained_identity(expected: &Path, actual: &Path) -> Result<(), PlatformError> {
    if normalize_final_path(actual) != normalize_final_path(expected) {
        return Err(PlatformError::UntrustedPath {
            path: actual.to_path_buf(),
            reason: "retained input handle identity differs from the validated path".into(),
        });
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn normalize_final_path(path: &Path) -> String {
    let text = path.as_os_str().to_string_lossy();
    let text = text.strip_prefix("\\\\?\\UNC\\").map_or_else(
        || text.strip_prefix("\\\\?\\").unwrap_or(&text).to_owned(),
        |unc| format!("\\\\{unc}"),
    );
    text.trim_end_matches(['\\', '/']).to_ascii_lowercase()
}

#[cfg(windows)]
fn final_handle_path(file: &File) -> Result<PathBuf, PlatformError> {
    use std::os::windows::io::AsRawHandle;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFinalPathNameByHandleW(
            file: *mut core::ffi::c_void,
            path: *mut u16,
            length: u32,
            flags: u32,
        ) -> u32;
    }
    let mut path = vec![0_u16; 32_768];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            path.as_mut_ptr(),
            u32::try_from(path.len()).expect("bounded final-path buffer"),
            0,
        )
    };
    if length == 0 || usize::try_from(length).map_or(true, |value| value >= path.len()) {
        return Err(PlatformError::TrustFailure(
            "could not resolve retained input handle identity".into(),
        ));
    }
    path.truncate(usize::try_from(length).expect("bounded final-path length"));
    Ok(PathBuf::from(String::from_utf16(&path).map_err(|_| {
        PlatformError::TrustFailure("retained input handle path was invalid UTF-16".into())
    })?))
}

fn read_bounded_utf8_from_file(
    file: File,
    path: &Path,
    limit: u64,
) -> Result<String, PlatformError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(PlatformError::UntrustedPath {
            path: path.to_path_buf(),
            reason: "expected a regular file".into(),
        });
    }
    if metadata.len() > limit {
        return Err(PlatformError::InputTooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }
    let capacity = usize::try_from(metadata.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(PlatformError::InputTooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }
    String::from_utf8(bytes).map_err(|_| PlatformError::InvalidUtf8 {
        path: path.to_path_buf(),
    })
}

/// Atomically replace one output using a same-directory temporary file.
///
/// # Errors
///
/// Returns an error when the output name is invalid or the temporary write,
/// synchronization, or atomic rename fails.
pub fn atomic_write(path: impl AsRef<Path>, bytes: &[u8]) -> Result<(), PlatformError> {
    let path = path.as_ref();
    let (parent, temporary) = atomic_paths(path)?;
    let write_result = write_and_replace(&parent, &temporary, path, bytes);
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

fn atomic_paths(path: &Path) -> Result<(PathBuf, PathBuf), PlatformError> {
    let parent = path.parent().ok_or_else(|| PlatformError::UntrustedPath {
        path: path.to_path_buf(),
        reason: "output has no parent".into(),
    })?;
    let name =
        path.file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| PlatformError::UntrustedPath {
                path: path.to_path_buf(),
                reason: "output file name is not Unicode".into(),
            })?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let temporary = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), nonce));
    Ok((parent.to_path_buf(), temporary))
}

fn write_and_replace(
    parent: &Path,
    temporary: &Path,
    path: &Path,
    bytes: &[u8],
) -> Result<(), PlatformError> {
    let mut file = atomic_options().open(temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn atomic_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_rejects_parent_traversal() {
        let root = tempfile::tempdir().expect("root");
        let policy = PathPolicy::new(root.path()).expect("policy");
        assert!(policy.output_file("../escape.json").is_err());
    }

    #[test]
    fn bounded_reader_rejects_oversized_input() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("large.json");
        fs::write(&path, b"12345").expect("write");
        assert!(matches!(
            read_bounded_utf8(path, 4),
            Err(PlatformError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn retained_reader_uses_the_same_bounded_input_contract() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("profile.json");
        fs::write(&path, br#"{"schema_version":"v3"}"#).expect("write");
        assert_eq!(
            read_bounded_utf8_no_follow(&path, 1024).expect("retained read"),
            r#"{"schema_version":"v3"}"#
        );
        assert!(matches!(
            read_bounded_utf8_no_follow(&path, 4),
            Err(PlatformError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn streamed_hash_matches_exact_bytes_and_size() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("resource.bin");
        let bytes = vec![0x5a; HASH_BUFFER_BYTES * 2 + 17];
        fs::write(&path, &bytes).expect("write");
        let actual = hash_bounded_file_no_follow(&path, bytes.len() as u64).expect("hash");
        assert_eq!(actual.digest, Sha256Digest::of_bytes(&bytes));
        assert_eq!(actual.size_bytes, bytes.len() as u64);
    }

    #[test]
    fn streamed_hash_accepts_exact_limit_and_rejects_one_more_byte() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("bounded.bin");
        fs::write(&path, b"12345").expect("write");
        assert!(hash_bounded_file_no_follow(&path, 5).is_ok());
        assert!(matches!(
            hash_bounded_file_no_follow(&path, 4),
            Err(PlatformError::InputTooLarge { limit: 4, .. })
        ));
    }

    #[test]
    fn streamed_hash_rejects_growth_after_handle_validation() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("growing.bin");
        fs::write(&path, b"1234").expect("write");
        let file = File::open(&path).expect("retained handle");
        OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("append handle")
            .write_all(b"5")
            .expect("grow fixture");
        assert!(matches!(
            hash_bounded_file_from_handle(file, &path, 4),
            Err(PlatformError::InputTooLarge { limit: 4, .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn streamed_hash_does_not_follow_a_symbolic_link() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("root");
        let target = root.path().join("target.bin");
        let link = root.path().join("link.bin");
        fs::write(&target, b"fixture").expect("write target");
        symlink(&target, &link).expect("create link");
        assert!(matches!(
            hash_bounded_file_no_follow(link, 1024),
            Err(PlatformError::UntrustedPath { .. })
        ));
    }

    #[test]
    fn retained_identity_rejects_a_final_handle_path_that_changed() {
        assert!(
            validate_retained_identity(
                Path::new(r"C:\trusted\profile.json"),
                Path::new(r"\\?\C:\escaped\profile.json"),
            )
            .is_err()
        );
        assert!(
            validate_retained_identity(
                Path::new(r"C:\trusted\profile.json"),
                Path::new(r"\\?\C:\trusted\profile.json"),
            )
            .is_ok()
        );
    }

    #[test]
    fn atomic_write_replaces_the_complete_file() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("result.json");
        atomic_write(&path, b"first").expect("first");
        atomic_write(&path, b"second").expect("second");
        assert_eq!(fs::read(path).expect("read"), b"second");
    }
}
