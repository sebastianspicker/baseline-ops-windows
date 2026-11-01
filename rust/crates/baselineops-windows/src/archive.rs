use crate::PlatformError;
use std::fs;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

mod extract;

/// Quotas for extracting an untrusted package or evidence archive.
#[derive(Clone, Copy, Debug)]
pub struct ArchivePolicy {
    /// Maximum number of regular files.
    pub max_files: usize,
    /// Maximum uncompressed size of one file.
    pub max_file_bytes: u64,
    /// Maximum total uncompressed bytes.
    pub max_total_bytes: u64,
    /// Maximum path depth below the extraction root.
    pub max_depth: usize,
}

impl Default for ArchivePolicy {
    fn default() -> Self {
        Self {
            max_files: 4096,
            max_file_bytes: 128 * 1024 * 1024,
            max_total_bytes: 512 * 1024 * 1024,
            max_depth: 16,
        }
    }
}

/// Extract a ZIP after rejecting ambiguous names, links, traversal, and quota abuse.
///
/// # Errors
///
/// Returns an error when the archive is malformed, violates a quota or path rule,
/// contains a link or special file, or cannot be extracted safely.
pub fn extract_zip_safely(
    reader: impl Read + Seek,
    destination: impl AsRef<Path>,
    policy: ArchivePolicy,
) -> Result<Vec<PathBuf>, PlatformError> {
    let destination = destination.as_ref();
    fs::create_dir_all(destination)?;
    let destination = fs::canonicalize(destination)?;
    if !destination.is_dir() {
        return Err(PlatformError::ArchiveRejected(
            "destination is not a directory".into(),
        ));
    }

    let mut archive = zip::ZipArchive::new(reader)
        .map_err(|error| PlatformError::ArchiveRejected(error.to_string()))?;
    if archive.len() > policy.max_files.saturating_mul(2) {
        return Err(PlatformError::ArchiveRejected(
            "archive contains too many entries".into(),
        ));
    }

    extract::entries(&mut archive, &destination, policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;

    fn archive_with(name: &str, bytes: &[u8]) -> Vec<u8> {
        let mut buffer = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut buffer);
            writer
                .start_file(name, SimpleFileOptions::default())
                .expect("member");
            writer.write_all(bytes).expect("content");
            writer.finish().expect("finish");
        }
        buffer.into_inner()
    }

    #[test]
    fn extracts_a_regular_member() {
        let bytes = archive_with("schemas/profile.json", b"{}");
        let root = tempfile::tempdir().expect("root");
        let paths = extract_zip_safely(Cursor::new(bytes), root.path(), ArchivePolicy::default())
            .expect("extract");
        assert_eq!(paths.len(), 1);
        assert_eq!(fs::read(&paths[0]).expect("read"), b"{}");
    }

    fn set_unix_mode(bytes: &mut [u8], mode: u32) {
        let central = bytes
            .windows(4)
            .position(|part| part == b"PK\x01\x02")
            .expect("central header");
        bytes[central + 5] = 3; // ZIP creator system: Unix.
        bytes[central + 38..central + 42].copy_from_slice(&(mode << 16).to_le_bytes());
    }

    #[test]
    fn rejects_a_symlink_member_without_touching_its_target() {
        let mut bytes = archive_with("link", b"../outside");
        set_unix_mode(&mut bytes, 0o120_777);
        let root = tempfile::tempdir().expect("root");
        let destination = root.path().join("destination");
        let outside = root.path().join("outside");
        fs::write(&outside, b"keep").expect("outside control");
        assert!(
            extract_zip_safely(Cursor::new(bytes), &destination, ArchivePolicy::default()).is_err()
        );
        assert!(fs::symlink_metadata(destination.join("link")).is_err());
        assert_eq!(fs::read(outside).expect("outside unchanged"), b"keep");
    }

    #[cfg(unix)]
    #[test]
    fn extraction_does_not_preserve_privileged_permission_bits() {
        use std::os::unix::fs::PermissionsExt;

        let mut bytes = archive_with("regular", b"content");
        set_unix_mode(&mut bytes, 0o107_755);
        let root = tempfile::tempdir().expect("root");
        let paths = extract_zip_safely(Cursor::new(bytes), root.path(), ArchivePolicy::default())
            .expect("extract");
        assert_eq!(
            fs::metadata(&paths[0])
                .expect("metadata")
                .permissions()
                .mode()
                & 0o7_000,
            0
        );
        assert_eq!(fs::read(&paths[0]).expect("read"), b"content");
    }

    #[test]
    fn preserves_a_non_ascii_member_name() {
        let bytes = archive_with("résumé.json", b"content");
        let root = tempfile::tempdir().expect("root");
        let paths = extract_zip_safely(Cursor::new(bytes), root.path(), ArchivePolicy::default())
            .expect("extract");
        assert_eq!(
            paths,
            [fs::canonicalize(root.path())
                .expect("canonical root")
                .join("résumé.json")]
        );
        assert_eq!(fs::read(&paths[0]).expect("read"), b"content");
    }

    #[test]
    fn rejects_traversal_and_reserved_names() {
        for name in ["../escape", "CON.txt", "data:stream"] {
            let bytes = archive_with(name, b"x");
            let root = tempfile::tempdir().expect("root");
            assert!(
                extract_zip_safely(Cursor::new(bytes), root.path(), ArchivePolicy::default())
                    .is_err()
            );
        }
    }

    #[test]
    fn rejects_quota_before_creating_an_output_parent() {
        let bytes = archive_with("later/member.bin", b"too large");
        let root = tempfile::tempdir().expect("root");
        let policy = ArchivePolicy {
            max_file_bytes: 1,
            ..ArchivePolicy::default()
        };
        assert!(extract_zip_safely(Cursor::new(bytes), root.path(), policy).is_err());
        assert!(!root.path().join("later").exists());
    }
}
