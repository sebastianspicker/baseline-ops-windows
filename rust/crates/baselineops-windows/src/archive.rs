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
