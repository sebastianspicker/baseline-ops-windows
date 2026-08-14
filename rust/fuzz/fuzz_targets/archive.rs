#![no_main]

use baselineops_windows::{ArchivePolicy, extract_zip_safely};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    if let Ok(root) = tempfile::tempdir() {
        let policy = ArchivePolicy {
            max_files: 32,
            max_file_bytes: 1024 * 1024,
            max_total_bytes: 2 * 1024 * 1024,
            max_depth: 8,
        };
        let _ = extract_zip_safely(Cursor::new(data), root.path(), policy);
    }
});
