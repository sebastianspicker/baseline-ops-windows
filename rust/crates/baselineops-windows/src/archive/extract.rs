use super::ArchivePolicy;
use crate::PlatformError;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Component, Path, PathBuf};

pub(super) fn entries<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    destination: &Path,
    policy: ArchivePolicy,
) -> Result<Vec<PathBuf>, PlatformError> {
    let mut validation = ArchiveValidation::new(policy);
    let mut extracted = Vec::new();
    for index in 0..archive.len() {
        extract_one(archive, index, destination, &mut validation, &mut extracted)?;
    }
    Ok(extracted)
}

fn extract_one<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    index: usize,
    destination: &Path,
    validation: &mut ArchiveValidation,
    extracted: &mut Vec<PathBuf>,
) -> Result<(), PlatformError> {
    let mut entry = archive
        .by_index(index)
        .map_err(|error| PlatformError::ArchiveRejected(error.to_string()))?;
    let relative = validation.entry_path(&entry)?;
    let output = destination.join(&relative);
    if entry.is_dir() {
        create_directory(&output)?;
    } else {
        create_file_parent(&output)?;
        write_entry(&mut entry, &output, validation.max_file_bytes(), &relative)?;
        extracted.push(output);
    }
    Ok(())
}

fn create_directory(output: &Path) -> Result<(), PlatformError> {
    fs::create_dir_all(output)?;
    reject_existing_link(output)
}

fn create_file_parent(output: &Path) -> Result<(), PlatformError> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
        reject_existing_link(parent)?;
    }
    Ok(())
}

struct ArchiveValidation {
    policy: ArchivePolicy,
    total_bytes: u64,
    file_count: usize,
    normalized_names: BTreeSet<String>,
}

impl ArchiveValidation {
    fn new(policy: ArchivePolicy) -> Self {
        Self {
            policy,
            total_bytes: 0,
            file_count: 0,
            normalized_names: BTreeSet::new(),
        }
    }

    fn max_file_bytes(&self) -> u64 {
        self.policy.max_file_bytes
    }

    fn entry_path<R: Read>(
        &mut self,
        entry: &zip::read::ZipFile<'_, R>,
    ) -> Result<PathBuf, PlatformError> {
        let relative = validate_entry_name(entry.name(), self.policy.max_depth)?;
        self.reject_duplicate_or_special(entry, &relative)?;
        if !entry.is_dir() {
            self.enforce_file_quotas(entry.size(), &relative)?;
        }
        Ok(relative)
    }

    fn reject_duplicate_or_special<R: Read>(
        &mut self,
        entry: &zip::read::ZipFile<'_, R>,
        relative: &Path,
    ) -> Result<(), PlatformError> {
        let normalized = relative.to_string_lossy().replace('\\', "/").to_lowercase();
        if !self.normalized_names.insert(normalized) {
            return Err(PlatformError::ArchiveRejected(
                "archive has duplicate or case-colliding paths".into(),
            ));
        }
        if is_link_or_special(entry.unix_mode()) {
            return Err(PlatformError::ArchiveRejected(
                "archive contains a link or special file".into(),
            ));
        }
        Ok(())
    }

    fn enforce_file_quotas(&mut self, size: u64, relative: &Path) -> Result<(), PlatformError> {
        self.file_count = self.file_count.saturating_add(1);
        reject_file_count(self.file_count, self.policy.max_files)?;
        reject_member_size(size, self.policy.max_file_bytes, relative)?;
        self.total_bytes = self
            .total_bytes
            .checked_add(size)
            .ok_or_else(|| PlatformError::ArchiveRejected("archive size overflow".into()))?;
        reject_total_size(self.total_bytes, self.policy.max_total_bytes)
    }
}

fn reject_file_count(count: usize, maximum: usize) -> Result<(), PlatformError> {
    if count > maximum {
        return Err(PlatformError::ArchiveRejected(
            "archive contains too many files".into(),
        ));
    }
    Ok(())
}

fn reject_member_size(size: u64, maximum: u64, relative: &Path) -> Result<(), PlatformError> {
    if size > maximum {
        return Err(PlatformError::ArchiveRejected(format!(
            "archive member exceeds the per-file quota: {}",
            relative.display()
        )));
    }
    Ok(())
}

fn reject_total_size(total: u64, maximum: u64) -> Result<(), PlatformError> {
    if total > maximum {
        return Err(PlatformError::ArchiveRejected(
            "archive exceeds the total uncompressed quota".into(),
        ));
    }
    Ok(())
}

fn write_entry<R: Read>(
    entry: &mut zip::read::ZipFile<'_, R>,
    output: &Path,
    max_file_bytes: u64,
    relative: &Path,
) -> Result<(), PlatformError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    let copied = std::io::copy(&mut entry.by_ref().take(max_file_bytes + 1), &mut file)?;
    if copied != entry.size() || copied > max_file_bytes {
        return Err(PlatformError::ArchiveRejected(format!(
            "archive member size changed while extracting: {}",
            relative.display()
        )));
    }
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn validate_entry_name(name: &str, max_depth: usize) -> Result<PathBuf, PlatformError> {
    reject_invalid_name(name)?;
    let (clean, depth) = normalized_components(name)?;
    if clean.as_os_str().is_empty() || depth > max_depth {
        return Err(PlatformError::ArchiveRejected(
            "archive member has an empty or over-deep path".into(),
        ));
    }
    Ok(clean)
}

fn reject_invalid_name(name: &str) -> Result<(), PlatformError> {
    if name.is_empty() || name.as_bytes().contains(&0) || name.contains(':') {
        return Err(PlatformError::ArchiveRejected(
            "archive member has an invalid or alternate-stream name".into(),
        ));
    }
    Ok(())
}

fn normalized_components(name: &str) -> Result<(PathBuf, usize), PlatformError> {
    let mut clean = PathBuf::new();
    let mut depth = 0_usize;
    for component in Path::new(name).components() {
        match component {
            Component::Normal(part) => {
                validate_windows_component(part.to_string_lossy().as_ref())?;
                clean.push(part);
                depth = depth.saturating_add(1);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(PlatformError::ArchiveRejected(
                    "archive member attempts path traversal".into(),
                ));
            }
        }
    }
    Ok((clean, depth))
}

fn validate_windows_component(component: &str) -> Result<(), PlatformError> {
    if component.ends_with([' ', '.']) {
        return Err(PlatformError::ArchiveRejected(
            "archive member has a Windows-ambiguous suffix".into(),
        ));
    }
    let stem = component
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'));
    if reserved {
        return Err(PlatformError::ArchiveRejected(
            "archive member uses a reserved Windows device name".into(),
        ));
    }
    Ok(())
}

fn is_link_or_special(mode: Option<u32>) -> bool {
    let Some(mode) = mode else {
        return false;
    };
    let file_type = mode & 0o170_000;
    file_type != 0 && file_type != 0o100_000 && file_type != 0o040_000
}

fn reject_existing_link(path: &Path) -> Result<(), PlatformError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(PlatformError::ArchiveRejected(
            "extraction path contains a symbolic link".into(),
        ));
    }
    Ok(())
}
