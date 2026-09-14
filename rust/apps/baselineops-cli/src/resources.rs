//! Standard-user external-resource parsing and digest binding.

use anyhow::{Context, Result, anyhow, bail};
use baselineops_domain::{
    LogicalResourceId, PlanV3, ResourceBindingV3, ResourceKind, Sha256Digest, canonical_json_digest,
};
use serde::Serialize;
use std::{collections::BTreeSet, fs, path::Path, path::PathBuf, str::FromStr};

const MAX_RESOURCES: usize = 32;
const MAX_RESOURCE_FILES: usize = 1_024;
const MAX_RESOURCE_BYTES: u64 = 256 * 1024 * 1024;

/// One command-line `logical-id=path` value. The path is never serialized.
#[derive(Clone, Debug)]
pub(crate) struct ResourceArgument {
    logical_id: LogicalResourceId,
    path: PathBuf,
}

impl ResourceArgument {
    pub(crate) fn logical_id(&self) -> &LogicalResourceId {
        &self.logical_id
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl FromStr for ResourceArgument {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (logical_id, path) = value
            .split_once('=')
            .ok_or_else(|| "resource must use logical-id=path".to_owned())?;
        let logical_id = LogicalResourceId::new(logical_id).map_err(str::to_owned)?;
        if path.is_empty() {
            return Err("resource path may not be empty".into());
        }
        Ok(Self {
            logical_id,
            path: PathBuf::from(path),
        })
    }
}

/// Bind all standard-user-opened resources without retaining their paths.
pub(crate) fn bind(arguments: &[ResourceArgument]) -> Result<Vec<ResourceBindingV3>> {
    if arguments.len() > MAX_RESOURCES {
        bail!("at most {MAX_RESOURCES} external resources may be bound");
    }
    let mut ids = BTreeSet::new();
    let mut bindings = Vec::with_capacity(arguments.len());
    for argument in arguments {
        if !ids.insert(argument.logical_id.clone()) {
            bail!("duplicate logical resource {}", argument.logical_id);
        }
        bindings.push(bind_one(argument)?);
    }
    bindings.sort_by(|left, right| left.logical_id.cmp(&right.logical_id));
    Ok(bindings)
}

/// Collect repeated bindings and the legacy support-directory alias.
pub(crate) fn bind_selection(selection: &crate::Selection) -> Result<Vec<ResourceBindingV3>> {
    let arguments = with_support_directory(
        selection.resources.clone(),
        selection.support_dir.as_deref(),
    );
    bind(&arguments)
}

/// Rebind every saved-plan resource and reject omissions, additions, or replacement.
pub(crate) fn rebind_plan(
    plan: &PlanV3,
    arguments: &[ResourceArgument],
    support_dir: Option<&Path>,
) -> Result<()> {
    let arguments = with_support_directory(arguments.to_vec(), support_dir);
    let rebound = bind(&arguments)?;
    if rebound != plan.resources {
        bail!("saved plan resources must all be rebound with identical digests and sizes");
    }
    Ok(())
}

fn with_support_directory(
    mut arguments: Vec<ResourceArgument>,
    support_dir: Option<&Path>,
) -> Vec<ResourceArgument> {
    if let Some(path) = support_dir {
        arguments.push(ResourceArgument {
            logical_id: LogicalResourceId::new("support_bundle").expect("static resource ID"),
            path: path.to_path_buf(),
        });
    }
    arguments
}

fn bind_one(argument: &ResourceArgument) -> Result<ResourceBindingV3> {
    let path = resolved_resource_path(argument)?;
    let metadata = fs::symlink_metadata(&path)?;
    let (kind, digest, size_bytes) = resource_digest(&path, &metadata, argument)?;
    Ok(ResourceBindingV3 {
        logical_id: argument.logical_id.clone(),
        kind,
        digest,
        size_bytes,
    })
}

fn resolved_resource_path(argument: &ResourceArgument) -> Result<PathBuf> {
    let unresolved = absolute_path(&argument.path)?;
    let metadata = fs::symlink_metadata(&unresolved)
        .with_context(|| format!("inspect resource {}", argument.logical_id))?;
    if is_reparse(&metadata) {
        bail!(
            "resource {} may not be a reparse point",
            argument.logical_id
        );
    }
    resolve_resource_path(&unresolved, &metadata, argument)
}

fn resolve_resource_path(
    path: &Path,
    metadata: &fs::Metadata,
    argument: &ResourceArgument,
) -> Result<PathBuf> {
    if metadata.is_file() {
        return resolve_input_file(path);
    }
    if metadata.is_dir() {
        let parent = path.parent().context("resource directory has no parent")?;
        return Ok(baselineops_windows::PathPolicy::new(parent)?.existing_directory(path)?);
    }
    bail!(
        "resource {} must be a regular file or directory",
        argument.logical_id
    )
}

fn resource_digest(
    path: &Path,
    metadata: &fs::Metadata,
    argument: &ResourceArgument,
) -> Result<(ResourceKind, Sha256Digest, u64)> {
    if metadata.is_file() {
        return file_digest(path, metadata, argument);
    }
    if metadata.is_dir() {
        let (digest, size_bytes) = bind_directory(path)?;
        return Ok((ResourceKind::DirectoryManifest, digest, size_bytes));
    }
    bail!(
        "resource {} must be a regular file or directory",
        argument.logical_id
    )
}

fn file_digest(
    path: &Path,
    _metadata: &fs::Metadata,
    argument: &ResourceArgument,
) -> Result<(ResourceKind, Sha256Digest, u64)> {
    let hash = baselineops_windows::hash_bounded_file_no_follow(path, MAX_RESOURCE_BYTES)
        .with_context(|| format!("hash resource {}", argument.logical_id))?;
    Ok((ResourceKind::File, hash.digest, hash.size_bytes))
}

#[derive(Serialize)]
struct ManifestEntry {
    path: String,
    digest: Sha256Digest,
    size_bytes: u64,
}

fn bind_directory(root: &std::path::Path) -> Result<(Sha256Digest, u64)> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries = Vec::new();
    let mut total = 0_u64;
    while let Some(directory) = pending.pop() {
        for child in sorted_children(&directory)? {
            bind_child(root, &child, &mut pending, &mut entries, &mut total)?;
        }
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok((canonical_json_digest(&entries)?, total))
}

fn sorted_children(directory: &Path) -> Result<Vec<fs::DirEntry>> {
    let mut children = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    children.sort_by_key(fs::DirEntry::file_name);
    Ok(children)
}

fn bind_child(
    root: &Path,
    child: &fs::DirEntry,
    pending: &mut Vec<PathBuf>,
    entries: &mut Vec<ManifestEntry>,
    total: &mut u64,
) -> Result<()> {
    let path = child.path();
    let metadata = fs::symlink_metadata(&path)?;
    if is_reparse(&metadata) {
        bail!("resource directories may not contain symbolic links");
    }
    if metadata.is_dir() {
        pending.push(path);
        return Ok(());
    }
    bind_directory_file(root, &path, &metadata, entries, total)
}

fn bind_directory_file(
    root: &Path,
    path: &Path,
    metadata: &fs::Metadata,
    entries: &mut Vec<ManifestEntry>,
    total: &mut u64,
) -> Result<()> {
    validate_directory_file(metadata, entries.len())?;
    let remaining = MAX_RESOURCE_BYTES.saturating_sub(*total);
    let entry = manifest_entry(root, path, remaining)?;
    add_resource_bytes(total, entry.size_bytes)?;
    entries.push(entry);
    Ok(())
}

fn validate_directory_file(metadata: &fs::Metadata, count: usize) -> Result<()> {
    if !metadata.is_file() || count >= MAX_RESOURCE_FILES {
        bail!("resource directory contains too many or unsupported entries");
    }
    Ok(())
}

fn add_resource_bytes(total: &mut u64, size: u64) -> Result<()> {
    *total = total
        .checked_add(size)
        .ok_or_else(|| anyhow!("resource byte count overflow"))?;
    if *total > MAX_RESOURCE_BYTES {
        bail!("resource directory exceeds the byte limit");
    }
    Ok(())
}

fn manifest_entry(root: &Path, path: &Path, limit: u64) -> Result<ManifestEntry> {
    let hash = baselineops_windows::hash_bounded_file_no_follow(path, limit)
        .context("hash bounded directory resource entry")?;
    Ok(ManifestEntry {
        path: relative_path(root, path)?,
        digest: hash.digest,
        size_bytes: hash.size_bytes,
    })
}

fn relative_path(root: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root)?
        .to_string_lossy()
        .replace('\\', "/"))
}

pub(crate) fn resolve_input_file(path: &Path) -> Result<PathBuf> {
    let absolute = absolute_path(path)?;
    let parent = absolute.parent().context("input file has no parent")?;
    Ok(baselineops_windows::PathPolicy::new(parent)?.existing_file(&absolute)?)
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

#[cfg(windows)]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_rejects_path_like_or_duplicate_authority() {
        assert!(
            "support_bundle=/tmp/input"
                .parse::<ResourceArgument>()
                .is_ok()
        );
        assert!("../bundle=/tmp/input".parse::<ResourceArgument>().is_err());
        let first = "bundle=/tmp/a".parse::<ResourceArgument>().expect("first");
        let second = "bundle=/tmp/b".parse::<ResourceArgument>().expect("second");
        assert!(bind(&[first, second]).is_err());
    }

    #[test]
    fn binding_detects_resource_replacement() {
        let root = tempfile::tempdir_in(std::env::current_dir().expect("working directory"))
            .expect("root");
        let path = root.path().join("input.json");
        fs::write(&path, b"first").expect("first fixture");
        let argument = ResourceArgument {
            logical_id: LogicalResourceId::new("feed").expect("ID"),
            path: path.clone(),
        };
        let first = bind(std::slice::from_ref(&argument)).expect("first binding");
        fs::write(path, b"second").expect("replacement fixture");
        let second = bind(&[argument]).expect("second binding");
        assert_ne!(first, second);
    }

    #[test]
    fn binding_hashes_exact_file_and_directory_entry_bytes() {
        let root = tempfile::tempdir_in(std::env::current_dir().expect("working directory"))
            .expect("root");
        let file = root.path().join("input.bin");
        let directory = root.path().join("directory");
        let entry = directory.join("entry.bin");
        fs::create_dir(&directory).expect("directory");
        fs::write(&file, b"standalone").expect("file");
        fs::write(&entry, b"directory-entry").expect("entry");

        let file_binding = bind(&[resource_argument("file", &file)]).expect("bind file");
        assert_eq!(
            file_binding[0].digest,
            Sha256Digest::of_bytes(b"standalone")
        );
        assert_eq!(file_binding[0].size_bytes, 10);

        let directory_binding =
            bind(&[resource_argument("directory", &directory)]).expect("bind directory");
        assert_eq!(directory_binding[0].size_bytes, 15);
        let manifest = [ManifestEntry {
            path: "entry.bin".into(),
            digest: Sha256Digest::of_bytes(b"directory-entry"),
            size_bytes: 15,
        }];
        assert_eq!(
            directory_binding[0].digest,
            canonical_json_digest(&manifest).unwrap()
        );
    }

    fn resource_argument(id: &str, path: &Path) -> ResourceArgument {
        ResourceArgument {
            logical_id: LogicalResourceId::new(id).expect("ID"),
            path: path.to_path_buf(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn binding_rejects_a_symbolic_link_resource() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir_in(std::env::current_dir().expect("working directory"))
            .expect("root");
        let target = root.path().join("target.json");
        let link = root.path().join("link.json");
        fs::write(&target, b"fixture").expect("target");
        symlink(target, &link).expect("link");
        let argument = ResourceArgument {
            logical_id: LogicalResourceId::new("feed").expect("ID"),
            path: link,
        };
        assert!(bind(&[argument]).is_err());
    }
}
