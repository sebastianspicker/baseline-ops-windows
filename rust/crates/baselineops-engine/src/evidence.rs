use baselineops_domain::{
    ArtifactId, ArtifactKind, ArtifactV3, JsonMap, Sha256Digest, canonical_json_bytes,
};
use baselineops_windows::atomic_write;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

mod error;

pub use error::EvidenceError;

const MANIFEST_NAME: &str = "evidence-manifest.v1.json";

/// Quotas applied before the evidence store retains a capability output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceLimits {
    /// Maximum bytes retained in one artifact.
    pub max_file_bytes: u64,
    /// Maximum bytes retained by the complete evidence store.
    pub max_total_bytes: u64,
    /// Maximum number of retained artifacts.
    pub max_artifacts: usize,
}

impl EvidenceLimits {
    /// Validate a policy before it is used to create or open a store.
    ///
    /// # Errors
    ///
    /// Returns an error when a quota is zero or the per-file quota exceeds the total quota.
    pub fn validate(self) -> Result<(), EvidenceError> {
        if self.max_file_bytes == 0
            || self.max_total_bytes == 0
            || self.max_artifacts == 0
            || self.max_file_bytes > self.max_total_bytes
        {
            return Err(EvidenceError::InvalidLimits);
        }
        Ok(())
    }
}

/// Platform protection boundary for the worker-controlled evidence root.
///
/// Production Windows code must implement this port using its installation or
/// run-directory policy. The engine deliberately makes no ACL claim itself.
pub trait EvidenceProtection: Send + Sync {
    /// Establish the required protection for a newly created evidence root.
    ///
    /// # Errors
    ///
    /// Returns an error when platform-specific protection cannot be established.
    fn protect(&self, root: &Path) -> Result<(), EvidenceError>;

    /// Prove that the evidence root remains protected before use.
    ///
    /// # Errors
    ///
    /// Returns an error when protection cannot be independently verified.
    fn verify(&self, root: &Path) -> Result<(), EvidenceError>;
}

/// One request to retain bytes as an artifact.
#[derive(Clone, Debug)]
pub struct EvidenceWrite<'a> {
    /// Worker-controlled relative artifact locator.
    pub locator: &'a str,
    /// Artifact classification retained in the result.
    pub kind: ArtifactKind,
    /// MIME type of the retained content.
    pub media_type: &'a str,
    /// Worker-trusted availability time.
    pub created_at: DateTime<Utc>,
    /// Capability metadata with no path or authority semantics.
    pub metadata: JsonMap,
}

/// Canonically serialized inventory for one evidence root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EvidenceManifest {
    /// Schema marker for strict readers.
    pub schema_version: String,
    /// Retained artifacts in deterministic locator order.
    pub artifacts: Vec<ArtifactV3>,
    /// Sum of the retained artifact sizes.
    pub total_bytes: u64,
}

impl EvidenceManifest {
    fn empty() -> Self {
        Self {
            schema_version: "1.0".into(),
            artifacts: Vec::new(),
            total_bytes: 0,
        }
    }
}

/// Protected, quota-bounded evidence store with digest-on-write retention.
pub struct EvidenceStore {
    root: PathBuf,
    limits: EvidenceLimits,
    protection: Arc<dyn EvidenceProtection>,
    manifest: EvidenceManifest,
    usable: bool,
    #[cfg(test)]
    fail_after_manifest_replace: AtomicBool,
}

impl EvidenceStore {
    /// Create an empty protected store. A protection implementation is required.
    ///
    /// # Errors
    ///
    /// Fails closed when protection cannot be established or verified, when the
    /// manifest already exists, or when the limits are invalid.
    pub fn create(
        root: impl AsRef<Path>,
        limits: EvidenceLimits,
        protection: Arc<dyn EvidenceProtection>,
    ) -> Result<Self, EvidenceError> {
        let root = validated_root(root, limits)?;
        fs::create_dir_all(&root)?;
        protection.protect(&root)?;
        protection.verify(&root)?;
        let manifest_path = root.join(MANIFEST_NAME);
        if manifest_path.exists() {
            return Err(EvidenceError::AlreadyExists);
        }
        let store = Self {
            root,
            limits,
            protection,
            manifest: EvidenceManifest::empty(),
            usable: true,
            #[cfg(test)]
            fail_after_manifest_replace: AtomicBool::new(false),
        };
        store.persist_manifest()?;
        Ok(store)
    }

    /// Open a protected store only after validating its canonical manifest and bytes.
    ///
    /// # Errors
    ///
    /// Fails when protection is absent or unverifiable, the manifest is noncanonical,
    /// or any retained artifact has changed since its digest was recorded.
    pub fn open(
        root: impl AsRef<Path>,
        limits: EvidenceLimits,
        protection: Arc<dyn EvidenceProtection>,
    ) -> Result<Self, EvidenceError> {
        let root = validated_root(root, limits)?;
        protection.verify(&root)?;
        let manifest = read_manifest(&root)?;
        validate_manifest(&root, &manifest, limits)?;
        Ok(Self {
            root,
            limits,
            protection,
            manifest,
            usable: true,
            #[cfg(test)]
            fail_after_manifest_replace: AtomicBool::new(false),
        })
    }

    /// Retain one new artifact without allowing overwrite of an existing locator.
    ///
    /// # Errors
    ///
    /// Fails before writing when the protected root cannot be verified, a locator is
    /// unsafe, or a quota would be exceeded.
    pub fn write(
        &mut self,
        request: EvidenceWrite<'_>,
        bytes: &[u8],
    ) -> Result<ArtifactV3, EvidenceError> {
        self.verify_access()?;
        let relative = safe_relative_path(request.locator)?;
        let (size_bytes, total_bytes) = self.write_quota(bytes)?;
        let path = self.root.join(&relative);
        ensure_safe_parent(&self.root, &relative)?;
        write_new_file(&path, bytes)?;
        let artifact = artifact_from(request, bytes, size_bytes);
        self.commit_artifact(&artifact, total_bytes, path)?;
        Ok(artifact)
    }

    fn write_quota(&self, bytes: &[u8]) -> Result<(u64, u64), EvidenceError> {
        let size = u64::try_from(bytes.len()).map_err(|_| EvidenceError::QuotaExceeded)?;
        if size > self.limits.max_file_bytes
            || self.manifest.artifacts.len() >= self.limits.max_artifacts
        {
            return Err(EvidenceError::QuotaExceeded);
        }
        let total = self
            .manifest
            .total_bytes
            .checked_add(size)
            .ok_or(EvidenceError::QuotaExceeded)?;
        if total > self.limits.max_total_bytes {
            return Err(EvidenceError::QuotaExceeded);
        }
        Ok((size, total))
    }

    fn commit_artifact(
        &mut self,
        artifact: &ArtifactV3,
        total: u64,
        path: PathBuf,
    ) -> Result<(), EvidenceError> {
        let previous_total = self.manifest.total_bytes;
        let insertion = insert_artifact_sorted(&mut self.manifest.artifacts, artifact.clone());
        self.manifest.total_bytes = total;
        if let Err(error) = self.persist_manifest() {
            self.manifest.artifacts.remove(insertion);
            self.manifest.total_bytes = previous_total;
            if let Err(rollback) = self.persist_manifest() {
                self.usable = false;
                return Err(EvidenceError::PersistenceRollback {
                    persistence: Box::new(error),
                    rollback: Box::new(rollback),
                });
            }
            if let Err(cleanup) = fs::remove_file(path) {
                self.usable = false;
                return Err(EvidenceError::Io(cleanup));
            }
            return Err(error);
        }
        Ok(())
    }

    /// Read retained bytes only after re-verifying protection and recorded integrity.
    ///
    /// # Errors
    ///
    /// Returns an error when the locator is unknown, protection fails, or retained bytes differ.
    pub fn read(&self, locator: &str) -> Result<Vec<u8>, EvidenceError> {
        self.verify_access()?;
        let relative = safe_relative_path(locator)?;
        let artifact = self
            .manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.locator == locator)
            .ok_or(EvidenceError::UnknownArtifact)?;
        read_verified_artifact(self.root.join(relative), artifact, locator)
    }

    /// Return the current canonical inventory without exposing a mutable root path.
    #[must_use]
    pub fn manifest(&self) -> &EvidenceManifest {
        &self.manifest
    }

    fn persist_manifest(&self) -> Result<(), EvidenceError> {
        self.protection.verify(&self.root)?;
        atomic_write(
            self.root.join(MANIFEST_NAME),
            &canonical_json_bytes(&self.manifest)?,
        )?;
        #[cfg(test)]
        if self
            .fail_after_manifest_replace
            .swap(false, Ordering::SeqCst)
        {
            return Err(EvidenceError::Protection(
                "injected post-replacement failure".into(),
            ));
        }
        Ok(())
    }

    fn verify_access(&self) -> Result<(), EvidenceError> {
        self.ensure_usable()?;
        self.protection.verify(&self.root)
    }

    fn ensure_usable(&self) -> Result<(), EvidenceError> {
        if !self.usable {
            return Err(EvidenceError::Unusable);
        }
        Ok(())
    }

    #[cfg(test)]
    fn fail_next_persist_after_replace(&self) {
        self.fail_after_manifest_replace
            .store(true, Ordering::SeqCst);
    }
}

fn insert_artifact_sorted(artifacts: &mut Vec<ArtifactV3>, artifact: ArtifactV3) -> usize {
    let insertion = artifacts.partition_point(|candidate| candidate.locator < artifact.locator);
    artifacts.insert(insertion, artifact);
    insertion
}

fn validated_root(
    root: impl AsRef<Path>,
    limits: EvidenceLimits,
) -> Result<PathBuf, EvidenceError> {
    limits.validate()?;
    Ok(root.as_ref().to_path_buf())
}

fn read_manifest(root: &Path) -> Result<EvidenceManifest, EvidenceError> {
    let bytes = fs::read(root.join(MANIFEST_NAME))?;
    let manifest = serde_json::from_slice::<EvidenceManifest>(&bytes)?;
    if canonical_json_bytes(&manifest)? != bytes {
        return Err(EvidenceError::NonCanonicalManifest);
    }
    Ok(manifest)
}

fn validate_manifest(
    root: &Path,
    manifest: &EvidenceManifest,
    limits: EvidenceLimits,
) -> Result<(), EvidenceError> {
    validate_manifest_header(manifest, limits)?;
    let mut locators = BTreeSet::<String>::new();
    let mut total = 0_u64;
    for artifact in &manifest.artifacts {
        validate_manifest_artifact(root, artifact, limits, &mut locators)?;
        total = total
            .checked_add(artifact.size_bytes)
            .ok_or(EvidenceError::QuotaExceeded)?;
    }
    if total != manifest.total_bytes || total > limits.max_total_bytes {
        return Err(EvidenceError::InvalidManifest);
    }
    Ok(())
}

fn validate_manifest_header(
    manifest: &EvidenceManifest,
    limits: EvidenceLimits,
) -> Result<(), EvidenceError> {
    if manifest.schema_version != "1.0" || manifest.artifacts.len() > limits.max_artifacts {
        return Err(EvidenceError::InvalidManifest);
    }
    Ok(())
}

fn validate_manifest_artifact(
    root: &Path,
    artifact: &ArtifactV3,
    limits: EvidenceLimits,
    locators: &mut BTreeSet<String>,
) -> Result<(), EvidenceError> {
    let path = safe_relative_path(&artifact.locator)?;
    if !locators.insert(artifact.locator.clone()) || artifact.size_bytes > limits.max_file_bytes {
        return Err(EvidenceError::InvalidManifest);
    }
    read_verified_artifact(root.join(path), artifact, &artifact.locator).map(|_| ())
}

fn safe_relative_path(locator: &str) -> Result<PathBuf, EvidenceError> {
    let path = Path::new(locator);
    if locator.is_empty()
        || locator.contains(['\\', ':'])
        || path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(EvidenceError::UnsafeLocator(locator.into()));
    }
    Ok(path.to_path_buf())
}

fn ensure_safe_parent(root: &Path, relative: &Path) -> Result<(), EvidenceError> {
    let mut current = root.to_path_buf();
    if let Some(parent) = relative.parent() {
        for part in parent.components() {
            let Component::Normal(part) = part else {
                return Err(EvidenceError::UnsafeLocator(relative.display().to_string()));
            };
            create_safe_directory(&mut current, part, relative)?;
        }
    }
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), EvidenceError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn artifact_from(request: EvidenceWrite<'_>, bytes: &[u8], size_bytes: u64) -> ArtifactV3 {
    ArtifactV3 {
        id: ArtifactId::new(),
        kind: request.kind,
        media_type: request.media_type.into(),
        locator: request.locator.into(),
        digest: Sha256Digest::of_bytes(bytes),
        size_bytes,
        created_at: request.created_at,
        metadata: request.metadata,
    }
}
fn read_verified_artifact(
    path: PathBuf,
    artifact: &ArtifactV3,
    locator: &str,
) -> Result<Vec<u8>, EvidenceError> {
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .open(path)?
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).ok() != Some(artifact.size_bytes)
        || Sha256Digest::of_bytes(&bytes) != artifact.digest
    {
        return Err(EvidenceError::IntegrityMismatch(locator.into()));
    }
    Ok(bytes)
}
fn create_safe_directory(
    current: &mut PathBuf,
    part: &std::ffi::OsStr,
    relative: &Path,
) -> Result<(), EvidenceError> {
    current.push(part);
    fs::create_dir(&*current).or_else(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            Ok(())
        } else {
            Err(error)
        }
    })?;
    let metadata = fs::symlink_metadata(&*current)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(EvidenceError::UnsafeLocator(relative.display().to_string()));
    }
    Ok(())
}

#[cfg(test)]
#[path = "evidence_tests.rs"]
mod tests;
