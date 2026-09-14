use baselineops_domain::Sha256Digest;
use baselineops_windows::{ArchivePolicy, extract_zip_safely};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

pub(crate) const MANIFEST_PATH: &str = "manifest.json";
pub(crate) const MANIFEST_SIGNATURE_PATH: &str = "manifest.json.p7";
pub(crate) const REQUIRED_EXECUTABLES: [&str; 3] = [
    "bin/baselineops.exe",
    "bin/baselineops-gui.exe",
    "bin/baselineops-worker.exe",
];

/// One immutable file in a v3 package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ManifestFile {
    /// Portable forward-slash path relative to package root.
    pub path: String,
    /// Exact byte length.
    pub size_bytes: u64,
    /// SHA-256 over the packaged bytes.
    pub sha256: Sha256Digest,
}

/// Signed-payload manifest shipped inside every package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PackageManifestV1 {
    /// Manifest schema marker.
    pub schema_version: String,
    /// Distribution identity.
    pub product: String,
    /// Rust package version.
    pub package_version: String,
    /// Rust target triple.
    pub target: String,
    /// Exact expected Authenticode certificate subject.
    pub signer_subject: String,
    /// Complete package inventory excluding manifest bytes and their detached signature.
    pub files: Vec<ManifestFile>,
}

/// Result of structural, digest, inventory, and signature verification.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PackageVerification {
    /// Parsed manifest.
    pub manifest: PackageManifestV1,
    /// Digest of the outer ZIP bytes.
    pub package_sha256: Sha256Digest,
    /// Number of payload files verified.
    pub verified_files: usize,
    /// Number of executable signatures verified.
    pub verified_signatures: usize,
}

/// Platform signature port. Windows production uses `WinVerifyTrust`, while tests use a fixture.
pub trait SignatureVerifier {
    /// Verify one executable and its exact expected signer.
    ///
    /// # Errors
    ///
    /// Returns [`PackageError::Signature`] when trust cannot be proved.
    fn verify(&self, executable: &Path, expected_subject: &str) -> Result<(), PackageError>;
}

/// Detached PKCS#7 verifier for the exact manifest bytes.
///
/// The expected subject comes from an external release policy. Implementations
/// must validate the signature before any manifest field becomes trusted.
pub trait DetachedSignatureVerifier {
    /// Verify a detached signature over exactly `signed_bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`PackageError::Signature`] when the signature, signer, or
    /// certificate chain cannot be proved.
    fn verify(
        &self,
        signed_bytes: &[u8],
        signature_bytes: &[u8],
        expected_subject: &str,
    ) -> Result<(), PackageError>;
}

/// Verify a package from a fresh extraction without executing its contents.
///
/// # Errors
///
/// Rejects malformed archives, incomplete inventories, digest mismatches, and untrusted signers.
pub fn verify_package(
    package: impl AsRef<Path>,
    expected_signer_subject: &str,
    detached_signature_verifier: &dyn DetachedSignatureVerifier,
    signature_verifier: &dyn SignatureVerifier,
) -> Result<PackageVerification, PackageError> {
    if expected_signer_subject.trim().is_empty() {
        return Err(PackageError::Signature(
            "an external release signer subject is required".into(),
        ));
    }
    let snapshot = snapshot_package(package.as_ref())?;
    let package_sha256 = hash_file(snapshot.path())?;
    let manifest = verify_payload(
        snapshot.path(),
        expected_signer_subject,
        detached_signature_verifier,
        signature_verifier,
    )?;
    Ok(PackageVerification {
        verified_files: manifest.files.len(),
        verified_signatures: REQUIRED_EXECUTABLES.len(),
        manifest,
        package_sha256,
    })
}

fn verify_payload(
    package: &Path,
    expected_signer_subject: &str,
    detached_verifier: &dyn DetachedSignatureVerifier,
    signature_verifier: &dyn SignatureVerifier,
) -> Result<PackageManifestV1, PackageError> {
    with_package_inventory(package, |actual| {
        let manifest = authenticated_manifest(actual, expected_signer_subject, detached_verifier)?;
        let actual = verify_inventory(&manifest, actual.clone())?;
        verify_required_signatures(&actual, expected_signer_subject, signature_verifier)?;
        Ok(manifest)
    })
}

fn with_package_inventory<T>(
    package: &Path,
    verify: impl FnOnce(&BTreeMap<String, (std::path::PathBuf, u64)>) -> Result<T, PackageError>,
) -> Result<T, PackageError> {
    let extraction = tempfile::tempdir()?;
    let extraction_root = fs::canonicalize(extraction.path())?;
    let archive = File::open(package)?;
    let extracted = extract_zip_safely(archive, &extraction_root, ArchivePolicy::default())?;
    let actual = extracted_inventory(&extraction_root, extracted)?;
    verify(&actual)
}

fn extracted_inventory(
    root: &Path,
    paths: Vec<std::path::PathBuf>,
) -> Result<BTreeMap<String, (std::path::PathBuf, u64)>, PackageError> {
    paths
        .into_iter()
        .map(|path| extracted_member(root, path))
        .collect()
}

fn extracted_member(
    root: &Path,
    path: std::path::PathBuf,
) -> Result<(String, (std::path::PathBuf, u64)), PackageError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| PackageError::InvalidManifest("extracted path escaped package root".into()))?
        .to_string_lossy()
        .replace('\\', "/");
    let size = path.metadata()?.len();
    Ok((relative, (path, size)))
}

fn authenticated_manifest(
    actual: &BTreeMap<String, (std::path::PathBuf, u64)>,
    expected_signer_subject: &str,
    verifier: &dyn DetachedSignatureVerifier,
) -> Result<PackageManifestV1, PackageError> {
    let (manifest_bytes, manifest_signature_bytes) = signed_manifest_bytes(actual)?;
    verifier.verify(
        &manifest_bytes,
        &manifest_signature_bytes,
        expected_signer_subject,
    )?;
    parse_authenticated_manifest(&manifest_bytes, expected_signer_subject)
}

fn signed_manifest_bytes(
    actual: &BTreeMap<String, (std::path::PathBuf, u64)>,
) -> Result<(Vec<u8>, Vec<u8>), PackageError> {
    Ok((
        fs::read(require_unique_special_member(actual, MANIFEST_PATH)?)?,
        fs::read(require_unique_special_member(
            actual,
            MANIFEST_SIGNATURE_PATH,
        )?)?,
    ))
}
fn parse_authenticated_manifest(
    bytes: &[u8],
    expected: &str,
) -> Result<PackageManifestV1, PackageError> {
    let manifest = serde_json::from_slice(bytes)?;
    validate_manifest(&manifest)?;
    validate_manifest_signer(&manifest, expected)?;
    Ok(manifest)
}

fn validate_manifest_signer(
    manifest: &PackageManifestV1,
    expected: &str,
) -> Result<(), PackageError> {
    if manifest.signer_subject != expected {
        return Err(PackageError::Signature(
            "manifest signer differs from the trusted release signer".into(),
        ));
    }
    Ok(())
}

fn verify_inventory(
    manifest: &PackageManifestV1,
    mut actual: BTreeMap<String, (std::path::PathBuf, u64)>,
) -> Result<BTreeMap<String, (std::path::PathBuf, u64)>, PackageError> {
    actual.remove(MANIFEST_PATH);
    actual.remove(MANIFEST_SIGNATURE_PATH);
    verify_inventory_count(&actual, manifest)?;
    for expected in &manifest.files {
        verify_inventory_file(&actual, expected)?;
    }
    Ok(actual)
}

fn verify_inventory_count(
    actual: &BTreeMap<String, (std::path::PathBuf, u64)>,
    manifest: &PackageManifestV1,
) -> Result<(), PackageError> {
    if actual.len() != manifest.files.len() {
        return Err(PackageError::InventoryMismatch(format!(
            "manifest lists {} files but package contains {}",
            manifest.files.len(),
            actual.len()
        )));
    }
    Ok(())
}
fn verify_inventory_file(
    actual: &BTreeMap<String, (std::path::PathBuf, u64)>,
    expected: &ManifestFile,
) -> Result<(), PackageError> {
    let (path, size) = actual.get(&expected.path).ok_or_else(|| {
        PackageError::InventoryMismatch(format!("manifest file is absent: {}", expected.path))
    })?;
    if *size != expected.size_bytes || hash_file(path)? != expected.sha256 {
        return Err(PackageError::InventoryMismatch(format!(
            "size or digest mismatch: {}",
            expected.path
        )));
    }
    Ok(())
}

fn verify_required_signatures(
    actual: &BTreeMap<String, (std::path::PathBuf, u64)>,
    expected_signer_subject: &str,
    signature_verifier: &dyn SignatureVerifier,
) -> Result<(), PackageError> {
    for executable in REQUIRED_EXECUTABLES {
        let (path, _) = actual.get(executable).ok_or_else(|| {
            PackageError::InventoryMismatch(format!("required executable is absent: {executable}"))
        })?;
        signature_verifier.verify(path, expected_signer_subject)?;
    }
    Ok(())
}

fn require_unique_special_member<'a>(
    actual: &'a BTreeMap<String, (std::path::PathBuf, u64)>,
    member: &str,
) -> Result<&'a Path, PackageError> {
    actual
        .get(member)
        .map(|(path, _)| path.as_path())
        .ok_or_else(|| PackageError::Signature(format!("package is missing required {member}")))
}

fn snapshot_package(package: &Path) -> Result<tempfile::NamedTempFile, PackageError> {
    let mut source = File::open(package)?;
    let mut snapshot = tempfile::NamedTempFile::new()?;
    std::io::copy(&mut source, snapshot.as_file_mut())?;
    snapshot.as_file_mut().sync_all()?;
    Ok(snapshot)
}

pub(crate) fn validate_manifest(manifest: &PackageManifestV1) -> Result<(), PackageError> {
    validate_manifest_identity(manifest)?;
    validate_manifest_paths(&manifest.files)?;
    validate_required_executables(&manifest.files)
}

fn validate_manifest_identity(manifest: &PackageManifestV1) -> Result<(), PackageError> {
    if manifest.schema_version != "1.0" {
        return invalid_manifest_identity();
    }
    if manifest.product != "BaselineOps for Windows" {
        return invalid_manifest_identity();
    }
    if manifest.package_version.trim().is_empty() {
        return invalid_manifest_identity();
    }
    if manifest.target != "x86_64-pc-windows-msvc" {
        return invalid_manifest_identity();
    }
    if manifest.signer_subject.trim().is_empty() {
        return invalid_manifest_identity();
    }
    Ok(())
}

fn invalid_manifest_identity<T>() -> Result<T, PackageError> {
    Err(PackageError::InvalidManifest(
        "manifest identity, target, version, or signer is invalid".into(),
    ))
}

fn validate_manifest_paths(files: &[ManifestFile]) -> Result<(), PackageError> {
    let mut paths = BTreeSet::new();
    for file in files {
        if !is_safe_manifest_path(&file.path) || !paths.insert(file.path.to_ascii_lowercase()) {
            return Err(PackageError::InvalidManifest(format!(
                "manifest path is unsafe or ambiguous: {}",
                file.path
            )));
        }
    }
    Ok(())
}

fn is_safe_manifest_path(value: &str) -> bool {
    if value.is_empty() || value.contains(['\\', ':']) {
        return false;
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return false;
    }
    if value
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return false;
    }
    path.components()
        .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn validate_required_executables(files: &[ManifestFile]) -> Result<(), PackageError> {
    for required in REQUIRED_EXECUTABLES {
        if !files.iter().any(|file| file.path == required) {
            return Err(PackageError::InvalidManifest(format!(
                "manifest omits required executable: {required}"
            )));
        }
    }
    Ok(())
}

pub(crate) fn hash_file(path: impl AsRef<Path>) -> Result<Sha256Digest, PackageError> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(Sha256Digest::from_digest_bytes(hash.finalize().into()))
}

/// Package validation failures map to rejected input/trust exit code 4.
#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    /// File operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Safe extraction rejected the ZIP.
    #[error(transparent)]
    Platform(#[from] baselineops_windows::PlatformError),
    /// Strict manifest parsing failed.
    #[error(transparent)]
    Domain(#[from] baselineops_domain::DomainError),
    /// Strict manifest parsing failed after authenticating the exact bytes.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Manifest fields were invalid.
    #[error("invalid package manifest: {0}")]
    InvalidManifest(String),
    /// ZIP bytes and manifest inventory disagreed.
    #[error("package inventory mismatch: {0}")]
    InventoryMismatch(String),
    /// Authenticode or signer validation failed.
    #[error("package signature verification failed: {0}")]
    Signature(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use fixtures::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[path = "fixtures.rs"]
    mod fixtures;

    fn detached_verifier(subject: &'static str) -> DetachedFixtureVerifier {
        DetachedFixtureVerifier {
            calls: AtomicUsize::new(0),
            subject,
        }
    }

    fn counting_verifier() -> CountingVerifier {
        CountingVerifier(AtomicUsize::new(0))
    }

    fn rejecting_verifiers() -> (RejectingDetachedVerifier, CountingVerifier) {
        (
            RejectingDetachedVerifier(AtomicUsize::new(0)),
            counting_verifier(),
        )
    }

    fn assert_signature_rejected(
        package: &std::path::Path,
        expected_subject: &str,
        detached: &dyn DetachedSignatureVerifier,
        verifier: &CountingVerifier,
    ) {
        assert!(matches!(
            verify_package(package, expected_subject, detached, verifier),
            Err(PackageError::Signature(_))
        ));
    }

    #[test]
    fn complete_package_verifies_every_required_signature() {
        let package = write_fixture_package(
            false,
            true,
            "CN=BaselineOps Test",
            b"fixture detached signature",
        );
        let detached = detached_verifier("CN=BaselineOps Test");
        let verifier = counting_verifier();
        let result = verify_package(package.path(), "CN=BaselineOps Test", &detached, &verifier)
            .expect("valid package");
        assert_eq!(result.verified_files, 4);
        assert_eq!(result.verified_signatures, 3);
        assert_eq!(verifier.0.load(Ordering::Relaxed), 3);
        assert_eq!(detached.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn digest_tampering_is_rejected_before_signature_checks() {
        let package = write_fixture_package(
            true,
            true,
            "CN=BaselineOps Test",
            b"fixture detached signature",
        );
        let detached = detached_verifier("CN=BaselineOps Test");
        let verifier = counting_verifier();
        assert!(matches!(
            verify_package(package.path(), "CN=BaselineOps Test", &detached, &verifier),
            Err(PackageError::InventoryMismatch(_))
        ));
        assert_eq!(verifier.0.load(Ordering::Relaxed), 0);
        assert_eq!(detached.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn signer_identity_requires_an_external_trust_anchor() {
        let package = write_fixture_package(
            false,
            true,
            "CN=BaselineOps Test",
            b"fixture detached signature",
        );
        let detached = detached_verifier("CN=Another Publisher");
        let verifier = counting_verifier();
        assert_signature_rejected(package.path(), "CN=Another Publisher", &detached, &verifier);
        assert_eq!(verifier.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn missing_detached_signature_fails_closed_before_manifest_parse() {
        let package = write_fixture_package(false, false, "CN=BaselineOps Test", b"");
        let (detached, verifier) = rejecting_verifiers();
        assert_signature_rejected(package.path(), "CN=BaselineOps Test", &detached, &verifier);
        assert_eq!(detached.0.load(Ordering::Relaxed), 0);
        assert_eq!(verifier.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn detached_failure_precedes_manifest_trust_and_executable_checks() {
        let package = write_fixture_package(
            false,
            true,
            "CN=Another Publisher",
            b"fixture detached signature",
        );
        let (detached, verifier) = rejecting_verifiers();
        assert_signature_rejected(package.path(), "CN=BaselineOps Test", &detached, &verifier);
        assert_eq!(detached.0.load(Ordering::Relaxed), 1);
        assert_eq!(verifier.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn tampered_detached_signature_is_rejected_before_manifest_parse() {
        let package = write_fixture_package(false, true, "CN=BaselineOps Test", b"tampered");
        let detached = detached_verifier("CN=BaselineOps Test");
        let verifier = counting_verifier();
        assert_signature_rejected(package.path(), "CN=BaselineOps Test", &detached, &verifier);
        assert_eq!(detached.calls.load(Ordering::Relaxed), 0);
        assert_eq!(verifier.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn manifest_paths_are_portable_and_unambiguous() {
        for invalid in [
            "",
            "/bin/tool.exe",
            "bin\\tool.exe",
            "C:/bin/tool.exe",
            "bin//tool.exe",
            "./bin/tool.exe",
            "bin/../tool.exe",
            "bin/tool.exe/",
        ] {
            assert!(!is_safe_manifest_path(invalid), "accepted {invalid:?}");
        }
        assert!(is_safe_manifest_path("bin/baselineops.exe"));
    }
}
